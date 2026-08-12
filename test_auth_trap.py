#!/usr/bin/env python3
"""
pytest validation suite for the AegisFTP credential trap (post-hardening).

Behavior under test (after the V1-V6 hardening):
  - The trap threshold is RANDOMIZED PER-IP in [AUTH_THRESHOLD_MIN, AUTH_THRESHOLD_MAX]
    (default 3-7). For an IP with threshold T:
        PASS attempts 1..T   -> 530 auth_failure
        PASS attempt T+1..    -> 230 auth_success
  - The failed-attempt counter is PER-IP and persists across TCP connections
    (V1): a new connection from the same IP continues from the accumulated
    count, so connection-rotating bots still trip the bait.
  - A NEW source IP sees the full sequence again.
  - Concurrent sessions from the SAME IP share the counter and must not race
    (no state leak / no crash); the total number of 530s across all sessions is
    exactly the per-IP threshold T (3-7), and everything else returns 230.

Usage:
    pytest test_auth_trap.py                       # default 127.0.0.1:21
    HONEYPOT_HOST=127.0.0.1 HONEYPOT_PORT=2121 pytest -v test_auth_trap.py

Environment overrides:
    HONEYPOT_HOST       target host (default 127.0.0.1)
    HONEYPOT_PORT       target port (default 21)
    HONEYPOT_TIMEOUT    per-socket timeout in seconds (default 30; jitter + tarpit)
    HONEYPOT_CONCURRENCY threads for the isolation test (default 10)
    HONEYPOT_CSV_LOG    CSV output path (default auth_trap_test_log.csv)

Output:
  auth_trap_test_log.csv with columns:
  session_id, attempt_number, username, password, response_code, timestamp,
  response_time_ms
"""

import csv
import os
import random
import socket
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import pytest

HOST = os.environ.get("HONEYPOT_HOST", "127.0.0.1")
PORT = int(os.environ.get("HONEYPOT_PORT", "21"))
TIMEOUT = float(os.environ.get("HONEYPOT_TIMEOUT", "30"))
CONCURRENCY = int(os.environ.get("HONEYPOT_CONCURRENCY", "10"))
CSV_LOG = os.environ.get("HONEYPOT_CSV_LOG", "auth_trap_test_log.csv")

TRAP_THRESHOLD_MIN = int(os.environ.get("AUTH_THRESHOLD_MIN", "3"))
TRAP_THRESHOLD_MAX = int(os.environ.get("AUTH_THRESHOLD_MAX", "7"))

# Each test run uses a random /24 loopback base so re-runs against a persistent
# server get fresh source IPs (the per-IP counter is intentionally persistent).
_IP_BASE = random.randint(1, 245)


def _ip(offset):
    return f"127.0.0.{_IP_BASE + offset}"


# ---------------------------------------------------------------------------
# Low-level raw-socket FTP client (precise per-command response + timing)
# ---------------------------------------------------------------------------

def extract_code(response_text):
    """Pull the 3-digit RFC 959 reply code out of a response block, or None."""
    if not response_text:
        return None
    first_line = response_text.splitlines()[0]
    token = first_line.split(" ", 1)[0]
    return int(token) if token.isdigit() else None


class FTPTrapSession:
    """Minimal FTP client using a raw TCP socket for exact trap validation.

    source_ip: bind a specific loopback source address so tests can give each
    session a unique IP (per-IP counter) or share one (accumulation tests).
    """

    def __init__(self, host=HOST, port=PORT, timeout=TIMEOUT, source_ip=None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.source_ip = source_ip
        self.session_id = str(uuid.uuid4())  # client-side label; server assigns its own
        self.sock = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def connect(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if self.source_ip:
            sock.bind((self.source_ip, 0))
        sock.settimeout(self.timeout)
        sock.connect((self.host, self.port))
        self.sock = sock
        banner = self._read_response()
        if not banner:
            raise ConnectionError("No banner received from server")
        return banner

    def _send(self, line):
        self.sock.sendall((line + "\r\n").encode("utf-8", errors="replace"))

    def _read_response(self):
        """Read one complete FTP reply, handling multiline (1xx-/2xx-) blocks."""
        data = b""
        while True:
            chunk = self.sock.recv(4096)
            if not chunk:
                break
            data += chunk
            text = data.decode("utf-8", errors="replace")
            if not text.endswith("\n"):
                continue
            lines = text.rstrip("\r\n").split("\n")
            last = lines[-1]
            # 'NNN ' ends a reply block; 'NNN-' means more lines follow
            if len(last) >= 4 and last[3] == " ":
                break
        return data.decode("utf-8", errors="replace").strip()

    def attempt(self, username, password):
        """Send USER + PASS. Returns (code, pass_response, response_time_ms, user_response)."""
        start = time.perf_counter()
        self._send(f"USER {username}")
        user_resp = self._read_response()
        self._send(f"PASS {password}")
        pass_resp = self._read_response()
        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
        return extract_code(pass_resp), pass_resp, elapsed_ms, user_resp

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            finally:
                self.sock = None


# ---------------------------------------------------------------------------
# Thread-safe CSV logger
# ---------------------------------------------------------------------------

class AttemptLogger:
    FIELDS = [
        "session_id",
        "attempt_number",
        "username",
        "password",
        "response_code",
        "timestamp",
        "response_time_ms",
    ]

    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self._fh = open(path, "w", newline="")
        self._writer = csv.DictWriter(self._fh, fieldnames=self.FIELDS)
        self._writer.writeheader()
        self._fh.flush()

    def log(self, session_id, attempt_number, username, password,
            response_code, timestamp, response_time_ms):
        row = {
            "session_id": session_id,
            "attempt_number": attempt_number,
            "username": username,
            "password": password,
            "response_code": response_code,
            "timestamp": timestamp,
            "response_time_ms": response_time_ms,
        }
        with self.lock:
            self._writer.writerow(row)
            self._fh.flush()

    def close(self):
        with self.lock:
            self._fh.close()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session", autouse=True)
def logger():
    log = AttemptLogger(CSV_LOG)
    yield log
    log.close()


@pytest.fixture(scope="session", autouse=True)
def honeypot_ready():
    try:
        with socket.create_connection((HOST, PORT), timeout=3) as s:
            s.recv(1024)
    except OSError as exc:
        pytest.skip(f"Honeypot unreachable at {HOST}:{PORT}: {exc}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def log_attempt(logger, session_id, attempt_number, username, password, code, ms):
    logger.log(
        session_id,
        attempt_number,
        username,
        password,
        code,
        datetime.now(timezone.utc).isoformat(),
        ms,
    )


def run_attempts(logger, source_ip, username, passwords):
    """Run a list of USER/PASS attempts on ONE connection from source_ip."""
    codes = []
    with FTPTrapSession(source_ip=source_ip) as s:
        s.connect()
        for n, pw in enumerate(passwords, start=1):
            code, resp, ms, _ = s.attempt(username, pw)
            log_attempt(logger, s.session_id, n, username, pw, code, ms)
            codes.append(code)
    return codes


def assert_trap_sequence(codes, source_ip_label):
    """Assert a fresh-IP trap sequence: 3+ leading 530s, one grant at attempt T+1 (T in 3-7), then 230s."""
    assert len(codes) >= 8, f"{source_ip_label}: need >=8 attempts to guarantee a grant"
    assert codes[:3] == [530, 530, 530], \
        f"{source_ip_label}: attempts 1-3 must be 530 (min threshold is 3), got {codes[:3]}"
    try:
        grant_idx = codes.index(230)
    except ValueError:
        grant_idx = None
    assert grant_idx is not None, f"{source_ip_label}: never granted: {codes}"
    assert TRAP_THRESHOLD_MIN <= grant_idx + 1 <= TRAP_THRESHOLD_MAX + 1, \
        f"{source_ip_label}: grant on attempt {grant_idx + 1} outside [{TRAP_THRESHOLD_MIN}+1, {TRAP_THRESHOLD_MAX}+1]: {codes}"
    assert all(c == 530 for c in codes[:grant_idx]), \
        f"{source_ip_label}: non-530 before grant: {codes}"
    assert all(c == 230 for c in codes[grant_idx:]), \
        f"{source_ip_label}: non-230 after grant (post-auth must stay open): {codes}"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_single_session_trap_sequence(logger):
    """One connection from a fresh IP: 530 until the (randomized) grant, then 230."""
    codes = run_attempts(logger, _ip(1), "admin", [f"pw{i}" for i in range(1, 9)])
    assert_trap_sequence(codes, "fresh IP")


def test_post_auth_state_is_open(logger):
    """After the grant, ANY later username/password combo returns 230."""
    ip = _ip(2)
    codes = run_attempts(logger, ip, "admin", [f"pw{i}" for i in range(1, 9)])
    assert 230 in codes

    open_codes = run_attempts(
        logger, ip, "admin",
        [f"post{i}" for i in range(1, 4)],
    )
    # Same IP: accumulated counter means the first attempt is already a grant,
    # and the post-auth open state holds for arbitrary credentials.
    assert open_codes == [230, 230, 230], f"post-auth open state broken: {open_codes}"

    arbitrary = run_attempts(logger, ip, "root", ["garbage", "hunter2", ""])
    assert arbitrary == [230, 230, 230], f"arbitrary creds after grant must pass: {arbitrary}"


def test_per_ip_counter_persists_across_connections(logger):
    """V1: a new TCP connection from the SAME IP continues from the accumulated
    counter (bait trips for rotating-connection bots), while a NEW IP resets."""
    ip = _ip(3)
    first = run_attempts(logger, ip, "admin", [f"pw{i}" for i in range(1, 9)])
    assert_trap_sequence(first, "session 1 (fresh IP)")

    second = run_attempts(logger, ip, "admin", ["reconnect-1", "reconnect-2"])
    assert second == [230, 230], \
        f"per-IP counter did not persist: new connection from same IP saw {second}"

    new_ip = _ip(4)
    third = run_attempts(logger, new_ip, "admin", [f"pw{i}" for i in range(1, 9)])
    assert_trap_sequence(third, "new IP (should reset)")


def test_concurrent_sessions_accumulate_ip_counter(logger):
    """10 parallel sessions sharing ONE IP. Total 530s must equal the per-IP
    threshold T (3-7); everything else is 230. Proves thread safety and that
    the counter is per-IP (isolated sessions would produce ~30 fails, not 3-7)."""
    shared_ip = _ip(5)

    def worker(idx):
        return run_attempts(logger, shared_ip, f"user{idx}", [f"pw{i}" for i in range(1, 5)])

    with ThreadPoolExecutor(max_workers=CONCURRENCY) as ex:
        futures = [ex.submit(worker, i) for i in range(CONCURRENCY)]
        results = [f.result() for f in futures]

    all_codes = [c for codes in results for c in codes]
    assert len(all_codes) == CONCURRENCY * 4, "missing attempts"
    fails = all_codes.count(530)
    grants = all_codes.count(230)
    assert fails + grants == len(all_codes), f"unexpected code in {set(all_codes)}"
    assert TRAP_THRESHOLD_MIN <= fails <= TRAP_THRESHOLD_MAX, \
        f"per-IP shared counter: expected 530 count == T in [{TRAP_THRESHOLD_MIN},{TRAP_THRESHOLD_MAX}], got {fails}"
    assert grants == len(all_codes) - fails
    assert any(230 in codes for codes in results), "no session ever granted"
    # Every worker must receive a response for all 4 attempts (no crashes/races)
    for i, codes in enumerate(results):
        assert len(codes) == 4, f"worker {i}: got {len(codes)} responses"


def test_response_timing_recorded(logger):
    """Every attempt must be measured and logged with a positive latency."""
    codes = run_attempts(logger, _ip(6), "admin", [f"pw{i}" for i in range(1, 9)])
    assert codes.count(230) >= 1
    # timing verified structurally by the CSV test below


def test_csv_log_columns_and_rows(logger):
    """CSV log must exist with the required header and contain logged attempts."""
    assert os.path.exists(CSV_LOG), f"CSV log {CSV_LOG} not written"
    with open(CSV_LOG, newline="") as f:
        reader = csv.DictReader(f)
        assert reader.fieldnames == AttemptLogger.FIELDS, \
            f"CSV header mismatch: {reader.fieldnames}"
        rows = list(reader)

    assert len(rows) > 0, "CSV log contains no attempt rows"
    for row in rows:
        assert row["session_id"], "missing session_id"
        assert row["attempt_number"].isdigit(), "non-numeric attempt_number"
        assert row["response_code"].isdigit(), f"non-numeric response_code: {row}"
        assert float(row["response_time_ms"]) > 0, "response_time_ms must be > 0"
        assert row["timestamp"], "missing timestamp"
