"""
Adaptive Deception Module for AegisFTP
Implements a Finite State Machine (FSM) & Reinforcement Learning (Q-table) Tarpit & Dynamic Deception Engine.
"""
import time
import random
import posixpath
import logging

logger = logging.getLogger("AegisFTP.Adaptive")

# Issue 6: sensitive-file containment. These keywords match the same bait
# assets the rest of the engine already treats as "sensitive" (see
# get_session_state's SENSITIVE_FILE_PROBING check and mitre_mapper's
# CREDENTIAL_DUMPING mapping), so a RETR on any of them is gated behind a
# simple behavioral trigger: the attacker must have already listed the
# containing directory in this session. This isn't a real security boundary
# (it's a deception control, not an ACL) -- it just stops a scripted
# "connect, auth, RETR /etc/shadow" one-liner from reaching the bait on the
# very first request, which is more realistic and buys more dwell time.
SENSITIVE_PROBE_KEYWORDS = ["passwd", "shadow", "config.php", "backup"]


def _is_sensitive_path(path_or_name):
    lowered = (path_or_name or "").lower()
    return any(k in lowered for k in SENSITIVE_PROBE_KEYWORDS)


class AdaptiveDeceptionEngine:
    def __init__(self):
        # Q-learning table initialization: States x Actions
        # States: LOW_ACTIVITY, HIGH_FREQUENCY_SCAN, SENSITIVE_FILE_PROBING, PAYLOAD_UPLOADED
        # Actions: NORMAL_RESPONSE, TARPIT_DELAY, DYNAMIC_INJECTION, FAKE_PERM_ERROR
        self.states = ["LOW_ACTIVITY", "HIGH_FREQUENCY_SCAN", "SENSITIVE_FILE_PROBING", "PAYLOAD_UPLOADED"]
        self.actions = ["NORMAL_RESPONSE", "TARPIT_DELAY", "DYNAMIC_INJECTION", "FAKE_PERM_ERROR"]
        
        # Q-table initialization with default heuristic rewards
        self.q_table = {
            s: {a: 0.0 for a in self.actions} for s in self.states
        }
        # Pre-seed Q-values based on deception objectives (maximizing dwell time & intelligence)
        self.q_table["HIGH_FREQUENCY_SCAN"]["TARPIT_DELAY"] = 5.0
        self.q_table["SENSITIVE_FILE_PROBING"]["DYNAMIC_INJECTION"] = 10.0
        self.q_table["PAYLOAD_UPLOADED"]["NORMAL_RESPONSE"] = 8.0

        # Session activity trackers
        self.session_cmd_timestamps = {}
        self.session_states = {}
        self.session_scan_thresholds = {}  # Issue 5: per-session randomized scan-detection threshold

    def _get_scan_threshold(self, session_id):
        """Issue 5: each session gets its own randomized command-rate
        threshold for HIGH_FREQUENCY_SCAN detection, chosen once and reused,
        instead of a single fixed global value. A fixed threshold is
        trivially fingerprintable -- an attacker can binary-search for the
        exact command count where response timing changes."""
        from honeypot.config import HIGH_FREQUENCY_SCAN_THRESHOLD_MIN, HIGH_FREQUENCY_SCAN_THRESHOLD_MAX
        if session_id not in self.session_scan_thresholds:
            self.session_scan_thresholds[session_id] = random.randint(
                HIGH_FREQUENCY_SCAN_THRESHOLD_MIN, HIGH_FREQUENCY_SCAN_THRESHOLD_MAX
            )
        return self.session_scan_thresholds[session_id]

    def get_session_state(self, session_id, last_cmd, last_args, has_uploaded_file=False):
        now = time.time()
        if session_id not in self.session_cmd_timestamps:
            self.session_cmd_timestamps[session_id] = []
        
        timestamps = self.session_cmd_timestamps[session_id]
        timestamps.append(now)
        # Keep window of last 10 seconds
        timestamps = [t for t in timestamps if now - t <= 10.0]
        self.session_cmd_timestamps[session_id] = timestamps

        cmd_rate = len(timestamps)

        if has_uploaded_file:
            return "PAYLOAD_UPLOADED"
        elif last_cmd in ["RETR", "SIZE"] and any(s in (last_args or "").lower() for s in ["config.php", "passwd", "shadow", "backup"]):
            return "SENSITIVE_FILE_PROBING"
        elif cmd_rate > self._get_scan_threshold(session_id):  # Randomized per-session scan threshold
            return "HIGH_FREQUENCY_SCAN"
        else:
            return "LOW_ACTIVITY"

    def select_action(self, state, epsilon=0.1):
        """Epsilon-greedy action selection"""
        if random.random() < epsilon:
            return random.choice(self.actions)
        else:
            state_actions = self.q_table.get(state, {})
            return max(state_actions, key=state_actions.get) if state_actions else "NORMAL_RESPONSE"

    def evaluate_response(self, session_id, command, args, vfs_instance, has_uploaded=False):
        """
        Determines response modification (delay, dynamic file creation, or response code modification)
        and runs dynamic Q-learning updates.
        """
        prev_state = self.session_states.get(session_id, "LOW_ACTIVITY")
        state = self.get_session_state(session_id, command, args, has_uploaded)
        self.session_states[session_id] = state
        action = self.select_action(state)

        # Update Q-values dynamically based on deception outcome
        reward = 1.0
        if state == "PAYLOAD_UPLOADED":
            reward = 10.0
        elif state == "SENSITIVE_FILE_PROBING":
            reward = 5.0
        elif state == "HIGH_FREQUENCY_SCAN" and action == "TARPIT_DELAY":
            reward = 8.0
        self.update_q_value(prev_state, action, reward, state)

        from honeypot.config import BASELINE_JITTER_MIN_SECONDS, BASELINE_JITTER_MAX_SECONDS

        result = {
            "state": state,
            "action": action,
            # Issue 5: every response carries a small baseline jitter, not
            # just TARPIT_DELAY responses. This removes the stark "0s vs
            # 2-4.5s" binary signal an attacker could use to fingerprint
            # exactly when the tarpit engaged.
            "delay_seconds": round(random.uniform(BASELINE_JITTER_MIN_SECONDS, BASELINE_JITTER_MAX_SECONDS), 3),
            "injected_file": None,
            "fake_perm_error": False
        }

        if action == "TARPIT_DELAY":
            # Tarpit response delay (2.0 to 4.5 seconds) to slow down automated brute-force bots
            result["delay_seconds"] = round(random.uniform(2.0, 4.5), 2)
            logger.info(f"[Adaptive Engine] Tarpitting session {session_id[:8]} for {result['delay_seconds']}s")

        elif action == "DYNAMIC_INJECTION":
            # Dynamically inject a believable honeypot asset based on which
            # sensitive file the attacker is probing (covers every keyword
            # that can trigger SENSITIVE_FILE_PROBING, not just config.php).
            args_lower = (args or "").lower()
            injection_map = [
                ("config.php", "/var/www/database_backup.sql",
                 "-- AegisFTP Dynamic Deception Trap Dump\n"
                 "CREATE TABLE admin_credentials (id INT, email VARCHAR(100), pass_hash VARCHAR(255));\n"
                 "INSERT INTO admin_credentials VALUES (1, 'sysadmin@internal-corp.local', '$2y$10$e8N3v...fakehash');\n",
                 "www-data"),
                ("passwd", "/etc/passwd.bak",
                 "root:x:0:0:root:/root:/bin/bash\n"
                 "backup-admin:x:1500:1500:Backup Service Account:/home/backup-admin:/bin/bash\n"
                 "svc-deploy:x:1501:1501:Deploy Automation:/home/svc-deploy:/bin/bash\n",
                 "root"),
                ("shadow", "/root/.ssh/id_rsa.bak",
                 "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                 "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn\n"
                 "NhAAAAAwEAAQAAAYEA0fakehoneypottrapkeycontentdonotusethisanywhererea\n"
                 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\n"
                 "-----END OPENSSH PRIVATE KEY-----\n",
                 "root"),
                ("backup", "/home/admin/db_credentials.txt",
                 "# Production DB Credentials - DO NOT COMMIT\n"
                 "DB_HOST=10.0.4.12\n"
                 "DB_USER=dbadmin\n"
                 "DB_PASS=Tr4pp3d-Cr3dent1al-2026!\n",
                 "admin"),
            ]

            if command == "RETR":
                for keyword, injected_path, content, owner in injection_map:
                    if keyword in args_lower:
                        vfs_instance.add_file(injected_path, content.encode('utf-8'), owner=owner)
                        result["injected_file"] = injected_path
                        logger.info(
                            f"[Adaptive Engine] Injected honeypot asset {injected_path} into VFS "
                            f"for session {session_id[:8]} (probe keyword: {keyword})"
                        )
                        break

        elif action == "FAKE_PERM_ERROR":
            if command in ["RETR", "CWD", "DELE"] and any(s in (args or "").lower() for s in ["shadow", "backup", "root"]):
                result["fake_perm_error"] = True
                logger.info(f"[Adaptive Engine] Enacted FAKE_PERM_ERROR deception for {command} {args}")

        return result

    def update_q_value(self, state, action, reward, next_state, alpha=0.1, gamma=0.9):
        """Q-Learning Bellman equation update"""
        max_next = max(self.q_table[next_state].values()) if next_state in self.q_table else 0.0
        current_q = self.q_table[state][action]
        new_q = current_q + alpha * (reward + gamma * max_next - current_q)
        self.q_table[state][action] = round(new_q, 4)

adaptive_engine = AdaptiveDeceptionEngine()


# Per-IP authentication trap state (module-level). Twisted's reactor is a
# single-threaded event loop (DatabaseManager is the only piece of this
# codebase that talks to another thread, and it has its own lock), so plain
# dict access here is safe without additional locking.
#
# This exists to close two gaps in the auth trap:
#   1. Per-session-only counters reset on every new TCP connection, so a
#      connection-per-attempt brute forcer (e.g. Hydra in its default mode)
#      never accumulates failures and never reaches the trap.
#   2. A fixed "grant on attempt N" threshold is a honeypot fingerprint.
# Each IP gets its own accumulating counter and its own randomized threshold,
# chosen once and reused for the lifetime of that IP's entry.
_ip_auth_state = {}


def get_ip_auth_state(client_ip: str) -> dict:
    """Returns (creating if needed) the per-IP auth trap state for client_ip."""
    from honeypot.config import FAILED_ATTEMPTS_THRESHOLD_MIN, FAILED_ATTEMPTS_THRESHOLD_MAX
    if client_ip not in _ip_auth_state:
        _ip_auth_state[client_ip] = {
            "failed_attempts": 0,
            "threshold": random.randint(FAILED_ATTEMPTS_THRESHOLD_MIN, FAILED_ATTEMPTS_THRESHOLD_MAX),
            "granted": False,
        }
    return _ip_auth_state[client_ip]


class ResponsePlan:
    """
    Response Plan object returned by decide_response seam.
    Defines the response text, protocol status code, short label response type,
    tarpit delay, and any extra metadata for execution.
    """
    def __init__(self, response_text: str, response_status: int, response_type: str, delay_seconds: float = 0.0, extra: dict = None):
        self.response_text = response_text
        self.response_status = int(response_status) if isinstance(response_status, int) or (isinstance(response_status, str) and response_status.isdigit()) else response_status
        self.response_type = response_type
        self.delay_seconds = delay_seconds
        self.extra = extra or {}

    def to_dict(self):
        return {
            "response_text": self.response_text,
            "response_status": self.response_status,
            "response_type": self.response_type,
            "delay_seconds": self.delay_seconds,
            "extra": self.extra
        }


# Autonomous Adapter Session Store (enables decide_response to be called with only 3 arguments per Job 3)
_adapter_sessions = {}

def get_adapter_session(session_id: str, client_ip: str = None) -> dict:
    if session_id not in _adapter_sessions:
        from honeypot.config import FAILED_ATTEMPTS_THRESHOLD
        ip_state = get_ip_auth_state(client_ip) if client_ip else None
        _adapter_sessions[session_id] = {
            "authenticated": False,
            "authenticated_user": None,
            "username": None,
            # Seed from this attacker IP's accumulated state (if any) so a
            # fresh connection from a known-bad IP continues where the last
            # connection left off, instead of resetting to 0.
            "failed_attempts": ip_state["failed_attempts"] if ip_state else 0,
            "failed_threshold": ip_state["threshold"] if ip_state else FAILED_ATTEMPTS_THRESHOLD,
            "cwd": "/var/www",
            "has_uploaded": False,
            "client_ip": client_ip,
            # Issue 6: post-authentication containment state.
            "listed_dirs": set(),
            "destructive_op_count": 0,
            "stor_count": 0,
        }
    return _adapter_sessions[session_id]


def decide_response(session_id: str, action: str, parameters: dict, context: dict = None) -> ResponsePlan:
    """
    Decides what fake content/behavior to return for this interaction.
    Complies with Adapter Contract Job 3: single choke point seam.
    Can be called as decide_response(session_id, action, parameters).
    """
    from honeypot.config import FTP_WELCOME_BANNER, FAILED_ATTEMPTS_THRESHOLD, MAX_DESTRUCTIVE_OPS_PER_SESSION
    from honeypot.virtual_fs import shared_vfs

    client_ip_hint = (context or {}).get("client_ip")
    sess = get_adapter_session(session_id, client_ip=client_ip_hint)
    if context:
        for k, v in context.items():
            if v is not None:
                sess[k] = v

    vfs_instance = sess.get("vfs") or shared_vfs
    has_uploaded = sess.get("has_uploaded", False)

    # Extract command string
    raw_action = (action or "").strip()
    parts = raw_action.split(" ", 1)
    cmd = parts[0].upper()
    raw_args = parameters.get("raw_args", parts[1] if len(parts) > 1 else "")

    # Query Adaptive Deception Engine for delay & dynamic injection
    delay_seconds = 0.0
    if vfs_instance:
        adaptive_eval = adaptive_engine.evaluate_response(session_id, cmd, raw_args, vfs_instance, has_uploaded)
        delay_seconds = adaptive_eval.get("delay_seconds", 0.0)

    # Response decision mapping
    if cmd == "CONNECT":
        return ResponsePlan(FTP_WELCOME_BANNER, 220, "welcome_banner", delay_seconds=delay_seconds)

    elif cmd == "USER":
        raw_user = (parameters.get("username") or raw_args.strip() or "").strip()
        username = raw_user if raw_user else "anonymous"
        sess["username"] = username
        return ResponsePlan(f"331 Password required for {username}.", 331, "auth_prompt", delay_seconds=delay_seconds)

    elif cmd == "PASS":
        if sess.get("authenticated", False):
            return ResponsePlan("230 Already logged in.", 230, "auth_success", delay_seconds=delay_seconds, extra={"authenticated": True})

        client_ip = sess.get("client_ip")
        ip_state = get_ip_auth_state(client_ip) if client_ip else None

        # If this attacker IP already crossed its trap threshold on an
        # earlier connection, grant access immediately rather than making
        # it re-earn entry. This mirrors real brute-force tooling, which
        # moves on to using credentials it believes it found, and it avoids
        # the trap resetting to a predictable "attempt 1" on every reconnect.
        if ip_state and ip_state.get("granted"):
            failed_attempts = sess.get("failed_attempts", 0) + 1
            sess["failed_attempts"] = failed_attempts
            auth_user = parameters.get("username") or sess.get("username") or "anonymous"
            sess["authenticated"] = True
            sess["authenticated_user"] = auth_user
            return ResponsePlan(
                "230 User logged in, proceed.", 230, "auth_success",
                delay_seconds=delay_seconds,
                extra={"authenticated": True, "failed_attempts": failed_attempts, "authenticated_user": auth_user}
            )

        failed_attempts = sess.get("failed_attempts", 0) + 1
        threshold = sess.get("failed_threshold", FAILED_ATTEMPTS_THRESHOLD)
        sess["failed_attempts"] = failed_attempts
        if ip_state is not None:
            ip_state["failed_attempts"] = failed_attempts

        if failed_attempts <= threshold:
            return ResponsePlan(
                "530 Login incorrect.", 530, "auth_failure",
                delay_seconds=delay_seconds,
                extra={"authenticated": False, "failed_attempts": failed_attempts}
            )
        else:
            auth_user = parameters.get("username") or sess.get("username") or "anonymous"
            sess["authenticated"] = True
            sess["authenticated_user"] = auth_user
            if ip_state is not None:
                ip_state["granted"] = True
            return ResponsePlan(
                "230 User logged in, proceed.", 230, "auth_success",
                delay_seconds=delay_seconds,
                extra={"authenticated": True, "failed_attempts": failed_attempts, "authenticated_user": auth_user}
            )

    elif cmd == "SYST":
        return ResponsePlan("215 UNIX Type: L8", 215, "system_info", delay_seconds=delay_seconds)

    elif cmd == "FEAT":
        feat_str = (
            "211-Features:\r\n"
            " EPSV\r\n"
            " PASV\r\n"
            " UTF8\r\n"
            " REST STREAM\r\n"
            " SIZE\r\n"
            " MDTM\r\n"
            " MLSD\r\n"
            " TVFS\r\n"
            "211 End"
        )
        return ResponsePlan(feat_str, 211, "features_list", delay_seconds=delay_seconds)

    elif cmd in ["PWD", "XPWD"]:
        if not sess.get("authenticated", False):
            return ResponsePlan("530 Please login with USER and PASS.", 530, "auth_required", delay_seconds=delay_seconds)
        cwd = sess.get("cwd", "/var/www")
        return ResponsePlan(f'257 "{cwd}" is current directory.', 257, "working_directory", delay_seconds=delay_seconds)

    elif cmd == "CWD":
        if not sess.get("authenticated", False):
            return ResponsePlan("530 Please login with USER and PASS.", 530, "auth_required", delay_seconds=delay_seconds)
        if adaptive_eval.get("fake_perm_error"):
            return ResponsePlan("550 Permission denied.", 550, "permission_denied", delay_seconds=delay_seconds)
        cwd = sess.get("cwd", "/var/www")
        target = parameters.get("path") or raw_args.strip()
        if vfs_instance:
            target_path = vfs_instance.normalize_path(cwd, target)
            node = vfs_instance.get_node(target_path)
            if node and node.is_dir:
                sess["cwd"] = target_path
                return ResponsePlan(
                    f'250 Directory successfully changed to "{target_path}".', 250, "directory_change",
                    delay_seconds=delay_seconds, extra={"new_cwd": target_path}
                )
        return ResponsePlan("550 Failed to change directory.", 550, "directory_error", delay_seconds=delay_seconds)

    elif cmd == "CDUP":
        if not sess.get("authenticated", False):
            return ResponsePlan("530 Please login with USER and PASS.", 530, "auth_required", delay_seconds=delay_seconds)
        cwd = sess.get("cwd", "/var/www")
        if vfs_instance:
            target_path = vfs_instance.normalize_path(cwd, "..")
            sess["cwd"] = target_path
            return ResponsePlan(
                f'250 Directory successfully changed to "{target_path}".', 250, "directory_change",
                delay_seconds=delay_seconds, extra={"new_cwd": target_path}
            )
        return ResponsePlan("550 Failed to change directory.", 550, "directory_error", delay_seconds=delay_seconds)

    elif cmd == "TYPE":
        if not sess.get("authenticated", False):
            return ResponsePlan("530 Please login with USER and PASS.", 530, "auth_required", delay_seconds=delay_seconds)
        mode = (parameters.get("type") or raw_args.strip()).upper()
        if mode in ["A", "I"]:
            return ResponsePlan(f"200 Switching to {mode} mode.", 200, "transfer_type", delay_seconds=delay_seconds, extra={"transfer_type": mode})
        return ResponsePlan("504 Command not implemented for that parameter.", 504, "error_response", delay_seconds=delay_seconds)

    elif cmd == "PASV":
        if not sess.get("authenticated", False):
            return ResponsePlan("530 Please login with USER and PASS.", 530, "auth_required", delay_seconds=delay_seconds)
        pasv_str = sess.get("pasv_str", "227 Entering Passive Mode.")
        return ResponsePlan(pasv_str, 227, "passive_mode", delay_seconds=delay_seconds)

    elif cmd == "PORT":
        if not sess.get("authenticated", False):
            return ResponsePlan("530 Please login with USER and PASS.", 530, "auth_required", delay_seconds=delay_seconds)
        if sess.get("bounce_detected", False):
            return ResponsePlan("501 Illegal PORT command (FTP Bounce Attack detected).", 501, "bounce_attack_blocked", delay_seconds=delay_seconds)
        p_parts = raw_args.strip().split(",")
        if len(p_parts) != 6 or not all(p.strip().isdigit() and 0 <= int(p.strip()) <= 255 for p in p_parts):
            return ResponsePlan("501 Syntax error in parameters or arguments.", 501, "syntax_error", delay_seconds=delay_seconds)
        return ResponsePlan("200 PORT command successful.", 200, "active_mode", delay_seconds=delay_seconds)

    elif cmd in ["LIST", "NLST"]:
        if not sess.get("authenticated", False):
            return ResponsePlan("530 Please login with USER and PASS.", 530, "auth_required", delay_seconds=delay_seconds)
        cwd = sess.get("cwd", "/var/www")
        list_target = parameters.get("path") or raw_args.strip()
        if list_target and not list_target.startswith("-"):
            listing_path = vfs_instance.normalize_path(cwd, list_target) if vfs_instance else cwd
        else:
            listing_path = cwd
        # Issue 6: record that this directory has now been "discovered" by
        # the attacker, which is the behavioral trigger that unlocks RETR
        # on any sensitive file inside it (see the RETR handler below).
        sess.setdefault("listed_dirs", set()).add(listing_path)
        return ResponsePlan("150 Here comes the directory listing.", 150, "directory_listing", delay_seconds=delay_seconds)

    elif cmd == "RETR":
        if not sess.get("authenticated", False):
            return ResponsePlan("530 Please login with USER and PASS.", 530, "auth_required", delay_seconds=delay_seconds)
        if adaptive_eval.get("fake_perm_error"):
            return ResponsePlan("550 Permission denied.", 550, "permission_denied", delay_seconds=delay_seconds)
        filename = parameters.get("path") or parameters.get("filename") or raw_args.strip()
        if not filename:
            return ResponsePlan("501 Syntax error, filename required.", 501, "syntax_error", delay_seconds=delay_seconds)
        cwd = sess.get("cwd", "/var/www")
        if vfs_instance:
            target_path = vfs_instance.normalize_path(cwd, filename)
            # Issue 6: sensitive bait files require the attacker to have
            # already listed their containing directory in this session --
            # a scripted "connect, auth, grab /etc/shadow" one-liner that
            # never looks around first gets a plain permission error.
            if _is_sensitive_path(target_path):
                parent_dir = posixpath.dirname(target_path) or "/"
                if parent_dir not in sess.get("listed_dirs", set()):
                    return ResponsePlan("550 Permission denied.", 550, "permission_denied", delay_seconds=delay_seconds)
            content = vfs_instance.get_file_content(target_path)
            if content is not None:
                return ResponsePlan(
                    f"150 Opening BINARY mode data connection for {filename} ({len(content)} bytes).", 150, "file_download",
                    delay_seconds=delay_seconds, extra={"content": content}
                )
        return ResponsePlan("550 Failed to open file.", 550, "file_error", delay_seconds=delay_seconds)

    elif cmd == "STOR":
        if not sess.get("authenticated", False):
            return ResponsePlan("530 Please login with USER and PASS.", 530, "auth_required", delay_seconds=delay_seconds)
        filename = parameters.get("path") or parameters.get("filename") or raw_args.strip()
        if not filename:
            return ResponsePlan("501 Syntax error, filename required.", 501, "syntax_error", delay_seconds=delay_seconds)
        # Issue 6: cap uploads per session so a scripted mass-upload can't
        # fill the fake filesystem indefinitely, while staying interactive
        # up to that point.
        stor_count = sess.get("stor_count", 0)
        if stor_count >= MAX_DESTRUCTIVE_OPS_PER_SESSION:
            return ResponsePlan("452 Insufficient storage space, upload quota exceeded.", 452, "quota_exceeded", delay_seconds=delay_seconds)
        cwd = sess.get("cwd", "/var/www")
        if vfs_instance:
            target_path = vfs_instance.normalize_path(cwd, filename)
            target_node = vfs_instance.get_node(target_path)
            if target_node and target_node.is_dir:
                return ResponsePlan("553 Target is a directory.", 553, "file_error", delay_seconds=delay_seconds)
        sess["stor_count"] = stor_count + 1
        return ResponsePlan("150 Ok to send data.", 150, "file_upload", delay_seconds=delay_seconds)

    elif cmd == "SIZE":
        if not sess.get("authenticated", False):
            return ResponsePlan("530 Please login with USER and PASS.", 530, "auth_required", delay_seconds=delay_seconds)
        cwd = sess.get("cwd", "/var/www")
        target = parameters.get("path") or parameters.get("filename") or raw_args.strip()
        if vfs_instance:
            target_path = vfs_instance.normalize_path(cwd, target)
            node = vfs_instance.get_node(target_path)
            if node and not node.is_dir:
                return ResponsePlan(f"213 {node.size}", 213, "file_size", delay_seconds=delay_seconds)
        return ResponsePlan("550 Could not get file size.", 550, "file_error", delay_seconds=delay_seconds)

    elif cmd == "DELE":
        if not sess.get("authenticated", False):
            return ResponsePlan("530 Please login with USER and PASS.", 530, "auth_required", delay_seconds=delay_seconds)
        cwd = sess.get("cwd", "/var/www")
        filename = parameters.get("path") or parameters.get("filename") or raw_args.strip()
        if not filename:
            return ResponsePlan("501 Syntax error, filename required.", 501, "syntax_error", delay_seconds=delay_seconds)
        # Issue 6: cap destructive operations (DELE + RMD share this budget)
        # per session so a scripted wipe can't destroy the whole fake
        # filesystem, while staying interactive up to that point.
        destructive_count = sess.get("destructive_op_count", 0)
        if destructive_count >= MAX_DESTRUCTIVE_OPS_PER_SESSION:
            return ResponsePlan("550 Permission denied.", 550, "destructive_limit_reached", delay_seconds=delay_seconds)
        if vfs_instance:
            target_path = vfs_instance.normalize_path(cwd, filename)
            node = vfs_instance.get_node(target_path)
            if node and node.is_dir:
                return ResponsePlan("550 Cannot delete directory with DELE (use RMD).", 550, "file_error", delay_seconds=delay_seconds)
            if getattr(vfs_instance, "remove_file", None):
                removed = vfs_instance.remove_file(target_path)
            else:
                removed = vfs_instance.remove_node(target_path)
            if removed:
                sess["destructive_op_count"] = destructive_count + 1
                return ResponsePlan("250 Delete operation successful.", 250, "file_delete", delay_seconds=delay_seconds)
        return ResponsePlan("550 File not found.", 550, "file_error", delay_seconds=delay_seconds)

    elif cmd == "MKD":
        if not sess.get("authenticated", False):
            return ResponsePlan("530 Please login with USER and PASS.", 530, "auth_required", delay_seconds=delay_seconds)
        cwd = sess.get("cwd", "/var/www")
        target = parameters.get("path") or raw_args.strip()
        if not target:
            return ResponsePlan("501 Syntax error, directory name required.", 501, "syntax_error", delay_seconds=delay_seconds)
        if vfs_instance:
            target_path = vfs_instance.normalize_path(cwd, target)
            if vfs_instance.get_node(target_path):
                return ResponsePlan("550 Directory or file already exists.", 550, "directory_error", delay_seconds=delay_seconds)
            if vfs_instance.create_dir(target_path):
                return ResponsePlan(f'257 "{target_path}" directory created.', 257, "directory_create", delay_seconds=delay_seconds)
        return ResponsePlan("550 Create directory operation failed.", 550, "directory_error", delay_seconds=delay_seconds)

    elif cmd == "RMD":
        if not sess.get("authenticated", False):
            return ResponsePlan("530 Please login with USER and PASS.", 530, "auth_required", delay_seconds=delay_seconds)
        cwd = sess.get("cwd", "/var/www")
        target = parameters.get("path") or raw_args.strip()
        if not target:
            return ResponsePlan("501 Syntax error, directory name required.", 501, "syntax_error", delay_seconds=delay_seconds)
        # Issue 6: shares the destructive-op budget with DELE.
        destructive_count = sess.get("destructive_op_count", 0)
        if destructive_count >= MAX_DESTRUCTIVE_OPS_PER_SESSION:
            return ResponsePlan("550 Permission denied.", 550, "destructive_limit_reached", delay_seconds=delay_seconds)
        if vfs_instance:
            target_path = vfs_instance.normalize_path(cwd, target)
            node = vfs_instance.get_node(target_path)
            if not node or not node.is_dir:
                return ResponsePlan("550 Directory not found.", 550, "directory_error", delay_seconds=delay_seconds)
            if node.children and len(node.children) > 0:
                return ResponsePlan("550 Directory not empty.", 550, "directory_error", delay_seconds=delay_seconds)
            if getattr(vfs_instance, "remove_dir", None):
                removed = vfs_instance.remove_dir(target_path)
            else:
                removed = vfs_instance.remove_node(target_path)
            if removed:
                sess["destructive_op_count"] = destructive_count + 1
                return ResponsePlan("250 Remove directory operation successful.", 250, "directory_remove", delay_seconds=delay_seconds)
        return ResponsePlan("550 Directory not found.", 550, "directory_error", delay_seconds=delay_seconds)

    elif cmd == "NOOP":
        return ResponsePlan("200 OK.", 200, "noop_response", delay_seconds=delay_seconds)

    elif cmd in ["EPSV", "EPSV4"]:
        if not sess.get("authenticated", False):
            return ResponsePlan("530 Please login with USER and PASS.", 530, "auth_required", delay_seconds=delay_seconds)
        epsv_str = sess.get("pasv_str", "229 Entering Extended Passive Mode.")
        return ResponsePlan(epsv_str, 229, "extended_passive_mode", delay_seconds=delay_seconds)

    elif cmd in ["AUTH", "PBSZ", "PROT"]:
        # This honeypot mimics a ProFTPD build without mod_tls, so a real
        # server would reject these with "not implemented" rather than
        # a generic "unknown command" (which is a honeypot tell on its own).
        return ResponsePlan(f"502 {cmd} command not implemented.", 502, "tls_not_supported", delay_seconds=delay_seconds)

    elif cmd == "OPTS":
        opts_val = raw_args.strip().upper()
        if opts_val in ["UTF8 ON", "UTF8"]:
            return ResponsePlan("200 UTF8 set to on.", 200, "opts_response", delay_seconds=delay_seconds)
        return ResponsePlan("501 Option not understood.", 501, "opts_error", delay_seconds=delay_seconds)

    elif cmd == "MDTM":
        if not sess.get("authenticated", False):
            return ResponsePlan("530 Please login with USER and PASS.", 530, "auth_required", delay_seconds=delay_seconds)
        cwd = sess.get("cwd", "/var/www")
        target = parameters.get("path") or raw_args.strip()
        if not target:
            return ResponsePlan("501 Syntax error, filename required.", 501, "syntax_error", delay_seconds=delay_seconds)
        if vfs_instance:
            target_path = vfs_instance.normalize_path(cwd, target)
            node = vfs_instance.get_node(target_path)
            if node and not node.is_dir:
                mtime_str = time.strftime("%Y%m%d%H%M%S", time.gmtime(node.mtime))
                return ResponsePlan(f"213 {mtime_str}", 213, "file_mtime", delay_seconds=delay_seconds)
        return ResponsePlan("550 File not found.", 550, "file_error", delay_seconds=delay_seconds)

    elif cmd == "RNFR":
        if not sess.get("authenticated", False):
            return ResponsePlan("530 Please login with USER and PASS.", 530, "auth_required", delay_seconds=delay_seconds)
        cwd = sess.get("cwd", "/var/www")
        target = parameters.get("path") or raw_args.strip()
        if not target:
            return ResponsePlan("501 Syntax error, filename required.", 501, "syntax_error", delay_seconds=delay_seconds)
        if vfs_instance:
            target_path = vfs_instance.normalize_path(cwd, target)
            node = vfs_instance.get_node(target_path)
            if node:
                sess["rnfr_path"] = target_path
                return ResponsePlan("350 File exists, ready for destination name.", 350, "rename_from", delay_seconds=delay_seconds)
        return ResponsePlan("550 File or directory not found.", 550, "file_error", delay_seconds=delay_seconds)

    elif cmd == "RNTO":
        if not sess.get("authenticated", False):
            return ResponsePlan("530 Please login with USER and PASS.", 530, "auth_required", delay_seconds=delay_seconds)
        rnfr_path = sess.pop("rnfr_path", None)
        if not rnfr_path:
            return ResponsePlan("503 Bad sequence of commands (RNFR required first).", 503, "bad_sequence", delay_seconds=delay_seconds)
        cwd = sess.get("cwd", "/var/www")
        target = parameters.get("path") or raw_args.strip()
        if not target:
            return ResponsePlan("501 Syntax error, filename required.", 501, "syntax_error", delay_seconds=delay_seconds)
        if vfs_instance:
            dest_path = vfs_instance.normalize_path(cwd, target)
            src_node = vfs_instance.get_node(rnfr_path)
            if src_node and not src_node.is_dir:
                dest_existing = vfs_instance.get_node(dest_path)
                if dest_existing and dest_existing.is_dir:
                    return ResponsePlan("553 Target is a directory.", 553, "file_error", delay_seconds=delay_seconds)
                vfs_instance.add_file(dest_path, src_node.content, owner=src_node.owner, group=src_node.group)
                vfs_instance.remove_file(rnfr_path)
                return ResponsePlan("250 Rename successful.", 250, "rename_success", delay_seconds=delay_seconds)
        return ResponsePlan("550 Rename failed.", 550, "file_error", delay_seconds=delay_seconds)

    elif cmd == "APPE":
        if not sess.get("authenticated", False):
            return ResponsePlan("530 Please login with USER and PASS.", 530, "auth_required", delay_seconds=delay_seconds)
        filename = parameters.get("path") or raw_args.strip()
        if not filename:
            return ResponsePlan("501 Syntax error, filename required.", 501, "syntax_error", delay_seconds=delay_seconds)
        # Issue 6: shares the upload budget with STOR.
        stor_count = sess.get("stor_count", 0)
        if stor_count >= MAX_DESTRUCTIVE_OPS_PER_SESSION:
            return ResponsePlan("452 Insufficient storage space, upload quota exceeded.", 452, "quota_exceeded", delay_seconds=delay_seconds)
        cwd = sess.get("cwd", "/var/www")
        if vfs_instance:
            target_path = vfs_instance.normalize_path(cwd, filename)
            target_node = vfs_instance.get_node(target_path)
            if target_node and target_node.is_dir:
                return ResponsePlan("553 Target is a directory.", 553, "file_error", delay_seconds=delay_seconds)
        sess["stor_count"] = stor_count + 1
        return ResponsePlan("150 Ok to send data.", 150, "file_append", delay_seconds=delay_seconds)

    elif cmd == "ABOR":
        return ResponsePlan("226 ABOR command successful.", 226, "abort_transfer", delay_seconds=delay_seconds)

    elif cmd == "STAT":
        target = parameters.get("path") or raw_args.strip()
        if target:
            if not sess.get("authenticated", False):
                return ResponsePlan("530 Please login with USER and PASS.", 530, "auth_required", delay_seconds=delay_seconds)
            return ResponsePlan(
                f"213-Status of {target}:\r\n Not available in this mode.\r\n213 End of status.",
                213, "status_response", delay_seconds=delay_seconds
            )
        login_line = ("     Logged in as " + (sess.get("authenticated_user") or "anonymous")) if sess.get("authenticated", False) else "     Not logged in"
        status_text = (
            "211-FTP server status:\r\n"
            f"     Connected to {sess.get('client_ip', 'unknown')}\r\n"
            f"{login_line}\r\n"
            "     TYPE: Binary\r\n"
            "211 End of status."
        )
        return ResponsePlan(status_text, 211, "status_response", delay_seconds=delay_seconds)

    elif cmd == "HELP":
        help_text = (
            "214-The following commands are recognized:\r\n"
            " USER PASS SYST FEAT PWD  CWD  CDUP TYPE PASV EPSV PORT\r\n"
            " LIST NLST RETR STOR APPE DELE MKD  RMD  SIZE MDTM RNFR\r\n"
            " RNTO ABOR STAT HELP NOOP MODE STRU SITE QUIT\r\n"
            "214 Help OK."
        )
        return ResponsePlan(help_text, 214, "help_response", delay_seconds=delay_seconds)

    elif cmd == "MODE":
        mode_val = raw_args.strip().upper()
        if mode_val == "S":
            return ResponsePlan("200 Mode set to S.", 200, "mode_response", delay_seconds=delay_seconds)
        return ResponsePlan("504 Command not implemented for that parameter.", 504, "error_response", delay_seconds=delay_seconds)

    elif cmd == "STRU":
        stru_val = raw_args.strip().upper()
        if stru_val == "F":
            return ResponsePlan("200 Structure set to F.", 200, "stru_response", delay_seconds=delay_seconds)
        return ResponsePlan("504 Command not implemented for that parameter.", 504, "error_response", delay_seconds=delay_seconds)

    elif cmd == "SITE":
        site_args = raw_args.strip()
        site_cmd = site_args.split(" ", 1)[0].upper() if site_args else ""
        if site_cmd == "CHMOD":
            return ResponsePlan("200 SITE CHMOD command successful.", 200, "site_chmod", delay_seconds=delay_seconds)
        elif site_cmd == "HELP":
            return ResponsePlan("214 SITE CHMOD", 214, "site_help", delay_seconds=delay_seconds)
        return ResponsePlan(f"502 SITE command '{site_cmd}' not implemented.", 502, "site_unimplemented", delay_seconds=delay_seconds)

    elif cmd == "QUIT":
        _adapter_sessions.pop(session_id, None)
        return ResponsePlan("221 Goodbye.", 221, "goodbye", delay_seconds=delay_seconds)

    return ResponsePlan(f"500 Unknown command '{cmd}'.", 500, "unknown_command", delay_seconds=delay_seconds)

