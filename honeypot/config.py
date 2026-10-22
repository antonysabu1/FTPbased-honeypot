import os

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Network Config
FTP_HOST = os.environ.get("FTP_HOST", "0.0.0.0")
FTP_PORT = int(os.environ.get("FTP_PORT", 21))
PASV_PORT_MIN = int(os.environ.get("PASV_PORT_MIN", 50000))
PASV_PORT_MAX = int(os.environ.get("PASV_PORT_MAX", 50010))

# Honeypot Auth Logic Config
# Each attacker IP is assigned a randomized failed-attempt threshold chosen
# once from [FAILED_ATTEMPTS_THRESHOLD_MIN, FAILED_ATTEMPTS_THRESHOLD_MAX]
# (see honeypot/adaptive.py: get_ip_auth_state). This replaces a fixed
# "always grant on attempt 4" threshold, which was trivially fingerprintable.
# FAILED_ATTEMPTS_THRESHOLD is kept only as a fallback default for the rare
# case a session is created with no client IP available to seed per-IP state.
FAILED_ATTEMPTS_THRESHOLD = int(os.environ.get("FAILED_ATTEMPTS_THRESHOLD", 3))
FAILED_ATTEMPTS_THRESHOLD_MIN = int(os.environ.get("FAILED_ATTEMPTS_THRESHOLD_MIN", 3))
FAILED_ATTEMPTS_THRESHOLD_MAX = int(os.environ.get("FAILED_ATTEMPTS_THRESHOLD_MAX", 7))

# Storage Paths
DATA_DIR = os.path.join(BASE_DIR, "data")
QUARANTINE_DIR = os.path.join(BASE_DIR, "quarantine")
DB_PATH = os.path.join(DATA_DIR, "honeypot.db")

# Flask Dashboard Config
DASHBOARD_HOST = os.environ.get("DASHBOARD_HOST", "0.0.0.0")
DASHBOARD_PORT = int(os.environ.get("DASHBOARD_PORT", 5000))
SECRET_KEY = os.environ.get("SECRET_KEY", "ftp-honeypot-secret-key-2026")

# Issue 2: the dashboard shows attacker IPs, trapped credentials and
# quarantined malware -- it must not be reachable without a login. Set
# these via environment variables before exposing the dashboard beyond
# localhost; the defaults are only safe for local development.
DASHBOARD_USERNAME = os.environ.get("DASHBOARD_USERNAME", "admin")
DASHBOARD_PASSWORD = os.environ.get("DASHBOARD_PASSWORD", "aegisftp-change-me")

# Server Banner
FTP_WELCOME_BANNER = os.environ.get("FTP_WELCOME_BANNER", "220 ProFTPD 1.3.5a Server (Debian FTP Server)")

# Post-authentication containment (Issue 6): caps on destructive VFS
# operations per session. DELE + RMD share one budget, STOR + APPE share
# another. Once exceeded, the honeypot returns a realistic-looking error
# instead of performing the operation, so a scripted wipe/mass-upload can't
# actually destroy or flood the fake filesystem while the session otherwise
# stays interactive.
MAX_DESTRUCTIVE_OPS_PER_SESSION = int(os.environ.get("MAX_DESTRUCTIVE_OPS_PER_SESSION", 10))

# Tarpit timing side-channel mitigation (Issue 5). The HIGH_FREQUENCY_SCAN
# command-rate trigger is randomized per session instead of a single fixed
# global threshold, and a small baseline jitter is applied to every
# response (not just tarpitted ones) so "delay vs no delay" stops being a
# clean binary signal an attacker can use to detect the honeypot.
HIGH_FREQUENCY_SCAN_THRESHOLD_MIN = int(os.environ.get("HIGH_FREQUENCY_SCAN_THRESHOLD_MIN", 4))
HIGH_FREQUENCY_SCAN_THRESHOLD_MAX = int(os.environ.get("HIGH_FREQUENCY_SCAN_THRESHOLD_MAX", 8))
BASELINE_JITTER_MIN_SECONDS = float(os.environ.get("BASELINE_JITTER_MIN_SECONDS", 0.05))
BASELINE_JITTER_MAX_SECONDS = float(os.environ.get("BASELINE_JITTER_MAX_SECONDS", 0.25))

# Per-IP tripwire / escalation (Issue 7). Accumulates a weighted attack
# score per source IP, independent of (and surviving across) individual
# sessions, and flags the IP as high-risk once the score crosses this
# threshold. Escalation doesn't block the attacker -- a hard block just
# sends them elsewhere -- it biases the adaptive engine toward heavier
# deception for that IP for the rest of the engagement.
TRIPWIRE_ESCALATION_THRESHOLD = float(os.environ.get("TRIPWIRE_ESCALATION_THRESHOLD", 12.0))

# Ensure required directories exist
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(QUARANTINE_DIR, exist_ok=True)

# Issue 2: restrict filesystem permissions on the data/quarantine dirs
# (and the DB file itself, if it already exists) to owner-only. These
# hold trapped credentials and attacker-uploaded malware -- other local
# accounts on a shared host shouldn't be able to read them.
try:
    os.chmod(DATA_DIR, 0o700)
    os.chmod(QUARANTINE_DIR, 0o700)
    if os.path.exists(DB_PATH):
        os.chmod(DB_PATH, 0o600)
except OSError:
    # Best-effort -- e.g. unsupported on this filesystem, or the
    # directory is owned by a different user. Don't crash startup over it.
    pass
