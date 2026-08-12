import os

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Network Config
FTP_HOST = os.environ.get("FTP_HOST", "0.0.0.0")
FTP_PORT = int(os.environ.get("FTP_PORT", 21))
PASV_PORT_MIN = int(os.environ.get("PASV_PORT_MIN", 50000))
PASV_PORT_MAX = int(os.environ.get("PASV_PORT_MAX", 50010))

# Honeypot Auth Logic Config
# The credential trap works on a PER-IP basis (see threat_intel.py). Failed PASS
# attempts accumulate per source IP across connections, so connection-rotating
# bots (Hydra -t N) still trip the bait. Each IP is granted a RANDOM threshold
# within [AUTH_THRESHOLD_MIN, AUTH_THRESHOLD_MAX] so the "always grant on
# attempt 4" fingerprint is removed (V2).
#
#   Attempts 1..T-1 for an IP  -> 530 Login incorrect
#   Attempt T and beyond        -> 230 User logged in (T is per-IP random)
#
# FAILED_ATTEMPTS_THRESHOLD is kept as the fallback default used by
# decide_response() when no per-IP threshold is available (e.g. direct unit
# tests), preserving backward compatibility.
FAILED_ATTEMPTS_THRESHOLD = int(os.environ.get("FAILED_ATTEMPTS_THRESHOLD", 3))
AUTH_THRESHOLD_MIN = int(os.environ.get("AUTH_THRESHOLD_MIN", 3))
AUTH_THRESHOLD_MAX = int(os.environ.get("AUTH_THRESHOLD_MAX", 7))

# Per-IP tripwire (V6): after this many failed attempts, or this many
# completed trap cycles (grants), the source IP is banned and future
# connections are refused (and reported to AbuseIPDB when a key is set).
MAX_IP_FAILED_ATTEMPTS = int(os.environ.get("MAX_IP_FAILED_ATTEMPTS", 100))
TRIPWIRE_GRANT_CYCLES = int(os.environ.get("TRIPWIRE_GRANT_CYCLES", 50))

# Response timing (V5): unconditional jittered latency on every reply so
# response time is never a pure function of command rate (anti-fingerprint).
# The large tarpit delay is applied probabilistically, not deterministically.
JITTER_DELAY_MIN = float(os.environ.get("JITTER_DELAY_MIN", 0.05))
JITTER_DELAY_MAX = float(os.environ.get("JITTER_DELAY_MAX", 0.35))
TARPIT_DELAY_MIN = float(os.environ.get("TARPIT_DELAY_MIN", 1.5))
TARPIT_DELAY_MAX = float(os.environ.get("TARPIT_DELAY_MAX", 6.0))
TARPIT_PROBABILITY = float(os.environ.get("TARPIT_PROBABILITY", 0.6))

# Storage Paths
DATA_DIR = os.path.join(BASE_DIR, "data")
QUARANTINE_DIR = os.path.join(BASE_DIR, "quarantine")
DB_PATH = os.path.join(DATA_DIR, "honeypot.db")

# Flask Dashboard Config
DASHBOARD_HOST = os.environ.get("DASHBOARD_HOST", "0.0.0.0")
DASHBOARD_PORT = int(os.environ.get("DASHBOARD_PORT", 5000))
SECRET_KEY = os.environ.get("SECRET_KEY", "ftp-honeypot-secret-key-2026")

# Dashboard HTTP Basic Auth (V7): the dashboard exposes credential/hash data,
# so it must not be publicly reachable without credentials.
DASHBOARD_USER = os.environ.get("DASHBOARD_USER", "admin")
DASHBOARD_PASSWORD = os.environ.get("DASHBOARD_PASSWORD", "aegisftp-admin-2026")

# Server Banner
FTP_WELCOME_BANNER = os.environ.get("FTP_WELCOME_BANNER", "220 ProFTPD 1.3.5a Server (Debian FTP Server)")

# Ensure required directories exist
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(QUARANTINE_DIR, exist_ok=True)
