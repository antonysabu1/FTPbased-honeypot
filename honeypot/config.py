import os

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Network Config
FTP_HOST = os.environ.get("FTP_HOST", "0.0.0.0")
FTP_PORT = int(os.environ.get("FTP_PORT", 21))
PASV_PORT_MIN = int(os.environ.get("PASV_PORT_MIN", 50000))
PASV_PORT_MAX = int(os.environ.get("PASV_PORT_MAX", 50010))

# Honeypot Auth Logic Config
# Requires 3 failed login attempts before allowing access to any credentials.
# Attempts 1, 2, and 3 return 530 Login incorrect.
# Attempt 4 and beyond for a session will accept any username/password.
FAILED_ATTEMPTS_THRESHOLD = int(os.environ.get("FAILED_ATTEMPTS_THRESHOLD", 3))

# Storage Paths
DATA_DIR = os.path.join(BASE_DIR, "data")
QUARANTINE_DIR = os.path.join(BASE_DIR, "quarantine")
DB_PATH = os.path.join(DATA_DIR, "honeypot.db")

# Flask Dashboard Config
DASHBOARD_HOST = os.environ.get("DASHBOARD_HOST", "0.0.0.0")
DASHBOARD_PORT = int(os.environ.get("DASHBOARD_PORT", 5000))
SECRET_KEY = os.environ.get("SECRET_KEY", "ftp-honeypot-secret-key-2026")

# Server Banner
FTP_WELCOME_BANNER = os.environ.get("FTP_WELCOME_BANNER", "220 ProFTPD 1.3.5a Server (Debian FTP Server)")

# Ensure required directories exist
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(QUARANTINE_DIR, exist_ok=True)
