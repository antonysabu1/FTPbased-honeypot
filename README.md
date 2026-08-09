# AegisFTP - High Interaction Twisted FTP Honeypot

A high-interaction FTP honeypot written from scratch using Python and the **Twisted** networking framework. Designed for threat intelligence gathering, brute-force dictionary logging, malware payload quarantine, and interactive web dashboard visualization.

---

## Key Features

- **Custom Protocol Handler Built From Scratch**: Fully custom FTP control and data protocol handlers over Twisted's `LineReceiver` (no Cowrie or Dionaea dependencies).
- **Brute-Force Dictionary Capture**: Automatically rejects the first **3 login attempts** (`530 Login incorrect`), capturing brute-force dictionary combinations (e.g., Hydra, Medusa, custom bots), and accepts any credentials starting on the **4th attempt** (`230 User logged in`).
- **Fake Virtual Linux Filesystem**:
  - Implements a virtual node tree with realistic Linux filesystem entries.
  - Includes target files: `/etc/passwd`, `/etc/shadow`, `/etc/hostname`, `/var/www/config.php` (DB credentials), `/var/www/html/index.php`, `/var/log/syslog`, `/home/admin/readme.txt`, `/home/admin/backup.sql`, `/tmp/`.
  - Dynamically updates when attackers upload files (`STOR`), allowing them to see and re-download their uploaded payloads.
- **SQLite Database Logging**:
  - Tracks session lifecycle (`sessions`), brute-force credential pairs (`auth_attempts`), raw FTP commands (`command_logs`), and quarantined payloads (`quarantined_files`).
- **Malware Quarantine Vault**:
  - Saves all uploaded files into `./quarantine/` with unique timestamp prefixes and SHA-256 content hashes.
- **Flask Live Web Dashboard**:
  - Real-time dark obsidian dashboard running on port 5000.
  - Interactive table feeds for Sessions, Brute-Force Dictionary Logs, Command Stream, and Quarantined Payloads.
  - Built-in Payload Inspector modal with UTF-8 text preview and Hex Dump viewer.
- **Docker Containerization**:
  - Complete `Dockerfile` and `docker-compose.yml` configuration ready for instant deployment.

---

## Directory Structure

```text
C:\Users\amalk\Downloads\ftp\FTPbased-honeypot\
├── honeypot/
│   ├── __init__.py
│   ├── config.py           # Port, threshold & path configurations
│   ├── database.py         # SQLite thread-safe database manager
│   ├── virtual_fs.py       # In-memory virtual Linux filesystem node hierarchy
│   └── ftp_server.py       # Custom Twisted FTP protocol & PASV/PORT data handlers
├── dashboard/
│   ├── __init__.py
│   ├── app.py              # Flask Web application & REST endpoints
│   ├── templates/
│   │   └── index.html      # HTML5 live monitoring interface
│   └── static/
│       ├── css/
│       │   └── style.css   # Dark glassmorphic design system
│       └── js/
│           └── dashboard.js# Real-time polling, search & payload viewer logic
├── quarantine/             # Storage folder for uploaded payloads (.gitignore protected)
├── data/                   # SQLite database storage folder
├── run_honeypot.py         # Starter script running Twisted FTP + Flask concurrent
├── requirements.txt        # Python package dependencies
├── Dockerfile              # Docker container setup
├── docker-compose.yml      # Docker compose configuration
└── README.md               # Documentation
```

---

## Quick Start (Local Setup)

### 1. Install Dependencies

Ensure Python 3.9+ is installed, then run:

```bash
pip install -r requirements.txt
```

### 2. Run Honeypot & Dashboard

To listen on default ports (FTP: Port 21 or custom, Dashboard: Port 5000):

*Note: On Linux/macOS or Windows port 21 may require Administrator/sudo privileges. You can also override `FTP_PORT` via environment variable.*

```bash
python run_honeypot.py
```

- **FTP Honeypot**: `ftp://localhost:21`
- **Flask Dashboard**: `http://localhost:5000`

---

## Docker Deployment

Deploy AegisFTP using Docker Compose:

```bash
docker-compose up --build -d
```

To stop the container:

```bash
docker-compose down
```

---

## Testing the Honeypot

You can simulate attacker activity using standard FTP tools or Python:

### 1. Brute-Force Authentication Test
Attempt logging in with different credentials:
- Attempt #1: `USER root`, `PASS 123456` -> Returns `530 Login incorrect.`
- Attempt #2: `USER admin`, `PASS admin123` -> Returns `530 Login incorrect.`
- Attempt #3: `USER user`, `PASS password` -> Returns `530 Login incorrect.`
- Attempt #4: `USER root`, `PASS secret` -> Returns `230 User logged in, proceed.`

### 2. Exploring Virtual Filesystem
Once logged in:
- Run `PWD` -> `/var/www`
- Run `CWD /etc` -> `250 Directory successfully changed`
- Run `LIST` -> Shows Linux directory listing including `passwd` and `shadow`
- Run `RETR /etc/passwd` -> Downloads virtual passwd file

### 3. File Upload & Quarantine
- Run `STOR malware_test.sh` -> Uploads file. Content is saved to `./quarantine/`, logged to SQLite, and viewable in the Flask dashboard.

---

## Disclaimer

This honeypot is built strictly for **educational and research purposes**. Always deploy honeypots in isolated environments/networks.