import sqlite3
import datetime
import threading
import os
import uuid
import json
from honeypot.config import DB_PATH

class DatabaseManager:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self._lock = threading.Lock()
        self.init_db()

    def get_connection(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        with self._lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            # Sessions table with GeoIP & AbuseIPDB metrics
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    client_ip TEXT NOT NULL,
                    client_port INTEGER NOT NULL,
                    country TEXT DEFAULT 'Unknown',
                    country_code TEXT DEFAULT 'XX',
                    city TEXT DEFAULT 'Unknown',
                    isp TEXT DEFAULT 'Unknown',
                    abuse_score INTEGER DEFAULT 0,
                    start_time TEXT NOT NULL,
                    end_time TEXT,
                    failed_attempts INTEGER DEFAULT 0,
                    authenticated_user TEXT,
                    status TEXT DEFAULT 'ACTIVE',
                    mitre_tags TEXT DEFAULT ''
                )
            """)
            
            # Auth attempts table (Brute-force log)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS auth_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    client_ip TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    username TEXT NOT NULL,
                    password TEXT NOT NULL,
                    success INTEGER NOT NULL,
                    attempt_number INTEGER NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES sessions (session_id)
                )
            """)
            
            # Command logs table with MITRE technique mapping
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS command_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    client_ip TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    command TEXT NOT NULL,
                    arguments TEXT,
                    response_code INTEGER,
                    mitre_technique TEXT DEFAULT '',
                    FOREIGN KEY (session_id) REFERENCES sessions (session_id)
                )
            """)
            
            # Quarantined files table with YARA scan matches
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS quarantined_files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    client_ip TEXT NOT NULL,
                    original_filename TEXT NOT NULL,
                    quarantine_filename TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    sha256_hash TEXT NOT NULL,
                    upload_timestamp TEXT NOT NULL,
                    yara_matches TEXT DEFAULT '',
                    FOREIGN KEY (session_id) REFERENCES sessions (session_id)
                )
            """)

            # Unified Events table conforming to the Adapter Contract schema
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    parameters TEXT,
                    raw_metadata TEXT,
                    session_source TEXT NOT NULL,
                    response_status TEXT,
                    response_type TEXT
                )
            """)

            conn.commit()
            conn.close()

        # V7: the DB holds harvested credentials - restrict to owner read/write.
        try:
            os.chmod(self.db_path, 0o600)
        except OSError:
            pass

    def log_event(self, event_data):
        """
        Logs an interaction using the shared Adapter Contract event schema.
        Fields:
        - event_id: str (UUID)
        - timestamp: str (ISO8601 UTC)
        - protocol: str ('ftp')
        - source_ip: str
        - session_id: str (UUID)
        - action: str
        - parameters: dict
        - raw_metadata: dict
        - session_source: 'protocol_native'
        - response_status: int or str
        - response_type: str
        """
        event_id = str(event_data.get("event_id") or uuid.uuid4())
        timestamp = str(event_data.get("timestamp") or (datetime.datetime.utcnow().isoformat() + "Z"))
        protocol = str(event_data.get("protocol") or "ftp")
        source_ip = str(event_data.get("source_ip") or "0.0.0.0")
        session_id = str(event_data.get("session_id") or "")
        action = str(event_data.get("action") or "")
        params = event_data.get("parameters") or {}
        raw_meta = event_data.get("raw_metadata") or {}
        session_source = str(event_data.get("session_source") or "protocol_native")
        response_status = str(event_data.get("response_status") if event_data.get("response_status") is not None else "")
        response_type = str(event_data.get("response_type") or "")

        parameters_str = json.dumps(params) if isinstance(params, (dict, list)) else str(params)
        raw_metadata_str = json.dumps(raw_meta) if isinstance(raw_meta, (dict, list)) else str(raw_meta)

        with self._lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO events (
                    event_id, timestamp, protocol, source_ip, session_id,
                    action, parameters, raw_metadata, session_source,
                    response_status, response_type
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event_id, timestamp, protocol, source_ip, session_id,
                action, parameters_str, raw_metadata_str, session_source,
                response_status, response_type
            ))
            conn.commit()
            conn.close()

        return event_id

    def create_session(self, session_id, client_ip, client_port, geo_info=None, abuse_score=0):
        now = datetime.datetime.utcnow().isoformat()
        geo = geo_info or {}
        with self._lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO sessions (session_id, client_ip, client_port, country, country_code, city, isp, abuse_score, start_time, failed_attempts, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 'ACTIVE')
            """, (
                session_id, client_ip, client_port,
                geo.get("country", "Unknown"), geo.get("country_code", "XX"),
                geo.get("city", "Unknown"), geo.get("isp", "Unknown"),
                abuse_score, now
            ))
            conn.commit()
            conn.close()

    def update_session_auth(self, session_id, failed_attempts, auth_user=None):
        with self._lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            if auth_user:
                cursor.execute("""
                    UPDATE sessions 
                    SET failed_attempts = ?, authenticated_user = ? 
                    WHERE session_id = ?
                """, (failed_attempts, auth_user, session_id))
            else:
                cursor.execute("""
                    UPDATE sessions 
                    SET failed_attempts = ? 
                    WHERE session_id = ?
                """, (failed_attempts, session_id))
            conn.commit()
            conn.close()

    def update_session_mitre_tags(self, session_id, tags_str):
        with self._lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute("UPDATE sessions SET mitre_tags = ? WHERE session_id = ?", (tags_str, session_id))
            conn.commit()
            conn.close()

    def close_session(self, session_id):
        now = datetime.datetime.utcnow().isoformat()
        with self._lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE sessions 
                SET end_time = ?, status = 'CLOSED' 
                WHERE session_id = ?
            """, (now, session_id))
            conn.commit()
            conn.close()

    def log_auth_attempt(self, session_id, client_ip, username, password, success, attempt_number):
        now = datetime.datetime.utcnow().isoformat()
        with self._lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO auth_attempts (session_id, client_ip, timestamp, username, password, success, attempt_number)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (session_id, client_ip, now, username, password, 1 if success else 0, attempt_number))
            conn.commit()
            conn.close()

    def log_command(self, session_id, client_ip, command, arguments, response_code=None, mitre_technique=""):
        now = datetime.datetime.utcnow().isoformat()
        with self._lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO command_logs (session_id, client_ip, timestamp, command, arguments, response_code, mitre_technique)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (session_id, client_ip, now, command, arguments, response_code, mitre_technique))
            conn.commit()
            conn.close()

    def log_quarantined_file(self, session_id, client_ip, original_filename, quarantine_filename, file_size, sha256_hash, yara_matches=""):
        now = datetime.datetime.utcnow().isoformat()
        with self._lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO quarantined_files (session_id, client_ip, original_filename, quarantine_filename, file_size, sha256_hash, upload_timestamp, yara_matches)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (session_id, client_ip, original_filename, quarantine_filename, file_size, sha256_hash, now, yara_matches))
            conn.commit()
            conn.close()

    # Dashboard Queries
    def get_stats(self):
        with self._lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM sessions")
            total_sessions = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM sessions WHERE status = 'ACTIVE'")
            active_sessions = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM auth_attempts")
            total_auth_attempts = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM command_logs")
            total_commands = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM quarantined_files")
            total_uploads = cursor.fetchone()[0]
            
            conn.close()
            return {
                "total_sessions": total_sessions,
                "active_sessions": active_sessions,
                "total_auth_attempts": total_auth_attempts,
                "total_commands": total_commands,
                "total_uploads": total_uploads
            }

    def get_recent_sessions(self, limit=50):
        with self._lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM sessions ORDER BY start_time DESC LIMIT ?
            """, (limit,))
            rows = [dict(r) for r in cursor.fetchall()]
            conn.close()
            return rows

    def get_auth_attempts(self, limit=100):
        with self._lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM auth_attempts ORDER BY timestamp DESC LIMIT ?
            """, (limit,))
            rows = [dict(r) for r in cursor.fetchall()]
            conn.close()
            return rows

    def get_command_logs(self, limit=100):
        with self._lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM command_logs ORDER BY timestamp DESC LIMIT ?
            """, (limit,))
            rows = [dict(r) for r in cursor.fetchall()]
            conn.close()
            return rows

    def get_quarantined_files(self, limit=50):
        with self._lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM quarantined_files ORDER BY upload_timestamp DESC LIMIT ?
            """, (limit,))
            rows = [dict(r) for r in cursor.fetchall()]
            conn.close()
            return rows

    def get_events(self, limit=100):
        with self._lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM events ORDER BY timestamp DESC LIMIT ?
            """, (limit,))
            rows = [dict(r) for r in cursor.fetchall()]
            conn.close()
            return rows

# Singleton instance
db = DatabaseManager()

def log_event(event_data):
    """Shared Adapter Contract log_event wrapper"""
    return db.log_event(event_data)

