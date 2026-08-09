import sqlite3
import datetime
import threading
import os
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
            
            # Sessions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    client_ip TEXT NOT NULL,
                    client_port INTEGER NOT NULL,
                    start_time TEXT NOT NULL,
                    end_time TEXT,
                    failed_attempts INTEGER DEFAULT 0,
                    authenticated_user TEXT,
                    status TEXT DEFAULT 'ACTIVE'
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
            
            # Command logs table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS command_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    client_ip TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    command TEXT NOT NULL,
                    arguments TEXT,
                    response_code INTEGER,
                    FOREIGN KEY (session_id) REFERENCES sessions (session_id)
                )
            """)
            
            # Quarantined files table
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
                    FOREIGN KEY (session_id) REFERENCES sessions (session_id)
                )
            """)
            
            conn.commit()
            conn.close()

    def create_session(self, session_id, client_ip, client_port):
        now = datetime.datetime.utcnow().isoformat()
        with self._lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO sessions (session_id, client_ip, client_port, start_time, failed_attempts, status)
                VALUES (?, ?, ?, ?, 0, 'ACTIVE')
            """, (session_id, client_ip, client_port, now))
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

    def log_command(self, session_id, client_ip, command, arguments, response_code=None):
        now = datetime.datetime.utcnow().isoformat()
        with self._lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO command_logs (session_id, client_ip, timestamp, command, arguments, response_code)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (session_id, client_ip, now, command, arguments, response_code))
            conn.commit()
            conn.close()

    def log_quarantined_file(self, session_id, client_ip, original_filename, quarantine_filename, file_size, sha256_hash):
        now = datetime.datetime.utcnow().isoformat()
        with self._lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO quarantined_files (session_id, client_ip, original_filename, quarantine_filename, file_size, sha256_hash, upload_timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (session_id, client_ip, original_filename, quarantine_filename, file_size, sha256_hash, now))
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

# Singleton instance
db = DatabaseManager()
