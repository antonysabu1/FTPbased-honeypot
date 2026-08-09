import unittest
import os
import tempfile
import sqlite3
import shutil

from honeypot.virtual_fs import VirtualFileSystem
from honeypot.database import DatabaseManager


class TestHoneypotComponents(unittest.TestCase):
    def setUp(self):
        self.vfs = VirtualFileSystem()
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_honeypot.db")
        self.db = DatabaseManager(self.db_path)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_virtual_fs_default_files(self):
        passwd_content = self.vfs.get_file_content("/etc/passwd")
        self.assertIsNotNone(passwd_content)
        self.assertIn(b"root:x:0:0:root", passwd_content)

        config_php = self.vfs.get_file_content("/var/www/config.php")
        self.assertIsNotNone(config_php)
        self.assertIn(b"DB_PASS", config_php)

    def test_virtual_fs_navigation(self):
        norm = self.vfs.normalize_path("/var/www", "html/config.php")
        self.assertEqual(norm, "/var/www/html/config.php")

        norm_up = self.vfs.normalize_path("/var/www/html", "..")
        self.assertEqual(norm_up, "/var/www")

        listing = self.vfs.list_dir("/etc")
        self.assertIsNotNone(listing)
        names = [entry.split()[-1] for entry in listing]
        self.assertIn("passwd", names)
        self.assertIn("shadow", names)

    def test_virtual_fs_dynamic_upload(self):
        test_payload = b"<?php echo 'shell'; ?>"
        res = self.vfs.add_file("/var/www/html/shell.php", test_payload)
        self.assertTrue(res)

        retrieved = self.vfs.get_file_content("/var/www/html/shell.php")
        self.assertEqual(retrieved, test_payload)

    def test_database_logging(self):
        session_id = "test-session-123"
        client_ip = "192.168.1.100"
        client_port = 54321

        self.db.create_session(session_id, client_ip, client_port)
        self.db.log_auth_attempt(session_id, client_ip, "admin", "123456", False, 1)
        self.db.log_auth_attempt(session_id, client_ip, "root", "root123", False, 2)
        self.db.log_auth_attempt(session_id, client_ip, "root", "password", False, 3)
        self.db.log_auth_attempt(session_id, client_ip, "root", "secret", True, 4)

        self.db.update_session_auth(session_id, 4, "root")
        self.db.log_command(session_id, client_ip, "PWD", "", 257)
        self.db.log_quarantined_file(session_id, client_ip, "shell.php", "q_shell.php", 22, "dummyhash")

        stats = self.db.get_stats()
        self.assertEqual(stats["total_sessions"], 1)
        self.assertEqual(stats["total_auth_attempts"], 4)
        self.assertEqual(stats["total_commands"], 1)
        self.assertEqual(stats["total_uploads"], 1)


if __name__ == "__main__":
    unittest.main()
