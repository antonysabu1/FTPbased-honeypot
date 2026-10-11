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

    def test_adapter_contract_logging(self):
        session_id = "ftp-session-uuid-001"
        client_ip = "10.0.0.5"

        event_data = {
            "event_id": "event-uuid-12345",
            "timestamp": "2026-08-12T08:00:00Z",
            "protocol": "ftp",
            "source_ip": client_ip,
            "session_id": session_id,
            "action": "RETR /var/www/config.php",
            "parameters": {"command": "RETR", "path": "/var/www/config.php"},
            "raw_metadata": {"raw_line": "RETR /var/www/config.php", "client_port": 12345},
            "session_source": "protocol_native",
            "response_status": 150,
            "response_type": "file_download"
        }

        event_id = self.db.log_event(event_data)
        self.assertEqual(event_id, "event-uuid-12345")

        events = self.db.get_events(limit=10)
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["protocol"], "ftp")
        self.assertEqual(ev["source_ip"], client_ip)
        self.assertEqual(ev["session_id"], session_id)
        self.assertEqual(ev["action"], "RETR /var/www/config.php")
        self.assertEqual(ev["session_source"], "protocol_native")
        self.assertEqual(str(ev["response_status"]), "150")
        self.assertEqual(ev["response_type"], "file_download")

    def test_decide_response_seam(self):
        from honeypot.adaptive import decide_response, ResponsePlan

        session_id = "test-seam-session"

        plan = decide_response(session_id, "CONNECT", {})
        self.assertIsInstance(plan, ResponsePlan)
        self.assertEqual(plan.response_status, 220)
        self.assertEqual(plan.response_type, "welcome_banner")

        plan_user = decide_response(session_id, "USER admin", {"username": "admin"})
        self.assertEqual(plan_user.response_status, 331)
        self.assertEqual(plan_user.response_type, "auth_prompt")

        plan_pass = decide_response(session_id, "PASS ******", {"password": "wrong"}, context={"failed_attempts": 0, "failed_threshold": 3})
        self.assertEqual(plan_pass.response_status, 530)
        self.assertEqual(plan_pass.response_type, "auth_failure")
        self.assertFalse(plan_pass.extra.get("authenticated"))

        plan_pass_ok = decide_response(session_id, "PASS ******", {"password": "secret"}, context={"failed_attempts": 3, "failed_threshold": 3})
        self.assertEqual(plan_pass_ok.response_status, 230)
        self.assertEqual(plan_pass_ok.response_type, "auth_success")
        self.assertTrue(plan_pass_ok.extra.get("authenticated"))

    def test_auth_enforcement_on_sensitive_commands(self):
        from honeypot.adaptive import decide_response
        session_id = "test-auth-required"

        for cmd in ["PWD", "TYPE I", "PASV", "PORT 127,0,0,1,10,20", "LIST", "RETR test.txt"]:
            parts = cmd.split(" ", 1)
            raw_args = parts[1] if len(parts) > 1 else ""
            plan = decide_response(session_id, cmd, {"command": parts[0], "raw_args": raw_args}, context={"authenticated": False})
            self.assertEqual(plan.response_status, 530, f"Command {cmd} should require authentication (530)")

    def test_port_syntax_validation(self):
        from honeypot.adaptive import decide_response
        session_id = "test-port-syntax"
        ctx = {"authenticated": True}

        # Valid PORT
        plan_ok = decide_response(session_id, "PORT 127,0,0,1,195,80", {"raw_args": "127,0,0,1,195,80"}, context=ctx)
        self.assertEqual(plan_ok.response_status, 200)

        # Invalid PORT (wrong count, non-integers, out of range)
        for bad_port in ["127,0,0,1", "bad,port,arguments", "127,0,0,1,999,999", ""]:
            plan_bad = decide_response(session_id, f"PORT {bad_port}", {"raw_args": bad_port}, context=ctx)
            self.assertEqual(plan_bad.response_status, 501, f"PORT {bad_port} should return 501 syntax error")

    def test_vfs_directory_protection_and_file_list(self):
        # Cannot overwrite existing directory with file
        res = self.vfs.add_file("/etc", b"evil content")
        self.assertFalse(res)
        etc_node = self.vfs.get_node("/etc")
        self.assertTrue(etc_node.is_dir)

        # Cannot recreate existing directory
        mkd_res = self.vfs.create_dir("/etc")
        self.assertFalse(mkd_res)

        # Single file LIST returns file stat instead of None
        file_list = self.vfs.list_dir("/etc/passwd")
        self.assertIsNotNone(file_list)
        self.assertEqual(len(file_list), 1)
        self.assertIn("passwd", file_list[0])

        # RMD fails on non-empty directory
        rmd_res = self.vfs.remove_dir("/etc")
        self.assertFalse(rmd_res)

        # DELE fails on directory
        dele_res = self.vfs.remove_file("/etc")
        self.assertFalse(dele_res)

    def test_threat_intel_docker_and_private_ip(self):
        from honeypot.threat_intel import threat_intel
        # Docker private subnet 172.17.0.1
        res_docker = threat_intel.lookup_geoip("172.17.0.1")
        self.assertEqual(res_docker["country"], "Private Network")
        self.assertEqual(res_docker["country_code"], "LOCAL")

        # Localhost
        res_local = threat_intel.lookup_geoip("127.0.0.1")
        self.assertEqual(res_local["country"], "Private Network")

    def test_database_quarantine_helpers(self):
        session_id = "test-q-helper"
        self.db.create_session(session_id, "127.0.0.1", 12345)
        self.db.log_quarantined_file(session_id, "127.0.0.1", "exploit.php", "2026_exploit.php", 100, "dummyhash", "PHP_Shell")
        
        files = self.db.get_quarantined_files(limit=1)
        self.assertEqual(len(files), 1)
        file_id = files[0]["id"]

        q_file = self.db.get_quarantined_file(file_id)
        self.assertIsNotNone(q_file)
        self.assertEqual(q_file["original_filename"], "exploit.php")

        none_file = self.db.get_quarantined_file(999999)
        self.assertIsNone(none_file)

    def test_pasv_listener_lifecycle(self):
        from honeypot.ftp_server import FTPControlProtocol
        proto = FTPControlProtocol()
        msg1 = proto._prepare_pasv_response()
        self.assertIsNotNone(msg1)
        self.assertIn("227 Entering Passive Mode", msg1)
        self.assertIsNotNone(proto.pasv_port)
        self.assertIsNotNone(proto.pasv_listener)

        # Calling it a second time properly closes previous port and allocates cleanly
        msg2 = proto._prepare_pasv_response()
        self.assertIsNotNone(msg2)
        self.assertIn("227 Entering Passive Mode", msg2)

        # Clean shutdown
        proto.close_pasv_listener()
        self.assertIsNone(proto.pasv_listener)
        self.assertIsNone(proto.pasv_port)

    def test_mitre_mapper_brute_force_isolation(self):
        from honeypot.mitre_mapper import mitre_mapper
        # PASS command triggers brute force
        tags_pass = mitre_mapper.classify_command("PASS", "password", failed_attempts=1)
        tech_ids = [t["technique_id"] for t in tags_pass]
        self.assertIn("T1110", tech_ids)

        # Subsequent PWD command should NOT be tagged as brute force even if failed_attempts > 0
        tags_pwd = mitre_mapper.classify_command("PWD", "", failed_attempts=2)
        tech_ids_pwd = [t["technique_id"] for t in tags_pwd]
        self.assertNotIn("T1110", tech_ids_pwd)
        self.assertIn("T1083", tech_ids_pwd)

    def test_flask_dashboard_endpoints(self):
        from dashboard.app import app
        client = app.test_client()

        # UI Root
        res_ui = client.get("/")
        self.assertEqual(res_ui.status_code, 200)
        self.assertIn(b"AegisFTP", res_ui.data)

        # APIs
        for ep in ["/api/stats", "/api/sessions", "/api/auth_attempts", "/api/commands", "/api/events", "/api/quarantine"]:
            res = client.get(ep)
            self.assertEqual(res.status_code, 200, f"Endpoint {ep} failed")
            data = res.get_json()
            self.assertIsNotNone(data)


if __name__ == "__main__":
    unittest.main()
