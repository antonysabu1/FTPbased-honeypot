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

    def test_adapter_contract_decide_response_pure_3_args(self):
        """Adapter Contract Job 3: decide_response(session_id, action, parameters) with ONLY 3 args"""
        from honeypot.adaptive import decide_response, ResponsePlan

        session_id = "pure-3arg-session-uuid"

        # 1. Connect
        plan_connect = decide_response(session_id, "CONNECT", {})
        self.assertIsInstance(plan_connect, ResponsePlan)
        self.assertEqual(plan_connect.response_status, 220)

        # 2. USER
        plan_user = decide_response(session_id, "USER admin", {"command": "USER", "username": "admin"})
        self.assertEqual(plan_user.response_status, 331)

        # 3. Multiple PASS attempts to simulate brute-force threshold
        for _ in range(3):
            plan_fail = decide_response(session_id, "PASS wrong", {"command": "PASS", "password": "wrong"})
            self.assertEqual(plan_fail.response_status, 530)
            self.assertEqual(plan_fail.response_type, "auth_failure")

        # 4th PASS succeeds (threshold = 3)
        plan_ok = decide_response(session_id, "PASS admin123", {"command": "PASS", "password": "admin123"})
        self.assertEqual(plan_ok.response_status, 230)
        self.assertEqual(plan_ok.response_type, "auth_success")

        # 4. PWD - session remembers authentication & initial cwd
        plan_pwd = decide_response(session_id, "PWD", {"command": "PWD"})
        self.assertEqual(plan_pwd.response_status, 257)
        self.assertIn("/var/www", plan_pwd.response_text)

        # 5. CWD - changes directory and updates session state
        plan_cwd = decide_response(session_id, "CWD /etc", {"command": "CWD", "path": "/etc"})
        self.assertEqual(plan_cwd.response_status, 250)

        # 6. PWD again - verifies cwd persisted across 3-arg calls
        plan_pwd2 = decide_response(session_id, "PWD", {"command": "PWD"})
        self.assertEqual(plan_pwd2.response_status, 257)
        self.assertIn("/etc", plan_pwd2.response_text)

        # 7. RETR file in /etc
        plan_retr = decide_response(session_id, "RETR passwd", {"command": "RETR", "path": "passwd"})
        self.assertEqual(plan_retr.response_status, 150)
        self.assertEqual(plan_retr.response_type, "file_download")

        # 8. QUIT cleans up session
        plan_quit = decide_response(session_id, "QUIT", {"command": "QUIT"})
        self.assertEqual(plan_quit.response_status, 221)

    def test_adapter_contract_exact_event_schema_fields(self):
        """Adapter Contract Job 2 & 2a: verify exact 11 fields schema"""
        from honeypot.database import log_event
        import json

        session_id = "test-schema-uuid"
        expected_fields = {
            "event_id", "timestamp", "protocol", "source_ip", "session_id",
            "action", "parameters", "raw_metadata", "session_source",
            "response_status", "response_type"
        }

        event_payload = {
            "event_id": "custom-uuid-112233",
            "timestamp": "2026-10-11T06:00:00Z",
            "protocol": "ftp",
            "source_ip": "203.0.113.42",
            "session_id": session_id,
            "action": "USER admin",
            "parameters": {"command": "USER", "username": "admin", "raw_args": "admin"},
            "raw_metadata": {"client_port": 49152},
            "session_source": "protocol_native",
            "response_status": 331,
            "response_type": "auth_prompt"
        }

        # Verify our payload keys match exactly
        self.assertEqual(set(event_payload.keys()), expected_fields)
        self.assertEqual(event_payload["protocol"], "ftp")
        self.assertEqual(event_payload["session_source"], "protocol_native")

        # Log and retrieve
        self.db.log_event(event_payload)
        events = self.db.get_events(limit=1)
        self.assertEqual(len(events), 1)
        logged = events[0]

        for field in expected_fields:
            self.assertIn(field, logged, f"Missing required field {field} in logged event")

        logged_params = json.loads(logged["parameters"]) if isinstance(logged["parameters"], str) else logged["parameters"]
        self.assertEqual(logged_params.get("username"), "admin")

    def test_adapter_contract_safety_isolation(self):
        """Adapter Contract Job 1 Safety: complete sandboxing and zero host execution"""
        # 1. Path traversal escape attempts
        escaped_path = self.vfs.normalize_path("/var/www", "../../../../../../../Windows/System32")
        # In VFS, path normalization collapses root slashes to /Windows/System32
        self.assertEqual(escaped_path, "/Windows/System32")
        # VFS does NOT map this to the real OS host filesystem
        node = self.vfs.get_node(escaped_path)
        self.assertIsNone(node)

        # 2. Host file access check
        self.assertIsNone(self.vfs.get_file_content("C:\\Windows\\win.ini"))
        self.assertIsNone(self.vfs.get_file_content("C:\\boot.ini"))

        # 3. File modifications in VFS stay purely in-memory
        test_content = b"TEST_HONEYPOT_ISOLATION_DATA"
        self.vfs.add_file("/var/www/test_isolation.txt", test_content)
        self.assertEqual(self.vfs.get_file_content("/var/www/test_isolation.txt"), test_content)
        self.assertFalse(os.path.exists("C:\\var\\www\\test_isolation.txt"))


    def test_epsv_response(self):
        from honeypot.adaptive import decide_response
        ctx = {"authenticated": True, "pasv_str": "229 Entering Extended Passive Mode (|||50003|)."}

        plan = decide_response("test-epsv-session", "EPSV", {"command": "EPSV", "raw_args": ""}, context=ctx)
        self.assertEqual(plan.response_status, 229)
        self.assertEqual(plan.response_type, "extended_passive_mode")
        self.assertIn("Extended Passive Mode", plan.response_text)

        plan_noauth = decide_response("test-epsv-noauth", "EPSV", {"command": "EPSV"}, context={"authenticated": False})
        self.assertEqual(plan_noauth.response_status, 530)

    def test_feat_advertises_new_capabilities(self):
        from honeypot.adaptive import decide_response
        plan = decide_response("test-feat-session", "FEAT", {"command": "FEAT"})
        self.assertEqual(plan.response_status, 211)
        for feature in ["EPSV", "MDTM", "TVFS", "PASV", "UTF8", "SIZE"]:
            self.assertIn(feature, plan.response_text)

    def test_auth_pbsz_prot_rejected_as_not_implemented(self):
        from honeypot.adaptive import decide_response
        for cmd in ["AUTH TLS", "PBSZ 0", "PROT P"]:
            parts = cmd.split(" ", 1)
            plan = decide_response("test-tls-session", cmd, {"command": parts[0], "raw_args": parts[1] if len(parts) > 1 else ""})
            self.assertEqual(plan.response_status, 502, f"{cmd} should return 502 Not Implemented")
            self.assertEqual(plan.response_type, "tls_not_supported")

    def test_opts_utf8(self):
        from honeypot.adaptive import decide_response
        session_id = "test-opts-session"

        plan_ok = decide_response(session_id, "OPTS UTF8 ON", {"command": "OPTS", "raw_args": "UTF8 ON"})
        self.assertEqual(plan_ok.response_status, 200)

        plan_bad = decide_response(session_id, "OPTS FOO BAR", {"command": "OPTS", "raw_args": "FOO BAR"})
        self.assertEqual(plan_bad.response_status, 501)

if __name__ == "__main__":
    unittest.main()
