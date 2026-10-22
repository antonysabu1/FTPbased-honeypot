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

        # 6a. LIST the directory first -- Issue 6's containment gate requires
        # this "discovery" step before a sensitive bait file (passwd) can be
        # RETR'd, so a scripted one-liner can't grab it on the first try.
        decide_response(session_id, "LIST", {"command": "LIST", "raw_args": ""})

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

    def test_mdtm_file_time(self):
        from honeypot.adaptive import decide_response
        session_id = "test-mdtm-session"
        ctx = {"authenticated": True, "vfs": self.vfs}

        plan_ok = decide_response(session_id, "MDTM /var/www/config.php", {"command": "MDTM", "path": "/var/www/config.php"}, context=ctx)
        self.assertEqual(plan_ok.response_status, 213)
        parts = plan_ok.response_text.split()
        self.assertEqual(parts[0], "213")
        self.assertTrue(parts[1].isdigit())
        self.assertEqual(len(parts[1]), 14)

        plan_missing = decide_response(session_id, "MDTM /no/such/file", {"command": "MDTM", "path": "/no/such/file"}, context=ctx)
        self.assertEqual(plan_missing.response_status, 550)

        plan_noauth = decide_response("test-mdtm-noauth", "MDTM /var/www/config.php", {"command": "MDTM", "path": "/var/www/config.php"}, context={"authenticated": False, "vfs": self.vfs})
        self.assertEqual(plan_noauth.response_status, 530)

    def test_rnfr_rnto_rename_flow(self):
        from honeypot.adaptive import decide_response
        session_id = "test-rename-session"
        ctx = {"authenticated": True, "vfs": self.vfs}

        plan_bad_seq = decide_response(session_id, "RNTO /home/admin/x.txt", {"command": "RNTO", "path": "/home/admin/x.txt"}, context=ctx)
        self.assertEqual(plan_bad_seq.response_status, 503)

        plan_rnfr_missing = decide_response(session_id, "RNFR /no/such/file", {"command": "RNFR", "path": "/no/such/file"}, context=ctx)
        self.assertEqual(plan_rnfr_missing.response_status, 550)

        plan_rnfr = decide_response(session_id, "RNFR /home/admin/readme.txt", {"command": "RNFR", "path": "/home/admin/readme.txt"}, context=ctx)
        self.assertEqual(plan_rnfr.response_status, 350)

        plan_rnto = decide_response(session_id, "RNTO /home/admin/renamed.txt", {"command": "RNTO", "path": "/home/admin/renamed.txt"}, context=ctx)
        self.assertEqual(plan_rnto.response_status, 250)

        self.assertIsNone(self.vfs.get_file_content("/home/admin/readme.txt"))
        self.assertIsNotNone(self.vfs.get_file_content("/home/admin/renamed.txt"))

        plan_rnto_again = decide_response(session_id, "RNTO /home/admin/again.txt", {"command": "RNTO", "path": "/home/admin/again.txt"}, context=ctx)
        self.assertEqual(plan_rnto_again.response_status, 503)

    def test_appe_returns_file_append_plan(self):
        from honeypot.adaptive import decide_response
        session_id = "test-appe-session"
        ctx = {"authenticated": True, "vfs": self.vfs}

        plan = decide_response(session_id, "APPE /var/log/syslog", {"command": "APPE", "path": "/var/log/syslog"}, context=ctx)
        self.assertEqual(plan.response_status, 150)
        self.assertEqual(plan.response_type, "file_append")

        plan_noauth = decide_response("test-appe-noauth", "APPE /var/log/syslog", {"command": "APPE", "path": "/var/log/syslog"}, context={"authenticated": False, "vfs": self.vfs})
        self.assertEqual(plan_noauth.response_status, 530)

    def test_abor_always_succeeds(self):
        from honeypot.adaptive import decide_response
        plan = decide_response("test-abor-session", "ABOR", {"command": "ABOR"}, context={"authenticated": False})
        self.assertEqual(plan.response_status, 226)
        self.assertEqual(plan.response_type, "abort_transfer")

    def test_stat_help_mode_stru_site_responses(self):
        from honeypot.adaptive import decide_response
        session_id = "test-misc-session"
        ctx = {"authenticated": True}

        plan_stat = decide_response(session_id, "STAT", {"command": "STAT", "raw_args": ""}, context=ctx)
        self.assertEqual(plan_stat.response_status, 211)
        self.assertIn("FTP server status", plan_stat.response_text)

        plan_help = decide_response(session_id, "HELP", {"command": "HELP"}, context=ctx)
        self.assertEqual(plan_help.response_status, 214)
        self.assertIn("RNFR", plan_help.response_text)

        plan_mode_ok = decide_response(session_id, "MODE S", {"command": "MODE", "raw_args": "S"}, context=ctx)
        self.assertEqual(plan_mode_ok.response_status, 200)
        plan_mode_bad = decide_response(session_id, "MODE Z", {"command": "MODE", "raw_args": "Z"}, context=ctx)
        self.assertEqual(plan_mode_bad.response_status, 504)

        plan_stru_ok = decide_response(session_id, "STRU F", {"command": "STRU", "raw_args": "F"}, context=ctx)
        self.assertEqual(plan_stru_ok.response_status, 200)
        plan_stru_bad = decide_response(session_id, "STRU R", {"command": "STRU", "raw_args": "R"}, context=ctx)
        self.assertEqual(plan_stru_bad.response_status, 504)

        plan_site_chmod = decide_response(session_id, "SITE CHMOD 755 file.txt", {"command": "SITE", "raw_args": "CHMOD 755 file.txt"}, context=ctx)
        self.assertEqual(plan_site_chmod.response_status, 200)
        plan_site_unknown = decide_response(session_id, "SITE FOO", {"command": "SITE", "raw_args": "FOO"}, context=ctx)
        self.assertEqual(plan_site_unknown.response_status, 502)

    def test_unknown_command_fallback_still_works(self):
        from honeypot.adaptive import decide_response
        plan = decide_response("test-unknown-session", "FOOBAR", {"command": "FOOBAR"}, context={"authenticated": True})
        self.assertEqual(plan.response_status, 500)
        self.assertEqual(plan.response_type, "unknown_command")


    def test_per_ip_auth_tracking_survives_reconnect(self):
        """Issue 1: Hydra-style connection-per-attempt brute forcing must still
        reach the trap, because failures accumulate per-IP, not just per-session."""
        from honeypot.adaptive import decide_response
        attacker_ip = "203.0.113.50"

        statuses = []
        for i in range(4):
            sid = f"hydra-session-{i}"
            plan = decide_response(
                sid, "PASS wrong",
                {"command": "PASS", "password": "wrong"},
                context={"vfs": self.vfs, "client_ip": attacker_ip, "failed_threshold": 3}
            )
            statuses.append(plan.response_status)

        self.assertEqual(statuses, [530, 530, 530, 230])

    def test_per_ip_auth_tracking_isolates_different_ips(self):
        """Issue 1: a different attacker IP must have its own independent counter."""
        from honeypot.adaptive import decide_response
        ip_a = "198.51.100.10"
        ip_b = "198.51.100.20"

        # Drive IP A through all 3 allowed failures (threshold=3 means
        # attempts 1-3 are still 530; only attempt 4 crosses it).
        for i in range(3):
            decide_response(
                f"ip-a-session-{i}", "PASS wrong", {"command": "PASS", "password": "wrong"},
                context={"vfs": self.vfs, "client_ip": ip_a, "failed_threshold": 3}
            )

        # IP B's first-ever attempt, on a separate session, must still be a
        # plain first failure, unaffected by IP A's accumulated count.
        plan_b = decide_response(
            "ip-b-session-0", "PASS wrong", {"command": "PASS", "password": "wrong"},
            context={"vfs": self.vfs, "client_ip": ip_b, "failed_threshold": 3}
        )
        self.assertEqual(plan_b.response_status, 530)

        # IP A's 4th attempt (new session, same IP) crosses its threshold.
        plan_a = decide_response(
            "ip-a-session-3", "PASS wrong", {"command": "PASS", "password": "wrong"},
            context={"vfs": self.vfs, "client_ip": ip_a, "failed_threshold": 3}
        )
        self.assertEqual(plan_a.response_status, 230)

    def test_per_ip_state_grants_fast_path_on_reconnect_after_trap_sprung(self):
        """Issue 1: once an IP has crossed its threshold, a brand new connection
        from that same IP should be granted immediately, not reset to attempt 1."""
        from honeypot.adaptive import decide_response
        attacker_ip = "192.0.2.77"

        for i in range(3):
            decide_response(
                f"sprung-session-{i}", "PASS wrong", {"command": "PASS", "password": "wrong"},
                context={"vfs": self.vfs, "client_ip": attacker_ip, "failed_threshold": 3}
            )
        plan_grant = decide_response(
            "sprung-session-3", "PASS wrong", {"command": "PASS", "password": "wrong"},
            context={"vfs": self.vfs, "client_ip": attacker_ip, "failed_threshold": 3}
        )
        self.assertEqual(plan_grant.response_status, 230)

        plan_reconnect = decide_response(
            "sprung-session-reconnect", "PASS anything", {"command": "PASS", "password": "anything"},
            context={"vfs": self.vfs, "client_ip": attacker_ip, "failed_threshold": 3}
        )
        self.assertEqual(plan_reconnect.response_status, 230)

    def test_randomized_threshold_is_not_fixed_and_stays_in_configured_range(self):
        """Issue 3: the per-IP threshold must not always be 3, and must fall
        within [FAILED_ATTEMPTS_THRESHOLD_MIN, FAILED_ATTEMPTS_THRESHOLD_MAX]."""
        from honeypot.adaptive import get_ip_auth_state
        from honeypot.config import FAILED_ATTEMPTS_THRESHOLD_MIN, FAILED_ATTEMPTS_THRESHOLD_MAX

        thresholds = set()
        for i in range(30):
            ip = f"203.0.113.{i}"
            state = get_ip_auth_state(ip)
            t = state["threshold"]
            self.assertGreaterEqual(t, FAILED_ATTEMPTS_THRESHOLD_MIN)
            self.assertLessEqual(t, FAILED_ATTEMPTS_THRESHOLD_MAX)
            thresholds.add(t)

        self.assertGreater(len(thresholds), 1)

    def test_randomized_threshold_is_stable_per_ip(self):
        """Issue 3: the threshold is chosen once per IP and reused, not re-rolled
        on every lookup (otherwise accumulated failures could never cross it)."""
        from honeypot.adaptive import get_ip_auth_state
        ip = "203.0.113.200"
        t1 = get_ip_auth_state(ip)["threshold"]
        t2 = get_ip_auth_state(ip)["threshold"]
        t3 = get_ip_auth_state(ip)["threshold"]
        self.assertEqual(t1, t2)
        self.assertEqual(t2, t3)


    def test_retr_sensitive_file_requires_directory_listing_first(self):
        """Issue 6: a scripted connect-auth-grab-passwd one-liner should not
        get the bait file on the very first RETR; it must LIST the
        directory first, matching how an attacker that looks around behaves."""
        from honeypot.adaptive import decide_response
        session_id = "test-sensitive-gate-session"
        ctx = {"authenticated": True, "vfs": self.vfs, "cwd": "/etc"}

        plan_blocked = decide_response(session_id, "RETR passwd", {"command": "RETR", "path": "passwd"}, context=ctx)
        self.assertEqual(plan_blocked.response_status, 550)

        decide_response(session_id, "LIST", {"command": "LIST", "raw_args": ""}, context=ctx)

        plan_allowed = decide_response(session_id, "RETR passwd", {"command": "RETR", "path": "passwd"}, context=ctx)
        self.assertEqual(plan_allowed.response_status, 150)

    def test_retr_non_sensitive_file_unaffected_by_listing_gate(self):
        """Issue 6: the containment gate must only apply to sensitive bait
        files; ordinary files remain accessible on the very first RETR."""
        from honeypot.adaptive import decide_response
        session_id = "test-nonsensitive-gate-session"
        ctx = {"authenticated": True, "vfs": self.vfs, "cwd": "/home/admin"}
        plan = decide_response(session_id, "RETR readme.txt", {"command": "RETR", "path": "readme.txt"}, context=ctx)
        self.assertEqual(plan.response_status, 150)

    def test_destructive_op_limit_on_dele_and_rmd(self):
        """Issue 6: DELE/RMD share a per-session destructive-op budget; once
        exceeded, further attempts are denied instead of mutating the VFS."""
        from honeypot.adaptive import decide_response
        from honeypot.config import MAX_DESTRUCTIVE_OPS_PER_SESSION
        session_id = "test-destructive-limit-session"
        ctx = {"authenticated": True, "vfs": self.vfs, "cwd": "/tmp"}

        for i in range(MAX_DESTRUCTIVE_OPS_PER_SESSION):
            self.vfs.add_file(f"/tmp/junk{i}.txt", b"x")
            plan = decide_response(session_id, f"DELE junk{i}.txt", {"command": "DELE", "path": f"junk{i}.txt"}, context=ctx)
            self.assertEqual(plan.response_status, 250)

        self.vfs.add_file("/tmp/one_too_many.txt", b"x")
        plan_denied = decide_response(session_id, "DELE one_too_many.txt", {"command": "DELE", "path": "one_too_many.txt"}, context=ctx)
        self.assertEqual(plan_denied.response_status, 550)
        self.assertIsNotNone(self.vfs.get_file_content("/tmp/one_too_many.txt"))

    def test_stor_quota_limit(self):
        """Issue 6: STOR/APPE share a per-session upload budget; once
        exceeded, the server reports a quota error instead of accepting
        more data."""
        from honeypot.adaptive import decide_response
        from honeypot.config import MAX_DESTRUCTIVE_OPS_PER_SESSION
        session_id = "test-stor-quota-session"
        ctx = {"authenticated": True, "vfs": self.vfs, "cwd": "/tmp"}

        for i in range(MAX_DESTRUCTIVE_OPS_PER_SESSION):
            plan = decide_response(session_id, f"STOR payload{i}.bin", {"command": "STOR", "path": f"payload{i}.bin"}, context=ctx)
            self.assertEqual(plan.response_status, 150)

        plan_denied = decide_response(session_id, "STOR one_too_many.bin", {"command": "STOR", "path": "one_too_many.bin"}, context=ctx)
        self.assertEqual(plan_denied.response_status, 452)

    def test_vfs_root_protected_from_destructive_operations(self):
        """Issue 6: operations targeting the VFS root must never succeed."""
        self.assertFalse(self.vfs.remove_file("/"))
        self.assertFalse(self.vfs.remove_dir("/"))
        self.assertFalse(self.vfs.remove_node("/"))
        self.assertFalse(self.vfs.create_dir("/"))


    def test_scan_threshold_randomized_per_session(self):
        """Issue 5: the HIGH_FREQUENCY_SCAN trigger point must not be a
        single fixed value across sessions, and must stay in range."""
        from honeypot.adaptive import adaptive_engine
        from honeypot.config import HIGH_FREQUENCY_SCAN_THRESHOLD_MIN, HIGH_FREQUENCY_SCAN_THRESHOLD_MAX

        thresholds = set()
        for i in range(30):
            sid = f"scan-threshold-session-{i}"
            t = adaptive_engine._get_scan_threshold(sid)
            self.assertGreaterEqual(t, HIGH_FREQUENCY_SCAN_THRESHOLD_MIN)
            self.assertLessEqual(t, HIGH_FREQUENCY_SCAN_THRESHOLD_MAX)
            thresholds.add(t)
        self.assertGreater(len(thresholds), 1)

    def test_scan_threshold_stable_per_session(self):
        """Issue 5: the threshold is chosen once per session and reused."""
        from honeypot.adaptive import adaptive_engine
        sid = "scan-threshold-stable-session"
        t1 = adaptive_engine._get_scan_threshold(sid)
        t2 = adaptive_engine._get_scan_threshold(sid)
        self.assertEqual(t1, t2)

    def test_baseline_jitter_applied_to_low_activity_response(self):
        """Issue 5: even a single, ordinary command gets a small non-zero
        baseline delay when no tarpit action is selected, so "0s" is no
        longer a reliable "not tarpitted" tell. select_action is pinned to
        NORMAL_RESPONSE here because it's epsilon-greedy (10% random
        exploration regardless of state) -- without pinning it, this test
        would be flaky, occasionally landing in the TARPIT_DELAY range by
        chance rather than testing the baseline jitter path itself."""
        from unittest.mock import patch
        from honeypot.adaptive import decide_response, adaptive_engine
        from honeypot.config import BASELINE_JITTER_MIN_SECONDS, BASELINE_JITTER_MAX_SECONDS
        session_id = "baseline-jitter-session"
        with patch.object(adaptive_engine, "select_action", return_value="NORMAL_RESPONSE"):
            plan = decide_response(session_id, "NOOP", {"command": "NOOP"}, context={"vfs": self.vfs, "authenticated": True})
        self.assertGreaterEqual(plan.delay_seconds, BASELINE_JITTER_MIN_SECONDS)
        self.assertLessEqual(plan.delay_seconds, BASELINE_JITTER_MAX_SECONDS)

    def test_high_frequency_scan_state_still_reachable(self):
        """Issue 5: a sustained burst of commands must still eventually
        reach HIGH_FREQUENCY_SCAN, regardless of which randomized threshold
        this session was assigned (sending more than the configured
        maximum guarantees it)."""
        from honeypot.adaptive import adaptive_engine
        from honeypot.config import HIGH_FREQUENCY_SCAN_THRESHOLD_MAX
        sid = "scan-state-reachable-session"
        state = "LOW_ACTIVITY"
        for _ in range(HIGH_FREQUENCY_SCAN_THRESHOLD_MAX + 3):
            state = adaptive_engine.get_session_state(sid, "NOOP", "", False)
        self.assertEqual(state, "HIGH_FREQUENCY_SCAN")


if __name__ == "__main__":
    unittest.main()
