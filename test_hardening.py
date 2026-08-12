#!/usr/bin/env python3
"""
In-process unit tests for the AegisFTP security hardening (V1-V7).

These run WITHOUT a network server: they import the honeypot modules directly
and exercise the new security logic (per-IP trap counter, randomized threshold,
tripwire ban, post-auth containment, real Q-learning, timing jitter, credential
hardening) at the unit level.

Usage:
    pytest test_hardening.py -v
"""

import os
import stat
import tempfile
import shutil
import unittest

from honeypot import config as cfg
from honeypot.threat_intel import ThreatIntelEngine
from honeypot.virtual_fs import VirtualFileSystem
from honeypot.adaptive import decide_response, adaptive_engine
from honeypot.database import DatabaseManager


class TestPerIPTrapCounter(unittest.TestCase):
    """V1/V6: per-IP accumulation, stable randomized threshold, tripwire."""

    def setUp(self):
        self.engine = ThreatIntelEngine(abuseipdb_key="")

    def test_threshold_is_randomized_within_bounds(self):
        for _ in range(25):
            t = self.engine.get_threshold(f"10.0.0.{_}")
            self.assertGreaterEqual(t, cfg.AUTH_THRESHOLD_MIN)
            self.assertLessEqual(t, cfg.AUTH_THRESHOLD_MAX)

    def test_threshold_is_stable_per_ip(self):
        ip = "203.0.113.9"
        self.assertEqual(
            self.engine.get_threshold(ip), self.engine.get_threshold(ip)
        )

    def test_failed_attempts_accumulate_per_ip(self):
        self.engine.register_attempt("198.51.100.1")
        self.engine.register_attempt("198.51.100.1")
        self.assertEqual(self.engine.get_failed_attempts("198.51.100.1"), 2)
        self.assertEqual(self.engine.get_failed_attempts("198.51.100.2"), 0)

    def test_failed_attempt_tripwire_bans_ip(self):
        ip = "198.51.100.2"
        self.assertFalse(self.engine.is_banned(ip))
        for _ in range(cfg.MAX_IP_FAILED_ATTEMPTS):
            self.engine.register_attempt(ip)
        self.assertTrue(self.engine.is_banned(ip))

    def test_grant_cycle_tripwire_bans_ip(self):
        ip = "198.51.100.3"
        for _ in range(cfg.TRIPWIRE_GRANT_CYCLES):
            self.engine.register_grant(ip)
        self.assertTrue(self.engine.is_banned(ip))

    def test_geoip_treats_all_loopback_as_private(self):
        info = self.engine.lookup_geoip("127.0.0.55")
        self.assertEqual(info["country_code"], "LOCAL")


class TestPostAuthContainment(unittest.TestCase):
    """V3: /etc/shadow gated behind recon; protected DELE/RMD refused."""

    def setUp(self):
        self.vfs = VirtualFileSystem()
        self.auth_ctx = {"authenticated": True, "vfs": self.vfs}

    def _retr(self, path, recon=False):
        ctx = {**self.auth_ctx, "cwd": "/", "recon_done": recon}
        return decide_response("s1", f"RETR {path}", {"raw_args": path}, ctx)

    def test_shadow_blocked_without_recon(self):
        plan = self._retr("/etc/shadow", recon=False)
        self.assertEqual(plan.response_status, 550)

    def test_shadow_allowed_after_recon(self):
        plan = self._retr("/etc/shadow", recon=True)
        self.assertEqual(plan.response_status, 150)
        self.assertIn(b"root:", plan.extra["content"])

    def test_regular_files_not_gated(self):
        plan = self._retr("/etc/passwd", recon=False)
        self.assertEqual(plan.response_status, 150)

    def test_protected_delete_refused(self):
        ctx = {**self.auth_ctx, "cwd": "/"}
        plan = decide_response("s2", "DELE /etc/passwd", {"raw_args": "/etc/passwd"}, ctx)
        self.assertEqual(plan.response_status, 550)
        self.assertEqual(plan.response_type, "file_error")
        # protected file must still exist
        self.assertIsNotNone(self.vfs.get_node("/etc/passwd"))

    def test_protected_rmdir_refused(self):
        ctx = {**self.auth_ctx, "cwd": "/"}
        plan = decide_response("s3", "RMD /etc", {"raw_args": "/etc"}, ctx)
        self.assertEqual(plan.response_status, 550)
        self.assertIsNotNone(self.vfs.get_node("/etc"))

    def test_delete_allowed_in_decoy_dir(self):
        self.vfs.add_file("/var/www/tmp.txt", b"x")
        ctx = {**self.auth_ctx, "cwd": "/var/www"}
        plan = decide_response("s4", "DELE tmp.txt", {"raw_args": "tmp.txt"}, ctx)
        self.assertEqual(plan.response_status, 250)


class TestAdaptiveEngineChanges(unittest.TestCase):
    """V4/V5: real Q-learning loop runs and timing jitter is always present."""

    def test_q_table_updates_from_interactions(self):
        vfs = VirtualFileSystem()
        session = "learn-session-1"
        q_before = {
            s: dict(a) for s, a in adaptive_engine.q_table.items()
        }
        for _ in range(5):
            adaptive_engine.evaluate_response(session, "PASS", "x", vfs)
            adaptive_engine.evaluate_response(session, "USER", "a", vfs)
            adaptive_engine.evaluate_response(session, "RETR", "config.php", vfs)
        changed = any(
            adaptive_engine.q_table[s][a] != q_before[s][a]
            for s in adaptive_engine.q_table
            for a in adaptive_engine.q_table[s]
        )
        self.assertTrue(changed, "Q-table must be updated by the reward loop (V4)")

    def test_dwell_reward_and_cleanup(self):
        vfs = VirtualFileSystem()
        session = "learn-session-2"
        adaptive_engine.evaluate_response(session, "USER", "admin", vfs)
        adaptive_engine.reward_dwell(session, 120.0)
        adaptive_engine.session_ended(session)
        self.assertNotIn(session, adaptive_engine.session_pending)
        self.assertNotIn(session, adaptive_engine.session_cmd_timestamps)

    def test_jitter_applied_to_every_response(self):
        vfs = VirtualFileSystem()
        plan = decide_response(
            "jitter-1", "NOOP", {"raw_args": ""},
            {"vfs": vfs, "authenticated": False},
        )
        # NOOP is non-authenticated and normally instant; jitter must still apply
        self.assertGreaterEqual(plan.delay_seconds, cfg.JITTER_DELAY_MIN)
        self.assertLessEqual(plan.delay_seconds, cfg.JITTER_DELAY_MAX + cfg.TARPIT_DELAY_MAX)


class TestCredentialHardening(unittest.TestCase):
    """V7: DB file permissions and webhook password redaction."""

    def test_database_file_permissions(self):
        tmpdir = tempfile.mkdtemp()
        try:
            db_path = os.path.join(tmpdir, "hardened.db")
            DatabaseManager(db_path)
            mode = stat.S_IMODE(os.stat(db_path).st_mode)
            self.assertEqual(mode, 0o600)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_webhook_alerts_redact_passwords(self):
        from honeypot.alerting import WebhookAlertNotifier

        captured = {}

        def fake_send_alert(title, message, severity="HIGH"):
            captured["title"] = title
            captured["message"] = message
            captured["severity"] = severity

        notifier = WebhookAlertNotifier()
        notifier.send_alert = fake_send_alert
        notifier.notify_brute_force_threshold("203.0.113.7", 4, "admin", "SuperSecretP@ss")

        self.assertNotIn("SuperSecretP@ss", captured["message"])
        # a 16-hex-char SHA-256 prefix is present instead
        self.assertRegex(captured["message"], r"Pass SHA-256\[16\]: `[0-9a-f]{16}`")


if __name__ == "__main__":
    unittest.main()
