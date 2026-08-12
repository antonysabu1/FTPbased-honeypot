"""
Real-Time Webhook Alerting Module for AegisFTP
Sends instant notifications to Telegram, Discord, or Slack webhooks on security events.
"""
import os
import json
import hashlib
import urllib.request
import logging

logger = logging.getLogger("AegisFTP.Alerting")


class WebhookAlertNotifier:
    def __init__(self):
        self.telegram_bot_token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
        self.telegram_chat_id = os.environ.get("TELEGRAM_CHAT_ID", "")
        self.discord_webhook_url = os.environ.get("DISCORD_WEBHOOK_URL", "")
        self.slack_webhook_url = os.environ.get("SLACK_WEBHOOK_URL", "")

    def send_alert(self, title, message, severity="HIGH"):
        payload_text = f"🚨 *[AegisFTP Alert - {severity}]* 🚨\n*{title}*\n{message}"

        # 1. Telegram Webhook
        if self.telegram_bot_token and self.telegram_chat_id:
            try:
                url = f"https://api.telegram.org/bot{self.telegram_bot_token}/sendMessage"
                data = json.dumps({"chat_id": self.telegram_chat_id, "text": payload_text, "parse_mode": "Markdown"}).encode('utf-8')
                req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})
                urllib.request.urlopen(req, timeout=3.0)
            except Exception as e:
                logger.error(f"Telegram alert delivery failed: {e}")

        # 2. Discord Webhook
        if self.discord_webhook_url:
            try:
                discord_payload = {
                    "embeds": [{
                        "title": f"🚨 AegisFTP Alert: {title}",
                        "description": message,
                        "color": 15158332 if severity == "HIGH" else 3066993,
                        "footer": {"text": "AegisFTP Threat Intelligence Sensor"}
                    }]
                }
                data = json.dumps(discord_payload).encode('utf-8')
                req = urllib.request.Request(self.discord_webhook_url, data=data, headers={'Content-Type': 'application/json'})
                urllib.request.urlopen(req, timeout=3.0)
            except Exception as e:
                logger.error(f"Discord alert delivery failed: {e}")

        # 3. Slack Webhook
        if self.slack_webhook_url:
            try:
                slack_payload = {"text": payload_text}
                data = json.dumps(slack_payload).encode('utf-8')
                req = urllib.request.Request(self.slack_webhook_url, data=data, headers={'Content-Type': 'application/json'})
                urllib.request.urlopen(req, timeout=3.0)
            except Exception as e:
                logger.error(f"Slack alert delivery failed: {e}")

    def notify_new_connection(self, client_ip, geo_info):
        title = "New Attacker Connection Established"
        msg = f"• *Attacker IP*: `{client_ip}`\n• *Country*: {geo_info.get('country')} ({geo_info.get('country_code')})\n• *ISP*: {geo_info.get('isp')}"
        self.send_alert(title, msg, severity="INFO")

    def notify_brute_force_threshold(self, client_ip, failed_attempts, username, password):
        title = "Brute-Force Threshold Exceeded (Access Granted Trap)"
        # V7: never send plaintext passwords over webhook channels - only a
        # truncated SHA-256 digest. Full plaintext stays local in the SQLite DB.
        password_hash = hashlib.sha256(password.encode("utf-8", errors="replace")).hexdigest()[:16]
        msg = (
            f"• *Attacker IP*: `{client_ip}`\n"
            f"• *Failed Attempts*: {failed_attempts}\n"
            f"• *Trapped Credential*: User: `{username}` | Pass SHA-256[16]: `{password_hash}`\n"
            f"• *Status*: Accepted into Virtual Filesystem"
        )
        self.send_alert(title, msg, severity="HIGH")

    def notify_banned_ip(self, client_ip):
        title = "Source IP Banned (Tripwire Tripped)"
        msg = f"• *Attacker IP*: `{client_ip}`\n• *Action*: Connection refused, reported to AbuseIPDB"
        self.send_alert(title, msg, severity="CRITICAL")

    def notify_payload_uploaded(self, client_ip, original_name, sha256_hash, size, geo_info, yara_matches):
        title = "Malware Payload Quarantined"
        matches_str = ", ".join(yara_matches) if yara_matches else "None"
        msg = (
            f"• *Attacker IP*: `{client_ip}` ({geo_info.get('country')})\n"
            f"• *Filename*: `{original_name}`\n"
            f"• *SHA-256*: `{sha256_hash}`\n"
            f"• *Size*: {size} Bytes\n"
            f"• *YARA Rules Matched*: `{matches_str}`"
        )
        self.send_alert(title, msg, severity="CRITICAL")

alert_notifier = WebhookAlertNotifier()
