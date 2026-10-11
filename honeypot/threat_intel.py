"""
Threat Intelligence & Enhanced Detection Module for AegisFTP
Integrates GeoIP location lookup, YARA payload signature scanning, AbuseIPDB threat intelligence, and FTP Bounce prevention.
"""
import os
import json
import urllib.request
import hashlib
import ipaddress
import logging

logger = logging.getLogger("AegisFTP.ThreatIntel")


class ThreatIntelEngine:
    def __init__(self, abuseipdb_key=None):
        self.abuseipdb_key = abuseipdb_key or os.environ.get("ABUSEIPDB_API_KEY", "")
        self.geoip_cache = {}

    def _is_private_ip(self, ip_address):
        if not ip_address or ip_address in ["localhost", "0.0.0.0"]:
            return True
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local
        except ValueError:
            return False

    def lookup_geoip(self, ip_address):
        """Fetches country, city, and ASN for attacker IP (with caching)"""
        if ip_address in self.geoip_cache:
            return self.geoip_cache[ip_address]

        if self._is_private_ip(ip_address):
            local_res = {"country": "Private Network", "country_code": "LOCAL", "city": "Internal", "isp": "Local LAN"}
            self.geoip_cache[ip_address] = local_res
            return local_res

        try:
            url = f"http://ip-api.com/json/{ip_address}?fields=status,country,countryCode,city,isp,query"
            req = urllib.request.Request(url, headers={'User-Agent': 'AegisFTP-Honeypot/1.0'})
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                if data.get("status") == "success":
                    result = {
                        "country": data.get("country", "Unknown"),
                        "country_code": data.get("countryCode", "XX"),
                        "city": data.get("city", "Unknown"),
                        "isp": data.get("isp", "Unknown")
                    }
                    self.geoip_cache[ip_address] = result
                    return result
        except Exception as e:
            logger.warning(f"GeoIP API lookup error for {ip_address}: {e}")

        fallback = {"country": "Unknown", "country_code": "XX", "city": "Unknown", "isp": "Unknown"}
        self.geoip_cache[ip_address] = fallback
        return fallback

    def check_abuseipdb(self, ip_address):
        """Checks IP reputation score on AbuseIPDB REST API"""
        if not self.abuseipdb_key or ip_address.startswith("192.168.") or ip_address == "127.0.0.1":
            return {"abuse_score": 0, "total_reports": 0, "status": "SKIPPED"}

        try:
            url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}&maxAgeInDays=90"
            req = urllib.request.Request(url, headers={
                'Key': self.abuseipdb_key,
                'Accept': 'application/json'
            })
            with urllib.request.urlopen(req, timeout=4.0) as resp:
                res = json.loads(resp.read().decode('utf-8'))
                data = res.get("data", {})
                return {
                    "abuse_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "is_whitelisted": data.get("isWhitelisted", False),
                    "status": "CHECKED"
                }
        except Exception as e:
            logger.warning(f"AbuseIPDB lookup failed for {ip_address}: {e}")
            return {"abuse_score": 0, "total_reports": 0, "status": "ERROR"}

    def scan_yara_rules(self, file_path):
        """Scans uploaded file with YARA engine or heuristic fallback pattern matching"""
        matches = []
        try:
            import yara
            # Compile inline security rules for web shells and reverse shells
            rules_source = """
            rule WebShell_PHP {
                strings:
                    $a = "eval(" ascii case_insensitive
                    $b = "system(" ascii case_insensitive
                    $c = "shell_exec(" ascii case_insensitive
                    $d = "passthru(" ascii case_insensitive
                    $e = "base64_decode(" ascii case_insensitive
                condition:
                    2 of ($a, $b, $c, $d, $e)
            }
            rule ReverseShell_Bash {
                strings:
                    $sh = "/bin/sh -i" ascii
                    $bash = "/bin/bash -i" ascii
                    $nc = "nc -e" ascii
                condition:
                    any of them
            }
            """
            compiled = yara.compile(source=rules_source)
            ymatches = compiled.match(file_path)
            matches = [m.rule for m in ymatches]
        except ImportError:
            # Fallback heuristic scan if yara-python module is not present
            try:
                with open(file_path, "rb") as f:
                    content = f.read().lower()
                if b"eval(" in content or b"system(" in content or b"shell_exec(" in content:
                    matches.append("Heuristic_WebShell_PHP")
                if b"/bin/bash -i" in content or b"nc -e" in content:
                    matches.append("Heuristic_ReverseShell_Bash")
            except Exception:
                pass

        return matches

    def check_ftp_bounce(self, client_ip, port_cmd_ip):
        """
        Prevents FTP Bounce Attack (T1090.002)
        Detects if PORT command directs output to a host other than client_ip
        """
        if port_cmd_ip != client_ip:
            logger.warning(f"[SECURITY ALERT] FTP Bounce Attack Attempt Detected! Client {client_ip} tried to bounce to {port_cmd_ip}")
            return True  # Bounce attack detected
        return False

threat_intel = ThreatIntelEngine()
