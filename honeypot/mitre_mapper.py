"""
MITRE ATT&CK Mapper Module for AegisFTP
Maps raw FTP command sequences and attack patterns to standardized MITRE ATT&CK Tactics & Techniques.
"""

MITRE_ATTACK_MAPPINGS = {
    "BRUTE_FORCE": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Repeated USER and PASS authentication attempts (dictionary / credential stuffing)."
    },
    "CREDENTIAL_DUMPING": {
        "technique_id": "T1003.008",
        "technique_name": "OS Credential Dumping: /etc/passwd and /etc/shadow",
        "tactic": "Credential Access",
        "description": "Retrieval of system credential files (/etc/passwd, /etc/shadow, or backup.sql)."
    },
    "WEB_SHELL_UPLOAD": {
        "technique_id": "T1505.003",
        "technique_name": "Server Software Component: Web Shell",
        "tactic": "Persistence / Initial Access",
        "description": "Uploading executable web scripts (.php, .sh, .py, .asp, .jsp) via STOR command."
    },
    "FTP_BOUNCE_ATTACK": {
        "technique_id": "T1090.002",
        "technique_name": "Proxy: External Proxy / FTP Bounce",
        "tactic": "Command and Control / Defense Evasion",
        "description": "Using PORT command pointing to an arbitrary third-party IP to bounce traffic or port scan."
    },
    "SITE_EXEC_COMMAND": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Executing server-side site commands (SITE EXEC, SITE CHMOD)."
    },
    "FILE_DIRECTORY_DISCOVERY": {
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic": "Discovery",
        "description": "Enumerating directory hierarchy using LIST, NLST, PWD, CWD."
    }
}


class MitreAttackMapper:
    @staticmethod
    def classify_command(command, args, failed_attempts=0, client_ip=None, active_host=None):
        tags = []
        cmd = (command or "").upper()
        arguments = (args or "").lower()

        # 1. Brute Force
        if cmd == "PASS" or failed_attempts > 0:
            tags.append(MITRE_ATTACK_MAPPINGS["BRUTE_FORCE"])

        # 2. Credential Dumping
        if cmd in ["RETR", "SIZE"] and any(f in arguments for f in ["passwd", "shadow", "config.php", "backup.sql"]):
            tags.append(MITRE_ATTACK_MAPPINGS["CREDENTIAL_DUMPING"])

        # 3. Web Shell / Payload Upload
        if cmd == "STOR" and any(ext in arguments for ext in [".php", ".sh", ".py", ".pl", ".exe", ".elf", ".asp", ".jsp"]):
            tags.append(MITRE_ATTACK_MAPPINGS["WEB_SHELL_UPLOAD"])

        # 4. FTP Bounce Attack
        if cmd == "PORT" and active_host and client_ip and active_host != client_ip:
            tags.append(MITRE_ATTACK_MAPPINGS["FTP_BOUNCE_ATTACK"])

        # 5. Site Execution
        if cmd == "SITE" and ("exec" in arguments or "chmod" in arguments):
            tags.append(MITRE_ATTACK_MAPPINGS["SITE_EXEC_COMMAND"])

        # 6. Discovery
        if cmd in ["LIST", "NLST", "PWD", "CWD"]:
            tags.append(MITRE_ATTACK_MAPPINGS["FILE_DIRECTORY_DISCOVERY"])

        return tags

    @staticmethod
    def get_session_mitre_summary(db_manager, session_id):
        """Queries database command logs for session and computes aggregated MITRE ATT&CK technique tags."""
        conn = db_manager.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT command, arguments FROM command_logs WHERE session_id = ?", (session_id,))
        logs = cursor.fetchall()

        cursor.execute("SELECT failed_attempts, client_ip FROM sessions WHERE session_id = ?", (session_id,))
        session_row = cursor.fetchone()
        conn.close()

        failed_attempts = session_row["failed_attempts"] if session_row else 0
        client_ip = session_row["client_ip"] if session_row else ""

        unique_tags = {}
        for row in logs:
            cmd_tags = MitreAttackMapper.classify_command(row["command"], row["arguments"], failed_attempts, client_ip)
            for t in cmd_tags:
                unique_tags[t["technique_id"]] = t

        return list(unique_tags.values())

mitre_mapper = MitreAttackMapper()
