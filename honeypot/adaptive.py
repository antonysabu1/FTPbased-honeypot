"""
Adaptive Deception Module for AegisFTP
Implements a Finite State Machine (FSM) & Reinforcement Learning (Q-table) Tarpit & Dynamic Deception Engine.
"""
import time
import random
import logging

from honeypot.config import (
    JITTER_DELAY_MIN,
    JITTER_DELAY_MAX,
    TARPIT_DELAY_MIN,
    TARPIT_DELAY_MAX,
    TARPIT_PROBABILITY,
)

logger = logging.getLogger("AegisFTP.Adaptive")

class AdaptiveDeceptionEngine:
    def __init__(self):
        # Q-learning table initialization: States x Actions
        # States: LOW_ACTIVITY, HIGH_FREQUENCY_SCAN, SENSITIVE_FILE_PROBING, PAYLOAD_UPLOADED
        # Actions: NORMAL_RESPONSE, TARPIT_DELAY, DYNAMIC_INJECTION, FAKE_PERM_ERROR
        self.states = ["LOW_ACTIVITY", "HIGH_FREQUENCY_SCAN", "SENSITIVE_FILE_PROBING", "PAYLOAD_UPLOADED"]
        self.actions = ["NORMAL_RESPONSE", "TARPIT_DELAY", "DYNAMIC_INJECTION", "FAKE_PERM_ERROR"]
        
        # Q-table initialization with default heuristic rewards
        self.q_table = {
            s: {a: 0.0 for a in self.actions} for s in self.states
        }
        # Pre-seed Q-values based on deception objectives (maximizing dwell time & intelligence)
        self.q_table["HIGH_FREQUENCY_SCAN"]["TARPIT_DELAY"] = 5.0
        self.q_table["SENSITIVE_FILE_PROBING"]["DYNAMIC_INJECTION"] = 10.0
        self.q_table["PAYLOAD_UPLOADED"]["NORMAL_RESPONSE"] = 8.0

        # Session activity trackers
        self.session_cmd_timestamps = {}
        self.session_states = {}
        # V4: (state, action) decided for each session, rewarded on the next
        # observed command so the Q-table genuinely adapts to attacker behavior.
        self.session_pending = {}

    def get_session_state(self, session_id, last_cmd, last_args, has_uploaded_file=False, record=True):
        now = time.time()
        if session_id not in self.session_cmd_timestamps:
            self.session_cmd_timestamps[session_id] = []
        
        timestamps = self.session_cmd_timestamps[session_id]
        if record:
            timestamps.append(now)
        # Keep window of last 10 seconds
        timestamps = [t for t in timestamps if now - t <= 10.0]
        self.session_cmd_timestamps[session_id] = timestamps

        cmd_rate = len(timestamps)

        if has_uploaded_file:
            return "PAYLOAD_UPLOADED"
        elif last_cmd in ["RETR", "SIZE"] and any(s in (last_args or "").lower() for s in ["config.php", "passwd", "shadow", "backup"]):
            return "SENSITIVE_FILE_PROBING"
        elif cmd_rate > 5:  # More than 5 commands in 10s = automated bot scan
            return "HIGH_FREQUENCY_SCAN"
        else:
            return "LOW_ACTIVITY"

    def select_action(self, state, epsilon=0.1):
        """Epsilon-greedy action selection"""
        if random.random() < epsilon:
            return random.choice(self.actions)
        else:
            state_actions = self.q_table.get(state, {})
            return max(state_actions, key=state_actions.get) if state_actions else "NORMAL_RESPONSE"

    def _reward_previous(self, session_id, command, args):
        """V4: Reward the previous (state, action) using the newly observed
        follow-on command as the outcome signal, then update the Q-table."""
        pending = self.session_pending.pop(session_id, None)
        if not pending:
            return
        state, action = pending
        next_state = self.get_session_state(session_id, command, args, record=False)

        # Engagement rewards: tarpits that still get more credential attempts
        # and injected assets that get re-fetched are the behaviors we want.
        if action == "TARPIT_DELAY":
            reward = 2.0 if command in ("PASS", "USER") else 0.5
        elif action == "DYNAMIC_INJECTION":
            reward = 3.0 if command == "RETR" else 1.0
        elif action == "FAKE_PERM_ERROR":
            reward = 0.8
        else:
            reward = -0.1
        if state == next_state and action != "NORMAL_RESPONSE":
            reward += 0.5  # attacker stayed in the same deceptive state

        self.update_q_value(state, action, reward, next_state)

    def reward_dwell(self, session_id, dwell_seconds):
        """V4: Bonus reward for long session dwell time (attacker stayed engaged)."""
        pending = self.session_pending.get(session_id)
        if not pending:
            return
        state, action = pending
        bonus = min(dwell_seconds / 30.0, 5.0)
        self.update_q_value(state, action, bonus, state)

    def session_ended(self, session_id):
        """Release per-session bookkeeping (prevents unbounded memory growth)."""
        self.session_pending.pop(session_id, None)
        self.session_cmd_timestamps.pop(session_id, None)
        self.session_states.pop(session_id, None)

    def evaluate_response(self, session_id, command, args, vfs_instance, has_uploaded=False):
        """
        Determines response modification (delay, dynamic file creation, or response code modification)
        """
        self._reward_previous(session_id, command, args)
        state = self.get_session_state(session_id, command, args, has_uploaded)
        action = self.select_action(state)
        self.session_pending[session_id] = (state, action)

        result = {
            "state": state,
            "action": action,
            "delay_seconds": 0.0,
            "injected_file": None
        }

        # V5: unconditional jittered latency on every reply so response time is
        # never a pure function of command rate (removes the timing fingerprint).
        result["delay_seconds"] = round(random.uniform(JITTER_DELAY_MIN, JITTER_DELAY_MAX), 2)

        if action == "TARPIT_DELAY" and random.random() < TARPIT_PROBABILITY:
            # Large tarpit delay is now probabilistic, not deterministic (V5)
            result["delay_seconds"] += round(random.uniform(TARPIT_DELAY_MIN, TARPIT_DELAY_MAX), 2)
            logger.info(f"[Adaptive Engine] Tarpitting session {session_id[:8]} for {result['delay_seconds']}s")

        elif action == "DYNAMIC_INJECTION":
            # Dynamically inject fake database backup if attacker is probing config.php
            if command == "RETR" and "config.php" in (args or "").lower():
                injected_path = "/var/www/database_backup.sql"
                backup_sql_content = (
                    "-- AegisFTP Dynamic Deception Trap Dump\n"
                    "CREATE TABLE admin_credentials (id INT, email VARCHAR(100), pass_hash VARCHAR(255));\n"
                    "INSERT INTO admin_credentials VALUES (1, 'sysadmin@internal-corp.local', '$2y$10$e8N3v...fakehash');\n"
                )
                vfs_instance.add_file(injected_path, backup_sql_content.encode('utf-8'), owner="www-data")
                result["injected_file"] = injected_path
                result["delay_seconds"] += round(random.uniform(0.2, 1.0), 2)
                logger.info(f"[Adaptive Engine] Injected honeypot asset {injected_path} into VFS for session {session_id[:8]}")

        elif action == "FAKE_PERM_ERROR":
            result["delay_seconds"] += round(random.uniform(0.1, 0.6), 2)

        return result

    def update_q_value(self, state, action, reward, next_state, alpha=0.1, gamma=0.9):
        """Q-Learning Bellman equation update"""
        max_next = max(self.q_table[next_state].values()) if next_state in self.q_table else 0.0
        current_q = self.q_table[state][action]
        new_q = current_q + alpha * (reward + gamma * max_next - current_q)
        self.q_table[state][action] = round(new_q, 4)

adaptive_engine = AdaptiveDeceptionEngine()


class ResponsePlan:
    """
    Response Plan object returned by decide_response seam.
    Defines the response text, protocol status code, short label response type,
    tarpit delay, and any extra metadata for execution.
    """
    def __init__(self, response_text: str, response_status: int, response_type: str, delay_seconds: float = 0.0, extra: dict = None):
        self.response_text = response_text
        self.response_status = int(response_status) if isinstance(response_status, int) or (isinstance(response_status, str) and response_status.isdigit()) else response_status
        self.response_type = response_type
        self.delay_seconds = delay_seconds
        self.extra = extra or {}

    def to_dict(self):
        return {
            "response_text": self.response_text,
            "response_status": self.response_status,
            "response_type": self.response_type,
            "delay_seconds": self.delay_seconds,
            "extra": self.extra
        }


def decide_response(session_id: str, action: str, parameters: dict, context: dict = None) -> ResponsePlan:
    """
    Decides what fake content/behavior to return for this interaction.
    RIGHT NOW: rule-based & adaptive decision logic for FTP adapter.
    LATER: internals get replaced with a call into the shared Control Engine.
    """
    from honeypot.config import FTP_WELCOME_BANNER, FAILED_ATTEMPTS_THRESHOLD

    context = context or {}
    vfs_instance = context.get("vfs")
    has_uploaded = context.get("has_uploaded", False)

    # Extract command string
    raw_action = (action or "").strip()
    parts = raw_action.split(" ", 1)
    cmd = parts[0].upper()
    raw_args = parameters.get("raw_args", parts[1] if len(parts) > 1 else "")

    # Query Adaptive Deception Engine for delay & dynamic injection
    delay_seconds = 0.0
    if vfs_instance:
        adaptive_eval = adaptive_engine.evaluate_response(session_id, cmd, raw_args, vfs_instance, has_uploaded)
        delay_seconds = adaptive_eval.get("delay_seconds", 0.0)

    # Response decision mapping
    if cmd == "CONNECT":
        return ResponsePlan(FTP_WELCOME_BANNER, 220, "welcome_banner", delay_seconds=delay_seconds)

    elif cmd == "USER":
        username = parameters.get("username", raw_args.strip() or "anonymous")
        return ResponsePlan(f"331 Password required for {username}.", 331, "auth_prompt", delay_seconds=delay_seconds)

    elif cmd == "PASS":
        failed_attempts = context.get("failed_attempts", 0) + 1
        threshold = context.get("failed_threshold", FAILED_ATTEMPTS_THRESHOLD)
        if failed_attempts <= threshold:
            return ResponsePlan(
                "530 Login incorrect.", 530, "auth_failure",
                delay_seconds=delay_seconds,
                extra={"authenticated": False, "failed_attempts": failed_attempts}
            )
        else:
            auth_user = parameters.get("username") or context.get("username") or "anonymous"
            return ResponsePlan(
                "230 User logged in, proceed.", 230, "auth_success",
                delay_seconds=delay_seconds,
                extra={"authenticated": True, "failed_attempts": failed_attempts, "authenticated_user": auth_user}
            )

    elif cmd == "SYST":
        return ResponsePlan("215 UNIX Type: L8", 215, "system_info", delay_seconds=delay_seconds)

    elif cmd == "FEAT":
        feat_str = "211-Features:\r\n PASV\r\n UTF8\r\n REST STREAM\r\n SIZE\r\n MLSD\r\n211 End"
        return ResponsePlan(feat_str, 211, "features_list", delay_seconds=delay_seconds)

    elif cmd in ["PWD", "XPWD"]:
        cwd = context.get("cwd", "/var/www")
        return ResponsePlan(f'257 "{cwd}" is current directory.', 257, "working_directory", delay_seconds=delay_seconds)

    elif cmd == "CWD":
        if not context.get("authenticated", False):
            return ResponsePlan("530 Please login with USER and PASS.", 530, "auth_required", delay_seconds=delay_seconds)
        cwd = context.get("cwd", "/var/www")
        target = raw_args.strip()
        if vfs_instance:
            target_path = vfs_instance.normalize_path(cwd, target)
            node = vfs_instance.get_node(target_path)
            if node and node.is_dir:
                return ResponsePlan(
                    f'250 Directory successfully changed to "{target_path}".', 250, "directory_change",
                    delay_seconds=delay_seconds, extra={"new_cwd": target_path}
                )
        return ResponsePlan("550 Failed to change directory.", 550, "directory_error", delay_seconds=delay_seconds)

    elif cmd == "CDUP":
        if not context.get("authenticated", False):
            return ResponsePlan("530 Please login with USER and PASS.", 530, "auth_required", delay_seconds=delay_seconds)
        cwd = context.get("cwd", "/var/www")
        if vfs_instance:
            target_path = vfs_instance.normalize_path(cwd, "..")
            return ResponsePlan(
                f'250 Directory successfully changed to "{target_path}".', 250, "directory_change",
                delay_seconds=delay_seconds, extra={"new_cwd": target_path}
            )
        return ResponsePlan("550 Failed to change directory.", 550, "directory_error", delay_seconds=delay_seconds)

    elif cmd == "TYPE":
        mode = raw_args.strip().upper()
        if mode in ["A", "I"]:
            return ResponsePlan(f"200 Switching to {mode} mode.", 200, "transfer_type", delay_seconds=delay_seconds, extra={"transfer_type": mode})
        return ResponsePlan("504 Command not implemented for that parameter.", 504, "error_response", delay_seconds=delay_seconds)

    elif cmd == "PASV":
        pasv_str = context.get("pasv_str", "227 Entering Passive Mode.")
        return ResponsePlan(pasv_str, 227, "passive_mode", delay_seconds=delay_seconds)

    elif cmd == "PORT":
        if context.get("bounce_detected", False):
            return ResponsePlan("501 Illegal PORT command (FTP Bounce Attack detected).", 501, "bounce_attack_blocked", delay_seconds=delay_seconds)
        return ResponsePlan("200 PORT command successful.", 200, "active_mode", delay_seconds=delay_seconds)

    elif cmd in ["LIST", "NLST"]:
        if not context.get("authenticated", False):
            return ResponsePlan("530 Please login with USER and PASS.", 530, "auth_required", delay_seconds=delay_seconds)
        return ResponsePlan("150 Here comes the directory listing.", 150, "directory_listing", delay_seconds=delay_seconds)

    elif cmd == "RETR":
        if not context.get("authenticated", False):
            return ResponsePlan("530 Please login with USER and PASS.", 530, "auth_required", delay_seconds=delay_seconds)
        filename = raw_args.strip()
        cwd = context.get("cwd", "/var/www")
        if vfs_instance:
            target_path = vfs_instance.normalize_path(cwd, filename)
            # V3: gate the single most sensitive asset behind prior recon activity,
            # so a freshly-granted session cannot immediately exfiltrate /etc/shadow.
            if target_path == "/etc/shadow" and not context.get("recon_done", False):
                return ResponsePlan("550 Permission denied.", 550, "file_error", delay_seconds=delay_seconds)
            content = vfs_instance.get_file_content(target_path)
            if content is not None:
                return ResponsePlan(
                    f"150 Opening BINARY mode data connection for {filename} ({len(content)} bytes).", 150, "file_download",
                    delay_seconds=delay_seconds, extra={"content": content}
                )
        return ResponsePlan("550 Failed to open file.", 550, "file_error", delay_seconds=delay_seconds)

    elif cmd == "STOR":
        if not context.get("authenticated", False):
            return ResponsePlan("530 Please login with USER and PASS.", 530, "auth_required", delay_seconds=delay_seconds)
        return ResponsePlan("150 Ok to send data.", 150, "file_upload", delay_seconds=delay_seconds)

    elif cmd == "SIZE":
        if not context.get("authenticated", False):
            return ResponsePlan("530 Please login with USER and PASS.", 530, "auth_required", delay_seconds=delay_seconds)
        cwd = context.get("cwd", "/var/www")
        if vfs_instance:
            target_path = vfs_instance.normalize_path(cwd, raw_args.strip())
            node = vfs_instance.get_node(target_path)
            if node and not node.is_dir:
                return ResponsePlan(f"213 {node.size}", 213, "file_size", delay_seconds=delay_seconds)
        return ResponsePlan("550 Could not get file size.", 550, "file_error", delay_seconds=delay_seconds)

    elif cmd == "DELE":
        if not context.get("authenticated", False):
            return ResponsePlan("530 Please login with USER and PASS.", 530, "auth_required", delay_seconds=delay_seconds)
        cwd = context.get("cwd", "/var/www")
        if vfs_instance:
            target_path = vfs_instance.normalize_path(cwd, raw_args.strip())
            # V3: the VFS is shared across sessions, so destructive ops on the
            # system-critical trees are refused to protect other sessions' intel.
            if vfs_instance.is_protected_path(target_path):
                return ResponsePlan("550 Operation not permitted.", 550, "file_error", delay_seconds=delay_seconds)
            if vfs_instance.remove_node(target_path):
                return ResponsePlan("250 Delete operation successful.", 250, "file_delete", delay_seconds=delay_seconds)
        return ResponsePlan("550 File not found.", 550, "file_error", delay_seconds=delay_seconds)

    elif cmd == "MKD":
        if not context.get("authenticated", False):
            return ResponsePlan("530 Please login with USER and PASS.", 530, "auth_required", delay_seconds=delay_seconds)
        cwd = context.get("cwd", "/var/www")
        if vfs_instance:
            target_path = vfs_instance.normalize_path(cwd, raw_args.strip())
            if vfs_instance.create_dir(target_path):
                return ResponsePlan(f'257 "{target_path}" directory created.', 257, "directory_create", delay_seconds=delay_seconds)
        return ResponsePlan("550 Create directory operation failed.", 550, "directory_error", delay_seconds=delay_seconds)

    elif cmd == "RMD":
        if not context.get("authenticated", False):
            return ResponsePlan("530 Please login with USER and PASS.", 530, "auth_required", delay_seconds=delay_seconds)
        cwd = context.get("cwd", "/var/www")
        if vfs_instance:
            target_path = vfs_instance.normalize_path(cwd, raw_args.strip())
            if vfs_instance.is_protected_path(target_path):
                return ResponsePlan("550 Operation not permitted.", 550, "directory_error", delay_seconds=delay_seconds)
            if vfs_instance.remove_node(target_path):
                return ResponsePlan("250 Remove directory operation successful.", 250, "directory_remove", delay_seconds=delay_seconds)
        return ResponsePlan("550 Directory not found.", 550, "directory_error", delay_seconds=delay_seconds)

    elif cmd == "NOOP":
        return ResponsePlan("200 OK.", 200, "noop_response", delay_seconds=delay_seconds)

    elif cmd == "QUIT":
        return ResponsePlan("221 Goodbye.", 221, "goodbye", delay_seconds=delay_seconds)

    return ResponsePlan(f"500 Unknown command '{cmd}'.", 500, "unknown_command", delay_seconds=delay_seconds)

