"""
Adaptive Deception Module for AegisFTP
Implements a Finite State Machine (FSM) & Reinforcement Learning (Q-table) Tarpit & Dynamic Deception Engine.
"""
import time
import random
import logging

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

    def get_session_state(self, session_id, last_cmd, last_args, has_uploaded_file=False):
        now = time.time()
        if session_id not in self.session_cmd_timestamps:
            self.session_cmd_timestamps[session_id] = []
        
        timestamps = self.session_cmd_timestamps[session_id]
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

    def evaluate_response(self, session_id, command, args, vfs_instance, has_uploaded=False):
        """
        Determines response modification (delay, dynamic file creation, or response code modification)
        """
        state = self.get_session_state(session_id, command, args, has_uploaded)
        action = self.select_action(state)

        result = {
            "state": state,
            "action": action,
            "delay_seconds": 0.0,
            "injected_file": None
        }

        if action == "TARPIT_DELAY":
            # Tarpit response delay (2.0 to 5.0 seconds) to slow down automated brute-force bots
            result["delay_seconds"] = round(random.uniform(2.0, 4.5), 2)
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
                logger.info(f"[Adaptive Engine] Injected honeypot asset {injected_path} into VFS for session {session_id[:8]}")

        return result

    def update_q_value(self, state, action, reward, next_state, alpha=0.1, gamma=0.9):
        """Q-Learning Bellman equation update"""
        max_next = max(self.q_table[next_state].values()) if next_state in self.q_table else 0.0
        current_q = self.q_table[state][action]
        new_q = current_q + alpha * (reward + gamma * max_next - current_q)
        self.q_table[state][action] = round(new_q, 4)

adaptive_engine = AdaptiveDeceptionEngine()
