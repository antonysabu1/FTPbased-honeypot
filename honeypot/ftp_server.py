import os
import time
import uuid
import hashlib
import datetime
import posixpath
from twisted.internet import reactor, protocol, defer
from twisted.protocols.basic import LineReceiver
from twisted.internet.endpoints import TCP4ServerEndpoint, TCP4ClientEndpoint, connectProtocol

from honeypot.config import (
    FTP_HOST, FTP_PORT, PASV_PORT_MIN, PASV_PORT_MAX,
    FAILED_ATTEMPTS_THRESHOLD, QUARANTINE_DIR, FTP_WELCOME_BANNER
)
from honeypot.database import db, log_event
from honeypot.virtual_fs import VirtualFileSystem
from honeypot.adaptive import adaptive_engine, decide_response, ResponsePlan
from honeypot.mitre_mapper import mitre_mapper
from honeypot.threat_intel import threat_intel
from honeypot.alerting import alert_notifier

# Shared Virtual Filesystem instance across sessions
vfs = VirtualFileSystem()


class FTPDataProtocol(protocol.Protocol):
    def __init__(self, mode='SEND', data=b'', deferred_result=None):
        self.mode = mode  # 'SEND' or 'RECV'
        self.data = data
        self.received_bytes = bytearray()
        self.deferred_result = deferred_result

    def connectionMade(self):
        if self.mode == 'SEND':
            self.transport.write(self.data)
            self.transport.loseConnection()

    def dataReceived(self, chunk):
        if self.mode == 'RECV':
            self.received_bytes.extend(chunk)

    def connectionLost(self, reason):
        if self.mode == 'RECV' and self.deferred_result and not self.deferred_result.called:
            self.deferred_result.callback(bytes(self.received_bytes))


class FTPDataServerFactory(protocol.ServerFactory):
    def __init__(self, mode='SEND', data=b'', deferred_result=None):
        self.mode = mode
        self.data = data
        self.deferred_result = deferred_result
        self.proto_instance = None

    def buildProtocol(self, addr):
        self.proto_instance = FTPDataProtocol(self.mode, self.data, self.deferred_result)
        return self.proto_instance


class FTPControlProtocol(LineReceiver):
    delimiter = b'\n'  # Handles \r\n and \n gracefully

    def __init__(self):
        self.session_id = str(uuid.uuid4())
        self.client_ip = "0.0.0.0"
        self.client_port = 0
        self.geo_info = {}
        self.authenticated = False
        self.authenticated_user = None
        self.username = None
        self.failed_attempts = 0
        self.recon_done = False
        self.connect_time = None
        self.cwd = "/var/www"
        self.transfer_type = "I"
        self.has_uploaded = False
        self.pasv_listener = None
        self.pasv_port = None
        self.pasv_factory = None
        self.active_host = None
        self.active_port = None

    def connectionMade(self):
        peer = self.transport.getPeer()
        self.client_ip = peer.host
        self.client_port = peer.port
        self.connect_time = time.time()

        # V6: refuse tripwire-banned source IPs before anything else
        if threat_intel.is_banned(self.client_ip):
            self.sendLine(b"421 Service not available, closing control connection.")
            log_event({
                "event_id": str(uuid.uuid4()),
                "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                "protocol": "ftp",
                "source_ip": self.client_ip,
                "session_id": self.session_id,
                "action": "CONNECT_BANNED",
                "parameters": {},
                "raw_metadata": {"client_port": self.client_port, "reason": "tripwire_ban"},
                "session_source": "protocol_native",
                "response_status": 421,
                "response_type": "banned_connection"
            })
            alert_notifier.notify_banned_ip(self.client_ip)
            self.transport.loseConnection()
            return

        # V1/V2: seed this session from the per-IP trap state so connection-
        # rotating bots accumulate toward the grant, with a per-IP random threshold.
        self.failed_attempts = threat_intel.get_failed_attempts(self.client_ip)
        self.grant_threshold = threat_intel.get_threshold(self.client_ip)

        # Enhanced Detection: GeoIP & AbuseIPDB Lookup
        self.geo_info = threat_intel.lookup_geoip(self.client_ip)
        abuse_data = threat_intel.check_abuseipdb(self.client_ip)

        # Log session in database
        db.create_session(
            self.session_id, self.client_ip, self.client_port,
            geo_info=self.geo_info, abuse_score=abuse_data.get("abuse_score", 0)
        )
        
        # Real-time Alerting
        alert_notifier.notify_new_connection(self.client_ip, self.geo_info)

        # Single choke point response decision via decide_response (Job 3)
        plan = decide_response(self.session_id, "CONNECT", {}, context={"vfs": vfs})

        # Log event using exact shared contract schema (Job 2 & 2a)
        log_event({
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "protocol": "ftp",
            "source_ip": self.client_ip,
            "session_id": self.session_id,
            "action": "CONNECT",
            "parameters": {},
            "raw_metadata": {"client_port": self.client_port, "geo_info": self.geo_info},
            "session_source": "protocol_native",
            "response_status": plan.response_status,
            "response_type": plan.response_type
        })

        # Send Welcome Banner
        self.sendLine(plan.response_text.encode('utf-8'))

    def connectionLost(self, reason):
        self.close_pasv_listener()
        # V4: reward longer dwell times so the Q-table learns to keep attackers engaged
        if self.connect_time:
            adaptive_engine.reward_dwell(self.session_id, time.time() - self.connect_time)
        adaptive_engine.session_ended(self.session_id)
        db.close_session(self.session_id)

    def lineReceived(self, line):
        try:
            line_str = line.decode('utf-8', errors='replace').rstrip('\r')
        except Exception:
            line_str = line.decode('latin-1', errors='replace').rstrip('\r')

        if not line_str.strip():
            return

        parts = line_str.split(" ", 1)
        command = parts[0].upper()
        args = parts[1] if len(parts) > 1 else ""

        # Normalize action string and build parameters dict
        if command == "USER":
            action = f"USER {args.strip()}"
            parameters = {"username": args.strip(), "raw_args": args}
        elif command == "PASS":
            action = "PASS ******"
            parameters = {"username": self.username or "unknown", "password": args.strip(), "raw_args": args}
        elif args:
            action = f"{command} {args.strip()}"
            parameters = {"command": command, "path": args.strip(), "raw_args": args}
        else:
            action = command
            parameters = {"command": command, "raw_args": args}

        # Setup PASV listener details if PASV command
        pasv_str = None
        if command == "PASV":
            pasv_str = self._prepare_pasv_response()

        # Check bounce attack if PORT command
        bounce_detected = False
        if command == "PORT":
            try:
                p_parts = args.strip().split(",")
                c_host = ".".join(p_parts[:4])
                bounce_detected = threat_intel.check_ftp_bounce(self.client_ip, c_host)
            except Exception:
                pass

        context = {
            "vfs": vfs,
            "authenticated": self.authenticated,
            "authenticated_user": self.authenticated_user,
            "username": self.username,
            # V1: the trap decision reads the LIVE per-IP failed-attempt count so
            # all concurrent sessions from one IP share the accumulation toward
            # the grant. This is the count BEFORE this attempt; decide_response
            # applies the +1 for the current PASS.
            "failed_attempts": threat_intel.get_failed_attempts(self.client_ip),
            "failed_threshold": getattr(self, "grant_threshold", FAILED_ATTEMPTS_THRESHOLD),
            "cwd": self.cwd,
            "has_uploaded": self.has_uploaded,
            "recon_done": self.recon_done,
            "active_host": self.active_host,
            "active_port": self.active_port,
            "client_ip": self.client_ip,
            "pasv_str": pasv_str,
            "bounce_detected": bounce_detected
        }

        # Decide response via single choke point seam (Job 3)
        plan = decide_response(self.session_id, action, parameters, context)

        # V1: register FAILED attempts at decision time (before any tarpit delay)
        # so concurrent sessions from one IP share the accumulation accurately.
        if command == "PASS" and not self.authenticated and not plan.extra.get("authenticated", False):
            threat_intel.register_attempt(self.client_ip)

        # Log event using exact shared contract schema (Job 2 & 2a)
        log_event({
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "protocol": "ftp",
            "source_ip": self.client_ip,
            "session_id": self.session_id,
            "action": action,
            "parameters": parameters,
            "raw_metadata": {
                "raw_line": line_str,
                "cwd": self.cwd,
                "transfer_type": self.transfer_type,
                "client_port": self.client_port
            },
            "session_source": "protocol_native",
            "response_status": plan.response_status,
            "response_type": plan.response_type
        })

        # Also log to legacy command table & MITRE classification for dashboard compatibility
        tags = mitre_mapper.classify_command(
            command, args, self.failed_attempts, self.client_ip, self.active_host
        )
        mitre_str = ",".join([t["technique_id"] for t in tags])
        db.log_command(self.session_id, self.client_ip, command, args, plan.response_status, mitre_str)

        # Dispatch command execution with tarpit delay if specified
        if plan.delay_seconds > 0:
            reactor.callLater(plan.delay_seconds, self._dispatch_plan, command, args, plan)
        else:
            self._dispatch_plan(command, args, plan)

    def _prepare_pasv_response(self):
        self.close_pasv_listener()

        def try_listen(port_candidate):
            try:
                endpoint = TCP4ServerEndpoint(reactor, port_candidate, interface=FTP_HOST)
                factory = FTPDataServerFactory()
                listener = endpoint.listen(factory)
                return listener, factory, port_candidate
            except Exception:
                return None

        listener_info = None
        for p in range(PASV_PORT_MIN, PASV_PORT_MAX + 1):
            res = try_listen(p)
            if res:
                listener_info = res
                break

        if not listener_info:
            res = try_listen(0)
            if res:
                listener_info = res

        if not listener_info:
            return None

        self.pasv_listener = listener_info[0]
        self.pasv_factory = listener_info[1]
        
        if hasattr(self.pasv_listener, 'getHost'):
            self.pasv_port = self.pasv_listener.getHost().port
        else:
            self.pasv_port = PASV_PORT_MIN

        ip_parts = (FTP_HOST if FTP_HOST != "0.0.0.0" else "127.0.0.1").split(".")
        p1 = self.pasv_port // 256
        p2 = self.pasv_port % 256
        return f"227 Entering Passive Mode ({ip_parts[0]},{ip_parts[1]},{ip_parts[2]},{ip_parts[3]},{p1},{p2})."

    def _dispatch_plan(self, command, args, plan):
        if command == "USER":
            self.username = args.strip() or "anonymous"
            self.sendLine(plan.response_text.encode('utf-8'))

        elif command == "PASS":
            password = args.strip()
            was_authenticated = self.authenticated
            self.failed_attempts = plan.extra.get("failed_attempts", self.failed_attempts + 1)
            is_auth = plan.extra.get("authenticated", False)
            if is_auth:
                self.authenticated = True
                self.authenticated_user = plan.extra.get("authenticated_user", self.username or "anonymous")
                db.log_auth_attempt(self.session_id, self.client_ip, self.username or "unknown", password, True, self.failed_attempts)
                db.update_session_auth(self.session_id, self.failed_attempts, self.authenticated_user)
                alert_notifier.notify_brute_force_threshold(
                    self.client_ip, self.failed_attempts, self.username or "unknown", password
                )
                if not was_authenticated:
                    # V6: count a completed trap cycle for this IP (may trip the ban)
                    threat_intel.register_grant(self.client_ip)
            else:
                db.log_auth_attempt(self.session_id, self.client_ip, self.username or "unknown", password, False, self.failed_attempts)
                db.update_session_auth(self.session_id, self.failed_attempts)

            self.sendLine(plan.response_text.encode('utf-8'))

        elif command in ["CWD", "CDUP"]:
            if plan.response_status == 250:
                self.cwd = plan.extra.get("new_cwd", self.cwd)
            self.sendLine(plan.response_text.encode('utf-8'))

        elif command == "TYPE":
            if plan.response_status == 200:
                self.transfer_type = plan.extra.get("transfer_type", self.transfer_type)
            self.sendLine(plan.response_text.encode('utf-8'))

        elif command == "PORT":
            if plan.response_status == 200:
                parts = args.strip().split(",")
                self.active_host = ".".join(parts[:4])
                self.active_port = int(parts[4]) * 256 + int(parts[5])
            self.sendLine(plan.response_text.encode('utf-8'))

        elif command in ["LIST", "NLST"]:
            if plan.response_status != 150:
                self.sendLine(plan.response_text.encode('utf-8'))
                return

            target = args.strip()
            if command == "LIST" and target.startswith("-"):
                parts = target.split()
                target = parts[-1] if len(parts) > 1 and not parts[-1].startswith("-") else ""

            target_path = vfs.normalize_path(self.cwd, target)
            if command == "LIST":
                items = vfs.list_dir(target_path)
            else:
                items = vfs.nlist_dir(target_path)

            if items is None:
                self.sendLine(b"550 Directory not found.")
                return

            self.recon_done = True  # V3: listing is reconnaissance, unlocks gated assets
            listing_bytes = ("\r\n".join(items) + "\r\n").encode('utf-8')
            self.sendLine(plan.response_text.encode('utf-8'))
            data_d = self._get_data_connection(mode='SEND', data=listing_bytes)

            def on_complete(_):
                self.sendLine(b"226 Directory send OK.")
                self.close_pasv_listener()

            def on_error(err):
                self.sendLine(b"425 Data connection failed.")
                self.close_pasv_listener()

            data_d.addCallbacks(on_complete, on_error)

        elif command == "RETR":
            if plan.response_status != 150:
                self.sendLine(plan.response_text.encode('utf-8'))
                return

            self.recon_done = True  # V3: a successful retrieval is also recon
            content = plan.extra.get("content", b"")
            self.sendLine(plan.response_text.encode('utf-8'))
            data_d = self._get_data_connection(mode='SEND', data=content)

            def on_complete(_):
                self.sendLine(b"226 Transfer complete.")
                self.close_pasv_listener()

            def on_error(err):
                self.sendLine(b"425 Data connection failed.")
                self.close_pasv_listener()

            data_d.addCallbacks(on_complete, on_error)

        elif command == "STOR":
            if plan.response_status != 150:
                self.sendLine(plan.response_text.encode('utf-8'))
                return

            filename = args.strip()
            vfs_path = vfs.normalize_path(self.cwd, filename)

            self.sendLine(plan.response_text.encode('utf-8'))
            data_d = self._get_data_connection(mode='RECV')

            def on_data_received(received_bytes):
                if received_bytes is None:
                    received_bytes = b""

                sha256_hash = hashlib.sha256(received_bytes).hexdigest()
                timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                safe_basename = os.path.basename(vfs_path).replace("/", "_").replace("\\", "_")
                quarantine_filename = f"{timestamp}_{sha256_hash[:8]}_{safe_basename}"
                quarantine_path = os.path.join(QUARANTINE_DIR, quarantine_filename)

                with open(quarantine_path, "wb") as f:
                    f.write(received_bytes)

                yara_matches = threat_intel.scan_yara_rules(quarantine_path)
                yara_str = ",".join(yara_matches)

                db.log_quarantined_file(
                    self.session_id,
                    self.client_ip,
                    safe_basename,
                    quarantine_filename,
                    len(received_bytes),
                    sha256_hash,
                    yara_str
                )

                vfs.add_file(vfs_path, received_bytes, owner=self.authenticated_user or "www-data")
                self.has_uploaded = True

                alert_notifier.notify_payload_uploaded(
                    self.client_ip, safe_basename, sha256_hash, len(received_bytes), self.geo_info, yara_matches
                )

                self.sendLine(b"226 File receive OK.")
                self.close_pasv_listener()

            def on_error(err):
                self.sendLine(b"425 Data connection failed.")
                self.close_pasv_listener()

            data_d.addCallbacks(on_data_received, on_error)

        elif command == "QUIT":
            self.sendLine(plan.response_text.encode('utf-8'))
            self.transport.loseConnection()

        else:
            self.sendLine(plan.response_text.encode('utf-8'))

    def send_response(self, response_text, command=None, args=None, code=None):
        """Deprecated compatibility helper; sendLine is used by _dispatch_plan"""
        self.sendLine(response_text.encode('utf-8'))

    def close_pasv_listener(self):
        if self.pasv_listener:
            try:
                self.pasv_listener.stopListening()
            except Exception:
                pass
            self.pasv_listener = None
            self.pasv_port = None
            self.pasv_factory = None

    def _get_data_connection(self, mode='SEND', data=b''):
        d = defer.Deferred()
        if self.pasv_listener and self.pasv_factory:
            self.pasv_factory.mode = mode
            self.pasv_factory.data = data
            self.pasv_factory.deferred_result = d
            return d
        elif self.active_host and self.active_port:
            proto = FTPDataProtocol(mode, data, d)
            endpoint = TCP4ClientEndpoint(reactor, self.active_host, self.active_port)
            connectProtocol(endpoint, proto)
            return d
        else:
            d.errback(Exception("No data connection established"))
            return d


class FTPHoneypotFactory(protocol.ServerFactory):
    protocol = FTPControlProtocol
