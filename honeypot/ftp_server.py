import os
import re
import uuid
import hashlib
import datetime
import posixpath
import logging

from twisted.internet import reactor, protocol, defer, threads
from twisted.protocols.basic import LineReceiver
from twisted.internet.endpoints import TCP4ClientEndpoint, connectProtocol

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

logger = logging.getLogger("AegisFTP.Server")

# Shared Virtual Filesystem instance across sessions
vfs = VirtualFileSystem()


class FTPDataProtocol(protocol.Protocol):
    def __init__(self, factory):
        self.factory = factory
        self.received_bytes = bytearray()

    def connectionMade(self):
        self.factory.protocol_connected(self)

    def dataReceived(self, chunk):
        if self.factory.mode == 'RECV':
            self.received_bytes.extend(chunk)

    def connectionLost(self, reason):
        if self.factory.mode == 'RECV' and self.factory.deferred_result and not self.factory.deferred_result.called:
            self.factory.deferred_result.callback(bytes(self.received_bytes))


class FTPDataServerFactory(protocol.ServerFactory):
    def __init__(self):
        self.mode = None  # 'SEND' or 'RECV'
        self.data = b''
        self.deferred_result = None
        self.proto_instance = None

    def buildProtocol(self, addr):
        proto = FTPDataProtocol(self)
        return proto

    def protocol_connected(self, proto):
        self.proto_instance = proto
        self._check_and_execute()

    def start_transfer(self, mode, data=b'', deferred_result=None):
        self.mode = mode
        self.data = data
        self.deferred_result = deferred_result
        self._check_and_execute()

    def _check_and_execute(self):
        if not self.proto_instance or not self.mode:
            return
        if self.mode == 'SEND':
            self.proto_instance.transport.write(self.data)
            self.proto_instance.transport.loseConnection()
            if self.deferred_result and not self.deferred_result.called:
                self.deferred_result.callback(True)


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
        self.geo_info = {"country": "Unknown", "country_code": "XX", "city": "Unknown", "isp": "Unknown"}

        # Log session in database immediately
        db.create_session(
            self.session_id, self.client_ip, self.client_port,
            geo_info=self.geo_info, abuse_score=0
        )

        # Single choke point response decision via decide_response
        plan = decide_response(self.session_id, "CONNECT", {}, context={"vfs": vfs})

        # Log event using exact shared contract schema
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

        # Background thread: GeoIP, AbuseIPDB, and Alerting without blocking Twisted reactor
        def bg_threat_lookups(ip):
            geo = threat_intel.lookup_geoip(ip)
            abuse = threat_intel.check_abuseipdb(ip)
            return geo, abuse

        def on_threat_lookups_done(result):
            geo, abuse = result
            self.geo_info = geo
            abuse_score = abuse.get("abuse_score", 0)
            try:
                conn = db.get_connection()
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE sessions 
                    SET country = ?, country_code = ?, city = ?, isp = ?, abuse_score = ?
                    WHERE session_id = ?
                """, (
                    geo.get("country", "Unknown"), geo.get("country_code", "XX"),
                    geo.get("city", "Unknown"), geo.get("isp", "Unknown"),
                    abuse_score, self.session_id
                ))
                conn.commit()
                conn.close()
            except Exception as e:
                logger.debug(f"Session geo update failed: {e}")
            threads.deferToThread(alert_notifier.notify_new_connection, self.client_ip, self.geo_info)

        threads.deferToThread(bg_threat_lookups, self.client_ip).addCallback(on_threat_lookups_done)

    def connectionLost(self, reason):
        self.close_pasv_listener()
        try:
            summary_tags = mitre_mapper.get_session_mitre_summary(db, self.session_id)
            tags_str = ",".join([t["technique_id"] for t in summary_tags])
            db.update_session_mitre_tags(self.session_id, tags_str)
        except Exception as e:
            logger.debug(f"Failed to update session mitre tags on disconnect: {e}")
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

        # Normalize action string and build parameters dict per Adapter Contract Job 2
        clean_args = args.strip()
        if command == "USER":
            action = f"USER {clean_args}" if clean_args else "USER"
            parameters = {"command": "USER", "username": clean_args, "raw_args": args}
        elif command == "PASS":
            action = "PASS ******"
            parameters = {"command": "PASS", "username": self.username or "unknown", "password": clean_args, "raw_args": args}
        elif command in ["CWD", "RETR", "STOR", "SIZE", "DELE", "MKD", "RMD"]:
            action = f"{command} {clean_args}" if clean_args else command
            parameters = {"command": command, "path": clean_args, "raw_args": args}
        elif command == "PORT":
            action = f"PORT {clean_args}" if clean_args else "PORT"
            parameters = {"command": "PORT", "raw_args": args}
            try:
                p_parts = clean_args.split(",")
                if len(p_parts) == 6:
                    parameters["host"] = ".".join(p_parts[:4])
                    parameters["port"] = int(p_parts[4]) * 256 + int(p_parts[5])
            except Exception:
                pass
        elif command == "TYPE":
            action = f"TYPE {clean_args}" if clean_args else "TYPE"
            parameters = {"command": "TYPE", "type": clean_args.upper(), "raw_args": args}
        elif clean_args:
            action = f"{command} {clean_args}"
            parameters = {"command": command, "raw_args": args}
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
            "failed_attempts": self.failed_attempts,
            "failed_threshold": FAILED_ATTEMPTS_THRESHOLD,
            "cwd": self.cwd,
            "has_uploaded": self.has_uploaded,
            "active_host": self.active_host,
            "active_port": self.active_port,
            "client_ip": self.client_ip,
            "pasv_str": pasv_str,
            "bounce_detected": bounce_detected
        }

        # Decide response via single choke point seam (Job 3)
        plan = decide_response(self.session_id, action, parameters, context)

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

        bound_port = None
        listener = None
        factory = FTPDataServerFactory()

        import socket
        # Try ports in candidate range
        for p in range(PASV_PORT_MIN, PASV_PORT_MAX + 1):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.bind((FTP_HOST, p))
                s.close()
            except Exception:
                s.close()
                continue
            try:
                listener = reactor.listenTCP(p, factory, interface=FTP_HOST)
                bound_port = p
                break
            except Exception:
                continue

        # If range exhausted, allow OS to assign an ephemeral port
        if not listener:
            try:
                listener = reactor.listenTCP(0, factory, interface=FTP_HOST)
                bound_port = listener.getHost().port
            except Exception:
                return None

        self.pasv_listener = listener
        self.pasv_factory = factory
        self.pasv_port = bound_port

        ip_parts = (FTP_HOST if FTP_HOST != "0.0.0.0" else "127.0.0.1").split(".")
        p1 = self.pasv_port // 256
        p2 = self.pasv_port % 256
        return f"227 Entering Passive Mode ({ip_parts[0]},{ip_parts[1]},{ip_parts[2]},{ip_parts[3]},{p1},{p2})."

    def _dispatch_plan(self, command, args, plan):
        if command == "USER":
            raw_user = (args or "").strip()
            self.username = raw_user if raw_user else "anonymous"
            self.sendLine(plan.response_text.encode('utf-8'))

        elif command == "PASS":
            password = args.strip()
            self.failed_attempts = plan.extra.get("failed_attempts", self.failed_attempts + 1)
            is_auth = plan.extra.get("authenticated", False)
            if is_auth:
                self.authenticated = True
                self.authenticated_user = plan.extra.get("authenticated_user", self.username or "anonymous")
                db.log_auth_attempt(self.session_id, self.client_ip, self.username or "unknown", password, True, self.failed_attempts)
                db.update_session_auth(self.session_id, self.failed_attempts, self.authenticated_user)
                threads.deferToThread(
                    alert_notifier.notify_brute_force_threshold,
                    self.client_ip, self.failed_attempts, self.username or "unknown", password
                )
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
                try:
                    parts = [int(p.strip()) for p in args.strip().split(",")]
                    if len(parts) == 6:
                        self.active_host = ".".join(str(p) for p in parts[:4])
                        self.active_port = parts[4] * 256 + parts[5]
                except Exception:
                    pass
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
                self.sendLine(b"550 Directory or file not found.")
                return

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
            if not filename:
                self.sendLine(b"501 Syntax error, filename required.")
                return

            vfs_path = vfs.normalize_path(self.cwd, filename)

            self.sendLine(plan.response_text.encode('utf-8'))
            data_d = self._get_data_connection(mode='RECV')

            def on_data_received(received_bytes):
                if received_bytes is None:
                    received_bytes = b""

                sha256_hash = hashlib.sha256(received_bytes).hexdigest()
                timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                safe_raw = os.path.basename(vfs_path.replace("\\", "/"))
                safe_basename = re.sub(r'[^a-zA-Z0-9._-]', '_', safe_raw) or "payload.bin"
                quarantine_filename = f"{timestamp}_{sha256_hash[:8]}_{safe_basename}"
                quarantine_path = os.path.join(QUARANTINE_DIR, quarantine_filename)

                try:
                    with open(quarantine_path, "wb") as f:
                        f.write(received_bytes)
                except Exception as e:
                    logger.error(f"Failed to write quarantined file {quarantine_path}: {e}")

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

                threads.deferToThread(
                    alert_notifier.notify_payload_uploaded,
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
            self.pasv_factory.start_transfer(mode, data, d)
            return d
        elif self.active_host and self.active_port:
            factory = FTPDataServerFactory()
            endpoint = TCP4ClientEndpoint(reactor, self.active_host, self.active_port)
            def on_connected(proto):
                factory.protocol_connected(proto)
                factory.start_transfer(mode, data, d)
            def on_connect_fail(err):
                if not d.called:
                    d.errback(err)
            connectProtocol(endpoint, factory.buildProtocol(None)).addCallbacks(on_connected, on_connect_fail)
            self.active_host = None
            self.active_port = None
            return d
        else:
            d.errback(Exception("No data connection established"))
            return d


class FTPHoneypotFactory(protocol.ServerFactory):
    protocol = FTPControlProtocol
