import os
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
from honeypot.database import db
from honeypot.virtual_fs import VirtualFileSystem
from honeypot.adaptive import adaptive_engine
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

        # Send Welcome Banner
        self.send_response(FTP_WELCOME_BANNER)

    def connectionLost(self, reason):
        self.close_pasv_listener()
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

        # Adaptive Deception Engine Evaluation (Tarpit delay & Dynamic honeypot asset injection)
        adaptive_eval = adaptive_engine.evaluate_response(
            self.session_id, command, args, vfs, self.has_uploaded
        )

        delay = adaptive_eval.get("delay_seconds", 0.0)

        # Dispatch command with optional tarpit delay
        if delay > 0:
            reactor.callLater(delay, self._dispatch_command, command, args)
        else:
            self._dispatch_command(command, args)

    def _dispatch_command(self, command, args):
        handler_name = f"ftp_{command}"
        if hasattr(self, handler_name):
            handler = getattr(self, handler_name)
            handler(args)
        else:
            self.send_response(f"500 Unknown command '{command}'.", command, args, 500)

    def send_response(self, response_text, command=None, args=None, code=None):
        if code is None:
            try:
                code = int(response_text.split()[0])
            except (ValueError, IndexError):
                code = 200

        if command:
            # MITRE ATT&CK Classification
            tags = mitre_mapper.classify_command(
                command, args, self.failed_attempts, self.client_ip, self.active_host
            )
            mitre_str = ",".join([t["technique_id"] for t in tags])
            db.log_command(self.session_id, self.client_ip, command, args, code, mitre_str)

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

    # --- FTP Command Handlers ---

    def ftp_USER(self, args):
        self.username = args.strip() or "anonymous"
        self.send_response(f"331 Password required for {self.username}.", "USER", args, 331)

    def ftp_PASS(self, args):
        password = args.strip()
        self.failed_attempts += 1

        if self.failed_attempts <= FAILED_ATTEMPTS_THRESHOLD:
            db.log_auth_attempt(self.session_id, self.client_ip, self.username or "unknown", password, False, self.failed_attempts)
            db.update_session_auth(self.session_id, self.failed_attempts)
            self.send_response("530 Login incorrect.", "PASS", "******", 530)
        else:
            self.authenticated = True
            self.authenticated_user = self.username or "anonymous"
            db.log_auth_attempt(self.session_id, self.client_ip, self.username or "unknown", password, True, self.failed_attempts)
            db.update_session_auth(self.session_id, self.failed_attempts, self.authenticated_user)
            
            # Send real-time webhook alert
            alert_notifier.notify_brute_force_threshold(
                self.client_ip, self.failed_attempts, self.username or "unknown", password
            )
            self.send_response("230 User logged in, proceed.", "PASS", "******", 230)

    def ftp_SYST(self, args):
        self.send_response("215 UNIX Type: L8", "SYST", args, 215)

    def ftp_FEAT(self, args):
        feat_response = (
            "211-Features:\r\n"
            " PASV\r\n"
            " UTF8\r\n"
            " REST STREAM\r\n"
            " SIZE\r\n"
            " MLSD\r\n"
            "211 End"
        )
        self.send_response(feat_response, "FEAT", args, 211)

    def ftp_PWD(self, args):
        self.send_response(f'257 "{self.cwd}" is current directory.', "PWD", args, 257)

    def ftp_XPWD(self, args):
        self.ftp_PWD(args)

    def ftp_CWD(self, args):
        if not self.authenticated:
            self.send_response("530 Please login with USER and PASS.", "CWD", args, 530)
            return

        target_path = vfs.normalize_path(self.cwd, args.strip())
        node = vfs.get_node(target_path)

        if node and node.is_dir:
            self.cwd = target_path
            self.send_response(f'250 Directory successfully changed to "{self.cwd}".', "CWD", args, 250)
        else:
            self.send_response("550 Failed to change directory.", "CWD", args, 550)

    def ftp_CDUP(self, args):
        if not self.authenticated:
            self.send_response("530 Please login with USER and PASS.", "CDUP", args, 530)
            return

        self.ftp_CWD("..")

    def ftp_TYPE(self, args):
        mode = args.strip().upper()
        if mode in ["A", "I"]:
            self.transfer_type = mode
            self.send_response(f"200 Switching to {mode} mode.", "TYPE", args, 200)
        else:
            self.send_response("504 Command not implemented for that parameter.", "TYPE", args, 504)

    def ftp_PASV(self, args):
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
            self.send_response("425 Can't open data connection.", "PASV", args, 425)
            return

        def on_listen_success(port_object):
            self.pasv_listener = port_object
            self.pasv_port = port_object.getHost().port
            
            ip_parts = (FTP_HOST if FTP_HOST != "0.0.0.0" else "127.0.0.1").split(".")
            p1 = self.pasv_port // 256
            p2 = self.pasv_port % 256
            pasv_str = f"227 Entering Passive Mode ({ip_parts[0]},{ip_parts[1]},{ip_parts[2]},{ip_parts[3]},{p1},{p2})."
            self.send_response(pasv_str, "PASV", args, 227)

        listener_deferred = listener_info[0]
        if isinstance(listener_deferred, defer.Deferred):
            self.pasv_factory = listener_info[1]
            listener_deferred.addCallback(on_listen_success)
        else:
            self.pasv_listener = listener_info[0]
            self.pasv_factory = listener_info[1]
            on_listen_success(listener_info[0])

    def ftp_PORT(self, args):
        try:
            parts = args.strip().split(",")
            if len(parts) != 6:
                raise ValueError
            candidate_host = ".".join(parts[:4])
            candidate_port = int(parts[4]) * 256 + int(parts[5])

            # Enhanced Detection: FTP Bounce Attack Prevention
            if threat_intel.check_ftp_bounce(self.client_ip, candidate_host):
                self.send_response("501 Illegal PORT command (FTP Bounce Attack detected).", "PORT", args, 501)
                return

            self.active_host = candidate_host
            self.active_port = candidate_port
            self.send_response("200 PORT command successful.", "PORT", args, 200)
        except Exception:
            self.send_response("501 Illegal PORT command.", "PORT", args, 501)

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

    def ftp_LIST(self, args):
        if not self.authenticated:
            self.send_response("530 Please login with USER and PASS.", "LIST", args, 530)
            return

        target = args.strip()
        if target.startswith("-"):
            parts = target.split()
            target = parts[-1] if len(parts) > 1 and not parts[-1].startswith("-") else ""

        target_path = vfs.normalize_path(self.cwd, target)
        listing = vfs.list_dir(target_path)

        if listing is None:
            self.send_response("550 Directory not found.", "LIST", args, 550)
            return

        listing_bytes = ("\r\n".join(listing) + "\r\n").encode('utf-8')

        self.send_response("150 Here comes the directory listing.", "LIST", args, 150)
        data_d = self._get_data_connection(mode='SEND', data=listing_bytes)

        def on_complete(_):
            self.send_response("226 Directory send OK.", "LIST", args, 226)
            self.close_pasv_listener()

        def on_error(err):
            self.send_response("425 Data connection failed.", "LIST", args, 425)
            self.close_pasv_listener()

        data_d.addCallbacks(on_complete, on_error)

    def ftp_NLST(self, args):
        if not self.authenticated:
            self.send_response("530 Please login with USER and PASS.", "NLST", args, 530)
            return

        target_path = vfs.normalize_path(self.cwd, args.strip())
        names = vfs.nlist_dir(target_path)

        if names is None:
            self.send_response("550 Directory not found.", "NLST", args, 550)
            return

        listing_bytes = ("\r\n".join(names) + "\r\n").encode('utf-8')
        self.send_response("150 Here comes the directory listing.", "NLST", args, 150)
        data_d = self._get_data_connection(mode='SEND', data=listing_bytes)

        def on_complete(_):
            self.send_response("226 Directory send OK.", "NLST", args, 226)
            self.close_pasv_listener()

        data_d.addBoth(lambda _: self.close_pasv_listener())

    def ftp_RETR(self, args):
        if not self.authenticated:
            self.send_response("530 Please login with USER and PASS.", "RETR", args, 530)
            return

        filename = args.strip()
        target_path = vfs.normalize_path(self.cwd, filename)
        content = vfs.get_file_content(target_path)

        if content is None:
            self.send_response("550 Failed to open file.", "RETR", args, 550)
            return

        self.send_response(f"150 Opening BINARY mode data connection for {filename} ({len(content)} bytes).", "RETR", args, 150)
        data_d = self._get_data_connection(mode='SEND', data=content)

        def on_complete(_):
            self.send_response("226 Transfer complete.", "RETR", args, 226)
            self.close_pasv_listener()

        def on_error(err):
            self.send_response("425 Data connection failed.", "RETR", args, 425)
            self.close_pasv_listener()

        data_d.addCallbacks(on_complete, on_error)

    def ftp_STOR(self, args):
        if not self.authenticated:
            self.send_response("530 Please login with USER and PASS.", "STOR", args, 530)
            return

        filename = args.strip()
        vfs_path = vfs.normalize_path(self.cwd, filename)

        self.send_response("150 Ok to send data.", "STOR", args, 150)
        data_d = self._get_data_connection(mode='RECV')

        def on_data_received(received_bytes):
            if received_bytes is None:
                received_bytes = b""

            sha256_hash = hashlib.sha256(received_bytes).hexdigest()
            timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            safe_basename = os.path.basename(vfs_path).replace("/", "_").replace("\\", "_")
            quarantine_filename = f"{timestamp}_{sha256_hash[:8]}_{safe_basename}"
            quarantine_path = os.path.join(QUARANTINE_DIR, quarantine_filename)

            # Save payload to quarantine
            with open(quarantine_path, "wb") as f:
                f.write(received_bytes)

            # Enhanced Detection: YARA Rule Scanner
            yara_matches = threat_intel.scan_yara_rules(quarantine_path)
            yara_str = ",".join(yara_matches)

            # Log payload in SQLite database
            db.log_quarantined_file(
                self.session_id,
                self.client_ip,
                safe_basename,
                quarantine_filename,
                len(received_bytes),
                sha256_hash,
                yara_str
            )

            # Add to Virtual Filesystem dynamically
            vfs.add_file(vfs_path, received_bytes, owner=self.authenticated_user or "www-data")
            self.has_uploaded = True

            # Real-time Webhook Alerting
            alert_notifier.notify_payload_uploaded(
                self.client_ip, safe_basename, sha256_hash, len(received_bytes), self.geo_info, yara_matches
            )

            self.send_response("226 File receive OK.", "STOR", args, 226)
            self.close_pasv_listener()

        def on_error(err):
            self.send_response("425 Data connection failed.", "STOR", args, 425)
            self.close_pasv_listener()

        data_d.addCallbacks(on_data_received, on_error)

    def ftp_SIZE(self, args):
        if not self.authenticated:
            self.send_response("530 Please login with USER and PASS.", "SIZE", args, 530)
            return

        target_path = vfs.normalize_path(self.cwd, args.strip())
        node = vfs.get_node(target_path)

        if node and not node.is_dir:
            self.send_response(f"213 {node.size}", "SIZE", args, 213)
        else:
            self.send_response("550 Could not get file size.", "SIZE", args, 550)

    def ftp_DELE(self, args):
        if not self.authenticated:
            self.send_response("530 Please login with USER and PASS.", "DELE", args, 530)
            return

        target_path = vfs.normalize_path(self.cwd, args.strip())
        if vfs.remove_node(target_path):
            self.send_response("250 Delete operation successful.", "DELE", args, 250)
        else:
            self.send_response("550 File not found.", "DELE", args, 550)

    def ftp_MKD(self, args):
        if not self.authenticated:
            self.send_response("530 Please login with USER and PASS.", "MKD", args, 530)
            return

        target_path = vfs.normalize_path(self.cwd, args.strip())
        if vfs.create_dir(target_path):
            self.send_response(f'257 "{target_path}" directory created.', "MKD", args, 257)
        else:
            self.send_response("550 Create directory operation failed.", "MKD", args, 550)

    def ftp_RMD(self, args):
        if not self.authenticated:
            self.send_response("530 Please login with USER and PASS.", "RMD", args, 530)
            return

        target_path = vfs.normalize_path(self.cwd, args.strip())
        if vfs.remove_node(target_path):
            self.send_response("250 Remove directory operation successful.", "RMD", args, 250)
        else:
            self.send_response("550 Directory not found.", "RMD", args, 550)

    def ftp_NOOP(self, args):
        self.send_response("200 OK.", "NOOP", args, 200)

    def ftp_QUIT(self, args):
        self.send_response("221 Goodbye.", "QUIT", args, 221)
        self.transport.loseConnection()


class FTPHoneypotFactory(protocol.ServerFactory):
    protocol = FTPControlProtocol
