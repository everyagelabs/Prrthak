"""Private real TLS receivers; no external webhook, Slack or email is contacted.

The production dispatcher resolves a fixture-only DNS answer and pins it. The
test socket factory permits only the explicitly owned port and redirects that
logical address to loopback. Real TLS verification uses the fixture CA; it is
never disabled. The controller and its encrypted outbox are temporary.
"""
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from datetime import timedelta
from email.parser import BytesParser
from email.policy import default
import base64
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
from pathlib import Path
import socket
import socketserver
import ssl
import tempfile
import threading
import types
import unittest
from unittest.mock import patch

from controller import notifications as n
from controller.pki import init_ca
from controller.platform import PlatformManager
from controller.store import Store, now, parse_time, stamp


class QuietHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    def handle_error(self, request, address):
        pass


class WebhookHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.server.received.append((self.path, dict(self.headers), body))
        behavior = self.server.responses.pop(0) if self.server.responses else 204
        if behavior == "drop_ack":
            self.close_connection = True
            self.connection.shutdown(socket.SHUT_RDWR)
            self.connection.close()
            return
        self.send_response(behavior)
        if behavior == 503:
            self.send_header("Retry-After", "120")
        self.send_header("Content-Length", "0")
        self.end_headers()


class SMTPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    def handle_error(self, request, address):
        pass
    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(8)
        if self.implicit_tls:
            connection = self.context.wrap_socket(connection, server_side=True)
        return connection, address


class SMTPHandler(socketserver.StreamRequestHandler):
    def send(self, value):
        self.wfile.write(value)
        self.wfile.flush()

    def handle(self):
        secure = self.server.implicit_tls
        self.send(b"220 localhost private SMTP fixture\r\n")
        while True:
            line = self.rfile.readline(65536)
            if not line:
                return
            command = line.split(None, 1)[0].upper()
            self.server.commands.append((command.decode(), secure))
            if command == b"EHLO":
                self.send(b"250-localhost\r\n" + (b"250-STARTTLS\r\n" if not secure and self.server.offer_starttls else b"") + b"250 AUTH PLAIN\r\n")
            elif command == b"STARTTLS":
                self.send(b"220 Begin verified TLS\r\n")
                self.rfile.close()
                self.wfile.close()
                self.connection = self.server.context.wrap_socket(self.connection, server_side=True)
                self.rfile, self.wfile = self.connection.makefile("rb"), self.connection.makefile("wb")
                secure = True
            elif command == b"AUTH":
                if not secure:
                    self.send(b"530 TLS required\r\n")
                    return
                credential = base64.b64decode(line.strip().split()[-1])
                self.server.authenticated.append(credential == b"\x00private-fixture-user\x00private-fixture-password")
                self.send(b"235 Authentication accepted\r\n")
            elif command in (b"MAIL", b"RCPT", b"RSET"):
                self.send(b"250 Accepted\r\n")
            elif command == b"DATA":
                self.send(b"354 End with a single dot\r\n")
                lines = []
                while True:
                    line = self.rfile.readline(65536)
                    if not line or line == b".\r\n":
                        break
                    lines.append(line)
                self.server.messages.append(BytesParser(policy=default).parsebytes(b"".join(lines)))
                if self.server.drop_ack:
                    self.connection.shutdown(socket.SHUT_RDWR)
                    self.connection.close()
                    return
                self.send(b"250 Queued by private fixture\r\n")
            elif command == b"QUIT":
                self.send(b"221 Bye\r\n")
                return
            else:
                self.send(b"500 Unsupported fixture command\r\n")


class PrivateNotificationTransportTests(unittest.TestCase):
    def setUp(self):
        self.resources = ExitStack()
        self.addCleanup(self.resources.close)
        self.root = Path(self.resources.enter_context(tempfile.TemporaryDirectory(prefix="prthak-private-notification-")))
        self.pki = init_ca(self.root / "tls")
        self.store = Store(self.root / "controller")
        with self.store.meta() as db:
            n.initialize(db)
        self.manager = PlatformManager(self.root / "private")
        self.manager.app = types.SimpleNamespace(store=self.store, demo=False)
        self.manager.shared_secret_key = lambda purpose: b"private-fixture-key-not-for-prod!"[:32]
        self.ca = (self.pki / "ca.pem").read_text()
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.load_cert_chain(self.pki / "controller.pem", self.pki / "controller-key.pem")
        self.ports = set()
        self.pinned_connections = []
        self.logs = io.StringIO()
        self.resources.enter_context(redirect_stdout(self.logs))
        self.resources.enter_context(redirect_stderr(self.logs))

    @staticmethod
    def resolver(host, port, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port))]

    def connect_private_fixture(self, destination, timeout=10, source_address=None, **kwargs):
        host, port = destination
        if host != "8.8.8.8" or port not in self.ports or source_address is not None:
            raise AssertionError("No unowned or external socket is allowed in this fixture")
        self.pinned_connections.append(destination)
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection.settimeout(timeout)
        connection.connect(("127.0.0.1", port))
        return connection

    def serve(self, server):
        self.ports.add(server.server_address[1])
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        def close():
            server.shutdown()
            server.server_close()
            thread.join(3)
        self.resources.callback(close)
        return server

    def configure(self, channel):
        body = {"expected_revision": n.get(self.manager)["revision"], "enabled": True, "channels": [{"id": "private-transport", "name": "Private transport fixture", "enabled": True, "minimum_severity": "warning", "event_types": ["*"], "custom_ca_pem": self.ca, **channel}]}
        plan = n.preview(self.manager, body, "fixture-super-admin", resolver=self.resolver)
        confirmation = {"preview_id": plan["id"], **{key: plan[key] for key in ("digest", "confirmation_nonce", "confirmation_phrase")}}
        n.apply(self.manager, confirmation, "fixture-super-admin", resolver=self.resolver)

    def queue(self, identifier):
        with self.store.meta() as db:
            self.store._put(db, "alerts", {"id": identifier, "kind": "port_scan", "severity": "warning", "message": "Private TLS transport acceptance event", "status": "open", "created_at": stamp()})
        self.assertEqual(n.enqueue_alerts(self.manager), 1)
        return next(row for row in n.deliveries(self.store)["items"] if row["event"].get("alert_id") == identifier)

    def dispatch(self, at=None):
        with patch.object(n.socket, "getaddrinfo", self.resolver), patch.object(n.socket, "create_connection", self.connect_private_fixture):
            return n.run_once(self.manager, at=at)

    def delivery(self, identifier):
        return next(row for row in n.deliveries(self.store)["items"] if row["id"] == identifier)

    def assert_no_credentials_in_public_or_logs(self):
        public = json.dumps(n.get(self.manager)) + json.dumps(n.deliveries(self.store)) + json.dumps(self.store.all("audit")) + self.logs.getvalue()
        for value in ("private-fixture-password", "private-fixture-user", "private-webhook-url-token", "private-hmac-token"):
            self.assertNotIn(value, public)

    def test_real_https_provider_ack_backoff_signature_and_ambiguous_outcome(self):
        server = QuietHTTPServer(("127.0.0.1", 0), WebhookHandler)
        server.socket = self.context.wrap_socket(server.socket, server_side=True)
        server.received, server.responses = [], [503, 204]
        self.serve(server)
        port = server.server_address[1]
        self.configure({"type": "webhook", "url": "https://localhost:" + str(port) + "/notify?token=private-webhook-url-token", "signing_secret": "private-hmac-token"})
        queued, at = self.queue("webhook-real"), now()
        self.dispatch(at)
        first = self.delivery(queued["id"])
        self.assertEqual(first["status"], "retry")
        self.assertGreaterEqual((parse_time(first["next_attempt_at"]) - at).total_seconds(), 119)
        self.assertEqual(self.dispatch(at + timedelta(seconds=30))["processed"], 0)
        self.dispatch(at + timedelta(seconds=121))
        self.assertEqual(self.delivery(queued["id"])["status"], "delivered")
        self.assertEqual([request[1]["Idempotency-Key"] for request in server.received], [queued["id"], queued["id"]])
        self.assertEqual(server.received[0][2], server.received[1][2])
        for path, headers, body in server.received:
            expected = "v1=" + hmac.new(b"private-hmac-token", headers["X-Prthak-Timestamp"].encode() + b"." + body, hashlib.sha256).hexdigest()
            self.assertEqual(headers["X-Prthak-Signature"], expected)
        server.responses = ["drop_ack"]
        unknown = self.queue("webhook-unknown")
        self.dispatch()
        self.assertEqual(self.delivery(unknown["id"])["status"], "uncertain")
        self.assertEqual(self.dispatch()["processed"], 0)
        self.assertEqual(len(server.received), 3)
        self.assertTrue(self.pinned_connections)
        self.assert_no_credentials_in_public_or_logs()

    def test_real_smtp_starttls_implicit_tls_and_lost_ack_keep_credentials_private(self):
        for security in ("starttls", "tls"):
            server = SMTPServer(("127.0.0.1", 0), SMTPHandler)
            server.context, server.implicit_tls, server.offer_starttls, server.drop_ack = self.context, security == "tls", True, False
            server.commands, server.messages, server.authenticated = [], [], []
            self.serve(server)
            self.configure({"id": "smtp-" + security, "type": "email", "smtp_host": "localhost", "smtp_port": server.server_address[1], "smtp_security": security,
                            "username": "private-fixture-user", "password": "private-fixture-password", "from_address": "alerts@example.test", "to_addresses": ["operator@example.test"]})
            queued = self.queue("smtp-real-" + security)
            self.dispatch()
            self.assertEqual(self.delivery(queued["id"])["status"], "delivered")
            self.assertEqual(server.authenticated, [True])
            self.assertTrue(all(secure for command, secure in server.commands if command in ("AUTH", "MAIL", "RCPT", "DATA")))
            self.assertEqual(server.messages[0]["Message-ID"], "<" + queued["id"] + "@prthak.invalid>")
            server.drop_ack = True
            unknown = self.queue("smtp-unknown-" + security)
            self.dispatch()
            self.assertEqual(self.delivery(unknown["id"])["status"], "uncertain")
            self.assertEqual(self.dispatch()["processed"], 0)
            server.drop_ack = False
            n.retry(self.manager, unknown["id"], {"expected_revision": n.get(self.manager)["revision"], "expected_attempts": 1, "confirm_possible_duplicate": True}, "fixture-super-admin")
            self.dispatch()
            self.assertEqual(self.delivery(unknown["id"])["status"], "delivered")
            self.assertEqual(server.messages[-1]["Message-ID"], server.messages[-2]["Message-ID"])
        self.assert_no_credentials_in_public_or_logs()

    def test_unknown_tls_authority_and_missing_starttls_never_send_credentials_or_payload(self):
        server = QuietHTTPServer(("127.0.0.1", 0), WebhookHandler)
        server.socket = self.context.wrap_socket(server.socket, server_side=True)
        server.received, server.responses = [], []
        self.serve(server)
        self.configure({"id": "untrusted-tls", "type": "webhook", "url": "https://localhost:" + str(server.server_address[1]) + "/notify", "custom_ca_pem": ""})
        queued = self.queue("untrusted-certificate")
        self.dispatch()
        self.assertEqual(self.delivery(queued["id"])["status"], "retry")
        self.assertEqual(server.received, [])
        smtp = SMTPServer(("127.0.0.1", 0), SMTPHandler)
        smtp.context, smtp.implicit_tls, smtp.offer_starttls, smtp.drop_ack = self.context, False, False, False
        smtp.commands, smtp.messages, smtp.authenticated = [], [], []
        self.serve(smtp)
        self.configure({"id": "missing-starttls", "type": "email", "smtp_host": "localhost", "smtp_port": smtp.server_address[1], "smtp_security": "starttls",
                        "username": "private-fixture-user", "password": "private-fixture-password", "from_address": "alerts@example.test", "to_addresses": ["operator@example.test"]})
        queued = self.queue("missing-starttls")
        self.dispatch()
        self.assertEqual(self.delivery(queued["id"])["status"], "failed")
        self.assertEqual(smtp.messages, [])
        self.assertFalse(any(command == "AUTH" for command, _ in smtp.commands))
        self.assert_no_credentials_in_public_or_logs()


if __name__ == "__main__":
    unittest.main()
