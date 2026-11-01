"""Owned real CLI/Gunicorn recovery, with stored Entra session fixtures.

This proves TLS/process/drain/admission behavior, not a live Microsoft tenant.
The parent-only file gate delays its private readiness probe; child code is
unmodified and the full database restore/HTTPS transport run normally.
"""
import base64
from datetime import timedelta
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import time
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from controller.auth import EntraConfig, SESSION_COOKIE
from controller.platform import _read_json
from controller.store import Store, now, stamp

ROOT = Path(__file__).resolve().parents[1]


class RecoveryCLIHTTPSAcceptance(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="prthak-reviewed-recovery-https-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.data, self.pki = self.root / "controller", self.root / "pki"
        self.pki.mkdir(mode=0o700)
        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Private recovery acceptance CA")])
        ca = x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now() - timedelta(minutes=2)).not_valid_after(now() + timedelta(days=30)).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(ca_key, hashes.SHA256())
        key = ec.generate_private_key(ec.SECP256R1())
        leaf = x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])).issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now() - timedelta(minutes=2)).not_valid_after(now() + timedelta(days=10)).add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True).add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False).add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False).sign(ca_key, hashes.SHA256())
        for name, value in (("ca.pem", ca.public_bytes(serialization.Encoding.PEM)), ("ca-key.pem", ca_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())), ("controller.pem", leaf.public_bytes(serialization.Encoding.PEM)), ("controller-key.pem", key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))):
            (self.pki / name).write_bytes(value)
            (self.pki / name).chmod(0o600)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            self.port = listener.getsockname()[1]
        self.context = ssl.create_default_context(cafile=str(self.pki / "ca.pem"))
        self.origin = "https://localhost:" + str(self.port)
        self.config = EntraConfig(tenant_id="11111111-1111-1111-1111-111111111111", client_id="22222222-2222-2222-2222-222222222222", redirect_uri=self.origin + "/api/v1/auth/callback", client_secret=secrets.token_urlsafe(40))
        self.store = Store(self.data)
        self.store.report("fixture", {"hostname": "recovery-native-fixture", "ips": ["10.249.10.10"], "listeners": []})
        self.cookies = [secrets.token_urlsafe(40), secrets.token_urlsafe(40)]
        with self.store.meta() as db:
            for raw, oid in zip(self.cookies, ("33333333-3333-3333-3333-333333333333", "44444444-4444-4444-4444-444444444444")):
                identity = self.config.tenant_id + ":" + oid
                self.store._put(db, "auth_users", {"id": identity, "tenant_id": self.config.tenant_id, "object_id": oid, "role": "super_admin", "enabled": True, "display_name": "Stored real-session fixture"})
                self.store._put(db, "auth_sessions", {"id": hashlib.sha256(raw.encode()).hexdigest(), "user_id": identity, "expires_at": stamp(now() + timedelta(hours=1)), "config": self.config.fingerprint})
        self.process, self.log = None, None
        self.addCleanup(self.stop)

    def request(self, method, path, body=None, person=0, extra=None):
        headers = dict(extra or {})
        if person is not None:
            raw = self.cookies[person]
            headers["Cookie"] = SESSION_COOKIE + "=" + raw
            headers["X-CSRF-Token"] = base64.urlsafe_b64encode(hmac.new(raw.encode(), b"prthak-csrf-v1", hashlib.sha256).digest()).decode().rstrip("=")
            headers["Origin"] = self.origin
        if body is not None:
            headers["Content-Type"] = "application/json"
        connection = http.client.HTTPSConnection("localhost", self.port, context=self.context, timeout=3)
        try:
            connection.request(method, path, json.dumps(body) if body is not None else None, headers)
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def start(self):
        environment = {key: value for key, value in os.environ.items() if not key.startswith(("SEG_", "PRTHAK_")) and key != "CONTROLLER_ORIGIN"}
        environment.update(SEG_ENTRA_TENANT_ID=self.config.tenant_id, SEG_ENTRA_CLIENT_ID=self.config.client_id, SEG_ENTRA_REDIRECT_URI=self.config.redirect_uri, SEG_ENTRA_CLIENT_SECRET=self.config.client_secret, CONTROLLER_ORIGIN=self.origin, PYTHONPYCACHEPREFIX="/private/tmp/prthak-recovery-cli-pycache")
        gate, seen = str(self.root / "release-private-ready"), str(self.root / "private-ready-seen")
        wrapper = ("from pathlib import Path\nimport controller.platform_runtime as runtime\noriginal=runtime.probe_readiness\n"
                   "def controlled(arguments,profile=None,tls_hostname=None,recovery_nonce=None):\n"
                   "    if recovery_nonce:\n        Path(" + repr(seen) + ").touch()\n        if not Path(" + repr(gate) + ").exists():return False\n"
                   "    return original(arguments,profile,tls_hostname=tls_hostname,recovery_nonce=recovery_nonce)\n"
                   "runtime.probe_readiness=controlled\nfrom controller.__main__ import main\nmain()\n")
        arguments = ["--listen", "127.0.0.1:" + str(self.port), "--data-dir", str(self.data), "--controller-id", "recovery-cli-fixture", "--cert", str(self.pki / "controller.pem"), "--key", str(self.pki / "controller-key.pem"), "--ca", str(self.pki / "ca.pem"), "--ca-key", str(self.pki / "ca-key.pem"), "--http-backend", "gunicorn"]
        self.log = (self.root / "controller.log").open("ab")
        self.process = subprocess.Popen([sys.executable, "-c", wrapper, *arguments], cwd=ROOT, env=environment, stdout=self.log, stderr=self.log, start_new_session=True)
        self.wait(lambda: self.request("GET", "/readyz", person=None)[0] == 200)

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                for row in subprocess.check_output(["ps", "-axo", "pid=,ppid="], text=True).splitlines():
                    pid, parent = map(int, row.split())
                    if parent == self.process.pid:
                        try:
                            os.killpg(pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                self.process.kill()
                self.process.wait(timeout=5)
        if self.log:
            self.log.close()

    def wait(self, predicate, timeout=35):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.process and self.process.poll() is not None:
                self.fail("Owned supervisor exited: " + (self.root / "controller.log").read_text()[-3000:])
            try:
                if predicate():
                    return
            except (OSError, ssl.SSLError, http.client.HTTPException):
                pass
            time.sleep(.1)
        self.fail("Owned recovery did not reach expected state: " + (self.root / "controller.log").read_text()[-3000:])

    def test_real_gunicorn_restore_holds_public_admission_then_invalidates_old_sessions(self):
        self.start()
        original_pid = self.process.pid
        groups = [int(row.split()[0]) for row in subprocess.check_output(["ps", "-axo", "pid=,ppid="], text=True).splitlines() if int(row.split()[1]) == original_pid]
        status, policy = self.request("POST", "/api/v1/policies", {"name": "Archived HTTPS business intent", "selector": {}, "mode": "enforce", "services": [{"port": 443, "sources": ["10.44.0.1/32"]}]})
        self.assertEqual(status, 201, policy)
        status, backup = self.request("POST", "/api/v1/platform/backups", {})
        self.assertEqual(status, 201, backup)
        status, changed = self.request("PUT", "/api/v1/policies/" + policy["id"], {**policy, "name": "Post-backup HTTPS intent", "services": [{"port": 8443, "sources": ["10.44.0.2/32"]}]})
        self.assertEqual(status, 200, changed)
        highwater = self.store.assignment("fixture")[0]["version"]
        status, plan = self.request("POST", "/api/v1/platform/recovery/preview", {"backup_id": backup["id"], "reason": "Actual stopped HTTPS recovery acceptance"})
        self.assertEqual(status, 200, plan)
        status, submitted = self.request("POST", "/api/v1/platform/recovery/confirm", {"preview_id": plan["id"], "digest": plan["digest"], "confirmation_nonce": plan["confirmation_nonce"]})
        self.assertEqual(status, 200, submitted)
        self.assertTrue(submitted["pending_approval"])
        self.assertNotEqual(submitted["preview"]["confirmation_nonce"], plan["confirmation_nonce"])
        status, replayed = self.request("POST", "/api/v1/platform/recovery/confirm", {"preview_id": plan["id"], "digest": plan["digest"], "confirmation_nonce": plan["confirmation_nonce"]})
        self.assertEqual(status, 409, replayed)
        plan = submitted["preview"]
        status, denied = self.request("POST", "/api/v1/platform/recovery/confirm", {"preview_id": plan["id"], "digest": plan["digest"], "confirmation_nonce": plan["confirmation_nonce"], "challenge": plan["confirmation_phrase"]}, person=1)
        self.assertEqual(status, 403, denied)
        status, queued = self.request("POST", "/api/v1/platform/recovery/confirm", {"preview_id": plan["id"], "digest": plan["digest"], "confirmation_nonce": plan["confirmation_nonce"], "challenge": plan["confirmation_phrase"]})
        self.assertEqual(status, 200, queued)
        self.assertFalse(queued["pending_approval"])
        self.assertEqual(queued["preview"]["approval"]["mode"], "single_admin")
        self.assertEqual(queued["preview"]["approval"]["requester"], queued["preview"]["approval"]["approved_by"])
        self.wait(lambda: (self.root / "private-ready-seen").exists() and self.request("GET", "/readyz", person=None)[0] == 503)
        self.assertEqual(self.process.pid, original_pid)
        for group in groups:
            with self.assertRaises(ProcessLookupError):
                os.killpg(group, 0)
        self.assertEqual(self.request("GET", "/api/v1/overview")[0], 503)
        private = _read_json(self.data / "platform/recovery" / plan["id"] / "control.json")
        nonce = private["writer_nonce"]
        self.assertEqual(self.request("GET", "/readyz", person=None, extra={"X-Prthak-Recovery-Admission": nonce})[0], 200)
        self.assertEqual(self.request("GET", "/api/v1/overview", extra={"X-Prthak-Recovery-Admission": nonce})[0], 503)
        with sqlite3.connect(self.data / "inventory.sqlite3") as db:
            restored = Store._get(db, "policies", policy["id"])
            host = Store._get(db, "servers", "fixture")
            self.assertEqual(restored["name"], "Archived HTTPS business intent")
            self.assertGreater(host["desired_version"], highwater)
            self.assertEqual(host["apply_status"], "pending")
            self.assertEqual(db.execute("SELECT COUNT(*) FROM auth_sessions").fetchone()[0], 0)
        (self.root / "release-private-ready").touch()
        self.wait(lambda: self.request("GET", "/readyz", person=None)[0] == 200)
        self.assertEqual(self.request("GET", "/api/v1/me")[0], 401)
        record = _read_json(self.data / "platform/recovery" / plan["id"] / "control.json")
        self.assertEqual(record["phase"], "completed")
        self.assertTrue(record["result"]["original_snapshot_preserved"])
        self.assertFalse((self.data / "platform/recovery-writer-fence.json").exists())


if __name__ == "__main__":
    unittest.main()
