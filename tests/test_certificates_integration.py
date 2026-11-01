"""Real loopback HTTPS and CLI-supervisor certificate activation acceptance.

Every test owns its temporary controller, PKI and listening port. No main demo,
system service, remote endpoint, or operator certificate is touched. The failure
case injects only a failed candidate verification into the supervisor process;
both candidate and restored controller children use the real CLI and TLS stack.
"""
from datetime import timedelta
import base64
import http.client
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

from controller.pki import init_ca
from controller.platform import PlatformManager
from controller.store import Store, now

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography.x509.oid import NameOID
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
try:
    import psycopg
    HAS_POSTGRES = True
except ImportError:
    HAS_POSTGRES = False


ROOT = Path(__file__).resolve().parent.parent
TERMINAL = {"applied", "rolled_back", "failed"}


@unittest.skipUnless(HAS_CRYPTO, "Install controller cryptography requirements for real HTTPS acceptance")
class CertificateCLIIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="prthak-certificates-cli-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.data = self.root / "controller"
        self.pki = init_ca(self.root / "tls")
        self.token = secrets.token_urlsafe(48)
        self.headers = {"Authorization": "Bearer " + self.token}
        self.context = ssl.create_default_context(cafile=str(self.pki / "ca.pem"))
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            self.port = listener.getsockname()[1]
        self.child = None
        self.log = None
        self.addCleanup(self.stop)
        # A real inventory row proves a certificate restart retains its database.
        Store(self.data).report("tls-fixture-host", {"hostname": "TLS fixture host", "ips": ["10.248.15.11"], "listeners": []})
        self.manager = PlatformManager(self.data)
        self.initial_profile = None
        self.expected_ha = False

    def start(self, reject_fingerprint=None):
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith(("SEG_", "PRTHAK_")) and key != "CONTROLLER_ORIGIN"}
        environment.update(SEG_SUPER_ADMIN_TOKEN=self.token,
                           CONTROLLER_ORIGIN="https://localhost:" + str(self.port),
                           PYTHONPYCACHEPREFIX=str(self.root.resolve() / "pycache"))
        arguments = ["--listen", "127.0.0.1:" + str(self.port), "--data-dir", str(self.data),
                     "--cert", str(self.pki / "controller.pem"), "--key", str(self.pki / "controller-key.pem"),
                     "--ca", str(self.pki / "ca.pem"), "--ca-key", str(self.pki / "ca-key.pem")]
        command = [sys.executable, "-m", "controller"]
        if reject_fingerprint:
            # This hook exists only in this isolated test interpreter. Child
            # processes still launch the unmodified `python -m controller` CLI.
            injection = ("from controller.platform_runtime import RuntimeSupervisor\n"
                         "original = RuntimeSupervisor._wait_certificate\n"
                         "def verify(self, arguments, profile, hostname, fingerprint):\n"
                         "    if fingerprint == " + repr(reject_fingerprint) + ": return False\n"
                         "    return original(self, arguments, profile, hostname, fingerprint)\n"
                         "RuntimeSupervisor._wait_certificate = verify\n"
                         "from controller.__main__ import main\nmain()\n")
            command = [sys.executable, "-c", injection]
        self.log = (self.root / "controller.log").open("ab")
        self.child = subprocess.Popen(command + arguments, cwd=ROOT, env=environment,
                                      stdout=self.log, stderr=self.log, start_new_session=True)
        self.wait("/readyz", lambda value: value.get("status") == "ready")

    def stop(self):
        child, self.child = self.child, None
        if child is not None and child.poll() is None:
            child.send_signal(signal.SIGTERM)
            try:
                child.wait(timeout=15)
            except subprocess.TimeoutExpired:
                # All PIDs are direct children of this test's known supervisor.
                # Drain those owned groups before killing an unresponsive parent.
                listing = subprocess.check_output(["ps", "-axo", "pid=,ppid="], text=True)
                for row in listing.splitlines():
                    pid, parent = map(int, row.split())
                    if parent == child.pid:
                        try:
                            os.killpg(pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                child.kill()
                child.wait(timeout=5)
        if self.log is not None:
            self.log.close()
            self.log = None

    def request(self, method, path, value=None):
        headers = dict(self.headers)
        payload = None
        if value is not None:
            payload = json.dumps(value)
            headers["Content-Type"] = "application/json"
        connection = http.client.HTTPSConnection("localhost", self.port, context=self.context, timeout=3)
        try:
            connection.request(method, path, body=payload, headers=headers)
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def wait(self, path, predicate, seconds=40):
        deadline = time.monotonic() + seconds
        latest = None
        while time.monotonic() < deadline:
            if self.child.poll() is not None:
                self.fail("Owned CLI supervisor exited: " + (self.root / "controller.log").read_text()[-4000:])
            try:
                status, latest = self.request("GET", path)
                if status == 200 and predicate(latest):
                    return latest
            except (OSError, ssl.SSLError, http.client.HTTPException):
                pass
            time.sleep(0.1)
        self.fail("Owned HTTPS controller did not reach expected state at " + path + ": " + str(latest))

    def fingerprint(self):
        with socket.create_connection(("127.0.0.1", self.port), timeout=3) as connection:
            with self.context.wrap_socket(connection, server_hostname="localhost") as tls:
                certificate = x509.load_der_x509_certificate(tls.getpeercert(binary_form=True))
                return certificate.fingerprint(hashes.SHA256()).hex()

    def leaf(self):
        ca = x509.load_pem_x509_certificate((self.pki / "ca.pem").read_bytes())
        ca_key = serialization.load_pem_private_key((self.pki / "ca-key.pem").read_bytes(), None)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        certificate = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
            .issuer_name(ca.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now() - timedelta(minutes=1)).not_valid_after(now() + timedelta(days=7))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False)
            .sign(ca_key, hashes.SHA256()))
        return certificate, key, ca

    def material(self, mode):
        if mode == "self_signed":
            return {"mode": mode, "hostname": "localhost", "sans": ["localhost", "127.0.0.1"]}
        certificate, key, ca = self.leaf()
        if mode == "pkcs12":
            archive = pkcs12.serialize_key_and_certificates(b"TLS test", key, certificate, [ca],
                        serialization.BestAvailableEncryption(b"fixture-archive-password"))
            return {"mode": mode, "hostname": "localhost", "password": "fixture-archive-password",
                    "pkcs12_base64": base64.b64encode(archive).decode()}
        return {"mode": "pem", "hostname": "localhost",
                "certificate_pem": certificate.public_bytes(serialization.Encoding.PEM).decode(),
                "private_key_pem": key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                      serialization.NoEncryption()).decode()}

    def activate(self, material, expected_status="applied"):
        status, review = self.request("POST", "/api/v1/platform/certificates/preview", material)
        self.assertEqual(status, 201, review)
        self.assertEqual(review["blockers"], [])
        confirmation = {key: review[key] for key in ("digest", "confirmation_nonce", "confirmation_phrase")}
        confirmation["preview_id"] = review["id"]
        status, queued = self.request("POST", "/api/v1/platform/certificates/apply", confirmation)
        self.assertEqual(status, 202, queued)
        self.assertNotEqual(queued["status"], "applied", "Queue acceptance must not imply an active certificate")
        job = self.wait("/api/v1/platform/jobs/" + queued["id"], lambda value: value.get("status") in TERMINAL)
        self.assertEqual(job["status"], expected_status, job)
        self.assertEqual(self.wait("/readyz", lambda value: value.get("status") == "ready")["status"], "ready")
        return review, job

    def test_pem_pkcs12_and_generated_certificate_activate_and_survive_cli_restart(self):
        original_pair = [(self.pki / filename).read_bytes() for filename in ("controller.pem", "controller-key.pem")]
        self.start()
        previous = self.fingerprint()
        for mode in ("pem", "pkcs12", "self_signed"):
            with self.subTest(mode=mode):
                review, job = self.activate(self.material(mode))
                expected = review["summary"]["certificate"]["fingerprint_sha256"]
                self.assertNotEqual(expected, previous)
                self.assertEqual(job["result"]["fingerprint_sha256"], expected)
                self.assertEqual(self.fingerprint(), expected)
                status, public = self.request("GET", "/api/v1/platform/certificates")
                self.assertEqual(status, 200)
                self.assertEqual(public["current"]["fingerprint_sha256"], expected)
                self.assertNotIn("private_key_pem", json.dumps(public))
                persisted = self.manager.launch_tls()
                self.assertEqual(persisted["fingerprint_sha256"], expected)
                self.assertEqual(Path(persisted["key"]).stat().st_mode & 0o777, 0o600)
                self.stop()
                # Bootstrap arguments still name the original pair: the durable
                # launch pointer must select the actually verified replacement.
                self.start()
                self.assertEqual(self.fingerprint(), expected)
                previous = expected
        self.assertEqual(original_pair, [(self.pki / filename).read_bytes() for filename in ("controller.pem", "controller-key.pem")])
        self.assertEqual(self.request("GET", "/api/v1/overview")[1]["servers"][0]["id"], "tls-fixture-host")
        self.assertEqual(self.profile_digest(self.manager.active_profile()), self.profile_digest(self.initial_profile))

    def test_failed_candidate_verification_restores_previous_live_https_and_database(self):
        rejected = self.material("pem")
        rejected_fingerprint = x509.load_pem_x509_certificate(rejected["certificate_pem"].encode()).fingerprint(hashes.SHA256()).hex()
        self.start(reject_fingerprint=rejected_fingerprint)
        # Establish a committed replacement first, so rollback must preserve the
        # previous durable TLS pointer rather than return to bootstrap arguments.
        self.activate(self.material("pem"))
        previous = self.fingerprint()
        pointer, profile = self.manager.launch_tls(), self.manager.active_profile()
        _, job = self.activate(rejected, expected_status="rolled_back")
        self.assertEqual(job["phase"], "previous_certificate_restored")
        self.assertEqual(self.fingerprint(), previous)
        self.assertEqual(self.manager.launch_tls(), pointer)
        self.assertEqual(self.profile_digest(self.manager.active_profile()), self.profile_digest(profile))
        readiness = self.request("GET", "/readyz")[1]
        self.assertEqual(readiness["ha"], self.expected_ha)
        if self.initial_profile:
            self.assertEqual(readiness["deployment_id"], self.initial_profile["deployment_id"])
            self.assertEqual(readiness["deployment_epoch"], self.initial_profile["epoch"])
        self.assertEqual(self.request("GET", "/api/v1/overview")[1]["servers"][0]["id"], "tls-fixture-host")
        self.stop()
        self.start()
        self.assertEqual(self.fingerprint(), previous)

    @staticmethod
    def profile_digest(profile):
        # A failure must not print private connection profiles or credentials.
        return hashlib.sha256(json.dumps(profile, sort_keys=True).encode()).hexdigest()


@unittest.skipUnless(HAS_CRYPTO and HAS_POSTGRES and os.environ.get("SEG_TEST_CERTIFICATE_POSTGRES") == "1",
                     "Set SEG_TEST_CERTIFICATE_POSTGRES=1 for dedicated PostgreSQL/CLI TLS acceptance")
class CertificatePostgresCLIIntegrationTests(CertificateCLIIntegrationTests):
    """Repeat real TLS imports, restart and rollback with a fenced shared DB profile."""

    def setUp(self):
        super().setUp()
        from psycopg import sql
        from controller.platform_runtime import migrate_stopped_sqlite

        self.admin_dsn = os.environ.get("SEG_TEST_PLATFORM_PG_ADMIN") or (
            "host=" + str(ROOT / ".local/ha-pg-socket") + " port=55432 user=prthak_test dbname=postgres")
        suffix = uuid.uuid4().hex[:12]
        names = ["prthak_test_tls_" + suffix + "_" + kind for kind in ("metadata", "traffic")]
        self.owned_databases = []

        def drop_owned():
            self.stop()
            with psycopg.connect(self.admin_dsn, autocommit=True, connect_timeout=3) as admin:
                for name in self.owned_databases:
                    if not name.startswith("prthak_test_tls_" + suffix + "_"):
                        raise AssertionError("Refusing to remove a database outside this test fixture")
                    admin.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(name)))

        self.addCleanup(drop_owned)
        with psycopg.connect(self.admin_dsn, autocommit=True, connect_timeout=3) as admin:
            for name in names:
                if admin.execute("SELECT 1 FROM pg_database WHERE datname=%s", (name,)).fetchone():
                    self.fail("Unique TLS test database unexpectedly exists; refusing to overwrite it")
                admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
                self.owned_databases.append(name)
        settings = psycopg.conninfo.conninfo_to_dict(self.admin_dsn)
        settings.update(sslmode="verify-full", sslrootcert=str(self.pki / "ca.pem"))
        metadata_dsn, traffic_dsn = [psycopg.conninfo.make_conninfo(**{**settings, "dbname": name}) for name in names]
        deployment = str(uuid.uuid4())
        migrate_stopped_sqlite(self.data, metadata_dsn, traffic_dsn, deployment, 1)
        self.initial_profile = {"deployment_id": deployment, "epoch": 1, "active_revision": 7,
            "metadata_dsn": metadata_dsn, "traffic_dsn": traffic_dsn, "mode": "dc_dr",
            "controller_origin": "https://localhost:" + str(self.port), "controller_server_name": "localhost",
            "controller_id": "tls-fixture-controller", "site": "isolated-site",
            "controller_tls": {"cert": str(self.pki / "controller.pem"), "key": str(self.pki / "controller-key.pem"),
                               "ca": str(self.pki / "ca.pem"), "ca_key": str(self.pki / "ca-key.pem")}}
        self.manager.commit_active_profile(self.initial_profile)
        self.expected_ha = True


if __name__ == "__main__":
    unittest.main()
