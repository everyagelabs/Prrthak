"""Loopback HTTPS platform acceptance; no main demo or endpoint is touched.

Set SEG_TEST_PLATFORM_JOIN=1 for the real PostgreSQL/CLI-supervisor join test.
It owns only prthak_test_join_http_metadata/traffic on the explicit private test
server. PostgreSQL uses its local Unix socket; HTTPS peer transport is real TLS.
"""
from datetime import timedelta
import base64
import http.client
import io
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
import uuid
import zipfile

from controller.app import App
from controller.auth import EntraAuth, EntraConfig
from controller.pki import Signer, init_ca
from controller.platform import PlatformManager
from controller.seed import SEEDED_SERVER_IDS, seed
from controller.store import Store, now
from test_integration import running

try:
    import cryptography
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
try:
    import psycopg
    HAS_PG = True
except ImportError:
    HAS_PG = False

ROOT = Path(__file__).resolve().parents[1]
JOIN_DATABASES = ("prthak_test_join_http_metadata", "prthak_test_join_http_traffic")


def http_request(port, method, path, payload=None, headers=None, tls=None):
    connection = (http.client.HTTPSConnection("localhost", port, context=tls, timeout=15)
                  if tls else http.client.HTTPConnection("127.0.0.1", port, timeout=15))
    outgoing = dict(headers or {})
    data = None if payload is None else json.dumps(payload).encode()
    if data is not None:
        outgoing["Content-Type"] = "application/json"
    try:
        connection.request(method, path, data, outgoing)
        response = connection.getresponse()
        body = response.read()
        metadata = dict(response.getheaders())
        return response.status, (json.loads(body) if body and "application/json" in metadata.get("Content-Type", "") else body), metadata
    finally:
        connection.close()


def server_tls(pki, client_ca=None):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(pki / "controller.pem", pki / "controller-key.pem")
    context.load_verify_locations(client_ca or pki / "ca.pem")
    context.verify_mode = ssl.CERT_OPTIONAL
    return context


@unittest.skipUnless(HAS_CRYPTO, "Install controller requirements for platform HTTPS acceptance")
class PlatformHTTPSAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.store = Store(self.root / "data")
        self.pki = init_ca(self.root / "tls")
        self.client = ssl.create_default_context(cafile=str(self.pki / "ca.pem"))
        self.tokens = {role: secrets.token_urlsafe(48) for role in ("super_admin", "admin", "read_only")}
        self.app = App(self.store, signer=Signer(self.pki / "ca.pem", self.pki / "ca-key.pem"), tokens=self.tokens,
                       auth=EntraAuth(self.store, EntraConfig()), controller_certificate=self.pki / "controller.pem")
        self.context = running(self.app, server_tls(self.pki))
        self.port = self.context.__enter__()
        self.addCleanup(self.stop_http)

    def stop_http(self):
        if self.context is not None:
            context, self.context = self.context, None
            context.__exit__(None, None, None)

    def api(self, method, path, value=None, role="super_admin", expected=200):
        headers = {"Authorization": "Bearer " + self.tokens[role]} if role else {}
        code, body, response_headers = http_request(self.port, method, "/api/v1/" + path, value, headers, self.client)
        self.assertEqual(code, expected, body if not isinstance(body, bytes) else "binary response")
        return body, response_headers

    def real_fixture(self):
        self.store.report("real-platform-host", {"hostname": "real-platform-host", "ips": ["10.249.10.11"],
            "listeners": [{"port": 8443, "protocol": "tcp", "process": "custom-api"}], "firewalld_state": "running"})
        self.store.update_server("real-platform-host", {"tags": {"application": "custom-real-app", "owner": "platform-test"}}, "fixture")
        return self.store.save_policy({"name": "Manual retained policy", "mode": "monitor", "selector": {"owner": "platform-test"},
            "services": [{"port": 8443, "protocol": "tcp", "sources": ["10.249.20.0/24"]}]}, "fixture")

    def test_https_backup_download_inspection_and_staged_validation_preserve_live_state(self):
        policy = self.real_fixture()
        (self.store.path / "private-key-sentinel.pem").write_text("NEVER_INCLUDE_PRIVATE_PKI_SENTINEL")
        backup, _ = self.api("POST", "platform/backups", {}, expected=201)
        self.assertTrue(backup["verified"])
        self.assertEqual(backup["backend"], "sqlite")
        self.assertNotIn("path", backup)
        listed, _ = self.api("GET", "platform/backups")
        self.assertEqual([row["id"] for row in listed["items"]], [backup["id"]])
        inspected, _ = self.api("GET", "platform/backups/" + backup["id"] + "/inspect")
        self.assertTrue(inspected["verified"])
        data, headers = self.api("GET", "platform/backups/" + backup["id"] + "/download")
        self.assertEqual(headers["Content-Type"], "application/zip")
        self.assertEqual(int(headers["Content-Length"]), len(data))
        self.assertIn(backup["id"] + ".zip", headers["Content-Disposition"])
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            self.assertEqual(set(archive.namelist()), {"manifest.json", "metadata.sqlite3", "traffic.sqlite3"})
            self.assertTrue(all(b"NEVER_INCLUDE_PRIVATE_PKI_SENTINEL" not in archive.read(name) for name in archive.namelist()))
            snapshot = self.root / "downloaded-metadata.sqlite3"
            snapshot.write_bytes(archive.read("metadata.sqlite3"))
            with sqlite3.connect(snapshot) as database:
                self.assertEqual(database.execute("PRAGMA quick_check").fetchone(), ("ok",))
                self.assertEqual(database.execute("SELECT id FROM servers").fetchall(), [("real-platform-host",)])
        self.store.save_policy({**policy, "name": "Edited after backup"}, "fixture", policy["id"])
        validation, _ = self.api("POST", "platform/backups/" + backup["id"] + "/restore-validation", {})
        self.assertTrue(validation["valid"])
        self.assertFalse(validation["can_restore_live"])
        self.assertTrue(validation["requires_offline_restore"])
        self.assertEqual(self.store.get("policies", policy["id"])["name"], "Edited after backup")
        self.assertEqual(self.store.get("servers", "real-platform-host")["hostname"], "real-platform-host")

    def test_admin_read_only_and_anonymous_cannot_access_backup_operations(self):
        self.real_fixture()
        backup, _ = self.api("POST", "platform/backups", {}, expected=201)
        prefix = "platform/backups/" + backup["id"]
        operations = (("GET", "platform/backups", None), ("POST", "platform/backups", {}),
            ("GET", prefix + "/inspect", None), ("GET", prefix + "/download", None),
            ("POST", prefix + "/restore-validation", {}), ("POST", "platform/demo/preview", {}),
            ("POST", "platform/ha/test", {"expected_revision": 0}))
        for role in ("admin", "read_only"):
            for method, path, value in operations:
                with self.subTest(role=role, path=path):
                    self.api(method, path, value, role=role, expected=403)
        self.api("GET", prefix + "/download", role=None, expected=401)
        self.assertEqual(len(self.store.all("maintenance_backups")), 1)

    def test_reviewed_default_cleanup_auto_backups_preserves_manual_data_and_survives_restart(self):
        seed(self.store)
        policy = self.real_fixture()
        group = self.store.save_group({"name": "Manual retained group", "type": "static", "server_ids": ["real-platform-host"]}, "fixture")
        location = self.store.save_location({"name": "Custom retained DC", "location": "Fixture site", "type": "datacenter"}, "fixture")
        self.store.update_server("real-platform-host", {"location_id": location["id"]}, "fixture")
        with self.store.meta() as database:
            self.store._put(database, "auth_users", {"id": "manual-account", "display_name": "Retained account"})
        old_digest = self.store.assignment("real-platform-host")[0]["digest"]
        old_group = self.store.get("groups", group["id"])
        plan, _ = self.api("POST", "platform/demo/preview", {}, expected=201)
        self.assertTrue(plan["can_clear"], plan["blockers"])
        self.assertEqual(plan["counts"]["servers"], len(SEEDED_SERVER_IDS))
        self.assertEqual(plan["preserved"]["real_endpoints"], 1)
        confirmation = {"preview_id": plan["id"], "confirmation_nonce": plan["confirmation_nonce"], "confirmation_phrase": plan["confirmation_phrase"]}
        self.api("POST", "platform/demo/clear", {**confirmation, "confirmation_phrase": "clear"}, expected=400)
        self.assertEqual(self.store.all("maintenance_backups"), [])
        result, _ = self.api("POST", "platform/demo/clear", confirmation)
        self.assertTrue(result["seed_disabled"])
        inspection, _ = self.api("GET", "platform/backups/" + result["backup_id"] + "/inspect")
        self.assertTrue(inspection["verified"])
        data, _ = self.api("GET", "platform/backups/" + result["backup_id"] + "/download")
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            before = self.root / "before-clear.sqlite3"
            before.write_bytes(archive.read("metadata.sqlite3"))
            with sqlite3.connect(before) as database:
                self.assertEqual(database.execute("SELECT COUNT(*) FROM servers").fetchone()[0], len(SEEDED_SERVER_IDS) + 1)
        self.assertEqual([server["id"] for server in self.store.servers()], ["real-platform-host"])
        self.assertEqual(self.store.get("policies", policy["id"]), policy)
        self.assertEqual(self.store.get("groups", group["id"]), old_group)
        self.assertEqual(self.store.get("locations", location["id"]), location)
        self.assertEqual(self.store.get("auth_users", "manual-account")["display_name"], "Retained account")
        self.assertEqual(self.store.assignment("real-platform-host")[0]["digest"], old_digest)
        replay, _ = self.api("POST", "platform/demo/clear", confirmation)
        self.assertTrue(replay["duplicate"])
        self.assertEqual(len(self.store.all("maintenance_backups")), 1)
        self.stop_http()
        restarted = Store(self.store.path)
        seed(restarted)
        with running(App(restarted, demo=True)) as port:
            code, body, _ = http_request(port, "GET", "/api/v1/servers")
            self.assertEqual(code, 200)
            self.assertEqual([server["id"] for server in body["items"]], ["real-platform-host"])

    def test_plain_http_cluster_bootstrap_is_denied_even_with_a_signer(self):
        isolated = Store(self.root / "http-only-fixture")
        app = App(isolated, signer=Signer(self.pki / "ca.pem", self.pki / "ca-key.pem"), tokens=self.tokens,
                  auth=EntraAuth(isolated, EntraConfig()))
        with running(app) as port:
            code, body, _ = http_request(port, "POST", "/api/v1/platform/cluster/enroll", {"action": "inspect", "token_id": "f" * 32, "secret": "synthetic"})
            self.assertEqual(code, 403)
            self.assertIn("HTTPS", body["error"])
            self.assertEqual(isolated.all("maintenance_settings"), [])


@unittest.skipUnless(HAS_CRYPTO and HAS_PG and os.environ.get("SEG_TEST_PLATFORM_JOIN") == "1",
                     "Set SEG_TEST_PLATFORM_JOIN=1 for dedicated real PostgreSQL/CLI join acceptance")
class PlatformLivePostgresJoinAcceptanceTests(unittest.TestCase):
    def test_real_https_join_uses_separate_web_ca_then_switches_cli_storage_auth_and_readiness(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
        from cryptography.x509.oid import NameOID
        from psycopg import sql
        from controller.postgres import PostgresStore
        from controller.platform_runtime import FENCE_NAME, RuntimeSafetyError, migrate_stopped_sqlite

        admin_dsn = os.environ.get("SEG_TEST_PLATFORM_PG_ADMIN") or ("host=" + str(ROOT / ".local/ha-pg-socket") + " port=55432 user=prthak_test dbname=postgres")
        with tempfile.TemporaryDirectory(prefix="prthak-https-join-") as temporary:
            root = Path(temporary)
            created = []
            child = None
            child_served = False
            child_exit_code = None
            log = None
            try:
                with psycopg.connect(admin_dsn, autocommit=True, connect_timeout=3) as admin:
                    for name in JOIN_DATABASES:
                        self.assertTrue(name.startswith("prthak_test_join_http_"))
                        if admin.execute("SELECT 1 FROM pg_database WHERE datname=%s", (name,)).fetchone():
                            self.skipTest("Dedicated join test database already exists; refusing to clear an unknown fixture")
                    for name in JOIN_DATABASES:
                        admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
                        created.append(name)
                endpoint_pki = init_ca(root / "endpoint-ca")
                web_pki = init_ca(root / "web-ca")
                bootstrap_pki = init_ca(root / "bootstrap-ca")
                # Deliberately DNS-only: connecting by IP must fail hostname verification.
                web_ca_key = serialization.load_pem_private_key((web_pki / "ca-key.pem").read_bytes(), None)
                web_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Separate corporate web test CA")])
                web_ca = (x509.CertificateBuilder().subject_name(web_name).issuer_name(web_name)
                    .public_key(web_ca_key.public_key()).serial_number(x509.random_serial_number())
                    .not_valid_before(now() - timedelta(minutes=1)).not_valid_after(now() + timedelta(days=2))
                    .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
                    .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                        data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                        encipher_only=False, decipher_only=False), True)
                    .add_extension(x509.SubjectKeyIdentifier.from_public_key(web_ca_key.public_key()), False)
                    .sign(web_ca_key, hashes.SHA256()))
                (web_pki / "ca.pem").write_bytes(web_ca.public_bytes(serialization.Encoding.PEM))
                web_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                web_cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
                    .issuer_name(web_ca.subject).public_key(web_key.public_key()).serial_number(x509.random_serial_number())
                    .not_valid_before(now() - timedelta(minutes=1)).not_valid_after(now() + timedelta(days=1))
                    .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                    .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False)
                    .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), False)
                    .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(web_ca_key.public_key()), False)
                    .add_extension(x509.SubjectKeyIdentifier.from_public_key(web_key.public_key()), False)
                    .sign(web_ca_key, hashes.SHA256()))
                (web_pki / "controller.pem").write_bytes(web_cert.public_bytes(serialization.Encoding.PEM))
                (web_pki / "controller-key.pem").write_bytes(web_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
                settings = psycopg.conninfo.conninfo_to_dict(admin_dsn)
                settings.update(sslmode="verify-full", sslrootcert=str(endpoint_pki / "ca.pem"))
                metadata_dsn = psycopg.conninfo.make_conninfo(**{**settings, "dbname": JOIN_DATABASES[0]})
                traffic_dsn = psycopg.conninfo.make_conninfo(**{**settings, "dbname": JOIN_DATABASES[1]})
                deployment = str(uuid.uuid4())
                source = Store(root / "primary-source")
                source.report("shared-live-pg-host", {"hostname": "shared-live-pg-host", "ips": ["10.249.80.11"], "listeners": [], "firewalld_state": "running"})
                migrate_stopped_sqlite(source.path, metadata_dsn, traffic_dsn, deployment, 1)
                shared = PostgresStore(metadata_dsn, traffic_dsn, deployment_id=deployment, epoch=1)
                manager = PlatformManager(root / "primary-control")
                key = ed25519.Ed25519PrivateKey.generate()
                ssh_private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()).decode()
                ssh_public = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
                spec = {"cluster_id": deployment, "name": "https-join-test", "controller_origin": "https://localhost", "mode": "dc_dr", "rpo": "synchronous_strict", "controller_cidrs": ["10.249.0.0/16"], "watchdog": {"mode": "required", "device": "/dev/watchdog", "approved": True},
                    "nodes": [{"id": name, "ip": "10.249.70." + str(index + 11), "site": "site-" + name, "role": "witness" if name == "witness" else "database", "ssh": {"user": "root", "host_key": ssh_public, "private_key": ssh_private}} for index, name in enumerate(("db-a", "db-b", "witness"))]}
                manager.save_configuration({"expected_revision": 0, "spec": spec}, "fixture")
                shared_tokens = {role: secrets.token_urlsafe(48) for role in ("super_admin", "admin", "read_only")}
                primary = App(shared, signer=Signer(endpoint_pki / "ca.pem", endpoint_pki / "ca-key.pem"), tokens=shared_tokens,
                    auth=EntraAuth(shared, EntraConfig()), controller_id="http-primary", site="source-site", platform_manager=manager,
                    controller_certificate=web_pki / "controller.pem")
                primary_client = ssl.create_default_context(cafile=str(web_pki / "ca.pem"))
                with running(primary, server_tls(web_pki, endpoint_pki / "ca.pem")) as primary_port:
                    origin = "https://localhost:" + str(primary_port)
                    manager.commit_active_profile({"deployment_id": deployment, "epoch": 1, "active_revision": 1,
                        "controller_origin": origin, "mode": "dc_dr", "spec": manager.configuration(True)["spec"],
                        "metadata_dsn": metadata_dsn, "traffic_dsn": traffic_dsn})
                    with socket.socket() as free:
                        free.bind(("127.0.0.1", 0))
                        target_port = free.getsockname()[1]
                    target_dir = root / "target-controller"
                    bootstrap_token = secrets.token_urlsafe(48)
                    environment = {key: value for key, value in os.environ.items() if not key.startswith("SEG_") and key != "PRTHAK_SUPERVISED_CHILD"}
                    environment.update(SEG_SUPER_ADMIN_TOKEN=bootstrap_token, PYTHONPYCACHEPREFIX="/private/tmp/prthak-platform-test-pycache")
                    log = (root / "target-controller.log").open("wb")
                    child = subprocess.Popen([sys.executable, "-m", "controller", "--listen", "127.0.0.1:" + str(target_port), "--data-dir", str(target_dir),
                        "--cert", str(bootstrap_pki / "controller.pem"), "--key", str(bootstrap_pki / "controller-key.pem"), "--ca", str(bootstrap_pki / "ca.pem"), "--ca-key", str(bootstrap_pki / "ca-key.pem")], cwd=ROOT, env=environment, stdout=log, stderr=log, start_new_session=True)
                    bootstrap_client = ssl.create_default_context(cafile=str(bootstrap_pki / "ca.pem"))
                    bootstrap_headers = {"Authorization": "Bearer " + bootstrap_token}
                    def wait_api(context, path, headers=None, predicate=None, seconds=35):
                        latest = None
                        deadline = time.monotonic() + seconds
                        while time.monotonic() < deadline:
                            if child.poll() is not None:
                                self.fail("Owned controller supervisor exited before acceptance completed")
                            try:
                                latest = http_request(target_port, "GET", path, headers=headers, tls=context)
                                if latest[0] == 200 and (predicate is None or predicate(latest[1])):
                                    return latest[1]
                            except (OSError, ssl.SSLError, http.client.HTTPException):
                                pass
                            time.sleep(0.15)
                        self.fail("Owned HTTPS controller did not reach expected readiness/auth state: " + str(latest[0] if latest else None))
                    self.assertFalse(wait_api(bootstrap_client, "/readyz")["ha"])
                    child_served = True
                    identity = {"node_id": "http-dr-controller", "site": "dr-test-site", "node_ip": "10.249.99.50"}
                    status, issued, _ = http_request(primary_port, "POST", "/api/v1/platform/join-tokens", identity, {"Authorization": "Bearer " + shared_tokens["super_admin"]}, primary_client)
                    self.assertEqual(status, 201)
                    code = PlatformManager._join_code(issued["join_code"])
                    pinned_client = ssl.create_default_context(cadata=code["ca"])
                    pinned_client.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
                    self.assertEqual(http_request(primary_port, "GET", "/healthz", tls=pinned_client)[0], 200)
                    wrong = {**code, "ca": endpoint_pki.joinpath("ca.pem").read_text()}
                    wrong_code = "PRTHAKJOIN1." + base64.urlsafe_b64encode(json.dumps(wrong).encode()).decode()
                    for supplied_code, peer in ((wrong_code, origin), (issued["join_code"], "https://127.0.0.1:" + str(primary_port))):
                        status, _, _ = http_request(target_port, "POST", "/api/v1/platform/join/preview", {**identity, "join_code": supplied_code, "peer_url": peer}, bootstrap_headers, bootstrap_client)
                        self.assertEqual(status, 400)
                        self.assertFalse(shared.get("maintenance_settings", "platform_join:" + code["id"]).get("consumed", False))
                    status, plan, _ = http_request(target_port, "POST", "/api/v1/platform/join/preview", {**identity, "join_code": issued["join_code"], "peer_url": origin}, bootstrap_headers, bootstrap_client)
                    self.assertEqual(status, 201, plan)
                    confirmation = {"preview_id": plan["id"], **{key: plan[key] for key in ("digest", "confirmation_nonce", "confirmation_phrase")}}
                    status, queued, _ = http_request(target_port, "POST", "/api/v1/platform/join/apply", confirmation, bootstrap_headers, bootstrap_client)
                    self.assertEqual(status, 202)
                    joined_client = ssl.create_default_context(cafile=str(endpoint_pki / "ca.pem"))
                    ready = wait_api(joined_client, "/readyz", predicate=lambda body: body.get("ha") and body.get("deployment_id") == deployment and body.get("active_revision") == 1)
                    self.assertEqual(ready["controller_id"], identity["node_id"])
                    self.assertEqual(ready["deployment_epoch"], 1)
                    new_headers = {"Authorization": "Bearer " + shared_tokens["super_admin"]}
                    job = wait_api(joined_client, "/api/v1/platform/jobs/" + queued["id"], new_headers, predicate=lambda body: body.get("status") == "applied")
                    self.assertEqual(job["phase"], "active")
                    status, _, _ = http_request(target_port, "GET", "/api/v1/auth", headers=bootstrap_headers, tls=joined_client)
                    self.assertEqual(status, 401)
                    status, principal, _ = http_request(target_port, "GET", "/api/v1/auth", headers=new_headers, tls=joined_client)
                    self.assertEqual(status, 200)
                    self.assertEqual(principal["role"], "super_admin")
                    status, inventory, _ = http_request(target_port, "GET", "/api/v1/servers", headers=new_headers, tls=joined_client)
                    self.assertEqual(status, 200)
                    self.assertEqual([server["id"] for server in inventory["items"]], ["shared-live-pg-host"])
                    self.assertTrue(shared.get("maintenance_settings", "platform_join:" + code["id"])["consumed"])
                    self.assertTrue((target_dir / FENCE_NAME).exists())
                    with self.assertRaises(RuntimeSafetyError):
                        Store(target_dir)
                    status, replay, _ = http_request(target_port, "POST", "/api/v1/platform/join/apply", confirmation, new_headers, joined_client)
                    self.assertEqual(status, 202)
                    self.assertEqual(replay["id"], queued["id"])
            finally:
                if child is not None:
                    child.terminate()
                    try:
                        child_exit_code = child.wait(30)
                    except subprocess.TimeoutExpired:
                        os.killpg(child.pid, signal.SIGKILL)
                        child_exit_code = child.wait(5)
                if log is not None:
                    log.close()
                if created:
                    with psycopg.connect(admin_dsn, autocommit=True, connect_timeout=3) as admin:
                        for name in created:
                            admin.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=%s AND pid<>pg_backend_pid()", (name,))
                            admin.execute(sql.SQL("DROP DATABASE {}").format(sql.Identifier(name)))
                if child_served:
                    self.assertEqual(child_exit_code, 0, "Owned supervisor did not verify a clean child-process-group shutdown")


if __name__ == "__main__":
    unittest.main()
