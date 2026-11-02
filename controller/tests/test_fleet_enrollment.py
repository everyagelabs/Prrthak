"""Reusable fleet bootstrap never shares endpoint private identities."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import timedelta
import http.client
import json
import os
from pathlib import Path
import tempfile
import threading
import types
import unittest
import ssl
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import NameOID

from controller import fleet_enrollment as fleet, recovery
from controller.agent_installation import create_fleet_kit, create_kit, _public_ca
from controller.endpoint_certificates import authorize, certificate
from controller.pki import Signer, init_ca
from controller.store import Store, now, parse_time, stamp
from controller.tests import private_pg as pg_fixture


def request(hostname, key=None):
    key = key or ed25519.Ed25519PrivateKey.generate()
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])).sign(key, None)
    return key, csr.public_bytes(serialization.Encoding.PEM).decode()


class FleetEnrollmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pki_temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.pki_temp.cleanup)
        cls.pki = init_ca(cls.pki_temp.name)

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name)
        self.store = Store(self.directory)
        self.signer = Signer(self.pki / "ca.pem", self.pki / "ca-key.pem")
        self.app = types.SimpleNamespace(store=self.store, signer=self.signer, demo=False, controller_certificate=self.pki / "controller.pem")
        self.body = {"name": "DC rollout", "family": "rhel", "architecture": "amd64", "controller_url": "https://localhost:8787",
                     "control_url": "https://localhost:8788", "discovery_url": "https://localhost:8789", "interval_seconds": 30, "discovery_interval_seconds": 900}

    def kit(self, **changes):
        return create_fleet_kit(self.app, {**self.body, **changes}, "admin")

    def enroll(self, kit, hostname="server-01", csr=None, store=None, signer=None):
        if csr is None:
            _, csr = request(hostname)
        return (store or self.store).enroll(kit["enrollment_token"], hostname, csr, signer or self.signer)

    def test_same_file_creates_independent_certificates_without_metadata_or_enforcement(self):
        result = self.kit()
        kit, profile = result["kit"], result["profile"]
        self.assertEqual((kit["schema_version"], kit["expected_hostname"]), (2, ""))
        self.assertEqual(kit["enrollment_profile_id"], profile["id"])
        self.assertEqual(parse_time(kit["expires_at"]) - parse_time(kit["issued_at"]), timedelta(hours=24))
        identities = [self.enroll(kit, "host-" + str(index)) for index in range(4)]
        self.assertEqual(len({item["server_id"] for item in identities}), 4)
        self.assertEqual(len({fleet._certificate_key(item["certificate"]) for item in identities}), 4)
        self.assertEqual(fleet.listing(self.store)["items"][0]["enrollment_count"], 4)
        self.assertEqual(fleet.listing(self.store)["total"], 1)
        for server in self.store.servers():
            self.assertEqual(server["tags"], {})
            self.assertIsNone(server["location_id"])
            self.assertFalse(self.store.assignment(server["id"])[0]["enforcement"]["authorized"])
        self.assertNotIn("PRIVATE KEY", json.dumps(result))
        self.assertNotIn(kit["enrollment_token"], json.dumps(self.store.all("tokens") + self.store.all("audit") + fleet.listing(self.store)["items"]))
        for flag in ("enforce", "allow_firewall_changes", "learning_auto_allow", "unexpected_port_monitor_enabled"):
            self.assertFalse(kit["config"][flag])

    def test_key_bound_retry_is_idempotent_across_store_instances_and_changed_csr_subject(self):
        kit = self.kit()["kit"]
        key, csr = request("request-subject")
        signed = []
        def sign(identity, value):
            signed.append(identity)
            return self.signer(identity, value)
        first = self.enroll(kit, csr=csr, signer=sign)
        _, changed = request("another-request-subject", key)
        self.assertNotEqual(changed, csr)
        second = self.enroll(kit, csr=changed, store=Store(self.directory), signer=sign)
        self.assertEqual(first, second)
        self.assertEqual(signed, [first["server_id"]])
        self.assertEqual(fleet.listing(self.store)["items"][0]["enrollment_count"], 1)

    def test_existing_key_cannot_bind_different_hostname_or_profile(self):
        kit = self.kit()["kit"]
        _, csr = request("first")
        original = self.enroll(kit, csr=csr)
        with self.assertRaises(PermissionError):
            self.enroll(kit, hostname="different-host", csr=csr)
        other = self.kit(name="Second deployment")["kit"]
        with self.assertRaises(PermissionError):
            self.enroll(other, csr=csr)
        self.assertEqual(len(self.store.servers()), 1)
        self.assertEqual(self.store.servers()[0]["id"], original["server_id"])

    def test_profile_revocation_blocks_new_and_retry_enrollment_but_not_existing_mtls(self):
        result = self.kit()
        _, csr = request("first")
        enrolled = self.enroll(result["kit"], csr=csr)
        revoked = fleet.revoke(self.store, result["profile"]["id"], "admin")
        self.assertEqual(revoked["status"], "revoked")
        self.assertEqual(fleet.revoke(self.store, revoked["id"], "admin"), revoked)
        for value in (csr, request("new")[1]):
            with self.assertRaises(PermissionError):
                self.enroll(result["kit"], csr=value)
        leaf = x509.load_pem_x509_certificate(enrolled["certificate"].encode())
        self.assertEqual(authorize(self.store, enrolled["server_id"], leaf.public_bytes(serialization.Encoding.DER))["status"], "active")
        self.assertEqual(fleet.listing(self.store)["items"][0]["enrollment_count"], 1)

    def test_expiry_is_checked_before_retry_and_at_the_boundary(self):
        result = self.kit(validity_hours=1)
        _, csr = request("first")
        self.enroll(result["kit"], csr=csr)
        with patch("controller.fleet_enrollment.now", return_value=parse_time(result["profile"]["expires_at"])):
            for value in (csr, request("new")[1]):
                with self.assertRaises(PermissionError):
                    self.enroll(result["kit"], csr=value)
            self.assertEqual(fleet.listing(self.store)["items"][0]["status"], "expired")

    def test_revoked_certificate_retired_or_missing_server_cannot_be_returned_or_resurrected(self):
        for state in ("revoked", "retired", "missing"):
            with self.subTest(state=state):
                result = self.kit(name=state)
                _, csr = request(state)
                enrolled = self.enroll(result["kit"], hostname=state, csr=csr)
                with self.store.meta() as db:
                    if state == "revoked":
                        _, issued = certificate(enrolled["certificate"])
                        record = self.store._get(db, "maintenance_settings", issued["id"])
                        record["status"] = "revoked"
                        self.store._put(db, "maintenance_settings", record)
                    else:
                        db.execute("DELETE FROM servers WHERE id=?", (enrolled["server_id"],))
                        if state == "retired":
                            self.store._put(db, "retired_endpoints", {"id": enrolled["server_id"], "retired_at": stamp()})
                with self.assertRaises(PermissionError):
                    self.enroll(result["kit"], hostname=state, csr=csr)
                with self.store.read_meta() as db:
                    if state != "revoked":
                        self.assertIsNone(self.store._get(db, "servers", enrolled["server_id"]))

    def test_issuer_key_mismatch_and_failed_publication_roll_back_all_state(self):
        result = self.kit()
        _, csr = request("first")
        _, wrong = request("wrong")
        with self.assertRaises(ValueError):
            self.enroll(result["kit"], csr=csr, signer=lambda identity, value: self.signer(identity, wrong))
        with patch.object(self.store, "compile_all", side_effect=ValueError("publication failed")):
            with self.assertRaises(ValueError):
                self.enroll(result["kit"], csr=csr)
        self.assertEqual(self.store.servers(), [])
        self.assertEqual(fleet.listing(self.store)["items"][0]["enrollment_count"], 0)
        self.assertEqual([row for row in self.store.all("tokens") if row.get("kind") == "enrollment_key"], [])
        self.enroll(result["kit"], csr=csr)
        self.assertEqual(len(self.store.servers()), 1)

    def test_invalid_configuration_or_csr_never_mints_authority_or_identity(self):
        for changes in ({"expected_hostname": "bound"}, {"tags": {}}, {"enforce": True}, {"name": "bad\nname"},
                        {"validity_hours": True}, {"validity_hours": 0}, {"validity_hours": 721}, {"controller_url": "https://wrong.example"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.kit(**changes)
        self.assertEqual(self.store.all("tokens"), [])
        result = self.kit()
        for csr in ("-----BEGIN CERTIFICATE REQUEST-----\nnot-a-csr", request("valid")[1].replace("BEGIN CERTIFICATE REQUEST", "BEGIN INVALID REQUEST")):
            with self.assertRaises(ValueError):
                self.enroll(result["kit"], csr=csr)
        self.assertEqual(self.store.servers(), [])

    def test_legacy_one_use_identity_and_reservation_are_preserved_and_indexed(self):
        from controller.server_management import create
        reserved = create(self.store, {"hostname": "reserved-host", "ips": ["10.0.0.50"]}, "admin")
        token = self.store.create_token("Reserved", "admin", server_id=reserved["id"])
        _, csr = request("reserved-host")
        enrolled = self.store.enroll(token["token"], "reserved-host", csr, self.signer)
        self.assertEqual(enrolled["server_id"], reserved["id"])
        self.assertEqual(self.store.enroll(token["token"], "reserved-host", csr, self.signer), enrolled)
        # Model a pre-0.10 used token without the additive SPKI index.
        with self.store.meta() as db:
            db.execute("DELETE FROM tokens WHERE id LIKE ?", (fleet.KEY + "%",))
        shared = self.kit()["kit"]
        with self.assertRaises(PermissionError):
            self.enroll(shared, hostname="reserved-host", csr=csr)
        self.assertEqual(len(self.store.servers()), 1)
        self.assertEqual(self.store.all("server_reservations"), [])

    def test_two_store_instances_serialize_duplicate_and_distinct_enrollments(self):
        result = self.kit()
        stores = [Store(self.directory), Store(self.directory)]
        _, csr = request("same")
        barrier = threading.Barrier(2)
        def same(index):
            barrier.wait()
            return self.enroll(result["kit"], csr=csr, store=stores[index])
        with ThreadPoolExecutor(max_workers=2) as pool:
            replies = list(pool.map(same, range(2)))
        self.assertEqual(replies[0], replies[1])
        barrier = threading.Barrier(2)
        requests = [request("different-" + str(index))[1] for index in range(2)]
        def distinct(index):
            barrier.wait()
            return self.enroll(result["kit"], hostname="different-" + str(index), csr=requests[index], store=stores[index])
        with ThreadPoolExecutor(max_workers=2) as pool:
            replies = list(pool.map(distinct, range(2)))
        self.assertNotEqual(replies[0]["server_id"], replies[1]["server_id"])
        self.assertEqual(fleet.listing(self.store)["items"][0]["enrollment_count"], 3)

    def test_revoke_and_enroll_are_linearized_across_instances(self):
        result = self.kit()
        entered, release = threading.Event(), threading.Event()
        other = Store(self.directory)
        _, csr = request("racing-host")
        def sign(identity, value):
            entered.set()
            if not release.wait(5):
                raise RuntimeError("Fixture signer barrier timed out")
            return self.signer(identity, value)
        with ThreadPoolExecutor(max_workers=2) as pool:
            pending = pool.submit(self.enroll, result["kit"], csr=csr, signer=sign)
            self.assertTrue(entered.wait(5))
            revoked = pool.submit(fleet.revoke, other, result["profile"]["id"], "admin")
            release.set()
            enrolled = pending.result(timeout=10)
            self.assertEqual(revoked.result(timeout=10)["status"], "revoked")
        self.assertEqual(len(self.store.servers()), 1)
        with self.assertRaises(PermissionError):
            self.enroll(result["kit"], csr=csr)
        leaf = x509.load_pem_x509_certificate(enrolled["certificate"].encode())
        authorize(self.store, enrolled["server_id"], leaf.public_bytes(serialization.Encoding.DER))

    def test_recovery_drops_shared_authority_and_retains_key_and_certificate_safety(self):
        result = self.kit()
        _, csr = request("recovery-host")
        enrolled = self.enroll(result["kit"], csr=csr)
        old_rows = self.store.all("tokens")
        fleet.revoke(self.store, result["profile"]["id"], "admin")
        with self.store.meta() as db:
            safety = recovery._safety(db)
        with tempfile.TemporaryDirectory() as directory:
            restored = Store(directory)
            with restored.meta() as db:
                for row in old_rows:
                    restored._put(db, "tokens", row)
                recovery._overlay_safety(db, safety, "fleet-recovery-fixture")
            self.assertEqual(fleet.listing(restored)["total"], 0)
            self.assertEqual({row["kind"] for row in restored.all("tokens")}, {"enrollment_key"})
            with self.assertRaises(PermissionError):
                self.enroll(result["kit"], csr=csr, store=restored)
            fresh = fleet.create(restored, "Fresh after recovery", 24, "admin")[1]
            with self.assertRaises(PermissionError):
                restored.enroll(fresh, "server-01", csr, self.signer)
            self.assertEqual(restored.get("servers", enrolled["server_id"])["id"], enrolled["server_id"])

    def test_listing_is_bounded_secret_free_and_ordered_by_creation(self):
        original = now() - timedelta(hours=4)
        profiles = [fleet.create(self.store, str(index), 24, "admin", issued_at=stamp(original + timedelta(hours=index)))[0] for index in range(3)]
        page = fleet.listing(self.store, limit=1, offset=1)
        self.assertEqual((page["total"], page["limit"], page["offset"]), (3, 1, 1))
        self.assertEqual([row["id"] for row in page["items"]], [profiles[1]["id"]])
        for options in ({"limit": 0}, {"limit": 201}, {"offset": -1}, {"limit": True}):
            with self.assertRaises(ValueError):
                fleet.listing(self.store, **options)

    def test_ca_must_cover_entire_shared_profile_lifetime(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Short fixture CA")])
        ca = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now() - timedelta(minutes=1)).not_valid_after(now() + timedelta(hours=2)).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA256())
        pem = ca.public_bytes(serialization.Encoding.PEM).decode()
        _public_ca(pem, now() + timedelta(hours=1))
        with self.assertRaises(ValueError):
            _public_ca(pem, now() + timedelta(hours=24))

    def rotate_key(self, enrolled, hostname, csr, mode):
        from controller import endpoint_certificates as lifecycle
        if mode == "recover":
            token = lifecycle.recovery_token(self.store, enrolled["server_id"], "admin")
            return lifecycle.recover(self.store, {"token": token["token"], "hostname": hostname, "csr": csr}, self.signer)
        leaf = x509.load_pem_x509_certificate(enrolled["certificate"].encode())
        with patch("controller.endpoint_certificates.now", return_value=now() + timedelta(days=61)):
            return lifecycle.renew(self.store, enrolled["server_id"], leaf.public_bytes(serialization.Encoding.DER), {"csr": csr}, self.signer)

    def test_recovered_and_renewed_keys_never_create_new_bootstrap_identities(self):
        for mode in ("recover", "renew"):
            with self.subTest(mode=mode):
                result = self.kit(name=mode)
                hostname = mode + "-host"
                enrolled = self.enroll(result["kit"], hostname=hostname)
                _, rotated_csr = request(hostname)
                rotated = self.rotate_key(enrolled, hostname, rotated_csr, mode)
                second = self.kit(name=mode + "-another-profile")
                for state in ("active", "revoked", "retired"):
                    if state != "active":
                        with self.store.meta() as db:
                            if state == "revoked":
                                _, issued = certificate(rotated["certificate"])
                                row = self.store._get(db, "maintenance_settings", issued["id"])
                                row["status"] = "revoked"
                                self.store._put(db, "maintenance_settings", row)
                            else:
                                self.store._put(db, "retired_endpoints", {"id": enrolled["server_id"], "retired_at": stamp()})
                                db.execute("DELETE FROM servers WHERE id=?", (enrolled["server_id"],))
                    for kit in (result["kit"], second["kit"]):
                        for claimed_hostname in (hostname, "changed-hostname"):
                            with self.subTest(mode=mode, state=state, hostname=claimed_hostname), self.assertRaises(PermissionError):
                                self.enroll(kit, hostname=claimed_hostname, csr=rotated_csr)
                self.assertEqual(len(self.store.servers()), 0)

    def test_historical_renewal_and_recovery_receipts_backfill_every_known_key(self):
        for mode in ("recover", "renew"):
            with self.subTest(mode=mode):
                hostname = mode + "-legacy"
                token = self.store.create_token(hostname, "admin")
                _, original_csr = request(hostname)
                enrolled = self.store.enroll(token["token"], hostname, original_csr, self.signer)
                _, rotated_csr = request(hostname)
                rotated = self.rotate_key(enrolled, hostname, rotated_csr, mode)
                # Deliberately restore the actual pre-0.10 indexing format:
                # certificate/renewal/recovery receipts remain; SPKI fields do not.
                with self.store.meta() as db:
                    db.execute("DELETE FROM tokens WHERE id LIKE ?", (fleet.KEY + "%",))
                    for row in self.store._all(db, "tokens"):
                        row.pop("fleet_key_indexed", None)
                        self.store._put(db, "tokens", row)
                    for row in self.store._all(db, "maintenance_settings"):
                        row.pop("public_key_sha256", None)
                        row.pop("fleet_key_indexed", None)
                        self.store._put(db, "maintenance_settings", row)
                shared = self.kit(name=mode + "-after-upgrade")["kit"]
                for csr in (original_csr, rotated_csr):
                    with self.assertRaises(PermissionError):
                        self.enroll(shared, hostname=hostname, csr=csr)
                _, identity = certificate(rotated["certificate"])
                self.assertEqual(self.store.get("maintenance_settings", identity["id"])["public_key_sha256"], fleet._certificate_key(rotated["certificate"]))

    def test_unknown_historical_keys_block_new_profiles_until_verified_mtls_census(self):
        from controller import endpoint_certificates as lifecycle
        token = self.store.create_token("legacy-census", "admin")
        _, csr = request("legacy-census")
        enrolled = self.store.enroll(token["token"], "legacy-census", csr, self.signer)
        _, rotated_csr = request("legacy-census")
        rotated = self.rotate_key(enrolled, "legacy-census", rotated_csr, "recover")
        with self.store.meta() as db:
            db.execute("DELETE FROM tokens WHERE id LIKE ?", (fleet.KEY + "%",))
            for row in self.store._all(db, "tokens"):
                row.pop("fleet_key_indexed", None)
                self.store._put(db, "tokens", row)
            for row in self.store._all(db, "maintenance_settings"):
                if row["id"].startswith("endpoint_recovery:"):
                    db.execute("DELETE FROM maintenance_settings WHERE id=?", (row["id"],))
                else:
                    row.pop("public_key_sha256", None)
                    row.pop("fleet_key_indexed", None)
                    self.store._put(db, "maintenance_settings", row)
        with self.assertRaisesRegex(ValueError, "key history"):
            self.kit()
        self.assertEqual(fleet.listing(self.store)["total"], 0)
        leaf = x509.load_pem_x509_certificate(rotated["certificate"].encode())
        lifecycle.authorize(self.store, enrolled["server_id"], leaf.public_bytes(serialization.Encoding.DER))
        shared = self.kit()["kit"]
        with self.assertRaises(PermissionError):
            self.enroll(shared, hostname="legacy-census", csr=rotated_csr)

    def test_same_key_renewal_preserves_bootstrap_provenance_and_other_identity_is_refused(self):
        from controller import endpoint_certificates as lifecycle
        result = self.kit()
        key, csr = request("same-key")
        enrolled = self.enroll(result["kit"], hostname="same-key", csr=csr)
        _, new_csr = request("another-subject", key)
        renewed = self.rotate_key(enrolled, "same-key", new_csr, "renew")
        claim = self.store.get("tokens", fleet.KEY + fleet._certificate_key(renewed["certificate"]))
        self.assertEqual((claim["server_id"], claim["profile_id"]), (enrolled["server_id"], result["profile"]["id"]))
        other = self.enroll(result["kit"], hostname="other")
        recovery_token = lifecycle.recovery_token(self.store, other["server_id"], "admin")
        with self.assertRaises(PermissionError):
            lifecycle.recover(self.store, {"token": recovery_token["token"], "hostname": "other", "csr": csr}, self.signer)
        self.assertEqual(self.store.get("servers", other["server_id"])["certificate_fingerprint"], certificate(other["certificate"])[1]["fingerprint_sha256"])

    def test_conflicting_historical_registry_key_hashes_cannot_overwrite_a_key_claim(self):
        _, csr = request("legacy-shared-key")
        common_key = fleet._csr_key(csr)
        with self.store.meta() as db:
            for identity in ("legacy-one", "legacy-two"):
                pem, _ = self.signer(identity, csr)
                _, registry = certificate(pem)
                registry.update(status="active", public_key_sha256=common_key)
                self.store._put(db, "maintenance_settings", registry)
        with self.assertRaises(PermissionError):
            self.kit()
        self.assertEqual(fleet.listing(self.store)["total"], 0)
        self.assertEqual(self.store.all("tokens"), [], "A refused census must roll back partial key claims")


@unittest.skipUnless(os.environ.get("PRTHAK_PLATFORM_PG_ACCEPTANCE") == "1", "Opt in to private PostgreSQL fleet enrollment acceptance")
class FleetEnrollmentPostgresTests(FleetEnrollmentTests):
    """Fresh private UUID databases; never reuse or truncate deployed data."""
    def setUp(self):
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import make_conninfo
        from controller.postgres import PostgresStore
        super().setUp()
        self.driver, self.sql = psycopg, sql
        self.parameters, self.databases = pg_fixture.parameters(), pg_fixture.names("fleetenroll")
        self.created = []
        self.addCleanup(self._drop)
        with psycopg.connect(**self.parameters, dbname="postgres", autocommit=True) as db:
            user, directory = db.execute("SELECT current_user,current_setting('data_directory')").fetchone()
            if user != "prthak_test" or Path(directory).resolve() != pg_fixture.data_directory():
                raise RuntimeError("Refusing nonfixture PostgreSQL")
            for database in self.databases.values():
                if db.execute("SELECT 1 FROM pg_database WHERE datname=%s", (database,)).fetchone():
                    raise RuntimeError("Fixture name already exists")
                db.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(database)))
                self.created.append(database)
        self.dsns = [make_conninfo(**self.parameters, dbname=self.databases[name]) for name in ("metadata", "traffic")]
        self.store = PostgresStore(*self.dsns)
        self.app.store = self.store

    def _drop(self):
        if self.created:
            with self.driver.connect(**self.parameters, dbname="postgres", autocommit=True) as db:
                for database in self.created:
                    db.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=%s AND pid<>pg_backend_pid()", (database,))
                    db.execute(self.sql.SQL("DROP DATABASE {}").format(self.sql.Identifier(database)))

    def test_key_bound_retry_is_idempotent_across_store_instances_and_changed_csr_subject(self):
        from controller.postgres import PostgresStore
        with patch(__name__ + ".Store", side_effect=lambda directory: PostgresStore(*self.dsns)):
            super().test_key_bound_retry_is_idempotent_across_store_instances_and_changed_csr_subject()

    def test_two_store_instances_serialize_duplicate_and_distinct_enrollments(self):
        from controller.postgres import PostgresStore
        with patch(__name__ + ".Store", side_effect=lambda directory: PostgresStore(*self.dsns)):
            super().test_two_store_instances_serialize_duplicate_and_distinct_enrollments()

    def test_revoke_and_enroll_are_linearized_across_instances(self):
        from controller.postgres import PostgresStore
        with patch(__name__ + ".Store", side_effect=lambda directory: PostgresStore(*self.dsns)):
            super().test_revoke_and_enroll_are_linearized_across_instances()


class FleetEnrollmentHTTPSBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pki_temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.pki_temp.cleanup)
        cls.pki = init_ca(cls.pki_temp.name)

    @contextmanager
    def running(self, app, secure=True):
        from controller.app import Server
        server = Server(("127.0.0.1", 0), app)
        if secure:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(self.pki / "controller.pem", self.pki / "controller-key.pem")
            server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server.server_address[1]
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def setUp(self):
        from controller.app import App
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.store = Store(temp.name)
        self.app = App(self.store, signer=Signer(self.pki / "ca.pem", self.pki / "ca-key.pem"),
                       controller_certificate=self.pki / "controller.pem",
                       tokens={"admin": "a" * 48, "read_only": "r" * 48})
        self.tls = ssl.create_default_context(cafile=str(self.pki / "ca.pem"))
        self.body = {"name": "HTTPS rollout", "family": "rhel", "architecture": "amd64", "controller_url": "https://localhost:8787"}

    def http(self, port, method="GET", path="", body=None, role="admin", origin=None, secure=True, headers=None):
        scheme = "https" if secure else "http"
        connection = http.client.HTTPSConnection("localhost", port, context=self.tls, timeout=15) if secure else http.client.HTTPConnection("localhost", port, timeout=15)
        fields = {"Origin": origin or scheme + "://localhost:" + str(port), "Authorization": "Bearer " + ("a" if role == "admin" else "r") * 48, **(headers or {})}
        if body is not None:
            fields["Content-Type"] = "application/json"
        connection.request(method, "/api/v1/agent-installation/fleet-profiles" + path, json.dumps(body) if body is not None else None, fields)
        response = connection.getresponse()
        raw = response.read()
        answer = response.status, json.loads(raw) if raw else None, dict(response.getheaders())
        connection.close()
        return answer

    def test_admin_https_origin_list_and_revoke_boundaries_are_enforced_without_secret_reads(self):
        with self.running(self.app) as port:
            for method, body in (("GET", None), ("POST", self.body)):
                self.assertEqual(self.http(port, method=method, body=body, role="read")[0], 403)
            self.assertEqual(self.http(port, "POST", body=self.body, origin="https://unrelated.example")[0], 403)
            self.assertEqual(self.store.all("tokens"), [])
            status, result, headers = self.http(port, "POST", body=self.body)
            self.assertEqual(status, 201, result)
            self.assertEqual(headers["Cache-Control"], "no-store")
            self.assertIn("attachment", headers["Content-Disposition"])
            secret, identifier = result["kit"]["enrollment_token"], result["profile"]["id"]
            status, page, _ = self.http(port, path="?limit=1&offset=0")
            self.assertEqual((status, page["total"], len(page["items"])), (200, 1, 1))
            self.assertNotIn(secret, json.dumps(page))
            self.assertEqual(self.http(port, path="/" + identifier)[0], 405)
            self.assertEqual(self.http(port, "POST", "/" + identifier + "/revoke", {}, role="read")[0], 403)
            self.assertEqual(self.http(port, "POST", "/" + identifier + "/revoke", {"delete_existing": True})[0], 400)
            status, revoked, _ = self.http(port, "POST", "/" + identifier + "/revoke", {})
            self.assertEqual((status, revoked["status"]), (200, "revoked"))
            self.assertNotIn(secret, json.dumps(self.store.all("tokens") + self.store.all("audit")))

    def test_plain_http_and_agent_listener_cannot_mint_shared_credentials(self):
        with self.running(self.app, secure=False) as port:
            self.assertEqual(self.http(port, "POST", body=self.body, secure=False)[0], 403)
        with self.running(self.app) as port:
            self.app.listener_channels = {port: "discovery"}
            self.assertEqual(self.http(port, "POST", body=self.body, headers={"X-Prthak-Channel": "management"})[0], 404)
        self.assertEqual(self.store.all("tokens"), [])


if __name__ == "__main__":
    unittest.main()
