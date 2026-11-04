import base64
from controller.tests import private_pg as pg_fixture

import copy
from datetime import timedelta
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
import os
from pathlib import Path
import ssl
import subprocess
import threading
import unittest
from unittest.mock import patch

from controller import cluster_bootstrap as bootstrap
from controller.appliance import Appliance
from controller.firewall import WorkflowConflict
from controller.platform import PlatformManager, _private_json
from controller.store import now, stamp
from controller.tests.test_appliance import ApplianceFixture


class BootstrapFixture(ApplianceFixture):
    def key(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        return rsa.generate_private_key(public_exponent=65537, key_size=3072)

    def enrollment(self, identifier="node-2", site="site-2", address="10.70.0.2", key=None, password=None):
        key = key or self.key()
        body = {"action": "password-bootstrap", "node_id": identifier, "site": site, "node_ip": address,
                "cluster_password": self.cluster_password if password is None else password, "transport_public_key": bootstrap._public_key(key),
                **self.api._database_runtime()}
        return key, body

    def enroll(self, **kwargs):
        key, body = self.enrollment(**kwargs)
        sealed = bootstrap.enroll(self.api, body, "192.0.2.9")
        return self.api.manager._unseal(sealed, key, body["node_id"]), key, body

    def install_joiner(self, response, identifier="node-2", site="site-2", key=None):
        joining = self.make_api(identifier, site)
        self.save(joining)
        if key is not None:
            from cryptography.hazmat.primitives import serialization
            private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
            _private_json(joining.manager.root / "appliance-node-key.json", {"key_ref": joining.manager.vault.put(private)})
        bootstrap._install_enrollment(joining, response, "https://seed.example:8787", (self.pki / "controller.pem").read_text(), "super_admin")
        return joining


@unittest.skipUnless(importlib.util.find_spec("cryptography"), "Bootstrap tests require real vault/cryptography dependencies")
class ClusterBootstrapTests(BootstrapFixture, unittest.TestCase):

    def test_local_runtime_is_manager_owned_and_gui_cannot_claim_a_profile(self):
        before = self.api._config()
        with self.assertRaises(ValueError):
            self.save(self.api, database_runtime_profile=bootstrap.DATABASE_RUNTIME_PROFILE)
        self.api.client.state["database_storage_compatible"] = False
        with self.assertRaisesRegex(ValueError, "verified Alpine"):
            self.save(self.api, cluster_password="", replication_password="")
        self.assertEqual(self.api._config(), before)

    def test_missing_legacy_or_incompatible_voter_cannot_create_authority_or_membership(self):
        _, valid = self.enrollment()
        before = self.api._config()
        for profile, compatible in ((None, True), ("postgres16-debian-glibc", True),
                                    (bootstrap.DATABASE_RUNTIME_PROFILE, False),
                                    (bootstrap.DATABASE_RUNTIME_PROFILE, "true")):
            with self.subTest(profile=profile, compatible=compatible):
                body = {**valid, "database_runtime_profile": profile, "database_storage_compatible": compatible}
                with patch.object(bootstrap, "_material") as material:
                    with self.assertRaisesRegex(ValueError, "verified Alpine"):
                        bootstrap.enroll(self.api, body, "192.0.2.9")
                    material.assert_not_called()
                self.assertEqual(self.api._config(), before)

    def test_current_source_manager_drift_is_not_hidden_by_cached_member_profile(self):
        _, body = self.enrollment()
        before = self.api._config()
        self.api.client.state["database_storage_compatible"] = False
        with self.assertRaisesRegex(ValueError, "verified Alpine"):
            bootstrap.enroll(self.api, body, "192.0.2.9")
        self.assertEqual(self.api._config(), before)
        with patch.object(bootstrap, "_material") as material:
            with self.assertRaisesRegex(ValueError, "verified Alpine"):
                bootstrap.manifest(self.api)
            material.assert_not_called()
        with self.assertRaisesRegex(ValueError, "verified Alpine"):
            bootstrap.reconcile(self.api)
        self.assertEqual(self.api.client.requests, [])

    def test_legacy_retained_voter_blocks_new_physical_replica_despite_fresh_claim(self):
        _, body = self.enrollment()
        with self.api.app.store.meta() as db:
            config = self.api._config(db)
            config["members"][0].pop("database_runtime_profile")
            self.api.app.store._put(db, "maintenance_settings", config)
        before = self.api._config()
        with self.assertRaisesRegex(ValueError, "verified Alpine"):
            bootstrap.enroll(self.api, body, "192.0.2.9")
        self.assertEqual(self.api._config(), before)

    def test_sync_requires_current_authenticated_runtime_report_without_fallback(self):
        response, key, body = self.enroll()
        sync = {"action": "node-sync", "node_id": body["node_id"], "site": body["site"],
                "node_ip": body["node_ip"], "sync_secret": response["sync_secret"]}
        before = self.api._config()
        with self.assertRaisesRegex(ValueError, "verified Alpine"):
            bootstrap.enroll(self.api, sync, "192.0.2.9")
        self.assertEqual(self.api._config(), before)
        accepted = self.api.manager._unseal(bootstrap.enroll(
            self.api, {**sync, **self.api._database_runtime()}, "192.0.2.9"), key, body["node_id"])
        self.assertEqual(accepted["configuration"]["members"][-1]["database_runtime_profile"], bootstrap.DATABASE_RUNTIME_PROFILE)

    def test_legacy_sealed_voter_reply_is_refused_before_private_material_install(self):
        response, _, _ = self.enroll()
        joining = self.make_api("node-2", "site-2")
        self.save(joining)
        before = joining._config()
        response["configuration"]["members"][0].pop("database_runtime_profile")
        with patch.object(bootstrap, "_save_material") as material:
            with self.assertRaisesRegex(ValueError, "verified Alpine"):
                bootstrap._install_enrollment(joining, response, "https://seed.example", "public-ca", "super_admin")
            material.assert_not_called()
        self.assertEqual(joining._config(), before)
        self.assertNotIn("authorized_join", joining._local())

    def test_management_only_member_needs_no_database_runtime_or_physical_clone(self):
        key, body = self.enrollment(site="site-1")
        body.pop("database_runtime_profile")
        body.pop("database_storage_compatible")
        response = self.api.manager._unseal(bootstrap.enroll(self.api, body, "192.0.2.9"), key, body["node_id"])
        member = response["configuration"]["members"][-1]
        self.assertEqual(member["role"], "management")
        joining = self.install_joiner(response, site="site-1", key=key)
        joining.client.state.pop("database_runtime_profile")
        joining.client.state["database_storage_compatible"] = False
        self.assertEqual(bootstrap.manifest(joining)["local_node"]["role"], "management")

    def test_activation_rechecks_all_three_voters_before_any_database_or_backup(self):
        self.enroll()
        self.enroll(identifier="node-3", site="site-3", address="10.70.0.3")
        config = self.api._config()
        self.assertTrue(all(member["database_runtime_profile"] == bootstrap.DATABASE_RUNTIME_PROFILE
                            for member in config["members"]))
        config["members"][-1]["database_runtime_profile"] = "postgres16-debian-glibc"
        with patch("psycopg.connect") as connect, patch.object(bootstrap, "_material") as material:
            with self.assertRaisesRegex(ValueError, "verified Alpine"):
                bootstrap._activate_source(self.api, config, self.api._local())
            connect.assert_not_called()
            material.assert_not_called()

    def test_runtime_evidence_is_bound_to_distinct_voter_id_site_and_ip(self):
        original = self.api._config()
        invalid = []
        swapped = copy.deepcopy(original)
        swapped["voters"][0]["ip"] = "10.70.0.99"
        invalid.append(swapped)
        duplicate = copy.deepcopy(original)
        duplicate["voters"] *= 3
        invalid.append(duplicate)
        omitted = copy.deepcopy(original)
        omitted["voters"] = []
        invalid.append(omitted)
        for config in invalid:
            with self.subTest(voters=config["voters"]), self.assertRaises(ValueError):
                bootstrap._assert_database_voters(config, own_id="node-1", own_runtime=self.api._database_runtime())

    def test_committed_public_port_refreshes_only_own_peer_origin(self):
        original = self.api._config()
        with self.api.app.store.meta() as db:
            current = self.api._config(db)
            current['members'].append({'id': 'unchanged-peer', 'ip': '10.70.0.99', 'site': 'other', 'role': 'management', 'origin': 'https://10.70.0.99:8787'})
            self.api.app.store._put(db, 'maintenance_settings', current)
        with patch('controller.application_port.advertised_origin', return_value='https://10.70.0.1:9443'), patch('controller.cluster_bootstrap.manifest', side_effect=StopIteration):
            with self.assertRaises(StopIteration):
                bootstrap.reconcile(self.api)
        current = self.api._config()
        own = next(member for member in current['members'] if member['id'] == 'node-1')
        peer = next(member for member in current['members'] if member['id'] == 'unchanged-peer')
        self.assertEqual(own['origin'], 'https://10.70.0.1:9443')
        self.assertEqual(peer['origin'], 'https://10.70.0.99:8787')
        self.assertEqual(current['controller_origin'], original['controller_origin'])
        self.assertEqual(current['revision'], original['revision'])

    def test_authenticated_member_updates_only_its_public_web_identity(self):
        response, key, body = self.enroll()
        revision = self.api._config()["revision"]
        certificate = (self.pki / "controller.pem").read_text()
        request = {"action": "node-sync", "node_id": "node-2", "site": "site-2", "node_ip": "10.70.0.2", "sync_secret": response["sync_secret"],
                   "tls_server_name": "localhost", "controller_ca": certificate, **self.api._database_runtime()}
        updated = self.api.manager._unseal(bootstrap.enroll(self.api, request, "192.0.2.9"), key, "node-2")
        member = next(value for value in updated["configuration"]["members"] if value["id"] == "node-2")
        self.assertEqual(member["tls_server_name"], "localhost")
        self.assertIn("BEGIN CERTIFICATE", member["controller_ca"])
        self.assertEqual(updated["configuration"]["revision"], revision)
        with self.assertRaises(ValueError):
            bootstrap.enroll(self.api, {**request, "controller_ca": certificate + (self.pki / "controller-key.pem").read_text()}, "192.0.2.9")
        with self.assertRaises(ValueError):
            bootstrap.enroll(self.api, {**request, "tls_server_name": "uncovered.example"}, "192.0.2.9")
        with self.assertRaises(PermissionError):
            bootstrap.enroll(self.api, {**request, "sync_secret": "wrong"}, "192.0.2.9")

    def test_actual_seal_binds_node_identity_key_and_ciphertext(self):
        key, body = self.enrollment()
        sealed = bootstrap.enroll(self.api, body, "192.0.2.9")
        response = self.api.manager._unseal(sealed, key, "node-2")
        self.assertEqual(response["configuration"]["deployment_id"], self.api._config()["deployment_id"])
        self.assertIn("ca_key", response["material"])
        self.assertNotIn(self.replication_password, json.dumps(sealed))
        with self.assertRaises(ValueError):
            self.api.manager._unseal(sealed, key, "different-node")
        with self.assertRaises(ValueError):
            self.api.manager._unseal(sealed, self.key(), "node-2")
        raw = bytearray(base64.b64decode(sealed["ciphertext"]))
        raw[-1] ^= 1
        with self.assertRaises(ValueError):
            self.api.manager._unseal({**sealed, "ciphertext": base64.b64encode(raw).decode()}, key, "node-2")

    def test_wrong_password_is_persistently_rate_limited_without_adding_members(self):
        key, body = self.enrollment(password="incorrect-cluster-password")
        for _ in range(8):
            with self.assertRaises(PermissionError):
                bootstrap.enroll(self.api, body, "192.0.2.9")
        with self.assertRaisesRegex(PermissionError, "limited"):
            bootstrap.enroll(self.api, {**body, "cluster_password": self.cluster_password}, "192.0.2.9")
        self.assertEqual(len(self.api._config()["members"]), 1)
        with patch("controller.cluster_bootstrap.now", return_value=now() + timedelta(minutes=6)):
            self.assertIsInstance(bootstrap.enroll(self.api, {**body, "cluster_password": self.cluster_password}, "192.0.2.9"), dict)
        self.assertEqual(len(self.api._config()["members"]), 2)

    def test_failed_bootstrap_prunes_only_expired_peer_attempts(self):
        _, body = self.enrollment(password="incorrect-cluster-password")
        store = self.api.app.store
        at = now()
        prefix = bootstrap.PASSWORD_ATTEMPT_PREFIX
        expired = prefix + "a" * 64
        current = prefix + "b" * 64
        unrelated = "applianceXauth:" + "c" * 64
        with store.meta() as db:
            for identifier, until in ((expired, at), (current, at + timedelta(minutes=1)), (unrelated, at)):
                store._put(db, "maintenance_settings", {"id": identifier, "count": 3, "until": stamp(until)})

        for peer in ("::ffff:c000:209", "192.0.2.9"):
            with self.assertRaisesRegex(PermissionError, "credentials were not accepted"):
                bootstrap.enroll(self.api, body, peer)

        key = prefix + hashlib.sha256(b"192.0.2.9").hexdigest()
        with store.read_meta() as db:
            self.assertIsNone(store._get(db, "maintenance_settings", expired))
            for identifier in (current, unrelated):
                self.assertEqual(store._get(db, "maintenance_settings", identifier)["count"], 3)
            self.assertEqual(store._get(db, "maintenance_settings", key)["count"], 2)

    def test_first_three_distinct_sites_are_voters_then_unlimited_management_nodes(self):
        self.enroll(identifier="node-2", site="site-1", address="10.70.0.2")
        self.enroll(identifier="node-3", site="site-2", address="10.70.0.3")
        self.enroll(identifier="node-4", site="site-3", address="10.70.0.4")
        for index in range(5, 9):
            self.enroll(identifier="node-" + str(index), site="site-" + str(index), address="10.70.0." + str(index))
        config = self.api._config()
        self.assertEqual(len(config["members"]), 8)
        self.assertEqual({member["id"] for member in config["voters"]}, {"node-1", "node-3", "node-4"})
        self.assertEqual(len({member["site"].casefold() for member in config["voters"]}), 3)
        self.assertTrue(all(member["role"] == "management" for member in config["members"] if member["id"] not in {"node-1", "node-3", "node-4"}))

    def test_same_transport_key_retry_preserves_revision_certificate_and_secret(self):
        response, key, body = self.enroll()
        revision = self.api._config()["revision"]
        retry = self.api.manager._unseal(bootstrap.enroll(self.api, body, "192.0.2.9"), key, "node-2")
        self.assertEqual(retry["configuration"]["revision"], revision)
        self.assertEqual(retry["node_certificate"], response["node_certificate"])
        self.assertEqual(retry["sync_secret"], response["sync_secret"])
        self.assertEqual(retry["material"], response["material"])
        self.assertEqual(len(self.api._config()["members"]), 2)

    def test_database_ca_is_distinct_and_rejects_real_enrolled_endpoint_certificate(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.x509.oid import NameOID
        response, key, body = self.enroll()
        material = response["material"]
        self.assertNotEqual(material["ca"], self.api.app.signer.ca.read_text())
        self.assertNotIn(self.api.app.signer.ca_key.read_text(), json.dumps(material))
        self.assertEqual(material["controller_ca"], self.api.app.signer.ca.read_text())
        certificate = x509.load_pem_x509_certificate(material["ca"].encode())
        self.assertTrue(certificate.extensions.get_extension_for_class(x509.BasicConstraints).critical)
        self.assertTrue(certificate.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign)
        self.assertIsNotNone(certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier))
        self.assertIsNotNone(certificate.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier))
        endpoint_key = self.key()
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "endpoint-acceptance")])).sign(endpoint_key, hashes.SHA256())
        endpoint, unused = self.api.app.signer("endpoint-acceptance", csr.public_bytes(serialization.Encoding.PEM).decode())
        internal_path, endpoint_path = self.directory / "internal-ca.pem", self.directory / "endpoint.pem"
        internal_path.write_text(material["ca"])
        endpoint_path.write_text(endpoint)
        rejected = subprocess.run(["openssl", "verify", "-CAfile", str(internal_path), str(endpoint_path)], capture_output=True, timeout=10)
        self.assertNotEqual(rejected.returncode, 0)
        accepted = subprocess.run(["openssl", "verify", "-CAfile", str(self.api.app.signer.ca), str(endpoint_path)], capture_output=True, timeout=10)
        self.assertEqual(accepted.returncode, 0)
        joined = self.install_joiner(response, key=key)
        self.assertEqual(bootstrap._material(joined), material)
        self.assertNotIn(self.api.app.signer.ca_key.read_text(), json.dumps(bootstrap.manifest(joined)))

    def test_legacy_endpoint_ca_material_is_not_silently_rotated_or_accepted(self):
        material = {"ca": self.api.app.signer.ca.read_text(), "ca_key": self.api.app.signer.ca_key.read_text(), "secrets": {}}
        bootstrap._save_material(self.api, material)
        with self.assertRaisesRegex(ValueError, "endpoint issuers"):
            bootstrap._material(self.api)

    def test_key_identity_ip_and_site_collisions_are_refused(self):
        response, key, body = self.enroll()
        for change in ({"transport_public_key": bootstrap._public_key(self.key())}, {"node_ip": "10.70.0.99"}, {"site": "new-site"}, {"node_id": "node-3"}):
            with self.subTest(change=list(change)), self.assertRaises(PermissionError):
                bootstrap.enroll(self.api, {**body, **change}, "192.0.2.9")
        self.assertEqual(len(self.api._config()["members"]), 2)

    def test_local_settings_cannot_erase_member_key_secret_or_violate_ip_site_uniqueness(self):
        response, key, body = self.enroll()
        joined = self.install_joiner(response)
        original = next(member for member in joined._config()["members"] if member["id"] == "node-2")
        self.save(joined, cluster_password="", replication_password="")
        saved = next(member for member in joined._config()["members"] if member["id"] == "node-2")
        self.assertEqual(saved["transport_public_key"], original["transport_public_key"])
        self.assertEqual(saved["sync_hash"], original["sync_hash"])
        for change in ({"node_ip": "10.70.0.1"}, {"site": "site-1"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.save(joined, cluster_password="", replication_password="", **change)

    def test_manifest_and_node_key_remain_stable_across_repeated_reads_and_restart(self):
        first = bootstrap.manifest(self.api)
        second = bootstrap.manifest(self.api)
        self.assertEqual(first, second)
        other_manager = PlatformManager(self.api.manager.data_dir)
        other_manager.attach(self.api.app)
        restarted = Appliance(other_manager, client=self.api.client)
        self.assertEqual(bootstrap.manifest(restarted), first)
        for path in self.api.manager.root.rglob("*.json"):
            self.assertNotIn(first["pki"]["private_key"], path.read_text())
            self.assertNotIn(self.replication_password, path.read_text())

    def test_identical_sync_installation_reuses_encrypted_material_and_credential_refs(self):
        response, key, body = self.enroll()
        joined = self.install_joiner(response, key=key)
        local = joined._local()
        material = json.loads((joined.manager.root / "appliance-material.json").read_text())
        count = len(list((joined.manager.root / "vault").glob("*.json")))
        bootstrap._install_enrollment(joined, response, "https://seed.example:8787", (self.pki / "controller.pem").read_text(), "super_admin")
        for field in ("peer_ca_ref", "sync_secret_ref", "node_certificate_ref"):
            self.assertEqual(joined._local()[field], local[field], field)
        self.assertEqual(json.loads((joined.manager.root / "appliance-material.json").read_text()), material)
        self.assertEqual(len(list((joined.manager.root / "vault").glob("*.json"))), count)

    def test_joined_preactive_identity_requires_membership_review_even_without_collision(self):
        response, key, body = self.enroll()
        joined = self.install_joiner(response, key=key)
        before = joined._config()
        for change in ({"site": "different-independent-site"}, {"node_ip": "10.70.0.99"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.save(joined, cluster_password="", replication_password="", **change)
        self.assertEqual(joined._config(), before)

    def test_preactive_cache_does_not_claim_to_save_shared_seed_settings(self):
        response, key, body = self.enroll()
        joined = self.install_joiner(response, key=key)
        before = joined._config()
        for change in ({"cluster_name": "Unexpected local-only rename"}, {"controller_origin": "https://different.example"}, {"cluster_password": "different-cluster-password-accepted-locally"}):
            payload = {"cluster_password": "", "replication_password": "", **change}
            with self.subTest(change=list(change)), self.assertRaises(ValueError):
                self.save(joined, **payload)
        self.assertEqual(joined._config(), before)

    def test_preactive_nonseed_cannot_admit_new_nodes_and_sync_is_identity_bound(self):
        response, key, body = self.enroll()
        joined = self.install_joiner(response)
        new_key, new_body = self.enrollment(identifier="node-3", site="site-3", address="10.70.0.3")
        with self.assertRaisesRegex(PermissionError, "original bootstrap"):
            bootstrap.enroll(joined, new_body, "192.0.2.10")
        sync = {"action": "node-sync", "node_id": "node-2", "site": "site-2", "node_ip": "10.70.0.2", "sync_secret": response["sync_secret"], **self.api._database_runtime()}
        updated = self.api.manager._unseal(bootstrap.enroll(self.api, sync, "192.0.2.9"), key, "node-2")
        self.assertEqual(updated["node_certificate"], response["node_certificate"])
        for change in ({"sync_secret": "wrong"}, {"site": "wrong"}, {"node_ip": "10.70.0.9"}):
            with self.subTest(change=change), self.assertRaises(PermissionError):
                bootstrap.enroll(self.api, {**sync, **change}, "192.0.2.9")

    def test_shared_authority_is_refused_before_sqlite_preflight_or_peer_contact(self):
        joined = self.make_api("node-2", "site-2")
        self.save(joined)
        with patch.object(joined.manager, "active_profile", return_value={"deployment_id": "already-active"}), patch.object(joined.manager, "_join_source_preflight") as preflight, patch.object(joined.manager, "_peer_request") as peer:
            with self.assertRaises(ValueError):
                joined.join_preview({"peer_url": "10.70.0.1", "cluster_password": self.cluster_password}, "super_admin")
            preflight.assert_not_called()
            peer.assert_not_called()

    def https_peer(self):
        parent = self
        received = []
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                received.append(body)
                reply = bootstrap.enroll(parent.api, body, self.client_address[0])
                raw = json.dumps(reply).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(self.pki / "controller.pem"), str(self.pki / "controller-key.pem"))
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(lambda: (server.shutdown(), server.server_close(), thread.join(3)))
        return "https://127.0.0.1:" + str(server.server_address[1]), received

    def test_real_https_preview_sends_no_password_until_typed_pin_is_approved(self):
        peer, received = self.https_peer()
        joined = self.make_api("node-2", "site-2")
        self.save(joined)
        plan = joined.join_preview({"peer_url": peer, "cluster_password": self.cluster_password}, "super_admin")
        self.assertEqual(received, [])
        self.assertFalse(plan["summary"]["trust_verified"])
        self.assertNotIn(self.cluster_password, json.dumps(plan))
        with self.assertRaises(WorkflowConflict):
            joined.join_apply({**self.confirmation(plan), "confirmation_phrase": "JOIN"}, "super_admin")
        self.assertEqual(received, [])
        queued = joined.join_apply(self.confirmation(plan), "super_admin")
        self.assertEqual(len(received), 1)
        self.assertEqual(received[0]["cluster_password"], self.cluster_password)
        self.assertEqual(joined.join_apply(self.confirmation(plan), "super_admin")["id"], queued["id"])
        self.assertEqual(len(received), 1)
        self.assertTrue(joined._local()["authorized_join"])
        self.assertEqual(joined._config()["deployment_id"], self.api._config()["deployment_id"])
        self.assertEqual(queued["status"], "queued")
        self.assertEqual(len(joined.app.store.servers()), 0)
        self.assertIsNone(joined.manager.active_profile())

    def test_identity_or_authority_change_after_pin_preview_sends_no_password(self):
        peer, received = self.https_peer()
        joined = self.make_api("node-2", "site-2")
        self.save(joined)
        plan = joined.join_preview({"peer_url": peer, "cluster_password": self.cluster_password}, "super_admin")
        self.save(joined, site="changed-site", cluster_password="", replication_password="")
        with self.assertRaises((ValueError, WorkflowConflict)):
            joined.join_apply(self.confirmation(plan), "super_admin")
        self.assertEqual(received, [])
        fresh = joined.join_preview({"peer_url": peer, "cluster_password": self.cluster_password}, "super_admin")
        with patch.object(joined.manager, "active_profile", return_value={"deployment_id": "now-active"}):
            with self.assertRaises(ValueError):
                joined.join_apply(self.confirmation(fresh), "super_admin")
        self.assertEqual(received, [])


@unittest.skipUnless(os.environ.get("PRTHAK_BOOTSTRAP_PG_ACCEPTANCE") == "1", "Opt in to dedicated real-PG bootstrap authority tests")
class SharedBootstrapPostgresTests(BootstrapFixture, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import make_conninfo
        cls.driver, cls.sql = psycopg, sql
        root = Path(__file__).resolve().parents[2]
        cls.names = pg_fixture.names("bootstrap")
        params = pg_fixture.parameters()
        with psycopg.connect(**params, dbname="postgres", autocommit=True) as db:
            user, path = db.execute("SELECT current_user,current_setting('data_directory')").fetchone()
            if user != "prthak_test" or Path(path).resolve() != pg_fixture.data_directory():
                raise RuntimeError("Only the prepared private PostgreSQL test cluster is allowed")
            for name in cls.names.values():
                if db.execute("SELECT 1 FROM pg_database WHERE datname=%s", (name,)).fetchone():
                    raise RuntimeError("Refusing to reuse a pre-existing private fixture database")
                db.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
        cls.dsns = {key: make_conninfo(**params, dbname=name) for key, name in cls.names.items()}

    def reset_targets(self):
        for key, dsn in self.dsns.items():
            with self.driver.connect(dsn, autocommit=True) as db:
                self.assertEqual(db.execute("SELECT current_database()").fetchone()[0], self.names[key])
                db.execute("DROP SCHEMA public CASCADE")
                db.execute("CREATE SCHEMA public")

    def setUp(self):
        from controller.platform_runtime import migrate_stopped_sqlite
        from controller.postgres import PostgresStore
        super().setUp()
        self.reset_targets()
        self.addCleanup(self.reset_targets)
        response, key, body = self.enroll()
        self.other = self.install_joiner(response, key=key)
        bootstrap.manifest(self.api)
        deployment = self.api._config()["deployment_id"]
        migrate_stopped_sqlite(self.api.app.store.path, self.dsns["metadata"], self.dsns["traffic"], deployment, 1)
        self.api.app.store = PostgresStore(self.dsns["metadata"], self.dsns["traffic"], deployment_id=deployment, epoch=1)
        self.other.app.store = PostgresStore(self.dsns["metadata"], self.dsns["traffic"], deployment_id=deployment, epoch=1)
        profile = {"metadata_dsn": self.dsns["metadata"], "traffic_dsn": self.dsns["traffic"], "deployment_id": deployment, "epoch": 1, "active_revision": 1, "controller_origin": "https://cluster.example"}
        self.api.manager.commit_active_profile(profile)
        self.other.manager.commit_active_profile(profile)

    def test_genuine_managed_pg_alternate_controller_retries_and_sync_preserve_secret_and_leaf(self):
        key, body = self.enrollment(identifier="node-3", site="site-3", address="10.70.0.3")
        first = self.api.manager._unseal(bootstrap.enroll(self.api, body, "192.0.2.9"), key, "node-3")
        retry = self.other.manager._unseal(bootstrap.enroll(self.other, body, "192.0.2.9"), key, "node-3")
        self.assertEqual(first["sync_secret"], retry["sync_secret"])
        self.assertEqual(first["node_certificate"], retry["node_certificate"])
        self.assertEqual(first["configuration"]["revision"], retry["configuration"]["revision"])
        sync = {"action": "node-sync", "node_id": "node-3", "site": "site-3", "node_ip": "10.70.0.3", "sync_secret": first["sync_secret"], **self.api._database_runtime()}
        update = self.other.manager._unseal(bootstrap.enroll(self.other, sync, "192.0.2.9"), key, "node-3")
        self.assertEqual(update["node_certificate"], first["node_certificate"])
        registry = self.api._config()
        self.assertEqual(len(registry["members"]), 3)
        self.assertNotIn(first["sync_secret"], json.dumps(registry))
        self.assertNotIn(first["material"]["sync_key"], json.dumps(registry))
        self.assertNotIn(first["material"]["ca_key"], json.dumps(registry))
        self.assertEqual(first["material"]["ca"], bootstrap._material(self.other)["ca"])
        self.assertNotIn(first["sync_secret"], json.dumps(self.other.status()))
        self.assertEqual(self.api.app.store.readiness(), {"metadata": True, "traffic": True})

    def test_genuine_managed_pg_password_limiter_is_shared_across_controllers(self):
        key, body = self.enrollment(identifier="node-3", site="site-3", address="10.70.0.3", password="incorrect-password-for-shared-test")
        for api in (self.api, self.other):
            store = api.app.store
            store.enable_worker_pool(metadata_max=2, traffic_max=1)
            self.addCleanup(store.close_worker_pool)
        for api in (self.api, self.other) * 4:
            with self.assertRaisesRegex(PermissionError, "credentials were not accepted"):
                bootstrap.enroll(api, body, "192.0.2.44")
        with self.assertRaisesRegex(PermissionError, "limited"):
            bootstrap.enroll(self.other, {**body, "cluster_password": self.cluster_password}, "192.0.2.44")
        self.assertEqual(len(self.api._config()["members"]), 2)


if __name__ == "__main__":
    unittest.main()
