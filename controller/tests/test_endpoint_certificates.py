from datetime import timedelta
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

from controller import endpoint_certificates as lifecycle
from controller import endpoint_renewal as rollout
from controller.auth import AuthDenied, EntraAuth, EntraConfig
from controller.authentication import Authentication
from controller.firewall import WorkflowConflict
from controller.pki import Signer, init_ca
from controller.store import Store, now, stamp


class EndpointCertificateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.pki = init_ca(self.root)
        self.signer = Signer(self.pki / 'ca.pem', self.pki / 'ca-key.pem')
        self.ca = x509.load_pem_x509_certificate(self.signer.ca.read_bytes())
        self.ca_key = serialization.load_pem_private_key(self.signer.ca_key.read_bytes(), None)
        self.store = Store(self.root / 'db')
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.server_id = 'endpoint-certificate-test'
        self.store.report(self.server_id, {'hostname': 'billing-test', 'ips': ['10.241.7.9'], 'listeners': []})
        self.cert = self.leaf(self.key, 20)
        with self.store.meta() as db:
            server = self.store._get(db, 'servers', self.server_id)
            lifecycle.record_issued(self.store, db, server, self.cert.public_bytes(serialization.Encoding.PEM).decode())
            self.store._put(db, 'servers', server)

    def leaf(self, key, days):
        return x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.server_id)])).issuer_name(self.ca.subject).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now()-timedelta(minutes=1)).not_valid_after(now()+timedelta(days=days)).add_extension(x509.BasicConstraints(ca=False,path_length=None),True).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),False).sign(self.ca_key,hashes.SHA256())

    def csr(self, key=None):
        return x509.CertificateSigningRequestBuilder().subject_name(self.cert.subject).sign(key or self.key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()

    def schedule(self):
        with self.store.meta() as db:
            server = self.store._get(db, "servers", self.server_id)
            server["capabilities"] = [rollout.CAPABILITY]
            self.store._put(db, "servers", server)
            self.store._put(db, "maintenance_settings", {"id": rollout.REVIEW_PREFIX + "expired", "expires_at": stamp(now() - timedelta(minutes=1))})
        app = SimpleNamespace(store=self.store, platform=True, signer=self.signer, demo=False, auth=Mock())
        owner = {"role": "super_admin", "auth_type": "session", "actor": "owner"}
        with self.assertRaises(PermissionError):
            rollout.preview(app, {}, {**owner, "auth_type": "token"})
        preview = rollout.preview(app, {}, owner)
        with self.store.read_meta() as db:
            self.assertIsNone(self.store._get(db, "maintenance_settings", rollout.REVIEW_PREFIX + "expired"))
        body = {"preview_id": preview["id"], **{key: preview[key] for key in ("digest", "confirmation_nonce", "confirmation_phrase")}}
        with self.assertRaises(WorkflowConflict):
            rollout.apply(app, body, {**owner, "actor": "another-admin"})
        result = rollout.apply(app, body, owner)
        self.assertEqual(result["counts"]["pending"], 1)
        with self.assertRaises(WorkflowConflict):
            rollout.apply(app, body, owner)
        return result["id"]

    def test_scheduled_renewal_uses_exact_same_key_and_retires_only_after_candidate_proof(self):
        der = self.cert.public_bytes(serialization.Encoding.DER)
        identifier = self.schedule()
        descriptor = self.store.assignment(self.server_id)[0]["certificate_renewal"]
        self.assertEqual(descriptor["id"], identifier)
        self.assertEqual(descriptor["new_fingerprint"], "")
        with self.assertRaises(PermissionError):
            lifecycle.renew(self.store, self.server_id, der, {"renewal_id": identifier, "csr": self.csr(ec.generate_private_key(ec.SECP256R1()))}, self.signer)
        self.assertFalse(lifecycle.renew(self.store, self.server_id, der, {"csr": self.csr()}, self.signer)["renewed"])
        response = lifecycle.renew(self.store, self.server_id, der, {"renewal_id": identifier, "csr": self.csr()}, self.signer)
        self.assertEqual(lifecycle.renew(self.store, self.server_id, der, {"renewal_id": identifier, "csr": self.csr()}, self.signer), response)
        newer = x509.load_pem_x509_certificate(response["certificate"].encode())
        new_der = newer.public_bytes(serialization.Encoding.DER)
        self.assertEqual(lifecycle.authorize(self.store, self.server_id, der)["status"], "active")
        self.assertEqual(lifecycle.listing(self.store)["renewal_rollout"]["counts"]["issued"], 1)
        action = {"renewal_id": identifier, "action": "confirm"}
        with self.assertRaises(PermissionError):
            lifecycle.renew(self.store, self.server_id, der, action, self.signer)
        with self.assertRaises(PermissionError):
            lifecycle.renew(self.store, self.server_id, new_der, action, self.signer)
        lifecycle.renew(self.store, self.server_id, new_der, {**action, "action": "probe", "split_channels": "true"}, self.signer)
        with self.assertRaises(PermissionError):
            lifecycle.renew(self.store, self.server_id, new_der, action, self.signer)
        with self.assertRaises(PermissionError):
            lifecycle.probe_discovery(self.store, self.server_id, der, {"certificate_renewal_probe": identifier})
        self.assertEqual(lifecycle.probe_discovery(self.store, self.server_id, new_der, {"certificate_renewal_probe": identifier})["action"], "probe-discovery")
        self.assertEqual(lifecycle.authorize(self.store, self.server_id, der)["status"], "active")
        restarted = Store(self.root / "db")
        self.assertEqual(lifecycle.renew(restarted, self.server_id, new_der, action, self.signer)["action"], "confirm")
        self.assertEqual(lifecycle.renew(restarted, self.server_id, new_der, action, self.signer)["action"], "confirm")
        self.assertEqual(lifecycle.authorize(restarted, self.server_id, der)["status"], "retiring")
        self.assertEqual(lifecycle.listing(restarted)["renewal_rollout"]["counts"]["confirmed"], 1)
        self.assertNotIn("certificate_renewal", restarted.assignment(self.server_id)[0])

    def test_scheduled_renewal_rejects_early_and_stale_assignments(self):
        der = self.cert.public_bytes(serialization.Encoding.DER)
        identifier = self.schedule()
        with self.store.meta() as db:
            job = rollout.job(self.store, db, self.server_id)
            job["not_before"] = stamp(now() + timedelta(minutes=1))
            self.store._put(db, "maintenance_settings", job)
        self.assertNotIn("certificate_renewal", self.store.assignment(self.server_id)[0])
        self.assertEqual(lifecycle.listing(self.store)["renewal_rollout"]["counts"]["scheduled"], 1)
        with self.assertRaises(PermissionError):
            lifecycle.renew(self.store, self.server_id, der, {"renewal_id": identifier, "csr": self.csr()}, self.signer)
        ordinary = lifecycle.renew(self.store, self.server_id, der, {"csr": self.csr()}, self.signer)
        self.assertTrue(ordinary["renewed"])
        self.assertEqual(lifecycle.listing(self.store)["renewal_rollout"]["counts"]["superseded"], 1)

    def test_bulk_renewal_revalidates_named_session_inside_confirmation(self):
        origin = "https://prthak.example.internal"
        headers = {"Host": "prthak.example.internal", "Origin": origin}
        auth = Authentication(self.store, entra=EntraAuth(self.store, EntraConfig()), origin=origin)
        app = SimpleNamespace(store=self.store, platform=True, signer=self.signer, demo=False, auth=auth)
        with self.store.meta() as db:
            server = self.store._get(db, "servers", self.server_id)
            server["capabilities"] = [rollout.CAPABILITY]
            self.store._put(db, "servers", server)
        limited = auth.local_login({"username": "admin", "password": "admin"}, headers)["principal"]
        with self.assertRaises(AuthDenied):
            rollout.preview(app, {}, limited)
        password = "Endpoint renewal test phrase 2026"
        actor = auth.change_password({"current_password": "admin", "new_password": password, "confirm_password": password},
                                     limited, {**headers, "X-CSRF-Token": limited["csrf_token"]})["principal"]
        review = rollout.preview(app, {}, actor)
        with self.store.meta() as db:
            db.execute("DELETE FROM auth_sessions WHERE id=?", (actor["_session_id"],))
        body = {"preview_id": review["id"], **{key: review[key] for key in ("digest", "confirmation_nonce", "confirmation_phrase")}}
        with self.assertRaises(AuthDenied):
            rollout.apply(app, body, actor)
        self.assertIsNone(lifecycle.listing(self.store)["renewal_rollout"])

    def test_renewal_replay_overlap_and_new_identity_survive_restart(self):
        der = self.cert.public_bytes(serialization.Encoding.DER)
        body = {'csr': self.csr()}
        response = lifecycle.renew(self.store, self.server_id, der, body, self.signer)
        self.assertTrue(response['renewed'])
        self.assertEqual(lifecycle.renew(self.store, self.server_id, der, body, self.signer), response)
        # ECDSA CSR signatures differ on retry, while the authenticated key does not.
        self.assertEqual(lifecycle.renew(self.store, self.server_id, der, {'csr': self.csr()}, self.signer), response)
        newer = x509.load_pem_x509_certificate(response['certificate'].encode())
        self.assertGreater(newer.not_valid_after_utc, self.cert.not_valid_after_utc)
        self.assertEqual(lifecycle.authorize(self.store, self.server_id, der)['status'], 'retiring')
        restarted = Store(self.root / 'db')
        with patch('controller.endpoint_certificates.now', return_value=now()+timedelta(hours=25)):
            with self.assertRaises(PermissionError):
                lifecycle.authorize(restarted, self.server_id, der)
        self.assertEqual(lifecycle.authorize(restarted, self.server_id, newer.public_bytes(serialization.Encoding.DER))['status'], 'active')

    def test_leaf_validity_boundaries_are_checked_before_registry_lookup(self):
        der = self.cert.public_bytes(serialization.Encoding.DER)
        for boundary in (self.cert.not_valid_before_utc-timedelta(microseconds=1), self.cert.not_valid_after_utc):
            with self.subTest(boundary=boundary), patch('controller.endpoint_certificates.now', return_value=boundary):
                with patch.object(self.store, 'read_meta', side_effect=AssertionError('Invalid-time certificates must not read or migrate registry state')):
                    with self.assertRaisesRegex(PermissionError, 'expired or not yet valid'):
                        lifecycle.authorize(self.store, self.server_id, der)
        with patch('controller.endpoint_certificates.now', return_value=self.cert.not_valid_before_utc):
            self.assertEqual(lifecycle.authorize(self.store, self.server_id, der)['status'], 'active')

    def test_invalid_time_legacy_certificate_is_never_registered(self):
        with self.store.meta() as db:
            server = self.store._get(db, 'servers', self.server_id)
            server.pop('certificate_registry', None)
            self.store._put(db, 'servers', server)
            db.execute('DELETE FROM maintenance_settings')
        der = self.cert.public_bytes(serialization.Encoding.DER)
        for boundary in (self.cert.not_valid_before_utc-timedelta(seconds=1), self.cert.not_valid_after_utc):
            with patch('controller.endpoint_certificates.now', return_value=boundary):
                with self.assertRaises(PermissionError):
                    lifecycle.authorize(self.store, self.server_id, der)
        self.assertFalse(self.store.get('servers', self.server_id).get('certificate_registry'))
        self.assertEqual(self.store.all('maintenance_settings'), [])

    def test_revocation_blocks_every_api_identity_and_unknown_same_cn(self):
        plan = lifecycle.revoke_preview(self.store, {'server_id': self.server_id}, 'super_admin')
        result = lifecycle.revoke_apply(self.store, {'preview_id': plan['id'], **{key: plan[key] for key in ('digest','confirmation_nonce','confirmation_phrase')}}, 'super_admin')
        self.assertEqual(result['revoked_count'], 1)
        for candidate in (self.cert, self.leaf(self.key, 30)):
            with self.assertRaises(PermissionError):
                lifecycle.authorize(self.store, self.server_id, candidate.public_bytes(serialization.Encoding.DER))
        with self.assertRaises(PermissionError):
            lifecycle.renew(self.store, self.server_id, self.cert.public_bytes(serialization.Encoding.DER), {'csr': self.csr(), 'hostname': 'billing-test'}, self.signer)

    def test_recovery_token_is_exact_key_bound_and_restores_existing_server(self):
        token = lifecycle.recovery_token(self.store, self.server_id, 'super_admin')
        csr = self.csr(ec.generate_private_key(ec.SECP256R1()))
        response = lifecycle.recover(self.store, {'token': token['token'], 'csr': csr, 'hostname': 'billing-test'}, self.signer)
        self.assertEqual(response['server_id'], self.server_id)
        self.assertEqual(lifecycle.recover(self.store, {'token': token['token'], 'csr': csr, 'hostname': 'billing-test'}, self.signer), response)
        with self.assertRaises(PermissionError):
            lifecycle.recover(self.store, {'token': token['token'], 'csr': self.csr(), 'hostname': 'billing-test'}, self.signer)
        self.assertEqual(len(self.store.servers()), 1)
        self.assertNotIn(token['token'], str(lifecycle.listing(self.store)))

    def test_new_leaf_outside_window_is_not_reissued(self):
        response = lifecycle.recover(self.store, {'token': lifecycle.recovery_token(self.store, self.server_id, 'super_admin')['token'], 'csr': self.csr(), 'hostname': 'billing-test'}, self.signer)
        current = x509.load_pem_x509_certificate(response['certificate'].encode())
        result = lifecycle.renew(self.store, self.server_id, current.public_bytes(serialization.Encoding.DER), {'csr': self.csr(), 'hostname': 'billing-test'}, self.signer)
        self.assertFalse(result['renewed'])

    def test_wrong_hostname_cannot_consume_recovery_token(self):
        token = lifecycle.recovery_token(self.store, self.server_id, 'super_admin')
        body = {'token': token['token'], 'csr': self.csr(), 'hostname': 'another-server'}
        with self.assertRaises(PermissionError):
            lifecycle.recover(self.store, body, self.signer)
        body['hostname'] = 'billing-test'
        self.assertEqual(lifecycle.recover(self.store, body, self.signer)['server_id'], self.server_id)

    def test_replay_cannot_return_a_subsequently_revoked_recovery_identity(self):
        token = lifecycle.recovery_token(self.store, self.server_id, 'super_admin')
        body = {'token': token['token'], 'csr': self.csr(), 'hostname': 'billing-test'}
        lifecycle.recover(self.store, body, self.signer)
        plan = lifecycle.revoke_preview(self.store, {'server_id': self.server_id}, 'super_admin')
        lifecycle.revoke_apply(self.store, {'preview_id': plan['id'], **{key: plan[key] for key in ('digest', 'confirmation_nonce', 'confirmation_phrase')}}, 'super_admin')
        with self.assertRaises(PermissionError):
            lifecycle.recover(self.store, body, self.signer)
