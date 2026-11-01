from datetime import timedelta
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

from controller import endpoint_certificates as lifecycle
from controller.pki import Signer, init_ca
from controller.store import Store, now


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
