"""Verify public vectors produced by real Python authority/signing/health code.

The companion Go reader validates these exact bytes in its own implementation.
This test does not build Go or claim native firewall/SSH/live-Entra acceptance.
"""
import base64
import copy
import json
from pathlib import Path
import unittest

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ed25519, padding
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from controller.policy_signing import DOMAIN
from controller.store import digest

FIXTURE = Path(__file__).with_name('fixtures') / 'host-default-deny.json'


class HostDefaultDenyInteropVectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        raw = FIXTURE.read_bytes()
        assert len(raw) < 1024 * 1024
        cls.document = json.loads(raw)

    def validate_case(self, case):
        policy, protection = case['policy'], case['protection']
        signature = policy['signature']
        payload = base64.b64decode(signature['payload'], validate=True)
        public = base64.b64decode(case['trust']['keys'][signature['key_id']], validate=True)
        ed25519.Ed25519PublicKey.from_public_bytes(public).verify(
            base64.b64decode(signature['signature'], validate=True), payload)
        envelope = json.loads(payload)
        self.assertEqual(envelope['domain'], DOMAIN)
        self.assertEqual(envelope['deployment_id'], case['trust']['deployment_id'])
        self.assertLessEqual(envelope['issued_at'], case['at'])
        self.assertLess(case['at'], envelope['expires_at'])
        self.assertEqual(envelope['policy'], {key: value for key, value in policy.items() if key != 'signature'})
        body = {key: policy[key] for key in ('mode', 'services')}
        if policy.get('host_default_deny') is True:
            body['host_default_deny'] = True
        self.assertEqual(policy['digest'], digest(body))
        authority, witness = policy['enforcement'], case['witness']
        self.assertIs(authority['host_default_deny_ack'], True)
        self.assertEqual(authority['approved_digest'], policy['digest'])
        self.assertEqual(authority['approved_version'], policy['version'])
        self.assertEqual(authority['host_default_deny_configuration_digest'], case['configuration_state']['digest'])
        self.assertEqual(authority['protection_digest'], protection['digest'])
        scope = {key: protection[key] for key in ('management_sources', 'ssh_ports', 'controller_url',
                  'management_probe_url', 'zone', 'host_default_deny_context_digest', 'host_default_deny_control_profile')}
        self.assertEqual(digest(scope), protection['digest'])
        proof = authority['approval_proof']
        self.assertEqual(proof['binding_digest'], digest({key: value for key, value in proof.items() if key != 'binding_digest'}))
        self.assertEqual(proof['scope']['kind'], 'host_default_deny')
        self.assertEqual(proof['scope']['action'], case['name'])
        self.assertEqual(proof['requester']['user_id'], proof['approved_by']['user_id'])
        self.assertEqual(witness['nonce'], case['nonce'])
        self.assertEqual(witness['approval_proof'], proof)
        self.assertEqual(witness['intent'], authority['intent'])
        for key in ('host_default_deny_ack', 'host_default_deny_revision', 'host_default_deny_configuration_digest'):
            self.assertEqual(witness[key], authority[key])
        for key in ('server_id', 'version', 'digest'):
            self.assertEqual(witness[key], policy[key])
        self.assertEqual(witness['protection_digest'], protection['digest'])
        self.assertEqual(witness['binding_digest'], authority['binding_digest'])
        self.assertEqual(witness['status'], 'healthy')
        self.assertIs(witness['controller_ok'], True)

    def test_actual_python_signed_assignment_authority_and_health_witness_are_consistent(self):
        self.assertEqual(self.document['schema_version'], 1)
        self.assertEqual([case['name'] for case in self.document['cases']], ['enable', 'disable'])
        for case in self.document['cases']:
            with self.subTest(action=case['name']):
                self.validate_case(case)

    def test_vectors_contain_public_pki_and_explicit_fixture_limits_only(self):
        provenance = self.document['provenance']
        self.assertIs(provenance['private_material_exported'], False)
        self.assertIn('agent 0.8.', provenance['native_helper_version'])
        self.assertIn('ManagementHealth.check', provenance['pipeline'])
        self.assertIn('Deterministic', provenance['management_actuator'])
        self.assertIn('not a native firewall', provenance['prior_apply'])
        serialized = json.dumps(self.document)
        for marker in ('-----BEGIN PRIVATE KEY-----', '-----BEGIN RSA PRIVATE KEY-----', '-----BEGIN EC PRIVATE KEY-----', 'isolated-identity-fixture'):
            self.assertNotIn(marker, serialized)
        for case in self.document['cases']:
            leaf = x509.load_pem_x509_certificate(case['certificate_pem'].encode())
            ca = x509.load_pem_x509_certificate(case['endpoint_ca_pem'].encode())
            self.assertEqual(leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, case['policy']['server_id'])
            self.assertEqual(leaf.issuer, ca.subject)
            ca.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes, padding.PKCS1v15(), leaf.signature_hash_algorithm)
            self.assertIn(ExtendedKeyUsageOID.CLIENT_AUTH, leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)

    def test_disable_uses_last_applied_matrix_and_distinct_real_native_config_digest(self):
        enable, disable = self.document['cases']
        self.assertIs(enable['policy']['host_default_deny'], True)
        self.assertFalse(disable['policy'].get('host_default_deny', False))
        self.assertIs(disable['removal'], True)
        self.assertFalse(disable['config']['allow_host_default_deny'])
        self.assertNotEqual(enable['configuration_state']['digest'], disable['configuration_state']['digest'])
        self.assertEqual(disable['policy']['services'], enable['policy']['services'])
        self.assertEqual([service['port'] for service in disable['policy']['services']], [8443])
        self.assertTrue(any(':' in source for service in enable['policy']['services'] for source in service['sources']))
        self.assertGreater(disable['policy']['version'], enable['policy']['version'])

    def test_changing_outer_host_flag_or_ack_does_not_match_the_real_python_signature(self):
        for field in ('host_default_deny', 'ack'):
            case = copy.deepcopy(self.document['cases'][0])
            if field == 'ack':
                case['policy']['enforcement']['host_default_deny_ack'] = False
            else:
                case['policy']['host_default_deny'] = False
            with self.subTest(field=field), self.assertRaises(AssertionError):
                self.validate_case(case)


if __name__ == '__main__':
    unittest.main()
