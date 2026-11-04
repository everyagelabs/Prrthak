import copy
import json
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
import uuid
from unittest.mock import Mock

from controller.firewall import WorkflowConflict
from controller.platform import PlatformManager
from controller.store import Store

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


@unittest.skipUnless(HAS_CRYPTO, 'Platform credential tests require controller requirements')
class PlatformManagerTests(unittest.TestCase):
    def setUp(self):
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.manager = PlatformManager(self.temp.name)
        key = ed25519.Ed25519PrivateKey.generate()
        self.private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()).decode()
        public = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
        self.spec = {'cluster_id': str(uuid.uuid4()), 'name': 'prthak-ha', 'controller_origin': 'https://prthak.example',
                     'mode': 'dc_dr', 'rpo': 'synchronous_strict', 'controller_cidrs': ['10.90.0.0/24'],
                     'database': {}, 'watchdog': {'mode': 'required', 'approved': True, 'device': '/dev/watchdog'},
                     'nodes': [{'id': 'node-' + str(i), 'name': 'node-' + str(i), 'ip': '10.70.0.' + str(i), 'site': 'dc-' + str(i),
                                'role': 'database' if i < 3 else 'witness',
                                'ssh': {'user': 'root', 'port': 22, 'host_key': public, 'private_key': self.private}} for i in range(1, 4)]}

    def save(self):
        return self.manager.save_configuration({'expected_revision': 0, 'spec': copy.deepcopy(self.spec)}, 'super')

    def test_controller_display_name_is_local_and_bound_to_the_controller(self):
        store = Mock()
        self.manager.app = types.SimpleNamespace(controller_id="node-1", store=store)
        self.assertEqual(self.manager.controller_display_name(), "")
        with self.assertRaises(WorkflowConflict):
            self.manager.save_controller_display_name({"controller_id": "node-2", "display_name": "Remote"}, "admin")
        with self.assertRaises(ValueError):
            self.manager.save_controller_display_name({"controller_id": "node-1", "display_name": "Name\nwith newline"}, "admin")
        saved = self.manager.save_controller_display_name({"controller_id": "node-1", "display_name": "  Primary DC  "}, "admin")
        self.assertEqual(saved, {"controller_id": "node-1", "display_name": "Primary DC"})
        self.assertEqual(PlatformManager(self.temp.name).controller_display_name(), "Primary DC")
        store.audit.assert_called_once_with("controller.display_name_changed", "admin", {
            "controller_id": "node-1", "previous": "", "display_name": "Primary DC",
        })
        self.manager.save_controller_display_name({"controller_id": "node-1", "display_name": ""}, "admin")
        self.assertEqual(self.manager.controller_display_name(), "")

    def test_credentials_are_encrypted_and_blanks_preserve_only_own_node_key(self):
        saved = self.save()
        self.assertEqual(saved['revision'], 1)
        self.assertNotIn(self.private, json.dumps(saved))
        self.assertTrue(all(node['ssh']['private_key_configured'] for node in saved['spec']['nodes']))
        raw = (self.manager.root / 'configuration.json').read_text()
        self.assertNotIn(self.private, raw)
        private = self.manager.configuration(True)
        reference = private['spec']['nodes'][0]['ssh']['private_key_ref']
        self.assertEqual(self.manager.vault.get(reference), self.private)
        for file in (self.manager.root / 'vault').glob('*'):
            self.assertEqual(file.stat().st_mode & 0o777, 0o600)
            self.assertNotIn(self.private, file.read_text())
        updated = copy.deepcopy(saved['spec'])
        for node in updated['nodes']:
            node['ssh']['private_key'] = ''
            node['ssh']['private_key_ref'] = 'secret:' + 'f' * 32
        self.manager.save_configuration({'expected_revision': 1, 'spec': updated}, 'super')
        self.assertEqual(self.manager.configuration(True)['spec']['nodes'][0]['ssh']['private_key_ref'], reference)
        with self.assertRaises(WorkflowConflict):
            self.manager.save_configuration({'expected_revision': 1, 'spec': updated}, 'super')

    def test_test_review_apply_is_exact_idempotent_and_not_implied_by_saved_settings(self):
        recovery = [{'node_id': 'node-1', 'status': 'recoverable', 'snapshot_digest': 'a' * 64}]
        received = []
        class Provider:
            def preview(self, spec):
                return {'status': 'preview', 'blockers': [], 'nodes': [], 'configuration_recovery': recovery, 'warnings': ['Interrupted owned configuration will be restored before retry']}
            def apply(self, spec, progress=None, expected_recovery_snapshots=None):
                received.append(expected_recovery_snapshots)
                if progress:
                    progress({'phase': 'install', 'status': 'running'})
                return {'status': 'ready', 'blockers': []}
            def private_connection_fields(self, spec):
                return {'private': 'not-public'}
        self.manager.provisioner_factory = lambda manager: Provider()
        self.save()
        self.assertIsNone(self.manager.active_profile())
        tested = self.manager.test_configuration({'expected_revision': 1}, 'super')
        self.manager.run_pending_provisioning()
        self.manager._provision_thread.join(3)
        self.assertEqual(self.manager.job(tested['id'])['status'], 'ready')
        plan = self.manager.preview({'expected_revision': 1, 'test_job_id': tested['id']}, 'super')
        self.assertEqual(plan['configuration_recovery'], recovery)
        self.assertTrue(plan['warnings'])
        body = {key: plan[key] for key in ('digest', 'confirmation_nonce', 'confirmation_phrase')}
        body['preview_id'] = plan['id']
        with self.assertRaises(WorkflowConflict):
            self.manager.apply({**body, 'confirmation_phrase': 'not confirmed'}, 'super')
        queued = self.manager.apply(body, 'super')
        self.assertEqual(self.manager.apply(body, 'super')['id'], queued['id'])
        self.manager.run_pending_provisioning()
        self.manager._provision_thread.join(3)
        public = self.manager.job(queued['id'])
        self.assertEqual(public['status'], 'ready')
        self.assertNotIn('not-public', json.dumps(public))
        self.assertEqual(received, [recovery])
        self.assertIsNone(self.manager.active_profile())

    def test_bad_credential_shapes_fail_before_queuing_or_saving_configuration(self):
        for value in (None, {}, [None] * 3):
            spec = {**self.spec, 'nodes': value}
            with self.subTest(nodes=value), self.assertRaises(ValueError):
                self.manager.save_configuration({'expected_revision': 0, 'spec': spec}, 'super')
        spec = copy.deepcopy(self.spec)
        spec['nodes'][0]['ssh']['private_key'] = ['invalid']
        with self.assertRaises(ValueError):
            self.manager.save_configuration({'expected_revision': 0, 'spec': spec}, 'super')
        self.assertEqual(self.manager.configuration()['revision'], 0)

    def test_default_controller_identity_survives_restart_and_explicit_join_identity_replaces_it(self):
        self.assertEqual(self.manager.local_controller_id('generated-first'), 'generated-first')
        other_process = PlatformManager(self.temp.name)
        self.assertEqual(other_process.local_controller_id('new-pid-generated'), 'generated-first')
        self.assertEqual(other_process.local_controller_id('joined-dr', explicit=True), 'joined-dr')
        self.assertEqual(self.manager.local_controller_id('another-pid'), 'joined-dr')

    def test_fresh_sqlite_join_preflight_skips_pg_only_tables_but_blocks_real_inventory(self):
        store = Store(Path(self.temp.name) / 'new-controller')
        self.manager.attach(types.SimpleNamespace(store=store))
        self.manager._join_source_preflight()
        store.report('existing-local-node', {'hostname': 'existing-local-node', 'ips': ['10.70.0.90'], 'listeners': []})
        with self.assertRaisesRegex(ValueError, 'no local servers'):
            self.manager._join_source_preflight()

    def test_changed_configuration_and_parent_recovery_cannot_run_an_old_plan(self):
        self.save()
        old = self.manager.configuration(True)
        queued = self.manager._queue('preflight', {'configuration': old}, 'super')
        public = self.manager.configuration()['spec']
        public['name'] = 'revised-ha'
        self.manager.save_configuration({'expected_revision': 1, 'spec': public}, 'super')
        self.manager.run_pending_provisioning()
        self.assertEqual(self.manager.job(queued['id'])['status'], 'blocked')
        profile = {'metadata_dsn': 'private metadata', 'traffic_dsn': 'private traffic', 'deployment_id': str(uuid.uuid4()), 'epoch': 1, 'active_revision': 1}
        runtime = self.manager._queue('join', {'profile_ref': self.manager.vault.put(json.dumps(profile))}, 'super')
        self.assertEqual(self.manager.claim_runtime_job()['profile'], profile)
        self.manager.recover_runtime_jobs()
        self.assertEqual(self.manager.claim_runtime_job()['id'], runtime['id'])
        self.assertNotIn('private metadata', (self.manager._job_path(runtime['id'])).read_text())

    def test_demo_can_never_start_remote_installation_or_join(self):
        store = Store(Path(self.temp.name) / 'source')
        app = types.SimpleNamespace(store=store, demo=True, signer=object())
        self.manager.attach(app)
        for callback in (lambda: self.manager.test_configuration({}, 'super'), lambda: self.manager.join_preview({}, 'super'), lambda: self.manager.activate({'confirm': True}, 'super')):
            with self.assertRaisesRegex(ValueError, 'HTTPS production'):
                callback()

    @unittest.skipUnless(HAS_PG, 'Encrypted node join profile needs psycopg connection parsing')
    def test_join_uses_one_time_bound_code_encrypted_transport_unique_tls_and_safe_retry(self):
        from controller.pki import init_ca, Signer
        from cryptography import x509
        primary = self.manager
        self.save()
        database_ca = primary.root / 'test-database-ca.pem'
        pki = init_ca(Path(self.temp.name) / 'pki-fixture')
        database_ca.write_text((pki / 'ca.pem').read_text())
        store = Store(Path(self.temp.name) / 'primary-data')
        store.ha = True  # Transport fixture uses real SQLite tables; no database connection is simulated as live.
        app = types.SimpleNamespace(store=store, demo=False, signer=Signer(pki / 'ca.pem', pki / 'ca-key.pem'),
              controller_id='primary', cluster=lambda: {'nodes': []}, auth=types.SimpleNamespace(enabled=False, config=None), tokens={'super_admin': 'synthetic-private-token'})
        primary.attach(app)
        primary.commit_active_profile({'deployment_id': self.spec['cluster_id'], 'epoch': 1, 'active_revision': 1,
            'controller_origin': 'https://localhost:8787', 'mode': 'dc_dr', 'spec': primary.configuration(True)['spec'],
            'metadata_dsn': 'host=10.70.0.1 dbname=prthak_metadata user=app password=synthetic-secret sslrootcert=' + str(database_ca),
            'traffic_dsn': 'host=10.70.0.1 dbname=prthak_traffic user=app password=synthetic-secret sslrootcert=' + str(database_ca)})
        identity = {'node_id': 'dr-controller', 'site': 'dr-dc', 'node_ip': '10.70.0.50'}
        issued = primary.create_join_token(identity, 'super')
        target = PlatformManager(Path(self.temp.name) / 'new-node')
        target._peer_request = lambda peer, ca, body: primary.enroll_node(body)
        plan = target.join_preview({**identity, 'join_code': issued['join_code'], 'peer_url': issued['peer_url']}, 'bootstrap')
        request = {key: plan[key] for key in ('digest', 'confirmation_nonce', 'confirmation_phrase')}
        request['preview_id'] = plan['id']
        queued = target.join_apply(request, 'bootstrap')
        self.assertEqual(target.join_apply(request, 'bootstrap')['id'], queued['id'])
        job = target.claim_runtime_job()
        profile = job['profile']
        self.assertEqual(profile['deployment_id'], self.spec['cluster_id'])
        self.assertEqual(profile['controller_id'], identity['node_id'])
        self.assertTrue(profile['join_preserve_local_snapshot'])
        cert = x509.load_pem_x509_certificate(Path(profile['controller_tls']['cert']).read_bytes())
        self.assertIn('10.70.0.50', [str(ip) for ip in cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.IPAddress)])
        # Verify the actual issued/decrypted join leaf, including strict CA/AKI
        # requirements and both canonical DNS and node-IP identities.
        for identity_option, value in (('-verify_hostname', 'localhost'), ('-verify_ip', identity['node_ip'])):
            verified = subprocess.run(['openssl', 'verify', '-x509_strict', '-purpose', 'sslserver',
                identity_option, value, '-CAfile', str(pki / 'ca.pem'), profile['controller_tls']['cert']],
                capture_output=True, text=True, timeout=10)
            self.assertEqual(verified.returncode, 0, verified.stdout + verified.stderr)
        issuer = x509.load_pem_x509_certificate((pki / 'ca.pem').read_bytes())
        self.assertEqual(cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier,
                         issuer.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest)
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage)
        self.assertTrue(usage.critical)
        self.assertTrue(usage.value.digital_signature)
        self.assertTrue(usage.value.key_encipherment)
        self.assertFalse(usage.value.key_cert_sign)
        self.assertIsNotNone(cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier))
        record = next(row for row in store.all('maintenance_settings') if row['id'].startswith('platform_join:'))
        self.assertTrue(record['consumed'])
        self.assertNotIn('synthetic-secret', json.dumps(record))
        self.assertNotIn('synthetic-private-token', json.dumps(record))
        with self.assertRaises(PermissionError):
            code = primary._join_code(issued['join_code'])
            primary.enroll_node({'action': 'inspect', 'token_id': code['id'], 'secret': code['secret'], **identity})
