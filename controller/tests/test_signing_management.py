import base64
from datetime import timedelta
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

from controller import signing_management as signing
from controller.firewall import WorkflowConflict
from controller.platform import PlatformManager
from controller.store import Store, now


class SigningManagementTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.store = Store(self.root/'db')
        self.manager = PlatformManager(self.root/'controller')
        self.manager.app = types.SimpleNamespace(store=self.store, demo=True, controller_id='node-one')
        clean = {name: '' for name in ('SEG_POLICY_SIGNED_BUNDLES_DIR', 'SEG_POLICY_SIGNING_TRUST_FILE', 'SEG_POLICY_SIGNING_KEY_FILE', 'SEG_POLICY_SIGNING_DEPLOYMENT_ID')}
        environment = patch.dict(os.environ, clean); environment.start(); self.addCleanup(environment.stop)
        self.signer = self.manager.policy_signer()
        self.seed = self.signer.path.read_bytes()
        self.trust = self.signer.public_trust()

    def checkpoint(self):
        return signing.checkpoint(self.manager, 'super-one')

    def missing_review(self):
        checkpoint = self.checkpoint(); self.signer.path.unlink()
        return signing.recovery_preview(self.manager, {'checkpoint_id': checkpoint['id']}, 'super-one')

    @staticmethod
    def confirmation(plan):
        return {'preview_id': plan['id'], **{key: plan[key] for key in ('digest', 'confirmation_nonce', 'confirmation_phrase')}}

    def test_status_is_truthful_online_public_only_and_rotation_is_unavailable(self):
        status = signing.status(self.manager)
        self.assertEqual(status['mode'], 'online_controller'); self.assertEqual(status['health'], 'online_key_available')
        self.assertEqual(status['public_trust'], self.trust); self.assertFalse(status['private_key_download']); self.assertFalse(status['rotation_available'])
        self.assertIn('online', status['custody']); self.assertIn('not off-node', status['checkpoint_scope'])
        text = json.dumps(status)
        self.assertNotIn(base64.b64encode(self.seed).decode(), text); self.assertNotIn(self.seed.hex(), text)

    def test_self_check_verifies_actual_ed25519_signature_without_changing_key_or_policy(self):
        result = signing.check(self.manager, 'super-one')
        self.assertEqual(result['status'], 'passed'); self.assertEqual(result['key_ids'], sorted(self.trust['keys']))
        self.assertEqual(self.signer.path.read_bytes(), self.seed); self.assertEqual(self.store.all('policies'), [])
        self.assertEqual(signing.status(self.manager)['last_check']['status'], 'passed')
        with patch.object(self.signer, 'sign_package', return_value={'algorithm': 'Ed25519', 'payload': 'not-base64', 'signature': 'bad', 'key_id': 'bad'}):
            self.assertEqual(signing.check(self.manager, 'super-one')['status'], 'failed')
        self.assertEqual(self.signer.path.read_bytes(), self.seed)

    def test_checkpoint_is_encrypted_local_and_never_in_public_or_database_backup_rows(self):
        checkpoint = self.checkpoint()
        self.assertEqual(checkpoint['key_ids'], sorted(self.trust['keys'])); self.assertNotIn('secret_ref', checkpoint)
        state = json.loads((self.manager.root/signing.STATE_FILE).read_text())
        self.assertIn('secret_ref', state['checkpoints'][0])
        serialized = json.dumps(state) + ''.join(path.read_text() for path in (self.manager.root/'vault').glob('*.json')) + json.dumps(self.store.all('audit'))
        self.assertNotIn(base64.b64encode(self.seed).decode(), serialized); self.assertNotIn(self.seed.hex(), serialized)
        self.assertEqual((self.manager.root/signing.STATE_FILE).stat().st_mode & 0o777, 0o600)

    def test_missing_key_recovery_restores_same_key_and_preserves_existing_pins(self):
        plan = self.missing_review()
        self.assertEqual(signing.status(self.manager)['health'], 'unavailable')
        result = signing.recovery_apply(self.manager, self.confirmation(plan), 'super-one')
        self.assertEqual(result['status'], 'restored'); self.assertEqual(result['self_check']['status'], 'passed')
        self.assertEqual(self.signer.path.read_bytes(), self.seed); self.assertEqual(self.manager.policy_signer().public_trust(), self.trust)
        self.assertEqual(signing.status(self.manager)['health'], 'online_key_available')
        with self.assertRaises(WorkflowConflict): signing.recovery_apply(self.manager, self.confirmation(plan), 'super-one')

    def test_recovery_rejects_wrong_actor_nonce_digest_phrase_and_expiry(self):
        plan = self.missing_review()
        with self.assertRaises(WorkflowConflict): signing.recovery_apply(self.manager, self.confirmation(plan), 'other-super')
        for change in ({'confirmation_nonce': 'wrong'}, {'digest': 'wrong'}, {'confirmation_phrase': 'yes'}):
            with self.subTest(change=change), self.assertRaises(WorkflowConflict):
                signing.recovery_apply(self.manager, {**self.confirmation(plan), **change}, 'super-one')
        with patch.object(signing, 'now', return_value=now()+timedelta(minutes=11)), self.assertRaises(WorkflowConflict):
            signing.recovery_apply(self.manager, self.confirmation(plan), 'super-one')
        self.assertFalse(self.signer.path.exists())

    def test_existing_or_newly_appeared_key_is_never_overwritten(self):
        checkpoint = self.checkpoint()
        with self.assertRaises(ValueError): signing.recovery_preview(self.manager, {'checkpoint_id': checkpoint['id']}, 'super-one')
        self.signer.path.unlink(); plan = signing.recovery_preview(self.manager, {'checkpoint_id': checkpoint['id']}, 'super-one')
        replacement = b'x'*32; self.signer.path.write_bytes(replacement); self.signer.path.chmod(0o600)
        with self.assertRaises(ValueError): signing.recovery_apply(self.manager, self.confirmation(plan), 'super-one')
        self.assertEqual(self.signer.path.read_bytes(), replacement)

    def test_changed_authority_wrong_node_and_unsafe_key_paths_block_recovery(self):
        plan = self.missing_review()
        with patch.object(self.manager, 'shared_secret_key', return_value=b'z'*32), self.assertRaises(ValueError):
            signing.recovery_apply(self.manager, self.confirmation(plan), 'super-one')
        self.manager.app.controller_id = 'node-two'
        with self.assertRaises(ValueError): signing.recovery_apply(self.manager, self.confirmation(plan), 'super-one')
        self.manager.app.controller_id = 'node-one'
        target = self.root/'outside.seed'; target.write_bytes(self.seed); target.chmod(0o600); self.signer.path.symlink_to(target)
        with self.assertRaises(ValueError): signing.recovery_apply(self.manager, self.confirmation(plan), 'super-one')
        self.assertEqual(target.read_bytes(), self.seed)

    def test_unsafe_or_missing_vault_key_is_not_silently_regenerated_or_cached(self):
        vault_key = self.manager.root/'vault'/'vault.key'
        vault_key.chmod(0o644)
        with self.assertRaises(ValueError): self.checkpoint()
        vault_key.chmod(0o600); previous = vault_key.read_bytes(); vault_key.unlink()
        with self.assertRaises(ValueError): self.checkpoint()
        self.assertFalse(vault_key.exists())
        from cryptography.fernet import Fernet
        vault_key.write_bytes(Fernet.generate_key()); vault_key.chmod(0o600)
        with self.assertRaises(Exception): self.checkpoint()
        self.assertNotEqual(vault_key.read_bytes(), previous)

    def test_checkpoint_limits_unsafe_state_and_external_path_are_preserved(self):
        with patch.object(signing, 'MAX_CHECKPOINTS', 1):
            self.checkpoint()
            with self.assertRaises(ValueError): self.checkpoint()
        path = self.manager.root/signing.STATE_FILE; path.chmod(0o644)
        with self.assertRaises(ValueError): self.checkpoint()
        self.assertEqual(signing.status(self.manager)['health'], 'unavailable')
        path.chmod(0o600)
        with patch.dict(os.environ, {'SEG_POLICY_SIGNING_KEY_FILE': str(self.signer.path), 'SEG_POLICY_SIGNING_DEPLOYMENT_ID': self.trust['deployment_id']}):
            self.assertEqual(signing.status(self.manager)['mode'], 'online_external_file')
            self.assertFalse(signing.status(self.manager)['checkpoint_available'])
            with self.assertRaises(ValueError): self.checkpoint()

    def test_recovery_body_never_accepts_arbitrary_seed_or_path(self):
        checkpoint = self.checkpoint()
        for body in ({'checkpoint_id': checkpoint['id'], 'path': '/tmp/foreign'}, {'checkpoint_id': checkpoint['id'], 'seed': self.seed.hex()}, {'checkpoint_id': 1}):
            with self.assertRaises(ValueError): signing.recovery_preview(self.manager, body, 'super-one')
        with self.assertRaises(ValueError): signing.recovery_apply(self.manager, {'seed': self.seed.hex()}, 'super-one')

    def test_restore_publication_failure_leaves_no_partial_active_key_or_temporary_copy(self):
        plan = self.missing_review()
        with patch.object(signing.os, 'link', side_effect=OSError('fixture publication failure')), self.assertRaises(ValueError):
            signing.recovery_apply(self.manager, self.confirmation(plan), 'super-one')
        self.assertFalse(self.signer.path.exists())
        self.assertEqual(list(self.signer.path.parent.glob('.signing-recovery-*')), [])
        self.assertEqual(signing.recovery_apply(self.manager, self.confirmation(plan), 'super-one')['status'], 'restored')

    def test_audit_is_written_after_the_cross_process_lifecycle_lease_is_released(self):
        import fcntl
        original = self.store.audit
        def audit(*args, **kwargs):
            descriptor = os.open(self.manager.root/signing.LOCK_FILE, os.O_RDWR)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)
            return original(*args, **kwargs)
        with patch.object(self.store, 'audit', side_effect=audit):
            self.assertEqual(signing.check(self.manager, 'super-one')['status'], 'passed')
            self.checkpoint()
