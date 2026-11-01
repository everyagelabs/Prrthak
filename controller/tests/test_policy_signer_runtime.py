import os
from pathlib import Path
import secrets
import tempfile
import unittest
from unittest.mock import patch
import uuid

from controller.app import App
from controller.auth import EntraAuth, EntraConfig
from controller.pki import Signer, init_ca
from controller.store import Store


class PolicySignerRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.pki = init_ca(self.root / 'tls')
        self.store = Store(self.root / 'db')
        self.app = App(self.store, signer=Signer(self.pki/'ca.pem', self.pki/'ca-key.pem'), auth=EntraAuth(self.store, EntraConfig()))
        self.manager = self.app.platform

    def test_cache_avoids_redecrypting_shared_material_but_detects_missing_authority(self):
        first = self.manager.policy_signer()
        with patch.object(self.manager, 'shared_secret_key', side_effect=AssertionError('No repeated derivation')):
            self.assertIs(self.manager.policy_signer(), first)
        (self.manager.root/'appliance-material.json').unlink()
        with self.assertRaises(ValueError):
            self.manager.policy_signer()
        self.assertFalse((self.manager.root/'appliance-material.json').exists())

    def test_unsafe_key_permissions_invalidate_the_cached_signer(self):
        signer = self.manager.policy_signer()
        signer.path.chmod(0o644)
        # A permission failure must be rejected before cache-stamp equality or
        # any shared-material derivation, regardless of filesystem timestamps.
        with patch.object(self.manager,'shared_secret_key',side_effect=AssertionError('Unsafe seed must fail before derivation')):
            with self.assertRaises(ValueError):
                self.manager.policy_signer()

    def test_external_key_with_explicit_domain_does_not_require_online_ca_material(self):
        path = self.root/'external-signing.seed'
        path.write_bytes(secrets.token_bytes(32))
        path.chmod(0o600)
        domain = str(uuid.uuid4())
        with patch.dict(os.environ, {'SEG_POLICY_SIGNING_KEY_FILE':str(path), 'SEG_POLICY_SIGNING_DEPLOYMENT_ID':domain}):
            with patch.object(self.manager, 'shared_secret_key', side_effect=AssertionError('External signing is separate')):
                self.assertEqual(self.manager.policy_signer().public_trust()['deployment_id'], domain)
        self.assertFalse((self.manager.root/'appliance-material.json').exists())
