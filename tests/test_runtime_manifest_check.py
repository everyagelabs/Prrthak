"""The real branch gate rejects stale signed application and bootstrap bytes."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

from controller.policy_signing import PolicySigner
from controller import __version__
from controller.runtime_integrity import IntegrityError

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('prthak_manifest_check', ROOT / 'scripts/check-runtime-manifest.py')
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class CommittedRuntimeManifestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        names = ('controller/__init__.py', 'controller/__main__.py', 'controller/app.py',
                 'controller/runtime_integrity.py', 'dashboard/index.html', 'dashboard/app.js',
                 'deploy/cluster/node_helper.py', 'deploy/verify_runtime_entrypoint.py',
                 'deploy/appliance/controller_entrypoint.py', 'deploy/appliance/node_manager.py')
        for name in names:
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text('public fixture ' + name)
        (self.root / 'controller/__init__.py').write_text('__version__ = "' + __version__ + '"\n')
        self.signer = PolicySigner(self.root / 'test.seed', '00000000-0000-0000-0000-000000000000', create=True)
        self.trust = self.root / 'deploy/release-public-trust.json'
        self.trust.write_text(json.dumps(self.signer.public_trust()))
        self.manifest = self.root / 'deploy/runtime-integrity.json'
        self.sign()

    def sign(self, edit=None):
        builder_spec = importlib.util.spec_from_file_location('prthak_manifest_fixture_builder', ROOT / 'scripts/sign-runtime.py')
        builder = importlib.util.module_from_spec(builder_spec)
        builder_spec.loader.exec_module(builder)
        value = builder.controller_manifest(self.root)
        if edit:
            edit(value)
        self.manifest.write_text(json.dumps(self.signer.sign_package(value)))

    def test_valid_source_and_documentation_only_change_pass(self):
        self.assertTrue(checker.check(self.root)['verified'])
        (self.root / 'README.md').write_text('Airtel Payments Bank documentation')
        self.assertTrue(checker.check(self.root)['verified'])

    def test_branding_change_requires_a_new_reviewed_signature(self):
        (self.root / 'dashboard/index.html').write_text('Airtel Payments Bank footer')
        with self.assertRaisesRegex(IntegrityError, 'dashboard/index.html'):
            checker.check(self.root)
        self.sign()
        self.assertTrue(checker.check(self.root)['verified'])

    def test_changed_host_manager_and_bootstrap_refuse_source_gate(self):
        for name in ('deploy/appliance/node_manager.py', 'deploy/verify_runtime_entrypoint.py'):
            with self.subTest(name=name):
                target = self.root / name
                old = target.read_bytes()
                target.write_bytes(old + b' changed')
                with self.assertRaises(IntegrityError):
                    checker.check(self.root)
                target.write_bytes(old)

    def test_signed_wrong_version_and_omitted_file_refuse_gate(self):
        self.sign(lambda value: value.update(version='0.0.1'))
        with self.assertRaises(IntegrityError):
            checker.check(self.root)
        self.sign(lambda value: value['files'].pop('dashboard/app.js'))
        with self.assertRaises(IntegrityError):
            checker.check(self.root)
