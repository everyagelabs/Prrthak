import base64
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from controller.policy_signing import PolicySigner
from controller.runtime_integrity import IntegrityError, verify


class RuntimeIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);(self.root/'controller').mkdir();(self.root/'dashboard').mkdir()
        self.signer=PolicySigner(self.root/'release.seed','00000000-0000-0000-0000-000000000000',create=True)
        self.names=['controller/__init__.py','controller/__main__.py','controller/app.py','dashboard/index.html','dashboard/app.js']
        for name in self.names:(self.root/name).write_text('trusted '+name)
        self.trust=self.root/'trust.json';self.trust.write_text(json.dumps(self.signer.public_trust()))
        self.manifest=self.root/'integrity.json'
        self.document={'kind':'prthak-controller-runtime-v1','version':'0.7.0','files':{name:{'bytes':len((self.root/name).read_bytes()),'sha256':hashlib.sha256((self.root/name).read_bytes()).hexdigest()} for name in self.names}}
        self.sign()

    def sign(self):self.manifest.write_text(json.dumps(self.signer.sign_package(self.document)))
    def check(self):return verify(self.root,self.manifest,self.trust,protected_directories=False)

    def test_valid_release_and_mutable_settings_are_independent(self):
        (self.root/'settings.json').write_text('{"polling":30}')
        self.assertTrue(self.check()['verified'])
        (self.root/'settings.json').write_text('{"polling":60}')
        self.assertTrue(self.check()['verified'])

    def test_same_length_modified_code_refuses_start(self):
        path=self.root/'dashboard/app.js';raw=path.read_bytes();path.write_bytes(b'X'+raw[1:])
        with self.assertRaises(IntegrityError):self.check()

    def test_unlisted_code_and_missing_files_refuse_start(self):
        new=self.root/'controller/injected.py';new.write_text('print("unsafe")')
        with self.assertRaises(IntegrityError):self.check()
        new.unlink();(self.root/self.names[0]).unlink()
        with self.assertRaises(IntegrityError):self.check()

    def test_manifest_tampering_unknown_signer_and_wrong_domain_refuse_start(self):
        signed=json.loads(self.manifest.read_text());signed['signature']=base64.b64encode(b'X'*64).decode();self.manifest.write_text(json.dumps(signed))
        with self.assertRaises(IntegrityError):self.check()
        self.sign();self.trust.write_text('{"keys":{}}')
        with self.assertRaises(IntegrityError):self.check()

    def test_symlink_and_writable_runtime_files_refuse_start(self):
        path=self.root/self.names[0];path.chmod(0o666)
        with self.assertRaises(IntegrityError):self.check()
        path.chmod(0o644);value=path.read_text();path.unlink();target=self.root/'other';target.write_text(value);path.symlink_to(target)
        with self.assertRaises(IntegrityError):self.check()

    def test_signed_traversal_still_cannot_expand_scope(self):
        self.document['files']['../outside.py']={'bytes':1,'sha256':'a'*64};self.sign()
        with self.assertRaises(IntegrityError):self.check()
