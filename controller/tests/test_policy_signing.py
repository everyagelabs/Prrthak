import copy
import json
from pathlib import Path
import tempfile
import unittest

from controller.policy_signing import PolicySigner, OfflinePolicySigner, verify


class PolicySigningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.signer = PolicySigner(Path(self.temp.name) / "signing.seed", "12345678-1234-5678-1234-567812345678", create=True)
        self.policy = {"server_id": "signed-endpoint", "version": 7, "digest": "a" * 64, "mode": "enforce", "services": [{"port": 8443, "protocol": "tcp", "sources": ["10.20.0.0/16"]}], "enforcement": {"authorized": True, "approved_digest": "a" * 64}, "generated_at": "2026-10-30T10:00:00+00:00"}

    def test_independent_key_stable_bucket_and_full_content_binding(self):
        signed = self.signer.sign(self.policy, at=1800000001)
        self.assertEqual(signed, self.signer.sign(self.policy, at=1800000020))
        self.assertEqual(verify(signed, self.signer.public_trust(), at=1800000020), self.policy)
        for field, value in (("server_id", "another-host"), ("version", 8), ("services", []), ("enforcement", {"authorized": False}), ("polling_settings", {"control_interval_seconds": 5})):
            with self.subTest(field=field), self.assertRaises(ValueError):
                verify({**signed, field: value}, self.signer.public_trust(), at=1800000020)
        self.assertNotIn(self.signer.path.read_bytes().hex(), json.dumps(signed))

    def test_expired_unknown_key_deployment_and_bit_flip_are_rejected(self):
        signed = self.signer.sign(self.policy, at=1800000001)
        for trust in ({**self.signer.public_trust(), "deployment_id": "another"}, {"deployment_id": self.signer.deployment_id, "keys": {}}):
            with self.assertRaises(ValueError):
                verify(signed, trust, at=1800000010)
        with self.assertRaises(ValueError):
            verify(signed, self.signer.public_trust(), at=1800002000)
        mutated = copy.deepcopy(signed)
        mutated["signature"]["payload"] = mutated["signature"]["payload"][:-3] + "AAAA"
        with self.assertRaises(ValueError):
            verify(mutated, self.signer.public_trust(), at=1800000010)

    def test_explicit_key_rotation_reuses_key_only_when_operator_pins_it(self):
        old = self.signer.public_trust()
        newer = PolicySigner(Path(self.temp.name) / "new.seed", self.signer.deployment_id, create=True)
        signed = newer.sign(self.policy, at=1800000001)
        with self.assertRaises(ValueError):
            verify(signed, old, at=1800000010)
        overlap = {"deployment_id": old["deployment_id"], "keys": {**old["keys"], **newer.public_trust()["keys"]}}
        self.assertEqual(verify(signed, overlap, at=1800000010), self.policy)
        self.signer.path.chmod(0o644)
        with self.assertRaises(ValueError):
            PolicySigner(self.signer.path, self.signer.deployment_id)

    def test_offline_provider_has_no_private_key_and_refuses_new_or_stale_authority(self):
        import hashlib
        directory = Path(self.temp.name) / "signed"
        directory.mkdir(mode=0o700)
        trust = Path(self.temp.name) / "public-trust.json"
        trust.write_text(json.dumps(self.signer.public_trust()))
        trust.chmod(0o644)
        provider = OfflinePolicySigner(directory, trust)
        with self.assertRaises(ValueError):
            provider.sign(self.policy, at=1800000010)
        artifact = directory / (hashlib.sha256(self.policy["server_id"].encode()).hexdigest()+".json")
        artifact.write_text(json.dumps(self.signer.sign(self.policy, at=1800000001)))
        artifact.chmod(0o600)
        self.assertEqual(provider.sign(self.policy, at=1800000010)["server_id"], self.policy["server_id"])
        self.assertFalse(hasattr(provider, "key"))
        with self.assertRaises(ValueError):
            provider.sign({**self.policy, "version": 8}, at=1800000010)
        with self.assertRaises(ValueError):
            provider.sign(self.policy, at=1800002000)
