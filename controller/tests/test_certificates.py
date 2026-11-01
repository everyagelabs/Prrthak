import base64
from datetime import timedelta
import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

from controller import certificates
from controller.firewall import WorkflowConflict
from controller.platform import PlatformManager
from controller.store import Store, now


@unittest.skipUnless(importlib.util.find_spec("cryptography"), "Certificate management needs controller requirements")
class CertificateTests(unittest.TestCase):
    def setUp(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        self.x509, self.serialization, self.rsa = x509, serialization, rsa
        self.hashes = hashes
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name)
        self.manager = PlatformManager(self.directory)
        self.store = Store(self.directory / "db")
        self.ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Certificate test issuer")])
        self.ca = x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(self.ca_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now() - timedelta(days=1)).not_valid_after(now() + timedelta(days=365)).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(self.ca_key, hashes.SHA256())
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.current = self.leaf(self.key)
        self.ca_path = self.write("ca.pem", self.pem(self.ca))
        self.ca_key_path = self.write("ca-key.pem", self.key_pem(self.ca_key))
        self.cert_path = self.write("server.pem", self.pem(self.current) + self.pem(self.ca))
        self.key_path = self.write("server-key.pem", self.key_pem(self.key))
        self.context = {"hostname": "controller.example", "cert_path": str(self.cert_path), "key_path": str(self.key_path), "ca_path": str(self.ca_path)}
        self.manager.certificate_context = lambda: dict(self.context)
        self.manager.app = types.SimpleNamespace(demo=False, signer=None, store=self.store)

    def write(self, name, value):
        path = self.directory / name
        path.write_text(value)
        path.chmod(0o600)
        return path

    def pem(self, certificate):
        return certificate.public_bytes(self.serialization.Encoding.PEM).decode()

    def key_pem(self, key, password=None):
        encryption = self.serialization.BestAvailableEncryption(password) if password else self.serialization.NoEncryption()
        return key.private_bytes(self.serialization.Encoding.PEM, self.serialization.PrivateFormat.PKCS8, encryption).decode()

    def leaf(self, key, hostname="controller.example", ca=False, client_only=False, expired=False, future=False):
        import ipaddress
        from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
        at = now()
        return self.x509.CertificateBuilder().subject_name(self.x509.Name([self.x509.NameAttribute(NameOID.COMMON_NAME, hostname)])).issuer_name(self.ca.subject).public_key(key.public_key()).serial_number(self.x509.random_serial_number()).not_valid_before(at + timedelta(days=1) if future else at - timedelta(days=2)).not_valid_after(at - timedelta(days=1) if expired else at + timedelta(days=30)).add_extension(self.x509.BasicConstraints(ca=ca, path_length=None), critical=True).add_extension(self.x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH if client_only else ExtendedKeyUsageOID.SERVER_AUTH]), critical=False).add_extension(self.x509.SubjectAlternativeName([self.x509.DNSName(hostname), self.x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False).sign(self.ca_key, self.hashes.SHA256())

    def body(self, certificate=None, key=None, **extra):
        return {"mode": "pem", "certificate_pem": self.pem(certificate or self.current) + self.pem(self.ca), "private_key_pem": self.key_pem(key or self.key), **extra}

    def confirm(self, plan):
        return {"preview_id": plan["id"], **{key: plan[key] for key in ("digest", "confirmation_nonce", "confirmation_phrase")}}

    def corporate_chain(self, root_path_length=None, intermediate_ca=True):
        from cryptography.x509.oid import NameOID
        root_key, issuer_key, leaf_key = [self.rsa.generate_private_key(public_exponent=65537, key_size=2048) for _ in range(3)]
        root_name = self.x509.Name([self.x509.NameAttribute(NameOID.COMMON_NAME, "Corporate web root")])
        issuer_name = self.x509.Name([self.x509.NameAttribute(NameOID.COMMON_NAME, "Corporate web intermediate")])

        def ca(subject, key, issuer, signing_key, is_ca, path_length):
            return (self.x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
                .public_key(key.public_key()).serial_number(self.x509.random_serial_number())
                .not_valid_before(now() - timedelta(days=1)).not_valid_after(now() + timedelta(days=90))
                .add_extension(self.x509.BasicConstraints(ca=is_ca, path_length=path_length if is_ca else None), True)
                .sign(signing_key, self.hashes.SHA256()))

        root = ca(root_name, root_key, root_name, root_key, True, root_path_length)
        issuer = ca(issuer_name, issuer_key, root_name, root_key, intermediate_ca, 0)
        with patch.object(self, "ca", issuer), patch.object(self, "ca_key", issuer_key):
            leaf = self.leaf(leaf_key)
        return leaf, issuer, root, leaf_key

    def imported_bundle(self, mode, chain, key):
        if mode == "pem":
            return {"mode": mode, "certificate_pem": "".join(self.pem(value) for value in chain), "private_key_pem": self.key_pem(key)}
        from cryptography.hazmat.primitives.serialization import pkcs12
        archive = pkcs12.serialize_key_and_certificates(b"Corporate web", key, chain[0], chain[1:] or None, self.serialization.NoEncryption())
        return {"mode": mode, "pkcs12_bytes": archive}

    def reviewed_chain(self, plan):
        record = json.loads((self.manager.root / "certificate-plans" / (plan["id"] + ".json")).read_text())
        material = json.loads(self.manager.vault.get(record["material_ref"]))
        return certificates._certificates(material["certificate_pem"].encode())

    def test_managed_unknown_corporate_leaf_or_partial_chain_requires_complete_issuer_bundle(self):
        self.context["managed_appliance"] = True
        leaf, issuer, root, key = self.corporate_chain()
        for mode in ("pem", "pkcs12"):
            for chain in ([leaf], [leaf, issuer]):
                with self.subTest(mode=mode, certificates=len(chain)), self.assertRaisesRegex(ValueError, "Include the issuing intermediate certificates and root CA"):
                    certificates.preview(self.manager, self.imported_bundle(mode, chain, key), "super_admin")
        self.assertFalse((self.manager.root / "certificate-plans").exists())

    def test_managed_complete_corporate_chain_is_reviewable_for_pem_and_pkcs12_with_trust_change(self):
        self.context["managed_appliance"] = True
        leaf, issuer, root, key = self.corporate_chain()
        for mode in ("pem", "pkcs12"):
            with self.subTest(mode=mode):
                plan = certificates.preview(self.manager, self.imported_bundle(mode, [leaf, issuer, root], key), "super_admin")
                self.assertEqual([certificates._fp(value) for value in self.reviewed_chain(plan)], [certificates._fp(value) for value in (leaf, issuer, root)])
                self.assertTrue(plan["summary"]["trust_change"])
                self.assertIn("AND UPDATE CLIENT TRUST", plan["confirmation_phrase"])

    def test_managed_leaf_only_import_is_completed_from_existing_public_anchors_or_current_chain(self):
        self.context["managed_appliance"] = True
        leaf, issuer, root, key = self.corporate_chain()
        anchor_path = self.write("corporate-public-chain.pem", self.pem(issuer) + self.pem(root))
        for location in ("trust_ca_path", "cert_path"):
            with self.subTest(location=location):
                original = dict(self.context)
                if location == "cert_path":
                    self.cert_path.write_text(self.pem(leaf) + self.pem(issuer) + self.pem(root))
                else:
                    self.context[location] = str(anchor_path)
                plan = certificates.preview(self.manager, self.imported_bundle("pem", [leaf], key), "super_admin")
                self.assertEqual([certificates._fp(value) for value in self.reviewed_chain(plan)], [certificates._fp(value) for value in (leaf, issuer, root)])
                self.context = original
        # The ordinary existing local issuer also produces a complete chain.
        self.manager.app.signer = types.SimpleNamespace(ca=self.ca_path, ca_key=self.ca_key_path)
        plan = certificates.preview(self.manager, {"mode": "self_signed", "hostname": "controller.example"}, "super_admin")
        self.assertEqual(len(self.reviewed_chain(plan)), 2)

    def test_managed_literal_self_signed_is_allowed_but_forged_self_signature_and_invalid_ca_paths_are_rejected(self):
        self.context["managed_appliance"] = True
        plan = certificates.preview(self.manager, {"mode": "self_signed", "hostname": "controller.example"}, "super_admin")
        self.assertTrue(plan["summary"]["trust_change"])
        literal = self.reviewed_chain(plan)[0]
        self.assertTrue(certificates._signed_by(literal, literal))
        record = json.loads((self.manager.root / "certificate-plans" / (plan["id"] + ".json")).read_text())
        material = json.loads(self.manager.vault.get(record["material_ref"]))
        damaged = bytearray(literal.public_bytes(self.serialization.Encoding.DER))
        damaged[-1] ^= 1
        forged = self.x509.load_der_x509_certificate(bytes(damaged))
        with self.assertRaisesRegex(ValueError, "complete, verifiable issuer chain"):
            certificates.preview(self.manager, {"mode": "pem", "certificate_pem": self.pem(forged), "private_key_pem": material["private_key_pem"]}, "super_admin")
        for options in ({"root_path_length": 0}, {"intermediate_ca": False}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                leaf, issuer, root, key = self.corporate_chain(**options)
                certificates.preview(self.manager, self.imported_bundle("pem", [leaf, issuer, root], key), "super_admin")

    def test_standalone_unknown_issuer_leaf_behavior_is_unchanged(self):
        leaf, issuer, root, key = self.corporate_chain()
        for mode in ("pem", "pkcs12"):
            with self.subTest(mode=mode):
                plan = certificates.preview(self.manager, self.imported_bundle(mode, [leaf], key), "super_admin")
                self.assertEqual(len(self.reviewed_chain(plan)), 1)
                self.assertTrue(plan["summary"]["trust_change"])

    def test_status_none_demo_and_current_public_metadata(self):
        self.assertFalse(certificates.status(None)["configured"])
        result = certificates.status(self.manager)
        self.assertEqual(result["current"]["sans"], ["controller.example", "127.0.0.1"])
        self.assertEqual(result["current"]["fingerprint_sha256"], certificates._fp(self.current))
        self.assertNotIn(str(self.directory), json.dumps(result))
        self.manager.app.demo = True
        self.assertTrue(certificates.status(self.manager)["demo"])
        self.context["cert_path"] = None
        self.assertIsNone(certificates.status(self.manager)["current"])

    def test_pem_preview_is_encrypted_and_apply_only_queues_exact_private_material(self):
        key = self.rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf = self.leaf(key)
        plan = certificates.preview(self.manager, self.body(leaf, key), "super_admin")
        self.assertFalse(plan["summary"]["trust_change"])
        self.assertNotIn("private_key", json.dumps(plan))
        self.assertEqual(self.cert_path.read_text(), self.pem(self.current) + self.pem(self.ca))
        job = certificates.apply(self.manager, self.confirm(plan), "super_admin")
        private = self.manager._job(job["id"])["private"]
        material = json.loads(self.manager.vault.get(private["material_ref"]))
        self.assertEqual(private["expected_current_fingerprint"], certificates._fp(self.current))
        self.assertEqual(private["expected_fingerprint"], certificates._fp(leaf))
        self.assertEqual(material["certificate_pem"], self.pem(leaf) + self.pem(self.ca))
        self.assertEqual(job["operation"], "certificate")
        self.assertEqual(certificates.apply(self.manager, self.confirm(plan), "super_admin")["id"], job["id"])
        for path in self.manager.root.rglob("*.json"):
            self.assertNotIn(self.key_pem(key), path.read_text())
        self.assertNotIn(self.key_pem(key), json.dumps(self.store.all("audit")))

    def test_pkcs12_base64_and_binary_discard_password_and_reject_wrong_password(self):
        from cryptography.hazmat.primitives.serialization import pkcs12
        password = "p12-secret-do-not-persist"
        raw = pkcs12.serialize_key_and_certificates(b"server", self.key, self.current, [self.ca], self.serialization.BestAvailableEncryption(password.encode()))
        for field, value in (("pkcs12_base64", base64.b64encode(raw).decode()), ("pkcs12_bytes", raw)):
            with self.subTest(field=field):
                plan = certificates.preview(self.manager, {"source": "pkcs12", field: value, "password": password}, "super_admin")
                self.assertEqual(plan["summary"]["certificate"]["fingerprint_sha256"], certificates._fp(self.current))
        for path in self.manager.root.rglob("*.json"):
            self.assertNotIn(password, path.read_text())
        with self.assertRaises(ValueError) as error:
            certificates.preview(self.manager, {"mode": "pkcs12", "pkcs12_bytes": raw, "password": "wrong-sensitive-password"}, "super_admin")
        self.assertNotIn("wrong-sensitive-password", str(error.exception))

    def test_encrypted_pem_key_password_supported_but_never_stored(self):
        password = "encrypted-key-secret"
        plan = certificates.preview(self.manager, self.body(private_key_pem=self.key_pem(self.key, password.encode()), key_password=password), "super_admin")
        self.assertEqual(plan["summary"]["certificate"]["fingerprint_sha256"], certificates._fp(self.current))
        for path in self.manager.root.rglob("*.json"):
            self.assertNotIn(password, path.read_text())

    def test_generation_prefers_existing_issuer_and_preserves_dns_and_ip_sans(self):
        signer = types.SimpleNamespace(ca=self.ca_path, ca_key=self.ca_key_path)
        self.manager.app.signer = signer
        body = {"mode": "self_signed", "hostname": "new-controller.example", "sans": ["127.0.0.1", "2001:db8::7", "extra.example"], "days": 30}
        plan = certificates.preview(self.manager, body, "super_admin")
        self.assertEqual(plan["summary"]["source"], "existing_local_issuer")
        self.assertFalse(plan["summary"]["trust_change"])
        self.assertFalse(plan["summary"]["endpoint_issuer_changed"])
        self.assertTrue({"controller.example", "new-controller.example", "extra.example", "127.0.0.1", "2001:db8::7"} <= set(plan["summary"]["certificate"]["sans"]))
        private = json.loads((self.manager.root / "certificate-plans" / (plan["id"] + ".json")).read_text())
        material = json.loads(self.manager.vault.get(private["material_ref"]))
        self.assertNotIn(self.key_pem(self.ca_key), json.dumps(material))
        self.assertEqual(body["sans"], ["127.0.0.1", "2001:db8::7", "extra.example"])

    def test_literal_self_signed_requires_explicit_client_trust_phrase(self):
        plan = certificates.preview(self.manager, {"source": "self_signed", "hostname": "controller.example"}, "super_admin")
        self.assertEqual(plan["summary"]["source"], "literal_self_signed")
        self.assertTrue(plan["summary"]["trust_change"])
        self.assertIn("AND UPDATE CLIENT TRUST", plan["confirmation_phrase"])
        with self.assertRaises(WorkflowConflict):
            certificates.apply(self.manager, {**self.confirm(plan), "confirmation_phrase": plan["confirmation_phrase"].replace(" AND UPDATE CLIENT TRUST", "")}, "super_admin")

    def test_different_endpoint_issuer_is_not_assumed_to_preserve_current_web_trust(self):
        from cryptography.x509.oid import NameOID
        key = self.rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = self.x509.Name([self.x509.NameAttribute(NameOID.COMMON_NAME, "Different endpoint issuer")])
        ca = self.x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(self.x509.random_serial_number()).not_valid_before(now() - timedelta(days=1)).not_valid_after(now() + timedelta(days=90)).add_extension(self.x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, self.hashes.SHA256())
        self.manager.app.signer = types.SimpleNamespace(ca=self.write("other-ca.pem", self.pem(ca)), ca_key=self.write("other-ca-key.pem", self.key_pem(key)))
        plan = certificates.preview(self.manager, {"mode": "self_signed", "hostname": "controller.example"}, "super_admin")
        self.assertEqual(plan["summary"]["source"], "existing_local_issuer")
        self.assertTrue(plan["summary"]["trust_change"])
        self.assertIn("AND UPDATE CLIENT TRUST", plan["confirmation_phrase"])

    def test_mismatch_weak_key_wrong_san_ca_leaf_and_wrong_eku_are_rejected(self):
        other = self.rsa.generate_private_key(public_exponent=65537, key_size=2048)
        weak = self.rsa.generate_private_key(public_exponent=65537, key_size=1024)
        cases = [self.body(key=other), self.body(self.leaf(weak), weak), self.body(self.leaf(self.key, hostname="different.example")), self.body(self.leaf(self.key, ca=True)), self.body(self.leaf(self.key, client_only=True)), self.body(self.leaf(self.key, expired=True)), self.body(self.leaf(self.key, future=True))]
        for body in cases:
            with self.subTest(certificate=body["certificate_pem"][:40]), self.assertRaises(ValueError):
                certificates.preview(self.manager, body, "super_admin")

    def test_nist_ecdsa_certificate_is_supported(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        key = ec.generate_private_key(ec.SECP256R1())
        plan = certificates.preview(self.manager, self.body(self.leaf(key), key), "super_admin")
        self.assertIn("ECDSA", plan["summary"]["certificate"]["key_algorithm"])

    def test_changed_current_certificate_or_profile_invalidates_review(self):
        plan = certificates.preview(self.manager, self.body(), "super_admin")
        self.cert_path.write_text(self.pem(self.leaf(self.key)) + self.pem(self.ca))
        with self.assertRaises(WorkflowConflict):
            certificates.apply(self.manager, self.confirm(plan), "super_admin")
        plan = certificates.preview(self.manager, self.body(), "super_admin")
        with patch.object(self.manager, "active_profile", return_value={"deployment_id": "new-deployment", "active_revision": 2}):
            with self.assertRaises(WorkflowConflict):
                certificates.apply(self.manager, self.confirm(plan), "super_admin")

    def test_expired_review_wrong_confirmation_and_demo_activation_are_rejected(self):
        plan = certificates.preview(self.manager, self.body(), "super_admin")
        with patch("controller.certificates.now", return_value=now() + timedelta(minutes=11)):
            with self.assertRaises(WorkflowConflict):
                certificates.apply(self.manager, self.confirm(plan), "super_admin")
        self.manager.app.demo = True
        with self.assertRaises(ValueError):
            certificates.apply(self.manager, self.confirm(plan), "super_admin")
        with self.assertRaises(ValueError):
            certificates.apply(self.manager, {"preview_id": "../../vault/vault.key"}, "super_admin")

    def test_malformed_sans_chain_and_new_endpoint_ca_fields_are_rejected(self):
        for body in ({"mode": "self_signed", "hostname": "controller.example", "sans": "extra.example"}, {"mode": "self_signed", "hostname": "controller.example", "sans": ["0.0.0.0"]}, {"mode": "self_signed", "hostname": "controller.example", "days": 826}, {**self.body(), "endpoint_ca_key": "must-never-import"}):
            with self.subTest(body=list(body)), self.assertRaises(ValueError):
                certificates.preview(self.manager, body, "super_admin")
        self.manager.app.signer = types.SimpleNamespace(ca=self.ca_path, ca_key=self.key_path)
        with self.assertRaisesRegex(ValueError, "no new trust root"):
            certificates.preview(self.manager, {"mode": "self_signed", "hostname": "controller.example"}, "super_admin")


if __name__ == "__main__":
    unittest.main()
