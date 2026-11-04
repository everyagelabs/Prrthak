import base64
from datetime import timedelta
import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

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
        self.ca = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(self.ca_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now() - timedelta(days=1)).not_valid_after(now() + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(self.ca_usage(), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(self.ca_key.public_key()), False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_key.public_key()), False)
            .sign(self.ca_key, hashes.SHA256()))
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

    def ca_usage(self):
        return self.x509.KeyUsage(digital_signature=False, content_commitment=False,
            key_encipherment=False, data_encipherment=False, key_agreement=False,
            key_cert_sign=True, crl_sign=True, encipher_only=None, decipher_only=None)

    def leaf(self, key, hostname="controller.example", ca=False, client_only=False, expired=False, future=False):
        import ipaddress
        from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
        at = now()
        return (self.x509.CertificateBuilder()
            .subject_name(self.x509.Name([self.x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
            .issuer_name(self.ca.subject).public_key(key.public_key()).serial_number(self.x509.random_serial_number())
            .not_valid_before(at + timedelta(days=1) if future else at - timedelta(days=2))
            .not_valid_after(at - timedelta(days=1) if expired else at + timedelta(days=30))
            .add_extension(self.x509.BasicConstraints(ca=ca, path_length=None), critical=True)
            .add_extension(self.x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH if client_only else ExtendedKeyUsageOID.SERVER_AUTH]), False)
            .add_extension(self.x509.SubjectAlternativeName([self.x509.DNSName(hostname), self.x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
            .add_extension(self.x509.KeyUsage(digital_signature=True, content_commitment=False,
                key_encipherment=True, data_encipherment=False, key_agreement=False,
                key_cert_sign=False, crl_sign=False, encipher_only=None, decipher_only=None), True)
            .add_extension(self.x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
            .add_extension(self.x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_key.public_key()), False)
            .sign(self.ca_key, self.hashes.SHA256()))

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
                .add_extension(self.ca_usage(), True)
                .add_extension(self.x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
                .add_extension(self.x509.AuthorityKeyIdentifier.from_issuer_public_key(signing_key.public_key()), False)
                .sign(signing_key, self.hashes.SHA256()))

        root = ca(root_name, root_key, root_name, root_key, True, root_path_length)
        issuer = ca(issuer_name, issuer_key, root_name, root_key, intermediate_ca, 0)
        with patch.object(self, "ca", issuer), patch.object(self, "ca_key", issuer_key):
            leaf = self.leaf(leaf_key)
        self.corporate_keys = (leaf_key, issuer_key, root_key)
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

    def reissue(self, certificate, signing_key, *, omit=(), replace=(), extra=()):
        builder = (self.x509.CertificateBuilder().subject_name(certificate.subject)
            .issuer_name(certificate.issuer).public_key(certificate.public_key())
            .serial_number(certificate.serial_number).not_valid_before(certificate.not_valid_before_utc)
            .not_valid_after(certificate.not_valid_after_utc))
        replacements = {value.oid: (value, critical) for value, critical in replace}
        for extension in certificate.extensions:
            if extension.oid not in omit and extension.oid not in replacements:
                builder = builder.add_extension(extension.value, extension.critical)
        for value, critical in list(replacements.values()) + list(extra):
            builder = builder.add_extension(value, critical)
        return builder.sign(signing_key, self.hashes.SHA256())

    def assert_invalid_before_persistence(self, body, reason=None):
        with patch("controller.platform.Vault.put") as vault, \
                patch("controller.certificates.atomic_private_json") as write, \
                patch.object(self.manager, "_queue") as queue, \
                patch.object(self.manager, "_audit") as audit:
            with self.assertRaises(ValueError) as failure:
                certificates.preview(self.manager, body, "super_admin")
            if reason:
                self.assertIn(reason, str(failure.exception))
            self.assertNotIn("PRIVATE KEY", str(failure.exception))
            for callback in (vault, write, queue, audit):
                callback.assert_not_called()

    def test_missing_leaf_authority_identifier_is_rejected_for_pem_and_pkcs12_before_persistence(self):
        leaf = self.reissue(self.current, self.ca_key, omit=(self.x509.ExtensionOID.AUTHORITY_KEY_IDENTIFIER,))
        for mode in ("pem", "pkcs12"):
            with self.subTest(mode=mode):
                self.assert_invalid_before_persistence(self.imported_bundle(mode, [leaf, self.ca], self.key), "Missing Authority Key Identifier")

    def test_ca_strict_usage_identifiers_and_critical_constraints_are_required(self):
        leaf, issuer, root, key = self.corporate_chain()
        _, issuer_key, root_key = self.corporate_keys
        oid = self.x509.ExtensionOID
        invalid = [
            ("root missing usage", [leaf, issuer, self.reissue(root, root_key, omit=(oid.KEY_USAGE,))]),
            ("intermediate missing usage", [leaf, self.reissue(issuer, root_key, omit=(oid.KEY_USAGE,)), root]),
            ("root missing SKI", [leaf, issuer, self.reissue(root, root_key, omit=(oid.SUBJECT_KEY_IDENTIFIER,))]),
            ("intermediate missing SKI", [leaf, self.reissue(issuer, root_key, omit=(oid.SUBJECT_KEY_IDENTIFIER,)), root]),
            ("intermediate missing AKI", [leaf, self.reissue(issuer, root_key, omit=(oid.AUTHORITY_KEY_IDENTIFIER,)), root]),
            ("noncritical CA constraints", [leaf, self.reissue(issuer, root_key,
                replace=((self.x509.BasicConstraints(ca=True, path_length=0), False),)), root]),
        ]
        for label, chain in invalid:
            for mode in ("pem", "pkcs12"):
                with self.subTest(case=label, mode=mode):
                    self.assert_invalid_before_persistence(self.imported_bundle(mode, chain, key), "Strict TLS")

    def test_unknown_critical_extensions_cannot_be_hidden_by_candidate_leaf_trust(self):
        leaf, issuer, root, key = self.corporate_chain()
        _, issuer_key, root_key = self.corporate_keys
        extension = self.x509.UnrecognizedExtension(self.x509.ObjectIdentifier("1.3.6.1.4.1.55555.9"), b"\x05\x00")
        for label, chain in (
                ("leaf", [self.reissue(leaf, issuer_key, extra=((extension, True),)), issuer, root]),
                ("intermediate", [leaf, self.reissue(issuer, root_key, extra=((extension, True),)), root]),
                ("root", [leaf, issuer, self.reissue(root, root_key, extra=((extension, True),))])):
            with self.subTest(certificate=label):
                self.assert_invalid_before_persistence(self.imported_bundle("pem", chain, key), "unhandled critical extension")

    def test_name_constraints_and_ca_server_purpose_are_verified_without_network(self):
        from cryptography.x509.oid import ExtendedKeyUsageOID
        leaf, issuer, root, key = self.corporate_chain()
        _, _, root_key = self.corporate_keys
        for label, restriction in (
                ("name constraints", self.x509.NameConstraints(permitted_subtrees=[self.x509.DNSName("only.example.org")], excluded_subtrees=None)),
                ("issuer purpose", self.x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]))):
            restricted = self.reissue(issuer, root_key, extra=((restriction, True),))
            with self.subTest(case=label):
                self.assert_invalid_before_persistence(self.imported_bundle("pem", [leaf, restricted, root], key), "Strict TLS")

    def test_authority_identifier_mismatch_cannot_pass_on_signature_alone(self):
        leaf = self.reissue(self.current, self.ca_key, replace=((
            self.x509.AuthorityKeyIdentifier(key_identifier=b"\x00" * 20,
                authority_cert_issuer=None, authority_cert_serial_number=None), False),))
        self.assertTrue(certificates._signed_by(leaf, self.ca))
        self.assert_invalid_before_persistence(self.body(leaf), "Strict TLS")

    def test_legitimate_constrained_intermediate_and_noncritical_extension_are_allowed(self):
        leaf, issuer, root, key = self.corporate_chain()
        _, issuer_key, root_key = self.corporate_keys
        constraints = self.x509.NameConstraints(permitted_subtrees=[self.x509.DNSName(".example")], excluded_subtrees=None)
        issuer = self.reissue(issuer, root_key, extra=((constraints, True),))
        extension = self.x509.UnrecognizedExtension(self.x509.ObjectIdentifier("1.3.6.1.4.1.55555.9"), b"\x05\x00")
        leaf = self.reissue(leaf, issuer_key, extra=((extension, False),))
        for mode in ("pem", "pkcs12"):
            with self.subTest(mode=mode):
                plan = certificates.preview(self.manager, self.imported_bundle(mode, [leaf, issuer, root], key), "super_admin")
                self.assertEqual(plan["summary"]["certificate"]["fingerprint_sha256"], certificates._fp(leaf))

    def test_path_length_rejected_for_standalone_and_managed_imports(self):
        leaf, issuer, root, key = self.corporate_chain(root_path_length=0)
        for managed in (False, True):
            self.context["managed_appliance"] = managed
            for mode in ("pem", "pkcs12"):
                with self.subTest(managed=managed, mode=mode):
                    self.assert_invalid_before_persistence(self.imported_bundle(mode, [leaf, issuer, root], key))

    def test_hostname_check_uses_san_for_dns_and_ip_and_rejects_cn_fallback(self):
        for hostname in ("controller.example", "127.0.0.1"):
            with self.subTest(hostname=hostname):
                plan = certificates.preview(self.manager, self.body(hostname=hostname), "super_admin")
                self.assertEqual(plan["summary"]["hostname"], hostname)
        leaf = self.reissue(self.current, self.ca_key, omit=(self.x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME,))
        self.assert_invalid_before_persistence(self.body(leaf))

    def test_standalone_partial_issuer_import_retains_explicit_trust_warning(self):
        leaf, issuer, _, key = self.corporate_chain()
        for mode in ("pem", "pkcs12"):
            with self.subTest(mode=mode):
                plan = certificates.preview(self.manager, self.imported_bundle(mode, [leaf, issuer], key), "super_admin")
                self.assertTrue(plan["summary"]["trust_change"])
                self.assertEqual(len(self.reviewed_chain(plan)), 2)

    def test_apply_revalidates_material_without_queueing_invalid_chain(self):
        plan = certificates.preview(self.manager, self.body(), "super_admin")
        path = self.manager.root / "certificate-plans" / (plan["id"] + ".json")
        stored = json.loads(path.read_text())
        material = json.loads(self.manager.vault.get(stored["material_ref"]))
        leaf = self.reissue(self.current, self.ca_key, omit=(self.x509.ExtensionOID.AUTHORITY_KEY_IDENTIFIER,))
        material["certificate_pem"] = self.pem(leaf) + self.pem(self.ca)
        stored["material_ref"] = self.manager.vault.put(json.dumps(material))
        path.write_text(json.dumps(stored))
        with patch.object(self.manager, "_queue") as queue:
            with self.assertRaisesRegex(ValueError, "no longer valid"):
                certificates.apply(self.manager, self.confirm(plan), "super_admin")
            queue.assert_not_called()

    def test_preupgrade_queued_invalid_certificate_is_rechecked_before_runtime_mutation(self):
        from controller.platform_runtime import RuntimeSupervisor
        leaf = self.reissue(self.current, self.ca_key, omit=(self.x509.ExtensionOID.AUTHORITY_KEY_IDENTIFIER,))
        # This job models material accepted before strict preflight existed.
        material = {"hostname": "controller.example", "certificate_pem": self.pem(leaf) + self.pem(self.ca), "private_key_pem": self.key_pem(self.key)}
        manager = types.SimpleNamespace(active_profile=lambda: None,
            certificate_context=lambda: dict(self.context), launch_tls=Mock(),
            _private_text=Mock(), runtime_job_update=Mock())
        stop = Mock()
        supervisor = RuntimeSupervisor(self.directory, manager, [], stop=stop)
        child = object()
        supervisor.child = child
        with self.assertRaisesRegex(ValueError, "Missing Authority Key Identifier"):
            supervisor.rotate_certificate({"id": "old-queued-job", "private": {"expected_fingerprint": certificates._fp(leaf)}, "material": material})
        self.assertIs(supervisor.child, child)
        for callback in (manager.launch_tls, manager._private_text, manager.runtime_job_update, stop):
            callback.assert_not_called()
        self.assertFalse((self.manager.root / "tls-revisions").exists())

    def test_queued_revalidation_checks_exact_reviewed_leaf(self):
        material, _ = certificates._material(self.body(), self.context)
        with self.assertRaisesRegex(ValueError, "reviewed HTTPS identity"):
            certificates.revalidate_activation(material, "0" * 64, self.context)

    def test_temporary_identity_is_private_and_deleted_before_handshake_on_success_and_failure(self):
        from controller import certificate_validation
        original = certificate_validation.ssl.SSLContext.load_cert_chain
        checked = []

        def load(context, path):
            path = Path(path)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
            checked.append(path)
            return original(context, path)

        handshake = certificate_validation._handshake

        def verify(*arguments):
            self.assertTrue(checked)
            self.assertFalse(checked[-1].exists())
            self.assertFalse(checked[-1].parent.exists())
            return handshake(*arguments)

        with patch.object(certificate_validation.ssl.SSLContext, "load_cert_chain", load), \
                patch.object(certificate_validation, "_handshake", verify), \
                patch("socket.socket", side_effect=AssertionError("Offline validation opened a socket")), \
                patch("subprocess.Popen", side_effect=AssertionError("Offline validation spawned a process")):
            certificates.preview(self.manager, self.body(), "super_admin")
            leaf = self.reissue(self.current, self.ca_key, omit=(self.x509.ExtensionOID.AUTHORITY_KEY_IDENTIFIER,))
            self.assert_invalid_before_persistence(self.body(leaf), "Strict TLS")
        self.assertEqual(len(checked), 2)
        self.assertTrue(all(not path.exists() and not path.parent.exists() for path in checked))

    def test_temporary_identity_is_removed_when_openssl_rejects_loading_it(self):
        import ssl
        from controller import certificate_validation
        paths = []

        def reject(context, path):
            paths.append(Path(path))
            raise ssl.SSLError("private fixture diagnostic must not escape")

        with patch.object(certificate_validation.ssl.SSLContext, "load_cert_chain", reject):
            self.assert_invalid_before_persistence(self.body(), "Strict TLS")
        self.assertTrue(paths)
        self.assertTrue(all(not path.exists() and not path.parent.exists() for path in paths))

    def test_in_memory_handshake_has_a_fixed_iteration_bound(self):
        import ssl
        from controller import certificate_validation
        stalled = Mock()
        stalled.do_handshake.side_effect = ssl.SSLWantReadError()
        context = Mock()
        context.wrap_bio.return_value = stalled
        with self.assertRaisesRegex(ValueError, "did not complete"):
            certificate_validation._handshake(context, context, "controller.example")
        self.assertEqual(stalled.do_handshake.call_count, 64)

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
        self.assertEqual(result["current"]["common_name"], "controller.example")
        self.assertEqual(result["current"]["issuer_common_name"], "Certificate test issuer")
        self.assertEqual(result["generation_issuer"], "literal_self_signed")
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
        body = {
            "mode": "self_signed",
            "hostname": "new-controller.example",
            "sans": ["127.0.0.1", "2001:db8::7", "extra.example"],
            "days": 30,
            "subject_common_name": " Regional controller ",
            "subject_organization": "Infrastructure",
            "subject_organizational_unit": "Sécurité",
        }
        plan = certificates.preview(self.manager, body, "super_admin")
        self.assertEqual(plan["summary"]["source"], "existing_local_issuer")
        self.assertEqual(certificates.status(self.manager)["generation_issuer"], "existing_local_issuer")
        self.assertFalse(plan["summary"]["trust_change"])
        self.assertFalse(plan["summary"]["endpoint_issuer_changed"])
        certificate = plan["summary"]["certificate"]
        self.assertEqual(certificate["common_name"], "Regional controller")
        self.assertEqual(certificate["organization"], "Infrastructure")
        self.assertEqual(certificate["organizational_unit"], "Sécurité")
        self.assertEqual(certificate["issuer_common_name"], "Certificate test issuer")
        self.assertEqual(set(certificate["sans"]), {"controller.example", "new-controller.example", "extra.example", "127.0.0.1", "2001:db8::7"})
        private = json.loads((self.manager.root / "certificate-plans" / (plan["id"] + ".json")).read_text())
        material = json.loads(self.manager.vault.get(private["material_ref"]))
        self.assertNotIn(self.key_pem(self.ca_key), json.dumps(material))
        self.assertEqual(body["sans"], ["127.0.0.1", "2001:db8::7", "extra.example"])

    def test_literal_self_signed_requires_explicit_client_trust_phrase(self):
        plan = certificates.preview(self.manager, {"source": "self_signed", "hostname": "controller.example", "subject_common_name": "Lab controller"}, "super_admin")
        self.assertEqual(plan["summary"]["source"], "literal_self_signed")
        certificate = plan["summary"]["certificate"]
        self.assertEqual(certificate["common_name"], "Lab controller")
        self.assertEqual(certificate["issuer"], certificate["subject"])
        self.assertTrue(plan["summary"]["trust_change"])
        self.assertIn("AND UPDATE CLIENT TRUST", plan["confirmation_phrase"])
        with self.assertRaises(WorkflowConflict):
            certificates.apply(self.manager, {**self.confirm(plan), "confirmation_phrase": plan["confirmation_phrase"].replace(" AND UPDATE CLIENT TRUST", "")}, "super_admin")

    def test_different_endpoint_issuer_is_not_assumed_to_preserve_current_web_trust(self):
        from cryptography.x509.oid import NameOID
        key = self.rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = self.x509.Name([self.x509.NameAttribute(NameOID.COMMON_NAME, "Different endpoint issuer")])
        ca = (self.x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(self.x509.random_serial_number()).not_valid_before(now() - timedelta(days=1))
            .not_valid_after(now() + timedelta(days=90)).add_extension(self.x509.BasicConstraints(ca=True, path_length=None), True)
            .add_extension(self.ca_usage(), True).add_extension(self.x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
            .add_extension(self.x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), False)
            .sign(key, self.hashes.SHA256()))
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

    def test_generated_subject_rejects_control_characters_overlong_unicode_and_import_overrides(self):
        generation = {"mode": "self_signed", "hostname": "controller.example"}
        for value in ("bad\nname", "é" * 33, 123):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "Subject common name must be printable text"):
                certificates.preview(self.manager, {**generation, "subject_common_name": value}, "super_admin")
        with self.assertRaisesRegex(ValueError, "already contain their signed subject"):
            certificates.preview(self.manager, self.body(subject_organization="Unsigned edit"), "super_admin")
        with self.assertRaisesRegex(ValueError, "Unsupported certificate field"):
            certificates.preview(self.manager, {**generation, "issuer_common_name": "Impersonated CA"}, "super_admin")


if __name__ == "__main__":
    unittest.main()
