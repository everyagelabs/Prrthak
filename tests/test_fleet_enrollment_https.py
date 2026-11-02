"""One fleet setup, independent endpoint identities and current revocation.

Uses private loopback HTTPS/mTLS and isolated native-agent state directories.
No native distribution installation, service activation or firewall writes.
"""
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from controller.app import App
from controller.pki import Signer, init_ca
from controller.store import Store
from test_integration import request, running


@unittest.skipUnless(os.environ.get("SEG_AGENT_BINARY"), "Set SEG_AGENT_BINARY for native fleet enrollment")
class FleetEnrollmentHTTPS(unittest.TestCase):
    def test_one_setup_enrolls_twenty_independent_native_agents_and_revoke_preserves_mtls(self):
        binary = str(Path(os.environ["SEG_AGENT_BINARY"]).resolve(strict=True))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            pki = init_ca(root / "pki")
            store = Store(root / "controller")
            app = App(store, signer=Signer(pki / "ca.pem", pki / "ca-key.pem"),
                      controller_certificate=pki / "controller.pem",
                      tokens={"admin": "fixture-admin", "read_only": "fixture-read"})
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.load_cert_chain(pki / "controller.pem", pki / "controller-key.pem")
            tls.load_verify_locations(pki / "ca.pem")
            tls.verify_mode = ssl.CERT_OPTIONAL
            client_tls = ssl.create_default_context(cafile=str(pki / "ca.pem"))
            with running(app, tls) as port:
                origin = f"https://localhost:{port}"
                admin = {"Authorization": "Bearer fixture-admin", "Origin": origin}
                body = {"name": "Twenty isolated native endpoints", "validity_hours": 24,
                        "family": "rhel", "architecture": "amd64", "controller_url": origin,
                        "interval_seconds": 30, "discovery_interval_seconds": 900}
                path = "/api/v1/agent-installation/fleet-profiles"
                self.assertEqual(request(port, "POST", path, body,
                    {"Authorization": "Bearer fixture-read", "Origin": origin}, client_tls)[0], 403)
                self.assertEqual(request(port, "POST", path, body,
                    {**admin, "Origin": "https://untrusted.example"}, client_tls)[0], 403)
                status, created, headers = request(port, "POST", path, body, admin, client_tls)
                self.assertEqual(status, 201, created)
                self.assertEqual(headers["Cache-Control"], "no-store")
                kit = created["kit"]
                profile_id = created["profile"]["id"]
                self.assertEqual(kit["schema_version"], 2)
                self.assertEqual(kit["enrollment_profile_id"], profile_id)
                self.assertFalse(kit.get("expected_hostname"))
                self.assertNotIn("PRIVATE KEY", json.dumps(kit))
                source = root / "same-fleet-setup.json"
                source.write_text(json.dumps(kit))
                source.chmod(0o600)
                source_digest = hashlib.sha256(source.read_bytes()).hexdigest()
                environment = dict(os.environ)
                environment.pop("SEG_ENROLLMENT_TOKEN", None)
                environment.pop("SEG_ENROLLMENT_TOKEN_FILE", None)

                def prepare(index):
                    directory = root / f"endpoint-{index}"
                    directory.mkdir(mode=0o700)
                    prepared = directory / "prepared"
                    prepared.mkdir(mode=0o700)
                    result = subprocess.run([binary, "--prepare-setup", str(source), "--setup-output", str(prepared)],
                        env=environment, capture_output=True, text=True, timeout=20)
                    self.assertNotIn(kit["enrollment_token"], result.stdout + result.stderr)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    config = json.loads((prepared / "agent.json").read_text())
                    self.assertFalse(config["enforce"])
                    self.assertFalse(config["learning_auto_allow"])
                    state = directory / "state"
                    # Relocate only fixture paths: the host installer uses the canonical paths.
                    config.update(state_dir=str(state), ca_cert=str(prepared / "controller-ca.crt"),
                        certificate=str(state / "agent.crt"), private_key=str(state / "agent.key"),
                        enrollment_token_file=str(prepared / "enrollment-token"))
                    if config.get("endpoint_ca_cert"):
                        config["endpoint_ca_cert"] = str(prepared / "endpoint-ca.crt")
                    target = directory / "agent.json"
                    target.write_text(json.dumps(config))
                    target.chmod(0o600)
                    return target, state

                def sync(endpoint):
                    result = subprocess.run([binary, "--config", str(endpoint[0]), "--once"],
                        env=environment, capture_output=True, text=True, timeout=45)
                    self.assertNotIn(kit["enrollment_token"], result.stdout + result.stderr)
                    self.assertEqual(result.returncode, 0, result.stderr)

                endpoints = [prepare(index) for index in range(20)]
                with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                    list(pool.map(sync, endpoints))
                server_ids, public_keys = set(), set()
                for _, state in endpoints:
                    cert = x509.load_pem_x509_certificate((state / "agent.crt").read_bytes())
                    key = serialization.load_pem_private_key((state / "agent.key").read_bytes(), password=None)
                    public = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
                    self.assertEqual(public, cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
                    public_keys.add(hashlib.sha256(public).hexdigest())
                    server_ids.add(cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value)
                    self.assertEqual((state / "agent.key").stat().st_mode & 0o777, 0o600)
                self.assertEqual(len(public_keys), 20)
                self.assertEqual(len(server_ids), 20)
                self.assertEqual({server["id"] for server in store.servers()}, server_ids)
                self.assertTrue(all(server["apply_status"] == "preview" for server in store.servers()))
                self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), source_digest)

                # Re-running the same binaries preserves their local identities.
                for endpoint in endpoints[:2]:
                    sync(endpoint)
                self.assertEqual({server["id"] for server in store.servers()}, server_ids)
                status, listing, _ = request(port, "GET", path, headers=admin, context=client_tls)
                self.assertEqual(status, 200, listing)
                self.assertNotIn(kit["enrollment_token"], json.dumps(listing))
                self.assertNotIn(kit["enrollment_token"], json.dumps(store.all("audit") + store.all("tokens")))
                status, revoked, _ = request(port, "POST", path + "/" + profile_id + "/revoke", {}, admin, client_tls)
                self.assertEqual(status, 200, revoked)

                newcomer = prepare(21)
                refused = subprocess.run([binary, "--config", str(newcomer[0]), "--once"],
                    env=environment, capture_output=True, text=True, timeout=30)
                self.assertNotEqual(refused.returncode, 0)
                self.assertNotIn(kit["enrollment_token"], refused.stdout + refused.stderr)
                self.assertFalse((newcomer[1] / "agent.crt").exists())
                # Profile revocation blocks new enrollment, not enrolled mTLS identities.
                sync(endpoints[0])
                self.assertEqual({server["id"] for server in store.servers()}, server_ids)


if __name__ == "__main__":
    unittest.main()
