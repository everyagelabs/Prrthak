import copy
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

from controller.platform_runtime import RuntimeSupervisor, RuntimeSafetyError
from controller.pki import init_ca


class RouterCertificateRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        pki = init_ca(self.root / "pki")
        self.chain = (pki / "controller.pem").read_text()
        self.key = (pki / "controller-key.pem").read_text()
        self.manager = types.SimpleNamespace(root=self.root / "state")
        self.runtime = RuntimeSupervisor(self.root, self.manager, [])

    def result(self, **changes):
        value = {"phase": "web_tls_verified", "verified": True, "router_ready": True, "fingerprint_sha256": "f" * 64, "server_name": "localhost"}
        value.update(changes)
        return {"id": "b" * 32, "status": "completed", "result": value}

    def test_exact_router_proof_and_durable_replay_strip_all_private_material(self):
        from unittest.mock import Mock
        client = Mock()
        client.status.return_value = {"revision": 7}
        client.submit.return_value = self.result()
        with patch.dict(os.environ, {"PRTHAK_APPLIANCE": "1"}), patch("controller.appliance.NodeClient", return_value=client):
            self.runtime._router_certificate("a" * 32, "activate", self.chain + self.key, "localhost", "f" * 64)
            first = copy.deepcopy(client.submit.call_args.args[0])
            client.status.return_value = {"revision": 12}
            self.runtime._router_certificate("a" * 32, "activate", self.chain, "localhost", "f" * 64)
        self.assertEqual(first, client.submit.call_args.args[0])
        self.assertEqual(first["expected_revision"], 7)
        self.assertNotIn("PRIVATE KEY", json.dumps(first))
        self.assertEqual(set(first), {"request_id", "action", "expected_revision", "certificate_chain", "server_name"})
        self.assertEqual(client.status.call_count, 1)

    def test_generic_or_wrong_identity_acknowledgements_cannot_commit(self):
        from unittest.mock import Mock
        client = Mock()
        client.status.return_value = {"revision": 7}
        variants = [{"status": "completed", "result": {"verified": True}}, self.result(fingerprint_sha256="0" * 64), self.result(server_name="elsewhere.example"), self.result(router_ready=False), {"status": "error", "result": self.result()["result"]}]
        with patch.dict(os.environ, {"PRTHAK_APPLIANCE": "1"}), patch("controller.appliance.NodeClient", return_value=client):
            for value in variants:
                with self.subTest(value=value), self.assertRaises(RuntimeSafetyError):
                    client.submit.return_value = value
                    self.runtime._router_certificate("a" * 32, "activate", self.chain, "localhost", "f" * 64)

    def test_standalone_does_not_require_installed_host_manager(self):
        with patch.dict(os.environ, {"PRTHAK_APPLIANCE": "0"}), patch("controller.appliance.NodeClient") as client:
            self.runtime._router_certificate("a" * 32, "activate", self.chain, "localhost", "f" * 64)
        client.assert_not_called()

    def test_recovery_gets_fresh_proof_instead_of_reusing_completed_receipt(self):
        from unittest.mock import Mock
        client = Mock()
        client.status.side_effect = [{"revision": 7}, {"revision": 8}]
        client.submit.return_value = self.result()
        client.job.return_value = self.result()
        with patch.dict(os.environ, {"PRTHAK_APPLIANCE": "1"}), patch("controller.appliance.NodeClient", return_value=client):
            self.runtime._router_certificate("a" * 32, "activate", self.chain, "localhost", "f" * 64)
            first = client.submit.call_args.args[0]
            self.runtime._router_certificate("a" * 32, "activate", self.chain, "localhost", "f" * 64, fresh=True)
            second = client.submit.call_args.args[0]
            client.job.return_value = {"id": second["request_id"], "status": "running"}
            self.runtime._router_certificate("a" * 32, "activate", self.chain, "localhost", "f" * 64, fresh=True)
            self.assertEqual(client.submit.call_args.args[0], second)
        self.assertNotEqual(first["request_id"], second["request_id"])
        self.assertEqual(second["expected_revision"], 8)
