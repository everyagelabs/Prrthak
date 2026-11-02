"""The read-only notification surface cannot publish policy or recheck traffic."""
from email.message import Message
import tempfile
import unittest
from unittest.mock import patch

from controller.app import App, handler_for
from controller.store import Store


class PolicyDeploymentHTTPTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.store = Store(directory.name)
        self.store.report("target", {"hostname": "billing-01", "ips": ["192.0.2.10"], "listeners": [], "firewalld_state": "running"})
        self.app = App(self.store, tokens={"read_only": "reader", "admin": "operator"})
        self.policy = self.store.save_policy({"name": "Billing", "mode": "monitor", "services": [{"port": 443, "sources": ["198.51.100.1"]}]}, "fixture")
        self.run = self.policy["deployment"]

    def request(self, path, method="GET", body=None, token="reader"):
        handler = object.__new__(handler_for(self.app))
        handler.command, handler.path, handler.connection = method, "/api/v1" + path, object()
        handler.client_address, handler.headers = ("127.0.0.1", 12345), Message()
        if token:
            handler.headers["Authorization"] = "Bearer " + token
        handler.body = lambda: body
        response = {}
        handler.response = lambda status, value=None, headers=None: response.update(status=status, value=value)
        handler.dispatch()
        return response

    def test_read_only_reads_exact_counts_bounded_targets_and_no_private_lease(self):
        run_id = self.run["id"]
        paths = ("/policy-deployments?limit=10&offset=0", f"/policy-deployments/{run_id}",
                 f"/policy-deployments/{run_id}/targets?limit=50&offset=0", f"/policy-deployments/{run_id}/targets/target")
        for path in paths:
            with self.subTest(path=path):
                response = self.request(path)
                self.assertEqual(response["status"], 200)
                self.assertNotIn("approval_proof", str(response["value"]))
                self.assertNotIn("'lease':", str(response["value"]))
        self.assertEqual(self.request(paths[0])["value"]["total"], 1)
        self.assertEqual(self.request(paths[2])["value"]["total"], 1)
        self.assertEqual(self.request(paths[3])["value"]["apply_status"], "unavailable")

    def test_missing_auth_bad_pagination_and_unknown_identity_fail_closed(self):
        self.assertEqual(self.request("/policy-deployments", token=None)["status"], 401)
        self.assertEqual(self.request("/policy-deployments?limit=99999")["status"], 400)
        self.assertEqual(self.request(f"/policy-deployments/{self.run['id']}/targets?limit=99999")["status"], 400)
        self.assertEqual(self.request("/policy-deployments/missing")["status"], 404)
        self.assertEqual(self.request(f"/policy-deployments/{self.run['id']}/targets/other")["status"], 404)

    def test_observe_again_requires_admin_and_cannot_carry_policy_changes(self):
        path = f"/policy-deployments/{self.run['id']}/targets/target/recheck"
        with patch("controller.policy_deployments.recheck", return_value={"id": "fresh-observation"}) as recheck:
            self.assertEqual(self.request(path, "POST", {})["status"], 403)
            recheck.assert_not_called()
            self.assertEqual(self.request(path, "POST", {"sources": ["0.0.0.0/0"]}, "operator")["status"], 400)
            recheck.assert_not_called()
            response = self.request(path, "POST", {}, "operator")
            self.assertEqual((response["status"], response["value"]["deployment"]["id"]), (201, "fresh-observation"))
            self.assertEqual(recheck.call_args.args[:3], (self.store, self.run["id"], "target"))

    def test_policy_save_response_contains_tracker_but_persisted_intent_does_not(self):
        self.store.lab_approvals = True  # Explicit isolated HTTP fixture, no live policy authority.
        response = self.request("/policies", "POST", {"name": "Other", "mode": "monitor", "services": [{"port": 8443}]}, "operator")
        self.assertEqual(response["status"], 201)
        self.assertEqual(response["value"]["deployment"]["target_count"], 1)
        saved = self.store.get("policies", response["value"]["id"])
        self.assertNotIn("deployment", saved)
