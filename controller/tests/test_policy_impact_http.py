"""Actual dispatch RBAC separates existing read previews from proposed intent."""
from email.message import Message
import tempfile
import unittest
from unittest.mock import patch

from controller.app import App, handler_for
from controller.store import Store


class PolicyImpactHTTPTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="prthak-impact-http-")
        self.addCleanup(directory.cleanup)
        self.store = Store(directory.name)
        self.store.report("target", {"hostname": "billing", "ips": ["192.0.2.10"], "listeners": []})
        self.policy = self.store.save_policy({"name": "Billing", "mode": "monitor", "services": [{"port": 443, "sources": ["198.51.100.1"]}]}, "fixture")
        self.app = App(self.store, tokens={"read_only": "reader", "admin": "operator"})

    def request(self, path, body=None, token="reader", method="POST"):
        handler = object.__new__(handler_for(self.app))
        handler.command, handler.path, handler.connection = method, "/api/v1" + path, object()
        handler.client_address, handler.headers = ("127.0.0.1", 12345), Message()
        if token:
            handler.headers["Authorization"] = "Bearer " + token
        handler.body = lambda: {} if body is None else body
        response = {}
        handler.response = lambda status, value=None, headers=None: response.update(status=status, value=value)
        handler.dispatch()
        return response

    def test_read_only_existing_preview_is_real_read_and_cannot_smuggle_proposed_intent(self):
        with patch.object(self.store, "save_policy", side_effect=AssertionError("published")), patch.object(self.store, "compile_all", side_effect=AssertionError("mutated")):
            response = self.request("/policies/" + self.policy["id"] + "/impact")
            self.assertEqual(response["status"], 200)
            self.assertTrue(response["value"]["read_only"])
            self.assertFalse(response["value"]["policy"]["proposed"])
            self.assertEqual(self.request("/policies/" + self.policy["id"] + "/impact", {"policy": self.policy})["status"], 400)
            self.assertEqual(self.request("/policies/impact", {"policy": self.policy})["status"], 403)

    def test_admin_can_preview_unsaved_or_exact_replacement_without_saving(self):
        value = {"name": "New draft", "mode": "enforce", "services": [{"port": 8443, "sources": ["2001:db8::/64"]}]}
        with patch.object(self.store, "save_policy", side_effect=AssertionError("published")):
            response = self.request("/policies/impact", {"policy": value}, token="operator")
            self.assertEqual(response["status"], 200)
            self.assertTrue(response["value"]["policy"]["proposed"])
            self.assertIsNone(response["value"]["policy"]["id"])
            response = self.request("/policies/impact", {"policy": value, "policy_id": self.policy["id"], "expected_revision": self.policy["revision"]}, token="operator")
            self.assertEqual(response["status"], 200)
            self.assertEqual(response["value"]["summary"]["effective_changed_servers"], 1)
        self.assertEqual(self.store.get("policies", self.policy["id"])["services"][0]["port"], 443)

    def test_anonymous_unknown_stale_and_invalid_scopes_fail_closed(self):
        path = "/policies/" + self.policy["id"] + "/impact"
        self.assertEqual(self.request(path, token=None)["status"], 401)
        self.assertEqual(self.request("/policies/missing/impact")["status"], 404)
        self.assertEqual(self.request(path, {"limit": 5000})["status"], 400)
        self.assertEqual(self.request("/policies/impact", {"policy": self.policy, "policy_id": self.policy["id"], "expected_revision": 999}, token="operator")["status"], 409)
        self.assertEqual(self.request(path, method="DELETE")["status"], 404)
