"""Real loopback HTTPS acceptance for the explicit whole-host deny push."""
import copy
import unittest

from controller import host_default_deny as deny
from controller.store import digest, stamp
from test_integration import stored_entra_admin
import test_learning_approval_views_https as fixture


class HostDefaultDenyHTTPS(unittest.TestCase):
    request = fixture.LearningApprovalViewHTTPS.request

    def setUp(self):
        fixture.LearningApprovalViewHTTPS.setUp(self)
        self.origin = "https://localhost:" + str(self.port)
        self.admin = stored_entra_admin(self.app, self.origin)
        self.principal = self.app.auth.authenticate(self.admin)
        protected = {"management_sources": ["10.90.0.0/24"], "ssh_ports": [2022],
                     "controller_url": self.origin, "management_probe_url": self.origin + "/api/v1/agent/enforcement/check",
                     "zone": "public", "host_default_deny_context_digest": "c" * 64,
                     "host_default_deny_control_profile": deny.PROFILE}
        settings = {"controller_url": self.origin, "control_url": "", "discovery_url": "",
                    "enforce": True, "allow_firewall_changes": False, "learning_auto_allow": False,
                    "unexpected_port_monitor_enabled": False, "allow_host_default_deny": True,
                    "management_sources": protected["management_sources"], "protected_ssh_ports": [2022], "zone": "public"}
        self.store.report("target", {"hostname": "target", "ips": ["10.70.0.1"], "firewalld_state": "running",
            "listeners": [{"port": 2022, "protocol": "tcp", "process": "sshd"}],
            "configuration_state": {**settings, "digest": "d" * 64},
            "capabilities": ["signed_assignments_v1", deny.CAPABILITY],
            "protection": {**protected, "digest": digest(protected), "ready": True, "blockers": [],
                           "host_default_deny_ready": True, "host_default_deny_blockers": []}})
        code, self.policy, _ = self.call("policies", "POST", {"name": "Approved HTTPS application", "selector": {},
                "mode": "enforce", "services": [{"port": 8443, "sources": ["10.50.0.0/24"]}]})
        self.assertEqual(code, 201, self.policy)

    def call(self, path, method="GET", body=None, headers=None):
        return self.request(path, method, False, body, extra_headers=self.admin if headers is None else headers)

    def preview(self, action="enable"):
        code, plan, _ = self.call("host-default-deny/preview", "POST", {"action": action, "server_ids": ["target"]})
        self.assertEqual(code, 201, plan)
        self.assertTrue(plan["can_apply"], plan["blockers"])
        return plan

    @staticmethod
    def body(plan):
        return {"digest": plan["digest"], "expected_revision": plan["revision"],
                "confirmation_nonce": plan["confirmation_nonce"], "acknowledge_downtime": True}

    def push(self, action="enable"):
        plan = self.preview(action)
        code, result, _ = self.call("host-default-deny/" + plan["id"] + "/confirm", "POST", self.body(plan))
        self.assertEqual(code, 200, result)
        return result

    def receipt(self):
        policy = self.store.assignment("target")[0]
        server = self.store.get("servers", "target")
        self.store.report("target", {"hostname": "target", "ips": ["10.70.0.1"], "listeners": [],
            "capabilities": server["capabilities"],
            "applied_version": policy["version"], "apply_status": "synced",
            "managed_enforcement": {"status": "enforced", "version": policy["version"], "digest": policy["digest"],
                "approval_id": policy["enforcement"]["approval_id"], "last_good_version": 0,
                "last_good_digest": "", "updated_at": stamp()}})

    def test_missing_false_string_or_numeric_ack_cannot_publish_or_reuse_review(self):
        before = self.store.assignment("target")[0]
        plan = self.preview()
        self.assertEqual(self.store.assignment("target")[0], before)
        path = "host-default-deny/" + plan["id"] + "/confirm"
        for value in (False, "true", 1, None):
            with self.subTest(value=value):
                self.assertEqual(self.call(path, "POST", {**self.body(plan), "acknowledge_downtime": value})[0], 400)
        missing = self.body(plan); missing.pop("acknowledge_downtime")
        self.assertEqual(self.call(path, "POST", missing)[0], 400)
        self.assertEqual(self.store.assignment("target")[0], before)
        self.assertEqual(self.call(path, "POST", self.body(plan))[0], 200)
        assigned = self.store.assignment("target")[0]
        self.assertTrue(assigned["host_default_deny"])
        self.assertTrue(assigned["enforcement"]["host_default_deny_ack"])
        self.assertEqual(assigned["enforcement"]["approval_proof"]["scope"]["kind"], deny.KIND)
        code, duplicate, _ = self.call(path, "POST", self.body(plan))
        self.assertEqual(code, 200)
        self.assertTrue(duplicate["duplicate"])
        self.assertEqual(self.store.assignment("target")[0], assigned)

    def test_auth_role_csrf_and_zero_match_status_query_are_enforced_over_tls(self):
        self.assertEqual(self.call("host-default-deny", headers={})[0], 401)
        cookie = {"Cookie": self.admin["Cookie"]}
        scope = {"action": "enable", "server_ids": ["target"]}
        self.assertEqual(self.call("host-default-deny/preview", "POST", scope, cookie)[0], 403)
        self.assertEqual(self.call("host-default-deny/preview", "POST", scope, {**self.admin, "Origin": "https://wrong.invalid"})[0], 403)
        user_id = self.principal["user"]["id"]
        with self.store.meta() as db:
            user = self.store._get(db, "auth_users", user_id); user["role"] = "read_only"; self.store._put(db, "auth_users", user)
        self.assertEqual(self.call("host-default-deny/preview", "POST", scope)[0], 403)
        code, page, headers = self.call("host-default-deny/query", "POST", {"server_ids": [], "limit": 20, "offset": 0})
        self.assertEqual((code, page["total"], page["items"]), (200, 0, []))
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_changed_allowlist_invalidates_preview_and_does_not_silently_authorize_deny(self):
        plan = self.preview()
        policy = copy.deepcopy(self.policy); policy["services"] = [{"port": 9443, "sources": ["10.51.0.0/24"]}]
        self.assertEqual(self.call("policies/" + policy["id"], "PUT", policy)[0], 200)
        self.assertEqual(self.call("host-default-deny/" + plan["id"] + "/confirm", "POST", self.body(plan))[0], 409)
        self.assertFalse(self.store.assignment("target")[0].get("host_default_deny", False))
        self.push(); self.receipt()
        changed = self.store.get("policies", policy["id"]); changed["services"] = [{"port": 10443, "sources": ["10.52.0.0/24"]}]
        self.assertEqual(self.call("policies/" + changed["id"], "PUT", changed)[0], 200)
        self.assertFalse(self.store.assignment("target")[0]["enforcement"]["authorized"])
        code, page, _ = self.call("host-default-deny/query", "POST", {"server_ids": ["target"]})
        self.assertEqual(code, 200)
        self.assertEqual(page["items"][0]["status"], "review_required")
        disable = self.preview("disable")
        self.assertEqual([row["port"] for row in disable["preview"]["targets"][0]["services"]], [9443])
        code, _, _ = self.call("host-default-deny/" + disable["id"] + "/confirm", "POST", self.body(disable))
        self.assertEqual(code, 200)
        removal = self.store.assignment("target")[0]
        self.assertFalse(removal.get("host_default_deny", False))
        self.assertEqual(removal["enforcement"]["intent"], "remove_host_default_deny")
        self.assertEqual([row["port"] for row in removal["services"]], [9443])


if __name__ == "__main__":
    unittest.main()
