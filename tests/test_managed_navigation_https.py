"""Small private HTTPS acceptance for managed navigation and exact authority."""
from datetime import timedelta
import hashlib
import json
import unittest
from unittest.mock import patch

from controller import managed_views
from controller.auth import EntraAuth, EntraConfig, SESSION_COOKIE
from controller.store import now, stamp
from controller.tests import test_managed_views as unit_fixture
import test_learning_approval_views_https as fixture


class ManagedNavigationHTTPS(unittest.TestCase):
    request = fixture.LearningApprovalViewHTTPS.request

    def setUp(self):
        fixture.LearningApprovalViewHTTPS.setUp(self)
        unit_fixture.ManagedPublicViewsTests.seed(self, count=6, sources=10)

    def test_read_only_pages_are_bounded_and_exact_selected_records_keep_all_sources(self):
        self.assertEqual(self.request("policy-rollouts", authenticated=False)[0], 401)
        with patch.object(self.store, "managed_rollouts", side_effect=AssertionError("Navigation cannot invoke canonical fleet rollout collection")), patch.object(self.store, "policy_history", side_effect=AssertionError("Navigation cannot invoke canonical bundle history collection")), patch.object(self.store, "policy_revisions", side_effect=AssertionError("Navigation cannot invoke canonical revision collection")):
            for path, field in (("policies/billing-policy/revisions", "revision"), ("servers/host-1/policy-history", "version")):
                code, page, headers = self.request(path + "?limit=1&offset=1")
                self.assertEqual((code, page["total"], len(page["items"]), page["items"][0][field]), (200, 6, 1, 5))
                self.assertEqual(headers["Cache-Control"], "no-store")
                self.assertNotIn("10.0.0.0/32", json.dumps(page))
                self.assertTrue(page["items"][0]["summary_only"])
            code, page, _ = self.request("policy-rollouts/query", "POST", body={"server_ids": ["host-1"], "limit": 1, "offset": 1})
            self.assertEqual((code, page["total"], page["items"][0]["id"]), (200, 3, "rollout-4"))
            self.assertNotIn("bindings", page["items"][0])
            self.assertNotIn("preview", page["items"][0])
            self.assertEqual(self.request("policy-rollouts/query", "POST", body={"server_ids": []})[1]["total"], 0)
            self.assertEqual(len(self.request("policies/billing-policy/revisions/3")[1]["services"][0]["sources"]), 10)
            self.assertEqual(len(self.request("servers/host-1/policy-history/3")[1]["services"][0]["sources"]), 10)
            self.assertEqual(len(self.request("policy-rollouts/rollout-2")[1]["preview"]["targets"][0]["bundle"]["services"][0]["sources"]), 10)

    def test_read_only_post_query_keeps_cookie_csrf_and_same_origin_checks(self):
        origin = "https://localhost:" + str(self.port)
        config = EntraConfig("11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222", origin + "/api/v1/auth/callback", "private-managed-test-secret")
        self.app.auth = EntraAuth(self.store, config, provider=object())
        raw = "c" * 48
        with self.store.meta() as db:
            self.store._put(db, "auth_users", {"id": "reader", "tenant_id": config.tenant_id, "object_id": "33333333-3333-3333-3333-333333333333", "role": "read_only", "enabled": True})
            self.store._put(db, "auth_sessions", {"id": hashlib.sha256(raw.encode()).hexdigest(), "user_id": "reader", "expires_at": stamp(now() + timedelta(hours=1)), "config": config.fingerprint})
        cookie = {"Cookie": SESSION_COOKIE + "=" + raw}
        csrf = self.request("auth", authenticated=False, extra_headers=cookie)[1]["csrf_token"]
        valid = {**cookie, "X-CSRF-Token": csrf, "Origin": origin}
        body = {"server_ids": ["host-1"], "limit": 1}
        self.assertEqual(self.request("policy-rollouts/query", "POST", False, body, extra_headers=cookie)[0], 403)
        self.assertEqual(self.request("policy-rollouts/query", "POST", False, body, extra_headers={**valid, "Origin": "https://wrong.invalid"})[0], 403)
        code, page, _ = self.request("policy-rollouts/query", "POST", False, body, extra_headers=valid)
        self.assertEqual((code, page["total"], len(page["items"])), (200, 3, 1))
        self.assertEqual(self.request("policy-rollouts/rollout-2/confirm", "POST", False, {}, extra_headers=valid)[0], 403)

    def test_oversized_exact_record_is_rejected_without_source_disclosure_or_loss_of_navigation(self):
        with patch.object(managed_views, "MAX_DETAIL_BYTES", 128):
            for path in ("policies/billing-policy/revisions/3", "servers/host-1/policy-history/3", "policy-rollouts/rollout-2"):
                code, value, _ = self.request(path)
                self.assertEqual(code, 400, (path, value))
                self.assertNotIn("10.0.0.0/32", json.dumps(value))
            self.assertEqual(self.request("policy-rollouts?limit=1")[0], 200)
        self.assertEqual(self.request("policy-rollouts/unknown")[0], 404)
