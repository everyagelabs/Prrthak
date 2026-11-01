"""Isolated loopback HTTPS for compact queues and exact, bounded review detail."""
import http.client
import json
from pathlib import Path
import ssl
import tempfile
import unittest
from datetime import timedelta
from unittest.mock import patch

from controller import approval_views
from controller.app import App
from controller.pki import init_ca
from controller.store import Store, now, stamp
from test_integration import running


class LearningApprovalViewHTTPS(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="prthak-approval-https-")
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.store = Store(root / "state")
        self.store.report("host-one", {"hostname":"host-one","ips":["192.0.2.1"],"listeners":[]})
        self.plan = {"id": "review-one", "session_id": "session-one", "name": "Exact Billing review", "status": "reviewed", "created_at": stamp(), "expires_at": stamp(now() + timedelta(minutes=10)), "confirmation_count": 0, "confirmation_nonce": "fixture-maker-nonce", "confirmation_phrase": "ALLOW EXACT REVIEW", "digest": "f" * 64, "targets": [{"server_id": "host-one", "services": [{"port": 443, "protocol": "tcp", "sources": ["192.0.2.44/32"]}]}]}
        self.initial = {**self.plan, "id": "initial-one", "status": "draft", "scope": {"targets": [{"server_id": "host-one", "ports": [{"port": 443, "protocol": "tcp"}]}]}}
        with self.store.meta() as db:
            self.store._put(db, "learning_policy_previews", self.plan)
            self.store._put(db, "sessions", {"id": "session-one", "status": "active", "server_ids":["host-one"],"starts_at":stamp(),"expires_at":stamp(now()+timedelta(minutes=10)),"selection_mode":"discovered","server_ports":{"host-one":[{"port":443,"protocol":"tcp"}]},"discovery_results":{"host-one":{"status":"ready","listeners":[{"process":"PRIVATE_SESSION_MATRIX"*100}]}}, "initial_approval_plan": self.initial})
        pki = init_ca(root)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(pki / "controller.pem", pki / "controller-key.pem")
        self.tls = ssl.create_default_context(cafile=str(pki / "ca.pem"))
        app = App(self.store, tokens={"read_only": "isolated-read-only-fixture"})
        self.app=app
        app.start_jobs = lambda: None
        context = running(app, tls)
        self.port = context.__enter__()
        self.addCleanup(context.__exit__, None, None, None)

    def request(self, path, method="GET", authenticated=True, body=None, parse_json=True, extra_headers=None):
        headers = {"Authorization": "Bearer isolated-read-only-fixture"} if authenticated else {}
        headers.update(extra_headers or {})
        if body is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(body)
        connection = http.client.HTTPSConnection("localhost", self.port, context=self.tls, timeout=10)
        try:
            connection.request(method, "/api/v1/" + path, body=body, headers=headers)
            response = connection.getresponse()
            raw=response.read()
            return response.status, (json.loads(raw) if raw else None) if parse_json else raw, dict(response.getheaders())
        finally:
            connection.close()

    def test_read_only_can_navigate_summaries_then_read_exact_detail_but_cannot_grant(self):
        self.assertEqual(self.request("learning-policies/approvals", authenticated=False)[0], 401)
        with patch.object(self.store, "_all", side_effect=AssertionError("Queue must not materialize global canonical rows")):
            code, queue, headers = self.request("learning-policies/approvals?limit=1&session_id=session-one")
        self.assertEqual((code, queue["total"], len(queue["items"]), queue["has_more"]), (200, 2, 1, True))
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertTrue(queue["items"][0]["summary_only"])
        for field in ("targets", "scope", "confirmation_nonce", "confirmation_phrase"):
            self.assertNotIn(field, queue["items"][0])
        code, detail, _ = self.request("learning-policies/approvals/review-one")
        self.assertEqual((code, detail), (200, self.plan))
        code, detail, _ = self.request("learning-policies/approvals/initial-one")
        self.assertEqual((code, detail), (200, {**self.initial, "kind": "initial_learning"}))
        self.assertEqual(self.request("learning/session-one/recommendations/apply", method="POST", body={"preview_id": "review-one", "confirm": True})[0], 403)

    def test_oversized_exact_review_is_small_json_error_before_canonical_decode(self):
        with patch.object(approval_views, "MAX_REVIEW_BYTES", 128):
            code, body, headers = self.request("learning-policies/approvals/review-one")
            self.assertEqual(code, 400)
            self.assertIn("8 MiB detail limit", body["error"])
            self.assertIn("application/json", headers["Content-Type"])
            self.assertNotIn("192.0.2.44", json.dumps(body))
            self.assertEqual(self.request("learning-policies/approvals/initial-one")[0], 400)
        self.assertEqual(self.request("learning-policies/approvals/review-one")[0], 200)
        self.assertEqual(self.request("learning-policies/approvals/unknown")[0], 404)

    def test_every_public_session_path_avoids_canonical_collection_and_agent_assignment(self):
        original_all,original_get=self.store._all,self.store._get
        def bounded_all(db,table):
            if table in ("sessions","learning_policy_previews"):
                raise AssertionError("Public session views must not materialize canonical history")
            return original_all(db,table)
        def bounded_get(db,table,identifier):
            if table=="sessions":raise AssertionError("Public evidence must use the minimal session header")
            return original_get(db,table,identifier)
        with patch.object(self.store,"_all",side_effect=bounded_all),patch.object(self.store,"_get",side_effect=bounded_get),patch.object(self.store,"assignment",side_effect=AssertionError("Public server detail must not evaluate agent assignments")):
            code,page,_=self.request("learning?limit=1")
            self.assertEqual((code,page["total"],page["active_total"]),(200,1,1))
            self.assertTrue(page["items"][0]["summary_only"])
            self.assertEqual(page["items"][0]["server_ids"],["host-one"])
            for path in ("overview","servers/host-one","learning/session-one/recommendations"):
                code,body,_=self.request(path)
                self.assertEqual(code,200,(path,body))
                self.assertNotIn("PRIVATE_SESSION_MATRIX",json.dumps(body))
                self.assertNotIn("fixture-maker-nonce",json.dumps(body))
            code,hosts,_=self.request("learning/session-one/hosts?limit=1")
            self.assertEqual((code,hosts["total"],hosts["items"][0]["ports"]),(200,1,[{"port":443,"protocol":"tcp"}]))
            self.assertNotIn("listeners",json.dumps(hosts))
            code,body,_=self.request("learning/session-one/export.csv",parse_json=False)
            self.assertEqual(code,200)
            self.assertTrue(body.startswith(b'\xef\xbb\xbf'))
            self.assertNotIn(b"PRIVATE_SESSION_MATRIX",body)
