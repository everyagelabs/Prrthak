from email.message import Message
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from controller.app import handler_for
from controller.http_limits import RequestLimits
from controller.store import Store, stamp


class BulkAlertAcknowledgementHTTPTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = Store(self.temporary.name)
        self.principal = {"actor": "local:admin", "role": "admin", "auth_type": "session"}

        def csrf(headers, principal):
            if headers.get("X-CSRF-Token") != "fixture-csrf":
                raise PermissionError("A valid CSRF token is required")

        self.app = SimpleNamespace(store=self.store, demo=False, limits=RequestLimits(),
                                   principal=lambda headers: self.principal,
                                   auth=SimpleNamespace(require_csrf=csrf), recovering=lambda: False)
        with self.store.meta() as db:
            self.store._put(db, "alerts", {"id": "system-alert", "status": "open", "created_at": stamp(), "message": "System alert"})

    def request(self, body, *, csrf=True, method="POST", origin="https://controller.test"):
        class TLS:
            pass

        handler = object.__new__(handler_for(self.app))
        handler.command, handler.path = method, "/api/v1/alerts/ack"
        handler.connection, handler.client_address = TLS(), ("127.0.0.1", 0)
        handler.headers = Message()
        handler.headers["Host"], handler.headers["Origin"] = "controller.test", origin
        if csrf:
            handler.headers["X-CSRF-Token"] = "fixture-csrf"
        handler.body = lambda: body
        replies = []
        handler.response = lambda status, value=None, headers=None: replies.append((status, value))
        with patch("controller.app.ssl.SSLSocket", TLS):
            handler.dispatch()
        return replies[0]

    def test_normal_admin_csrf_and_origin_boundaries_and_read_only_rejection(self):
        self.assertEqual(self.request({"scope": "all"}, csrf=False)[0], 403)
        self.assertEqual(self.request({"scope": "all"}, origin="https://other.test")[0], 403)
        self.principal["role"] = "read_only"
        self.assertEqual(self.request({"scope": "all"})[0], 403)
        self.principal = None
        self.assertEqual(self.request({"scope": "all"})[0], 401)
        self.assertEqual(self.store.get("alerts", "system-alert")["status"], "open")
        self.principal = {"actor": "local:admin", "role": "admin", "auth_type": "session"}
        status, result = self.request({"scope": "all"})
        self.assertEqual((status, result["acknowledged_count"]), (200, 1))
        self.principal["role"] = "super_admin"
        self.assertEqual(self.request({"scope": "all"})[1]["acknowledged_count"], 0)
        self.assertEqual(self.store.get("alerts", "system-alert")["acknowledged_by"], "local:admin")

    def test_filtered_request_is_validated_and_cannot_accidentally_ack_orphan_system_alert(self):
        self.assertEqual(self.request({"scope": "filtered"})[0], 400)
        self.assertEqual(self.request({"scope": "filtered", "query": {"ports": ["22/invalid"]}})[0], 400)
        status, result = self.request({"scope": "filtered", "query": {"server_ids": []}})
        self.assertEqual((status, result["acknowledged_count"]), (200, 0))
        self.assertEqual(self.store.get("alerts", "system-alert")["status"], "open")


if __name__ == "__main__":
    unittest.main()
