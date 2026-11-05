import base64
import copy
from datetime import timedelta
from email.message import Message
import hashlib
from io import BytesIO
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from controller.app import handler_for
from controller.appliance import ManagerUnavailable
from controller.firewall import WorkflowConflict
from controller.http_limits import RequestLimits
from controller.offline_updates import CAPABILITY, CHUNK_BYTES, CONFIRMATION, OfflineUpdates
from controller.platform import PlatformManager
from controller.store import Store, now


class NodeManager:
    def __init__(self):
        self.jobs = {}
        self.requests = []
        self.capable = True
        self.lose_submission = False

    def status(self):
        return {"capabilities": [CAPABILITY] if self.capable else []}

    def submit(self, request):
        self.requests.append(copy.deepcopy(request))
        if self.lose_submission:
            raise ManagerUnavailable("Host submission outcome is unknown")
        return self.jobs.setdefault(request["request_id"], {"status": "queued"})

    def job(self, identifier):
        return self.jobs[identifier]


def release(archive, rhel_major="9"):
    name = f"prthak-controller-0.19.0-offline-rhel{rhel_major}-x86_64.tar.gz"
    manifest = {"filename": name, "bytes": len(archive), "sha256": hashlib.sha256(archive).hexdigest()}
    payload = json.dumps({"domain": "prthak-package-manifest-v1", "manifest": manifest}).encode()
    return {"name": name, "size": len(archive), "signature": {"algorithm": "Ed25519", "key_id": "d" * 32,
            "payload": base64.b64encode(payload).decode(), "signature": base64.b64encode(b"a" * 64).decode()}}


class OfflineUpdatesTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        manager = PlatformManager(Path(directory.name) / "data")
        self.client = NodeManager()
        self.principal = {"actor": "local:administrator", "role": "super_admin", "auth_type": "session"}

        def require_csrf(headers, principal):
            if headers.get("X-CSRF-Token") != "fixture-csrf":
                raise PermissionError("A valid session CSRF token is required")

        self.app = SimpleNamespace(platform=manager, demo=False, store=Store(manager.data_dir), limits=RequestLimits(),
                                   auth=SimpleNamespace(_require_super=lambda principal, db: None, require_csrf=require_csrf),
                                   principal=lambda headers: self.principal, recovering=lambda: False)
        manager.attach(self.app)
        self.api = OfflineUpdates(manager, self.principal, self.client)
        environment = patch.dict(os.environ, {"PRTHAK_APPLIANCE": "1"})
        environment.start()
        self.addCleanup(environment.stop)

    def test_exact_offset_retry_restart_and_rollback_receipt(self):
        metadata = release(b"archive contents")
        uploading = self.api.start(metadata)
        identifier = uploading["id"]
        self.assertEqual(self.api.chunk(identifier, 0, b"archive ")["offset"], 8)
        self.assertEqual(self.api.start(metadata)["offset"], 8)
        with self.assertRaises(WorkflowConflict):
            self.api.chunk(identifier, 0, b"different")
        with self.assertRaises(WorkflowConflict):
            self.api.review(identifier, {})
        self.api.chunk(identifier, 8, b"contents")
        self.assertEqual(self.api.chunk(identifier, 8, b"contents")["offset"], len(b"archive contents"))
        self.assertEqual(self.api.review(identifier, {})["status"], "reviewing")
        request = self.client.requests[-1]
        self.assertEqual(request["upload_id"], identifier)
        self.assertEqual(request["signature"], metadata["signature"])
        with self.assertRaises(WorkflowConflict):
            self.api.cancel(identifier)
        self.client.jobs[request["request_id"]] = {"status": "completed", "result": {
            "review_id": "e" * 32, "confirmation_nonce": "n" * 32, "version": "0.19.0",
            "sha256": hashlib.sha256(b"archive contents").hexdigest(), "expires_at": (now() + timedelta(minutes=5)).timestamp(),
        }}
        ready = self.api.status()["update"]
        self.assertEqual(ready["status"], "ready")
        self.assertEqual(ready["confirmation_phrase"], CONFIRMATION)
        self.assertTrue(ready["review"]["expires_at"].endswith("Z"))
        self.assertNotIn("confirmation_nonce", json.dumps(ready))
        with self.assertRaises(ValueError):
            self.api.apply(identifier, {"confirmation": "OK"})

        self.client.lose_submission = True
        with self.assertRaises(ManagerUnavailable):
            self.api.apply(identifier, {"confirmation": CONFIRMATION})
        self.assertFalse(self.api._archive(identifier).exists())
        retry = self.api.status()["update"]
        self.assertTrue(retry["can_retry"])
        self.assertEqual(retry["confirmation_phrase"], CONFIRMATION)
        self.client.lose_submission = False
        self.api.apply(identifier, {"confirmation": CONFIRMATION})
        self.assertEqual(self.client.requests[-1], self.client.requests[-2])
        job = {"status": "error", "result": {
            "phase": "rolled_back", "verified": False, "rolled_back": True, "failure_stage": "candidate_health",
        }}
        self.client.jobs[self.client.requests[-1]["request_id"]] = job
        restarted = OfflineUpdates(self.app.platform, self.principal, self.client)
        receipt = restarted.status()["update"]
        self.assertEqual(receipt["status"], "rolled_back")
        self.assertIn("candidate HTTPS", receipt["failure_step"])
        job["result"].update(phase="rollback_failed", rolled_back=False, recovery_stage="verify_previous")
        receipt = restarted.status()["update"]
        self.assertEqual(receipt["status"], "failed")
        self.assertIn("restored controller", receipt["recovery_step"])
        job["result"].update(failure_stage="private Docker output", recovery_stage=["unrecognized value"])
        receipt = restarted.status()["update"]
        self.assertNotIn("failure_step", receipt)
        self.assertNotIn("recovery_step", receipt)
        self.assertTrue(restarted.cancel(identifier)["cancelled"])
        self.assertIsNone(restarted.status()["update"])
        self.assertFalse(restarted._archive(identifier).exists())

    def test_rhel10_upload_selects_the_exact_host_major_before_staging(self):
        self.client.status = lambda: {"capabilities": [CAPABILITY], "offline_update_rhel_major": "10"}
        with self.assertRaisesRegex(ValueError, "RHEL major version"):
            self.api.start(release(b"rhel9"))
        self.assertFalse(self.api.directory.exists())
        metadata = release(b"rhel10", "10")
        uploaded = self.api.start(metadata)
        self.assertEqual(uploaded["name"], metadata["name"])
        self.assertEqual(self.api.chunk(uploaded["id"], 0, b"rhel10")["offset"], 6)

    def test_legacy_rhel9_manager_refuses_a_rhel10_update_before_staging(self):
        with self.assertRaisesRegex(ValueError, "RHEL major version"):
            self.api.start(release(b"rhel10", "10"))
        self.assertFalse(self.api.directory.exists())

    def request(self, method, path, body=b"", *, csrf=True, origin="https://controller.test"):
        class TLS:
            _prthak_body_read = staticmethod(lambda: None)

        handler = object.__new__(handler_for(self.app))
        handler.command, handler.path = method, "/api/v1/platform/updates" + path
        handler.connection, handler.client_address = TLS(), ("127.0.0.1", 0)
        handler.headers = Message()
        handler.headers["Content-Length"] = str(len(body))
        handler.headers["Content-Type"] = "application/octet-stream" if method == "PUT" else "application/json"
        handler.headers["Host"], handler.headers["Origin"] = "controller.test", origin
        if csrf:
            handler.headers["X-CSRF-Token"] = "fixture-csrf"
        handler.rfile = BytesIO(body)
        replies = []
        handler.response = lambda status, value, headers=None: replies.append((status, value))
        with patch("controller.app.ssl.SSLSocket", TLS), patch("controller.offline_updates.NodeClient", return_value=self.client):
            handler.dispatch()
        return replies[0]

    def test_http_super_admin_and_csrf_apply_to_bounded_raw_chunk(self):
        body = json.dumps(release(b"tar")).encode()
        self.client.capable = False
        self.assertEqual(self.request("GET", "")[1]["available"], False)
        self.assertEqual(self.request("POST", "/upload", body)[0], 409)
        self.client.capable = True
        self.assertEqual(self.request("POST", "/upload", body, csrf=False)[0], 403)
        self.assertEqual(self.request("POST", "/upload", body, origin="https://other.test")[0], 403)
        status, record = self.request("POST", "/upload", body)
        self.assertEqual(status, 201)
        path = "/" + record["id"] + "/chunks/0"
        self.principal["role"] = "admin"
        self.assertEqual(self.request("PUT", path, b"tar")[0], 403)
        self.principal["role"] = "super_admin"
        self.assertEqual(self.request("PUT", path, b"tar", csrf=False)[0], 403)
        self.assertEqual(self.request("PUT", path, b"x" * (CHUNK_BYTES + 1))[0], 400)
        self.assertEqual(self.request("GET", "")[1]["update"]["offset"], 0)
        self.assertEqual(self.request("PUT", path, b"tar")[1]["offset"], 3)
        self.principal["auth_type"] = "token"
        self.assertEqual(self.request("GET", "")[0], 403)

    def test_pending_host_update_fences_api_before_authentication_or_upload(self):
        pending = self.app.platform.data_dir / "update-pending"
        pending.touch()
        with patch("controller.app.OFFLINE_UPDATE_WRITE_FENCE", pending):
            for method, path in (("GET", ""), ("POST", "/upload")):
                status, response = self.request(method, path, csrf=False)
                self.assertEqual(status, 503)
                self.assertIn("being verified", response["error"])
        self.assertEqual(self.client.requests, [])

    def test_inaccessible_legacy_fence_keeps_api_closed_during_manager_repair(self):
        class LegacyFence:
            def lstat(self):
                raise PermissionError('mode 0700 root directory')

        with patch("controller.app.OFFLINE_UPDATE_WRITE_FENCE", LegacyFence()):
            status, response = self.request("GET", "", csrf=False)
        self.assertEqual(status, 503)
        self.assertIn("being verified", response["error"])
        self.assertEqual(self.client.requests, [])
