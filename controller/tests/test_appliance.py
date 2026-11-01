import copy
from datetime import timedelta
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

from controller.appliance import Appliance, ManagerUnavailable, NodeClient, hash_password, verify_password, execute_job
from controller.firewall import WorkflowConflict
from controller.pki import Signer, init_ca
from controller.platform import PlatformManager
from controller.store import Store, now, stamp


class RecordingClient:
    """Only the service/storage actuator is faked; store and vault are real."""
    def __init__(self):
        self.requests = []
        self.result = {"status": "completed", "result": {"status": "completed"}}
        self.state = {"revision": 7, "data_root": "/srv/actual-persistent", "services": [{"id": "controller", "name": "Controller", "state": "running", "enabled": True, "private_password": "not-public"}], "routing": {"failover_state": "preferred", "pools": []}, "secret": "not-public"}

    def status(self):
        return copy.deepcopy(self.state)

    def submit(self, body):
        self.requests.append(copy.deepcopy(body))
        return {"id": body.get("request_id", "a" * 32), **copy.deepcopy(self.result)}

    def job(self, identifier):
        return {"id": identifier, **copy.deepcopy(self.result)}


class ApplianceFixture:
    cluster_password = "cluster-password-private-acceptance"
    replication_password = "replication-password-private-acceptance-1234"

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name)
        self.environment = patch.dict(os.environ, {"PRTHAK_APPLIANCE": "1", "PRTHAK_APPLIANCE_NODE_ID": "", "PRTHAK_APPLIANCE_NODE_IP": "", "PRTHAK_APPLIANCE_SITE": ""})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.pki = init_ca(self.directory / "issuer")
        self.api = self.make_api("node-1", "site-1")
        self.save(self.api)

    def make_api(self, identifier, site, demo=False):
        root = self.directory / identifier
        manager = PlatformManager(root)
        store = Store(root / "db")
        app = types.SimpleNamespace(store=store, demo=demo, signer=Signer(self.pki / "ca.pem", self.pki / "ca-key.pem"), controller_id=identifier, site=site,
                                    controller_certificate=self.pki / "controller.pem", controller_private_key=self.pki / "controller-key.pem", cluster=lambda: {"nodes": []})
        manager.attach(app)
        return Appliance(manager, client=RecordingClient())

    def save(self, api, **extra):
        node = api.app.controller_id.rsplit("-", 1)[-1]
        values = {"expected_revision": api._config()["revision"], "cluster_name": "Acceptance cluster", "site": api.app.site, "node_ip": "10.70.0." + node,
                  "controller_origin": "https://cluster.example", "cluster_password": self.cluster_password, "replication_password": self.replication_password,
                  "preferred_controller_url": "https://preferred.example:8787", "fallback_controller_url": "https://fallback.example:8787", "watchdog_approved": True}
        values.update(extra)
        return api.save(values, "super_admin")

    @staticmethod
    def confirmation(plan):
        return {"preview_id": plan["id"], **{key: plan[key] for key in ("digest", "confirmation_nonce", "confirmation_phrase")}}


@unittest.skipUnless(importlib.util.find_spec("cryptography"), "Appliance vault tests require controller requirements")
class ApplianceTests(ApplianceFixture, unittest.TestCase):
    def test_hash_and_replication_are_private_and_status_exposes_only_flags(self):
        config = self.api._config()
        self.assertNotEqual(config["password_hash"]["hash"], self.cluster_password)
        self.assertTrue(verify_password(self.cluster_password, config["password_hash"]))
        self.assertFalse(verify_password("wrong", config["password_hash"]))
        state = self.api.status()
        self.assertTrue(state["cluster"]["cluster_password_configured"])
        self.assertTrue(state["cluster"]["replication_password_configured"])
        self.assertTrue(state["cluster"]["replication_password_pending"])
        self.assertNotIn("password_hash", json.dumps(state))
        self.assertNotIn("not-public", json.dumps(state))
        for path in self.directory.rglob("*"):
            if path.is_file():
                content = path.read_bytes()
                self.assertNotIn(self.cluster_password.encode(), content, str(path))
                self.assertNotIn(self.replication_password.encode(), content, str(path))

    def test_blank_passwords_preserve_hash_and_private_credential_reference(self):
        old, local = self.api._config(), self.api._local()
        self.save(self.api, cluster_password="", replication_password="")
        self.assertEqual(self.api._config()["password_hash"], old["password_hash"])
        self.assertEqual(self.api._local()["pending_replication_ref"], local["pending_replication_ref"])
        self.assertEqual(self.api.manager.vault.get(local["pending_replication_ref"]), self.replication_password)

    def test_local_settings_and_actual_manager_mount_survive_manager_restart(self):
        other_manager = PlatformManager(self.api.manager.data_dir)
        other_manager.attach(self.api.app)
        restarted = Appliance(other_manager, client=self.api.client)
        state = restarted.status()
        self.assertEqual(state["identity"]["site"], "site-1")
        self.assertEqual(state["identity"]["ip"], "10.70.0.1")
        self.assertEqual(state["data_root"], "/srv/actual-persistent")
        self.assertEqual(state["routing"]["preferred_controller_url"], "https://preferred.example:8787")
        self.assertEqual(state["routing"]["fallback_controller_url"], "https://fallback.example:8787")
        self.assertTrue(state["watchdog_approved"])

    def test_stale_revision_invalid_ip_and_unsupported_settings_refuse_without_mutation(self):
        previous = self.api._config()
        for change in ({"expected_revision": 0}, {"node_ip": "0.0.0.0"}, {"node_ip": "127.0.0.1"}, {"data_root": "/etc"}, {"watchdog_approved": "yes"}):
            with self.subTest(change=change), self.assertRaises((ValueError, WorkflowConflict)):
                self.save(self.api, **change)
        self.assertEqual(self.api._config(), previous)

    def test_service_review_typed_confirmation_is_immutable_and_idempotent(self):
        plan = self.api.service_review({"service": "controller", "action": "restart"}, "super_admin")
        with self.assertRaises(WorkflowConflict):
            self.api.service_apply({**self.confirmation(plan), "confirmation_phrase": "restart"}, "super_admin")
        job = self.api.service_apply(self.confirmation(plan), "super_admin")
        self.assertEqual(self.api.service_apply(self.confirmation(plan), "super_admin")["id"], job["id"])
        request = json.loads(self.api.manager.vault.get(self.api.manager._job(job["id"])["private"]["request_ref"]))
        self.assertEqual((request["service"], request["action"]), ("controller", "restart"))
        self.assertEqual(self.api.client.requests, [])

    def test_membership_heartbeat_does_not_stale_review_but_relevant_config_does(self):
        plan = self.api.service_review({"service": "controller", "action": "restart"}, "super_admin")
        with self.api.app.store.meta() as db:
            config = self.api._config(db)
            config["members"][0]["last_seen"] = stamp()
            self.api.app.store._put(db, "maintenance_settings", config)
        self.api.service_apply(self.confirmation(plan), "super_admin")
        changed = self.api.service_review({"service": "controller", "action": "restart"}, "super_admin")
        self.save(self.api, cluster_password="", replication_password="")
        with self.assertRaises(WorkflowConflict):
            self.api.service_apply(self.confirmation(changed), "super_admin")

    def test_storage_review_requires_real_manager_review_and_preserves_typed_path(self):
        self.api.client.result = {"status": "completed", "result": {"review_id": "b" * 32, "confirmation_nonce": "manager-nonce-" + "x" * 24, "data_root": "/mnt/cluster-data", "source_preserved": True, "requires_stopped_services": True}}
        plan = self.api.storage_review({"data_root": "/mnt/cluster-data"}, "super_admin")
        self.assertEqual(plan["confirmation_phrase"], "MOVE STORAGE TO /mnt/cluster-data")
        job = self.api.storage_apply(self.confirmation(plan), "super_admin")
        self.assertEqual(self.api.storage_apply(self.confirmation(plan), "super_admin")["id"], job["id"])
        request = json.loads(self.api.manager.vault.get(self.api.manager._job(job["id"])["private"]["request_ref"]))
        self.assertEqual(request["review_id"], "b" * 32)
        self.assertEqual(request["confirmation_nonce"], "manager-nonce-" + "x" * 24)
        self.assertEqual(len(self.api.client.requests), 1)

    def test_storage_missing_review_credentials_and_blockers_never_offer_apply(self):
        self.api.client.result = {"status": "completed", "result": {}}
        with self.assertRaises(ManagerUnavailable):
            self.api.storage_review({"data_root": "/mnt/cluster-data"}, "super_admin")
        self.api.client.result = {"status": "completed", "result": {"review_id": "b" * 32, "confirmation_nonce": "manager-nonce-" + "x" * 24, "blockers": ["Target contains foreign files"]}}
        plan = self.api.storage_review({"data_root": "/mnt/cluster-data"}, "super_admin")
        self.assertFalse(plan["can_apply"])
        with self.assertRaises(WorkflowConflict):
            self.api.storage_apply(self.confirmation(plan), "super_admin")

    def test_demo_blocks_service_storage_and_join_actuation(self):
        self.api.app.demo = True
        for operation in (lambda: self.api.service_review({"service": "controller", "action": "restart"}, "super_admin"), lambda: self.api.storage_review({"data_root": "/mnt/cluster-data"}, "super_admin"), lambda: self.api.join_preview({"peer_url": "10.70.0.2", "cluster_password": self.cluster_password}, "super_admin")):
            with self.assertRaises(ValueError):
                operation()
        self.assertEqual(self.api.client.requests, [])

    def test_failed_actuator_is_not_reported_applied(self):
        plan = self.api.service_review({"service": "database", "action": "stop"}, "super_admin")
        queued = self.api.service_apply(self.confirmation(plan), "super_admin")
        self.api.client.result = {"status": "blocked", "error": "Quorum is unavailable"}
        with patch("controller.appliance.NodeClient", return_value=self.api.client):
            execute_job(self.api.manager, self.api.manager._job(queued["id"]))
        result = self.api.manager.job(queued["id"])
        self.assertEqual(result["status"], "blocked")
        self.assertNotEqual(result["phase"], "verified")

    def test_configure_waiting_for_voters_is_staged_and_not_runtime_verified(self):
        queued = self.api.manager._queue("appliance", {"request_ref": self.api.manager.vault.put(json.dumps({"action": "configure", "configuration": {}}))}, "super_admin")
        self.api.client.result = {"status": "completed", "result": {"status": "waiting_for_voters", "database_active": False}}
        with patch("controller.appliance.NodeClient", return_value=self.api.client):
            execute_job(self.api.manager, self.api.manager._job(queued["id"]))
        result = self.api.manager.job(queued["id"])
        self.assertNotEqual(result["status"], "applied")
        self.assertNotEqual(result["phase"], "verified")


if __name__ == "__main__":
    unittest.main()
