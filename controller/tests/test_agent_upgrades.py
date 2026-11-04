from contextlib import contextmanager
from datetime import timedelta
from io import BytesIO
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

from controller import agent_upgrades as upgrade, channels
from controller.firewall import WorkflowConflict
from controller.store import Store, now, stamp


class AgentUpgradeTests(TestCase):
    version = "0.18.4"
    previous_version = "0.18.3"
    assets = {"amd64": {"sha256": "a" * 64, "bytes": 4200}, "arm64": {"sha256": "b" * 64, "bytes": 4300}}

    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.store = Store(temporary.name)
        self.app = SimpleNamespace(store=self.store, platform=object(), demo=False, auth=Mock())
        self.admin = {"actor": "alice", "role": "super_admin", "auth_type": "session"}
        package_inventory = patch.object(upgrade.releases, "available_versions", return_value=[
            {"version": self.version, "architectures": self.assets},
        ])
        self.package_inventory = package_inventory.start()
        self.addCleanup(package_inventory.stop)
        self.report("a")
        self.report("b", agent_architecture="arm64")
        self.report("old", capabilities=[])
        self.location = self.store.save_location(
            {"name": "Pune", "type": "datacenter", "location": "Pune"}, "admin"
        )
        self.store.update_server("a", {"tags": {"tier": "web"}, "location_id": self.location["id"]}, "admin")
        self.store.update_server("old", {"tags": {"tier": "web"}}, "admin")
        self.group = self.store.save_group(
            {"name": "Web", "type": "dynamic", "selector": {"tier": "web"}, "server_ids": []}, "admin"
        )

    def report(self, identifier, **overrides):
        return self.store.report(identifier, {
            "hostname": identifier, "listeners": [], "ips": [], "agent_version": self.previous_version,
            "agent_architecture": "amd64", "capabilities": [upgrade.CAPABILITY], **overrides,
        })

    def preview(self, **scope):
        return upgrade.preview(self.app, {"version": self.version, **scope}, self.admin)

    def confirm(self, plan, principal=None, **overrides):
        return upgrade.confirm(self.app, plan["id"], {"digest": plan["digest"], **overrides}, principal or self.admin)

    def assignment(self, identifier):
        return self.store.assignment(identifier)[0].get("agent_upgrade")

    def test_each_scope_reviews_exact_eligible_endpoints_and_publishes_nothing(self):
        scopes = (
            ({"server_ids": ["b"]}, {"b"}, set()),
            ({"group_ids": [self.group["id"]]}, {"a"}, {"old"}),
            ({"selector": {"tier": "web"}}, {"a"}, {"old"}),
            ({"selector": {"location_id": self.location["id"]}}, {"a"}, set()),
            ({"all": True}, {"a", "b"}, {"old"}),
        )
        for scope, targets, exclusions in scopes:
            with self.subTest(scope=scope):
                plan = self.preview(**scope)
                self.assertTrue(plan["can_apply"])
                self.assertEqual({row["server_id"] for row in plan["targets"]}, targets)
                self.assertEqual({row["server_id"] for row in plan["exclusions"]}, exclusions)
        for scope in ({}, {"all": True, "server_ids": ["a"]}, {"selector": {"location_id": "missing"}}, {"server_ids": ["missing"]}):
            with self.subTest(scope=scope), self.assertRaises(ValueError):
                self.preview(**scope)
        self.assertEqual(upgrade.listing(self.app, self.admin)["rollouts"], [])
        self.assertIsNone(self.assignment("a"))
        self.assertIsNone(self.assignment("b"))

    def test_confirmation_publishes_frozen_targets_and_rejects_retargeting(self):
        plan = self.preview(selector={"tier": "web"})
        self.store.update_server("b", {"tags": {"tier": "web"}}, "admin")
        self.store.update_server("a", {"tags": {"tier": "worker"}}, "admin")
        with self.assertRaises(WorkflowConflict):
            self.confirm(plan, digest="changed")
        with self.assertRaises(PermissionError):
            self.confirm(plan, principal={**self.admin, "actor": "bob"})
        approved = self.confirm(plan)
        self.assertEqual(approved["outcomes"], {"queued": 1})
        self.assertIsNotNone(approved["confirmed_at"])
        self.assertEqual(self.confirm(plan), approved)
        assignment = self.assignment("a")
        self.assertEqual(assignment, {
            "id": plan["id"], "version": self.version, "architecture": "amd64",
            **self.assets["amd64"], "expires_at": approved["expires_at"],
        })
        self.assertIsNone(self.assignment("b"))
        self.assertIsNone(self.assignment("old"))
        excluded = self.preview(server_ids=["a"])
        self.assertFalse(excluded["can_apply"])
        self.assertIn("already active", excluded["exclusions"][0]["reason"])
        self.assertEqual(upgrade.listing(self.app, self.admin)["rollouts"][0]["id"], plan["id"])

    def test_unapproved_or_mismatched_artifacts_cannot_be_downloaded(self):
        plan = self.preview(server_ids=["a"])
        with self.assertRaises(KeyError), upgrade.download(self.app, "a", plan["id"], "archive"):
            self.fail("A review alone cannot authorize a download")
        self.confirm(plan)

        @contextmanager
        def package(architecture, version, asset, expected):
            self.assertEqual((architecture, version, asset), ("amd64", self.version, "archive"))
            self.assertEqual(expected["sha256"], self.assets["amd64"]["sha256"])
            yield ("agent.tar.gz", 3, BytesIO(b"pkg"))

        with patch.object(upgrade.releases, "open_exact_download", package):
            with self.assertRaises(KeyError), upgrade.download(self.app, "b", plan["id"], "archive"):
                self.fail("An enrolled endpoint cannot borrow another endpoint's rollout")
            with upgrade.download(self.app, "a", plan["id"], "archive") as (_, _, stream):
                self.assertEqual(stream.read(), b"pkg")
        with patch.object(upgrade.releases, "open_exact_download", side_effect=FileNotFoundError):
            with self.assertRaises(KeyError), upgrade.download(self.app, "a", plan["id"], "archive"):
                self.fail("A missing exact artifact cannot fall back to a different release")

    def test_outcomes_require_exact_endpoint_and_applied_version(self):
        plan = self.preview(server_ids=["a"])
        self.confirm(plan)
        receipt = {"id": plan["id"], "version": self.version, "status": "applied", "error": ""}
        self.report("b", agent_version=self.version, agent_upgrade=receipt)
        self.report("a", agent_upgrade=receipt)
        self.assertEqual(upgrade.detail(self.app, plan["id"], self.admin)["outcomes"], {"queued": 1})
        self.report("a", agent_upgrade={**receipt, "status": "upgrading"})
        self.assertEqual(upgrade.detail(self.app, plan["id"], self.admin)["outcomes"], {"upgrading": 1})
        self.report("a", agent_version=self.version, agent_upgrade={**receipt, "status": "rolled_back"})
        self.assertEqual(upgrade.detail(self.app, plan["id"], self.admin)["outcomes"], {"upgrading": 1})
        self.report("a", agent_version=self.version, agent_upgrade=receipt)
        self.report("a", agent_version=self.version, agent_upgrade={**receipt, "status": "error"})
        result = upgrade.detail(self.app, plan["id"], self.admin)
        self.assertEqual((result["status"], result["outcomes"]), ("completed", {"applied": 1}))
        self.assertEqual(result["targets"][0]["reported_version"], self.version)
        self.assertIsNone(self.assignment("a"))

    def test_confirmation_blocks_changed_assets_versions_and_unprivileged_sessions(self):
        plan = self.preview(server_ids=["a"])
        for identity in ({**self.admin, "role": "admin"}, {**self.admin, "auth_type": "token"}):
            with self.assertRaises(PermissionError):
                upgrade.listing(self.app, identity)
            with self.assertRaises(PermissionError):
                self.confirm(plan, identity)
        original = self.package_inventory.return_value
        self.package_inventory.return_value = [
            {"version": self.version, "architectures": {"amd64": {"sha256": "c" * 64, "bytes": 4200}}},
        ]
        with self.assertRaises(WorkflowConflict):
            self.confirm(plan)
        self.package_inventory.return_value = original
        self.report("a", agent_version="0.18.2")
        with self.assertRaises(WorkflowConflict):
            self.confirm(plan)
        self.assertIsNone(self.assignment("a"))

    def test_expiry_and_recovery_remove_upgrade_authority(self):
        plan = self.preview(server_ids=["a"])
        self.confirm(plan)
        with self.store.meta() as db:
            db.execute("UPDATE agent_upgrade_targets SET expires_at=?", (stamp(now() - timedelta(seconds=1)),))
        self.assertIsNone(self.assignment("a"))
        self.assertEqual(upgrade.detail(self.app, plan["id"], self.admin)["outcomes"], {"expired": 1})
        plan = self.preview(server_ids=["a"])
        self.confirm(plan)
        with self.store.meta() as db:
            upgrade.invalidate_after_recovery(self.store, db)
        self.assertIsNone(self.assignment("a"))
        self.assertEqual(upgrade.detail(self.app, plan["id"], self.admin)["status"], "revoked")

    def test_upgrade_assets_are_admitted_only_to_control_get_on_separated_listeners(self):
        path = "/api/v1/agent/upgrade/" + "a" * 32 + "/archive"
        self.assertTrue(channels.admitted("control", "GET", path))
        for listener in ("discovery", "management"):
            self.assertFalse(channels.admitted(listener, "GET", path))
        self.assertFalse(channels.admitted("control", "POST", path))
        self.assertFalse(channels.admitted("control", "GET", path + "/extra"))
