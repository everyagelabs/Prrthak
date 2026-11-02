import json
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
import time
import unittest
from unittest.mock import patch
import zipfile

from controller import maintenance
from controller.firewall import WorkflowConflict
from controller.seed import seed
from controller.store import Store


class MaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = Store(Path(self.temporary.name) / "controller")
        self.store.backup_dir = Path(self.temporary.name) / "private-backups"

    def report(self, identifier="real-node", **extra):
        self.store.report(identifier, {"hostname": identifier, "ips": ["10.90.0.10"], "listeners": [], "firewalld_state": "running", **extra})

    def confirm(self, plan):
        return maintenance.clear_confirm(self.store, {"preview_id": plan["id"], "confirmation_nonce": plan["confirmation_nonce"], "confirmation_phrase": plan["confirmation_phrase"]}, "super_admin")

    def test_sqlite_backup_is_private_database_only_verified_and_staged_for_validation(self):
        self.report()
        pki = self.store.path / "pki"
        pki.mkdir()
        (pki / "ca-key.pem").write_text("PRIVATE-KEY-MUST-NOT-BE-IN-ARCHIVE")
        (self.store.path / "controller.env").write_text("PASSWORD=not-a-database-file")
        backup = maintenance.backup_create(self.store, "super_admin")
        self.assertTrue(backup["verified"])
        self.assertEqual(backup["backend"], "sqlite")
        self.assertNotIn("path", backup)
        path = maintenance.backup_download(self.store, backup["id"])
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
        with zipfile.ZipFile(path) as archive:
            self.assertEqual(set(archive.namelist()), {"metadata.sqlite3", "traffic.sqlite3", "manifest.json"})
            self.assertNotIn(b"PRIVATE-KEY-MUST-NOT-BE-IN-ARCHIVE", archive.read("manifest.json"))
            snapshot = Path(self.temporary.name) / "restored-metadata.sqlite3"
            snapshot.write_bytes(archive.read("metadata.sqlite3"))
            with sqlite3.connect(snapshot) as db:
                self.assertEqual(db.execute("SELECT id FROM servers").fetchall(), [("real-node",)])
        inspection = maintenance.backup_inspect(self.store, backup["id"])
        self.assertTrue(inspection["verified"])
        self.assertEqual({member["kind"] for member in inspection["manifest"]["members"]}, {"metadata", "traffic"})
        validation = maintenance.restore_validate(self.store, backup["id"], "super_admin")
        self.assertTrue(validation["valid"])
        self.assertFalse(validation["can_restore_live"])
        self.assertEqual(self.store.get("servers", "real-node")["hostname"], "real-node")

    def test_corrupt_archives_and_user_controlled_paths_are_rejected(self):
        backup = maintenance.backup_create(self.store, "super_admin")
        path = maintenance.backup_download(self.store, backup["id"])
        with path.open("ab") as target:
            target.write(b"changed")
        with self.assertRaises(maintenance.MaintenanceError):
            maintenance.backup_inspect(self.store, backup["id"])
        for identifier in ("../../etc/passwd", "/tmp/secret", "a" * 31, None):
            with self.subTest(identifier=identifier), self.assertRaises(ValueError):
                maintenance.backup_download(self.store, identifier)

    def test_archive_is_not_advertised_available_on_another_controller_without_bytes(self):
        backup = maintenance.backup_create(self.store, "super_admin")
        self.store.backup_dir = Path(self.temporary.name) / "another-controller-backups"
        self.assertFalse(maintenance.backup_listing(self.store)[0]["available"])
        with self.assertRaises(maintenance.MaintenanceError):
            maintenance.backup_download(self.store, backup["id"])

    def test_default_clear_requires_review_and_creates_verified_backup_before_mutation(self):
        seed(self.store)
        before_audit = len(self.store.all("audit"))
        with self.store.meta() as db:
            self.store._put(db, "auth_users", {"id": "keep-account", "email": "admin@example.internal"})
        plan = maintenance.clear_preview(self.store, "super_admin")
        self.assertTrue(plan["can_clear"], plan["blockers"])
        self.assertEqual(plan["counts"]["servers"], 14)
        self.assertEqual(plan["counts"]["policies"], 5)
        self.assertEqual(len(self.store.servers()), 14)
        with self.assertRaises(ValueError):
            maintenance.clear_confirm(self.store, {"preview_id": plan["id"], "confirmation_nonce": plan["confirmation_nonce"], "confirmation_phrase": "clear"}, "super_admin")
        result = self.confirm(plan)
        self.assertTrue(result["seed_disabled"])
        self.assertEqual(self.store.servers(), [])
        self.assertEqual(self.store.all("policies"), [])
        self.assertEqual(self.store.all("groups"), [])
        self.assertEqual(self.store.all("locations"), [])
        self.assertEqual(self.store.all("sessions"), [])
        self.assertEqual(self.store.flows(), [])
        self.assertTrue(maintenance.seed_disabled(self.store))
        self.assertGreater(len(self.store.all("audit")), before_audit)
        self.assertEqual(self.store.get("auth_users", "keep-account")["email"], "admin@example.internal")
        self.assertTrue(maintenance.backup_inspect(self.store, result["backup_id"])["verified"])
        archive = maintenance.backup_download(self.store, result["backup_id"])
        with zipfile.ZipFile(archive) as backup:
            metadata = Path(self.temporary.name) / "before-clear.sqlite3"
            metadata.write_bytes(backup.read("metadata.sqlite3"))
            with sqlite3.connect(metadata) as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM servers").fetchone()[0], 14)
        self.assertTrue(self.confirm(plan)["duplicate"])

    def test_backup_failure_cannot_clear_any_data_or_disable_seed(self):
        seed(self.store)
        plan = maintenance.clear_preview(self.store, "super_admin")
        with patch("controller.maintenance.backup_create", side_effect=maintenance.MaintenanceError("backup unavailable")):
            with self.assertRaises(maintenance.MaintenanceError):
                self.confirm(plan)
        self.assertEqual(len(self.store.servers()), 14)
        self.assertFalse(maintenance.seed_disabled(self.store))

    def test_clear_preserves_real_hosts_shared_policies_manual_groups_and_custom_locations(self):
        seed(self.store)
        self.report()
        location = self.store.save_location({"name": "Real custom DC", "location": "Independent site", "type": "datacenter"}, "super_admin")
        self.store.update_server("real-node", {"location_id": location["id"], "tags": {"application": "real-custom-app", "owner": "ops"}}, "super_admin")
        group = self.store.save_group({"name": "Manual custom group", "type": "static", "server_ids": ["real-node"]}, "super_admin")
        stored_group = self.store.get("groups", group["id"])
        policy = self.store.save_policy({"name": "Real policy", "selector": {"owner": "ops"}, "mode": "monitor", "services": [{"port": 1234, "sources": ["10.99.0.0/24"]}]}, "super_admin")
        stored_policy = self.store.get("policies", policy["id"])
        before = self.store.assignment("real-node")[0]
        plan = maintenance.clear_preview(self.store, "super_admin")
        self.assertTrue(plan["can_clear"], plan["blockers"])
        self.assertEqual(plan["preserved"]["real_endpoints"], 1)
        self.assertEqual(len(plan["preserved"]["shared_policy_ids"]), 1)
        self.confirm(plan)
        self.assertEqual([server["id"] for server in self.store.servers()], ["real-node"])
        self.assertEqual(self.store.get("groups", group["id"]), stored_group)
        self.assertEqual(self.store.get("locations", location["id"]), location)
        self.assertEqual(self.store.get("policies", policy["id"]), stored_policy)
        self.assertEqual(self.store.get("servers", "real-node")["tags"]["owner"], "ops")
        self.assertEqual(self.store.assignment("real-node")[0]["digest"], before["digest"])

    def test_mixed_dependencies_and_manual_reference_changes_block_cleanup(self):
        seed(self.store)
        self.report()
        group = self.store.save_group({"name": "Do not change manual membership", "type": "static", "server_ids": ["real-node", "srv-web-01"]}, "super_admin")
        stored_group = self.store.get("groups", group["id"])
        plan = maintenance.clear_preview(self.store, "super_admin")
        self.assertFalse(plan["can_clear"])
        self.assertTrue(any("manual/static group" in reason for reason in plan["blockers"]))
        with self.assertRaises(WorkflowConflict):
            self.confirm(plan)
        self.assertEqual(self.store.get("groups", group["id"]), stored_group)
        self.assertEqual(maintenance.backup_listing(self.store), [])

    def test_real_effective_policy_depending_on_synthetic_sources_blocks_clear(self):
        seed(self.store)
        self.report()
        self.store.save_policy({"name": "Real source dependency", "selector": {}, "mode": "monitor", "services": [{"port": 9876, "sources": [], "source_selector": {"application": "payments"}}]}, "super_admin")
        plan = maintenance.clear_preview(self.store, "super_admin")
        self.assertFalse(plan["can_clear"])
        self.assertTrue(any("effective policy depends" in reason for reason in plan["blockers"]))

    def test_stale_preview_and_edited_default_policy_are_not_silently_removed(self):
        seed(self.store)
        plan = maintenance.clear_preview(self.store, "super_admin")
        policy = self.store.all("policies")[0]
        edited = self.store.save_policy({**policy, "name": "My explicitly customized policy"}, "super_admin", policy["id"])
        stored_edited = self.store.get("policies", edited["id"])
        with self.assertRaises(WorkflowConflict):
            self.confirm(plan)
        self.assertEqual(len(self.store.servers()), 14)
        fresh = maintenance.clear_preview(self.store, "super_admin")
        self.assertTrue(fresh["can_clear"])
        self.confirm(fresh)
        self.assertEqual(self.store.get("policies", policy["id"]), stored_edited)

    def test_known_id_without_synthetic_flag_is_not_a_default_fixture(self):
        self.report("srv-web-01")
        plan = maintenance.clear_preview(self.store, "super_admin")
        self.assertEqual(plan["counts"]["servers"], 0)
        self.confirm(plan)
        self.assertEqual(self.store.get("servers", "srv-web-01")["hostname"], "srv-web-01")

    def test_postgres_client_argv_excludes_connection_secrets_and_errors_are_safe(self):
        output = Path(self.temporary.name) / "pg.dump"
        executable = Path(self.temporary.name) / "client"
        executable.write_text("#!/bin/sh\nprintf 'PGDMP-unit-fixture'\n")
        executable.chmod(0o700)
        arguments = [str(executable), "--format=custom", "--no-owner", "--no-privileges", "--no-password"]
        secret = "never-in-argv-or-errors"
        environment = {"PGPASSWORD": secret, "PGDATABASE": "private-database"}
        with patch("controller.maintenance.subprocess.Popen", wraps=__import__("subprocess").Popen) as popen:
            maintenance._bounded_command(arguments, environment, output, time.monotonic() + 5)
        self.assertNotIn(secret, str(popen.call_args.args[0]))
        self.assertNotIn("private-database", str(popen.call_args.args[0]))
        self.assertEqual(output.read_bytes(), b"PGDMP-unit-fixture")
        executable.write_text("#!/bin/sh\nprintf '%s' \"$PGPASSWORD\" >&2\nexit 2\n")
        with self.assertRaises(maintenance.MaintenanceError) as failure:
            maintenance._bounded_command(arguments, environment, output, time.monotonic() + 5)
        self.assertNotIn(secret, str(failure.exception))


if __name__ == "__main__":
    unittest.main()
