import copy
import json
import tempfile
import unittest
from unittest.mock import patch

from controller import service_groups
from controller.firewall import WorkflowConflict
from controller.store import Store, digest, validate_policy


class ServiceGroupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(self.temp.name)
        self.store.lab_approvals = True  # Explicit isolated single-actor lab fixture.
        self.report("target", ["10.1.0.1"], {"role": "target"})
        self.report("other", ["10.1.0.2"], {"role": "other"})
        self.report("source-a", ["10.2.0.1", "2001:db8::1"], {"role": "client", "environment": "prod"})
        self.report("source-b", ["10.2.0.2"], {"role": "client", "environment": "dev"})

    def report(self, identifier, addresses, tags=None, **extra):
        self.store.report(identifier, {"hostname": identifier, "ips": addresses, "listeners": [], "firewalld_state": "running", "applied_version": 0, **extra})
        if tags is not None:
            self.store.update_server(identifier, {"tags": tags}, "admin")

    def catalogue(self, ports=(80, 443), **extra):
        return service_groups.save(self.store, {"name": "Web", "ports": [{"port": port, "protocol": "tcp"} for port in ports], **extra}, "admin")

    def group(self, name, *, selector=None, server_ids=None):
        return self.store.save_group({"name": name, "type": "dynamic" if selector else "static", "selector": selector or {}, "server_ids": server_ids or []}, "admin")

    def policy(self, group, **extra):
        return self.store.save_policy({"name": "Allow web", "selector": {"role": "target"}, "mode": "enforce", "services": [{"service_group_id": group["id"], "sources": ["10.90.0.0/24"]}], **extra}, "admin")

    def edit(self, group, **extra):
        return service_groups.save(self.store, {**group, "expected_revision": group["revision"], **extra}, "admin", group["id"])

    def bundle(self, identifier="target"):
        return self.store.assignment(identifier)[0]

    def test_catalogue_normalization_identity_revision_and_history(self):
        group = self.catalogue(ports=(443, 80, 443))
        self.assertEqual(group["ports"], [{"port": 80, "protocol": "tcp"}, {"port": 443, "protocol": "tcp"}])
        self.assertEqual(service_groups.listing(self.store)[0], group)
        original = service_groups.revisions(self.store, group["id"], 1)
        renamed = self.edit(group, name="Public web")
        self.assertEqual(renamed["id"], group["id"])
        self.assertEqual(renamed["revision"], 2)
        self.assertEqual(service_groups.revisions(self.store, group["id"], 1), original)
        self.assertEqual(self.edit(renamed)["revision"], 2)
        with self.assertRaises(ValueError):
            service_groups.save(self.store, {**renamed, "name": "Unsafe stale edit"}, "admin", group["id"])
        with self.assertRaises(WorkflowConflict):
            self.edit(group, name="Stale")
        with self.assertRaises(ValueError):
            self.edit(renamed, id="different")
        service_groups.delete(self.store, group["id"], "admin")
        self.assertEqual(len(service_groups.revisions(self.store, group["id"])), 2)
        with self.assertRaises(KeyError):
            service_groups.get(self.store, group["id"])

    def test_validation_rejects_nested_ranges_protocols_and_unknown_references(self):
        for ports in ([], [{"port": "80-90"}], [{"port": True}], [{"port": 80, "protocol": "sctp"}], [{"service_group_id": "nested"}], [{"port": port} for port in range(1, 102)]):
            with self.subTest(ports=ports):
                with self.assertRaises(ValueError):
                    service_groups.save(self.store, {"name": "Bad", "ports": ports}, "admin")
        with self.assertRaises(ValueError):
            self.policy({"id": "missing"})
        for row in ({"service_group_id": "missing", "port": 80}, {"service_group_id": "missing", "protocol": "tcp"}, {"port": 80, "source_group_ids": "group"}, {"port": 80, "source_group_ids": [""]}):
            with self.assertRaises(ValueError):
                validate_policy({"name": "Invalid", "services": [row]})
        with self.assertRaises(ValueError):
            self.store.save_policy({"name": "Unknown source", "services": [{"port": 80, "source_group_ids": ["missing"]}]}, "admin")

    def test_multiple_source_groups_cidrs_and_and_selector_are_union_for_each_port(self):
        web = self.catalogue()
        clients = self.group("Production clients", selector={"role": "client", "environment": "prod"})
        pinned = self.group("Pinned clients", server_ids=["source-b"])
        self.policy(web, services=[{"service_group_id": web["id"], "sources": ["10.99.0.0/24"], "source_selector": {"role": "client", "environment": "prod"}, "source_group_ids": [clients["id"], pinned["id"]]}, {"port": 5432, "sources": ["10.88.0.0/24"]}])
        by_port = {service["port"]: service for service in self.bundle()["services"]}
        expected = ["10.2.0.1/32", "10.2.0.2/32", "10.99.0.0/24", "2001:db8::1/128"]
        self.assertEqual(by_port[80]["sources"], expected)
        self.assertEqual(by_port[443]["sources"], expected)
        self.assertEqual(by_port[5432]["sources"], ["10.88.0.0/24"])
        self.assertEqual(self.bundle("other")["services"], [])
        before = self.bundle()
        self.store.update_server("source-b", {"tags": {"role": "client", "environment": "prod"}}, "admin")
        self.assertEqual(self.bundle()["version"], before["version"])
        self.store.save_group({**pinned, "server_ids": []}, "admin", pinned["id"])
        self.assertEqual(self.bundle()["version"], before["version"])
        self.store.update_server("source-b", {"tags": {"role": "client", "environment": "dev"}}, "admin")
        changed = self.bundle()
        self.assertEqual(changed["version"], before["version"] + 1)
        self.assertNotIn("10.2.0.2/32", changed["services"][0]["sources"])
        self.report("source-a", ["10.2.0.3"])
        self.assertIn("10.2.0.3/32", self.bundle()["services"][0]["sources"])

    def test_duplicate_rows_groups_and_policies_do_not_duplicate_effective_rules(self):
        web = self.catalogue(ports=(443, 443))
        saved = self.policy(web, services=[
            {"port": 443, "sources": ["10.90.0.1", "10.90.0.1/32"]},
            {"port": 443, "sources": ["10.90.0.1/32"]},
            {"service_group_id": web["id"], "sources": ["10.90.0.1/32"]},
        ])
        self.assertEqual(len(saved["services"]), 2)
        before = self.bundle()
        self.assertEqual(before["services"], [{"port": 443, "protocol": "tcp", "mode": "enforce", "sources": ["10.90.0.1/32"]}])
        self.policy(web, name="Same permissions", services=[{"port": 443, "sources": ["10.90.0.1"]}])
        after = self.bundle()
        self.assertEqual(after["services"], before["services"])
        self.assertEqual((after["version"], after["digest"]), (before["version"], before["digest"]))
        self.assertEqual(self.bundle("other")["services"], [])

    def test_overlapping_enforce_unions_only_its_sources_and_monitor_never_widens(self):
        web = self.catalogue()
        self.policy(web)
        self.policy(web, name="Other enforced source", services=[{"port": 443, "sources": ["10.91.0.0/24"]}])
        self.policy(web, name="Observe", mode="monitor", services=[{"service_group_id": web["id"], "sources": ["0.0.0.0/0"]}, {"port": 8080, "sources": ["0.0.0.0/0"]}])
        by_port = {service["port"]: service for service in self.bundle()["services"]}
        self.assertEqual(by_port[80]["sources"], ["10.90.0.0/24"])
        self.assertEqual(by_port[443]["sources"], ["10.90.0.0/24", "10.91.0.0/24"])
        self.assertEqual(by_port[8080]["mode"], "monitor")

    def test_edit_preview_only_changed_hosts_versions_policy_snapshots_and_restore(self):
        web = self.catalogue()
        policy = self.policy(web)
        redundant = self.policy(web, name="Other target web", selector={"role": "other"})
        self.policy(web, name="Already allows replacement", selector={"role": "other"}, services=[{"port": 8443, "sources": ["10.90.0.0/24"]}])
        original = self.bundle()
        other = self.bundle("other")
        historical_policy = self.store.policy_revisions(policy["id"], 1)
        preview_value = {**web, "expected_revision": web["revision"], "ports": web["ports"] + [{"port": 8443, "protocol": "tcp"}]}
        before_audit = len(self.store.all("audit"))
        impact = service_groups.preview(self.store, preview_value)
        self.assertEqual(impact["affected_server_ids"], ["target"])
        self.assertEqual(set(impact["affected_policy_ids"]), {policy["id"], redundant["id"]})
        self.assertEqual(impact["target_server_count"], 2)
        self.assertEqual(self.bundle()["version"], original["version"])
        self.assertEqual(len(self.store.all("audit")), before_audit)
        with patch.object(self.store, "compile_all", wraps=self.store.compile_all) as compile_all:
            edited = service_groups.save(self.store, preview_value, "admin", web["id"])
            self.assertEqual(compile_all.call_count, 1)
        self.assertEqual(self.bundle()["version"], original["version"] + 1)
        self.assertEqual(self.bundle("other")["version"], other["version"])
        current_policy = self.store.get("policies", policy["id"])
        self.assertEqual(current_policy["revision"], 2)
        self.assertEqual(current_policy["services"][0]["service_group_snapshot"]["revision"], 2)
        self.assertEqual(self.store.policy_revisions(policy["id"], 1), historical_policy)
        history = self.store.policy_history("target", original["version"])
        self.assertEqual(history["service_group_snapshots"][0]["ports"], web["ports"])
        self.assertEqual(history["service_group_snapshots"][0]["revision"], 1)
        renamed = self.edit(edited, name="Renamed web")
        unchanged = self.bundle()
        self.assertEqual(unchanged["version"], original["version"] + 1)
        restored = self.store.rollback_policy(policy["id"], 1, "Use current service catalogue", "admin")
        self.assertEqual(restored["services"][0]["service_group_snapshot"]["revision"], renamed["revision"])
        self.assertIn({"port": 8443, "protocol": "tcp"}, restored["services"][0]["service_group_snapshot"]["ports"])
        self.assertEqual(self.bundle()["version"], unchanged["version"])

    def test_impact_preview_includes_only_affected_reported_addresses_without_writes(self):
        addresses = ["172.31.3.131", "100.66.222.60", "2001:db8::60"]
        self.report("target", addresses, {"role": "target"}, transport_ip="198.51.100.99")
        web = self.catalogue()
        self.policy(web)
        before = {table: copy.deepcopy(self.store.all(table)) for table in ("servers", "policies", "service_groups", "audit")}
        impact = service_groups.preview(self.store, {**web, "expected_revision": 1,
            "ports": web["ports"] + [{"port": 8443, "protocol": "tcp"}]})
        self.assertEqual(impact["effective_change_count"], 1)
        self.assertEqual(impact["affected_server_ids"], ["target"])
        self.assertEqual(impact["affected_servers"][0]["ips"], sorted(addresses))
        self.assertNotIn("198.51.100.99", json.dumps(impact))
        for table, rows in before.items():
            self.assertEqual(self.store.all(table), rows, table)
        impact["affected_servers"][0]["ips"].clear()
        self.assertEqual(self.store.server("target")["ips"], sorted(addresses))

    def test_delete_guards_and_missing_reference_fail_closed(self):
        web = self.catalogue()
        clients = self.group("Pinned source", server_ids=["source-a"])
        policy = self.policy(web, services=[{"service_group_id": web["id"], "source_group_ids": [clients["id"]]}])
        with self.assertRaises(ValueError):
            service_groups.delete(self.store, web["id"], "admin")
        with self.assertRaises(ValueError):
            self.store.delete_group(clients["id"], "admin")
        before = self.bundle()
        for table, identifier in (("groups", clients["id"]), ("service_groups", web["id"])):
            with self.assertRaises(ValueError):
                with self.store.meta() as db:
                    db.execute("DELETE FROM " + table + " WHERE id=?", (identifier,))
                    self.store.compile_all(db)
            self.assertIsNotNone(self.store.get(table, identifier))
            self.assertEqual(self.bundle()["version"], before["version"])
        # Even pre-existing corrupt catalogue state cannot become a valid empty
        # bundle or a managed-cleanup request on the next compile.
        with self.store.meta() as db:
            db.execute("DELETE FROM service_groups WHERE id=?", (web["id"],))
        with self.assertRaises(ValueError):
            with self.store.meta() as db:
                self.store.compile_all(db)
        self.assertEqual(self.bundle()["version"], before["version"])
        self.assertEqual(self.bundle()["services"], before["services"])
        with self.assertRaises(ValueError):
            self.store.rollback_policy(policy["id"], 1, "Deleted catalogue remains invalid", "admin")

    def test_edit_rolls_back_catalogue_policies_audit_and_bundles_atomically(self):
        web = self.catalogue()
        policy = self.policy(web)
        before = {table: copy.deepcopy(self.store.all(table)) for table in ("service_groups", "service_group_revisions", "policies", "policy_revisions", "servers", "bundle_history", "audit")}
        original_compile = self.store.compile_all

        def fail_after_compilation(db):
            original_compile(db)
            raise RuntimeError("injected transaction failure")

        with patch.object(self.store, "compile_all", side_effect=fail_after_compilation):
            with self.assertRaises(RuntimeError):
                self.edit(web, ports=[{"port": 8443, "protocol": "tcp"}])
        for table, rows in before.items():
            self.assertEqual(self.store.all(table), rows, table)
        self.assertEqual(self.store.get("policies", policy["id"])["revision"], 1)

    def test_group_edit_invalidates_existing_managed_approval_and_never_creates_one(self):
        web = self.catalogue()
        self.policy(web)
        baseline = {"management_sources": ["10.99.0.0/24"], "ssh_ports": [2022], "controller_url": "https://controller.example", "management_probe_url": "https://controller.example/api/v1/agent/enforcement/check", "zone": "public"}
        self.report("target", ["10.1.0.1"], protection={**baseline, "digest": digest(baseline), "ready": True, "blockers": []})
        first = self.store.create_managed_rollout({"name": "Review", "server_ids": ["target"]}, "admin")
        second = self.store.confirm_managed_rollout(first["id"], {"confirmation_nonce": first["confirmation_nonce"]}, "admin")
        self.store.confirm_managed_rollout(first["id"], {"confirmation_nonce": second["confirmation_nonce"], "challenge": second["confirmation_phrase"]}, "admin")
        self.assertTrue(self.bundle()["enforcement"]["authorized"])
        renamed = self.edit(web, name="Renamed")
        self.assertTrue(self.bundle()["enforcement"]["authorized"])
        before = len(self.store.all("managed_approvals"))
        self.edit(renamed, ports=[{"port": 8443, "protocol": "tcp"}])
        self.assertFalse(self.bundle()["enforcement"]["authorized"])
        self.assertEqual(len(self.store.all("managed_approvals")), before)


if __name__ == "__main__":
    unittest.main()
