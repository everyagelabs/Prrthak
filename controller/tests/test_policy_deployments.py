"""Exact applied-bundle receipts and passive native witnesses stay separate."""
from datetime import timedelta
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from controller import policy_deployments as deployments
from controller.store import Store, digest, now, stamp
from controller.tests import private_pg


class DeploymentChecks:
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.store = self.make_store()
        with self.store.meta() as db: deployments.initialize(db)
        self.at = now().replace(microsecond=0) - timedelta(seconds=60)
        self.publication_sequence = 0
        self.authorization = patch("controller.approvals.authorized", return_value=True)
        self.authorization.start(); self.addCleanup(self.authorization.stop)
        self.host = self.server("host-a")

    def make_store(self):
        return Store(self.temp.name)

    def server(self, identifier, *, ports=(443, 8443), sources=None, capability=True):
        services = [{"port": port, "protocol": "tcp", "sources": ["10.241.0.0/16"] if sources is None else sources, "mode": "enforce"} for port in ports]
        body = {"mode": "enforce", "services": services}
        host = {"id": identifier, "hostname": identifier, "ips": ["192.0.2.10"], "_compiled": {**body, "server_id": identifier, "version": 42, "digest": digest(body)}, "protection": {"digest": "b" * 64, "ready": True, "ssh_ports": [22], "management_sources": ["10.90.0.0/24"]}, "capabilities": ["signed_assignments_v1"] + ([deployments.CAPABILITY] if capability else []), "last_seen": stamp()}
        with self.store.meta() as db:
            self.store._put(db, "servers", host)
            db.execute("INSERT INTO managed_approvals(id,server_id,version,digest,protection_digest,approval_id,expires_at,active,data) VALUES(?,?,?,?,?,?,?,?,?)", (identifier + ":approval", identifier, 42, host["_compiled"]["digest"], "b" * 64, "approval-" + identifier, "9999-12-31T23:59:59Z", 1, json.dumps({"approval_proof": {"fixture": True}})))
        return host

    def publish(self, hosts=None, **extra):
        hosts = hosts or [self.host]
        refs = [{"server_id": host["id"], "version": 42, "digest": host["_compiled"]["digest"], "ports": [{"port": s["port"], "protocol": s["protocol"]} for s in host["_compiled"]["services"]], **extra} for host in hosts]
        self.publication_sequence += 1
        publication_at = self.at + timedelta(microseconds=self.publication_sequence)
        with patch.object(deployments, "now", return_value=publication_at), self.store.meta() as db:
            run = deployments.create(self.store, db, refs, "admin", "Billing publication")
        with self.store.read_meta() as db:
            target = json.loads(db.execute("SELECT data FROM policy_deployment_targets WHERE deployment_id=? AND server_id=?", (run["id"], hosts[0]["id"])).fetchone()[0])
        return run, target

    def accepted_readback(self, target, **changes):
        result = {"status": "enforced", "version": 42, "digest": target["digest"], "approval_id": target["approval_id"], "protection_digest": target["lease"]["protection_digest"], "approved_ips": self.host["ips"], "generation": "c" * 32, "updated_at": stamp(self.at + timedelta(seconds=1)), "committed_at": None, "verification_id": target["id"], "verification_readback_at": stamp(self.at + timedelta(seconds=1)), **changes}
        self.host["managed_enforcement"] = result
        with self.store.meta() as db:
            self.store._put(db, "servers", self.host)
            deployments.outcome(self.store, db, self.host, result)
        return result

    def receipt(self, target, *, complete=False):
        lease = copy.deepcopy(target["lease"])
        report = {**lease, "sequence": 1, "state": "verified" if complete else "observing", "applied_generation": "c" * 32, "armed_at": stamp(self.at + timedelta(seconds=2)), "committed_at": None, "checked_at": stamp(self.at + timedelta(seconds=6)), "ports": []}
        for port in lease["ports"]:
            item = dict(port)
            for action in ("allow", "deny"):
                case = {"status": "verified" if complete else "awaiting", "reason": "Native witness" if complete else "Awaiting traffic"}
                if complete: case["evidence"] = self.witness(report, port, action)
                item[action] = case
            report["ports"].append(item)
        return report

    def witness(self, report, port, action):
        epoch = "d" * 64
        value = {"event_id": digest([port, action]), "source_ip": "10.241.1.9" if action == "allow" else "198.51.100.9", "destination_ip": self.host["ips"][0], **port, "address_family": "ipv4", "capture_kind": "accepted_connection" if action == "allow" else "denied_packet", "capture_backend": "conntrack" if action == "allow" else "nflog", "count_unit": "connections" if action == "allow" else "packets", "expected_action": "allowed" if action == "allow" else "denied", "observed_at": stamp(self.at + timedelta(seconds=4)), "received_at": stamp(self.at + timedelta(seconds=5)), "capture_epoch": epoch}
        if action == "allow": value["connection_started_at"] = stamp(self.at + timedelta(seconds=3))
        else:
            material = "\x00".join(("prthak-policy-verification-deny-v1", report["id"], report["applied_generation"], epoch, port["protocol"], str(port["port"]), "ipv4"))
            value["rule_prefix"] = "PRTV" + hashlib.sha256(material.encode()).hexdigest()[:16] + ":"
        return value

    def admit(self, report):
        with self.store.meta() as db:
            return deployments.report(self.store, db, self.host, report)

    def test_applied_is_independent_and_silence_expires_without_success(self):
        run, target = self.publish(unchanged_intent=True)
        self.accepted_readback(target)
        self.assertTrue(self.admit(self.receipt(target)))
        detail = deployments.detail(self.store, run["id"], self.host["id"])
        self.assertEqual((detail["apply_status"], detail["traffic_status"], detail["verified_port_count"]), ("applied", "awaiting", 0))
        self.assertTrue(detail["unchanged_intent"])
        with patch.object(deployments, "now", return_value=self.at + timedelta(seconds=601)):
            detail = deployments.detail(self.store, run["id"], self.host["id"])
            summary = deployments.summary(self.store, run["id"])
        self.assertEqual((detail["traffic_status"], summary["state"], summary["traffic_verified_count"], summary["unverified_count"]), ("unverified", "attention", 0, 1))

    def test_every_allow_and_deny_case_of_every_port_needs_its_own_native_witness(self):
        run, target = self.publish(); self.accepted_readback(target)
        partial = self.receipt(target, complete=True)
        partial["state"] = "observing"; partial["ports"][1]["deny"] = {"status": "awaiting", "reason": "No denied packet yet"}
        self.assertTrue(self.admit(partial))
        self.assertEqual(deployments.summary(self.store, run["id"])["traffic_verified_count"], 0)
        full = self.receipt(target, complete=True); full["sequence"] = 2
        self.assertTrue(self.admit(full))
        summary = deployments.summary(self.store, run["id"])
        self.assertEqual((summary["state"], summary["applied_count"], summary["traffic_verified_count"]), ("verified", 1, 1))
        self.assertEqual(deployments.detail(self.store, run["id"], self.host["id"])["verified_port_count"], 2)

    def test_arm_claim_alone_cannot_mark_applied(self):
        _, target = self.publish()
        for changes in ({}, {"approval_id": "wrong"}, {"protection_digest": "a" * 64}, {"approved_ips": ["192.0.2.99"]}, {"generation": "f" * 32}, {"updated_at": target["created_at"]}):
            with self.subTest(changes=changes):
                self.host.pop("managed_enforcement", None)
                if changes: self.accepted_readback(target, **changes)
                with self.assertRaisesRegex(ValueError, "readback"):
                    self.admit(self.receipt(target))

    def test_generic_old_wrong_source_and_cross_scope_events_are_refused_atomically(self):
        run, target = self.publish(); self.accepted_readback(target)
        original = self.receipt(target, complete=True)
        mutations = [lambda r: r["ports"][0]["allow"]["evidence"].update(connection_started_at=r["armed_at"]), lambda r: r["ports"][0]["allow"]["evidence"].update(source_ip="198.51.100.4"), lambda r: r["ports"][0]["deny"]["evidence"].update(source_ip="10.241.1.4"), lambda r: r["ports"][0]["deny"]["evidence"].update(rule_prefix="PRTN" + "a" * 16 + ":"), lambda r: r["ports"][0]["allow"]["evidence"].update(destination_ip="192.0.2.99"), lambda r: r["ports"][0]["allow"]["evidence"].update(capture_backend="journal"), lambda r: r["ports"][0]["allow"].pop("evidence"), lambda r: r["ports"][0].update(protocol="udp"), lambda r: r.update(digest="e" * 64)]
        for mutation in mutations:
            attempt = copy.deepcopy(original); mutation(attempt)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): self.admit(attempt)
        self.assertEqual(deployments.summary(self.store, run["id"])["traffic_verified_count"], 0)

    def test_first_witness_sequence_replay_and_conservative_invalidation(self):
        run, target = self.publish(); self.accepted_readback(target)
        report = self.receipt(target, complete=True); self.assertTrue(self.admit(report))
        self.assertFalse(self.admit(report))
        replay = copy.deepcopy(report); replay["checked_at"] = stamp(self.at + timedelta(seconds=7))
        with self.assertRaisesRegex(ValueError, "sequence"): self.admit(replay)
        replacement = copy.deepcopy(report); replacement["sequence"] = 2; replacement["ports"][0]["allow"]["evidence"]["event_id"] = "e" * 64
        with self.assertRaisesRegex(ValueError, "first admitted witness"): self.admit(replacement)
        invalidated = copy.deepcopy(report); invalidated.update(sequence=2, state="superseded", error="Observer restarted")
        self.host["_compiled"]["version"] = 43
        self.host["_compiled"]["services"][0]["sources"] = ["203.0.113.0/24"]
        self.assertTrue(self.admit(invalidated))
        current = deployments.summary(self.store, run["id"])
        self.assertEqual((current["state"], current["traffic_verified_count"], current["superseded_count"]), ("attention", 0, 1))

    def test_unsupported_agents_and_large_port_scopes_do_not_block_publication(self):
        old = self.server("old-agent", capability=False)
        big = self.server("many-ports", ports=tuple(range(1000, 1065)))
        for host in (old, big):
            run, _ = self.publish([host])
            item = deployments.targets(self.store, run["id"])["items"][0]
            self.assertEqual(item["traffic_status"], "unavailable")
            self.assertEqual(item["port_count"], len(host["_compiled"]["services"]))

    def test_wrong_approval_or_stale_outcome_does_not_mark_applied(self):
        run, target = self.publish()
        for changes in ({"approval_id": "wrong"}, {"protection_digest": "a" * 64}, {"approved_ips": ["192.0.2.99"]}, {"updated_at": target["created_at"]}):
            self.accepted_readback(target, **changes)
            self.assertEqual(deployments.targets(self.store, run["id"])["items"][0]["apply_status"], "pending")

    def test_rollback_prevents_late_traffic_success_and_recovery_downgrades_history(self):
        run, target = self.publish(); result = self.accepted_readback(target)
        with self.store.meta() as db:
            deployments.outcome(self.store, db, self.host, {**result, "status": "rolled_back", "rollback_reason": "SSH health failed"})
        self.assertFalse(self.admit(self.receipt(target, complete=True)))
        self.assertEqual(deployments.summary(self.store, run["id"])["rolled_back_count"], 1)
        run, target = self.publish(); self.accepted_readback(target); self.admit(self.receipt(target, complete=True))
        with self.store.meta() as db: deployments.invalidate_after_recovery(None, db)
        item = deployments.detail(self.store, run["id"], self.host["id"])
        self.assertEqual(item["traffic_status"], "superseded"); self.assertTrue(item["historical_only"])
        self.assertTrue(all(port["status"] == "superseded" for port in item["ports"]))
        self.assertEqual(item["ports"][0]["allow"]["status"], "verified")

    def test_not_applicable_requires_impossible_effective_case(self):
        _, target = self.publish(); self.accepted_readback(target)
        report = self.receipt(target); report["ports"][0]["deny"] = {"status": "not_applicable", "reason": "Pretend universal source"}
        with self.assertRaisesRegex(ValueError, "Not-applicable"): self.admit(report)

    def test_target_pagination_exact_totals_and_global_active_total_are_not_first_page_counts(self):
        hosts = [self.server("node-" + str(index).zfill(4), ports=(443,)) for index in range(101)]
        run, _ = self.publish(hosts)
        pages = [deployments.targets(self.store, run["id"], limit=50, offset=offset) for offset in (0, 50, 100)]
        self.assertEqual([len(page["items"]) for page in pages], [50, 50, 1])
        self.assertEqual({page["total"] for page in pages}, {101})
        self.assertEqual(len({item["server_id"] for page in pages for item in page["items"]}), 101)
        for index in range(12): self.publish([self.server("extra-" + str(index), ports=(443,))])
        listing = deployments.listing(self.store)
        self.assertEqual((len(listing["items"]), listing["total"], listing["active_total"]), (10, 13, 13))

    def test_provider_revocation_stops_assignment_and_positive_receipts(self):
        _, target = self.publish(); self.accepted_readback(target)
        with patch("controller.approvals.authorized", return_value=False), self.store.meta() as db:
            self.assertIsNone(deployments.assignment(self.store, db, self.host))
            self.assertFalse(deployments.report(self.store, db, self.host, self.receipt(target, complete=True)))

    def test_recheck_is_fresh_observation_without_policy_or_authority_mutation(self):
        run, target = self.publish()
        before = self.store.get("servers", self.host["id"])
        with patch("controller.managed.authorization", return_value={"authorized": True}):
            fresh = deployments.recheck(self.store, run["id"], self.host["id"], "admin")
        self.assertNotEqual(fresh["id"], run["id"])
        self.assertEqual(self.store.get("servers", self.host["id"]), before)
        with self.store.read_meta() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM managed_approvals").fetchone()[0], 1)
        changed = copy.deepcopy(self.host); changed["_compiled"]["version"] = 43
        with self.store.meta() as db: self.store._put(db, "servers", changed)
        from controller.firewall import WorkflowConflict
        with self.assertRaises(WorkflowConflict): deployments.recheck(self.store, run["id"], self.host["id"], "admin")

    def test5000_targets_have_exact_totals_bounded_pages_and_no_source_duplication(self):
        hosts, server_values, approvals = [], [], []
        for index in range(5000):
            host = copy.deepcopy(self.host); host.update(id=f"fleet-{index:05d}", hostname=f"fleet-{index:05d}")
            host["_compiled"]["services"] = host["_compiled"]["services"][:1]
            host["_compiled"]["digest"] = digest({"mode": "enforce", "services": host["_compiled"]["services"]})
            hosts.append(host); server_values.append((host["id"], json.dumps(host)))
            approvals.append((host["id"] + ":approval", host["id"], 42, host["_compiled"]["digest"], "b" * 64, "approval-" + host["id"], "9999-12-31T23:59:59Z", 1, json.dumps({"approval_proof": {"fixture": True}})))
        with self.store.meta() as db:
            db.executemany("INSERT INTO servers(id,data) VALUES(?,?)", server_values)
            db.executemany("INSERT INTO managed_approvals(id,server_id,version,digest,protection_digest,approval_id,expires_at,active,data) VALUES(?,?,?,?,?,?,?,?,?)", approvals)
        run, target = self.publish(hosts)
        self.assertNotIn("sources", json.dumps(target))
        summary = deployments.summary(self.store, run["id"])
        self.assertEqual((summary["target_count"], summary["active_count"], summary["applied_count"], summary["traffic_verified_count"]), (5000, 5000, 0, 0))
        tail = deployments.targets(self.store, run["id"], limit=50, offset=4950)
        self.assertEqual((tail["total"], len(tail["items"]), tail["has_more"]), (5000, 50, False))

    def test_wire_types_and_navigation_bounds_are_strict(self):
        _, target = self.publish(); self.accepted_readback(target)
        for field, value in (("schema_version", True), ("version", 42.0), ("sequence", True), ("state", []), ("ports", [])):
            report = self.receipt(target); report[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): self.admit(report)
        for limit, offset in ((True, 0), (51, 0), (1, -1)):
            with self.assertRaises(ValueError): deployments.targets(self.store, target["deployment_id"], limit, offset)
        with self.assertRaises(ValueError): deployments.listing(self.store, 11)

    def test_publication_precision_rejects_old_same_second_readback_and_accepts_time_equivalent_echo(self):
        with patch.object(deployments, "now", return_value=self.at + timedelta(microseconds=500000)), self.store.meta() as db:
            run = deployments.create(self.store, db, [{"server_id": self.host["id"], "version": 42, "digest": self.host["_compiled"]["digest"], "ports": [{"port": 443, "protocol": "tcp"}]}], "admin", "Precise publication")
            target = json.loads(db.execute("SELECT data FROM policy_deployment_targets WHERE deployment_id=?", (run["id"],)).fetchone()[0])
        self.assertIn(".500000Z", target["created_at"])
        self.accepted_readback(target, updated_at=stamp(self.at))
        self.assertEqual(deployments.targets(self.store, run["id"])["items"][0]["apply_status"], "pending")
        self.accepted_readback(target)
        report = self.receipt(target)
        report["starts_at"] = report["starts_at"].replace(".500000Z", ".5Z")
        report["expires_at"] = report["expires_at"].replace(".500000Z", ".5Z")
        self.assertTrue(self.admit(report))

    def test_already_present_comes_from_first_exact_readback_and_cannot_be_relabelled_by_polling(self):
        run, target = self.publish(unchanged_intent=True)
        self.accepted_readback(target, already_present=False)
        self.accepted_readback(target, already_present=True)
        self.assertFalse(deployments.targets(self.store, run["id"])["items"][0]["already_present"])
        run, target = self.publish(unchanged_intent=True)
        self.accepted_readback(target, already_present=True)
        self.assertTrue(deployments.targets(self.store, run["id"])["items"][0]["already_present"])

    def test_lost_initial_report_and_later_polls_preserve_exact_pre_arm_readback_anchor(self):
        run, target = self.publish()
        self.accepted_readback(target, updated_at=stamp(self.at + timedelta(seconds=5)))
        report = self.receipt(target, complete=True)
        self.assertTrue(self.admit(report))
        first = deployments.detail(self.store, run["id"], self.host["id"])
        self.accepted_readback(target, updated_at=stamp(self.at + timedelta(seconds=10)), already_present=True)
        report.update(sequence=2, checked_at=stamp(self.at + timedelta(seconds=11)))
        self.assertTrue(self.admit(report))
        later = deployments.detail(self.store, run["id"], self.host["id"])
        self.assertEqual(later["readback_at"], first["readback_at"])
        self.assertEqual(later["ports"], first["ports"])
        self.assertFalse(later["already_present"])
        self.accepted_readback(target, updated_at=stamp(self.at + timedelta(seconds=10)), verification_readback_at=(self.at + timedelta(seconds=1, microseconds=500000)).isoformat())
        report["sequence"] = 3
        with self.assertRaisesRegex(ValueError, "immutable readback"): self.admit(report)

    def test_late_restart_downgrade_does_not_reject_healthy_report_or_admit_late_positive_evidence(self):
        run, target = self.publish(); self.accepted_readback(target)
        report = self.receipt(target, complete=True); self.assertTrue(self.admit(report))
        late = self.at + timedelta(hours=2)
        report.update(sequence=2, state="superseded", error="Observer restarted", checked_at=stamp(late))
        with patch.object(deployments, "now", return_value=late): self.assertTrue(self.admit(report))
        self.assertEqual(deployments.summary(self.store, run["id"])["superseded_count"], 1)
        run, target = self.publish(); self.accepted_readback(target)
        report = self.receipt(target, complete=True)
        with patch.object(deployments, "now", return_value=late), self.assertRaisesRegex(ValueError, "upload window"): self.admit(report)

    def automatic_fixture(self):
        source = self.server("source-host", ports=())
        for host, role in ((self.host, "api"), (source, "lb")):
            host.update(tags={"role": role}, _metadata_overrides={"tags": {"role": role}})
            with self.store.meta() as db: self.store._put(db, "servers", host)
        def reconcile(store, db, server, *args, **kwargs):
            body = server.get("_compiled", {})
            if body.get("mode") != "enforce": return False
            current = db.execute("SELECT version,digest FROM managed_approvals WHERE server_id=? AND active=1 LIMIT 1", (server["id"],)).fetchone()
            if current and (current[0], current[1]) == (body["version"], body["digest"]): return False
            db.execute("UPDATE managed_approvals SET active=0 WHERE server_id=?", (server["id"],))
            identifier = "automatic-" + server["id"] + "-" + str(body["version"])
            db.execute("INSERT INTO managed_approvals(id,server_id,version,digest,protection_digest,approval_id,expires_at,active,data) VALUES(?,?,?,?,?,?,?,?,?)", (identifier, server["id"], body["version"], body["digest"], server["protection"]["digest"], identifier, "9999-12-31T23:59:59Z", 1, json.dumps({"approval_proof": {"fixture": True}})))
            return True
        for mock in (patch("controller.managed.reconcile_direct", side_effect=reconcile), patch("controller.managed.authorization", return_value={"authorized": True})):
            mock.start(); self.addCleanup(mock.stop)
        with self.store.meta() as db: self.store.compile_all(db, track_automatic=False)
        policy = self.store.save_policy({"name": "Application API", "selector": {"role": "api"}, "mode": "enforce", "services": [{"port": 8443, "protocol": "tcp", "sources": [], "source_selector": {"role": "lb"}}]}, "admin")
        return source, policy

    def test_automatic_source_tag_resolution_tracks_new_effective_version_and_supersedes_active_lease(self):
        source, policy = self.automatic_fixture()
        before = deployments.listing(self.store); self.assertEqual(before["total"], 1)
        version = self.store.get("servers", self.host["id"])["_compiled"]["version"]
        self.store.update_server(source["id"], {"tags": {"role": "other"}}, "admin")
        after = deployments.listing(self.store)
        self.assertEqual(after["total"], 2)
        automatic = next(run for run in after["items"] if run["origin"] == "resolved_membership")
        current = deployments.targets(self.store, automatic["id"])["items"][0]
        self.assertGreater(current["version"], version)
        self.assertEqual(deployments.summary(self.store, before["items"][0]["id"])["superseded_count"], 1)

    def test_noop_metadata_monitor_baseline_and_explicit_save_do_not_create_automatic_tracker_noise(self):
        source, policy = self.automatic_fixture()
        self.assertEqual(deployments.listing(self.store)["total"], 1)
        self.store.update_server(source["id"], {"tags": {"role": "lb", "owner": "same-source"}}, "admin")
        self.assertEqual(deployments.listing(self.store)["total"], 1)
        self.store.save_policy({"name": policy["name"], "selector": policy["selector"], "group_ids": policy["group_ids"], "mode": policy["mode"], "services": policy["services"]}, "admin", policy["id"])
        self.assertEqual(deployments.listing(self.store)["total"], 2)
        self.assertTrue(all(run["origin"] != "resolved_membership" for run in deployments.listing(self.store)["items"]))

    def test_actual_go_marshaled_golden_is_admitted_without_rewriting_native_evidence(self):
        fixture = json.loads((Path(__file__).parent / "fixtures/policy-verification-v1.json").read_text())
        policy, receipt = fixture["policy"], fixture["receipt"]
        lease = policy["policy_verification"]
        original_id = self.host["id"]
        self.host.update(id=policy["server_id"], hostname=policy["server_id"], ips=fixture["ips"], protection=fixture["protection"], _compiled={key: policy[key] for key in ("version", "digest", "mode", "services")})
        managed = {**fixture["managed_enforcement"], "protection_digest": lease["protection_digest"], "approved_ips": fixture["ips"]}
        self.host["managed_enforcement"] = managed
        with self.store.meta() as db:
            self.store._put(db, "servers", self.host)
            db.execute("UPDATE managed_approvals SET server_id=?,version=?,digest=?,protection_digest=?,approval_id=? WHERE server_id=?", (self.host["id"], policy["version"], policy["digest"], lease["protection_digest"], lease["approval_id"], original_id))
        from controller.store import parse_time
        with patch.object(deployments, "now", return_value=parse_time(lease["starts_at"])), patch.object(deployments.uuid, "uuid4", side_effect=[lease["deployment_id"], lease["id"]]), self.store.meta() as db:
            run = deployments.create(self.store, db, [{"server_id": self.host["id"], "version": policy["version"], "digest": policy["digest"], "ports": lease["ports"]}], "admin", "Actual Go wire")
        with patch.object(deployments, "now", return_value=parse_time(receipt["checked_at"])):
            self.assertTrue(self.admit(receipt))
            actual = deployments.detail(self.store, run["id"], self.host["id"])
        self.assertEqual((actual["apply_status"], actual["traffic_status"], actual["already_present"]), ("applied", "verified", True))
        self.assertEqual(actual["ports"][0]["allow"]["evidence"], receipt["ports"][0]["allow"]["evidence"])
        self.assertEqual(actual["ports"][0]["deny"]["evidence"], receipt["ports"][0]["deny"]["evidence"])


class SQLitePolicyDeployments(DeploymentChecks, unittest.TestCase):
    pass


class ModernDeploymentIntegration(unittest.TestCase):
    def test_single_admin_bulk_rollout_immediately_publishes_tracking_and_signed_observation_scope(self):
        from controller.tests.test_approvals import IndependentApprovalTests
        fixture = IndependentApprovalTests("test_direct_admin_action_publishes_exact_signed_audit_proof_once")
        fixture.setUp(); self.addCleanup(fixture.doCleanups)
        with fixture.store.meta() as db:
            server = fixture.store._get(db, "servers", "target")
            server["capabilities"].append(deployments.CAPABILITY)
            fixture.store._put(db, "servers", server)
        plan = fixture.draft()
        self.assertEqual(plan["status"], "queued")
        self.assertEqual(plan["deployment"]["target_count"], 1)
        assigned = fixture.store.assignment("target")[0]
        self.assertEqual(assigned["enforcement"]["approval_proof"]["mode"], "single_admin")
        self.assertEqual(assigned["policy_verification"]["deployment_id"], plan["deployment"]["id"])
        self.assertEqual(assigned["policy_verification"]["approval_id"], plan["id"])
        self.assertEqual(deployments.targets(fixture.store, plan["deployment"]["id"])["total"], 1)


PG_NAMES = private_pg.names("policy_deploy")


@unittest.skipUnless(os.environ.get("PRTHAK_PLATFORM_PG_ACCEPTANCE") == "1", "Owner opt-in for private PostgreSQL deployment fixture")
class PostgreSQLPolicyDeployments(DeploymentChecks, unittest.TestCase):
    @classmethod
    def verify(cls, db, expected):
        user, directory, database = db.execute("SELECT current_user,current_setting('data_directory'),current_database()").fetchone()
        if user != "prthak_test" or Path(directory).resolve() != private_pg.data_directory() or database != expected:
            raise RuntimeError("Only the prepared private PostgreSQL deployment fixture is allowed")

    @classmethod
    def setUpClass(cls):
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import make_conninfo
        cls.driver, cls.sql = psycopg, sql
        cls.parameters = private_pg.parameters()
        with psycopg.connect(**cls.parameters, dbname="postgres", autocommit=True) as db:
            cls.verify(db, "postgres")
            for name in PG_NAMES.values():
                if db.execute("SELECT 1 FROM pg_database WHERE datname=%s", (name,)).fetchone():
                    raise RuntimeError("Refusing to reuse a pre-existing private fixture database")
                db.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
        cls.dsns = {namespace: make_conninfo(**cls.parameters, dbname=name) for namespace, name in PG_NAMES.items()}

    @classmethod
    def tearDownClass(cls):
        with cls.driver.connect(**cls.parameters, dbname="postgres", autocommit=True) as db:
            cls.verify(db, "postgres")
            for name in PG_NAMES.values():
                db.execute(cls.sql.SQL("DROP DATABASE {} WITH (FORCE)").format(cls.sql.Identifier(name)))

    def reset(self):
        for namespace, dsn in self.dsns.items():
            with self.driver.connect(dsn, autocommit=True) as db:
                self.verify(db, PG_NAMES[namespace])
                db.execute("DROP SCHEMA public CASCADE"); db.execute("CREATE SCHEMA public")

    def make_store(self):
        from controller.postgres import PostgresStore
        self.reset(); self.addCleanup(self.reset)
        return PostgresStore(self.dsns["metadata"], self.dsns["traffic"])
