import copy
import csv
import io
import ipaddress
import tempfile
import unittest
from datetime import timedelta
from unittest.mock import patch

from controller import learning_policies as lp
from controller import server_management as lifecycle
from controller.firewall import WorkflowConflict
from controller.store import Store, digest, now, stamp


class LearningPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(self.temp.name)
        self.store.lab_approvals = True  # Explicit isolated automatic-learning lab fixture.
        self.baseline = {"management_sources": ["10.99.0.0/24"], "ssh_ports": [2022], "controller_url": "https://controller.example", "management_probe_url": "https://controller.example/api/v1/agent/enforcement/check", "zone": "public"}
        self.report("a", "10.1.0.1")
        self.report("b", "10.1.0.2")

    def report(self, identifier, address, **extra):
        listeners = [{"port": port, "protocol": "tcp", "address": "0.0.0.0", "service": service, "process": process} for port, service, process in ((80, "HTTP", "nginx"), (5432, "PostgreSQL", "postgres"), (2022, "SSH", "sshd"))]
        return self.store.report(identifier, {"hostname": identifier, "ips": [address], "listeners": listeners, "discovery_performed": True, "discovered_at": stamp(), "firewalld_state": "running", "agent_version": "0.4.0", "capabilities": ["learning_discovery_v1", "learning_auto_allow_v1"], "protection": {**self.baseline, "digest": digest(self.baseline), "ready": True, "blockers": []}, **extra})

    def session(self, auto=True):
        session = self.store.create_session({"server_ids": ["a"], "selection_mode": "discovered", "duration_seconds": 3600, "policy_action": "auto_allow" if auto else "observe", "auto_allow_confirmed": auto}, "admin")
        self.report("a", "10.1.0.1", learning_discovery_session_ids=[session["id"]])
        return session

    def batch(self, session, rows, identifier="batch-1"):
        events = [{"source_ip": source, "port": port, "protocol": "tcp", "count": count, "verdict": "observed", "first_seen": stamp(), "last_seen": stamp()} for source, port, count in rows]
        self.store.enqueue_flows("a", {"batch_id": identifier, "session_id": session["id"], "events": events})
        self.store.process_flows()

    def assignment(self, identifier="a"):
        return self.store.assignment(identifier)[0]["learning_allow"]

    def ack(self, body, status="applied", **extra):
        return self.report("a", "10.1.0.1", learning_allow_outcome={"generation": body["generation"], "digest": body["digest"], "binding_digest": body["binding_digest"], "status": status, **extra})

    def test_auto_preserves_exact_source_service_pairs_and_normal_policy_authority(self):
        session = self.session()
        ordinary = self.store.assignment("a")[0]
        self.batch(session, [("10.20.0.1", 80, 3), ("10.20.0.2", 5432, 4), ("2001:db8::10", 80, 1)])
        recommendation = lp.recommendations(self.store, session["id"])
        self.assertEqual(recommendation["total_rows"], 3)
        services = {row["port"]: row for row in self.assignment()["services"]}
        self.assertEqual(services[80]["sources"], ["10.20.0.1/32", "2001:db8::10/128"])
        self.assertEqual(services[5432]["sources"], ["10.20.0.2/32"])
        self.assertTrue(self.assignment()["authorized"])
        self.assertEqual({row["service"] for row in recommendation["rows"]}, {"HTTP", "PostgreSQL"})
        current = self.store.assignment("a")[0]
        self.assertEqual((current["version"], current["digest"], current["enforcement"]), (ordinary["version"], ordinary["digest"], ordinary["enforcement"]))
        self.assertFalse(self.assignment("b")["authorized"])
        self.assertEqual(self.store.all("managed_approvals"), [])

    def test_batch_receipt_is_replay_safe_and_evidence_survives_pruning(self):
        session = self.session(False)
        self.batch(session, [("10.20.0.1", 80, 3)])
        with self.store.traffic() as db:
            db.execute("UPDATE batches SET evidence_processed=0")
        self.store.process_flows()
        self.assertEqual(lp.recommendations(self.store, session["id"])["rows"][0]["count"], 3)
        self.store = Store(self.temp.name)
        self.store.lab_approvals = True  # Explicit isolated automatic-learning lab fixture.
        with patch("controller.store.now", return_value=now() + timedelta(days=2)):
            self.store.prune()
        self.assertEqual(lp.recommendations(self.store, session["id"])["rows"][0]["count"], 3)

    def test_auto_excludes_management_and_nonunicast_sources(self):
        session = self.session()
        self.batch(session, [("10.20.0.1", 2022, 2), ("224.0.0.2", 80, 1), ("0.0.0.0", 80, 1), ("10.20.0.2", 80, 2)])
        rows = lp.recommendations(self.store, session["id"])["rows"]
        self.assertEqual(sum(row["eligible_for_auto"] for row in rows), 1)
        self.assertEqual(self.assignment()["services"], [{"port": 80, "protocol": "tcp", "sources": ["10.20.0.2/32"]}])

    def test_stop_halts_new_auto_additions_without_removing_committed_policy(self):
        session = self.session()
        self.batch(session, [("10.20.0.1", 80, 1)])
        before = self.assignment()
        self.ack(before)
        self.store.stop_session(session["id"], "admin")
        self.batch(session, [("10.20.0.2", 80, 1)], "late-batch")
        after = self.assignment()
        self.assertEqual(after["services"], before["services"])
        self.assertFalse(after["authorized"])
        self.assertEqual(lp.recommendations(self.store, session["id"])["total_rows"], 2)
        self.assertEqual(len(lp.listing(self.store)), 1)

    def test_capacity_blocks_new_candidates_without_widening_or_erasing_existing(self):
        session = self.session()
        sources = [str(ipaddress.IPv4Address("10.20.0.1") + index) for index in range(65)]
        self.batch(session, [(source, 80, 1) for source in sources[:64]])
        before = self.assignment()
        self.assertEqual(len(before["services"][0]["sources"]), 64)
        self.batch(session, [(sources[64], 80, 1)], "batch-2")
        self.assertEqual(self.assignment()["services"], before["services"])
        policy = lp.listing(self.store)[0]
        self.assertEqual(policy["status"], "blocked")
        self.assertIn("64", policy["error"])

    def test_capability_enabled_learning_retains_five_thousand_exact_sources_and_downgrade_blocks(self):
        session = self.session()
        capabilities = ["learning_discovery_v1", "learning_auto_allow_v1", "learning_ipsets_v1"]
        self.report("a", "10.1.0.1", capabilities=capabilities)
        sources = [str(ipaddress.IPv4Address("10.20.0.1") + index) for index in range(5000)]
        for offset in range(0, len(sources), 1000):
            self.batch(session, [(source, 80, 1) for source in sources[offset:offset+1000]], "large-"+str(offset))
        assigned = self.assignment()
        self.assertTrue(assigned["authorized"], assigned["reason"])
        self.assertEqual(assigned["services"], [{"port": 80, "protocol": "tcp", "sources": sorted(source+"/32" for source in sources)}])
        self.assertEqual(lp.recommendations(self.store, session["id"])["total_rows"], 5000)
        self.report("a", "10.1.0.1")
        downgraded = self.assignment()
        self.assertFalse(downgraded["authorized"])
        self.assertIn("64", downgraded["reason"])
        self.assertEqual(downgraded["services"], assigned["services"])

    def test_new_source_capacity_does_not_bypass_host_family_bank_or_service_bounds(self):
        server = {"capabilities": ["learning_ipsets_v1"]}
        services = [{"port": 8000+index, "protocol": "tcp", "sources": [f"10.20.0.{index+1}/32", "2001:db8::1/128"]} for index in range(33)]
        self.assertIn("32 distinct", lp._capacity_error(server, services))
        self.assertIn("10000", lp._capacity_error(server, [{"port": 443, "protocol": "tcp", "sources": [str(ipaddress.IPv4Address("10.20.0.1")+index)+"/32" for index in range(10001)]}]))

    def test_over_capacity_automatic_evidence_is_blocked_without_loading_or_partial_grant(self):
        session=self.session()
        self.report('a','10.1.0.1',capabilities=['learning_discovery_v1','learning_auto_allow_v1','learning_ipsets_v1'])
        self.batch(session,[('10.20.0.1',80,1)])
        before=self.assignment()['services']
        with self.store.meta() as db:
            original=lp._evidence(db,session['id'],'a')[0]
            for index in range(10000):
                source=str(ipaddress.IPv4Address('10.21.0.1')+index)
                lp._put_evidence(db,{**original,'id':f'overflow-{index:05d}','source_ip':source,'source_cidr':source+'/32'})
        with patch.object(lp,'_evidence',side_effect=AssertionError('Oversized authority evidence must not be materialized or truncated')):
            self.batch(session,[('10.22.0.1',80,1)],'overflow-batch')
        self.assertEqual(self.assignment()['services'],before)
        self.assertEqual(lp.listing(self.store)[0]['status'],'blocked')
        self.assertIn('bounded automatic-source review capacity',lp.listing(self.store)[0]['error'])
        public=lp.recommendations(self.store,session['id'],limit=2)
        self.assertEqual((public['total_rows'],len(public['rows'])),(10002,2))

    def test_user_edit_and_delete_suppress_auto_recreation_and_wait_for_cleanup_ack(self):
        session = self.session()
        self.batch(session, [("10.20.0.1", 80, 1), ("10.20.0.2", 5432, 1)])
        self.ack(self.assignment())
        policy = lp.listing(self.store)[0]
        edited = lp.update(self.store, policy["id"], {"expected_revision": policy["revision"], "services": [{"port": 80, "protocol": "tcp", "sources": ["10.20.0.1/32"]}]}, "admin")
        self.batch(session, [("10.20.0.2", 5432, 1), ("10.20.0.3", 80, 1)], "later")
        self.assertEqual(lp.get(self.store, policy["id"])["services"], edited["services"])
        removed = lp.remove(self.store, policy["id"], {"expected_revision": edited["revision"]}, "admin")
        self.assertTrue(removed["removed"])
        self.assertTrue(removed["removal_pending"])
        cleanup = self.assignment()
        self.assertEqual(cleanup["services"], [])
        self.assertTrue(cleanup["authorized"])
        self.assertEqual(cleanup["authorities"][0]["kind"], "reviewed")
        self.assertEqual(len(lp.listing(self.store)), 1)
        with self.store.read_meta() as db:
            self.assertTrue(lp.retirement_blockers(self.store, db, self.store._get(db, "servers", "a")))
        self.ack(cleanup, "blocked", error="offline")
        self.assertTrue(lp.listing(self.store)[0]["removal_pending"])
        self.ack(cleanup)
        self.assertEqual(lp.listing(self.store), [])
        with self.store.read_meta() as db:
            self.assertEqual(lp.retirement_blockers(self.store, db, self.store._get(db, "servers", "a")), [])
        self.batch(session, [("10.20.0.1", 80, 1)], "last")
        self.assertEqual(lp.listing(self.store), [])

    def test_review_group_membership_and_evidence_changes_invalidate_preview(self):
        session = self.session(False)
        self.batch(session, [("10.20.0.1", 80, 1), ("10.20.0.2", 5432, 1)])
        evidence = lp.recommendations(self.store, session["id"])
        group = self.store.save_group({"name": "Targets", "type": "static", "server_ids": ["b"]}, "admin")
        body = {"row_ids": [row["id"] for row in evidence["rows"]], "group_ids": [group["id"]], "expected_evidence_revision": evidence["evidence_revision"]}
        plan = lp.preview(self.store, session["id"], body, "admin")
        self.store.save_group({**group, "server_ids": ["a", "b"]}, "admin", group["id"])
        with self.assertRaises(WorkflowConflict):
            lp.apply(self.store, session["id"], {"preview_id": plan["id"], "digest": plan["digest"], "confirm": True}, "admin")
        plan = lp.preview(self.store, session["id"], body, "admin")
        result = lp.apply(self.store, session["id"], {"preview_id": plan["id"], "digest": plan["digest"], "confirm": True}, "admin")
        self.assertEqual(result["target_server_ids"], ["a", "b"])
        for policy in result["policies"]:
            self.assertEqual(policy["services"], [{"port": 80, "protocol": "tcp", "sources": ["10.20.0.1/32"]}, {"port": 5432, "protocol": "tcp", "sources": ["10.20.0.2/32"]}])
        self.assertEqual(self.store.all("managed_approvals"), [])

    def test_authority_binds_exact_historical_generation_and_protected_ips(self):
        session = self.session()
        self.batch(session, [("10.20.0.1", 80, 1)])
        body = self.assignment()
        witness = lp.verify_assignment(self.store, "a", body)
        self.assertEqual(witness["version"], body["generation"])
        with self.assertRaises(PermissionError):
            lp.verify_assignment(self.store, "a", {**body, "digest": "bad"})
        self.report("a", "10.1.0.8")
        self.assertFalse(self.assignment()["authorized"])
        with self.assertRaises(PermissionError):
            self.ack({**body, "binding_digest": "bad"})

    def test_export_is_complete_beyond_aggregate_limit_and_formula_safe(self):
        self.report("a", "10.1.0.1", hostname="=evil()")
        session = self.session(False)
        sources = [str(ipaddress.IPv4Address("10.23.0.1") + index) for index in range(600)]
        self.batch(session, [(source, 80, 1) for source in sources])
        data = lp.recommendations(self.store, session["id"], limit=200)
        self.assertEqual(data["total_rows"], 600)
        self.assertTrue(data["has_more"])
        self.report("a", "10.1.0.1", hostname="=evil()")
        rows = list(csv.DictReader(io.StringIO(lp.export_csv(self.store, session["id"]))))
        self.assertEqual(len(rows), 600)
        self.assertEqual(rows[0]["hostname"], "'=evil()")

    def test_legacy_agent_cannot_receive_authority_and_is_blocked_in_review(self):
        session = self.session()
        self.batch(session, [("10.20.0.1", 80, 1)])
        self.report("a", "10.1.0.1", capabilities=["learning_discovery_v1"], agent_version="0.3.0")
        self.assertFalse(self.assignment()["authorized"])
        self.assertIn("Upgrade", self.assignment()["reason"])
        evidence = lp.recommendations(self.store, session["id"])
        plan = lp.preview(self.store, session["id"], {"server_ids": ["a"], "row_ids": [evidence["rows"][0]["id"]], "expected_evidence_revision": evidence["evidence_revision"]}, "admin")
        self.assertTrue(any("Upgrade" in reason for reason in plan["targets"][0]["blocked_reasons"]))
        with self.assertRaises(ValueError):
            lp.apply(self.store, session["id"], {"preview_id": plan["id"], "digest": plan["digest"], "confirm": True}, "admin")

    def test_failed_auto_grant_is_held_across_new_hits_until_explicit_review(self):
        session = self.session()
        self.batch(session, [("10.20.0.1", 80, 1)])
        failed = self.assignment()
        self.ack(failed, "rolled_back", error="management health failed")
        self.batch(session, [("10.20.0.2", 5432, 1)], "after-failure")
        held = self.assignment()
        self.assertEqual(held["services"], failed["services"])
        self.assertFalse(held["authorized"])
        self.assertEqual(self.store.get("sessions", session["id"])["auto_allow_paused_server_ids"], ["a"])
        policy = lp.listing(self.store)[0]
        self.assertTrue(policy["auto_held"])
        lp.update(self.store, policy["id"], {"expected_revision": policy["revision"], "services": policy["services"]}, "admin")
        reviewed = self.assignment()
        self.assertTrue(reviewed["authorized"])
        self.assertEqual(reviewed["authorities"][0]["kind"], "reviewed")

    def test_current_block_reason_reaches_policy_and_applied_clears_endpoint_error(self):
        session = self.session()
        self.batch(session, [("10.20.0.1", 80, 1)])
        body = self.assignment()
        reason = "Synthetic UI fixture: no real endpoint firewall is connected."
        self.ack(body, "blocked", error=reason)
        policy = lp.listing(self.store)[0]
        self.assertEqual(policy["status"], "blocked")
        self.assertEqual(policy["error"], reason)
        self.assertEqual(policy["endpoint_error"], reason)
        self.assertEqual(policy["last_outcome"]["generation"], body["generation"])
        self.ack(body)
        applied = lp.listing(self.store)[0]
        self.assertEqual(applied["status"], "applied")
        self.assertEqual(applied["error"], "")
        self.assertEqual(applied["endpoint_error"], "")

    def test_stale_historical_receipts_cannot_replace_newer_policy_reason(self):
        session = self.session()
        self.batch(session, [("10.20.0.1", 80, 1)])
        old = self.assignment()
        self.ack(old, "blocked", error="Old generation: waiting for configuration")
        self.batch(session, [("10.20.0.2", 5432, 1)], "new-generation")
        latest = self.assignment()
        self.assertGreater(latest["generation"], old["generation"])
        reason = "Current generation: controller health probe unavailable"
        self.ack(latest, "blocked", error=reason)
        self.ack(old, "blocked", error="Late old blocked receipt")
        self.assertEqual(lp.listing(self.store)[0]["error"], reason)
        self.assertEqual(self.store.get("servers", "a")["learning_allow_outcome"]["generation"], latest["generation"])
        self.ack(old, "error", error="Late old mutating error")
        policy = lp.listing(self.store)[0]
        self.assertEqual(policy["error"], reason)
        self.assertEqual(policy["last_outcome"]["generation"], latest["generation"])
        self.assertTrue(policy["auto_held"])
        self.ack(latest)
        self.assertEqual(lp.listing(self.store)[0]["error"], "")
        self.ack(old, "error", error="Ancient failure after newer apply")
        self.assertEqual(lp.listing(self.store)[0]["error"], "")

    def verified_empty_cleanup(self):
        session = self.session()
        self.batch(session, [("10.20.0.1", 80, 1)])
        self.ack(self.assignment())
        self.store.stop_session(session["id"], "admin")
        policy = lp.listing(self.store)[0]
        lp.remove(self.store, policy["id"], {"expected_revision": policy["revision"]}, "admin")
        cleanup = self.assignment()
        self.ack(cleanup)
        return cleanup, policy["id"]

    def test_retirement_review_survives_identical_verified_cleanup_receipts(self):
        cleanup, policy_id = self.verified_empty_cleanup()
        plan = lifecycle.delete_preview(self.store, "a", "admin")
        self.assertTrue(plan["can_delete"], plan["blockers"])
        original_clock = lp.get(self.store, policy_id)["last_outcome"]["updated_at"]
        for seconds in (2, 4):
            with patch("controller.store.now", return_value=now() + timedelta(seconds=seconds)):
                self.ack(cleanup)
        self.assertNotEqual(lp.get(self.store, policy_id)["last_outcome"]["updated_at"], original_clock)
        result = lifecycle.delete_confirm(self.store, "a", {"plan_id": plan["id"], "confirmation_nonce": plan["confirmation_nonce"]}, "admin")
        self.assertEqual(result["status"], "applied")

    def test_retirement_review_still_rejects_real_learning_and_target_changes(self):
        _, policy_id = self.verified_empty_cleanup()
        mutations = [("learning_allow_hosts", "a", "generation", 999),
                     ("learning_allow_hosts", "a", "status", "blocked"),
                     ("learning_allow_hosts", "a", "services", [{"port": 80, "protocol": "tcp", "sources": ["10.20.0.1/32"]}]),
                     ("servers", "a", "ips", ["10.1.0.99"]),
                     ("servers", "a", "protection_digest", "changed-protection")]
        for table, identifier, field, changed in mutations:
            with self.subTest(field=field):
                plan = lifecycle.delete_preview(self.store, "a", "admin")
                self.assertTrue(plan["can_delete"])
                with self.store.meta() as db:
                    original = self.store._get(db, table, identifier)
                    row = copy.deepcopy(original)
                    row[field] = changed
                    self.store._put(db, table, row)
                with self.assertRaises(WorkflowConflict):
                    lifecycle.delete_confirm(self.store, "a", {"plan_id": plan["id"], "confirmation_nonce": plan["confirmation_nonce"]}, "admin")
                with self.store.meta() as db:
                    self.store._put(db, table, original)


if __name__ == "__main__":
    unittest.main()
