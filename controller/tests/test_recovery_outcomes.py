"""Recovery receipts remain unverified evidence until fresh approved read-back."""
import copy
from datetime import timedelta
import unittest

from controller.store import now, stamp
from controller.tests import test_managed as fixture


class RecoveryReceiptTests(unittest.TestCase):
    protected = fixture.ManagedPolicyTests.protected
    report = fixture.ManagedPolicyTests.report
    draft = fixture.ManagedPolicyTests.draft
    approve = fixture.ManagedPolicyTests.approve
    outcome = fixture.ManagedPolicyTests.outcome
    mark_enforced = fixture.ManagedPolicyTests.mark_enforced

    def setUp(self):
        fixture.ManagedPolicyTests.setUp(self)

    def recovering(self, identifier="target", floor=100, compile_intent=True):
        with self.store.meta() as db:
            server = self.store._get(db, "servers", identifier)
            server.update(_recovery_version_floor=floor, recovery_reconciliation_required=True)
            self.store._put(db, "servers", server)
            if compile_intent:
                self.store.compile_all(db)

    @staticmethod
    def unknown(**extra):
        return {"status": "enforced", "version": 100, "digest": "b" * 64, "approval_id": "unknown-retained-authority", "last_good_version": 100, "last_good_digest": "b" * 64, "updated_at": stamp(), **extra}

    def test_bounded_unknown_receipt_preserves_inventory_without_claiming_applied_authority(self):
        self.recovering()
        histories, outcomes = len(self.store.all("bundle_history")), len(self.store.all("managed_outcomes"))
        self.report("target", "10.0.0.1", managed_enforcement=self.unknown(), applied_version=100, apply_status="synced")
        server = self.store.get("servers", "target")
        evidence = server["recovery_unverified_outcome"]
        self.assertEqual(evidence["status"], "unverified")
        self.assertEqual(evidence["original_status"], "enforced")
        self.assertTrue(evidence["evidence_only"])
        self.assertFalse(evidence["authorized"])
        self.assertFalse(server.get("_managed_rules_active", False))
        self.assertNotEqual(server.get("managed_enforcement", {}).get("status"), "enforced")
        self.assertEqual(len(self.store.all("managed_outcomes")), outcomes)
        self.assertEqual(len(self.store.all("bundle_history")), histories)
        assignment = self.store.assignment("target")[0]
        self.assertGreater(assignment["version"], 100)
        self.assertFalse(assignment["enforcement"]["authorized"])
        self.assertEqual(server["apply_status"], "pending")

    def test_normal_mode_above_floor_and_malformed_receipts_stay_strict(self):
        with self.assertRaises(PermissionError):
            self.report("target", "10.0.0.1", managed_enforcement=self.unknown())
        self.recovering()
        for value in (self.unknown(version=101), self.unknown(last_good_version=101), self.unknown(version=True), self.unknown(updated_at=stamp(now() + timedelta(hours=1))), self.unknown(digest="invalid-hash")):
            with self.subTest(version=value["version"], last_good=value["last_good_version"], digest=value["digest"]):
                with self.assertRaises((PermissionError, ValueError)):
                    self.report("target", "10.0.0.1", managed_enforcement=value)
        self.assertNotIn("recovery_unverified_outcome", self.store.get("servers", "target"))

    def test_known_bundle_or_approval_identity_with_changed_digest_is_never_adopted(self):
        approved = self.approve()
        outcome = self.outcome()
        self.recovering(floor=100, compile_intent=False)
        for payload in ({**outcome, "digest": "f" * 64}, self.unknown(approval_id=approved["id"]), {**outcome, "last_good_version": outcome["version"], "last_good_digest": "c" * 64}):
            with self.assertRaises((PermissionError, ValueError)):
                self.report("target", "10.0.0.1", managed_enforcement=payload)
        self.assertNotIn("recovery_unverified_outcome", self.store.get("servers", "target"))

    def test_another_endpoint_approval_cannot_become_recovery_evidence(self):
        self.approve()
        payload = self.outcome()
        self.recovering(identifier="source", floor=100, compile_intent=False)
        with self.assertRaises(PermissionError):
            self.report("source", "10.0.0.2", managed_enforcement=payload)
        self.assertNotIn("recovery_unverified_outcome", self.store.get("servers", "source"))

    def test_fresh_higher_approved_readback_clears_reconciliation_flag(self):
        self.recovering()
        self.report("target", "10.0.0.1", managed_enforcement=self.unknown(), applied_version=100)
        self.approve()
        payload = self.outcome()
        self.assertGreater(payload["version"], 100)
        self.report("target", "10.0.0.1", managed_enforcement=payload, applied_version=payload["version"], apply_status="synced")
        server = self.store.get("servers", "target")
        self.assertNotIn("recovery_reconciliation_required", server)
        self.assertNotIn("recovery_unverified_outcome", server)
        self.assertEqual(server["managed_enforcement"]["status"], "enforced")
        self.assertTrue(server["_managed_rules_active"])
        self.assertEqual(len(self.store.all("managed_outcomes")), 1)

    def test_recovery_evidence_cannot_erase_a_previously_known_managed_baseline(self):
        self.mark_enforced()
        before = copy.deepcopy(self.store.get("servers", "target"))
        self.recovering(floor=100, compile_intent=False)
        with self.assertRaises(ValueError):
            self.report("target", "10.0.0.1", managed_enforcement=self.unknown(status="rolled_back", last_good_version=0, last_good_digest=""))
        after = self.store.get("servers", "target")
        self.assertEqual(after["last_good_version"], before["last_good_version"])
        self.assertTrue(after["_managed_rules_active"])


if __name__ == "__main__":
    unittest.main()
