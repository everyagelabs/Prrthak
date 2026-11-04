"""Exact signed maintenance stays separate from ordinary policy enforcement."""
import copy
from datetime import timedelta
from email.message import Message
from pathlib import Path
import socket
import types
import tempfile
import unittest
from unittest.mock import patch

from controller import firewall_activation as activation, notifications
from controller.app import App, handler_for
from controller.firewall import WorkflowConflict
from controller.management_health import ManagementHealth
from controller.platform import PlatformManager
from controller.store import now, stamp
from controller.tests import test_approvals as fixture


class FirewallActivationTests(unittest.TestCase):
    person = fixture.IndependentApprovalTests.person

    def setUp(self):
        fixture.IndependentApprovalTests.setUp(self)
        with self.store.meta() as db:
            host = self.store._get(db, "servers", "target")
            host["capabilities"].extend((activation.CAPABILITY, activation.AGENT_ONLY_CAPABILITY))
            host["configuration_state"] = {"digest": "d" * 64}
            # Activation has its own native health admission, not a false claim
            # that an inactive daemon meets normal enforcement readiness.
            host["protection"]["ready"] = False
            host["protection"]["blockers"] = ["firewalld is inactive"]
            host["firewalld_state"] = "not running"
            self.store._put(db, "servers", host)

    def scope(self, operation="activate_existing"):
        return {"server_ids": ["target"], "operation": operation}

    def assess(self, operation="activate_existing"):
        return activation.assess(self.store, self.scope(operation), self.maker["actor"], self.maker)

    def receipt(self, status="assessed", **changes):
        host = self.store.get("servers", "target")
        job = host[activation.JOB]
        facts = {"firewalld_active": False, "firewalld_enabled": "disabled", "ufw_active": False,
                 "ufw_enabled": "absent", "version": "2.3.1", "backend": "nftables", "zone": "public",
                 "ips": host["ips"], "ssh_ports": [2022], "management_sources": ["10.90.0.0/24"],
                 "discovered_ports": [{"port": 2022, "protocol": "tcp"}, {"port": 8443, "protocol": "tcp"}],
                 "translated_rules": [], "can_apply": True, "blockers": [], "notes": ["Business services may be blocked"]}
        value = {"schema_version": 1, **{key: job[key] for key in ("id", "operation", "target_operation", "plan_digest", "configuration_digest")},
                 "baseline_digest": job["baseline_digest"] or "a" * 64, "protection_digest": job["protection_digest"] or host["protection_digest"],
                 "status": status, "checked_at": stamp(), "assessment": facts, **changes}
        self.store.report("target", {"hostname": host["hostname"], "ips": host["ips"], "capabilities": host["capabilities"],
             "discovery_performed": False, "listeners": [], "firewalld_state": host["firewalld_state"], "firewall_activation": value})
        return value

    def preview(self, operation="activate_existing"):
        self.assess(operation); self.receipt()
        return activation.preview(self.store, self.scope(operation), self.maker["actor"], self.maker)

    @staticmethod
    def payload(plan, **changes):
        return {"digest": plan["digest"], "confirmation_nonce": plan["confirmation_nonce"],
                "confirmation_phrase": activation.CHALLENGE, "acknowledge_downtime": True, **changes}

    def confirm(self, plan):
        return activation.confirm(self.store, plan["id"], self.payload(plan), self.maker["actor"], self.maker)

    def health(self, ssh_ports=None):
        assigned = self.store.assignment("target")[0]["firewall_activation"]
        return {**{key: assigned[key] for key in ("id", "plan_digest", "baseline_digest", "protection_digest", "configuration_digest")}, "nonce": "b" * 32, "ssh_ports": [] if ssh_ports is None else ssh_ports}

    def test_assessment_does_not_enable_policy_or_fake_generic_readiness(self):
        before = self.store.assignment("target")[0]
        self.assess()
        after = self.store.assignment("target")[0]
        self.assertEqual((before["version"], before["digest"], before["services"]), (after["version"], after["digest"], after["services"]))
        self.assertEqual(after["firewall_activation"]["operation"], "assess")
        self.assertNotIn("approval_proof", after["firewall_activation"])
        self.assertFalse(self.store.get("servers", "target")["protection"]["ready"])
        self.receipt()
        self.assertNotIn("firewall_activation", self.store.assignment("target")[0])

    def test_waiting_assessment_is_reused_and_reports_only_the_actual_blocker(self):
        plan = activation.preview(self.store, self.scope(), self.maker["actor"], self.maker)
        self.assertEqual(plan["targets"][0]["blockers"], ["Request a fresh assessment for this operation"])
        requested = self.assess()["items"][0]["id"]
        self.assertEqual(self.assess()["items"][0]["id"], requested)
        plan = activation.preview(self.store, self.scope(), self.maker["actor"], self.maker)
        self.assertEqual(plan["targets"][0]["blockers"], ["Waiting for the agent to finish this assessment"])
        self.receipt("blocked", assessment=None, error="pin restricted SSH management source IPs or CIDRs")
        plan = activation.preview(self.store, self.scope(), self.maker["actor"], self.maker)
        self.assertEqual(plan["targets"][0]["blockers"], ["pin restricted SSH management source IPs or CIDRs"])

    def test_preview_checks_current_witness_scope_and_canonical_interface_addresses(self):
        self.assess("prepare_egress")
        host = self.store.get("servers", "target")
        self.receipt(assessment={"firewalld_active": False, "firewalld_enabled": "disabled", "ufw_active": False,
                                "ufw_enabled": "absent", "version": "2.3.1", "backend": "nftables", "zone": "public",
                                "ips": host["ips"] * 2, "ssh_ports": [2022], "management_sources": ["10.90.0.0/24"],
                                "discovered_ports": [], "translated_rules": [], "can_apply": True, "blockers": [], "notes": []})
        preview = lambda health: activation.preview(self.store, self.scope("prepare_egress"), self.maker["actor"], self.maker, management_health=health)
        self.assertIn("Platform settings", preview(ManagementHealth("", []))["targets"][0]["blockers"][0])
        self.assertTrue(preview(ManagementHealth("10.90.0.5", ["10.70.0.0/24"]))["can_apply"])

    def test_start_admits_only_exact_authenticated_agent_witness_without_ssh(self):
        self.assess()
        facts = self.receipt()["assessment"]
        self.receipt(assessment={**facts, "ssh_ports": [], "management_sources": []})
        app = App(self.store, auth=self.auth)
        app.management_health = ManagementHealth("", [])
        with patch.object(app.management_health, "_targets", side_effect=AssertionError("SSH must not be used")):
            plan = activation.preview(self.store, self.scope(), self.maker["actor"], self.maker, management_health=app.management_health)
            self.assertTrue(plan["can_apply"], plan["blockers"])
            activation.confirm(self.store, plan["id"], self.payload(plan), self.maker["actor"], self.maker, management_health=app.management_health)
            request = self.health()

            def check(body, identity="target"):
                handler = object.__new__(handler_for(app))
                handler.command, handler.path, handler.connection = "POST", "/api/v1/agent/firewall-activation/check", object()
                handler.client_address, handler.headers = ("127.0.0.1", 12345), Message()
                handler.body = lambda: body
                result = {}
                handler.response = lambda status, value=None, headers=None: result.update(status=status, value=value)
                with patch.object(app, "endpoint_identity", return_value=identity):
                    handler.dispatch()
                return result

            self.assertEqual(check({**request, "ssh_ports": [2022]})["status"], 400)
            self.assertEqual(check({**request, "nonce": "invalid"})["status"], 400)
            self.assertEqual(check({**request, "plan_digest": "f" * 64})["status"], 403)
            self.assertEqual(check(request, identity="different-endpoint")["status"], 403)
            self.assertNotIn("admitted_at", self.store.get("servers", "target")[activation.JOB])
            proof = check(request)
            self.assertEqual(proof["status"], 200, proof)
            self.assertEqual(proof["value"]["health_mode"], activation.AGENT_ONLY_MODE)
            self.assertEqual(proof["value"]["ssh_checks"], [])
            self.assertTrue(proof["value"]["controller_ok"])
            for key in set(request) - {"ssh_ports"}:
                self.assertEqual(proof["value"][key], request[key])
            self.assertIn("admitted_at", self.store.get("servers", "target")[activation.JOB])

    def test_start_requires_upgraded_agent_and_new_assessment_mode(self):
        old = self.assess()["items"][0]["id"]
        with self.store.meta() as db:
            host = self.store._get(db, "servers", "target")
            host[activation.JOB].pop("health_mode")
            self.store._put(db, "servers", host)
        self.receipt()
        plan = activation.preview(self.store, self.scope(), self.maker["actor"], self.maker)
        self.assertFalse(plan["can_apply"])
        self.assertNotEqual(self.assess()["items"][0]["id"], old)
        with self.store.meta() as db:
            host = self.store._get(db, "servers", "target")
            host["capabilities"].remove(activation.AGENT_ONLY_CAPABILITY)
            self.store._put(db, "servers", host)
        self.assertNotIn("firewall_activation", self.store.assignment("target")[0])
        with self.assertRaises(WorkflowConflict) as blocked:
            self.assess()
        self.assertIn("Upgrade this endpoint's agent", str(blocked.exception.plan))
        self.assertEqual(self.assess("migrate_ufw")["count"], 1)

    def test_stop_and_allow_all_recheck_managed_conflicts_before_review_and_witness(self):
        for operation in sorted(activation.MANAGED_POLICY_CONFLICT_OPERATIONS):
            with self.subTest(operation=operation), self.assertRaises(WorkflowConflict) as blocked:
                self.assess(operation)
            self.assertIn("pending managed enforcement", str(blocked.exception.plan))
        for policy in self.store.all("policies"):
            self.store.delete_policy(policy["id"], self.maker["actor"])
        for operation in sorted(activation.MANAGED_POLICY_CONFLICT_OPERATIONS):
            with self.subTest(operation=operation):
                plan = self.preview(operation)
                self.assertTrue(plan["can_apply"], plan["blockers"])
                with self.store.meta() as db:
                    host = self.store._get(db, "servers", "target")
                    host["_managed_rules_active"] = True
                    self.store._put(db, "servers", host)
                with self.assertRaises(WorkflowConflict):
                    self.confirm(plan)
                with self.store.meta() as db:
                    host = self.store._get(db, "servers", "target")
                    host.pop("_managed_rules_active")
                    self.store._put(db, "servers", host)
                self.confirm(plan)
                request = self.health()
                self.assertEqual(activation.verify(self.store, "target", request)["health_mode"], activation.AGENT_ONLY_MODE)
                with self.store.meta() as db:
                    host = self.store._get(db, "servers", "target")
                    host["network_control"] = {"egress": {"active": True}}
                    self.store._put(db, "servers", host)
                with self.assertRaises(PermissionError):
                    activation.verify(self.store, "target", request)
                with self.store.meta() as db:
                    host = self.store._get(db, "servers", "target")
                    host.pop("network_control")
                    self.store._put(db, "servers", host)
                self.receipt("rolled_back")

    def test_all_operations_require_fresh_review_phrase_and_manual_ack_same_admin(self):
        for policy in self.store.all("policies"):
            self.store.delete_policy(policy["id"], self.maker["actor"])
        for operation in sorted(activation.OPERATIONS):
            with self.subTest(operation=operation):
                plan = self.preview(operation)
                self.assertTrue(plan["can_apply"], plan["blockers"])
                for changes in ({"confirmation_phrase": "yes"}, {"acknowledge_downtime": False}, {"acknowledge_downtime": 1}, {"confirmation_nonce": "wrong"}, {"digest": "f" * 64}):
                    with self.assertRaises((ValueError, WorkflowConflict)):
                        activation.confirm(self.store, plan["id"], self.payload(plan, **changes), self.maker["actor"], self.maker)
                with self.assertRaises(WorkflowConflict):
                    activation.confirm(self.store, plan["id"], self.payload(plan), self.checker["actor"], self.checker)
                self.confirm(plan)
                job = self.store.assignment("target")[0]["firewall_activation"]
                self.assertEqual(job["approval_proof"]["mode"], "single_admin")
                self.assertEqual(job["approval_proof"]["scope"], {"kind": "firewall_activation", "server_ids": ["target"]})
                self.receipt("completed")
                with self.assertRaises(WorkflowConflict): self.confirm(plan)

    def test_expired_assessment_and_changed_addresses_configuration_or_policy_block_review(self):
        self.assess(); self.receipt(checked_at=stamp(now() - timedelta(minutes=4)))
        self.assertFalse(activation.preview(self.store, self.scope(), self.maker["actor"], self.maker)["can_apply"])
        for field, changed in (("ips", ["10.70.0.2"]), ("configuration_state", {"digest": "e" * 64}), ("desired_version", 999)):
            plan = self.preview()
            with self.store.meta() as db:
                host = self.store._get(db, "servers", "target"); before = copy.deepcopy(host[field]); host[field] = changed; self.store._put(db, "servers", host)
            with self.subTest(field=field), self.assertRaises(WorkflowConflict): self.confirm(plan)
            with self.store.meta() as db:
                host = self.store._get(db, "servers", "target"); host[field] = before; self.store._put(db, "servers", host)

    def test_invalid_receipt_is_atomic_and_cannot_change_reviewed_binding(self):
        self.confirm(self.preview()); host = self.store.get("servers", "target")
        for changes in ({"baseline_digest": "e" * 64}, {"operation": []}, {"assessment": {}}, {"error": "é" * 513}, {"status": []}, {"checked_at": stamp(now()+timedelta(minutes=2))}, {"raw_private_config": "no"}):
            job = host[activation.JOB]
            good = {"schema_version": 1, **{key: job[key] for key in ("id", "operation", "target_operation", "plan_digest", "configuration_digest", "baseline_digest", "protection_digest")}, "status": "completed", "checked_at": stamp(), **changes}
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.store.report("target", {"hostname": "must-not-save", "ips": host["ips"], "firewall_activation": good})
            self.assertEqual(self.store.get("servers", "target"), host)

    def test_terminal_and_superseded_receipts_do_not_rearm_old_work(self):
        self.confirm(self.preview()); completed = self.receipt("completed")
        self.receipt("applying", checked_at=stamp(now()+timedelta(seconds=1)))
        self.assertEqual(self.store.get("servers", "target")[activation.RECEIPT], completed)
        self.assess()
        with self.store.meta() as db:
            host = self.store._get(db, "servers", "target"); activation.report(self.store, db, host, completed); self.store._put(db, "servers", host)
        self.assertEqual(self.store.assignment("target")[0]["firewall_activation"]["operation"], "assess")

    def test_admitted_uncertain_mutation_cannot_be_overwritten_even_after_expiry(self):
        self.confirm(self.preview()); request = self.health()
        witness = activation.verify(self.store, "target", request)
        self.assertEqual(witness["ips"], ["10.70.0.1"])
        self.assertEqual(witness["ssh_ports"], [2022])
        self.receipt("error", error="Rollback could not be verified")
        with self.store.meta() as db:
            host = self.store._get(db, "servers", "target"); host[activation.JOB]["created_at"] = stamp(now()-timedelta(hours=1)); host[activation.JOB]["expires_at"] = stamp(now()-timedelta(minutes=30)); self.store._put(db, "servers", host)
        with self.assertRaises(WorkflowConflict): self.assess()
        self.receipt("rolled_back"); self.assess()

    def test_revoked_admin_stops_delivery_and_fresh_health(self):
        self.confirm(self.preview()); request = self.health()
        with self.store.meta() as db:
            user = self.store._get(db, "auth_users", self.maker["user"]["id"]); user["enabled"] = False; self.store._put(db, "auth_users", user)
        self.assertNotIn("firewall_activation", self.store.assignment("target")[0])
        with self.assertRaises(PermissionError): activation.verify(self.store, "target", request)

    def test_restore_invalidates_archived_authority_without_losing_receipts_policy_or_other_settings(self):
        self.confirm(self.preview()); request = self.health(); activation.verify(self.store, "target", request)
        before = self.store.get("servers", "target"); policy = self.store.all("policies")
        with self.store.meta() as db:
            self.store._put(db, "maintenance_settings", {"id": "unrelated", "private": "retained"})
            result = activation.invalidate_after_recovery(self.store, db)
        self.assertEqual((result["invalidated_jobs"], result["invalidated_reviews"]), (1, 1))
        self.assertNotIn("firewall_activation", self.store.assignment("target")[0])
        with self.assertRaises(PermissionError): activation.verify(self.store, "target", request)
        self.assertEqual(self.store.get("servers", "target")[activation.RECEIPT], before[activation.RECEIPT])
        self.assertEqual(self.store.all("policies"), policy)
        self.assertEqual(self.store.get("maintenance_settings", "unrelated")["private"], "retained")

    def test_public_navigation_is_bounded_and_contains_no_private_job_or_proof(self):
        self.confirm(self.preview())
        page = activation.listing(self.store, {"server_ids": ["target"], "limit": 1})
        self.assertEqual(page["total"], 1)
        self.assertNotIn("approval_proof", page["items"][0]["job"])
        self.assertNotIn("assessment", page["items"][0]["job"])
        self.assertNotIn(activation.JOB, self.store.server("target"))
        for body in ({"limit": 101}, {"offset": True}, {"server_ids": ["bad/path"]}):
            with self.assertRaises(ValueError): activation.listing(self.store, body)

    def test_rolled_back_notification_enters_real_outbox_with_supported_severity(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        manager = PlatformManager(Path(temporary.name) / "activation-notifications")
        manager.app = types.SimpleNamespace(store=self.store, demo=False)
        manager.shared_secret_key = lambda purpose: b"x" * 32
        resolver = lambda host, port, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port))]
        channel = {"id": "maintenance", "name": "Maintenance", "type": "webhook", "enabled": True, "url": "https://alerts.example.test/events", "signing_secret": "test-secret", "minimum_severity": "warning", "event_types": ["firewall_activation_error"]}
        body = {"expected_revision": 0, "enabled": True, "channels": [channel]}
        preview = notifications.preview(manager, body, self.maker["actor"], resolver=resolver)
        notifications.apply(manager, {"preview_id": preview["id"], **{key: preview[key] for key in ("digest", "confirmation_nonce", "confirmation_phrase")}}, self.maker["actor"], resolver=resolver)
        self.confirm(self.preview()); self.receipt("rolled_back", error="Health check failed; exact baseline restored")
        self.assertEqual(notifications.enqueue_alerts(manager), 1)
        queued = notifications.deliveries(self.store)["items"]
        self.assertEqual(queued[0]["event"]["severity"], "warning")
        self.assertEqual(queued[0]["event"]["kind"], "firewall_activation_error")

    def test_hot_pages_project_only_small_fields_and_details_require_one_explicit_endpoint(self):
        self.assess(); good = self.receipt()
        with self.store.meta() as db:
            host = self.store._get(db, "servers", "target")
            host[activation.RECEIPT]["assessment"]["notes"] = ["N" * 1024] * 32
            host[activation.JOB]["approval_proof"] = "private" * 10000
            self.store._put(db, "servers", host)
        import json
        page = activation.listing(self.store)
        self.assertLess(len(json.dumps(page)), 3000)
        self.assertNotIn("assessment", page["items"][0]["receipt"])
        full = activation.listing(self.store, {"server_ids": ["target"], "limit": 1, "details": True})
        self.assertEqual(len(full["items"][0]["receipt"]["assessment"]["notes"]), 32)
        self.assertNotIn("approval_proof", full["items"][0]["job"])
        for value in ({"details": True}, {"server_ids": ["target"], "details": True}, {"server_ids": ["target", "other"], "limit": 1, "details": True}):
            with self.assertRaises(ValueError): activation.listing(self.store, value)

    def test_readonly_http_details_and_rbac_do_not_grant_mutation(self):
        for policy in self.store.all("policies"):
            self.store.delete_policy(policy["id"], self.maker["actor"])
        self.assess("activate_allow_all")
        receipt = self.receipt()
        app = App(self.store, tokens={"read_only": "reader", "admin": "lab-admin"})
        def request(path, body, token="reader"):
            handler = object.__new__(handler_for(app))
            handler.command, handler.path, handler.connection = "POST", "/api/v1" + path, object()
            handler.client_address, handler.headers = ("127.0.0.1", 12345), Message()
            if token: handler.headers["Authorization"] = "Bearer " + token
            handler.body = lambda: body
            result = {}
            handler.response = lambda status, value=None, headers=None: result.update(status=status, value=value)
            handler.dispatch()
            return result
        summary = request("/firewall-activation/query", {"server_ids": ["target"], "limit": 1})
        self.assertEqual(summary["status"], 200)
        item = summary["value"]["items"][0]
        self.assertEqual(item["receipt"]["id"], item["job"]["id"])
        self.assertEqual(item["receipt"]["plan_digest"], item["job"]["plan_digest"])
        self.assertEqual(item["receipt"]["plan_digest"], receipt["plan_digest"])
        self.assertNotIn("assessment", item["receipt"])
        page = request("/firewall-activation/query", {"server_ids": ["target"], "limit": 1, "details": True})
        self.assertEqual(page["status"], 200)
        self.assertEqual(page["value"]["items"][0]["receipt"]["assessment"]["ssh_ports"], [2022])
        self.assertNotIn("approval_proof", str(page["value"]))
        self.assertEqual(request("/firewall-activation/assess", self.scope())["status"], 403)
        self.assertEqual(request("/firewall-activation/example/confirm", {})["status"], 403)
        self.assertEqual(request("/firewall-activation/assess", self.scope(), "lab-admin")["status"], 403)
        self.assertEqual(request("/firewall-activation/query", {}, None)["status"], 401)
        self.assertEqual(request("/firewall-activation/query", {"details": True})["status"], 400)


# Reuse the existing owner-opt-in, private PostgreSQL cluster guard so both
# projection dialects and post-restore invalidation run in final acceptance.
from controller.tests import test_source_banks as bank_tests
import os
@unittest.skipUnless(os.environ.get("PRTHAK_PLATFORM_PG_ACCEPTANCE") == "1", "Owner opt-in for private PostgreSQL firewall maintenance fixture")
class PostgreSQLFirewallActivationTests(FirewallActivationTests):
    setUpClass = bank_tests.PostgreSQLSourceBankMaintenance.__dict__["setUpClass"]
    cleanup_databases = bank_tests.PostgreSQLSourceBankMaintenance.__dict__["cleanup_databases"]
    verify_cluster = bank_tests.PostgreSQLSourceBankMaintenance.__dict__["verify_cluster"]
    make_store = bank_tests.PostgreSQLSourceBankMaintenance.make_store

    def setUp(self):
        with patch.object(fixture, "Store", side_effect=lambda _: self.make_store()):
            super().setUp()
