import hashlib
import json
import tempfile
import unittest
from unittest.mock import patch
from datetime import timedelta
from email.message import Message
from pathlib import Path

from controller.app import App, handler_for
from controller.store import LearningExpired, Store, now, parse_time, stamp
from controller.tests.capture_fixture import typed_event


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(self.temp.name)
        self.report("target", "10.1.1.1")
        self.report("source", "10.2.1.1")

    def report(self, identifier, ip, listeners=None, **extra):
        return self.store.report(identifier, {"hostname": identifier, "ips": [ip], "capabilities":["traffic_capture_v1"], "listeners": listeners if listeners is not None else [{"port": 80, "protocol": "tcp", "address": "0.0.0.0", "process": "nginx"}], "firewalld_state": "running", "applied_version": 0, **extra})

    def policy(self, **extra):
        return self.store.save_policy({"name": "web", "selector": {"role": "web"}, "mode": "enforce", "services": [{"port": 80, "protocol": "tcp", "sources": ["10.10.0.1"], "source_selector": {"role": "lb"}}], **extra}, "admin")

    def set_tags(self, identifier, tags):
        self.store.update_server(identifier, {"tags": tags}, "admin")

    def session(self):
        return self.store.create_session({"server_ids": ["target"], "ports": [{"port": 80, "protocol": "tcp"}], "duration_seconds": 3600}, "admin")

    def batch(self, session):
        event_time = stamp()
        return {"batch_id": "first", "session_id": session["id"], "events": [typed_event("10.2.1.1",80,identity=session['id']+str(index),at=event_time) for index in range(3)]}

    def test_compiler_tracks_membership_only_when_effective_rules_change(self):
        self.set_tags("target", {"role": "web"})
        policy = self.policy()
        before, _ = self.store.assignment("target")
        self.assertEqual(before["services"][0]["sources"], ["10.10.0.1/32"])
        self.set_tags("source", {"role": "lb"})
        after, _ = self.store.assignment("target")
        self.assertEqual(after["version"], before["version"] + 1)
        self.assertIn("10.2.1.1/32", after["services"][0]["sources"])
        self.set_tags("source", {"role": "lb", "irrelevant": "changed"})
        unchanged, _ = self.store.assignment("target")
        self.assertEqual(unchanged["version"], after["version"])
        self.store.save_policy({**policy, "name": "Renamed"}, "admin", policy["id"])
        renamed, _ = self.store.assignment("target")
        self.assertEqual(renamed["version"], after["version"])
        self.report("source", "10.2.1.2")
        changed, _ = self.store.assignment("target")
        self.assertEqual(changed["version"], after["version"] + 1)
        self.assertIn("10.2.1.2/32", changed["services"][0]["sources"])
        self.assertNotIn("10.2.1.1/32", changed["services"][0]["sources"])

    def test_monitor_sources_cannot_widen_enforced_service(self):
        self.set_tags("target", {"role": "web"})
        self.policy()
        self.policy(name="observe", mode="monitor", services=[{"port": 80, "protocol": "tcp", "sources": ["0.0.0.0/0"]}, {"port": 22, "protocol": "tcp", "sources": ["0.0.0.0/0"]}])
        policy, _ = self.store.assignment("target")
        by_port = {service["port"]: service for service in policy["services"]}
        self.assertEqual(by_port[80]["mode"], "enforce")
        self.assertEqual(by_port[80]["sources"], ["10.10.0.1/32"])
        self.assertEqual(by_port[22]["mode"], "monitor")

    def test_invalid_policy_rejected_and_empty_source_selector_does_not_match_all(self):
        with self.assertRaises(ValueError):
            self.policy(services=[{"port": 80, "sources": ["garbage"]}])
        self.set_tags("target", {"role": "web"})
        self.policy(services=[{"port": 80, "protocol": "tcp", "sources": []}])
        policy, _ = self.store.assignment("target")
        self.assertEqual(policy["services"][0]["sources"], [])

    def test_learning_changes_etag_not_access_policy_version(self):
        before, initial_tag = self.store.assignment("target")
        session = self.session()
        during, learning_tag = self.store.assignment("target")
        self.assertNotEqual(initial_tag, learning_tag)
        self.assertEqual(before["version"], during["version"])
        self.assertEqual(len(during["learning_sessions"]), 1)
        self.store.stop_session(session["id"], "admin")
        after, final_tag = self.store.assignment("target")
        self.assertEqual(before["version"], after["version"])
        self.assertEqual(after["learning_sessions"], [])
        self.assertNotEqual(initial_tag, final_tag)
        self.assertEqual(after["learning_tombstones"][0]["id"], session["id"])
        self.assertIn("stopped_at", after["learning_tombstones"][0])
        stopped = self.store.get("sessions", session["id"])
        with patch("controller.store.now", return_value=parse_time(stopped["stopped_at"]) + timedelta(minutes=6)):
            after_grace, grace_tag = self.store.assignment("target")
        self.assertEqual(after_grace["learning_tombstones"], [])
        self.assertEqual(before["assignment_digest"], after_grace["assignment_digest"])
        self.assertGreater(after_grace["assignment_generation"], after["assignment_generation"])
        self.assertNotEqual(initial_tag, grace_tag)

    def test_stop_request_preserves_reported_collection_until_agent_ack(self):
        session = self.session()
        self.report("target", "10.1.1.1", collector_status="learning")
        self.store.stop_session(session["id"], "admin")
        requested = self.store.get("servers", "target")
        self.assertEqual(requested["collector_status"], "learning")
        self.assertEqual(requested["collector_desired_status"], "off")
        self.assertTrue(requested["learning_stop_pending"])
        self.store.evaluate_health()
        self.assertEqual(self.store.get("servers", "target")["collector_status"], "learning")
        self.report("target", "10.1.1.1", collector_status="off")
        acknowledged = self.store.get("servers", "target")
        self.assertEqual(acknowledged["collector_status"], "off")
        self.assertFalse(acknowledged["learning_stop_pending"])

    def test_offline_collector_is_unknown_and_expired_assignments_have_cutoffs(self):
        session = self.session()
        self.report("target", "10.1.1.1", collector_status="learning")
        expiry = parse_time(session["expires_at"])
        after_expiry = expiry + timedelta(seconds=1)
        with patch("controller.store.now", return_value=after_expiry):
            self.store.evaluate_health()
            policy, _ = self.store.assignment("target")
        server = self.store.get("servers", "target")
        self.assertEqual(server["collector_status"], "learning")
        self.assertEqual(server["collector_state"], "unknown")
        self.assertTrue(server["collector_status_stale"])
        self.assertTrue(server["learning_stop_pending"])
        self.assertEqual(policy["learning_sessions"], [])
        tombstone = policy["learning_tombstones"][0]
        self.assertEqual(tombstone["status"], "expired")
        self.assertEqual(tombstone["stopped_at"], session["expires_at"])
        self.assertEqual(tombstone["expires_at"], session["expires_at"])

    def test_learning_expiry_is_independent_of_api_and_preserves_policy(self):
        self.set_tags("target", {"role": "web"})
        self.policy()
        before, _ = self.store.assignment("target")
        session = self.session()
        self.store.evaluate_health(at=parse_time(session["expires_at"]) + timedelta(seconds=1))
        self.assertEqual(self.store.get("sessions", session["id"])["status"], "expired")
        after, _ = self.store.assignment("target")
        self.assertEqual(before["digest"], after["digest"])
        self.assertEqual(after["learning_sessions"], [])

    def test_durable_queue_survives_restart_and_is_idempotent(self):
        session = self.session()
        batch = self.batch(session)
        self.assertFalse(self.store.enqueue_flows("target", batch)["duplicate"])
        restarted = Store(self.temp.name)
        self.assertEqual(restarted.process_flows(), 1)
        self.assertEqual(restarted.process_flows(), 0)
        self.assertTrue(restarted.enqueue_flows("target", batch)["duplicate"])
        self.assertEqual(restarted.flows()[0]["count"], 3)
        changed = {**batch, "events": [{**batch["events"][0], "count": 7}]}
        with self.assertRaises(ValueError):
            restarted.enqueue_flows("target", changed)

    def test_flow_identity_and_selected_ports_are_enforced(self):
        session = self.session()
        batch = self.batch(session)
        with self.assertRaises(PermissionError):
            self.store.enqueue_flows("source", batch)
        batch["events"][0]["port"] = 22
        with self.assertRaises(ValueError):
            self.store.enqueue_flows("target", batch)
        batch["events"][0]["port"] = 80
        batch["events"][0]["first_seen"] = stamp(now() - timedelta(hours=1))
        with self.assertRaises(ValueError):
            self.store.enqueue_flows("target", batch)

    def test_duplicate_sessions_and_short_durations_are_rejected(self):
        self.session()
        with self.assertRaises(ValueError):
            self.session()
        with self.assertRaises(ValueError):
            self.store.create_session({"server_ids": ["source"], "ports": [{"port": 80}], "duration_seconds": 1}, "admin")

    def test_self_report_cannot_change_policy_tags(self):
        self.set_tags("target", {"role": "web"})
        self.report("target", "10.1.1.1", tags={"role": "admin"}, expected_services=[])
        self.assertEqual(self.store.get("servers", "target")["tags"], {"role": "web"})

    def test_control_interval_sets_three_poll_tolerance_in_all_health_views(self):
        base = parse_time(stamp())
        desired = self.store.assignment("target")[0]["version"]
        with patch("controller.store.now", return_value=base):
            self.report("target", "10.1.1.1", control_interval_seconds=300, heartbeat_timeout_seconds=99999999, applied_version=desired, apply_status="synced", collector_status="learning")
        for elapsed in (200, 900):
            self.store.evaluate_health(at=base + timedelta(seconds=elapsed))
            server = self.store.get("servers", "target")
            self.assertEqual(server["status"], "healthy")
            self.assertEqual(server["control_interval_seconds"], 300)
            self.assertEqual(server["heartbeat_timeout_seconds"], 900)
            self.assertEqual(server["collector_state"], "learning")
            self.assertFalse(server["collector_status_stale"])
            self.assertEqual(server["service_health_status"], "healthy")
            self.assertFalse(any(alert["server_id"] == "target" and alert["kind"] == "agent_offline" for alert in self.store.all("alerts")))
        self.store.evaluate_health(at=base + timedelta(seconds=901))
        offline = self.store.get("servers", "target")
        self.assertEqual(offline["status"], "offline")
        self.assertEqual(offline["collector_state"], "unknown")
        self.assertTrue(offline["collector_status_stale"])
        self.assertEqual(offline["service_health_status"], "unknown")

    def test_control_interval_validation_and_legacy_timeout(self):
        for invalid in (4, 3601, 1000000000, True, "300", 300.0, None):
            with self.subTest(interval=invalid):
                with self.assertRaises(ValueError):
                    self.report("target", "10.1.1.1", control_interval_seconds=invalid)
        self.report("target", "10.1.1.1", control_interval_seconds=5)
        self.assertEqual(self.store.get("servers", "target")["heartbeat_timeout_seconds"], 180)
        self.report("target", "10.1.1.1", control_interval_seconds=3600)
        self.assertEqual(self.store.get("servers", "target")["heartbeat_timeout_seconds"], 10800)
        self.report("target", "10.1.1.1")
        legacy = self.store.get("servers", "target")
        self.assertEqual(legacy["control_interval_seconds"], 60)
        self.assertEqual(legacy["heartbeat_timeout_seconds"], 180)

    def test_offline_agent_suppresses_missing_service_and_recovers_once(self):
        self.store.update_server("target", {"expected_services": [{"port": 443, "protocol": "tcp"}]}, "admin")
        self.store.evaluate_health(at=now() + timedelta(minutes=5))
        target_alerts = [alert for alert in self.store.all("alerts") if alert["server_id"] == "target"]
        self.assertEqual([item["kind"] for item in target_alerts if item["kind"] != "service_discovered"], ["agent_offline"])
        self.store.evaluate_health()
        self.store.evaluate_health()
        target_alerts = [alert for alert in self.store.all("alerts") if alert["server_id"] == "target"]
        self.assertEqual(sum(item["kind"] == "recovered" for item in target_alerts), 1)
        self.assertTrue(any(item["kind"] == "service_down" for item in target_alerts))

    def test_vanished_listener_and_recovery_are_detected(self):
        self.report("target", "10.1.1.1", listeners=[])
        self.assertTrue(any(alert["kind"] == "service_down" and alert["status"] == "open" for alert in self.store.all("alerts")))
        self.report("target", "10.1.1.1")
        self.assertTrue(any(alert["kind"] == "recovered" for alert in self.store.all("alerts")))

    def test_firewall_service_failure_has_one_occurrence_and_truthful_recovery(self):
        self.report("target", "10.1.1.1", firewalld_state="not-running")
        self.store.evaluate_health()
        self.store.evaluate_health()
        alert = self.store.get("alerts", "firewall-service:target")
        self.assertEqual((alert["kind"], alert["severity"], alert["status"]),
                         ("firewall_service_unavailable", "critical", "open"))
        self.assertEqual(alert["details"]["rule_state"], "unverified")
        self.assertEqual(alert["details"]["basis"], "agent_report")
        occurrence = alert["occurrence_id"]
        self.store.acknowledge(alert["id"], "admin")
        self.store.evaluate_health()
        self.assertEqual(self.store.get("alerts", alert["id"])["occurrence_id"], occurrence)
        self.report("target", "10.1.1.1", firewalld_state="active")
        self.store.evaluate_health()
        self.assertEqual(self.store.get("alerts", alert["id"])["status"], "resolved")
        self.report("target", "10.1.1.1", firewalld_state="not-running")
        self.store.evaluate_health()
        self.assertNotEqual(self.store.get("alerts", alert["id"])["occurrence_id"], occurrence)

    def test_missing_heartbeat_cannot_infer_firewall_failure_or_recovery(self):
        self.report("target", "10.1.1.1", firewalld_state="not-running")
        self.store.evaluate_health(at=now() + timedelta(minutes=10))
        with self.assertRaises(KeyError):
            self.store.get("alerts", "firewall-service:target")
        self.store.evaluate_health()
        self.assertEqual(self.store.get("alerts", "firewall-service:target")["status"], "open")
        self.report("target", "10.1.1.1", firewalld_state="running")
        self.store.evaluate_health(at=now() + timedelta(minutes=10))
        self.assertEqual(self.store.get("alerts", "firewall-service:target")["status"], "open")

    def test_unreported_firewall_state_does_not_raise_a_confirmed_outage(self):
        self.report("target", "10.1.1.1", firewalld_state="unknown")
        self.store.evaluate_health()
        with self.assertRaises(KeyError):
            self.store.get("alerts", "firewall-service:target")

    def test_discovery_failure_preserves_listeners_and_coverage_quality(self):
        session = self.session()
        self.report("target", "10.1.1.1", listeners=[], discovery_error="ss command failed", learning_coverage={"session_id": session["id"], "started_at": stamp(), "dropped_events": 5, "rate_limited": True, "error": "journal stream interrupted"})
        server = self.store.get("servers", "target")
        self.assertEqual(server["listeners"][0]["port"], 80)
        self.assertTrue(server["learning_coverage"]["rate_limited"])
        self.assertEqual(server["learning_coverage"]["error"], "journal stream interrupted")
        self.store.evaluate_health()
        self.assertEqual(self.store.get("servers", "target")["status"], "warning")
        self.assertFalse(any(alert["kind"] == "service_down" for alert in self.store.all("alerts")))

    def test_expired_upload_returns_specific_error_but_duplicate_stays_idempotent(self):
        session = self.session()
        batch = self.batch(session)
        self.store.enqueue_flows("target", batch)
        with patch("controller.store.now", return_value=parse_time(session["expires_at"]) + timedelta(minutes=6)):
            self.assertTrue(self.store.enqueue_flows("target", batch)["duplicate"])
            with self.assertRaises(LearningExpired):
                self.store.enqueue_flows("target", {**batch, "batch_id": "late"})

    def test_enrollment_token_is_one_time_and_has_no_agent_tags(self):
        token = self.store.create_token("test-host", "admin")
        signed = []
        def signer(identifier, csr):
            signed.append(identifier)
            return "certificate", "ca"
        enrolled = self.store.enroll(token["token"], "host", "-----BEGIN CERTIFICATE REQUEST-----\nrequest", signer)
        self.assertEqual(signed, [enrolled["server_id"]])
        self.assertEqual(self.store.get("servers", enrolled["server_id"])["tags"], {})
        replay = self.store.enroll(token["token"], "host", "-----BEGIN CERTIFICATE REQUEST-----\nrequest", signer)
        self.assertEqual(replay, enrolled)
        self.assertEqual(signed, [enrolled["server_id"]])
        self.assertEqual(len(self.store.servers()), 3)
        with self.assertRaises(PermissionError):
            self.store.enroll(token["token"], "another", "-----BEGIN CERTIFICATE REQUEST-----\nrequest", signer)
        with self.assertRaises(PermissionError):
            self.store.enroll(token["token"], "host", "-----BEGIN CERTIFICATE REQUEST-----\ndifferent-request", signer)
        with patch("controller.store.now", return_value=parse_time(token["expires_at"])):
            with self.assertRaises(PermissionError):
                self.store.enroll(token["token"], "host", "-----BEGIN CERTIFICATE REQUEST-----\nrequest", signer)
        self.assertNotIn(token["token"], json.dumps(self.store.all("tokens")))

    def test_group_dynamic_arbitrary_tags_and_new_host_inheritance(self):
        group = self.store.save_group({"name": "Billing high", "type": "dynamic", "selector": {"application": "billing", "custom_tier": "high"}}, "admin")
        policy = self.policy(selector={}, group_ids=[group["id"]])
        self.assertEqual(group["member_count"], 0)
        self.assertEqual(self.store.assignment("source")[0]["services"], [])
        self.report("new-host", "10.3.1.1")
        self.set_tags("new-host", {"application": "billing"})
        self.assertEqual(self.store.assignment("new-host")[0]["services"], [])
        self.set_tags("new-host", {"application": "billing", "custom_tier": "high"})
        compiled, _ = self.store.assignment("new-host")
        self.assertEqual(compiled["services"][0]["port"], 80)
        self.assertIn(policy["id"], self.store.get("servers", "new-host")["matched_policy_ids"])
        current = self.store.groups()[0]
        self.assertEqual(current["member_ids"], ["new-host"])
        self.assertEqual(current["member_count"], 1)

    def test_group_static_union_and_empty_group_never_matches_all(self):
        first = self.store.save_group({"name": "First", "type": "static", "server_ids": ["target"]}, "admin")
        second = self.store.save_group({"name": "Second", "type": "static", "server_ids": ["source"]}, "admin")
        self.policy(selector={}, group_ids=[first["id"], second["id"]])
        self.assertTrue(self.store.assignment("target")[0]["services"])
        self.assertTrue(self.store.assignment("source")[0]["services"])
        self.report("outside", "10.5.1.1")
        self.assertEqual(self.store.assignment("outside")[0]["services"], [])
        self.store.save_group({"name": "First empty", "type": "static", "server_ids": []}, "admin", first["id"])
        self.assertEqual(self.store.assignment("target")[0]["services"], [])
        self.assertTrue(self.store.assignment("source")[0]["services"])

    def test_group_rename_preserves_versions_and_member_edit_changes_only_targets(self):
        group = self.store.save_group({"name": "Test", "type": "static", "server_ids": ["target"]}, "admin")
        self.policy(selector={}, group_ids=[group["id"]])
        before = {host: self.store.assignment(host)[0]["version"] for host in ("target", "source")}
        renamed = self.store.save_group({"name": "Renamed", "type": "static", "server_ids": ["target"]}, "admin", group["id"])
        self.assertEqual(renamed["created_at"], group["created_at"])
        self.assertEqual({host: self.store.assignment(host)[0]["version"] for host in before}, before)
        self.store.save_group({"name": "Renamed", "type": "static", "server_ids": ["target", "source"]}, "admin", group["id"])
        self.assertEqual(self.store.assignment("target")[0]["version"], before["target"])
        self.assertEqual(self.store.assignment("source")[0]["version"], before["source"] + 1)

    def test_group_validation_unknown_reference_and_delete_guard(self):
        for invalid in ({"name": "bad", "type": "dynamic", "selector": {}}, {"name": "bad", "type": "static", "server_ids": ["unknown"]}, {"name": "bad", "type": "dynamic", "selector": {"app": "x"}, "server_ids": ["target"]}):
            with self.assertRaises(ValueError):
                self.store.save_group(invalid, "admin")
        group = self.store.save_group({"name": "Target", "type": "static", "server_ids": ["target"]}, "admin")
        with self.assertRaises(ValueError):
            self.policy(group_ids=[group["id"]])  # existing helper's nonempty selector is ambiguous
        with self.assertRaises(ValueError):
            self.policy(selector={}, group_ids=["unknown-group"])
        policy = self.policy(selector={}, group_ids=[group["id"]])
        with self.assertRaises(ValueError):
            self.store.delete_group(group["id"], "admin")
        self.store.delete_policy(policy["id"], "admin")
        self.store.delete_group(group["id"], "admin")
        self.assertEqual(self.store.groups(), [])

    def test_missing_stored_group_fails_closed_without_selector_fallback(self):
        group = self.store.save_group({"name": "Target", "type": "static", "server_ids": ["target"]}, "admin")
        self.policy(selector={}, group_ids=[group["id"]])
        # Even legacy/corrupt metadata cannot convert an absent group into an all-host policy.
        with self.store.lock, self.store.meta() as db:
            db.execute("DELETE FROM groups WHERE id=?", (group["id"],))
            self.store.compile_all(db)
        self.assertEqual(self.store.assignment("target")[0]["services"], [])
        self.assertEqual(self.store.assignment("source")[0]["services"], [])

    def test_dashboard_tags_join_group_after_identity_only_enrollment_and_agent_cannot_override(self):
        group = self.store.save_group({"name": "Billing", "type": "dynamic", "selector": {"application": "billing"}}, "admin")
        self.policy(selector={}, group_ids=[group["id"]])
        with self.assertRaises(ValueError):
            self.store.create_token("billing-host", "admin", {"application": "billing"})
        token = self.store.create_token("billing-host", "admin")
        response = self.store.enroll(token["token"], "new-billing-host", "-----BEGIN CERTIFICATE REQUEST-----\nrequest", lambda *args: ("cert", "ca"))
        identifier = response["server_id"]
        self.assertEqual(self.store.get("servers", identifier)["tags"], {})
        self.store.update_server(identifier, {"tag_updates": {"application": "billing", "environment": "production"}}, "admin")
        self.assertEqual(self.store.get("servers", identifier)["tags"], {"application": "billing", "environment": "production"})
        self.assertIn(identifier, next(item for item in self.store.groups() if item["id"] == group["id"])["member_ids"])
        self.assertTrue(self.store.assignment(identifier)[0]["services"])
        self.report(identifier, "10.20.0.7", tags={"application": "admin"})
        self.assertEqual(self.store.get("servers", identifier)["tags"]["application"], "billing")

    def test_old_used_enrollment_token_without_cached_reply_is_rejected(self):
        token = self.store.create_token("legacy", "admin")
        token_id = hashlib.sha256(token["token"].encode()).hexdigest()
        with self.store.lock, self.store.meta() as db:
            record = self.store._get(db, "tokens", token_id)
            record["used"] = True
            self.store._put(db, "tokens", record)
        with self.assertRaises(PermissionError):
            self.store.enroll(token["token"], "host", "-----BEGIN CERTIFICATE REQUEST-----\nrequest", lambda *args: ("cert", "ca"))


class AuthTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.app = App(Store(self.temp.name), tokens={"admin": "admin-secret", "operator": "operator-secret", "viewer": "viewer-secret"})

    def request(self, method, path, token=None, body=None, extra=None, app=None):
        cls = handler_for(app or self.app)
        handler = object.__new__(cls)
        handler.command, handler.path = method, path
        handler.connection = object()
        handler.client_address = ("127.0.0.1", 12345)
        handler.headers = Message()
        if token:
            handler.headers["Authorization"] = "Bearer " + token
        for key, value in (extra or {}).items():
            handler.headers[key] = value
        handler.body = lambda: body or {}
        captured = {}
        def response(status, value=None, headers=None):
            captured.update(status=status, value=value, headers=headers)
        handler.response = response
        handler.dispatch()
        return captured

    def test_unauthenticated_dashboard_api_is_rejected(self):
        self.assertEqual(self.request("GET", "/api/v1/overview")["status"], 401)
        self.assertEqual(self.request("GET", "/api/v1/auth", "viewer-secret")["value"]["role"], "read_only")

    def test_viewer_cannot_mutate_and_operator_cannot_issue_tokens(self):
        self.assertEqual(self.request("POST", "/api/v1/policies", "viewer-secret")["status"], 403)
        self.assertEqual(self.request("POST", "/api/v1/enrollment-tokens", "operator-secret")["status"], 403)
        self.assertEqual(self.request("POST", "/api/v1/enrollment-tokens", "admin-secret", {"name": "endpoint"})["status"], 201)

    def test_production_rejects_spoofed_agent_header_and_body(self):
        value = self.request("POST", "/api/v1/agent/report", "admin-secret", {"server_id": "victim"}, {"X-Agent-ID": "victim"})
        self.assertEqual(value["status"], 403)

    def test_group_api_role_guards_and_overview(self):
        response = self.request("POST", "/api/v1/groups", "admin-secret", {"name": "Billing", "type": "dynamic", "selector": {"application": "billing"}})
        self.assertEqual(response["status"], 201)
        identifier = response["value"]["id"]
        groups = self.request("GET", "/api/v1/groups", "viewer-secret")
        self.assertEqual(groups["value"]["items"][0]["id"], identifier)
        self.assertEqual(self.request("POST", "/api/v1/groups", "viewer-secret", {"name": "bad"})["status"], 403)
        self.assertEqual(self.request("GET", "/api/v1/overview", "viewer-secret")["value"]["groups"][0]["id"], identifier)
        self.assertEqual(self.request("PUT", "/api/v1/groups/" + identifier, "operator-secret", {"name": "Billing edited", "type": "dynamic", "selector": {"application": "billing"}})["status"], 403)
        self.assertEqual(self.request("PUT", "/api/v1/groups/" + identifier, "admin-secret", {"name": "Billing edited", "type": "dynamic", "selector": {"application": "billing"}})["status"], 200)
        self.assertEqual(self.request("DELETE", "/api/v1/groups/" + identifier, "operator-secret")["status"], 403)
        self.assertEqual(self.request("DELETE", "/api/v1/groups/" + identifier, "admin-secret")["status"], 204)

    def test_firewall_read_access_and_admin_only_bulk_changes(self):
        self.assertEqual(self.request("GET", "/api/v1/firewall")["status"], 401)
        self.assertEqual(self.request("GET", "/api/v1/firewall", "viewer-secret")["status"], 200)
        self.assertEqual(self.request("GET", "/api/v1/firewall/changes", "viewer-secret")["status"], 200)
        self.assertEqual(self.request("POST", "/api/v1/firewall/changes", "operator-secret", {})["status"], 403)
        self.assertEqual(self.request("POST", "/api/v1/firewall/changes/id/confirm", "operator-secret", {})["status"], 403)
        self.assertEqual(self.request("POST", "/api/v1/firewall/changes/id/cancel", "operator-secret", {})["status"], 403)

    def test_location_api_requires_admin_catalogue_and_assignment_but_all_roles_read(self):
        value = {"name": "Mumbai primary", "location": "Mumbai, India", "type": "datacenter"}
        self.assertEqual(self.request("POST", "/api/v1/locations", "operator-secret", value)["status"], 403)
        created = self.request("POST", "/api/v1/locations", "admin-secret", value)
        self.assertEqual(created["status"], 201)
        identifier = created["value"]["id"]
        self.assertEqual(self.request("GET", "/api/v1/locations", "viewer-secret")["value"]["items"][0]["id"], identifier)
        self.app.store.report("host", {"hostname": "host", "ips": ["10.0.0.1"], "listeners": []})
        self.assertEqual(self.request("PATCH", "/api/v1/servers/host", "operator-secret", {"location_id": identifier})["status"], 403)
        assigned = self.request("PATCH", "/api/v1/servers/host", "admin-secret", {"location_id": identifier})
        self.assertEqual(assigned["value"]["location"]["id"], identifier)
        self.assertEqual(self.request("GET", "/api/v1/servers/host", "viewer-secret")["value"]["location_id"], identifier)
        self.assertEqual(self.request("DELETE", "/api/v1/locations/" + identifier, "admin-secret")["status"], 400)
        self.assertEqual(self.request("PUT", "/api/v1/locations/" + identifier, "admin-secret", {**value, "name": "Mumbai renamed"})["status"], 200)
        self.assertEqual(self.request("GET", "/api/v1/overview", "viewer-secret")["value"]["locations"][0]["name"], "Mumbai renamed")

    def test_cross_origin_mutation_is_rejected(self):
        value = self.request("POST", "/api/v1/enrollment-tokens", "admin-secret", {"name": "x"}, {"Origin": "https://evil.example", "Host": "controller.local"})
        self.assertEqual(value["status"], 403)

    def test_demo_identity_and_etag_contract(self):
        demo = App(self.app.store, demo=True)
        result = self.request("POST", "/api/v1/agent/report", body={"hostname": "test", "ips": ["10.0.0.1"], "listeners": [], "server_id": "victim"}, extra={"X-Agent-ID": "actual"}, app=demo)
        self.assertEqual(result["value"]["server_id"], "actual")
        first = self.request("GET", "/api/v1/agent/policy", extra={"X-Agent-ID": "actual"}, app=demo)
        cached = self.request("GET", "/api/v1/agent/policy", extra={"X-Agent-ID": "actual", "If-None-Match": first["headers"]["ETag"]}, app=demo)
        self.assertEqual(cached["status"], 304)


class DemoTickerTests(unittest.TestCase):
    def test_ticker_refreshes_only_synthetic_seed_hosts_and_preserves_scenarios(self):
        from controller.seed import seed, tick_synthetic_hosts
        with tempfile.TemporaryDirectory() as temp:
            store = Store(temp)
            seed(store)
            store.update_server("srv-web-01", {"tags": {"custom": "retained"}, "expected_services": [{"port": 1234, "protocol": "tcp"}]}, "admin")
            store.report("root-integration-agent", {"hostname": "real-agent", "ips": ["10.99.1.1"], "listeners": [], "firewalld_state": "running"})
            untouched = store.get("servers", "root-integration-agent")
            future = now() + timedelta(minutes=10)
            tick_synthetic_hosts(store, at=future)
            store.evaluate_health(at=future)
            online = store.get("servers", "srv-web-01")
            self.assertEqual(online["last_seen"], stamp(future))
            self.assertEqual(online["tags"], {"custom": "retained"})
            self.assertEqual(online["expected_services"], [{"port": 1234, "protocol": "tcp"}])
            self.assertEqual(online["applied_version"], online["desired_version"])
            self.assertEqual(store.get("servers", "srv-db-02")["status"], "offline")
            self.assertEqual(store.get("servers", "srv-api-02")["apply_status"], "error")
            self.assertEqual(store.get("servers", "root-integration-agent")["last_seen"], untouched["last_seen"])
            self.assertNotIn("synthetic", store.get("servers", "root-integration-agent"))

    def test_existing_demo_migration_marks_only_known_ids_and_learning_can_stop(self):
        from controller.seed import seed, tick_synthetic_hosts
        with tempfile.TemporaryDirectory() as temp:
            store = Store(temp)
            seed(store)
            with store.lock, store.meta() as db:
                server = store._get(db, "servers", "srv-web-01")
                server.pop("synthetic")
                store._put(db, "servers", server)
            seed(store)
            self.assertTrue(store.get("servers", "srv-web-01")["synthetic"])
            tick_synthetic_hosts(store)
            self.assertEqual(store.get("servers", "srv-web-01")["collector_status"], "learning")
            store.stop_session("learn-payments-web", "admin")
            tick_synthetic_hosts(store)
            self.assertEqual(store.get("servers", "srv-web-01")["collector_status"], "off")


class PKITests(unittest.TestCase):
    def test_signer_overrides_csr_identity_and_issues_client_only_certificate(self):
        from controller.pki import Signer, init_ca, run
        with tempfile.TemporaryDirectory() as temp:
            ca = init_ca(temp)
            csr = run("req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(Path(temp) / "client.key"), "-subj", "/CN=forged-admin")
            cert, _ = Signer(ca / "ca.pem", ca / "ca-key.pem")("enrolled-identity", csr)
            output = Path(temp) / "client.pem"
            output.write_text(cert)
            self.assertIn("enrolled-identity", run("x509", "-in", str(output), "-noout", "-subject"))
            self.assertNotIn("forged-admin", run("x509", "-in", str(output), "-noout", "-subject"))
            self.assertIn("OK", run("verify", "-purpose", "sslclient", "-CAfile", str(ca / "ca.pem"), str(output)))


if __name__ == "__main__":
    unittest.main()
