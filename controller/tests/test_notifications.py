import copy
from datetime import timedelta
import json
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import types
import unittest
from unittest.mock import patch

from controller import notifications as n
from controller import store as store_module
from controller.firewall import WorkflowConflict
from controller.platform import PlatformManager
from controller.store import Store, now, parse_time, stamp


class NotificationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.store = Store(self.root / "db")
        with self.store.meta() as db:
            n.initialize(db)
        self.manager = PlatformManager(self.root / "private")
        self.manager.app = types.SimpleNamespace(store=self.store, demo=False)
        self.manager.shared_secret_key = lambda purpose: b"fixture-shared-key-not-for-prod!!"[:32]
        self.resolver = lambda host, port, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port))]
        self.secret = "webhook-private-secret-do-not-print"

    def channel(self, **extra):
        return {"id": "security", "name": "Security alerts", "type": "webhook", "enabled": True,
                "url": "https://alerts.example.test/private-token?key=private-url-credential", "signing_secret": self.secret,
                "minimum_severity": "warning", "event_types": ["*"], **extra}

    def email_channel(self, **extra):
        return {"id": "mail", "name": "Email alerts", "type": "email", "enabled": True, "minimum_severity": "info", "event_types": ["*"],
                "smtp_host": "smtp.example.test", "smtp_port": 587, "smtp_security": "starttls", "from_address": "alerts@example.test",
                "to_addresses": ["operator@example.test"], **extra}

    def body(self, channels=None, enabled=True):
        return {"expected_revision": n.get(self.manager)["revision"], "enabled": enabled,
                "channels": [self.channel()] if channels is None else channels}

    def review(self, body=None):
        return n.preview(self.manager, body or self.body(), "named-super-admin", resolver=self.resolver)

    def confirm(self, plan):
        return {"preview_id": plan["id"], **{key: plan[key] for key in ("digest", "confirmation_nonce", "confirmation_phrase")}}

    def configure(self, body=None):
        return n.apply(self.manager, self.confirm(self.review(body)), "named-super-admin", resolver=self.resolver)

    def alert(self, identifier="fresh-alert", **extra):
        with self.store.meta() as db:
            self.store._put(db, "alerts", {"id": identifier, "kind": "port_scan", "severity": "warning", "message": "Observed unexpected connection sources", "status": "open", "created_at": stamp(), **extra})

    def queue(self, identifier="fresh-alert"):
        self.alert(identifier)
        self.assertEqual(n.enqueue_alerts(self.manager), 1)
        return next(row for row in n.deliveries(self.store)["items"] if row["event"].get("alert_id") == identifier)

    def test_disabled_defaults_do_not_resolve_or_send(self):
        self.assertFalse(n.get(self.manager)["enabled"])
        self.alert()
        self.assertEqual(n.enqueue_alerts(self.manager), 0)
        with patch.object(n, "dispatch", side_effect=AssertionError("No unconfigured network sends")):
            self.assertEqual(n.run_once(self.manager)["processed"], 0)

    def test_named_admin_change_queues_only_a_safe_summary_for_email(self):
        self.configure(self.body([self.email_channel(event_types=["admin_change"]), self.channel(event_types=["admin_change"])]))
        with self.store.meta() as db:
            self.store._put(db, "auth_users", {"id": "administrator-1", "role": "admin", "display_name": "Pilot Administrator"})
            self.store.audit("policy.created", "local:administrator-1", {"credential": self.secret}, db)
            self.store.audit("policy.created", "agent:administrator-1", {}, db)
            self.store.audit("firewall_change.confirmed", "local:administrator-1", {"status": "awaiting_second_confirmation"}, db)
        self.assertEqual(n.enqueue_alerts(self.manager), 1)
        delivery = n.deliveries(self.store)["items"][0]
        self.assertEqual(delivery["channel_type"], "email")
        self.assertIn("Pilot Administrator", delivery["event"]["message"])
        self.assertNotIn(self.secret, json.dumps(delivery))
        self.assertEqual(n.enqueue_alerts(self.manager), 0)

    def test_wrong_length_encryption_key_fails_closed_without_saving_settings(self):
        previous = self.manager.shared_secret_key
        self.manager.shared_secret_key = lambda purpose: b"x" * 16
        with self.assertRaisesRegex(ValueError, "Encrypted notification state is unavailable"):
            self.configure()
        self.manager.shared_secret_key = previous
        self.assertEqual(n.get(self.manager)["revision"], 0)

    def test_review_apply_encrypts_credentials_and_masks_public_state_audit_and_delivery(self):
        plan = self.review()
        self.assertEqual(plan["summary"]["channels"][0]["destination"], "https://alerts.example.test/…")
        self.assertTrue(plan["summary"]["channels"][0]["credential_flags"]["signing_secret_configured"])
        self.assertNotIn(self.secret, json.dumps(plan))
        n.apply(self.manager, self.confirm(plan), "named-super-admin", resolver=self.resolver)
        self.queue()
        for table in ("notification_reviews", "notification_settings", "notification_revisions", "notification_deliveries", "audit"):
            serialized = json.dumps(self.store.all(table))
            for secret in (self.secret, "private-url-credential", "/private-token"):
                self.assertNotIn(secret, serialized)
        self.assertNotIn("sealed", json.dumps(n.get(self.manager)))

    def test_blank_credentials_preserve_existing_private_values_and_foreign_cluster_cannot_decrypt(self):
        self.configure()
        public = n.get(self.manager)["channels"][0]
        self.configure(self.body([{key: public[key] for key in ("id", "name", "type", "enabled", "minimum_severity", "event_types")}]))
        self.queue()
        received = []
        n.run_once(self.manager, transport=lambda channel, delivery: received.append(channel) or {"transport": "webhook", "status_code": 204})
        self.assertEqual(received[0]["signing_secret"], self.secret)
        self.assertIn("private-url-credential", received[0]["url"])
        self.manager.shared_secret_key = lambda purpose: b"foreign-cluster-key-not-for-prod!"[:32]
        with self.assertRaisesRegex(ValueError, "Encrypted notification state is unavailable"):
            n.run_once(self.manager, transport=lambda *_: self.fail("Must fail closed before transport"))

    def test_destination_review_blocks_metadata_loopback_rebinding_http_and_url_credentials(self):
        for address in ("127.0.0.1", "169.254.169.254", "100.100.100.200", "0.0.0.0", "::1", "fe80::1", "224.0.0.1"):
            with self.subTest(address=address):
                resolver = lambda host, port, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port))]
                with self.assertRaises(ValueError):
                    n.preview(self.manager, self.body([self.channel(allow_private_network=True)]), "admin", resolver=resolver)
        for url in ("http://example.test/hook", "https://user:password@example.test/hook", "https://example.test:0/hook", "https://example.test/#fragment"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                self.review(self.body([self.channel(url=url)]))
        plan = self.review()
        resolver = lambda host, port, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.4.4", port))]
        with self.assertRaises(WorkflowConflict):
            n.apply(self.manager, self.confirm(plan), "admin", resolver=resolver)
        self.assertEqual(n.get(self.manager)["revision"], 0)

    def test_private_network_requires_explicit_approval_and_slack_hosts_are_fixed(self):
        resolver = lambda host, port, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.55.1.20", port))]
        with self.assertRaises(ValueError):
            n.preview(self.manager, self.body(), "admin", resolver=resolver)
        plan = n.preview(self.manager, self.body([self.channel(allow_private_network=True)]), "admin", resolver=resolver)
        self.assertEqual(plan["summary"]["channels"][0]["addresses"], ["10.55.1.20"])
        with self.assertRaises(ValueError):
            self.review(self.body([self.channel(type="slack", url="https://hooks.slack.com.attacker.test/services/token")]))

    def test_stale_typed_confirmation_and_expired_reviews_do_not_enable_delivery(self):
        plan = self.review()
        with self.assertRaises(WorkflowConflict):
            n.apply(self.manager, {**self.confirm(plan), "confirmation_phrase": "yes"}, "admin", resolver=self.resolver)
        with patch.object(n, "now", return_value=now() + timedelta(minutes=11)), self.assertRaises(WorkflowConflict):
            n.apply(self.manager, self.confirm(plan), "admin", resolver=self.resolver)
        self.configure()
        with self.assertRaises(WorkflowConflict):
            n.apply(self.manager, self.confirm(plan), "admin", resolver=self.resolver)

    def test_old_alerts_are_not_broadcast_and_event_channel_idempotency_survives_repeated_scans(self):
        self.alert("historical")
        plan = self.review()
        self.alert("during-review")
        n.apply(self.manager, self.confirm(plan), "admin", resolver=self.resolver)
        self.assertEqual(n.enqueue_alerts(self.manager), 0)
        self.queue()
        self.assertEqual(n.enqueue_alerts(self.manager), 0)
        self.assertEqual(n.deliveries(self.store)["total"], 1)

    def test_filters_do_not_send_resolved_or_low_severity_alerts(self):
        self.configure(self.body([self.channel(minimum_severity="critical", event_types=["port_scan"])]))
        self.alert("low")
        self.alert("wrong-kind", severity="critical", kind="service_discovered")
        self.alert("resolved", severity="critical", status="resolved")
        self.alert("eligible", severity="critical")
        self.assertEqual(n.enqueue_alerts(self.manager), 1)
        self.assertEqual(n.deliveries(self.store)["items"][0]["event"]["alert_id"], "eligible")

    def test_traffic_burst_requires_explicit_selection_and_only_new_occurrences_are_sent(self):
        self.configure(self.body([self.email_channel()]))
        self.alert("existing-burst", kind="traffic_burst")
        self.assertEqual(n.enqueue_alerts(self.manager), 0)
        plan = self.review(self.body([self.email_channel(event_types=["*", "traffic_burst"])]))
        self.alert("burst-during-review", kind="traffic_burst")
        n.apply(self.manager, self.confirm(plan), "named-super-admin", resolver=self.resolver)
        self.alert("fresh-burst", kind="traffic_burst")
        self.alert("service", kind="service_discovered", severity="info")
        self.assertEqual(n.enqueue_alerts(self.manager), 2)
        self.assertEqual({row["event"]["alert_id"] for row in n.deliveries(self.store)["items"]}, {"fresh-burst", "service"})

    def test_projected_events_only_reach_explicit_email_on_their_original_revision(self):
        settings = self.configure(self.body([
            self.email_channel(id="selected", minimum_severity="warning", event_types=["admin_change", "port_allowed"]),
            self.email_channel(),
            self.channel(event_types=["admin_change", "port_allowed"]),
        ]))
        with self.store.meta() as db:
            for identifier, kind, revision in (
                ("admin", "admin_change", settings["revision"]),
                ("port", "port_allowed", settings["revision"]),
                ("stale", "admin_change", settings["revision"] - 1),
            ):
                event = {"id": identifier, "kind": kind, "severity": "info", "message": "Reviewed action",
                         "configuration_revision": revision, "created_at": stamp()}
                db.execute("INSERT INTO notification_events(id,created_at,data) VALUES(?,?,?)", (identifier, event["created_at"], json.dumps(event)))
        self.assertEqual(n.enqueue_alerts(self.manager), 2)
        self.assertEqual(n.enqueue_alerts(self.manager), 0)
        self.assertEqual({(row["event_id"], row["channel_id"]) for row in n.deliveries(self.store)["items"]},
                         {("admin", "selected"), ("port", "selected")})
        self.assertEqual(self.store.all("notification_events"), [])

    def test_retry_then_provider_acknowledgement_is_durable_with_stable_delivery_id(self):
        self.configure()
        queued = self.queue()
        at = now()
        ids = []
        def temporary(channel, delivery):
            ids.append(delivery["id"])
            raise n.DeliveryFailure("retry", "provider_temporary", 503)
        n.run_once(self.manager, transport=temporary, at=at)
        failed = n.deliveries(self.store)["items"][0]
        self.assertEqual(failed["status"], "retry")
        self.assertEqual(n.run_once(self.manager, transport=temporary, at=at)["processed"], 0)
        def accepted(channel, delivery):
            ids.append(delivery["id"])
            return {"transport": "webhook", "status_code": 204, "unexpected_secret": self.secret}
        n.run_once(self.manager, transport=accepted, at=at + timedelta(seconds=31))
        result = n.deliveries(self.store)["items"][0]
        self.assertEqual(result["status"], "delivered")
        self.assertEqual(ids, [queued["id"], queued["id"]])
        self.assertNotIn(self.secret, json.dumps(result))
        self.assertEqual(result["receipt"], {"transport": "webhook", "status_code": 204})

    def test_ambiguous_delivery_is_not_automatically_duplicated_and_manual_retry_is_explicit(self):
        self.configure()
        queued = self.queue()
        def ambiguous(*_):
            raise RuntimeError("A private token must never escape: " + self.secret)
        n.run_once(self.manager, transport=ambiguous)
        value = n.deliveries(self.store)["items"][0]
        self.assertEqual(value["status"], "uncertain")
        self.assertNotIn(self.secret, json.dumps(value))
        self.assertEqual(n.run_once(self.manager, transport=lambda *_: self.fail("No blind retry"))["processed"], 0)
        with self.assertRaises(WorkflowConflict):
            n.retry(self.manager, queued["id"], {"expected_attempts": 1}, "admin")
        n.retry(self.manager, queued["id"], {"expected_revision": 1, "expected_attempts": 1, "confirm_possible_duplicate": True}, "admin")
        n.run_once(self.manager, transport=lambda *_: {"transport": "webhook", "status_code": 200})
        self.assertEqual(n.deliveries(self.store)["items"][0]["status"], "delivered")

    def test_temporary_provider_failures_stop_at_the_durable_retry_budget(self):
        self.configure()
        row = self.queue()
        delivery_ids = []
        def unavailable(channel, delivery):
            delivery_ids.append(delivery["id"])
            raise n.DeliveryFailure("retry", "provider_temporary", status_code=503)
        for _ in range(n.MAX_ATTEMPTS):
            current = next(value for value in n.deliveries(self.store)["items"] if value["id"] == row["id"])
            self.assertEqual(n.run_once(self.manager, transport=unavailable, at=parse_time(current["next_attempt_at"]) + timedelta(seconds=1))["processed"], 1)
        current = n.deliveries(self.store)["items"][0]
        self.assertEqual((current["status"], current["attempts"]), ("failed", n.MAX_ATTEMPTS))
        self.assertEqual(current["receipt"]["status_code"], 503)
        self.assertEqual(n.run_once(self.manager, transport=unavailable, at=now() + timedelta(days=1))["processed"], 0)
        self.assertEqual(delivery_ids, [row["id"]] * n.MAX_ATTEMPTS)

    def test_expired_worker_lease_holds_non_idempotent_delivery_and_recovers_idempotent_webhook(self):
        for supported in (False, True):
            with self.subTest(idempotent=supported):
                self.configure(self.body([self.channel(id="idempotent-" + str(supported), idempotency_supported=supported)]))
                value = self.queue("lease-" + str(supported))
                with self.store.meta() as db:
                    private = self.store._get(db, "notification_deliveries", value["id"])
                    private.update(status="in_flight", attempts=1, lease_until=stamp(now() - timedelta(seconds=1)))
                    n._put_delivery(db, private)
                n.run_once(self.manager, transport=lambda *_: {"transport": "webhook", "status_code": 200})
                row = next(row for row in n.deliveries(self.store)["items"] if row["id"] == value["id"])
                self.assertEqual(row["status"], "delivered" if supported else "uncertain")

    def test_changed_channel_cancels_pending_snapshot_and_test_requests_are_idempotent(self):
        self.configure()
        queued = self.queue()
        self.configure(self.body([self.channel(url="https://other.example.test/secret")]))
        self.assertEqual(n.deliveries(self.store)["items"][0]["status"], "cancelled")
        body = {"expected_revision": 2, "confirm": True, "request_id": "operator-test-one"}
        first = n.test(self.manager, "security", body, "admin")
        self.assertEqual(first["status"], "pending")
        self.assertEqual(n.test(self.manager, "security", body, "admin")["id"], first["id"])
        self.assertNotEqual(first["id"], queued["id"])
        self.manager.app.demo = True
        with self.assertRaises(ValueError):
            n.test(self.manager, "security", body, "admin")
        self.assertTrue(n.run_once(self.manager)["demo_blocked"])

    def test_http_transport_pins_reviewed_address_verifies_tls_signs_and_never_follows_redirects(self):
        self.configure()
        self.queue()
        calls = []
        class Connection:
            def __init__(self, host, port, address, context):
                calls.append((host, address, context.check_hostname, context.verify_mode))
            def connect(self):
                pass
            def request(self, method, path, payload, headers):
                calls.append((method, path, json.loads(payload), headers))
            def getresponse(self):
                return types.SimpleNamespace(status=302, read=lambda _: b"redirect")
            def close(self):
                pass
        with patch.object(n, "PinnedHTTPS", Connection), patch.object(n.socket, "getaddrinfo", self.resolver):
            n.run_once(self.manager)
        self.assertEqual(calls[0], ("alerts.example.test", "8.8.8.8", True, ssl.CERT_REQUIRED))
        self.assertTrue(calls[1][3]["X-Prthak-Signature"].startswith("v1="))
        self.assertEqual(calls[1][3]["Idempotency-Key"], n.deliveries(self.store)["items"][0]["id"])
        self.assertEqual(n.deliveries(self.store)["items"][0]["status"], "failed")
        self.assertEqual(len(calls), 2)

    def test_smtp_requires_starttls_before_auth_or_payload_and_keeps_stable_message_id(self):
        channel = self.channel(type="email", smtp_host="smtp.example.test", smtp_port=587, smtp_security="starttls", from_address="alerts@example.test", to_addresses=["operator@example.test"], username="private-smtp-user", password="private-smtp-password")
        for key in ("url", "signing_secret"):
            channel.pop(key)
        self.configure(self.body([channel]))
        self.queue()
        sequence = []
        class SMTP:
            def __init__(self, *args, **kwargs):
                sequence.append("connect")
            def ehlo(self):
                sequence.append("ehlo")
            def has_extn(self, extension):
                return True
            def starttls(self, context):
                self.assert_verified = context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
                sequence.append("verified_tls" if self.assert_verified else "unsafe_tls")
            def login(self, username, password):
                sequence.append("auth")
            def send_message(self, message):
                sequence.append(message["Message-ID"])
                return {}
            def close(self):
                sequence.append("close")
        with patch.object(n.smtplib, "SMTP", SMTP), patch.object(n.socket, "getaddrinfo", self.resolver):
            n.run_once(self.manager)
        self.assertEqual(sequence[:5], ["connect", "ehlo", "verified_tls", "ehlo", "auth"])
        self.assertTrue(sequence[5].endswith("@prthak.invalid>"))
        self.assertEqual(n.deliveries(self.store)["items"][0]["status"], "delivered")
        self.assertNotIn("private-smtp-password", json.dumps(self.store.all("audit")))

    def test_email_has_readable_plain_and_escaped_html_alternatives(self):
        channel = self.email_channel()
        event = n._event({"id": "event-123", "alert_id": "alert-123", "kind": "service_discovered", "severity": "info",
                          "hostname": "billing<&>", "message": "New service <script> on 8443/tcp & ready",
                          "created_at": "2026-11-04T10:00:00Z"})
        mail = n._email_message(channel, {"id": "delivery-123", "event": event})
        self.assertEqual(mail["Subject"], "Prṛthak · New service discovered (Information)")
        self.assertEqual(mail["Message-ID"], "<delivery-123@prthak.invalid>")
        self.assertIn("Time (UTC): 04 Nov 2026, 10:00:00", mail.get_body(preferencelist=("plain",)).get_content())
        html = mail.get_body(preferencelist=("html",)).get_content()
        self.assertIn("billing&lt;&amp;&gt;", html)
        self.assertIn("New service &lt;script&gt; on 8443/tcp &amp; ready", html)
        self.assertNotIn("<script>", html)
        self.assertIn("alert-123", html)

    def test_concurrent_workers_claim_only_once_and_another_controller_can_use_shared_encryption(self):
        self.configure()
        self.queue()
        other = PlatformManager(self.root / "other-controller")
        other.app = types.SimpleNamespace(store=Store(self.root / "db"), demo=False)
        other.shared_secret_key = self.manager.shared_secret_key
        entered, release = threading.Event(), threading.Event()
        sends, errors = [], []
        def transport(channel, delivery):
            sends.append(delivery["id"])
            entered.set()
            release.wait(3)
            return {"transport": "webhook", "status_code": 204}
        def worker():
            try:
                n.run_once(self.manager, transport=transport)
            except Exception as error:
                errors.append(type(error).__name__)
        thread = threading.Thread(target=worker)
        thread.start()
        try:
            self.assertTrue(entered.wait(3))
            self.assertEqual(n.run_once(other, transport=lambda *_: self.fail("An unexpired lease cannot be claimed twice"))["processed"], 0)
        finally:
            release.set()
            thread.join(3)
        self.assertEqual(errors, [])
        self.assertEqual(len(sends), 1)
        self.queue("peer-delivery")
        self.assertEqual(n.run_once(other, transport=lambda channel, _: {"transport": "webhook", "status_code": 204} if channel["signing_secret"] == self.secret else self.fail("Shared credential did not decrypt"))["processed"], 1)

    def test_rebinding_is_blocked_before_connect_and_ambiguous_http_retry_requires_receiver_deduplication(self):
        for supported in (False, True):
            self.configure(self.body([self.channel(id="transport-" + str(supported), idempotency_supported=supported)]))
            queued = self.queue("transport-" + str(supported))
            class Connection:
                def __init__(self, *args):
                    pass
                def connect(self):
                    pass
                def request(self, *args):
                    pass
                def getresponse(self):
                    raise OSError("Private provider detail must not escape")
                def close(self):
                    pass
            with patch.object(n, "PinnedHTTPS", Connection), patch.object(n.socket, "getaddrinfo", self.resolver):
                n.run_once(self.manager)
            row = next(value for value in n.deliveries(self.store)["items"] if value["id"] == queued["id"])
            self.assertEqual(row["status"], "retry" if supported else "uncertain")
        self.configure(self.body([self.channel(id="dns-protection")]))
        self.queue("dns-change")
        rebound = lambda host, port, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.1.2.3", port))]
        with patch.object(n, "PinnedHTTPS", side_effect=AssertionError("No socket after rebinding")), patch.object(n.socket, "getaddrinfo", rebound):
            n.run_once(self.manager)
        self.assertEqual(next(value for value in n.deliveries(self.store)["items"] if value["event"].get("alert_id") == "dns-change")["status"], "failed")

    def test_smtp_never_falls_back_to_plaintext_and_provider_retry_after_is_respected(self):
        email = self.channel(type="email", smtp_host="smtp.example.test", smtp_port=587, smtp_security="starttls", from_address="alerts@example.test", to_addresses=["operator@example.test"], username="secret-user", password="secret-password")
        self.configure(self.body([email]))
        self.queue()
        class NoStartTLS:
            def __init__(self, *args, **kwargs):
                pass
            def ehlo(self):
                pass
            def has_extn(self, extension):
                return False
            def login(self, *args):
                raise AssertionError("Credentials cannot be transmitted without TLS")
            def send_message(self, *args):
                raise AssertionError("Payload cannot be transmitted without TLS")
            def close(self):
                pass
        with patch.object(n.smtplib, "SMTP", NoStartTLS), patch.object(n.socket, "getaddrinfo", self.resolver):
            n.run_once(self.manager)
        self.assertEqual(n.deliveries(self.store)["items"][0]["status"], "failed")
        self.configure(self.body([self.channel(id="rate-limited")]))
        queued = self.queue("rate-limited")
        at = now()
        def throttled(*args):
            raise n.DeliveryFailure("retry", "provider_temporary", 429, 300)
        n.run_once(self.manager, transport=throttled, at=at)
        row = next(value for value in n.deliveries(self.store)["items"] if value["id"] == queued["id"])
        self.assertGreaterEqual((parse_time(row["next_attempt_at"]) - at).total_seconds(), 299)

    def test_same_alert_id_down_recovery_down_sends_two_occurrences_and_one_opted_in_recovery(self):
        self.configure(self.body([self.channel(minimum_severity="info", event_types=["agent_offline", "recovered"])]))
        at = now()
        with self.store.meta() as db, patch.object(store_module, "now", return_value=at):
            self.store._event(db, "offline:host-one", "agent_offline", "critical", "host-one", "Host one is down")
        self.assertEqual(n.enqueue_alerts(self.manager), 1)
        with self.store.meta() as db:
            alert = self.store._get(db, "alerts", "offline:host-one")
            alert.update(status="acknowledged", updated_at=stamp(at + timedelta(seconds=1)))
            self.store._put(db, "alerts", alert)
        self.assertEqual(n.enqueue_alerts(self.manager), 0, "Acknowledgement cannot create another occurrence")
        with self.store.meta() as db, patch.object(store_module, "now", return_value=at + timedelta(seconds=5)):
            self.store._resolve(db, "offline:host-one", "host-one", "Host one recovered")
        self.assertEqual(n.enqueue_alerts(self.manager), 1)
        with self.store.meta() as db, patch.object(store_module, "now", return_value=at + timedelta(seconds=10)):
            self.store._event(db, "offline:host-one", "agent_offline", "critical", "host-one", "Host one is down again")
        self.assertEqual(n.enqueue_alerts(self.manager), 1)
        self.assertEqual(n.enqueue_alerts(self.manager), 0)
        rows = n.deliveries(self.store)["items"]
        self.assertEqual(sum(row["event"]["kind"] == "agent_offline" for row in rows), 2)
        self.assertEqual(sum(row["event"]["kind"] == "recovered" for row in rows), 1)
        self.assertEqual(len({row["event_id"] for row in rows}), 3)
        n.run_once(self.manager, transport=lambda *_: {"transport": "webhook", "status_code": 204})
        self.assertTrue(all(row["status"] == "delivered" for row in n.deliveries(self.store)["items"]))

    def test_baseline_suppresses_only_the_old_occurrence_and_recovery_respects_filters(self):
        at = now()
        with self.store.meta() as db, patch.object(store_module, "now", return_value=at):
            self.store._event(db, "offline:preexisting", "agent_offline", "critical", "preexisting", "Old outage")
        self.configure()
        self.assertEqual(n.enqueue_alerts(self.manager), 0)
        with self.store.meta() as db, patch.object(store_module, "now", return_value=at + timedelta(seconds=5)):
            self.store._resolve(db, "offline:preexisting", "preexisting", "Old outage recovered")
        self.assertEqual(n.enqueue_alerts(self.manager), 0, "Warning-only destinations do not implicitly opt into informational recovery")
        with self.store.meta() as db, patch.object(store_module, "now", return_value=at + timedelta(seconds=10)):
            self.store._event(db, "offline:preexisting", "agent_offline", "critical", "preexisting", "New outage")
        self.assertEqual(n.enqueue_alerts(self.manager), 1)
        with self.store.read_meta() as db:
            channel = n._private(self.manager, n._settings(self.store, db))["channels"][0]
        self.assertNotIn("baseline_alert_ids", channel)
        self.assertTrue(all(len(value) == 64 for value in channel["baseline_occurrences"]))

    def test_same_second_reopening_uses_the_store_occurrence_identity(self):
        self.configure()
        at = now()
        with patch.object(store_module, "now", return_value=at):
            with self.store.meta() as db:
                self.store._event(db, "offline:rapid", "agent_offline", "critical", "rapid", "First outage")
            self.assertEqual(n.enqueue_alerts(self.manager), 1)
            with self.store.meta() as db:
                self.store._resolve(db, "offline:rapid", "rapid", "Recovered")
                self.store._event(db, "offline:rapid", "agent_offline", "critical", "rapid", "Second outage")
            self.assertEqual(n.enqueue_alerts(self.manager), 1)
        rows = n.deliveries(self.store)["items"]
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["event"]["created_at"], rows[1]["event"]["created_at"])
        self.assertNotEqual(rows[0]["event_id"], rows[1]["event_id"])


    def test_ipv6_transition_and_translation_addresses_cannot_bypass_destination_review(self):
        for address in ("::ffff:169.254.169.254", "64:ff9b::a9fe:a9fe", "64:ff9b:1::a9fe:a9fe", "2002:a9fe:a9fe::", "fec0::1"):
            resolver = lambda host, port, **kwargs: [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", (address, port))]
            with self.subTest(address=address), self.assertRaises(ValueError):
                n._addresses("private.example.test", 443, True, resolver)


if __name__ == "__main__":
    unittest.main()
