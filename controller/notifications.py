"""Reviewed external alert delivery with encrypted shared state and a durable outbox.

No transport is enabled by default. HTTPS/SMTP destinations are resolved and
reviewed before use; credentials never appear in public state, logs or audit.
An ambiguous non-idempotent send is held for operator review rather than silently
duplicated. Only a successful provider acknowledgement becomes delivered.
"""
from __future__ import annotations

import base64
from contextvars import ContextVar
from datetime import timedelta
from email.message import EmailMessage
import hashlib
import hmac
from functools import wraps
import http.client
import ipaddress
import json
import re
import secrets
import smtplib
import socket
import ssl
from urllib.parse import urlsplit
import uuid

from .firewall import WorkflowConflict
from .store import digest, now, parse_time, stamp

PURPOSE = "notifications-v1"
KEY_CONTEXT = ContextVar("notification_key", default=None)
SEVERITY = {"info": 0, "warning": 1, "critical": 2}
MAX_ATTEMPTS = 5
LEASE_SECONDS = 120
TERMINAL = {"delivered", "failed", "uncertain", "cancelled"}
MESSAGES = {"connection": "The reviewed destination could not be reached securely; delivery will retry.",
            "destination_changed": "Destination addresses changed; review the destination again before delivery.",
            "provider_rejected": "The provider rejected this notification.",
            "provider_temporary": "The provider reported a temporary delivery failure.",
            "authentication": "The SMTP provider rejected authentication; review its configured credentials.",
            "partial": "Only some email recipients were accepted. Review before retrying to avoid duplicate messages.",
            "ambiguous": "Provider acknowledgement is unknown. Review before retrying; the message may already have arrived.",
            "lease_expired": "The sending controller stopped before recording acknowledgement. Delivery may have occurred.",
            "configuration_changed": "The reviewed channel changed or was disabled before this delivery started.",
            "exhausted": "Automatic retry limit reached. Review this delivery before retrying.",
            "private_state": "Encrypted notification state is unavailable on this controller; delivery is blocked."}


def initialize(db):
    for table in ("notification_settings", "notification_revisions", "notification_reviews"):
        db.execute(f"CREATE TABLE IF NOT EXISTS {table} (id TEXT PRIMARY KEY,data TEXT NOT NULL)")
    db.executescript("""
      CREATE TABLE IF NOT EXISTS notification_deliveries (
        id TEXT PRIMARY KEY,event_id TEXT NOT NULL,channel_id TEXT NOT NULL,status TEXT NOT NULL,
        next_attempt_at TEXT NOT NULL,lease_until TEXT,created_at TEXT NOT NULL,data TEXT NOT NULL,
        UNIQUE(event_id,channel_id));
      CREATE INDEX IF NOT EXISTS notification_delivery_due ON notification_deliveries(status,next_attempt_at);
    """)


def _store(manager):
    store = getattr(getattr(manager, "app", None), "store", None)
    if store is None:
        raise ValueError("Configure a private controller state directory before managing notifications")
    return store


def _key(manager):
    snapshot = KEY_CONTEXT.get()
    return snapshot[1] if snapshot and snapshot[0] is manager else manager.shared_secret_key(PURPOSE)


def _with_key(callback):
    @wraps(callback)
    def execute(manager, *args, **kwargs):
        try:
            key = _key(manager)
            if not isinstance(key, bytes) or len(key) != 32:
                raise ValueError()
        except Exception:
            raise ValueError(MESSAGES["private_state"]) from None
        token = KEY_CONTEXT.set((manager, key))
        try:
            return callback(manager, *args, **kwargs)
        finally:
            KEY_CONTEXT.reset(token)
    return execute


def _seal(manager, value, label):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    try:
        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(_key(manager)).encrypt(nonce, json.dumps(value, sort_keys=True).encode(), (PURPOSE + ":" + label).encode())
    except Exception:
        raise ValueError(MESSAGES["private_state"]) from None
    return {"format": 1, "nonce": base64.b64encode(nonce).decode(), "ciphertext": base64.b64encode(ciphertext).decode()}


def _open(manager, value, label):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    try:
        return json.loads(AESGCM(_key(manager)).decrypt(base64.b64decode(value["nonce"], validate=True), base64.b64decode(value["ciphertext"], validate=True), (PURPOSE + ":" + label).encode()))
    except Exception:
        raise ValueError(MESSAGES["private_state"]) from None


def _settings(store, db):
    return store._get(db, "notification_settings", "settings") or {"id": "settings", "revision": 0, "enabled": False, "channels": []}


def _private(manager, config):
    return _open(manager, config["sealed"], "config:" + str(config["revision"])) if config.get("sealed") else {"channels": []}


def _text(value, maximum, label, *, empty=False):
    if not isinstance(value, str) or len(value) > maximum or (not empty and not value.strip()) or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("Provide a valid " + label)
    return value.strip()


def _secret(value, previous, name):
    value = value.get(name)
    if value in (None, ""):
        return previous.get(name, "")
    if not isinstance(value, str) or len(value) > 8192 or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("Invalid notification credential")
    return value


def _addresses(host, port, allow_private, resolver=None):
    try:
        records = (resolver or socket.getaddrinfo)(host, port, type=socket.SOCK_STREAM)
        addresses = sorted({str(ipaddress.ip_address(row[4][0])) for row in records})
    except Exception:
        raise DestinationUnavailable("The notification destination could not be resolved") from None
    if not addresses or len(addresses) > 16:
        raise ValueError("The destination must resolve to between one and sixteen concrete addresses")
    for value in addresses:
        address = ipaddress.ip_address(value)
        private = any(address in network for network in PRIVATE_NETWORKS if address.version == network.version)
        transition = address.version == 6 and (address.ipv4_mapped is not None or address.sixtofour is not None or address.teredo is not None or address.is_site_local or any(address in network for network in TRANSITION_NETWORKS))
        if transition or address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified or (not address.is_global and not (allow_private and private)):
            raise ValueError("Notification destinations cannot use local, link-local or reserved addresses. Private networks require explicit review approval.")
    return addresses


PRIVATE_NETWORKS = tuple(ipaddress.ip_network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"))
TRANSITION_NETWORKS = tuple(ipaddress.ip_network(value) for value in ("::/96", "64:ff9b::/96", "64:ff9b:1::/48"))


class DestinationUnavailable(ValueError):
    pass


def _mailbox(value):
    value = _text(value, 254, "email address")
    if not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,63}", value):
        raise ValueError("Use a plain email address without a display name")
    return value


def _occurrence(alert):
    fields = {key: alert.get(key) for key in ("id", "created_at", "kind")}
    if alert.get("occurrence_id"):
        fields["occurrence_id"] = alert["occurrence_id"]
    return digest(fields)


def _baseline(channel, alerts, configured_at=None):
    if "baseline_occurrences" in channel:
        return channel["baseline_occurrences"]
    # Pre-release ID-only configurations conservatively exclude the current
    # old occurrence, but must never suppress a future reopening of that ID.
    legacy = set(channel.get("baseline_alert_ids", []))
    return [_occurrence(alert) for alert in alerts if alert["id"] in legacy and (not configured_at or alert.get("created_at", "") <= configured_at)]


def _normalize(manager, body, current, db, resolver=None):
    if not isinstance(body, dict) or set(body) - {"expected_revision", "enabled", "channels"}:
        raise ValueError("Provide expected_revision, enabled and notification channels")
    if not isinstance(body.get("enabled"), bool) or not isinstance(body.get("channels"), list) or len(body["channels"]) > 20:
        raise ValueError("Choose enabled true/false and at most twenty channels")
    previous = {channel["id"]: channel for channel in _private(manager, current)["channels"]}
    alerts = _store(manager)._all(db, "alerts")
    channels, ids = [], set()
    allowed = {"id", "name", "type", "enabled", "minimum_severity", "event_types", "allow_private_network", "idempotency_supported", "url", "signing_secret", "auth_token", "smtp_host", "smtp_port", "smtp_security", "username", "password", "from_address", "to_addresses", "custom_ca_pem"}
    for raw in body["channels"]:
        if not isinstance(raw, dict) or set(raw) - allowed:
            raise ValueError("Unsupported notification channel field")
        identifier = raw.get("id") or uuid.uuid4().hex
        if not isinstance(identifier, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,100}", identifier) or identifier in ids:
            raise ValueError("Notification channel IDs must be distinct")
        ids.add(identifier)
        old = previous.get(identifier, {})
        kind, enabled = raw.get("type"), raw.get("enabled", True)
        if kind not in ("slack", "teams", "webhook", "email") or not isinstance(enabled, bool):
            raise ValueError("Choose a Slack, Microsoft Teams, webhook or email channel and an enabled state")
        if old and old["type"] != kind:
            raise ValueError("Create a new channel when changing its transport type")
        level, events = raw.get("minimum_severity", "warning"), raw.get("event_types", ["*"])
        if level not in SEVERITY or not isinstance(events, list) or not 1 <= len(events) <= 50 or any(not isinstance(event, str) or not re.fullmatch(r"\*|[A-Za-z0-9_.:-]{1,80}", event) for event in events):
            raise ValueError("Choose a valid severity and event type list")
        private, idempotent = raw.get("allow_private_network", False), raw.get("idempotency_supported", False)
        if not isinstance(private, bool) or not isinstance(idempotent, bool) or kind != "webhook" and idempotent:
            raise ValueError("Private-network and receiver-idempotency approvals must be explicit booleans")
        channel = {"id": identifier, "name": _text(raw.get("name"), 120, "channel name"), "type": kind, "enabled": enabled,
                   "minimum_severity": level, "event_types": sorted(set(events)), "allow_private_network": private,
                   "idempotency_supported": idempotent}
        ca = raw.get("custom_ca_pem") or old.get("custom_ca_pem", "")
        if not isinstance(ca, str) or len(ca) > 65536:
            raise ValueError("Custom notification trust must be a bounded PEM CA bundle")
        if ca:
            try:
                ssl.create_default_context().load_verify_locations(cadata=ca)
            except Exception:
                raise ValueError("Custom notification CA certificates could not be verified") from None
        channel["custom_ca_pem"] = ca
        if kind in ("slack", "teams", "webhook"):
            url = _secret(raw, old, "url")
            parsed = urlsplit(url)
            try:
                port = parsed.port if parsed.port is not None else 443
            except ValueError:
                raise ValueError("Use a valid HTTPS notification destination") from None
            if parsed.scheme != "https" or not parsed.hostname or not 1 <= port <= 65535 or parsed.username or parsed.password or parsed.fragment or "\\" in url or any(char.isspace() for char in url):
                raise ValueError("Use a complete HTTPS webhook URL without URL credentials or fragments")
            if kind == "slack" and (parsed.hostname not in ("hooks.slack.com", "hooks.slack-gov.com") or not parsed.path.startswith("/services/")):
                raise ValueError("Use an official Slack incoming-webhook URL")
            if kind == "teams":
                host=parsed.hostname.lower()
                if port!=443 or not (host in ('outlook.office.com','webhook.office.com') or any(host.endswith(suffix) for suffix in ('.webhook.office.com','.logic.azure.com','.api.powerplatform.com'))):
                    raise ValueError("Use an official Microsoft Teams Workflow or incoming-webhook HTTPS URL")
            channel.update(url=url, host=parsed.hostname.lower(), port=port,
                           signing_secret=_secret(raw, old, "signing_secret"), auth_token=_secret(raw, old, "auth_token"))
        else:
            host = _text(raw.get("smtp_host", old.get("host", "")), 253, "SMTP hostname")
            if any(char in host for char in "/\\@?#:"):
                raise ValueError("Use an SMTP DNS hostname or numeric IPv4 address")
            port, security = raw.get("smtp_port", 587), raw.get("smtp_security", "starttls")
            recipients = raw.get("to_addresses", old.get("to_addresses", []))
            if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535 or security not in ("tls", "starttls") or not isinstance(recipients, list) or not 1 <= len(recipients) <= 20:
                raise ValueError("Choose a TLS SMTP port, TLS or required STARTTLS, and one to twenty recipients")
            channel.update(host=host.lower(), port=port, smtp_security=security, from_address=_mailbox(raw.get("from_address", old.get("from_address", ""))),
                           to_addresses=sorted({_mailbox(value) for value in recipients}), username=_secret(raw, old, "username"), password=_secret(raw, old, "password"))
            if bool(channel["username"]) != bool(channel["password"]):
                raise ValueError("Provide both SMTP username and password, or use an explicitly unauthenticated TLS relay")
        channel["addresses"] = _addresses(channel["host"], channel["port"], private, resolver)
        channel["baseline_occurrences"] = _baseline(old, alerts, current.get("updated_at")) if old.get("enabled") and current.get("enabled") else [_occurrence(alert) for alert in alerts]
        channel["start_new_stream"] = not (old.get("enabled") and current.get("enabled"))
        binding_key = hmac.new(_key(manager), b"prthak-notification-channel-binding", hashlib.sha256).digest()
        channel["binding"] = hmac.new(binding_key, json.dumps({key: value for key, value in channel.items() if key not in ("baseline_occurrences", "start_new_stream", "binding")}, sort_keys=True).encode(), hashlib.sha256).hexdigest()
        channels.append(channel)
    return {"enabled": body["enabled"], "channels": channels}


def _public_channel(channel):
    public = {key: channel.get(key) for key in ("id", "name", "type", "enabled", "minimum_severity", "event_types", "allow_private_network", "idempotency_supported")}
    public.update(host=channel["host"], port=channel["port"], addresses=channel["addresses"],
                  destination=("https://" + channel["host"] + (":" + str(channel["port"]) if channel["port"] != 443 else "") + "/…") if channel["type"] != "email" else channel["host"] + ":" + str(channel["port"]),
                  credential_flags={key + "_configured": bool(channel.get(key)) for key in ("url", "signing_secret", "auth_token", "username", "password", "custom_ca_pem")})
    if channel["type"] == "email":
        public.update(smtp_host=channel["host"], smtp_port=channel["port"], smtp_security=channel["smtp_security"], from_address=channel["from_address"], to_addresses=channel["to_addresses"])
    return public


def get(manager):
    store = _store(manager)
    with store.read_meta() as db:
        config = _settings(store, db)
        counts = {row[0]: row[1] for row in db.execute("SELECT status,COUNT(*) FROM notification_deliveries GROUP BY status").fetchall()}
    return {key: config.get(key) for key in ("revision", "enabled", "channels", "updated_at", "updated_by")} | {"delivery_counts": counts, "disabled_by_default": True,
        "semantics": "Receiver acknowledgement required; uncertain Slack/SMTP sends are held for review. Webhook retries use a stable Idempotency-Key.", "new_alerts_only": True}


@_with_key
def preview(manager, body, actor, *, resolver=None):
    store = _store(manager)
    with store.lock, store.meta() as db:
        current = _settings(store, db)
        expected = body.get("expected_revision") if isinstance(body, dict) else None
        if isinstance(expected, bool) or not isinstance(expected, int) or expected != current["revision"]:
            raise WorkflowConflict("Notification configuration changed; reload before reviewing", {"current_revision": current["revision"]})
        private = _normalize(manager, body, current, db, resolver)
        identifier = uuid.uuid4().hex
        public = {"enabled": private["enabled"], "channels": [_public_channel(channel) for channel in private["channels"]]}
        plan = {"id": identifier, "expected_revision": expected, "summary": public, "expires_at": stamp(now() + timedelta(minutes=10)),
                "confirmation_nonce": secrets.token_urlsafe(24), "confirmation_phrase": "ENABLE REVIEWED NOTIFICATIONS" if private["enabled"] else "SAVE DISABLED NOTIFICATIONS",
                "warnings": ["This authorizes external delivery of future alert summaries to exactly the reviewed destinations. DNS address changes require another destination review.", "An already sending notification may finish using its frozen, previously reviewed destination."],
                "blockers": [], "sealed": _seal(manager, private, "review:" + identifier), "created_by": actor}
        plan["digest"] = digest({key: value for key, value in plan.items() if key != "sealed"})
        store._put(db, "notification_reviews", plan)
        store.audit("notifications.reviewed", actor, {"review_id": identifier, "channel_ids": [channel["id"] for channel in private["channels"]]}, db)
    return {key: value for key, value in plan.items() if key not in ("sealed", "created_by")}


def _put_delivery(db, value):
    fields = ("id", "event_id", "channel_id", "status", "next_attempt_at", "lease_until", "created_at")
    db.execute("INSERT INTO notification_deliveries(" + ",".join(fields) + ",data) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status,next_attempt_at=excluded.next_attempt_at,lease_until=excluded.lease_until,data=excluded.data", tuple(value.get(key) for key in fields) + (json.dumps(value, sort_keys=True),))


def _cas_delivery(db, previous, value):
    return db.execute("UPDATE notification_deliveries SET status=?,next_attempt_at=?,lease_until=?,data=? WHERE id=? AND data=? RETURNING id",
                      (value["status"], value["next_attempt_at"], value.get("lease_until"), json.dumps(value, sort_keys=True), value["id"], previous)).fetchone() is not None


@_with_key
def apply(manager, body, actor, *, resolver=None):
    store = _store(manager)
    identifier = body.get("preview_id") if isinstance(body, dict) else None
    with store.lock, store.meta() as db:
        plan = store._get(db, "notification_reviews", identifier) if isinstance(identifier, str) else None
        current = _settings(store, db)
        if not plan or parse_time(plan["expires_at"]) <= now() or current["revision"] != plan["expected_revision"] or any(body.get(key) != plan[key] for key in ("digest", "confirmation_nonce", "confirmation_phrase")):
            raise WorkflowConflict("Use a fresh exact notification destination review and confirmation phrase", {})
        private = _open(manager, plan["sealed"], "review:" + plan["id"])
        for channel in private["channels"]:
            if _addresses(channel["host"], channel["port"], channel["allow_private_network"], resolver) != channel["addresses"]:
                raise WorkflowConflict(MESSAGES["destination_changed"], {})
            if channel.pop("start_new_stream", False):
                channel["baseline_occurrences"] = [_occurrence(alert) for alert in store._all(db, "alerts")]
        config = {"id": "settings", "revision": current["revision"] + 1, "enabled": private["enabled"], "channels": [_public_channel(channel) for channel in private["channels"]],
                  "updated_at": stamp(), "updated_by": actor}
        config["sealed"] = _seal(manager, private, "config:" + str(config["revision"]))
        store._put(db, "notification_settings", config)
        store._put(db, "notification_revisions", {**config, "id": "revision:" + str(config["revision"])})
        bindings = {channel["id"]: channel["binding"] for channel in private["channels"] if channel["enabled"] and config["enabled"]}
        for row in db.execute("SELECT data FROM notification_deliveries WHERE status IN ('pending','retry')").fetchall():
            delivery = json.loads(row[0])
            if bindings.get(delivery["channel_id"]) != delivery["channel_binding"]:
                delivery.update(status="cancelled", error=MESSAGES["configuration_changed"], updated_at=stamp())
                _put_delivery(db, delivery)
        plan["applied_revision"] = config["revision"]
        store._put(db, "notification_reviews", plan)
        store.audit("notifications.configured", actor, {"revision": config["revision"], "enabled": config["enabled"], "channel_ids": list(bindings)}, db)
    return get(manager)


def _event(value):
    identifier = _text(value.get("id"), 200, "notification event ID")
    kind = _text(value.get("kind"), 80, "event type")
    severity = value.get("severity", "warning")
    if severity not in SEVERITY:
        raise ValueError("Unknown notification severity")
    # Payloads contain only intentional alert summary fields, never config,
    # arbitrary event details, headers, certificates or credentials.
    return {"id": identifier, "kind": kind, "severity": severity, **({"alert_id": str(value["alert_id"])[:200]} if value.get("alert_id") else {}),
            "message": str(value.get("message", "Alert reported"))[:1800], "server_id": str(value.get("server_id", ""))[:100],
            "hostname": str(value.get("hostname", ""))[:253], "created_at": value.get("created_at") or stamp()}


def _enqueue(store, db, config, channel, event, *, test=False):
    if db.execute("SELECT id FROM notification_deliveries WHERE event_id=? AND channel_id=?", (event["id"], channel["id"])).fetchone():
        return None
    identifier, at = uuid.uuid4().hex, stamp()
    delivery = {"id": identifier, "event_id": event["id"], "channel_id": channel["id"], "channel_name": channel["name"], "channel_type": channel["type"],
                "channel_binding": channel["binding"], "configuration_revision": config["revision"], "destination": _public_channel(channel)["destination"],
                "event": event, "status": "pending", "attempts": 0, "next_attempt_at": at, "lease_until": None, "created_at": at, "updated_at": at, "test": test, "error": ""}
    _put_delivery(db, delivery)
    return delivery


def enqueue_alerts(manager):
    store = _store(manager)
    with store.read_meta() as db:
        if not _settings(store, db).get("sealed"):
            return 0
    return _enqueue_alerts(manager)


@_with_key
def _enqueue_alerts(manager):
    store = _store(manager)
    if getattr(manager.app, "demo", False):
        return 0
    count = 0
    with store.lock, store.meta() as db:
        config = _settings(store, db)
        if not config["enabled"]:
            return 0
        private = _private(manager, config)
        hosts = {server["id"]: server.get("hostname", "") for server in store._all(db, "servers")}
        alerts = store._all(db, "alerts")
        baselines = {channel["id"]: set(_baseline(channel, alerts, config.get("updated_at"))) for channel in private["channels"]}
        for alert in alerts:
            recovery = alert.get("kind") == "recovered" and alert.get("status") == "resolved"
            if (alert.get("status") not in ("open", "acknowledged") and not recovery) or alert.get("severity") not in SEVERITY:
                continue
            occurrence = _occurrence(alert)
            event = _event({**alert, "id": "alert:" + occurrence, "alert_id": alert["id"], "hostname": hosts.get(alert.get("server_id"), "")})
            for channel in private["channels"]:
                if channel["enabled"] and occurrence not in baselines[channel["id"]] and SEVERITY[event["severity"]] >= SEVERITY[channel["minimum_severity"]] and ("*" in channel["event_types"] or event["kind"] in channel["event_types"]):
                    count += int(_enqueue(store, db, config, channel, event) is not None)
    return count


@_with_key
def test(manager, identifier, body, actor):
    store = _store(manager)
    if getattr(manager.app, "demo", False):
        raise ValueError("Demo mode cannot send external notifications")
    request_id = body.get("request_id") if isinstance(body, dict) else None
    if not isinstance(body, dict) or body.get("confirm") is not True or not isinstance(request_id, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,100}", request_id):
        raise ValueError("Explicitly confirm this test with a stable request_id")
    with store.lock, store.meta() as db:
        config = _settings(store, db)
        if isinstance(body.get("expected_revision"), bool) or not isinstance(body.get("expected_revision"), int) or body.get("expected_revision") != config["revision"]:
            raise WorkflowConflict("Notification settings changed; reload before testing", {})
        channel = next((value for value in _private(manager, config)["channels"] if value["id"] == identifier and value["enabled"]), None)
        if channel is None:
            raise ValueError("Choose an enabled, reviewed notification channel")
        delivery = _enqueue(store, db, config, channel, _event({"id": "test:" + request_id, "kind": "configuration_test", "severity": "info", "message": "Prṛthak reviewed notification delivery test"}), test=True)
        if delivery is None:
            delivery = json.loads(db.execute("SELECT data FROM notification_deliveries WHERE event_id=? AND channel_id=?", ("test:" + request_id, identifier)).fetchone()[0])
        store.audit("notifications.test_requested", actor, {"delivery_id": delivery["id"], "channel_id": identifier}, db)
    return _public_delivery(delivery)


def _public_delivery(value):
    return {key: value.get(key) for key in ("id", "event_id", "channel_id", "channel_name", "channel_type", "destination", "event", "status", "attempts", "next_attempt_at", "created_at", "updated_at", "test", "error", "receipt")}


def deliveries(store, limit=100, offset=0):
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 200 or isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise ValueError("Choose a delivery page size from one to two hundred")
    with store.read_meta() as db:
        rows = db.execute("SELECT data FROM notification_deliveries ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?", (limit, offset)).fetchall()
        total = db.execute("SELECT COUNT(*) FROM notification_deliveries").fetchone()[0]
    return {"items": [_public_delivery(json.loads(row[0])) for row in rows], "total": total, "limit": limit, "offset": offset, "has_more": offset + len(rows) < total}


@_with_key
def retry(manager, identifier, body, actor):
    store = _store(manager)
    with store.lock, store.meta() as db:
        value = store._get(db, "notification_deliveries", identifier)
        if not value:
            raise KeyError(identifier)
        config = _settings(store, db)
        if not isinstance(body, dict) or isinstance(body.get("expected_attempts"), bool) or not isinstance(body.get("expected_attempts"), int) or value["status"] not in ("failed", "uncertain") or body.get("expected_attempts") != value["attempts"] or body.get("confirm_possible_duplicate") is not True:
            raise WorkflowConflict("Review the current failed or uncertain delivery and explicitly accept possible duplication", {})
        if isinstance(body.get("expected_revision"), bool) or not isinstance(body.get("expected_revision"), int) or body["expected_revision"] != config["revision"]:
            raise WorkflowConflict("The saved destination changed; review the retry again", {})
        channel = next((channel for channel in _private(manager, config)["channels"] if channel["id"] == value["channel_id"] and channel["enabled"]), None)
        if channel is None:
            raise ValueError("This delivery no longer has an enabled reviewed destination")
        if value["attempts"] >= 20:
            raise ValueError("This delivery reached its bounded operator retry limit")
        value.update(status="retry", next_attempt_at=stamp(), retry_budget=value["attempts"] + MAX_ATTEMPTS, error="", updated_at=stamp(),
                     channel_binding=channel["binding"], configuration_revision=config["revision"], destination=_public_channel(channel)["destination"])
        _put_delivery(db, value)
        store.audit("notifications.retry_requested", actor, {"delivery_id": identifier, "attempts": value["attempts"]}, db)
    return _public_delivery(value)


class DeliveryFailure(Exception):
    def __init__(self, outcome, code, status_code=None, retry_after=None):
        self.outcome, self.code, self.status_code = outcome, code, status_code
        self.retry_after = retry_after


class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, port, address, context):
        super().__init__(host, port, timeout=10, context=context)
        self.address = address

    def connect(self):
        raw = socket.create_connection((self.address, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close()
            raise


def _tls(channel):
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if channel.get("custom_ca_pem"):
        context.load_verify_locations(cadata=channel["custom_ca_pem"])
    return context


def _http(channel, delivery):
    event = delivery["event"]
    if channel["type"] == "slack":
        text = ("Prṛthak · " + event["severity"].upper() + " · " + event["kind"] + "\n" + event["hostname"] + "\n" + event["message"])[:2900]
        value = {"text": text, "mrkdwn": False, "parse": "none", "unfurl_links": False, "unfurl_media": False,
                 "blocks": [{"type": "section", "text": {"type": "plain_text", "text": text}}]}
    elif channel["type"] == "teams":
        text=("Prṛthak · "+event["severity"].upper()+" · "+event["kind"]+"\n"+event["hostname"]+"\n"+event["message"])[:2900]
        value={"type":"message","attachments":[{"contentType":"application/vnd.microsoft.card.adaptive","contentUrl":None,
               "content":{"$schema":"http://adaptivecards.io/schemas/adaptive-card.json","type":"AdaptiveCard","version":"1.2",
                          "body":[{"type":"TextBlock","text":text,"wrap":True}]}}]}
    else:
        value = {"product": "prthak", "delivery_id": delivery["id"], "event": event}
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    timestamp = str(int(now().timestamp()))
    headers = {"Content-Type": "application/json", "User-Agent": "Prthak-Notifications/1", "Idempotency-Key": delivery["id"], "X-Prthak-Event-ID": event["id"], "X-Prthak-Timestamp": timestamp}
    if channel.get("signing_secret"):
        headers["X-Prthak-Signature"] = "v1=" + hmac.new(channel["signing_secret"].encode(), timestamp.encode() + b"." + payload, hashlib.sha256).hexdigest()
    if channel.get("auth_token"):
        headers["Authorization"] = "Bearer " + channel["auth_token"]
    parsed = urlsplit(channel["url"])
    connection = PinnedHTTPS(channel["host"], channel["port"], channel["addresses"][(delivery["attempts"] - 1) % len(channel["addresses"])], _tls(channel))
    transmitting = False
    try:
        connection.connect()
        transmitting = True
        connection.request("POST", (parsed.path or "/") + ("?" + parsed.query if parsed.query else ""), payload, headers)
        response = connection.getresponse()
        body = response.read(65537)
        if 200 <= response.status < 300 and len(body) <= 65536 and (channel["type"] != "slack" or body.strip() == b"ok"):
            return {"transport": channel["type"], "status_code": response.status}
        if response.status in (408, 425, 429) or 500 <= response.status <= 599:
            delay = response.getheader("Retry-After", "")
            delay = max(30, min(86400, int(delay))) if re.fullmatch(r"[0-9]{1,6}", delay) else None
            raise DeliveryFailure("retry", "provider_temporary", response.status, delay)
        raise DeliveryFailure("failed", "provider_rejected", response.status)
    except DeliveryFailure:
        raise
    except Exception:
        raise DeliveryFailure("retry" if not transmitting or channel["idempotency_supported"] else "uncertain", "connection" if not transmitting else "ambiguous") from None
    finally:
        connection.close()


def _smtp(channel, delivery):
    address = channel["addresses"][(delivery["attempts"] - 1) % len(channel["addresses"])]
    context = _tls(channel)

    class SMTP(smtplib.SMTP):
        def _get_socket(self, host, port, timeout):
            return socket.create_connection((address, port), timeout)

    class SMTPS(smtplib.SMTP_SSL):
        def _get_socket(self, host, port, timeout):
            raw = socket.create_connection((address, port), timeout)
            try:
                return self.context.wrap_socket(raw, server_hostname=self._host)
            except Exception:
                raw.close()
                raise

    client, transmitting = None, False
    try:
        client = SMTPS(channel["host"], channel["port"], timeout=10, context=context) if channel["smtp_security"] == "tls" else SMTP(channel["host"], channel["port"], timeout=10)
        client.ehlo()
        if channel["smtp_security"] == "starttls":
            if not client.has_extn("starttls"):
                raise DeliveryFailure("failed", "provider_rejected")
            client.starttls(context=context)
            client.ehlo()
        if channel["username"]:
            client.login(channel["username"], channel["password"])
        message = EmailMessage()
        message["From"], message["To"] = channel["from_address"], ", ".join(channel["to_addresses"])
        message["Subject"] = "Prṛthak " + delivery["event"]["severity"].upper() + " · " + delivery["event"]["kind"].replace("\n", " ")[:80]
        message["Message-ID"] = "<" + delivery["id"] + "@prthak.invalid>"
        message.set_content(json.dumps(delivery["event"], ensure_ascii=False, indent=2))
        transmitting = True
        rejected = client.send_message(message)
        if rejected:
            raise DeliveryFailure("uncertain", "partial")
        return {"transport": "email", "accepted_recipients": len(channel["to_addresses"])}
    except DeliveryFailure:
        raise
    except smtplib.SMTPAuthenticationError:
        raise DeliveryFailure("failed", "authentication") from None
    except (smtplib.SMTPRecipientsRefused, smtplib.SMTPSenderRefused, smtplib.SMTPDataError) as error:
        code = getattr(error, "smtp_code", 0)
        if isinstance(error, smtplib.SMTPRecipientsRefused):
            codes = [value[0] for value in error.recipients.values()]
            code = min(codes) if codes else 0
        raise DeliveryFailure("retry" if 400 <= code < 500 else "failed", "provider_temporary" if 400 <= code < 500 else "provider_rejected", code) from None
    except Exception:
        raise DeliveryFailure("uncertain" if transmitting else "retry", "ambiguous" if transmitting else "connection") from None
    finally:
        if client:
            client.close()


def dispatch(channel, delivery, *, resolver=None):
    try:
        addresses = _addresses(channel["host"], channel["port"], channel["allow_private_network"], resolver)
    except DestinationUnavailable:
        raise DeliveryFailure("retry", "connection") from None
    except ValueError:
        raise DeliveryFailure("failed", "destination_changed") from None
    if addresses != channel["addresses"]:
        raise DeliveryFailure("failed", "destination_changed")
    return _smtp(channel, delivery) if channel["type"] == "email" else _http(channel, delivery)


def run_once(manager, *, transport=None, limit=20, at=None):
    store = _store(manager)
    with store.read_meta() as db:
        if not _settings(store, db).get("sealed"):
            return {"processed": 0}
    return _run_once(manager, transport=transport, limit=limit, at=at)


@_with_key
def _run_once(manager, *, transport=None, limit=20, at=None):
    store, at = _store(manager), at or now()
    if getattr(manager.app, "demo", False):
        return {"processed": 0, "demo_blocked": True}
    processed = 0
    for _ in range(min(20, max(0, limit))):
        with store.lock, store.meta() as db:
            config = _settings(store, db)
            private = _private(manager, config)
            channels = {channel["id"]: channel for channel in private["channels"]}
            for row in db.execute("SELECT data FROM notification_deliveries WHERE status='in_flight' AND lease_until<=?", (stamp(at),)).fetchall():
                abandoned = json.loads(row[0])
                channel = channels.get(abandoned["channel_id"], {})
                abandoned.update(status="retry" if channel.get("idempotency_supported") else "uncertain", error=MESSAGES["lease_expired"], lease_until=None, updated_at=stamp(at))
                _put_delivery(db, abandoned)
            row = db.execute("SELECT data FROM notification_deliveries WHERE status IN ('pending','retry') AND next_attempt_at<=? ORDER BY next_attempt_at,id LIMIT 1", (stamp(at),)).fetchone()
            if not row:
                break
            delivery = json.loads(row[0])
            channel = channels.get(delivery["channel_id"])
            if not channel or not channel["enabled"] or not (config["enabled"] or delivery["test"]) or channel["binding"] != delivery["channel_binding"]:
                delivery.update(status="cancelled", error=MESSAGES["configuration_changed"], updated_at=stamp(at))
                _put_delivery(db, delivery)
                continue
            if delivery["attempts"] >= delivery.get("retry_budget", MAX_ATTEMPTS):
                delivery.update(status="failed", error=MESSAGES["exhausted"], updated_at=stamp(at))
                _put_delivery(db, delivery)
                continue
            lease = uuid.uuid4().hex
            delivery.update(status="in_flight", attempts=delivery["attempts"] + 1, lease_token=lease, lease_until=stamp(at + timedelta(seconds=LEASE_SECONDS)), updated_at=stamp(at))
            if not _cas_delivery(db, row[0], delivery):
                continue
        try:
            retry_after = None
            receipt = (transport or dispatch)(channel, delivery)
            result = {"status": "delivered", "receipt": {key: receipt[key] for key in ("transport", "status_code", "accepted_recipients") if key in receipt}, "error": ""}
        except DeliveryFailure as error:
            retry_after = error.retry_after
            result = {"status": error.outcome, "error": MESSAGES.get(error.code, MESSAGES["ambiguous"])}
            if isinstance(error.status_code, int) and 100 <= error.status_code <= 599:
                result["receipt"] = {"transport": channel["type"], "status_code": error.status_code}
            if error.outcome == "retry" and delivery["attempts"] >= delivery.get("retry_budget", MAX_ATTEMPTS):
                result.update(status="failed", error=MESSAGES["exhausted"])
        except Exception:
            result = {"status": "uncertain", "error": MESSAGES["ambiguous"]}
        with store.lock, store.meta() as db:
            saved = db.execute("SELECT data FROM notification_deliveries WHERE id=?", (delivery["id"],)).fetchone()
            current = json.loads(saved[0]) if saved else None
            if current and current["status"] == "in_flight" and current.get("lease_token") == lease:
                delay = max(retry_after or 0, min(3600, 30 * 2 ** min(8, current["attempts"] - 1)))
                current.update(result, lease_until=None, updated_at=stamp(at), next_attempt_at=stamp(at + timedelta(seconds=delay)))
                if _cas_delivery(db, saved[0], current):
                    store.audit("notifications.delivery_outcome", "notification-worker", {"delivery_id": current["id"], "channel_id": current["channel_id"], "status": current["status"], "attempts": current["attempts"]}, db)
        processed += 1
    return {"processed": processed}
