"""Safe email summaries for audited changes and confirmed inbound allows."""
import json

from .store import digest, stamp


ADMIN_ACTIONS = {
    "policy.created", "policy.updated", "policy.deleted", "policy.restored_as_new_revision",
    "group.created", "group.updated", "group.deleted",
    "service_group.created", "service_group.updated", "service_group.deleted",
    "location.created", "location.updated", "location.deleted",
    "server.updated", "server.reserved", "server.retired",
    "metadata.bulk.applied", "metadata.csv_import.applied", "metadata.csv_profile_delete.applied",
    "metadata.subnet.applied", "metadata.subnet_delete.applied",
    "access.user.created", "access.user.updated", "access.user.sessions_revoked",
    "access.local.password_reset", "access.local.password_changed", "access.saml.configured",
    "agent_polling.updated", "agent_upgrade.confirmed",
    "firewall_change.confirmed", "firewall_change.cancelled", "firewall_activation.authorized",
    "managed_rollout.confirmed", "managed_rollout.cancelled", "host_default_deny.pushed", "network_control.pushed",
    "managed_policy.cleanup_authorized", "source_banks.activation_authorized",
    "learning.started", "learning.stopped", "learning_policy.applied_from_review",
    "learning_policy.edited", "learning_policy.removed", "hit_monitor.enable", "hit_monitor.disable",
    "enrollment_token.created", "fleet_enrollment.created", "fleet_enrollment.revoked", "endpoint.certificates_revoked",
    "endpoint.configuration.approved", "endpoint.configuration.revoked",
    "application_port.queued", "controller.display_name_changed", "controller_update.apply_confirmed",
    "maintenance.backup_schedule_updated", "maintenance.default_data_cleared", "recovery.approved",
    "appliance.configuration_saved", "appliance.replication_rotation_requested", "appliance.member_suspended",
    "platform.configuration_saved", "platform.job_queued", "platform.provider.transition_requested",
    "policy_signing.recovered", "risk.catalog.updated", "siem.configured",
}


def initialize(db):
    db.execute("CREATE TABLE IF NOT EXISTS notification_events (id TEXT PRIMARY KEY, created_at TEXT NOT NULL, data TEXT NOT NULL)")
    db.execute("CREATE INDEX IF NOT EXISTS notification_events_pending ON notification_events(created_at,id)")


def subscribed_revision(store, db, kind):
    config = store._get(db, "notification_settings", "settings") or {}
    if config.get("enabled") and any(channel.get("type") == "email" and channel.get("enabled")
                                     and kind in channel.get("event_types", ()) for channel in config.get("channels", ())):
        return config["revision"]
    return None


def queue(db, revision, identifier, kind, message, *, server=None, created_at=None, severity="info"):
    server = server or {}
    at = created_at or stamp()
    event = {"id": identifier, "kind": kind, "severity": severity, "message": message, "created_at": at,
             "server_id": server.get("id", ""), "hostname": server.get("hostname", ""), "configuration_revision": revision}
    db.execute("INSERT INTO notification_events(id,created_at,data) VALUES(?,?,?) ON CONFLICT(id) DO NOTHING",
               (identifier, at, json.dumps(event)))


def admin_change(store, db, entry):
    action, actor = entry["action"], entry["actor"]
    if action not in ADMIN_ACTIONS or not isinstance(actor, str):
        return
    if action == "firewall_change.confirmed" and entry["details"].get("status") != "queued":
        return
    if action == "managed_rollout.confirmed" and entry["details"].get("step") != 2:
        return
    provider, _, identity = actor.partition(":")
    if provider not in ("local", "entra", "saml", "legacy-token"):
        return
    revision = subscribed_revision(store, db, "admin_change")
    if revision is None:
        return
    user = store._get(db, "auth_users", identity) if provider != "legacy-token" else {"role": identity}
    if not user or user.get("role") not in ("admin", "super_admin"):
        return
    name = user.get("display_name") or actor
    server_id = entry["details"].get("server_id")
    server = store._get(db, "servers", server_id) if isinstance(server_id, str) else None
    queue(db, revision, "admin:" + entry["id"], "admin_change",
          f"{name} made an administrative change ({action}). Audit reference {entry['id']}.",
          server=server, created_at=entry["created_at"])


def allow_entries(services):
    return {(service["protocol"], service["port"], source) for service in services
            if service.get("mode", "enforce") == "enforce" for source in service.get("sources", ())}


def port_allowed(db, revision, server, origin, generation, ports):
    ports = sorted({(str(port), protocol) for protocol, port in ports})
    if not ports:
        return
    labels = ", ".join(f"{port}/{protocol}" for port, protocol in ports[:30])
    if len(ports) > 30:
        labels += f", and {len(ports) - 30} more"
    identifier = "allow:" + digest([server["id"], origin, generation])
    queue(db, revision, identifier, "port_allowed",
          f"The agent confirmed new or changed inbound allow entries for {labels} ({origin}).", server=server)
