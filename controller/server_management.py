"""Reviewed inventory reservations and retirement; no remote firewall commands.

Reservations are deliberately separate from enrolled inventory. Planned addresses
must not participate in policy source resolution before an authenticated report.
"""
import copy
import ipaddress
import json
import re
import secrets
import uuid
from datetime import timedelta

from .firewall import WorkflowConflict
from .store import digest, now, parse_time, stamp


def initialize(db):
    for table in ("server_reservations", "retired_endpoints", "server_lifecycle_plans"):
        db.execute(f"CREATE TABLE IF NOT EXISTS {table} (id TEXT PRIMARY KEY, data TEXT NOT NULL)")


def reservation_listing(store):
    with store.read_meta() as db:
        rows = [{**row, "ips": [], "planned_ips": row.get("planned_ips", row.get("ips", [])), "address_status": "planned_unverified"}
                for row in store._all(db, "server_reservations")]
        return sorted(rows, key=lambda row: row["hostname"].casefold())


def create(store, value, actor):
    if not isinstance(value, dict) or set(value) - {"hostname", "ips"}:
        raise ValueError("A reservation accepts hostname and planned ips only; business metadata is assigned centrally after discovery or through CSV")
    hostname = value.get("hostname")
    if not isinstance(hostname, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,252}", hostname):
        raise ValueError("Provide the endpoint's exact hostname (up to 253 letters, numbers, dots, underscores or hyphens)")
    addresses = value.get("ips", [])
    if not isinstance(addresses, list) or len(addresses) > 100 or any(not isinstance(item, str) or "%" in item for item in addresses):
        raise ValueError("Planned ips must be a list of up to 100 numeric IPv4/IPv6 addresses")
    try:
        addresses = sorted({str(ipaddress.ip_address(item)) for item in addresses})
    except ValueError:
        raise ValueError("Planned ips must be numeric IPv4/IPv6 addresses, not subnets")
    with store.lock, store.meta() as db:
        if any(row.get("hostname", "").casefold() == hostname.casefold()
               for table in ("servers", "server_reservations") for row in store._all(db, table)):
            raise ValueError("This hostname is already enrolled or awaiting enrollment")
        value = {"id": str(uuid.uuid4()), "hostname": hostname, "ips": [], "planned_ips": addresses,
                 "lifecycle": "waiting_enrollment", "status": "waiting_enrollment",
                 "last_seen": None, "listeners": [], "tags": {}, "location_id": None,
                 "created_at": stamp(), "created_by": actor,
                 "address_status": "planned_unverified"}
        store._put(db, "server_reservations", value)
        store.audit("server.reserved", actor, {"server_id": value["id"], "hostname": hostname,
                    "planned_ips": addresses, "address_status": "planned_unverified"}, db)
        return value


def assert_report_allowed(store, db, identifier):
    if store._get(db, "retired_endpoints", identifier):
        raise PermissionError("Endpoint identity is retired; install with a newly authorized enrollment identity")
    if store._get(db, "server_reservations", identifier) and not store._get(db, "servers", identifier):
        raise PermissionError("A pending server must complete its bound certificate enrollment before reporting")


def validate_binding(store, db, token_record, hostname=None):
    if token_record.get("revoked"):
        raise PermissionError("Enrollment token was revoked")
    identifier = token_record.get("server_id")
    if identifier is None:
        return None
    if not isinstance(identifier, str) or not identifier or len(identifier) > 100:
        raise ValueError("Invalid reserved server identity")
    reservation = store._get(db, "server_reservations", identifier)
    if not reservation or store._get(db, "servers", identifier) or store._get(db, "retired_endpoints", identifier):
        raise PermissionError("Enrollment token is not bound to a current pending server")
    if hostname is not None and hostname != reservation["hostname"]:
        raise PermissionError("Agent hostname does not match the reserved server bound to this token")
    return reservation


def consume_reservation(store, db, identifier):
    if not store._get(db, "servers", identifier):
        raise ValueError("Create the authenticated endpoint before consuming its reservation")
    db.execute("DELETE FROM server_reservations WHERE id=?", (identifier,))


def _cleanup_verified(store, db, server, approvals):
    result = server.get("managed_enforcement", {})
    version = result.get("version", 0)
    if not (server.get("_managed_rules_active") is False and result.get("status") == "enforced"
            and result.get("intent") == "remove_managed_rules" and version > 0
            and server.get("_last_managed_applied_version") == version
            and server.get("applied_version") == version):
        return False
    row = db.execute("SELECT data FROM bundle_history WHERE server_id=? AND version=?", (server["id"], version)).fetchone()
    if not row:
        return False
    bundle = json.loads(row[0])
    if bundle.get("mode") == "enforce" or bundle.get("digest") != result.get("digest"):
        return False
    cleanup = [item for item in approvals if item.get("approval_id") == result.get("approval_id")
               and item.get("intent") == "remove_managed_rules" and item.get("approved_version") == version
               and item.get("approved_digest") == result.get("digest")]
    if not cleanup or any(item.get("intent", "enforce") != "remove_managed_rules"
                          and item.get("approved_version", 0) > version for item in approvals):
        return False
    from .managed_views import _current_evidence
    row = db.execute("SELECT data FROM managed_outcomes WHERE server_id=? AND " + _current_evidence(db) + " ORDER BY created_at DESC LIMIT 1", (server["id"],)).fetchone()
    if not row:
        return False
    outcome = json.loads(row[0])
    return (outcome.get("status") == "enforced" and outcome.get("intent") == "remove_managed_rules"
            and outcome.get("version") == version and outcome.get("digest") == result.get("digest")
            and outcome.get("approval_id") == result.get("approval_id"))


def _blockers(store, db, server, reserved=False):
    if reserved:
        return []
    result, problems = server.get("managed_enforcement", {}), []
    if server.get("recovery_reconciliation_required") is True and server.get("recovery_unverified_outcome"):
        problems.append("Recovery retained an unverified endpoint firewall baseline. Complete fresh approved read-back or verified cleanup before retirement.")
    approvals = [json.loads(row[0]) for row in db.execute("SELECT data FROM managed_approvals WHERE server_id=?", (server["id"],))]
    managed_history = (server.get("_managed_rules_active") is True
                       or bool(server.get("_last_managed_applied_version"))
                       or any(item.get("intent", "enforce") != "remove_managed_rules" for item in approvals))
    if managed_history and not _cleanup_verified(store, db, server, approvals):
        problems.append("Managed access may still be installed or authorized. Complete and verify a Remove Prṛthak-managed rules rollout before retiring this endpoint.")
    if result.get("status") in ("staging", "runtime_healthchecking", "committing", "error") or server.get("apply_status") == "applying":
        problems.append("A managed firewall transaction is active or uncertain; resolve it before retirement.")
    for change in store._all(db, "firewall_changes"):
        if (change.get("status") == "queued" and server["id"] in change.get("operations_by_server", {})
                and server["id"] not in change.get("results", {})):
            problems.append("An imported firewall change has no terminal endpoint result: " + change["id"])
    active_sessions = [session["id"] for session in store._all(db, "sessions")
                       if server["id"] in session.get("server_ids", []) and session.get("status") == "active"
                       and parse_time(session["expires_at"]) > now()]
    if active_sessions or server.get("collector_status") == "learning" or server.get("learning_stop_pending"):
        problems.append("Stop temporary learning and wait for the agent's cleanup acknowledgement before retirement.")
    from .learning_policies import retirement_blockers
    problems.extend(retirement_blockers(store, db, server))
    from .hit_monitoring import retirement_blockers as hit_retirement_blockers
    problems.extend(hit_retirement_blockers(store, db, server))
    monitor = server.get("security_monitor", {})
    if monitor.get("enabled") or monitor.get("status") in ("active", "starting", "degraded"):
        problems.append("Disable unexpected-port monitoring and confirm cleanup before retiring the endpoint.")
    return problems


def _snapshot(store, db):
    servers = []
    fields = ("id", "hostname", "ips", "tags", "location_id", "tag_sources", "location_source", "_metadata_overrides", "_compiled", "_managed_rules_active",
              "_last_managed_applied_version", "applied_version", "protection_digest", "collector_status",
              "learning_stop_pending")
    for value in store._all(db, "servers"):
        server = {key: value.get(key) for key in fields}
        server["managed_enforcement"] = {key: field for key, field in value.get("managed_enforcement", {}).items() if key != "updated_at"}
        server["security_monitor"] = {key: field for key, field in value.get("security_monitor", {}).items()
                                      if key not in ("started_at", "last_checked_at")}
        server["firewall_snapshot"] = {key: field for key, field in value.get("firewall_snapshot", {}).items()
                                       if key not in ("collected_at", "last_attempt_at")}
        servers.append(server)
    tables = {}
    for table in ("policies", "groups", "server_reservations", "firewall_changes", "managed_rollouts", "sessions", "learning_allow_policies", "learning_allow_hosts", "hit_monitors", "hit_monitor_targets"):
        rows = store._all(db, table)
        if table == "hit_monitor_targets":
            for row in rows:
                for key in ("checked_at", "received_at"):
                    row.get("last_outcome", {}).pop(key, None)
        if table in ("learning_allow_policies", "learning_allow_hosts"):
            for row in rows:
                # An identical acknowledged outcome is retransmitted with a new
                # report clock. It does not change the reviewed cleanup state.
                # Keep generation, digest, status, error and all authority times.
                if isinstance(row.get("last_outcome"), dict):
                    row["last_outcome"] = {key: value for key, value in row["last_outcome"].items() if key != "updated_at"}
        tables[table] = sorted(rows, key=lambda row: row["id"])
    return digest({"servers": sorted(servers, key=lambda row: row["id"]),
                   **tables,
                   "approvals": [list(row) for row in db.execute("SELECT id,active,data FROM managed_approvals ORDER BY id")]})


def _public(plan):
    return {key: value for key, value in plan.items() if not key.startswith("_")}


def delete_preview(store, identifier, actor):
    with store.lock, store.meta() as db:
        server = store._get(db, "servers", identifier)
        reserved = server is None
        server = server or store._get(db, "server_reservations", identifier)
        if not server:
            raise KeyError(identifier)
        blockers = _blockers(store, db, server, reserved)
        static_groups = [group["id"] for group in store._all(db, "groups")
                         if group.get("type") == "static" and identifier in group.get("server_ids", [])]
        rollouts = [plan["id"] for plan in store._all(db, "managed_rollouts")
                    if identifier in plan.get("server_ids", []) and plan.get("status") in ("draft", "awaiting_second_confirmation", "queued")]
        firewall_changes = [plan["id"] for plan in store._all(db, "firewall_changes")
                            if identifier in plan.get("server_ids", []) and plan.get("status") in ("draft", "awaiting_second_confirmation", "queued")]
        profiles = [profile["id"] for profile in store._all(db, "metadata_ip_profiles") if profile["id"] in server.get("ips", [])]
        plan = {"id": str(uuid.uuid4()), "server_id": identifier,
                "kind": "reservation_retirement" if reserved else "server_retirement",
                "before": store.public(server), "status": "blocked" if blockers else "draft",
                "can_delete": not blockers, "blockers": blockers, "created_at": stamp(), "created_by": actor,
                "expires_at": stamp(now() + timedelta(minutes=10)), "_snapshot_digest": _snapshot(store, db),
                "impact": {"static_group_ids": static_groups, "invalidated_rollout_ids": rollouts,
                           "invalidated_firewall_change_ids": firewall_changes, "retained_ip_profile_ids": profiles,
                           "history_retained": True, "agent_identity_rejected": True,
                           "recompile_source_membership": not reserved},
                "warnings": ["Retirement archives inventory and rejects this agent identity. It does not uninstall the local service or modify server firewall rules.",
                             "Remaining static/dynamic group membership and intended source policies are recalculated. Changed bundles need their own rollout approval."]}
        if profiles:
            plan["warnings"].append("Saved CSV IP profiles remain available for future discovery. Remove obsolete profiles separately through central assignment management.")
        if not blockers:
            plan["confirmation_nonce"] = secrets.token_urlsafe(24)
        store._put(db, "server_lifecycle_plans", plan)
        store.audit("server.retirement_preview", actor, {"plan_id": plan["id"], "server_id": identifier,
                    "can_delete": not blockers, "blockers": blockers}, db)
        return _public(plan)


def delete_confirm(store, identifier, body, actor):
    if not isinstance(body, dict):
        raise ValueError("Retirement confirmation must be an object")
    with store.lock, store.meta() as db:
        plan_id = body.get("plan_id")
        if not isinstance(plan_id, str) or not plan_id or len(plan_id) > 100:
            raise ValueError("Retirement confirmation requires the reviewed plan_id")
        plan = store._get(db, "server_lifecycle_plans", plan_id)
        if not plan:
            raise KeyError(plan_id)
        if plan["server_id"] != identifier:
            raise WorkflowConflict("Retirement plan does not match the selected endpoint", _public(plan))
        nonce = body.get("confirmation_nonce")
        if (plan.get("status") != "draft" or not plan.get("can_delete") or parse_time(plan["expires_at"]) <= now()
                or not isinstance(nonce, str) or not secrets.compare_digest(nonce, plan.get("confirmation_nonce", ""))):
            raise WorkflowConflict("Retirement review is blocked, expired, already applied or confirmation does not match", _public(plan))
        if _snapshot(store, db) != plan["_snapshot_digest"]:
            raise WorkflowConflict("Inventory, policy, group membership or firewall work changed; preview retirement again", _public(plan))
        server_id = plan["server_id"]
        reserved = plan["kind"] == "reservation_retirement"
        table = "server_reservations" if reserved else "servers"
        server = store._get(db, table, server_id)
        if not server:
            raise WorkflowConflict("The reviewed endpoint no longer exists", _public(plan))
        blockers = _blockers(store, db, server, reserved)
        if blockers:
            raise WorkflowConflict("Endpoint firewall or monitoring work is not safe to retire", {**_public(plan), "blockers": blockers})
        archive = {"id": server_id, "hostname": server["hostname"], "retired_at": stamp(), "retired_by": actor,
                   "plan_id": plan["id"], "kind": plan["kind"], "server": copy.deepcopy(server)}
        store._put(db, "retired_endpoints", archive)
        db.execute(f"DELETE FROM {table} WHERE id=?", (server_id,))
        for group in store._all(db, "groups"):
            if group.get("type") == "static" and server_id in group.get("server_ids", []):
                group["server_ids"] = [item for item in group["server_ids"] if item != server_id]
                group["updated_at"] = stamp()
                store._put(db, "groups", group)
        for table_name in ("managed_rollouts", "firewall_changes"):
            for work in store._all(db, table_name):
                if server_id in work.get("server_ids", []) and work.get("status") in ("draft", "awaiting_second_confirmation", "queued"):
                    work.update({"status": "invalidated", "confirmation_nonce": "",
                                 "error": "A reviewed endpoint was retired", "invalidated_at": stamp(), "retired_server_id": server_id})
                    store._put(db, table_name, work)
                    if table_name == "managed_rollouts":
                        db.execute("UPDATE managed_approvals SET active=0 WHERE approval_id=?", (work["id"],))
        db.execute("UPDATE managed_approvals SET active=0 WHERE server_id=?", (server_id,))
        for token in store._all(db, "tokens"):
            if token.get("server_id") == server_id and not token.get("used"):
                token.update({"revoked": True, "revoked_at": stamp()})
                store._put(db, "tokens", token)
        for alert in store._all(db, "alerts"):
            if alert.get("server_id") == server_id and alert.get("status") in ("open", "acknowledged"):
                alert.update({"status": "resolved", "updated_at": stamp(), "resolved_by": actor,
                              "resolution_reason": "Endpoint retired; monitoring is no longer active"})
                store._put(db, "alerts", alert)
        if not reserved:
            from .metadata import reconcile_all
            reconcile_all(store, db)
            store.compile_all(db)
        plan.update({"status": "applied", "retired_at": archive["retired_at"], "applied_by": actor})
        plan.pop("confirmation_nonce", None)
        store._put(db, "server_lifecycle_plans", plan)
        store.audit("server.retired", actor, {"server_id": server_id, "plan_id": plan["id"],
                    "before": store.public(server), "impact": plan["impact"]}, db)
        return _public(plan)
