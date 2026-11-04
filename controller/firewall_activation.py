"""Explicit reviewed endpoint service/config maintenance, separate from policy.

Installation never calls this workflow. Every mutation needs a fresh native
assessment, exact single-Admin acknowledgement and independent agent rollback.
"""
import copy
from datetime import timedelta
import json
import re
import secrets
import uuid

from . import approvals
from .firewall import WorkflowConflict
from .management_health import ManagementHealthUnavailable
from .network_addresses import address, network
from .source_banks import _identity, _fresh, _transaction
from .store import digest, now, parse_time, stamp

CAPABILITY = "firewall_activation_v1"
AGENT_ONLY_CAPABILITY = "firewall_activation_agent_only_v1"
AGENT_ONLY_MODE = "agent_controller_mtls"
AGENT_ONLY_OPERATIONS = {"activate_existing", "deactivate_existing", "activate_allow_all"}
MANAGED_POLICY_CONFLICT_OPERATIONS = {"deactivate_existing", "activate_allow_all"}
KIND = "firewall_activation"
JOB = "_firewall_activation_job"
RECEIPT = "firewall_activation"
PREFIX = "firewall_activation_review:"
CHALLENGE = "APPLY FIREWALL MAINTENANCE"
OPERATIONS = AGENT_ONLY_OPERATIONS | {"migrate_ufw", "prepare_egress", "enable_native_counters"}
TERMINAL = {"assessed", "blocked", "completed", "rolled_back", "error", "expired", "cancelled"}
ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
HEX = re.compile(r"[a-f0-9]{64}\Z")


def _context(server):
    return {"ips": sorted(server.get("ips", [])), "configuration_digest": (server.get("configuration_state") or {}).get("digest", ""), "protection_digest": server.get("protection_digest", ""), "desired_version": server.get("desired_version", 0), "desired_digest": (server.get("_compiled") or {}).get("digest", "")}


def _selection(store, db, value):
    from .host_default_deny import _selection as select
    if not isinstance(value, dict) or set(value) - {"server_ids", "group_ids", "operation"} or not isinstance(value.get("operation"), str) or value["operation"] not in OPERATIONS:
        raise ValueError("Select explicit endpoints/groups and one supported firewall maintenance operation")
    identifiers, _ = select(store, db, {key: value.get(key, []) for key in ("server_ids", "group_ids")})
    if len(identifiers) > 20:
        raise ValueError("Select at most 20 endpoints in one reviewed firewall maintenance operation")
    return identifiers


def _blockers(server, *, operation=None):
    issues = []
    if CAPABILITY not in server.get("capabilities", []) or "signed_assignments_v1" not in server.get("capabilities", []):
        issues.append("An upgraded agent with signed firewall_activation_v1 support is required")
    if operation in AGENT_ONLY_OPERATIONS and AGENT_ONLY_CAPABILITY not in server.get("capabilities", []):
        issues.append("Upgrade this endpoint's agent to change firewalld service state without SSH")
    if not _fresh(server.get("last_seen")):
        issues.append("A fresh authenticated endpoint heartbeat is required")
    if not HEX.fullmatch(_context(server)["configuration_digest"]):
        issues.append("A current authenticated endpoint configuration receipt is required")
    if not server.get("ips"):
        issues.append("Agent-reported interface addresses are required")
    return issues


def _managed_policy_conflict(store, db, server, operation):
    if operation not in MANAGED_POLICY_CONFLICT_OPERATIONS:
        return ""
    from .host_default_deny import guarded
    from .network_control import assignment as network_assignment

    if (server.get("_compiled", {}).get("mode") == "enforce"
            or server.get("_managed_rules_active") or guarded(server)):
        return "Remove active or pending managed enforcement and whole-host deny before this operation"
    if (server.get("configuration_state") or {}).get("enforce") is True:
        return "Turn off managed enforcement in the endpoint configuration before this operation"
    learning = store._get(db, "learning_allow_hosts", server["id"]) or {}
    if learning.get("applied_services") or learning.get("services"):
        return "Remove active or pending learned access rules before this operation"
    controls = server.get("network_control") or {}
    pending = network_assignment(store, db, server)
    for kind, key, active_status in (("egress", "egress_bundle", "enforced"), ("quarantine", "quarantine", "quarantined")):
        reported = controls.get(kind) or {}
        descriptor = pending.get(key) or {}
        if reported.get("active", reported.get("status") == active_status):
            return "Remove active outbound policy or emergency quarantine before this operation"
        if descriptor and descriptor["operation"] != "assess" and (
            reported.get("id") != descriptor["id"] or reported.get("status") not in
            {"enforced", "removed", "quarantined", "released", "expired", "rolled_back", "blocked", "error"}
        ):
            return "Wait for the pending outbound policy or emergency quarantine operation"
    return ""


def _busy(server):
    job = server.get(JOB) or {}
    return bool(job and job.get("operation") != "assess" and job.get("status") not in {"completed", "rolled_back", "blocked"} and (job.get("admitted_at") or _fresh(job.get("created_at"), 900)))


def _public(job):
    return {key: copy.deepcopy(job[key]) for key in ("id", "operation", "target_operation", "status", "server_id", "plan_digest", "baseline_digest", "protection_digest", "configuration_digest", "created_by", "created_at", "expires_at", "updated_at", "error") if key in job}


def _new_job(server, operation, target, actor, assessment=None):
    receipt = assessment or {}
    job = {"id": str(uuid.uuid4()), "server_id": server["id"], "operation": operation, "target_operation": target, "status": "assigned", "context": _context(server), "baseline_digest": receipt.get("baseline_digest", ""), "protection_digest": receipt.get("protection_digest", ""), "configuration_digest": _context(server)["configuration_digest"], "created_by": actor, "created_at": stamp(), "expires_at": stamp(now() + timedelta(minutes=15))}
    if target in AGENT_ONLY_OPERATIONS:
        job["health_mode"] = AGENT_ONLY_MODE
    if assessment:
        job["assessment"] = copy.deepcopy(receipt["assessment"])
    job["plan_digest"] = digest(job)
    return job


def assess(store, value, actor, principal):
    with store.lock, store.meta() as db:
        _transaction(db)
        _identity(store, db, actor, principal)
        identifiers = _selection(store, db, value)
        operation = value["operation"]
        agent_only = operation in AGENT_ONLY_OPERATIONS
        selected = []
        for identifier in identifiers:
            server = store._get(db, "servers", identifier)
            if not server:
                raise ValueError("A selected endpoint no longer exists")
            blockers = _blockers(server, operation=operation)
            conflict = _managed_policy_conflict(store, db, server, operation)
            if conflict:
                blockers.append(conflict)
            if _busy(server):
                blockers.append("Wait for the active maintenance outcome; uncertain work cannot be overwritten")
            if blockers:
                raise WorkflowConflict("Firewall assessment is unavailable", {"server_id": identifier, "blockers": blockers})
            selected.append(server)
        result = []
        for server in selected:
            previous = server.get(JOB) or {}
            if (previous.get("operation") == "assess" and previous.get("target_operation") == value["operation"]
                    and (not agent_only or previous.get("health_mode") == AGENT_ONLY_MODE)
                    and previous.get("status") == "assigned" and previous.get("context") == _context(server)
                    and parse_time(previous["expires_at"]) > now()):
                result.append(_public(previous))
                continue
            job = _new_job(server, "assess", value["operation"], actor)
            server[JOB] = job
            store._put(db, "servers", server)
            store.audit("firewall_activation.assessment_requested", actor, {"server_id": server["id"], "job_id": job["id"], "operation": value["operation"]}, db)
            result.append(_public(job))
        return {"items": result, "count": len(result), "read_only_host_assessment": True}


def _assessed(store, db, server, operation, management_health=None):
    job, receipt = server.get(JOB) or {}, server.get(RECEIPT) or {}
    agent_only = operation in AGENT_ONLY_OPERATIONS
    issues = _blockers(server, operation=operation)
    conflict = _managed_policy_conflict(store, db, server, operation)
    if conflict:
        issues.append(conflict)
    if (job.get("operation") != "assess" or job.get("target_operation") != operation
            or agent_only and job.get("health_mode") != AGENT_ONLY_MODE):
        return {}, issues + ["Request a fresh assessment for this operation"]
    context = _context(server)
    if job.get("context") != context:
        return {}, issues + ["Endpoint addresses, policy or configuration changed; request a fresh assessment"]
    if receipt.get("id") != job.get("id") or receipt.get("plan_digest") != job.get("plan_digest"):
        reason = ("Waiting for the agent to finish this assessment" if parse_time(job["expires_at"]) > now()
                  else "The assessment request expired; request a fresh assessment")
        return {}, issues + [reason]
    if receipt.get("configuration_digest") != context["configuration_digest"]:
        return receipt, issues + ["Endpoint configuration changed; request a fresh assessment"]
    if not _fresh(receipt.get("checked_at")):
        return receipt, issues + ["The native assessment expired; request a fresh assessment"]
    facts = receipt.get("assessment") or {}
    issues.extend(facts.get("blockers") or [])
    if receipt.get("status") != "assessed":
        if receipt.get("error") or not facts.get("blockers"):
            issues.append(receipt.get("error") or "The agent could not complete the native assessment")
        return receipt, sorted(set(issues))
    if facts.get("can_apply") is not True or not HEX.fullmatch(receipt.get("baseline_digest", "")) or not HEX.fullmatch(receipt.get("protection_digest", "")):
        issues.append("The native assessment does not prove this operation is supported and ready")
    if sorted({str(address(ip)) for ip in facts.get("ips", [])}) != context["ips"]:
        issues.append("Native assessed interface addresses differ from the current authenticated report")
    if not agent_only:
        if not facts.get("ssh_ports") or not facts.get("management_sources"):
            issues.append("Actual SSH listeners and restricted management sources are required")
        if not issues and management_health is not None:
            try:
                management_health.check_configuration(facts)
            except ManagementHealthUnavailable as error:
                issues.append(str(error))
    return receipt, sorted(set(issues))


def preview(store, value, actor, principal, *, management_health=None):
    with store.lock, store.meta() as db:
        _transaction(db)
        _identity(store, db, actor, principal)
        identifiers = _selection(store, db, value)
        bindings, jobs, targets, blockers = {}, {}, [], []
        for identifier in identifiers:
            server = store._get(db, "servers", identifier)
            if not server:
                raise ValueError("A selected endpoint no longer exists")
            receipt, issues = _assessed(store, db, server, value["operation"], management_health)
            targets.append({"server_id": identifier, "hostname": server["hostname"], "assessment": copy.deepcopy(receipt.get("assessment")), "baseline_digest": receipt.get("baseline_digest", ""), "blockers": issues})
            blockers.extend(server["hostname"] + ": " + issue for issue in issues)
            bindings[identifier] = {"context": _context(server), "receipt": receipt}
            if not issues:
                jobs[identifier] = _new_job(server, value["operation"], value["operation"], actor, receipt)
        plan = {"id": str(uuid.uuid4()), "kind": KIND, "operation": value["operation"], "created_by": actor, "created_at": stamp(), "expires_at": stamp(now() + timedelta(minutes=3)), "targets": targets, "bindings": bindings, "jobs": jobs, "can_apply": not blockers, "blockers": blockers, "challenge": CHALLENGE, "status": "preview"}
        plan["digest"] = digest(plan)
        plan["confirmation_nonce"] = secrets.token_urlsafe(32)
        store._put(db, "maintenance_settings", {"id": PREFIX + plan["id"], "plan": plan})
        return {key: copy.deepcopy(plan[key]) for key in ("id", "operation", "created_by", "created_at", "expires_at", "targets", "can_apply", "blockers", "challenge", "status", "digest", "confirmation_nonce")}


def confirm(store, identifier, value, actor, principal, *, management_health=None):
    if not isinstance(value, dict) or set(value) != {"digest", "confirmation_nonce", "confirmation_phrase", "acknowledge_downtime"} or value["acknowledge_downtime"] is not True or value["confirmation_phrase"] != CHALLENGE:
        raise ValueError("Type APPLY FIREWALL MAINTENANCE and manually acknowledge potential service downtime")
    with store.lock, store.meta() as db:
        _transaction(db)
        _identity(store, db, actor, principal)
        record = store._get(db, "maintenance_settings", PREFIX + identifier)
        plan = (record or {}).get("plan") or {}
        if not plan or plan.get("status") != "preview" or not plan.get("can_apply") or plan.get("created_by") != actor or parse_time(plan["expires_at"]) <= now() or value["digest"] != plan.get("digest") or value["confirmation_nonce"] != plan.get("confirmation_nonce"):
            raise WorkflowConflict("Firewall maintenance review expired, changed or belongs to another Admin", {})
        result = []
        for server_id, binding in plan["bindings"].items():
            server = store._get(db, "servers", server_id)
            if not server:
                raise WorkflowConflict("A reviewed endpoint was removed", {})
            receipt, issues = _assessed(store, db, server, plan["operation"], management_health)
            if issues or binding != {"context": _context(server), "receipt": receipt}:
                raise WorkflowConflict("Native assessment changed; review again", {"server_id": server_id, "blockers": issues})
            job = _new_job(server, plan["operation"], plan["operation"], actor, receipt)
            approvals.request(store, db, job, actor, principal, endpoint_ids=[server_id], scope_kind=KIND)
            job["approval_proof"] = approvals.decide(store, db, job, actor, principal)
            server[JOB] = job
            store._put(db, "servers", server)
            store.audit("firewall_activation.authorized", actor, {"server_id": server_id, "job_id": job["id"], "operation": job["operation"], "baseline_digest": job["baseline_digest"]}, db)
            result.append(_public(job))
        plan["status"] = "confirmed"
        plan.pop("confirmation_nonce", None)
        store._put(db, "maintenance_settings", record)
        return {"id": identifier, "status": "assigned", "items": result, "count": len(result)}


def assignment(store, db, server):
    job = server.get(JOB) or {}
    if not job or job.get("status") in TERMINAL or parse_time(job["expires_at"]) <= now() or job.get("context") != _context(server) or CAPABILITY not in server.get("capabilities", []):
        return None
    if job.get("health_mode") == AGENT_ONLY_MODE and AGENT_ONLY_CAPABILITY not in server.get("capabilities", []):
        return None
    if _managed_policy_conflict(store, db, server, job.get("target_operation")):
        return None
    if job["operation"] != "assess" and not approvals.authorized(store, db, job.get("approval_proof"), plan_id=job["id"], plan_digest=job["plan_digest"], server_id=server["id"]):
        return None
    return {key: copy.deepcopy(job[key]) for key in ("id", "operation", "target_operation", "plan_digest", "baseline_digest", "protection_digest", "configuration_digest", "expires_at", "approval_proof") if key in job}


def validate_receipt(value):
    keys = {"schema_version", "id", "operation", "target_operation", "plan_digest", "baseline_digest", "protection_digest", "configuration_digest", "status", "checked_at"}
    if not isinstance(value, dict) or set(value) - keys - {"assessment", "error"} or not keys <= value.keys() or len(json.dumps(value).encode()) > 131072:
        raise ValueError("Invalid bounded firewall maintenance receipt")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1 or not isinstance(value["id"], str) or not ID.fullmatch(value["id"]) or not isinstance(value["operation"], str) or not isinstance(value["target_operation"], str) or value["operation"] not in OPERATIONS | {"assess"} or value["target_operation"] not in OPERATIONS or value["operation"] != "assess" and value["operation"] != value["target_operation"]:
        raise ValueError("Invalid firewall maintenance operation or identity")
    for field in ("plan_digest", "baseline_digest", "protection_digest", "configuration_digest"):
        item = value[field]
        if not isinstance(item, str) or not HEX.fullmatch(item) and not (field in ("baseline_digest", "protection_digest") and item == ""):
            raise ValueError("Invalid firewall maintenance binding")
    if value["status"] not in ("assessed", "blocked", "applying", "completed", "rolled_back", "error") or value["operation"] == "assess" and value["status"] not in ("assessed", "blocked", "error"):
        raise ValueError("Invalid firewall maintenance outcome")
    if not isinstance(value.get("error", ""), str) or len(value.get("error", "").encode()) > 1024 or parse_time(value["checked_at"]) > now() + timedelta(seconds=60):
        raise ValueError("Invalid firewall maintenance receipt diagnostics or time")
    result = copy.deepcopy(value)
    result["checked_at"] = stamp(parse_time(value["checked_at"]))
    facts = value.get("assessment")
    if facts is not None:
        fields = {"firewalld_active", "firewalld_enabled", "ufw_active", "ufw_enabled", "version", "backend", "zone", "ips", "ssh_ports", "management_sources", "discovered_ports", "translated_rules", "can_apply", "blockers", "notes"}
        if not isinstance(facts, dict) or set(facts) != fields or any(type(facts[key]) is not bool for key in ("firewalld_active", "ufw_active", "can_apply")):
            raise ValueError("Invalid firewall maintenance assessment fields")
        for field in ("firewalld_enabled", "ufw_enabled", "version", "backend", "zone"):
            if not isinstance(facts[field], str) or len(facts[field]) > 128:
                raise ValueError("Invalid bounded firewall assessment metadata")
        for field, bound in (("blockers", 32), ("notes", 32)):
            if not isinstance(facts[field], list) or len(facts[field]) > bound or any(not isinstance(text, str) or len(text.encode()) > 1024 for text in facts[field]):
                raise ValueError("Invalid firewall maintenance assessment diagnostics")
        for field, limit in (("ips", 64), ("management_sources", 100), ("ssh_ports", 8), ("discovered_ports", 100), ("translated_rules", 128)):
            if not isinstance(facts[field], list) or len(facts[field]) > limit:
                raise ValueError("Firewall maintenance assessment exceeds its exact scope bound")
        for ip in facts["ips"]:
            address(ip)
        for cidr in facts["management_sources"]:
            if network(cidr).prefixlen == 0:
                raise ValueError("Firewall maintenance requires restricted management sources")
        if any(type(port) is not int or not 1 <= port <= 65535 for port in facts["ssh_ports"]):
            raise ValueError("Invalid discovered SSH port")
        from .store import validate_port
        for port in facts["discovered_ports"]:
            if not isinstance(port, dict) or set(port) != {"port", "protocol"}:
                raise ValueError("Discovered maintenance ports must be exact TCP/UDP pairs")
            validate_port(port)
        for rule in facts["translated_rules"]:
            if not isinstance(rule, dict) or set(rule) != {"family", "source", "port", "protocol", "action", "priority"} or rule["family"] not in ("ipv4", "ipv6") or rule["action"] not in ("accept", "reject", "drop") or type(rule["priority"]) is not int or not -30000 <= rule["priority"] <= -25000:
                raise ValueError("Unsupported translated UFW rule")
            validate_port(rule)
            subnet = network(rule["source"])
            if subnet.version != (4 if rule["family"] == "ipv4" else 6):
                raise ValueError("Translated UFW source family differs")
        missing_ssh_scope = value["target_operation"] not in AGENT_ONLY_OPERATIONS and (
            not facts["ssh_ports"] or not facts["management_sources"])
        if facts["can_apply"] and (facts["blockers"] or missing_ssh_scope):
            raise ValueError("Ready maintenance assessment needs exact protected management context")
    if value["status"] == "assessed" and facts is None:
        raise ValueError("Assessed maintenance receipt requires its native facts")
    return result


def report(store, db, server, receipt):
    job = server.get(JOB) or {}
    if any(receipt.get(key) != job.get(key) for key in ("id", "plan_digest", "operation", "target_operation", "configuration_digest")):
        return
    if job["operation"] != "assess" and any(receipt.get(key) != job.get(key) for key in ("baseline_digest", "protection_digest")):
        raise ValueError("Maintenance outcome differs from the exact reviewed baseline")
    if job.get("status") in TERMINAL and receipt["status"] != job["status"] and not (job["status"] == "error" and receipt["status"] == "rolled_back"):
        return
    previous = server.get(RECEIPT) or {}
    if previous.get("id") == receipt["id"] and previous.get("checked_at", "") > receipt["checked_at"]:
        return
    server[RECEIPT] = receipt
    job.update(status=receipt["status"], updated_at=receipt["checked_at"], error=receipt.get("error", ""))
    if receipt["status"] in ("error", "rolled_back"):
        store._event(db, "firewall-activation:" + receipt["id"], "firewall_activation_error", "critical" if receipt["status"] == "error" else "warning", server["id"], "Firewall maintenance " + receipt["status"] + ": " + server["hostname"], {"job_id": receipt["id"], "operation": job["operation"], "error": receipt.get("error", "")})
    elif receipt["status"] == "completed" and previous.get("status") != "completed":
        store.audit("firewall_activation.completed", "agent:" + server["id"], {"server_id": server["id"], "job_id": job["id"], "operation": job["operation"]}, db)


def verify(store, server_id, value):
    keys = {"id", "plan_digest", "baseline_digest", "protection_digest", "configuration_digest", "nonce", "ssh_ports"}
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError("Provide the exact firewall maintenance identity and fresh nonce")
    with store.lock, store.meta() as db:
        _transaction(db)
        server = store._get(db, "servers", server_id)
        active = assignment(store, db, server) if server else None
        if not active or active["operation"] == "assess" or _blockers(server) or any(value.get(key) != active.get(key) for key in ("id", "plan_digest", "baseline_digest", "protection_digest", "configuration_digest")):
            raise PermissionError("Exact firewall maintenance authority expired or changed")
        job = server[JOB]
        facts = job["assessment"]
        if sorted({str(address(ip)) for ip in facts["ips"]}) != sorted(server["ips"]):
            raise PermissionError("Assessed interface addresses changed")
        agent_only = active["operation"] in AGENT_ONLY_OPERATIONS and job.get("health_mode") == AGENT_ONLY_MODE
        if agent_only and value["ssh_ports"] != []:
            raise ValueError("Agent-based firewalld service changes require an empty SSH probe list")
        if not job.get("admitted_at"):
            job["admitted_at"] = stamp()
            store._put(db, "servers", server)
        return {"server_id": server_id, **{key: active[key] for key in ("id", "plan_digest", "baseline_digest", "protection_digest", "configuration_digest")}, "ips": facts["ips"], "ssh_ports": facts["ssh_ports"], "management_sources": facts["management_sources"], **({"health_mode": AGENT_ONLY_MODE} if agent_only else {})}


def listing(store, value=None):
    value = value or {}
    if not isinstance(value, dict) or set(value) - {"server_ids", "limit", "offset", "details"}:
        raise ValueError("Use supported bounded firewall maintenance navigation fields")
    ids, limit, offset = value.get("server_ids"), value.get("limit", 50), value.get("offset", 0)
    details = value.get("details", False)
    if type(details) is not bool or type(limit) is not int or not 1 <= limit <= 100 or type(offset) is not int or not 0 <= offset <= 10000000 or ids is not None and (not isinstance(ids, list) or len(ids) > 10000 or any(not isinstance(item, str) or not ID.fullmatch(item) for item in ids)):
        raise ValueError("Invalid firewall maintenance page or endpoint scope")
    if details and (ids is None or len(set(ids)) != 1 or limit != 1 or offset != 0):
        raise ValueError("Detailed assessment requires exactly one explicit endpoint, limit 1 and offset 0")
    from .approval_views import _expression
    from .traffic_views import _ids
    job_fields = ("id", "operation", "target_operation", "status", "server_id", "plan_digest", "baseline_digest", "protection_digest", "configuration_digest", "created_by", "created_at", "expires_at", "updated_at", "error")
    receipt_fields = ("id", "operation", "target_operation", "status", "checked_at", "error", "baseline_digest")
    with store.read_meta() as db:
        where, args = _ids(db, "id", sorted(set(ids))) if ids is not None else ("1=1", [])
        total = int(db.execute("SELECT COUNT(*) FROM servers WHERE " + where, args).fetchone()[0])
        paths = [(key,) for key in ("hostname", "ips", "firewalld_state", "ufw_active")]
        # Do not transfer private proofs or large native assessments into hot
        # paged history responses. Full receipt is a single-endpoint opt-in.
        paths += [(JOB, key) for key in job_fields]
        paths += [(RECEIPT,)] if details else [(RECEIPT, key) for key in receipt_fields]
        projection = ["id"] + [_expression(db, path) for path in paths]
        items = []
        for row in db.execute("SELECT " + ",".join(projection) + " FROM servers WHERE " + where + " ORDER BY id LIMIT ? OFFSET ?", (*args, limit, offset)):
            item = {"server_id": row[0], "hostname": row[1], "ips": json.loads(row[2] or "[]"), "firewalld_state": row[3] or "unknown", "ufw_active": str(row[4]).lower() in ("1", "true")}
            job = {key: row[5 + index] for index, key in enumerate(job_fields) if row[5 + index] is not None}
            position = 5 + len(job_fields)
            receipt = json.loads(row[position] or "null") if details else {key: row[position + index] for index, key in enumerate(receipt_fields) if row[position + index] is not None}
            item.update(job=job or None, receipt=receipt or None)
            items.append(item)
        return {"items": items, "total": total, "limit": limit, "offset": offset, "has_more": offset + len(items) < total, "details": details}


def invalidate_after_recovery(store, db):
    """Restored business rows cannot replay archived service-change authority.

    This deliberately leaves observed receipts/history and endpoint state alone.
    A cached in-flight agent must obtain a fresh health admission; removing its
    archived job revokes that check and its independent watchdog remains armed.
    """
    postgres = getattr(db, "dialect", "sqlite") == "postgresql"
    exists = "(data::jsonb->?) IS NOT NULL" if postgres else "json_type(data,?) IS NOT NULL"
    key = JOB if postgres else "$." + JOB
    count = int(db.execute("SELECT COUNT(*) FROM servers WHERE " + exists, (key,)).fetchone()[0])
    if postgres:
        db.execute("UPDATE servers SET data=(data::jsonb - ?)::text WHERE " + exists, (JOB, key))
    else:
        db.execute("UPDATE servers SET data=json_remove(data,?) WHERE " + exists, ("$." + JOB, key))
    reviews = int(db.execute("SELECT COUNT(*) FROM maintenance_settings WHERE substr(id,1,?)=?", (len(PREFIX), PREFIX)).fetchone()[0])
    db.execute("DELETE FROM maintenance_settings WHERE substr(id,1,?)=?", (len(PREFIX), PREFIX))
    return {"invalidated_jobs": count, "invalidated_reviews": reviews, "fresh_review_required": True}
