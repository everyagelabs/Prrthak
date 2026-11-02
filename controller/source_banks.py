"""Exact, single-Admin source-bank maintenance delivered to the local agent.

Assessment is read-only. Activation is a distinct, acknowledged operation; it
does not authorize access policies or change endpoint enforcement opt-ins.
"""
import copy
from datetime import timedelta
import re
import secrets
import uuid

from . import approvals
from .firewall import WorkflowConflict
from .store import digest, now, parse_time, stamp

CAPABILITY = "source_bank_preparation_v1"
KIND = "source_bank_preparation"
JOB = "_source_bank_job"
RECEIPT = "source_bank_preparation"
PREFIX = "source_bank_review:"
CHALLENGE = "PREPARE SOURCE BANKS"
TERMINAL = {"assessed", "blocked", "prepared", "rolled_back", "error", "cancelled", "expired"}


def _transaction(db):
    if getattr(db, "dialect", "sqlite") != "postgresql":
        db.execute("BEGIN IMMEDIATE")


def _context(server):
    return {"ips": sorted(server.get("ips", [])), "configuration_digest": (server.get("configuration_state") or {}).get("digest", ""),
            "protection_digest": server.get("protection_digest", ""), "desired_version": server.get("desired_version", 0),
            "desired_digest": (server.get("_compiled") or {}).get("digest", "")}


def _fresh(value, seconds=180):
    if not isinstance(value, str) or not 1 <= len(value) <= 64:
        return False
    try:
        return now() - timedelta(seconds=seconds) <= parse_time(value) <= now() + timedelta(seconds=60)
    except (ValueError, TypeError, OverflowError):
        return False


def _selection(store, db, value):
    if not isinstance(value, dict) or set(value) - {"server_ids", "group_ids"}:
        raise ValueError("Select explicit servers or saved server groups")
    from .host_default_deny import _selection as select
    ids, _ = select(store, db, value)
    if len(ids) > 100:
        raise ValueError("Select at most 100 endpoints for one reviewed maintenance operation")
    return ids


def _identity(store, db, actor, principal):
    if approvals._lab(store) and not (principal or {}).get("auth_type") == "session":
        return
    approvals.identity(store, db, actor, principal)


def _blockers(server, *, activation=False):
    result = []
    if CAPABILITY not in server.get("capabilities", []) or "signed_assignments_v1" not in server.get("capabilities", []):
        result.append("Upgrade to an agent supporting signed GUI source-bank preparation")
    if not _fresh(server.get("last_seen")):
        result.append("A fresh authenticated heartbeat within 180 seconds is required")
    if activation:
        protected = server.get("protection") or {}
        if not protected.get("ready") or not _fresh(server.get("protection_reported_at")):
            result.append("A fresh ready SSH/controller protection report is required")
        if not re.fullmatch(r"[a-f0-9]{64}", _context(server)["configuration_digest"]):
            result.append("A current authenticated endpoint configuration receipt is required")
    return result


def _public_job(job):
    return {key: copy.deepcopy(job[key]) for key in ("id", "server_id", "operation", "status", "plan_digest", "baseline_digest", "protection_digest", "created_at", "expires_at", "created_by", "updated_at", "error") if key in job}


def _new_job(server, operation, actor, baseline=""):
    job = {"id": str(uuid.uuid4()), "server_id": server["id"], "operation": operation, "status": "assigned",
           "baseline_digest": baseline, "protection_digest": server.get("protection_digest", ""), "context": _context(server),
           "created_at": stamp(), "expires_at": stamp(now() + timedelta(minutes=15)), "created_by": actor}
    job["plan_digest"] = digest(job)
    return job


def _busy(server):
    job = server.get(JOB) or {}
    if job.get("operation") != "prepare_activate" or job.get("status") in {"prepared", "rolled_back", "blocked"}:
        return False
    # Admission precedes every endpoint write. Once admitted, expiry/error is
    # uncertainty rather than proof of rollback; a new assessment cannot erase it.
    return bool(job.get("admitted_at")) or _fresh(job.get("created_at"), 900)


def assess(store, value, actor, principal):
    with store.lock, store.meta() as db:
        _transaction(db)
        _identity(store, db, actor, principal)
        ids = _selection(store, db, value)
        selected = []
        for identifier in ids:
            server = store._get(db, "servers", identifier)
            if not server:
                raise ValueError("A selected endpoint no longer exists")
            blockers = _blockers(server)
            if _busy(server):
                blockers.append("Wait for or cancel the current source-bank activation")
            if blockers:
                raise WorkflowConflict("Source-bank assessment is not ready", {"server_id": identifier, "blockers": blockers})
            selected.append(server)
        result = []
        for server in selected:
            job = _new_job(server, "assess", actor)
            server[JOB] = job
            store._put(db, "servers", server)
            store.audit("source_banks.assessment_requested", actor, {"server_id": server["id"], "job_id": job["id"]}, db)
            result.append(_public_job(job))
        return {"items": result, "count": len(result)}


def _assessed(server):
    receipt, job = server.get(RECEIPT) or {}, server.get(JOB) or {}
    blockers = _blockers(server, activation=True)
    if job.get("operation") != "assess" or receipt.get("id") != job.get("id") or receipt.get("plan_digest") != job.get("plan_digest"):
        blockers.append("Request and receive a new source-bank assessment first")
    if receipt.get("status") != "assessed" or not _fresh(receipt.get("checked_at")):
        blockers.append("A successful source-bank assessment within 180 seconds is required")
    if job.get("context") != _context(server) or receipt.get("protection_digest") != server.get("protection_digest"):
        blockers.append("Endpoint addresses, policy or protection changed; reassess")
    blockers += receipt.get("blockers") or []
    if not re.fullmatch(r"[a-f0-9]{64}", receipt.get("baseline_digest", "")):
        blockers.append("The endpoint did not report a complete maintenance baseline")
    if receipt.get("active_banks") == 256 and receipt.get("permanent_banks") == 256 and not receipt.get("activation_required"):
        blockers.append("Source banks are already active; no preparation is needed")
    return receipt, sorted(set(blockers))


def preview(store, value, actor, principal):
    with store.lock, store.meta() as db:
        _transaction(db)
        _identity(store, db, actor, principal)
        ids = _selection(store, db, value)
        targets, bindings, jobs, blockers = [], {}, {}, []
        for identifier in ids:
            server = store._get(db, "servers", identifier)
            if not server:
                raise ValueError("A selected endpoint no longer exists")
            receipt, issues = _assessed(server)
            target = {"server_id": identifier, "hostname": server["hostname"], "blockers": issues,
                      "baseline_digest": receipt.get("baseline_digest", ""), "protection_digest": receipt.get("protection_digest", ""), "assessed_at": receipt.get("checked_at", ""),
                      **{key: receipt.get(key) for key in ("missing_banks", "active_banks", "permanent_banks", "activation_required")}}
            targets.append(target)
            blockers += [server["hostname"] + ": " + message for message in issues]
            bindings[identifier] = {"context": _context(server), "assessment": receipt}
            if not issues:
                job = _new_job(server, "prepare_activate", actor, receipt["baseline_digest"])
                approvals.request(store, db, job, actor, principal, endpoint_ids=[identifier], scope_kind=KIND)
                jobs[identifier] = job
        plan = {"id": str(uuid.uuid4()), "kind": KIND, "created_by": actor, "created_at": stamp(),
                "expires_at": stamp(now() + timedelta(minutes=3)), "targets": targets, "bindings": bindings, "jobs": jobs,
                "can_apply": not blockers, "blockers": blockers, "challenge": CHALLENGE, "status": "preview"}
        plan["digest"] = digest(plan)
        plan["confirmation_nonce"] = secrets.token_urlsafe(32)
        store._put(db, "maintenance_settings", {"id": PREFIX + plan["id"], "plan": plan})
        return {key: copy.deepcopy(plan[key]) for key in ("id", "kind", "created_by", "created_at", "expires_at", "targets", "can_apply", "blockers", "challenge", "status", "digest", "confirmation_nonce")}


def confirm(store, identifier, value, actor, principal):
    if not isinstance(value, dict) or set(value) != {"digest", "confirmation_nonce", "confirmation_phrase", "acknowledge_downtime"} or value.get("acknowledge_downtime") is not True or value.get("confirmation_phrase") != CHALLENGE:
        raise ValueError("Type PREPARE SOURCE BANKS and manually acknowledge the maintenance/reload impact")
    with store.lock, store.meta() as db:
        _transaction(db)
        _identity(store, db, actor, principal)
        record = store._get(db, "maintenance_settings", PREFIX + identifier)
        plan = (record or {}).get("plan") or {}
        if not plan or plan.get("status") != "preview" or plan.get("created_by") != actor or not plan.get("can_apply") or parse_time(plan["expires_at"]) <= now() or value["digest"] != plan.get("digest") or value["confirmation_nonce"] != plan.get("confirmation_nonce"):
            raise WorkflowConflict("Source-bank review expired, changed or belongs to another Admin", {})
        result = []
        for server_id, binding in plan["bindings"].items():
            server = store._get(db, "servers", server_id)
            if not server:
                raise WorkflowConflict("A selected endpoint was removed", {})
            receipt, issues = _assessed(server)
            if issues or binding != {"context": _context(server), "assessment": receipt}:
                raise WorkflowConflict("Source-bank assessment changed; review again", {"server_id": server_id, "blockers": issues})
            job = copy.deepcopy(plan["jobs"][server_id])
            # The validity period starts at this explicit action, and the digest
            # and current-Admin proof bind that exact period.
            job["created_at"], job["expires_at"] = stamp(), stamp(now() + timedelta(minutes=15))
            job["plan_digest"] = digest({key: item for key, item in job.items() if key not in ("approval", "plan_digest")})
            approvals.request(store, db, job, actor, principal, endpoint_ids=[server_id], scope_kind=KIND)
            job["approval_proof"] = approvals.decide(store, db, job, actor, principal)
            server[JOB] = job
            store._put(db, "servers", server)
            store.audit("source_banks.activation_authorized", actor, {"server_id": server_id, "job_id": job["id"], "review_id": identifier, "baseline_digest": job["baseline_digest"]}, db)
            result.append(_public_job(job))
        plan["status"] = "confirmed"
        plan.pop("confirmation_nonce", None)
        store._put(db, "maintenance_settings", record)
        return {"id": identifier, "items": result, "count": len(result), "status": "assigned"}


def assignment(store, db, server):
    job = server.get(JOB) or {}
    if not job or job.get("status") in TERMINAL or parse_time(job["expires_at"]) <= now() or CAPABILITY not in server.get("capabilities", []) or job.get("context") != _context(server):
        return None
    if job["operation"] == "prepare_activate" and not approvals.authorized(store, db, job.get("approval_proof"), plan_id=job["id"], plan_digest=job["plan_digest"], server_id=server["id"]):
        return None
    return {key: copy.deepcopy(job[key]) for key in ("id", "operation", "plan_digest", "baseline_digest", "protection_digest", "expires_at", "approval_proof") if key in job}


def validate_receipt(value):
    required = {"schema_version", "id", "operation", "plan_digest", "status", "checked_at", "baseline_digest", "protection_digest", "missing_banks", "active_banks", "permanent_banks", "created_banks", "activation_required", "blockers"}
    if not isinstance(value, dict) or set(value) - required - {"error"} or not required <= value.keys():
        raise ValueError("Invalid source-bank receipt fields")
    result = copy.deepcopy(value)
    if type(value["schema_version"]) is not int or value["schema_version"] != 1 or not isinstance(value["id"], str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value["id"]) or value["operation"] not in ("assess", "prepare_activate"):
        raise ValueError("Invalid source-bank receipt identity")
    for key in ("plan_digest", "baseline_digest", "protection_digest"):
        if not isinstance(value[key], str) or not (key != "plan_digest" and value[key] == "") and not re.fullmatch(r"[a-f0-9]{64}", value[key]):
            raise ValueError("Invalid source-bank receipt binding")
    if not isinstance(value["status"], str) or value["status"] not in ({"assessed", "blocked", "error"} if value["operation"] == "assess" else {"blocked", "preparing", "prepared", "rolled_back", "error"}):
        raise ValueError("Invalid source-bank receipt status")
    for key in ("missing_banks", "active_banks", "permanent_banks", "created_banks"):
        if type(value[key]) is not int or not 0 <= value[key] <= 256:
            raise ValueError("Invalid source-bank receipt counts")
    if type(value["activation_required"]) is not bool or not isinstance(value["blockers"], list) or len(value["blockers"]) > 32 or any(not isinstance(message, str) or len(message.encode("utf-8")) > 1024 for message in value["blockers"]):
        raise ValueError("Invalid source-bank receipt diagnostics")
    if "error" in value and (not isinstance(value["error"], str) or len(value["error"].encode("utf-8")) > 1024):
        raise ValueError("Invalid source-bank receipt error")
    if not isinstance(value["checked_at"], str) or len(value["checked_at"]) > 64:
        raise ValueError("Invalid source-bank receipt time")
    parsed = parse_time(value["checked_at"])
    if parsed > now() + timedelta(seconds=60):
        raise ValueError("Source-bank receipt time is in the future")
    result["checked_at"] = stamp(parsed)
    if value["status"] == "prepared" and (value["active_banks"] != 256 or value["permanent_banks"] != 256 or value["missing_banks"] or value["activation_required"]):
        raise ValueError("Prepared receipt must confirm every active and permanent source bank")
    return result


def report(store, db, server, receipt):
    job = server.get(JOB) or {}
    if receipt["id"] != job.get("id") or receipt["plan_digest"] != job.get("plan_digest") or receipt["operation"] != job.get("operation"):
        return  # Delayed receipts from a superseded assessment cannot rearm it.
    if job["operation"] == "prepare_activate" and any(receipt[key] != job.get(key) for key in ("baseline_digest", "protection_digest")):
        raise ValueError("Source-bank activation receipt differs from its exact reviewed baseline or protection")
    if job.get("status") in TERMINAL and receipt["status"] not in TERMINAL:
        return  # A delayed progress report cannot revive terminal authority.
    if job.get("status") in TERMINAL and receipt["status"] != job["status"] and not (job["status"] == "error" and receipt["status"] == "rolled_back"):
        return  # A completed result cannot be replaced by a contradictory replay.
    previous = server.get(RECEIPT) or {}
    if previous.get("id") == receipt["id"] and previous.get("checked_at", "") > receipt["checked_at"]:
        return
    server[RECEIPT] = receipt
    if job.get("status") not in {"cancelled", "expired"}:
        job.update(status=receipt["status"], updated_at=receipt["checked_at"], error=receipt.get("error", ""))
    if receipt["status"] in {"error", "rolled_back"}:
        store._event(db, "source-banks:" + receipt["id"], "source_bank_preparation_error", "high", server["id"], "Source-bank maintenance " + receipt["status"] + ": " + server["hostname"], {"job_id": receipt["id"], "error": receipt.get("error", "")})
    elif receipt["status"] == "prepared":
        store.audit("source_banks.prepared", "agent:" + server["id"], {"server_id": server["id"], "job_id": receipt["id"], "created_banks": receipt["created_banks"]}, db) if previous.get("status") != "prepared" or previous.get("id") != receipt["id"] else None


def verify(store, server_id, value):
    if not isinstance(value, dict) or set(value) != {"id", "plan_digest", "baseline_digest", "protection_digest", "nonce", "ssh_ports"}:
        raise ValueError("Provide the exact source-bank maintenance identity and fresh nonce")
    with store.lock, store.meta() as db:
        _transaction(db)
        server = store._get(db, "servers", server_id)
        active = assignment(store, db, server) if server else None
        if not active or active["operation"] != "prepare_activate" or any(value.get(key) != active.get(key) for key in ("id", "plan_digest", "baseline_digest", "protection_digest")):
            raise PermissionError("Source-bank maintenance authority expired, was revoked or changed")
        protected = server.get("protection") or {}
        if _blockers(server, activation=True):
            raise PermissionError("Fresh protected management context is required")
        if not server[JOB].get("admitted_at"):
            server[JOB]["admitted_at"] = stamp()
            store._put(db, "servers", server)
        return {"server_id": server_id, **{key: active[key] for key in ("id", "plan_digest", "baseline_digest", "protection_digest")},
                "ips": sorted(server["ips"]), "ssh_ports": protected["ssh_ports"], "management_sources": protected["management_sources"]}


def listing(store, value=None):
    value = value or {}
    if not isinstance(value, dict) or set(value) - {"server_ids", "limit", "offset"}:
        raise ValueError("Use bounded source-bank navigation fields")
    ids, limit, offset = value.get("server_ids"), value.get("limit", 50), value.get("offset", 0)
    if type(limit) is not int or not 1 <= limit <= 100 or type(offset) is not int or not 0 <= offset <= 10000000 or ids is not None and (not isinstance(ids, list) or len(ids) > 10000 or any(not isinstance(item, str) or not 1 <= len(item) <= 128 for item in ids)):
        raise ValueError("Invalid source-bank page or endpoint selection")
    from .approval_views import _expression
    import json
    with store.read_meta() as db:
        source = "SELECT jsonb_array_elements_text(?::jsonb)" if getattr(db, "dialect", "sqlite") == "postgresql" else "SELECT value FROM json_each(?)"
        where, args = ("id IN (" + source + ")", (json.dumps(sorted(set(ids))),)) if ids is not None else ("1=1", ())
        total = db.execute("SELECT COUNT(*) FROM servers WHERE " + where, args).fetchone()[0]
        fields = ("hostname", "capabilities", JOB, RECEIPT)
        sql = "SELECT id," + ",".join(_expression(db, (key,)) for key in fields) + " FROM servers WHERE " + where + " ORDER BY id LIMIT ? OFFSET ?"
        result = []
        for row in db.execute(sql, args + (limit, offset)):
            job, receipt, caps = json.loads(row[3] or "{}"), json.loads(row[4] or "null"), json.loads(row[2] or "[]")
            result.append({"server_id": row[0], "hostname": row[1], "capable": CAPABILITY in caps, "job": _public_job(job), "receipt": receipt})
    return {"items": result, "total": total, "limit": limit, "offset": offset, "has_more": offset + len(result) < total}
