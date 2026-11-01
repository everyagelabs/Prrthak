"""A shared, recipient-sealed barrier protocol for live replication credentials.

Only fixed node-manager operations mutate PostgreSQL/Patroni. The shared store
contains public progress and sealed envelopes, never a password or a Vault ref.
After durable SQL-role intent this protocol can only roll forward.
"""
from __future__ import annotations

import copy
import secrets
from datetime import timedelta

from .firewall import WorkflowConflict
from .platform import _private_json
from .store import digest, now, parse_time, stamp

PREFIX = "appliance_replication_rotation:"
PHASES = ("prepare", "change-role", "reload", "verify", "finalize")
TERMINAL = frozenset(("completed", "aborted"))
ACKS = {"prepare": "prepared", "change-role": "role_change_ack", "reload": "reload_ack", "verify": "verified", "finalize": "verified", "abort": "aborted"}
RESULT_PHASES = {"prepare": "prepared", "change-role": "role_changed", "reload": "reloaded", "verify": "verified", "finalize": "finalized", "abort": "aborted"}
_OWNER = secrets.token_hex(16)


def _record(api, config, db):
    identifier = config.get("replication_rotation_id")
    return api.app.store._get(db, "maintenance_settings", PREFIX + identifier) if identifier else None


def _get(api, db=None):
    if db is not None:
        return _record(api, api._config(db), db)
    with api.app.store.read_meta() as connection:
        return _get(api, connection)


def _public(record):
    if not record:
        return None
    return {key: copy.deepcopy(record.get(key)) for key in (
        "rotation_id", "phase", "created_at", "created_by", "updated_at", "completed_at", "voters", "primary_id",
        "role_change_intent", "acks", "errors", "membership_digest"
    )} | {"pending": record["phase"] not in TERMINAL, "can_abort": not record.get("role_change_intent") and record["phase"] not in TERMINAL}


def status(api, config=None, db=None):
    if not api.app:
        return None
    if db is not None:
        return _public(_record(api, config or api._config(db), db))
    return _public(_get(api))


def in_progress(api, db=None):
    record = _get(api, db)
    return bool(record and record["phase"] not in TERMINAL)


def _membership(config):
    voters = {v["id"] for v in config.get("voters", [])}
    return [{key: value[key] for key in ("id", "ip", "site", "transport_public_key")} for value in sorted(config.get("members", []), key=lambda m: m["id"]) if value["id"] in voters]


def _health(state, voters, *, all_healthy=True):
    health = state.get("health", {})
    checked = health.get("checked_at")
    if isinstance(checked, bool) or not isinstance(checked, (int, float)) or not -5 <= now().timestamp() - checked <= 45:
        return None
    if health.get("status") != "observed" or health.get("quorum_healthy") is not True or health.get("primary_count") != 1 or health.get("database_ready") is not True:
        return None
    nodes = health.get("nodes", [])
    if not isinstance(nodes, list) or len(nodes) != 3 or {node.get("id") for node in nodes} != {v["id"] for v in voters}:
        return None
    if any(node.get("ip") != voter["ip"] for voter in voters for node in nodes if node.get("id") == voter["id"]):
        return None
    if all_healthy and (health.get("all_voters_healthy") is not True or any(node.get("etcd_healthy") is not True or node.get("postgres_running") is not True for node in nodes)):
        return None
    primary = [node["id"] for node in nodes if node.get("role") in ("primary", "leader", "master")]
    return primary[0] if len(primary) == 1 else None


def _register_identity(api, config):
    from .cluster_bootstrap import _keys, _public_key
    identity = api._identity()
    member = next((member for member in config.get("members", []) if member["id"] == identity["id"]), None)
    if not member or any(member[key] != identity[key] for key in ("id", "ip", "site")):
        raise ValueError("This controller is not the registered cluster member")
    public = _public_key(_keys(api))
    if member.get("transport_public_key") and member["transport_public_key"] != public:
        raise ValueError("The registered controller key differs from its private installed identity")
    member["transport_public_key"] = public


def _password(api, record):
    from .cluster_bootstrap import _keys
    identity = api._identity()
    envelope = record.get("recipients", {}).get(identity["id"])
    if not envelope:
        raise ValueError("This controller has no sealed credential for the rotation")
    value = api.manager._unseal(envelope, _keys(api), identity["id"])
    if value.get("rotation_id") != record["rotation_id"] or value.get("deployment_id") != record["deployment_id"]:
        raise ValueError("The sealed rotation credential has a different deployment binding")
    password = value.get("password")
    if not isinstance(password, str) or not 32 <= len(password) <= 256:
        raise ValueError("The sealed replication credential is invalid")
    return password


def queue(api, db, config, password, actor):
    """Called inside Appliance.save's shared transaction; mutates config pointer."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from .cluster_bootstrap import _material, _seal
    if not api._installed() or not api.app.store.ha:
        raise ValueError("Live replication rotation requires an active managed appliance")
    if not isinstance(password, str) or not 32 <= len(password) <= 128 or any(ord(c) < 32 or ord(c) > 126 for c in password):
        raise ValueError("Live replication passwords must contain 32 to 128 printable ASCII characters")
    _register_identity(api, config)
    previous = _record(api, config, db)
    if previous and previous["phase"] not in TERMINAL:
        if _password(api, previous) == password:
            return _public(previous)
        raise WorkflowConflict("A replication-password rotation is already pending; finish or safely abort it first", {})
    if previous and previous["phase"] == "completed":
        active_password = _password(api, previous)
    else:
        active_password = _material(api)["secrets"]["replication"]
    if password == active_password:
        raise ValueError("This replication password is already active; leave the password field blank to preserve it")
    try:
        voters = _membership(config)
    except KeyError:
        raise ValueError("Every database voter must register its persistent controller transport key before rotation") from None
    if len(voters) != 3 or len({v["site"].casefold() for v in voters}) != 3:
        raise ValueError("Replication rotation requires three registered voters in distinct sites")
    primary = _health(api.client.status(), voters)
    if not primary:
        raise ValueError("All three database voters and quorum must be freshly observed healthy before preparing a replication password")
    identifier = secrets.token_hex(16)
    recipients = {}
    for member in config.get("members", []):
        try:
            public = serialization.load_pem_public_key(member.get("transport_public_key", "").encode())
            if not isinstance(public, rsa.RSAPublicKey) or public.key_size < 3072:
                raise ValueError()
        except (ValueError, TypeError):
            raise ValueError("Every registered controller must have its strong persistent transport key before rotation") from None
        recipients[member["id"]] = _seal({"rotation_id": identifier, "deployment_id": config["deployment_id"], "password": password}, public, member["id"])
    record = {"id": PREFIX + identifier, "rotation_id": identifier, "deployment_id": config["deployment_id"],
              "phase": "prepare", "voters": [{k: v[k] for k in ("id", "ip", "site")} for v in voters], "membership_digest": digest(voters),
              "recipients": recipients, "primary_id": primary, "role_change_intent": False,
              "acks": {}, "actions": {}, "errors": {}, "created_at": stamp(), "created_by": actor, "updated_at": stamp()}
    config["replication_rotation_id"] = identifier
    api.app.store._put(db, "maintenance_settings", record)
    api.app.store.audit("appliance.replication_rotation_requested", actor, {"rotation_id": identifier, "voter_ids": [v["id"] for v in voters]}, db)
    return _public(record)


def request_abort(api, actor):
    with api.app.store.lock, api.app.store.meta() as db:
        record = _get(api, db)
        if not record or record["phase"] in TERMINAL:
            return _public(record)
        if record.get("role_change_intent"):
            raise WorkflowConflict("SQL role-change intent is durable; this rotation must roll forward and cannot restore an old password", {})
        record.update(phase="abort", updated_at=stamp())
        api.app.store._put(db, "maintenance_settings", record)
        api.app.store.audit("appliance.replication_rotation_abort_requested", actor, {"rotation_id": record["rotation_id"]}, db)
        return _public(record)


def _all(record, phase):
    return all(record.get("acks", {}).get(phase, {}).get(v["id"]) for v in record["voters"])


def sync_completed_material(api, material=None, db=None):
    """Offline members catch up on their next pass before enrollment/configure."""
    from .cluster_bootstrap import _material, _save_material
    record = _get(api, db)
    if not record or record["phase"] != "completed":
        return material
    material = material if material is not None else _material(api)
    password = _password(api, record)
    if material["secrets"]["replication"] != password:
        material = copy.deepcopy(material)
        material["secrets"]["replication"] = password
        _save_material(api, material)
    local = api._local()
    if local.get("replication_rotation_applied") != record["rotation_id"] or local.get("pending_replication_ref"):
        local.update(replication_rotation_applied=record["rotation_id"])
        local.pop("pending_replication_ref", None)
        _private_json(api.manager.root / "appliance-local.json", local)
    return material


def _advance(record, state):
    phase = record["phase"]
    if phase == "prepare" and _all(record, phase):
        primary = _health(state, record["voters"])
        if primary:
            record.update(phase="change-role", primary_id=primary, role_change_intent=True)
    elif phase == "change-role":
        if record.get("acks", {}).get("change-role"):
            record["phase"] = "reload"
        else:
            primary = _health(state, record["voters"], all_healthy=False)
            if primary:
                record["primary_id"] = primary
    elif phase in ("reload", "verify", "finalize", "abort") and _all(record, phase):
        record["phase"] = {"reload": "verify", "verify": "finalize", "finalize": "completed", "abort": "aborted"}[phase]
        if record["phase"] in TERMINAL:
            record["completed_at"] = stamp()


def _action(api, record, state):
    node = api._identity()["id"]
    phase = record["phase"]
    if phase in TERMINAL or node not in {v["id"] for v in record["voters"]} or record.get("acks", {}).get(phase, {}).get(node):
        return None
    if phase == "prepare" and not _health(state, record["voters"]):
        record.setdefault("errors", {})[node] = "Waiting for a fresh healthy observation of all three voters and quorum before prepare"
        return None
    if phase == "change-role" and (_health(state, record["voters"] , all_healthy=False) != node or record.get("primary_id") != node):
        return None
    key = node + ":" + phase
    previous = record.setdefault("actions", {}).get(key, {})
    if previous.get("retry_at") and parse_time(previous["retry_at"]) > now():
        return None
    if previous.get("status") == "pending":
        if previous.get("owner") != _OWNER and parse_time(previous["lease_until"]) > now():
            return None
        current = previous
    else:
        attempt = previous.get("attempt", 0) + 1
        current = {"attempt": attempt, "request_id": digest({"rotation": record["rotation_id"], "node": node, "phase": phase, "attempt": attempt})[:32],
                   "expected_revision": state.get("revision"), "status": "pending"}
        record["actions"][key] = current
    current.update(owner=_OWNER, lease_until=stamp(now() + timedelta(seconds=45)))
    return {"node": node, "phase": phase, **copy.deepcopy(current)}


def reconcile(api):
    """One own-node action outside the shared transaction; safe to retry/restart."""
    if not api._installed() or not api.app.store.ha:
        return False
    sync_completed_material(api)
    if not in_progress(api):
        return False
    try:
        state = api.client.status()
    except Exception:
        return True
    with api.app.store.lock, api.app.store.meta() as db:
        config = api._config(db)
        record = _record(api, config, db)
        if not record or record["phase"] in TERMINAL:
            return False
        try:
            membership = digest(_membership(config))
        except KeyError:
            membership = ""
        if record["deployment_id"] != config.get("deployment_id") or membership != record["membership_digest"]:
            record.setdefault("errors", {})[api._identity()["id"]] = "Database voter membership or key binding changed; operator recovery is required"
            api.app.store._put(db, "maintenance_settings", record)
            return True
        _advance(record, state)
        action = _action(api, record, state)
        record["updated_at"] = stamp()
        api.app.store._put(db, "maintenance_settings", record)
    if not action:
        if record["phase"] == "completed":
            sync_completed_material(api)
        return record["phase"] not in TERMINAL
    request = {"action": "rotate-replication", "rotation_id": record["rotation_id"], "phase": action["phase"],
               "request_id": action["request_id"], "expected_revision": action["expected_revision"]}
    if action["phase"] == "prepare":
        request["password"] = _password(api, record)
    if action["phase"] == "finalize":
        request["all_voters_verified"] = _all(record, "verify")
    result = None
    try:
        try:
            result = api.client.job(action["request_id"])
        except KeyError:
            result = api.client.submit(request)
    except Exception:
        # An interrupted reply is ambiguous: look up the SAME durable operation
        # on the next pass rather than assuming no SQL mutation occurred.
        result = {"status": "unknown"}
    with api.app.store.lock, api.app.store.meta() as db:
        current = _get(api, db)
        key = action["node"] + ":" + action["phase"]
        entry = current.get("actions", {}).get(key, {}) if current else {}
        if not current or entry.get("request_id") != action["request_id"]:
            return True
        actual = result.get("result", {})
        complete = result.get("status") in ("succeeded", "completed", "applied")
        accepted = complete and isinstance(actual, dict) and actual.get("rotation_id") == current["rotation_id"] and actual.get("phase") == RESULT_PHASES[action["phase"]] and actual.get(ACKS[action["phase"]]) is True
        if action["phase"] == "verify":
            accepted = accepted and actual.get("new_connection") is True
        if action["phase"] == "abort":
            accepted = complete and isinstance(actual, dict) and actual.get("rotation_id") == current["rotation_id"] and actual.get("phase") == "aborted"
        if accepted:
            current.setdefault("acks", {}).setdefault(action["phase"], {})[action["node"]] = stamp()
            current.setdefault("errors", {}).pop(action["node"], None)
            entry["status"] = "acknowledged"
        elif result.get("status") not in ("queued", "running", "unknown"):
            entry.update(status="failed", retry_at=stamp(now() + timedelta(seconds=5)))
            current.setdefault("errors", {})[action["node"]] = "The node manager has not verified " + action["phase"] + "; this durable phase will retry without assuming success"
        current["updated_at"] = stamp()
        api.app.store._put(db, "maintenance_settings", current)
    return True
