"""Reviewed recovery into stopped SQLite files or fresh PostgreSQL namespaces.

The supervisor remains alive.  Normal Store access never bypasses a recovery
fence; the small, fixed-key control ledger has its own bounded SQL path.
Database archives do not supply, replace, or generate the current PKI/Vault.
"""
from __future__ import annotations

import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sqlite3
import threading
import time
import uuid
from contextlib import closing, contextmanager
from datetime import timedelta

from . import __version__
from . import approvals, maintenance
from .firewall import WorkflowConflict
from .platform import _private_json, _read_json
from .platform_runtime import (FENCE_NAME, META_TABLES, TRAFFIC_TABLES, _columns,
                               _hash_rows, _snapshot_source, _source_rows,
                               _statistics, atomic_private_json)
from .store import Store, digest, now, parse_time, stamp

SCHEME = "prthak-reviewed-recovery-v1"
CONTROL_ID = "recovery_control:active"
PLAN_PREFIX = "recovery:"
LOCAL_FENCE = "recovery-writer-fence.json"
CONTROL_LOCK = 0x50525448414B0211
ID = re.compile(r"[a-f0-9]{32}")
SHA = re.compile(r"[a-f0-9]{64}")
TERMINAL = frozenset(("completed", "cancelled"))
IMMUTABLE = ("audit", "bundle_history", "policy_revisions", "service_group_revisions", "managed_outcomes", "learning_allow_history")
CURRENT = ("auth_users", "maintenance_backups", "managed_rollouts", "learning_allow_hosts", "learning_allow_policies", "notification_settings", "notification_revisions", "notification_deliveries", "endpoint_configuration_reviews", "hit_monitors", "hit_monitor_targets", "policy_deployments", "policy_deployment_targets")
SAFETY_TABLES = (*IMMUTABLE, *CURRENT, "managed_approvals", "servers", "retired_endpoints", "maintenance_settings", "tokens", "firewall_changes")
_OWNER = secrets.token_hex(16)
_ADMITTED = set()


class RecoveryError(RuntimeError):
    """A safe, public operator message, never a driver/DSN exception."""


class RecoveryBusy(RecoveryError):
    pass


def _root(manager):
    path = Path(manager.root) / "recovery"
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink():
        raise RecoveryError("Recovery state must be a private regular directory")
    path.chmod(0o700)
    return path


def _directory(manager, identifier):
    if not isinstance(identifier, str) or not ID.fullmatch(identifier):
        raise ValueError("Invalid recovery identity")
    path = _root(manager) / identifier
    path.mkdir(mode=0o700, exist_ok=True)
    if path.is_symlink():
        raise RecoveryError("Recovery work directory must not be a symlink")
    return path


def _node(manager):
    app = getattr(manager, "app", None)
    return os.environ.get("PRTHAK_APPLIANCE_NODE_ID") or (app.controller_id if app else None) or _read_json(manager.root / "controller-identity.json", {}).get("controller_id")


def _store(manager):
    app = getattr(manager, "app", None)
    if not app or not getattr(app, "store", None):
        raise RecoveryError("Recovery review requires the current healthy controller and its live safety ledger")
    if app.demo:
        raise RecoveryError("Database recovery is unavailable in the synthetic demo")
    return app.store


def _super(store, db, actor, principal):
    subject = approvals.identity(store, db, actor, principal)
    if subject["role"] != "super_admin":
        raise PermissionError("Database recovery requires a live enabled Entra Super Admin")
    return subject


def _super_maker(store, db, plan):
    maker = plan.get("approval", {}).get("requester", {})
    row = store._get(db, "auth_users", maker.get("user_id"))
    if not row or row.get("enabled") is not True or row.get("role") != "super_admin":
        raise PermissionError("The recovery requester must remain an enabled Super Admin")


def _regular_hash(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 32 * 1024 * 1024:
        raise RecoveryError("A referenced PKI or credential file is missing, unsafe or too large")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _private_context(manager, profile=None, known_paths=None):
    """Local bindings only; raw paths and private bytes never enter API/PG."""
    context = _read_json(manager.root / "controller-tls-context.json", {}) if known_paths else manager.certificate_context() if hasattr(manager, "certificate_context") else {}
    paths = {}
    for name in ("cert_path", "key_path", "ca_path"):
        if context.get(name):
            paths[name] = str(Path(context[name]).absolute())
    app = getattr(manager, "app", None)
    if app and getattr(app, "signer", None):
        paths["issuer_key"] = str(app.signer.ca_key.absolute())
    for name in ("ca_key",):
        value = (profile or {}).get("controller_tls", {}).get(name)
        if value:
            paths["issuer_key"] = str(Path(value).absolute())
    paths.update(known_paths or {})
    from .auth import EntraConfig
    environment = {**os.environ, **(profile or {}).get("controller_env", {})}
    auth = getattr(getattr(app, "auth", None), "config", None) or EntraConfig.from_env(environment)
    if environment.get("SEG_ENTRA_CLIENT_SECRET_FILE"):
        paths["entra_secret_file"] = str(Path(environment["SEG_ENTRA_CLIENT_SECRET_FILE"]).absolute())
    for variable, name in (("SEG_POLICY_SIGNING_KEY_FILE", "policy_signing_key"), ("SEG_POLICY_SIGNING_TRUST_FILE", "policy_signing_trust")):
        if environment.get(variable):
            paths[name] = str(Path(environment[variable]).absolute())
    if not all(name in paths for name in ("cert_path", "key_path", "ca_path")):
        raise RecoveryError("The current trusted HTTPS pair and endpoint CA must be present before recovery")
    hashes = {name: _regular_hash(path) for name, path in paths.items()}
    protected = {}
    for directory in ("vault", "policy-signing", "cluster-pki", "controller-pki"):
        base = manager.root / directory
        if not base.exists():
            continue
        if base.is_symlink():
            raise RecoveryError("Current protected platform material must not be a symlink")
        for path in sorted(base.rglob("*")):
            if path.is_symlink():
                raise RecoveryError("Protected platform material contains a symlink")
            if path.is_file():
                protected[str(path.relative_to(manager.root))] = _regular_hash(path)
    if len(protected) > 10000:
        raise RecoveryError("Protected recovery material exceeds the bounded file catalogue")
    auth_binding = {"fingerprint": auth.fingerprint if auth.enabled else None, "secret_sha256": hashlib.sha256(auth.client_secret.encode()).hexdigest() if auth.enabled else None}
    overlay = manager.launch_tls() if hasattr(manager, "launch_tls") else {}
    signing = {name: environment.get(name) for name in ("SEG_POLICY_SIGNING_DEPLOYMENT_ID", "SEG_POLICY_SIGNING_KEY_FILE", "SEG_POLICY_SIGNING_TRUST_FILE", "SEG_POLICY_SIGNED_BUNDLES_DIR")}
    from .application_port import committed_binding
    binding = {"files": hashes, "protected": protected, "profile_digest": digest(profile), "node_id": _node(manager), "auth_context_digest": digest(auth_binding), "launch_tls_digest": digest(overlay), "signing_context_digest": digest(signing), "tls_context_digest": digest(_read_json(manager.root / "controller-tls-context.json", {})), "application_port_digest": digest(committed_binding(manager))}
    return {"paths": paths, "binding": binding, "digest": digest(binding)}


def _context_matches(manager, profile, expected):
    actual = _private_context(manager, profile, expected["paths"])
    before, after = expected["binding"], actual["binding"]
    if any(before[key] != after[key] for key in ("files", "profile_digest", "node_id", "auth_context_digest", "launch_tls_digest", "signing_context_digest", "tls_context_digest", "application_port_digest")):
        return False
    if any(after["protected"].get(key) != value for key, value in before["protected"].items()):
        return False
    # Recovery's own encrypted source/profile envelopes add Vault entries;
    # they cannot replace its key, the issuer, or an existing secret reference.
    return all(key.startswith("vault/") and key != "vault/vault.key" for key in set(after["protected"]) - set(before["protected"]))


def _members(store, db, node, profile):
    if not store.ha:
        return [node], [], None
    config = store._get(db, "maintenance_settings", "appliance_cluster") or {}
    if not profile or profile.get("deployment_id") != config.get("deployment_id"):
        raise RecoveryError("Shared recovery requires the exact managed active deployment profile")
    voters = copy.deepcopy(config.get("voters", []))
    if len(voters) != 3 or len({value.get("id") for value in voters}) != 3:
        raise RecoveryError("Shared recovery requires exactly three registered database voters")
    controllers = {value["id"] for value in store._all(db, "controller_nodes")}
    controllers.update(value["id"] for value in config.get("members", []))
    controllers.add(node)
    if None in controllers or not controllers or len(controllers) > 10000:
        raise RecoveryError("Registered controller membership is invalid or exceeds the recovery bound")
    rotation_id = config.get("replication_rotation_id")
    rotation = store._get(db, "maintenance_settings", "appliance_replication_rotation:" + rotation_id) if rotation_id else None
    if rotation and rotation.get("phase") not in ("completed", "aborted"):
        raise RecoveryError("Complete or safely abort replication credential rotation before recovery")
    return sorted(controllers), voters, config


def _public_plan(plan):
    keys = ("id", "kind", "status", "digest", "plan_digest", "created_at", "created_by", "expires_at", "reason", "backup", "backend", "source", "source_node", "controller_ids", "voters", "database_names", "can_restore", "blockers", "warnings", "confirmation_count", "confirmation_nonce", "confirmation_phrase", "approval")
    return {key: copy.deepcopy(plan[key]) for key in keys if key in plan}


def _public_job(record):
    return {key: copy.deepcopy(record.get(key)) for key in ("id", "operation", "status", "phase", "created_at", "updated_at", "backup_id", "backend", "source_node", "controller_ids", "acks", "errors", "result") if key in record}


def _exclude_port_transition(store, db):
    # PostgreSQL meta() already owns the shared writer advisory lock. SQLite
    # needs its database writer lock before checking either operation's ledger.
    if not store.ha and not db.in_transaction:
        db.execute("BEGIN IMMEDIATE")
    from .provider_lifecycle import CONTROL, TERMINAL
    provider=store._get(db,'maintenance_settings',CONTROL)
    if provider and provider.get('phase') not in TERMINAL:
        raise RecoveryError('Finish or roll back the current sign-in provider transition before database recovery')
    from .application_port import in_progress
    if in_progress(store, db):
        raise RecoveryBusy("Finish the current application port change or its verified rollback before database recovery")


def preview(manager, body, actor, principal=None):
    store = _store(manager)
    with store.read_meta() as db:
        _super(store, db, actor, principal)
    if not isinstance(body, dict) or set(body) - {"backup_id", "reason"}:
        raise ValueError("Recovery preview accepts a backup identity and reason only")
    reason = body.get("reason", "")
    if not isinstance(reason, str) or not 8 <= len(reason.strip()) <= 500:
        raise ValueError("Give a recovery reason of 8 to 500 characters")
    backup, manifest = maintenance._inspect(store, body.get("backup_id"))
    if manifest.get("version") != __version__ or manifest.get("backend") != ("postgresql" if store.ha else "sqlite"):
        raise RecoveryError("This archive needs a separately tested version/backend migration before live recovery")
    if store.ha and any(not member.get("data_hashes") or set(member["data_hashes"]) != set(member["tables"]) - {"runtime_deployment"} for member in backup["members"]):
        raise RecoveryError("This PostgreSQL archive supports structural validation only; create a new backup with canonical data hashes before reviewed live recovery")
    profile = manager.active_profile()
    private = _private_context(manager, profile)
    identifier, node = uuid.uuid4().hex, _node(manager)
    if not node:
        raise RecoveryError("A persisted controller identity is required before recovery")
    with store.lock, store.meta() as db:
        _exclude_port_transition(store, db)
        _super(store, db, actor, principal)
        active = store._get(db, "maintenance_settings", CONTROL_ID)
        if active and active.get("phase") not in TERMINAL:
            raise RecoveryError("Another recovery is already active; inspect its durable progress")
        controllers, voters, config = _members(store, db, node, profile)
        source = {"deployment_id": (profile or {}).get("deployment_id"), "epoch": (profile or {}).get("epoch"), "active_revision": (profile or {}).get("active_revision"), "private_context_digest": private["digest"], "membership_digest": digest({"controllers": controllers, "voters": voters})}
        plan = {"id": identifier, "kind": SCHEME, "status": "draft", "backend": backup["backend"], "backup": maintenance._public(backup), "archive_sha256": backup["archive_sha256"], "source": source, "source_node": node, "controller_ids": controllers, "voters": voters, "created_at": stamp(), "created_by": actor, "expires_at": stamp(now() + timedelta(minutes=15)), "reason": reason.strip(), "can_restore": True, "blockers": [], "warnings": ["Every controller writer will be fenced and drained; HTTPS will be temporarily unavailable", "Current PKI, Vault, revocations, retired identities, disabled users and immutable endpoint history are retained", "Browser sessions, unused credentials, pending approvals and learning automation are invalidated; policy application requires fresh review", "The current database and protected material are preserved privately for rollback; this is a live-source recovery, not an offline disaster-recovery claim"], "confirmation_count": 0, "confirmation_nonce": secrets.token_urlsafe(32)}
        if store.ha:
            plan["database_names"] = {namespace: "prthak_restore_" + identifier + "_" + namespace for namespace in ("metadata", "traffic")}
            plan["warnings"].append("Every registered controller must acknowledge its writer fence and prepared new profile; unavailable peers block release")
        plan["plan_digest"] = digest({key: plan[key] for key in ("id", "backend", "archive_sha256", "source", "source_node", "controller_ids", "voters", "reason")})
        plan["digest"] = plan["plan_digest"]
        plan["confirmation_phrase"] = "RESTORE DATABASE " + plan["digest"][:12]
        approvals.request(store, db, plan, actor, principal)
        atomic_private_json(_directory(manager, identifier) / "context.json", private)
        store._put(db, "maintenance_plans", {**plan, "id": PLAN_PREFIX + identifier})
        store.audit("recovery.preview_created", actor, {"recovery_id": identifier, "backup_id": backup["id"], "digest": plan["digest"]}, db)
    return _public_plan(plan)


def confirm(manager, body, actor, principal=None):
    store = _store(manager)
    if not isinstance(body, dict) or not ID.fullmatch(str(body.get("preview_id", ""))):
        raise ValueError("Select a current recovery preview")
    identifier = body["preview_id"]
    with store.lock, store.meta() as db:
        _exclude_port_transition(store, db)
        _super(store, db, actor, principal)
        plan = store._get(db, "maintenance_plans", PLAN_PREFIX + identifier)
        if not plan or plan.get("kind") != SCHEME:
            raise ValueError("Unknown recovery preview")
        plan = {**plan, "id": identifier}
        _super_maker(store, db, plan)
        active = store._get(db, "maintenance_settings", CONTROL_ID)
        if active and active.get("phase") not in TERMINAL and active.get("recovery_id") != identifier:
            raise WorkflowConflict("A different recovery owns the durable writer transition; wait for its verified terminal result", {})
        if plan.get("status") == "queued":
            return {"pending_approval": False, "preview": _public_plan(plan), "job": {"id": identifier, "operation": "recovery", "status": "queued"}, "duplicate": True}
        if plan.get("status") not in ("draft", "awaiting_second_confirmation") or parse_time(plan["expires_at"]) <= now() or body.get("digest") != plan["digest"] or body.get("confirmation_nonce") != plan.get("confirmation_nonce"):
            raise WorkflowConflict("Recovery review is stale, changed or expired", _public_plan(plan))
        profile = manager.active_profile()
        controllers, voters, _ = _members(store, db, _node(manager), profile)
        if digest({"controllers": controllers, "voters": voters}) != plan["source"]["membership_digest"] or any((profile or {}).get(key) != plan["source"].get(key) for key in ("deployment_id", "epoch", "active_revision")):
            raise WorkflowConflict("Deployment membership or active profile changed; review recovery again", {})
        backup = store._get(db, "maintenance_backups", plan["backup"]["id"])
        if not backup or backup.get("archive_sha256") != plan["archive_sha256"]:
            raise WorkflowConflict("The immutable selected backup changed or disappeared", {})
        final = plan["confirmation_count"] == 1
        if final and body.get("challenge") != plan["confirmation_phrase"]:
            raise ValueError("Type the exact displayed recovery phrase")
        approvals.confirm(store, db, plan, actor, principal, final=final)
        plan["confirmation_count"] += 1
        plan["status"] = "queued" if final else "awaiting_second_confirmation"
        if final:
            plan.pop("confirmation_nonce", None)
            record = {"id": CONTROL_ID, "recovery_id": identifier, "operation": "recovery", "status": "queued", "phase": "queued", "backend": plan["backend"], "backup_id": backup["id"], "archive_sha256": plan["archive_sha256"], "source_node": plan["source_node"], "controller_ids": plan["controller_ids"], "voters": plan["voters"], "source": plan["source"], "target_epoch": (profile or {}).get("epoch", 0) + 1, "plan_digest": plan["digest"], "approval_proof": approvals.proof(plan), "acks": {}, "actions": {}, "errors": {}, "created_at": stamp(), "updated_at": stamp()}
            record["fence_digest"] = digest({key: record[key] for key in ("recovery_id", "archive_sha256", "source", "target_epoch", "controller_ids")})
            job = {**record, "id": identifier, "private": {"recovery_id": identifier}}
            # Publish the job before its DB authority. The supervisor discovers
            # only the committed control row, so this cannot overwrite a later
            # running/completed receipt after the request transaction commits.
            _private_json(manager._job_path(identifier), job)
            store._put(db, "maintenance_settings", record)
        else:
            plan["confirmation_nonce"] = secrets.token_urlsafe(32)
        store._put(db, "maintenance_plans", {**plan, "id": PLAN_PREFIX + identifier})
        store.audit("recovery.approved" if final else "recovery.submitted", actor, {"recovery_id": identifier, "digest": plan["digest"]}, db)
    return {"pending_approval": not final, "preview": _public_plan(plan), **({"job": _public_job(job)} if final else {})}


def status(manager):
    if not manager or not getattr(manager, "app", None):
        return {"active": None, "pending_reviews": [], "requires_supervisor": True}
    store = manager.app.store
    with store.read_meta() as db:
        record = store._get(db, "maintenance_settings", CONTROL_ID)
        plans = [{**value, "id": value["id"][len(PLAN_PREFIX):]} for value in store._all(db, "maintenance_plans") if value.get("kind") == SCHEME and value.get("status") in ("draft", "awaiting_second_confirmation") and parse_time(value["expires_at"]) > now()]
    if not record:
        saved = sorted(_root(manager).glob("*/control.json"), key=lambda path: path.stat().st_mtime, reverse=True)
        record = _read_json(saved[0]) if saved else None
    return {"active": _public_job({**record, "id": record["recovery_id"]}) if record else None, "pending_reviews": [_public_plan(plan) for plan in plans[-20:]], "requires_supervisor": True}


def _facade(directory):
    store = Store.__new__(Store)
    store.path, store.meta_path, store.traffic_path = Path(directory), Path(directory) / "inventory.sqlite3", Path(directory) / "traffic.sqlite3"
    store.lock, store.flow_lock = threading.RLock(), threading.RLock()
    store.retention_hours = 24
    return store


def _rows(db, table):
    columns = _columns(table)
    return [[row[index] for index in range(len(columns))] for row in db.execute(f'SELECT {",".join(columns)} FROM "{table}" ORDER BY {columns[0]}').fetchall()]


def _json_rows(db, table):
    return [json.loads(row[0]) for row in db.execute(f'SELECT data FROM "{table}"').fetchall()]


def _replace(db, table, rows):
    columns = _columns(table)
    db.execute(f'DELETE FROM "{table}"')
    sql = f'INSERT INTO "{table}"({",".join(columns)}) VALUES({",".join("?" for _ in columns)})'
    for row in rows:
        db.execute(sql, row)


def _safety(db):
    return {table: _rows(db, table) for table in SAFETY_TABLES}


def _merge_immutable(db, table, incoming):
    columns = _columns(table)
    current = {row[0]: row for row in _rows(db, table)}
    for row in incoming:
        if row[0] in current:
            if _hash_rows(columns, [current[row[0]]]) != _hash_rows(columns, [row]):
                raise RecoveryError("An immutable history identity has different content; automatic recovery is refused")
        else:
            db.execute(f'INSERT INTO "{table}"({",".join(columns)}) VALUES({",".join("?" for _ in columns)})', row)


def _overlay_safety(db, safety, recovery_id):
    """High-water authority state wins over the selected older business data."""
    from .managed import record_revision
    for table in IMMUTABLE:
        _merge_immutable(db, table, safety[table])
    for table in CURRENT:
        _replace(db, table, safety[table])
    from .policy_deployments import invalidate_after_recovery
    invalidate_after_recovery(None, db)
    # Current monitor identities win over an older archive, but capture never
    # resumes merely because a database was recovered. A fresh reviewed enable
    # creates a new frozen scope and fresh signed short leases.
    for monitor in _json_rows(db, "hit_monitors"):
        monitor.update(enabled=False, requires_review=True, stopped_at=stamp(), recovery_id=recovery_id,
                       revision=monitor.get("revision", 0) + 1)
        Store._put(db, "hit_monitors", monitor)
    db.execute("UPDATE hit_monitor_targets SET enabled=0")
    # Active is a mutable index column; the approval body itself is immutable.
    old = {row[0]: row for row in _rows(db, "managed_approvals")}
    for row in safety["managed_approvals"]:
        previous = old.get(row[0])
        if previous and any(previous[index] != row[index] for index in range(len(row)) if _columns("managed_approvals")[index] != "active"):
            raise RecoveryError("An immutable approval has conflicting content")
        db.execute("DELETE FROM managed_approvals WHERE id=?", (row[0],))
        columns = _columns("managed_approvals")
        db.execute(f'INSERT INTO managed_approvals({",".join(columns)}) VALUES({",".join("?" for _ in columns)})', row)
    db.execute("UPDATE managed_approvals SET active=0")
    current_settings = {row[0]: json.loads(row[1]) for row in safety["maintenance_settings"]}
    # Operational identity and approval authority must never roll back with
    # business inventory. An old archive cannot re-enable a pilot or old SSO.
    for value in _json_rows(db,"maintenance_settings"):
        key=value['id']
        if key in ('controller_provider_authority','controller_provider_transition','approval_settings') or key.startswith(('controller_provider_plan:','approval_settings_review:','provider_revoked_learning_proof:','platform_join:')):
            db.execute('DELETE FROM maintenance_settings WHERE id=?',(key,))
    for key,value in current_settings.items():
        if key in ('controller_provider_authority','controller_provider_transition') or key.startswith(('controller_provider_plan:','provider_revoked_learning_proof:')) or key.startswith('platform_join:') and value.get('consumed') is True:
            Store._put(db,'maintenance_settings',value)
    pilot=current_settings.get('approval_settings')
    if pilot:
        pilot=copy.deepcopy(pilot)
        pilot.update(revision=pilot['revision']+1,mode='two_person',server_ids=[],expires_at=None,
                     membership_digest=digest({}),updated_at=stamp(),updated_by='database-recovery')
        Store._put(db,'maintenance_settings',pilot)
    for review in _json_rows(db,'endpoint_configuration_reviews'):
        if review.get('status')!='revoked':
            review.update(status='revoked',revoked_at=stamp(),revoked_by='database-recovery',
                          revocation_reason='Database recovery requires a fresh endpoint configuration review')
            Store._put(db,'endpoint_configuration_reviews',review)
    for value in _json_rows(db, "maintenance_settings"):
        if value["id"].startswith("endpoint_certificate:"):
            db.execute("DELETE FROM maintenance_settings WHERE id=?", (value["id"],))
    for key, value in current_settings.items():
        if key.startswith(("endpoint_certificate:", "backup_schedule_run:", "application_port:", "assignment_guard:")) or key in ("appliance_cluster", "demo_seed_disabled", "backup_schedule"):
            Store._put(db, "maintenance_settings", value)
    for table in ("auth_sessions", "auth_states", "tokens", "learning_policy_previews", "notification_reviews", "hit_monitor_reviews"):
        db.execute(f'DELETE FROM "{table}"')
    for row in safety["tokens"]:
        if json.loads(row[1]).get("used") is True:
            Store._put(db, "tokens", json.loads(row[1]))
    for value in _json_rows(db, "maintenance_settings"):
        if value["id"].startswith(("endpoint_recovery:", "recovery_control:", "endpoint_revoke_review:", "source_bank_review:")):
            db.execute("DELETE FROM maintenance_settings WHERE id=?", (value["id"],))
    for key, value in current_settings.items():
        if key.startswith("endpoint_recovery:") and value.get("used") is True:
            Store._put(db, "maintenance_settings", value)
    retired = {row[0]: row for row in _rows(db, "retired_endpoints")}
    retired.update({row[0]: row for row in safety["retired_endpoints"]})
    _replace(db, "retired_endpoints", list(retired.values()))
    source_servers = {row[0]: json.loads(row[1]) for row in safety["servers"]}
    restored = {value["id"]: value for value in _json_rows(db, "servers")}
    certificate_fields = ("certificate_registry", "certificate_not_after", "certificate_fingerprint", "certificate_revoked")
    known_endpoint_fields = (*certificate_fields, "_managed_rules_active", "_host_default_deny_active", "host_default_deny_state", "_managed_receipt_cursor", "_host_default_deny_owned_cleanup_required", "_last_managed_applied_version", "last_good_version", "last_good_digest", "managed_enforcement", "applied_version")
    for identifier, source in source_servers.items():
        if identifier in retired:
            continue
        server = restored.get(identifier)
        if server is None:
            server = {key: copy.deepcopy(source[key]) for key in ("id", "hostname", "ips", "created_at") if key in source}
            if not source.get("last_seen"):
                raise RecoveryError("A current post-backup endpoint has no authenticated freshness record")
            server.update(tags={}, _metadata_overrides={"tags": {}}, tag_sources={}, metadata_conflicts=[], listeners=[], expected_services=[], matched_policy_ids=[], location_id=None, location_source={"type": "unassigned"}, status="warning", capabilities=[], last_seen=source["last_seen"], os="unknown", os_version="", firewalld_version="", firewall_backend="", firewalld_state="unknown", ufw_active=False, collector_status="off")
        for field in known_endpoint_fields:
            if field in source:
                server[field] = source[field]
        restored[identifier] = server
    for identifier, server in restored.items():
        if identifier in retired:
            db.execute("DELETE FROM servers WHERE id=?", (identifier,))
            continue
        server.pop("_compiled", None)
        server.pop("_source_bank_job", None)
        server.pop("source_bank_preparation", None)
        current = source_servers.get(identifier, {})
        server["_recovery_version_floor"] = max(current.get("applied_version", 0), current.get("desired_version", 0), current.get("_compiled", {}).get("version", 0))
        server["recovery_reconciliation_required"] = True
        if identifier not in source_servers:
            server.update(certificate_registry=True, certificate_revoked=True)
        server.update(desired_version=0, apply_status="pending", apply_error="Recovery requires a fresh authenticated endpoint report and authorized policy review", recovery_id=recovery_id)
        for field in ("protection", "management_protection"):
            if isinstance(server.get(field), dict):
                server[field] = {**server[field], "ready": False, "blockers": ["Fresh post-recovery endpoint protection report required"]}
        Store._put(db, "servers", server)
    for session in _json_rows(db, "sessions"):
        if session.get("status") == "active":
            session.update(status="stopped", stopped_at=stamp(), stopped_by="database-recovery", stop_reason="Fresh learning authority is required after database recovery")
        for field in ("initial_approval_proof", "initial_approval_plan", "initial_approval_target_bindings"):
            session.pop(field, None)
        Store._put(db, "sessions", session)
    from .learning_targets import rebuild as rebuild_learning_targets
    rebuild_learning_targets(Store, db)
    for rollout in _json_rows(db, "managed_rollouts"):
        if rollout.get("status") in ("draft", "awaiting_second_confirmation", "authorized"):
            rollout.update(status="invalidated", invalidated_at=stamp(), invalidation_reason="Database recovery requires a fresh authorized rollout")
            rollout.pop("confirmation_nonce", None)
            Store._put(db, "managed_rollouts", rollout)
    for policy in _json_rows(db, "learning_allow_policies"):
        policy.pop("approval_proof", None)
        policy.update(auto_updates=False, status="blocked", error="Learning grant held after recovery; review again before mutation")
        Store._put(db, "learning_allow_policies", policy)
    changes = {value["id"]: value for value in _json_rows(db, "firewall_changes")}
    changes.update({row[0]: json.loads(row[1]) for row in safety["firewall_changes"]})
    for value in changes.values():
        if value.get("status") not in ("applied", "cancelled", "rolled_back", "expired"):
            value.update(status="cancelled", cancelled_at=stamp(), cancelled_by="database-recovery")
            value.pop("approval_proof", None)
        Store._put(db, "firewall_changes", value)
    for table in ("maintenance_plans", "metadata_plans", "server_lifecycle_plans"):
        for value in _json_rows(db, table):
            if value.get("status") not in ("applied", "cancelled", "expired"):
                value.update(status="cancelled", cancelled_by="database-recovery")
                value.pop("confirmation_nonce", None)
                Store._put(db, table, value)
    for value in _json_rows(db, "notification_deliveries"):
        if value.get("status") not in ("sent", "cancelled", "failed"):
            value.update(status="cancelled", error="Pending delivery invalidated by reviewed recovery")
            columns = _columns("notification_deliveries")
            db.execute("UPDATE notification_deliveries SET status=?,data=? WHERE id=?", ("cancelled", json.dumps(value, sort_keys=True), value["id"]))
    # Restored current definitions get a new revision above retained history.
    restored_groups = {}
    for group in _json_rows(db, "service_groups"):
        maximum = db.execute("SELECT MAX(revision) FROM service_group_revisions WHERE service_group_id=?", (group["id"],)).fetchone()[0] or 0
        group.update(revision=max(maximum, group.get("revision", 0)) + 1, updated_at=stamp())
        from .service_groups import _record_revision
        _record_revision(db, group, "database-recovery", "Restored service definition above retained history")
        Store._put(db, "service_groups", group)
        restored_groups[group["id"]] = group
    for policy in _json_rows(db, "policies"):
        from .service_groups import snapshot
        for service in policy["services"]:
            if service.get("service_group_id"):
                group = restored_groups.get(service["service_group_id"])
                if group is None:
                    raise RecoveryError("Restored desired policy refers to a missing service group")
                service["service_group_snapshot"] = snapshot(group)
        maximum = db.execute("SELECT MAX(revision) FROM policy_revisions WHERE policy_id=?", (policy["id"],)).fetchone()[0] or 0
        policy.update(revision=max(maximum, policy.get("revision", 0)) + 1, updated_at=stamp())
        record_revision(db, policy, "database-recovery", "Restored desired intent; fresh authorized rollout required")
        Store._put(db, "policies", policy)
    Store._put(db, "maintenance_settings", {"id": "recovery_prepared", "recovery_id": recovery_id, "prepared_at": stamp(), "requires_fresh_authority": True})


def _record_completion(db, record):
    completed = record["completed_at"]
    Store._put(db, "maintenance_settings", {"id": "recovery_last_completed", "recovery_id": record["recovery_id"], "completed_at": completed, "backend": record["backend"], "requires_fresh_authority": True})
    event = {"id": "recovery-completed:" + record["recovery_id"], "action": "recovery.completed", "actor": record["approval_proof"]["approved_by"]["actor"], "created_at": completed, "details": {"recovery_id": record["recovery_id"], "backup_id": record["backup_id"], "backend": record["backend"], "plan_digest": record["plan_digest"], "requires_fresh_authority": True}}
    Store._put(db, "audit", event)


def _save_material(manager, work, context):
    target = work / "protected-material"
    target.mkdir(mode=0o700, exist_ok=True)
    copied, total = {}, 0
    for name, original in context["paths"].items():
        data = Path(original).read_bytes()
        if hashlib.sha256(data).hexdigest() != context["binding"]["files"][name]:
            raise RecoveryError("A current PKI file changed before its protected rollback copy")
        total += len(data)
        destination = target / (name + ".pem")
        destination.write_bytes(data)
        destination.chmod(0o600)
        copied[name] = hashlib.sha256(data).hexdigest()
    for relative in context["binding"]["protected"]:
        source, destination = manager.root / relative, target / "platform" / relative
        data = source.read_bytes()
        if hashlib.sha256(data).hexdigest() != context["binding"]["protected"][relative]:
            raise RecoveryError("Current protected material changed before its verified rollback copy")
        total += len(data)
        if total > 256 * 1024 * 1024:
            raise RecoveryError("Protected rollback material exceeds its bounded size")
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        destination.write_bytes(data)
        destination.chmod(0o600)
        copied[relative] = hashlib.sha256(data).hexdigest()
    atomic_private_json(work / "protected-manifest.json", {"current_context_digest": context["digest"], "files": copied})


@contextmanager
def _sqlite_exclusive(directory):
    descriptor = os.open(Path(directory) / ".prthak-storage.lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RecoveryBusy("A current SQLite transaction is still active; recovery will retry without replacing data") from None
        yield
    finally:
        os.close(descriptor)


def _local_record(manager):
    fence = _read_json(manager.root / LOCAL_FENCE)
    if fence:
        return _read_json(_directory(manager, fence["recovery_id"]) / "control.json"), fence
    for path in sorted(_root(manager).glob("*/control.json")):
        value = _read_json(path)
        if value and value.get("phase") not in TERMINAL:
            return value, None
    return None, None


def assert_start_allowed(manager, profile=None):
    fence = _read_json(manager.root / LOCAL_FENCE)
    if not fence:
        return
    record = _read_json(_directory(manager, fence["recovery_id"]) / "control.json", {})
    if str(manager.root) not in _ADMITTED or record.get("phase") not in ("starting", "completed") or record.get("released_profile_digest") != digest(profile):
        raise RecoveryError("The durable recovery writer fence is still active; normal child startup is refused")


def child_environment(manager):
    """Only a supervisor-owned candidate launch receives the private admission."""
    if str(manager.root) not in _ADMITTED:
        return {}
    record, fence = _local_record(manager)
    if not record or not fence:
        return {}
    return {"PRTHAK_RECOVERY_ADMISSION": record["writer_nonce"]}


def sqlite_admitted(directory, fence):
    value = os.environ.get("PRTHAK_RECOVERY_ADMISSION", "")
    return bool(fence.get("state") == "RECOVERY_CANDIDATE" and re.fullmatch(r"[a-f0-9]{64}", value) and hashlib.sha256(value.encode()).hexdigest() == fence.get("admission_hash"))


def _start(supervisor, profile):
    key = str(supervisor.manager.root)
    _ADMITTED.add(key)
    try:
        return supervisor.start_child(profile)
    finally:
        _ADMITTED.discard(key)


def _wait_ready(supervisor, arguments, profile, writer_nonce=None):
    from .platform_runtime import probe_readiness
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if supervisor.child is None or supervisor.child.poll() is not None:
            return False
        if supervisor.probe is probe_readiness:
            manager = supervisor.manager
            overlay = manager.launch_tls() if hasattr(manager, "launch_tls") else {}
            context = manager.certificate_context() if hasattr(manager, "certificate_context") else {}
            # start_child applies a committed certificate overlay without
            # rewriting the database profile's older bootstrap TLS name.
            hostname = overlay.get("hostname") or (profile or {}).get("controller_server_name") or context.get("hostname")
            ready = supervisor.probe(arguments, profile, tls_hostname=hostname, recovery_nonce=writer_nonce)
        else:
            ready = supervisor.probe(arguments, profile)
        if ready:
            return True
        time.sleep(0.2)
    return False


def _job_update(manager, record):
    identifier = record["recovery_id"]
    path = manager._job_path(identifier)
    value = _read_json(path, {"id": identifier, "operation": "recovery", "created_at": record["created_at"], "private": {"recovery_id": identifier}})
    value.update(status="applied" if record["phase"] == "completed" else "blocked" if record.get("errors") else "running", phase=record["phase"], updated_at=stamp(), result=_public_job({**record, "id": identifier}))
    _private_json(path, value)


def _local_save(manager, record):
    record["updated_at"] = stamp()
    path = _directory(manager, record["recovery_id"]) / "control.json"
    previous = _read_json(path, {})
    persisted = copy.deepcopy(record)
    for key in ("writer_nonce", "released_profile_digest"):
        if key not in persisted and key in previous:
            persisted[key] = previous[key]
    atomic_private_json(path, persisted)
    _job_update(manager, record)


def _drain(supervisor):
    if supervisor.child is not None:
        if supervisor.stop(supervisor.child) is not True:
            raise RecoveryError("The complete controller child process group did not drain; no database replacement is allowed")
        supervisor.child = None


def _sqlite_tick(supervisor, record):
    manager, source = supervisor.manager, Path(supervisor.source_dir)
    identifier = record["recovery_id"]
    work = _directory(manager, identifier)
    context = _read_json(work / "context.json")
    if not context:
        raise RecoveryError("The original local PKI/Vault recovery binding is unavailable")
    if record["phase"] == "queued":
        facade = _facade(source)
        existing_fence = _read_json(source / FENCE_NAME)
        if existing_fence and (existing_fence.get("recovery_id") != identifier or existing_fence.get("state") != "RECOVERING"):
            raise RecoveryError("A retired or different storage fence cannot be overwritten by SQLite recovery")
        try:
            if not _context_matches(manager, None, context):
                raise RecoveryError("Current PKI, Vault or profile changed after review; replacement is refused")
            from .platform_runtime import _argument
            issuer_key = _argument(supervisor.arguments, "--ca-key")
            if issuer_key and _regular_hash(issuer_key) != context["binding"]["files"].get("issuer_key"):
                raise RecoveryError("The supervised endpoint issuer key changed after recovery review")
            facade.backup_dir = manager.root / "backups"
            with closing(sqlite3.connect(source / "inventory.sqlite3")) as db:
                backup = Store._get(db, "maintenance_backups", record["backup_id"])
            if not backup or backup["archive_sha256"] != record["archive_sha256"] or backup.get("status") != "complete":
                raise RecoveryError("The immutable selected archive changed after review")
            maintenance._inspect_record(backup, manager.root / "backups" / (record["backup_id"] + ".zip"))
            with _sqlite_exclusive(source):
                with closing(sqlite3.connect(source / "inventory.sqlite3")) as db:
                    current = Store._get(db, "maintenance_settings", CONTROL_ID)
                    if not current or current.get("recovery_id") != identifier or current.get("plan_digest") != record["plan_digest"] or current.get("phase") != "queued":
                        raise RecoveryError("The queued local request is no longer the committed recovery owner")
                    _current_super_proof(db, record)
                fence = {"recovery_id": identifier, "state": "RECOVERING", "fence_digest": record["fence_digest"]}
                atomic_private_json(source / FENCE_NAME, fence)
                atomic_private_json(manager.root / LOCAL_FENCE, fence)
        except (RecoveryError, maintenance.MaintenanceError) as error:
            if isinstance(error, RecoveryBusy):
                raise
            record.update(phase="cancelled", status="blocked", errors={_node(manager): str(error)})
            with _sqlite_exclusive(source):
                with closing(sqlite3.connect(source / "inventory.sqlite3")) as db:
                    with db:
                        current = Store._get(db, "maintenance_settings", CONTROL_ID)
                        if current and current.get("recovery_id") == identifier:
                            Store._put(db, "maintenance_settings", record)
                owned = _read_json(source / FENCE_NAME)
                if owned and owned.get("recovery_id") == identifier and owned.get("state") == "RECOVERING":
                    (source / FENCE_NAME).unlink()
                    (manager.root / LOCAL_FENCE).unlink(missing_ok=True)
            _local_save(manager, record)
            return False
        record["phase"] = "draining"
        _local_save(manager, record)
    if record["phase"] == "draining":
        _drain(supervisor)
        with _sqlite_exclusive(source):
            if not record.get("original_snapshot"):
                _, proof, fingerprint, original = _snapshot_source(source, "sqlite-recovery-" + identifier)
                record.update(original_snapshot=original.name, original_fingerprint=fingerprint)
                _save_material(manager, work, context)
                with closing(sqlite3.connect(original / "inventory.sqlite3")) as db:
                    atomic_private_json(work / "safety.json", _safety(db))
            extracted = work / "candidate"
            if extracted.exists():
                shutil.rmtree(extracted)
            extracted.mkdir(mode=0o700)
            facade = _facade(source)
            # The archive index is read from the untouched current snapshot,
            # rather than opening a guarded live Store after its writer fence.
            with closing(sqlite3.connect(source / record["original_snapshot"] / "inventory.sqlite3")) as db:
                backup = Store._get(db, "maintenance_backups", record["backup_id"])
            if not backup or backup["archive_sha256"] != record["archive_sha256"]:
                raise RecoveryError("Selected archive no longer matches its reviewed immutable record")
            path = manager.root / "backups" / (record["backup_id"] + ".zip")
            maintenance._inspect_record(backup, path, extracted)
            # Create only known migrations in an isolated candidate directory.
            os.replace(extracted / "metadata.sqlite3", extracted / "inventory.sqlite3")
            candidate = Store(extracted)
            safety = _read_json(work / "safety.json")
            with candidate.meta() as db:
                _overlay_safety(db, safety, identifier)
                candidate.compile_all(db)
            with closing(sqlite3.connect(extracted / "inventory.sqlite3")) as db:
                db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                db.execute("PRAGMA journal_mode=DELETE")
            for filename in ("inventory.sqlite3", "traffic.sqlite3"):
                maintenance._sqlite_description(extracted / filename)
            record["candidate_fingerprint"] = digest({namespace: _statistics(_source_rows(extracted / filename, namespace)) for namespace, filename in (("metadata", "inventory.sqlite3"), ("traffic", "traffic.sqlite3"))})
            record["phase"] = "replacing"
            _local_save(manager, record)
    if record["phase"] == "replacing":
        _drain(supervisor)
        with _sqlite_exclusive(source):
            for filename in ("inventory.sqlite3", "traffic.sqlite3"):
                # Copy first: an interrupted pair replacement can replay both
                # exact immutable candidates, without consuming either file.
                incoming = work / "candidate" / filename
                replacement = source / (".restore-" + identifier + "-" + filename)
                shutil.copyfile(incoming, replacement)
                replacement.chmod(0o600)
                with replacement.open("rb") as stream:
                    os.fsync(stream.fileno())
                for suffix in ("-wal", "-shm"):
                    (source / (filename + suffix)).unlink(missing_ok=True)
                os.replace(replacement, source / filename)
            actual = digest({namespace: _statistics(_source_rows(source / filename, namespace)) for namespace, filename in (("metadata", "inventory.sqlite3"), ("traffic", "traffic.sqlite3"))})
            if actual != record["candidate_fingerprint"]:
                raise RecoveryError("Restored SQLite pair did not match the exact verified candidate")
            record.update(phase="starting", released_profile_digest=digest(None), writer_nonce=secrets.token_hex(32))
            _local_save(manager, record)
            atomic_private_json(source / FENCE_NAME, {"state": "RECOVERY_CANDIDATE", "recovery_id": identifier, "admission_hash": hashlib.sha256(record["writer_nonce"].encode()).hexdigest()})
    if record["phase"] == "starting":
        arguments = _start(supervisor, None) if supervisor.child is None else supervisor.arguments
        if not _wait_ready(supervisor, arguments, None, record["writer_nonce"]):
            _drain(supervisor)
            raise RecoveryError("Restored child did not verify readiness; verified candidates and the original rollback snapshot remain preserved")
        record.update(phase="completed", status="applied", completed_at=stamp(), errors={}, result={"verified": True, "backend": "sqlite", "original_snapshot_preserved": True, "protected_material_preserved": True, "candidate_fingerprint": record["candidate_fingerprint"], "requires_fresh_authority": True})
        with closing(sqlite3.connect(source / "inventory.sqlite3")) as db:
            with db:
                _record_completion(db, record)
        _local_save(manager, record)
        (source / FENCE_NAME).unlink(missing_ok=True)
        (manager.root / LOCAL_FENCE).unlink(missing_ok=True)
    return record["phase"] not in TERMINAL


def supervisor_tick(supervisor):
    """Called before ordinary restart; True keeps the normal writer paused."""
    manager = supervisor.manager
    local, fence = _local_record(manager)
    profile = manager.active_profile()
    if profile or fence and fence.get("backend") == "postgresql":
        return _postgres_tick(supervisor, local, fence, profile)
    if not local:
        # Recover the queue-publication crash window while the source is live.
        try:
            facade = _facade(supervisor.source_dir)
            with facade.read_meta() as db:
                record = facade._get(db, "maintenance_settings", CONTROL_ID)
            if record and record.get("phase") not in TERMINAL and record.get("backend") == "sqlite":
                local = record
                _local_save(manager, local)
        except Exception:
            if (Path(supervisor.source_dir) / FENCE_NAME).exists():
                return True
            return False
    if not local or local.get("phase") in TERMINAL:
        return False
    try:
        return _sqlite_tick(supervisor, local)
    except Exception as error:
        local.setdefault("errors", {})[_node(manager) or "local"] = str(error) if isinstance(error, (RecoveryError, maintenance.MaintenanceError)) else "Recovery could not be verified; writers remain fenced and original data is preserved"
        _local_save(manager, local)
        return True


def _pg_connect(profile, namespace):
    import psycopg
    try:
        return psycopg.connect(profile[namespace + "_dsn"], connect_timeout=5, application_name="prthak-reviewed-recovery", target_session_attrs="read-write")
    except Exception:
        raise RecoveryError("The exact source recovery database is unavailable; no local fallback is allowed") from None


def _raw_marker(connection):
    row = connection.execute("SELECT data FROM runtime_deployment WHERE id='active'").fetchone()
    return json.loads(row[0]) if row else {}


def _source_marker(marker, profile, namespace, record=None):
    if marker.get("deployment_id") != profile["deployment_id"] or marker.get("epoch") != profile["epoch"] or marker.get("namespace") != namespace or marker.get("state") not in ("READY", "FENCED_RECOVERY"):
        raise RecoveryError("The recovery source identity, namespace or epoch differs from the reviewed deployment")
    if marker.get("state") == "FENCED_RECOVERY" and (not record or marker.get("recovery_id") != record["recovery_id"] or marker.get("recovery_fence_digest") != record["fence_digest"]):
        raise RecoveryError("The source belongs to a different durable recovery fence")


@contextmanager
def _control(profile, record=None):
    """The only post-fence control path: fixed old namespace + fixed row key."""
    from .postgres import Connection
    with closing(_pg_connect(profile, "metadata")) as connection:
        try:
            with connection:
                connection.execute("SET LOCAL statement_timeout='15s'")
                connection.execute("SET LOCAL lock_timeout='5s'")
                connection.execute("SELECT pg_advisory_xact_lock(%s)", (CONTROL_LOCK,))
                wrapper = Connection(connection)
                current = Store._get(wrapper, "maintenance_settings", CONTROL_ID)
                _source_marker(_raw_marker(connection), profile, "metadata", record or current)
                if record and (not current or current["recovery_id"] != record["recovery_id"]):
                    raise RecoveryError("Recovery control identity changed; automatic execution is refused")
                yield wrapper, current
        except RecoveryError:
            raise
        except Exception:
            raise RecoveryError("The bounded shared recovery transaction could not be verified") from None


def _control_put(db, record):
    record["updated_at"] = stamp()
    Store._put(db, "maintenance_settings", record)


def _fence_postgres(profile, record):
    from .postgres import Connection, PostgresStore
    with closing(_pg_connect(profile, "metadata")) as metadata, closing(_pg_connect(profile, "traffic")) as traffic:
        for connection, namespace, key in ((metadata, "metadata", PostgresStore.META_LOCK), (traffic, "traffic", PostgresStore.TRAFFIC_LOCK)):
            connection.execute("SET LOCAL statement_timeout='15s'")
            connection.execute("SET LOCAL lock_timeout='5s'")
            connection.execute("SELECT pg_advisory_xact_lock(%s)", (key,))
            if namespace == "metadata":
                _current_super_proof(Connection(connection), record)
                proxy = Store.__new__(Store)
                proxy.ha = True
                controllers, voters, _ = _members(proxy, Connection(connection), record["source_node"], profile)
                if digest({"controllers": controllers, "voters": voters}) != record["source"]["membership_digest"]:
                    raise RecoveryError("Registered controller membership changed after recovery review")
            marker = _raw_marker(connection)
            _source_marker(marker, profile, namespace, record)
            marker.update(state="FENCED_RECOVERY", recovery_id=record["recovery_id"], recovery_fence_digest=record["fence_digest"])
            connection.execute("UPDATE runtime_deployment SET data=%s WHERE id='active'", (json.dumps(marker, sort_keys=True),))
        # A crash between commits is a partial fence, never a release. The
        # same recovery can complete it, and no child drain is ACKed early.
        traffic.commit()
        metadata.commit()
    _verify_source_fences(profile, record)


def _verify_source_fences(profile, record):
    for namespace in ("metadata", "traffic"):
        with closing(_pg_connect(profile, namespace)) as db:
            marker = _raw_marker(db)
            _source_marker(marker, profile, namespace, record)
            if marker.get("state") != "FENCED_RECOVERY":
                raise RecoveryError("Both original namespace writer fences must be durable before drain or restore")


def _cancel_queued_source(profile, record):
    """Undo only this untouched pre-drain fence; never rewind an import."""
    from .postgres import PostgresStore
    if record.get("phase") != "queued" or record.get("acks") or record.get("actions"):
        return False
    with closing(_pg_connect(profile, "metadata")) as metadata, closing(_pg_connect(profile, "traffic")) as traffic:
        for connection, namespace, key in ((metadata, "metadata", PostgresStore.META_LOCK), (traffic, "traffic", PostgresStore.TRAFFIC_LOCK)):
            connection.execute("SET LOCAL lock_timeout='5s'")
            connection.execute("SELECT pg_advisory_xact_lock(%s)", (key,))
            marker = _raw_marker(connection)
            _source_marker(marker, profile, namespace, record)
            marker["state"] = "READY"
            marker.pop("recovery_id", None)
            marker.pop("recovery_fence_digest", None)
            connection.execute("UPDATE runtime_deployment SET data=%s WHERE id='active'", (json.dumps(marker, sort_keys=True),))
        traffic.commit()
        metadata.commit()
    return True


def _candidate_profile(profile, record):
    from psycopg.conninfo import conninfo_to_dict, make_conninfo
    result = copy.deepcopy(profile)
    for namespace in ("metadata", "traffic"):
        values = conninfo_to_dict(profile[namespace + "_dsn"])
        values["dbname"] = "prthak_restore_" + record["recovery_id"] + "_" + namespace
        result[namespace + "_dsn"] = make_conninfo(**values)
    result.update(epoch=record["target_epoch"], active_revision=profile["active_revision"] + 1)
    if isinstance(result.get("spec", {}).get("database"), dict):
        result["spec"]["database"].update({namespace: "prthak_restore_" + record["recovery_id"] + "_" + namespace for namespace in ("metadata", "traffic")})
    result["recovery_id"] = record["recovery_id"]
    return result


def _current_super_proof(db, record):
    proxy = Store.__new__(Store)
    if not approvals.authorized(proxy, db, record["approval_proof"], plan_id=record["recovery_id"], plan_digest=record["plan_digest"]):
        raise RecoveryError("The exact administrative recovery authorization is no longer valid")
    for subject in (record["approval_proof"]["requester"], record["approval_proof"]["approved_by"]):
        user = Store._get(db, "auth_users", subject["user_id"])
        if not user or user.get("enabled") is not True or user.get("role") != "super_admin":
            raise RecoveryError("The recovery decision maker must remain an enabled Super Admin")


def _pg_local(manager, profile, record):
    work = _directory(manager, record["recovery_id"])
    private = _read_json(work / "node.json")
    if not private:
        context = _private_context(manager, profile)
        private = {"source_profile_ref": manager.vault.put(json.dumps(profile, sort_keys=True)), "context": context, "writer_nonce": secrets.token_hex(32)}
        atomic_private_json(work / "node.json", private)
    atomic_private_json(manager.root / LOCAL_FENCE, {"backend": "postgresql", "recovery_id": record["recovery_id"], "source_profile_ref": private["source_profile_ref"], "fence_digest": record["fence_digest"]})
    return private


def _tool(manager, name):
    class Tools:
        pass
    tools = Tools()
    app = getattr(manager, "app", None)
    configured = getattr(manager, "recovery_programs", {})
    value = configured.get(name) or (getattr(app.store, name + "_path", None) if app else None)
    if value:
        setattr(tools, name + "_path", value)
    return maintenance._program(tools, name)


def _pg_original(manager, profile, record, work):
    """Independent rollback pair + safety catalogue after both writer fences."""
    _verify_source_fences(profile, record)
    original = work / "original"
    original.mkdir(mode=0o700, exist_ok=True)
    proof = _read_json(original / "manifest.json")
    if proof:
        for item in proof["members"]:
            if maintenance._sha(original / item["name"], time.monotonic() + 30) != item["sha256"]:
                raise RecoveryError("The original PostgreSQL rollback snapshot changed")
        return proof
    deadline = time.monotonic() + 420
    members = []
    for namespace in ("metadata", "traffic"):
        path = original / (namespace + ".dump")
        environment = maintenance._pg_environment(profile[namespace + "_dsn"])
        try:
            maintenance._bounded_command([_tool(manager, "pg_dump"), "--format=custom", "--no-owner", "--no-privileges", "--no-password"], environment, path, deadline)
        finally:
            environment.clear()
        path.chmod(0o600)
        members.append({"name": path.name, "sha256": maintenance._sha(path, deadline), "size_bytes": path.stat().st_size})
    from .postgres import Connection
    with closing(_pg_connect(profile, "metadata")) as db:
        safety = _safety(Connection(db))
    atomic_private_json(work / "safety.json", safety)
    proof = {"members": members, "safety_digest": digest(safety), "created_at": stamp()}
    atomic_private_json(original / "manifest.json", proof)
    return proof


def _filtered_catalogue(manager, archive, destination, namespace):
    output = destination.with_suffix(".all")
    maintenance._bounded_command([_tool(manager, "pg_restore"), "--list", str(archive)], {key: os.environ[key] for key in ("PATH", "LANG", "LC_ALL") if key in os.environ}, output, time.monotonic() + 30)
    # Exclude only the old runtime identity table. Its replacement IMPORTING
    # marker is installed before restore and survives the transactional import.
    lines = []
    allowed_tables = set(META_TABLES if namespace == "metadata" else TRAFFIC_TABLES)
    for line in output.read_text().splitlines():
        if not line or line.startswith(";"):
            lines.append(line)
            continue
        match = re.match(r"\d+;\s+\d+\s+\d+\s+(.+)", line)
        if not match:
            raise RecoveryError("The PostgreSQL archive catalogue is not recognized")
        entry = match[1]
        if re.search(r"(?:TABLE(?: DATA)? public runtime_deployment(?: |$)|CONSTRAINT public runtime_deployment )", entry):
            continue
        if re.search(r"\b(FUNCTION|PROCEDURE|TRIGGER|EVENT TRIGGER|FOREIGN|SERVER|PUBLICATION|SUBSCRIPTION|POLICY|SECURITY LABEL)\b", entry):
            raise RecoveryError("The archive contains executable or external schema objects outside the supported controller schema")
        if "EXTENSION" in entry and not re.search(r"\bplpgsql(?: |$)", entry):
            raise RecoveryError("External PostgreSQL extensions are outside the supported recovery schema")
        table = re.match(r"(?:TABLE(?: DATA)?|CONSTRAINT|FK CONSTRAINT) public ([a-z_][a-z0-9_]*)\b", entry)
        if table and table[1] not in allowed_tables:
            raise RecoveryError("The PostgreSQL archive contains an unknown controller table")
        lines.append(line)
    destination.write_text("\n".join(lines) + "\n")
    destination.chmod(0o600)


def _restore_namespace(manager, profile, record, namespace, archive, member, work):
    from .postgres import Connection
    with closing(_pg_connect(profile, namespace)) as connection:
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (CONTROL_LOCK,))
        connection.execute("SET LOCAL statement_timeout='15s'")
        tables = {row[0] for row in connection.execute("SELECT tablename FROM pg_tables WHERE schemaname='public'").fetchall()}
        marker = _raw_marker(connection) if "runtime_deployment" in tables else None
        if marker:
            if any(marker.get(key) != value for key, value in {"deployment_id": profile["deployment_id"], "epoch": profile["epoch"], "namespace": namespace, "import_id": record["recovery_id"], "archive_sha256": record["archive_sha256"]}.items()):
                raise RecoveryError("Candidate identity belongs to another import; overwrite is refused")
            if marker.get("archive_restored") is True:
                return
            if marker.get("state") != "IMPORTING":
                raise RecoveryError("An unrecognized candidate import state cannot be resumed")
        elif tables:
            raise RecoveryError("A nonempty candidate without this exact owned import marker is refused")
        else:
            marker = {"deployment_id": profile["deployment_id"], "epoch": profile["epoch"], "namespace": namespace, "import_id": record["recovery_id"], "source_fingerprint": record["fence_digest"], "state": "IMPORTING", "archive_sha256": record["archive_sha256"]}
            connection.execute("CREATE TABLE runtime_deployment(id TEXT PRIMARY KEY,data TEXT NOT NULL)")
            connection.execute("INSERT INTO runtime_deployment(id,data) VALUES('active',%s)", (json.dumps(marker, sort_keys=True),))
        connection.commit()
    # A completed single-transaction restore followed by a process crash can
    # be recognized without executing its DDL a second time.
    with closing(_pg_connect(profile, namespace)) as connection:
        description = maintenance._pg_description(Connection(connection))
    imported = description == {"schema_digest": member["schema_digest"], "tables": member["tables"]}
    if imported:
        with closing(_pg_connect(profile, namespace)) as connection:
            actual_hashes = maintenance._pg_data_hashes(Connection(connection), description["tables"])
        if actual_hashes != member["data_hashes"]:
            raise RecoveryError("An uncertain restored component has different canonical data; adoption is refused")
    if not imported:
        if description["tables"] != {"runtime_deployment": 1}:
            raise RecoveryError("An interrupted candidate differs from both empty and the verified archive catalogue")
        catalogue = work / (namespace + ".toc")
        _filtered_catalogue(manager, archive, catalogue, namespace)
        environment = maintenance._pg_environment(profile[namespace + "_dsn"])
        try:
            maintenance._bounded_command([_tool(manager, "pg_restore"), "--dbname", "prthak_restore_" + record["recovery_id"] + "_" + namespace, "--no-owner", "--no-privileges", "--single-transaction", "--exit-on-error", "--no-password", "--use-list", str(catalogue), str(archive)], environment, work / (namespace + "-restore.log"), time.monotonic() + 180)
        finally:
            environment.clear()
        with closing(_pg_connect(profile, namespace)) as connection:
            description = maintenance._pg_description(Connection(connection))
        if description != {"schema_digest": member["schema_digest"], "tables": member["tables"]}:
            raise RecoveryError("Restored namespace schema/counts differ from its immutable backup manifest")
        with closing(_pg_connect(profile, namespace)) as connection:
            if maintenance._pg_data_hashes(Connection(connection), description["tables"]) != member["data_hashes"]:
                raise RecoveryError("Restored namespace canonical content differs from its immutable archive")
    with closing(_pg_connect(profile, namespace)) as connection:
        marker = _raw_marker(connection)
        marker["archive_restored"] = True
        connection.execute("UPDATE runtime_deployment SET data=%s WHERE id='active'", (json.dumps(marker, sort_keys=True),))
        connection.commit()


def _namespace_proof(connection, namespace):
    tables = META_TABLES if namespace == "metadata" else TRAFFIC_TABLES
    description = maintenance._pg_description(connection, canonical_hashes=True)
    if set(description["tables"]) != set(tables) | {"runtime_deployment"}:
        raise RecoveryError("Candidate contains an incomplete or unexpected fixed controller schema")
    return {"counts": {table: description["tables"][table] for table in tables}, "hashes": {table: description["data_hashes"][table] for table in tables}}


def _import_postgres(manager, source, record, private):
    from .postgres import Connection, PostgresStore
    work = _directory(manager, record["recovery_id"])
    original = _pg_original(manager, source, record, work)
    _save_material(manager, work, private["context"])
    with _control(source, record) as (db, _):
        backup = Store._get(db, "maintenance_backups", record["backup_id"])
    if not backup or backup.get("archive_sha256") != record["archive_sha256"]:
        raise RecoveryError("The selected source archive no longer matches its reviewed immutable record")
    extracted = work / "archive"
    if extracted.exists():
        shutil.rmtree(extracted)
    extracted.mkdir(mode=0o700)
    maintenance._inspect_record(backup, manager.root / "backups" / (record["backup_id"] + ".zip"), extracted)
    target = _candidate_profile(source, record)
    for namespace in ("metadata", "traffic"):
        member = next(value for value in backup["members"] if value["kind"] == namespace)
        _restore_namespace(manager, target, record, namespace, extracted / member["name"], member, work)
    context = {"deployment_id": target["deployment_id"], "epoch": target["epoch"], "import_id": record["recovery_id"], "source_fingerprint": record["fence_digest"]}
    candidate = PostgresStore(target["metadata_dsn"], target["traffic_dsn"], _migration_context=context)
    safety = _read_json(work / "safety.json")
    if digest(safety) != original["safety_digest"]:
        raise RecoveryError("The captured current safety ledger changed; recovery is refused")
    with candidate.meta() as db:
        marker = Store._get(db, "runtime_deployment", "active")
        if marker.get("safety_applied") is not True:
            _overlay_safety(db, safety, record["recovery_id"])
            config = Store._get(db, "maintenance_settings", "appliance_cluster")
            if not config or config.get("deployment_id") != target["deployment_id"]:
                raise RecoveryError("Restored appliance authority does not match the current deployment")
            config.update(database={namespace: "prthak_restore_" + record["recovery_id"] + "_" + namespace for namespace in ("metadata", "traffic")}, epoch=target["epoch"], revision=config.get("revision", 0) + 1)
            Store._put(db, "maintenance_settings", config)
            candidate.compile_all(db)
            marker["safety_applied"] = True
            db.execute("UPDATE runtime_deployment SET data=? WHERE id='active'", (json.dumps(marker, sort_keys=True),))
    candidate.initialize_schema()
    proofs = {}
    for namespace in ("metadata", "traffic"):
        with closing(_pg_connect(target, namespace)) as connection:
            proofs[namespace] = _namespace_proof(Connection(connection), namespace)
    fingerprint = digest({"namespaces": proofs, "archive_sha256": record["archive_sha256"], "safety_digest": original["safety_digest"]})
    for namespace in ("metadata", "traffic"):
        with closing(_pg_connect(target, namespace)) as connection:
            marker = _raw_marker(connection)
            marker.update(state="VERIFIED", source_fingerprint=fingerprint, proof=proofs[namespace])
            connection.execute("UPDATE runtime_deployment SET data=%s WHERE id='active'", (json.dumps(marker, sort_keys=True),))
            connection.commit()
    return {"source_fingerprint": fingerprint, "proofs": proofs, "original_snapshot_preserved": True, "protected_material_preserved": True}


def _ack(record, phase, node, value=True):
    record.setdefault("acks", {}).setdefault(phase, {})[node] = {"at": stamp(), "value": value}
    record.setdefault("errors", {}).pop(node, None)
    record.setdefault("retry_state", {}).pop(node, None)


def _all(record, phase, voters=False):
    expected = {value["id"] for value in record["voters"]} if voters else set(record["controller_ids"])
    return expected <= set(record.get("acks", {}).get(phase, {}))


def _host_action(manager, record, phase, node, client):
    from .replication_rotation import _health
    state = client.status()
    if phase == "create" and _health(state, record["voters"]) != node:
        return None
    key = node + ":" + phase
    action = record.setdefault("actions", {}).get(key)
    if not action:
        action = {"request_id": digest({"recovery": record["recovery_id"], "node": node, "phase": phase, "attempt": 0})[:32], "attempt": 0, "expected_revision": state.get("revision"), "status": "pending"}
        record["actions"][key] = action
    if action["status"] == "acknowledged":
        return action
    if action["status"] in ("blocked", "error", "failed", "not_primary"):
        delay = min(60, 5 * 2 ** min(action["attempt"], 4))
        if parse_time(action.get("updated_at", stamp())) + timedelta(seconds=delay) > now():
            return action
        action.update(attempt=action["attempt"] + 1, expected_revision=state.get("revision"), status="pending")
        action["request_id"] = digest({"recovery": record["recovery_id"], "node": node, "phase": phase, "attempt": action["attempt"]})[:32]
    return action


def _perform_host(manager, source, record, phase, node, client):
    with _control(source, record) as (db, current):
        action = _host_action(manager, current, phase, node, client)
        if not action or action.get("status") != "pending":
            _control_put(db, current)
            return
        _control_put(db, current)
        request = {"action": "restore-databases", "restore_id": current["recovery_id"], "phase": phase, "request_id": action["request_id"], "expected_revision": action["expected_revision"], "deployment_id": source["deployment_id"], "archive_sha256": current["archive_sha256"], "target_epoch": current["target_epoch"], "fence_digest": current["fence_digest"], "all_writers_fenced": True}
        if phase == "finalize":
            request["all_profile_acks"] = _all(current, "profile")
    try:
        try:
            result = client.job(action["request_id"])
        except KeyError:
            result = client.submit(request)
    except Exception:
        result = {"status": "unknown"}
    with _control(source, record) as (db, current):
        entry = current["actions"].get(node + ":" + phase, {})
        if entry.get("request_id") != action["request_id"]:
            return
        actual = result.get("result", {})
        from psycopg.conninfo import conninfo_to_dict
        expected_binding = digest({"restore_id": current["recovery_id"], "deployment_id": source["deployment_id"], "archive_sha256": current["archive_sha256"], "target_epoch": current["target_epoch"], "fence_digest": current["fence_digest"], "source_databases": {namespace: conninfo_to_dict(source[namespace + "_dsn"])["dbname"] for namespace in ("metadata", "traffic")}})
        flag = {"prepare": "prepared", "create": "created", "verify": "verified", "finalize": "finalized"}[phase]
        expected_phase = {"prepare": "prepared", "create": "created", "verify": "verified", "finalize": "finalized"}[phase]
        accepted = result.get("status") in ("completed", "succeeded", "applied") and actual.get(flag) is True and actual.get("phase") == expected_phase and actual.get("binding_digest") == expected_binding and actual.get("database_names") == {namespace: "prthak_restore_" + record["recovery_id"] + "_" + namespace for namespace in ("metadata", "traffic")}
        if phase == "create":
            accepted = accepted and actual.get("empty") is True and actual.get("owners_verified") is True
        if phase == "verify":
            accepted = accepted and actual.get("new_connections") is True and actual.get("marker_verified") is True
        if accepted:
            entry["status"] = "acknowledged"
            _ack(current, phase, node, {"binding_digest": actual.get("binding_digest"), "revision": actual.get("revision")})
        elif result.get("status") not in ("queued", "running", "unknown"):
            entry.update(status="not_primary" if actual.get("not_primary") else "blocked", updated_at=stamp())
            current.setdefault("errors", {})[node] = "The fixed host recovery phase was not independently verified; original databases remain fenced and preserved"
        _control_put(db, current)


def _release_markers(target, record):
    from .postgres import Connection
    actual = {}
    for namespace in ("metadata", "traffic"):
        with closing(_pg_connect(target, namespace)) as connection:
            marker = _raw_marker(connection)
            if marker.get("state") not in ("VERIFIED", "READY") or marker.get("import_id") != record["recovery_id"] or marker.get("source_fingerprint") != record["import_result"]["source_fingerprint"]:
                raise RecoveryError("Candidate namespace binding changed before release")
            actual[namespace] = _namespace_proof(Connection(connection), namespace)
            if actual[namespace] != record["import_result"]["proofs"][namespace]:
                raise RecoveryError("Candidate data changed before global writer admission")
    for namespace in ("metadata", "traffic"):
        with closing(_pg_connect(target, namespace)) as connection:
            marker = _raw_marker(connection)
            marker["state"] = "READY"
            connection.execute("UPDATE runtime_deployment SET data=%s WHERE id='active'", (json.dumps(marker, sort_keys=True),))
            connection.commit()


def _postgres_tick(supervisor, local, fence, profile):
    manager, node = supervisor.manager, _node(supervisor.manager)
    if fence and fence.get("source_profile_ref"):
        source = json.loads(manager.vault.get(fence["source_profile_ref"]))
    else:
        source = profile
    if not source:
        return bool(fence)
    try:
        with _control(source) as (db, record):
            if not record or record.get("phase") in TERMINAL and not fence:
                return False
            if node not in record.get("controller_ids", []):
                raise RecoveryError("This controller is outside the frozen recovery membership; its old writer remains blocked")
            if record["phase"] == "cancelled":
                _local_save(manager, record)
                (manager.root / LOCAL_FENCE).unlink(missing_ok=True)
                return False
            private = _pg_local(manager, source, record)
            retry = record.get("retry_state", {}).get(node)
            if record["phase"] not in TERMINAL and retry and parse_time(retry["next_attempt_at"]) > now():
                return True
            if record["phase"] == "queued" and node == record["source_node"]:
                _current_super_proof(db, record)
                reviewed = _read_json(_directory(manager, record["recovery_id"]) / "context.json")
                if not reviewed or not _context_matches(manager, source, reviewed):
                    raise RecoveryError("Source PKI, Vault or active profile changed after review")
                backup = Store._get(db, "maintenance_backups", record["backup_id"])
                if not backup or backup.get("archive_sha256") != record["archive_sha256"]:
                    raise RecoveryError("Selected source archive differs from its immutable review")
                maintenance._inspect_record(backup, manager.root / "backups" / (record["backup_id"] + ".zip"))
                _fence_postgres(source, record)
                record["phase"] = "draining"
                _control_put(db, record)
        # All remaining phases operate only after independently verifying both
        # source guards, even if a prior coordinator died between commits.
        if record["phase"] == "queued":
            return True
        _verify_source_fences(source, record)
        work = _directory(manager, record["recovery_id"])
        if record["phase"] not in ("activating", "finalizing", "completed"):
            _drain(supervisor)
        if record["phase"] == "draining":
            _save_material(manager, work, private["context"])
            with _control(source, record) as (db, current):
                _ack(current, "drained", node, private["context"]["digest"])
                if _all(current, "drained"):
                    current["phase"] = "preparing"
                _control_put(db, current)
        from .appliance import NodeClient
        client = getattr(manager, "recovery_client", None) or NodeClient()
        voter = node in {value["id"] for value in record["voters"]}
        with _control(source, record) as (_, record):
            record = copy.deepcopy(record)
        if record["phase"] == "preparing" and voter:
            _perform_host(manager, source, record, "prepare", node, client)
        elif record["phase"] == "creating" and voter:
            _perform_host(manager, source, record, "create", node, client)
        elif record["phase"] == "restoring" and node == record["source_node"]:
            with _control(source, record) as (db, current):
                lease = current.get("import_lease", {})
                allowed = not lease or lease.get("owner") == _OWNER or parse_time(lease["until"]) <= now()
                if allowed:
                    current["import_lease"] = {"owner": _OWNER, "until": stamp(now() + timedelta(minutes=15))}
                    _control_put(db, current)
            if allowed:
                imported = _import_postgres(manager, source, record, private)
                with _control(source, record) as (db, current):
                    current.update(import_result=imported, phase="verifying")
                    current.setdefault("errors", {}).pop(node, None)
                    current.setdefault("retry_state", {}).pop(node, None)
                    _control_put(db, current)
        elif record["phase"] == "verifying" and voter:
            _perform_host(manager, source, record, "verify", node, client)
        elif record["phase"] == "profiles":
            target = _candidate_profile(source, record)
            if not private.get("candidate_profile_ref"):
                private["candidate_profile_ref"] = manager.vault.put(json.dumps(target, sort_keys=True))
                atomic_private_json(work / "node.json", private)
            with _control(source, record) as (db, current):
                _ack(current, "profile", node, digest(target))
                _control_put(db, current)
        elif record["phase"] in ("activating", "finalizing"):
            target = json.loads(manager.vault.get(private["candidate_profile_ref"]))
            local_record = {**record, "phase": "starting", "writer_nonce": private["writer_nonce"], "released_profile_digest": digest(target)}
            _local_save(manager, local_record)
            if manager.active_profile() != target:
                _drain(supervisor)
                manager.commit_active_profile(target)
            arguments = _start(supervisor, target) if supervisor.child is None else supervisor.arguments
            if not _wait_ready(supervisor, arguments, target, private["writer_nonce"]):
                _drain(supervisor)
                raise RecoveryError("The exact candidate child failed private readiness; public writer admission remains blocked")
            with _control(source, record) as (db, current):
                _ack(current, "ready", node, digest(target))
                _control_put(db, current)
            if record["phase"] == "finalizing" and voter:
                _perform_host(manager, source, record, "finalize", node, client)
        with _control(source, record) as (db, current):
            if current["phase"] == "preparing" and _all(current, "prepare", voters=True):
                current["phase"] = "creating"
            if current["phase"] == "creating" and current.get("acks", {}).get("create"):
                current["phase"] = "restoring"
            if current["phase"] == "verifying" and _all(current, "verify", voters=True):
                current["phase"] = "profiles"
            if current["phase"] == "profiles" and _all(current, "profile"):
                target = _candidate_profile(source, current)
                _release_markers(target, current)
                current["phase"] = "activating"
            if current["phase"] == "activating" and _all(current, "ready"):
                current["phase"] = "finalizing"
            if current["phase"] == "finalizing" and _all(current, "finalize", voters=True):
                current.update(phase="completed", status="applied", completed_at=stamp(), errors={}, result={"verified": True, "backend": "postgresql", "target_epoch": current["target_epoch"], "original_databases_preserved": True, "protected_material_preserved": True, "all_controller_profiles_verified": True, "requires_fresh_authority": True})
            _control_put(db, current)
            record = copy.deepcopy(current)
        if record["phase"] == "completed":
            from .postgres import Connection
            with closing(_pg_connect(manager.active_profile(), "metadata")) as candidate:
                _record_completion(Connection(candidate), record)
                candidate.commit()
            _local_save(manager, {**record, "released_profile_digest": digest(manager.active_profile())})
            (manager.root / LOCAL_FENCE).unlink(missing_ok=True)
            return False
        _local_save(manager, record)
        return True
    except Exception as error:
        message = str(error) if isinstance(error, (RecoveryError, maintenance.MaintenanceError)) else "Shared recovery could not be verified; original databases and the durable writer fences are preserved"
        try:
            with _control(source) as (db, current):
                if current:
                    current.setdefault("errors", {})[node or "local"] = message
                    if node == current["source_node"] and _cancel_queued_source(source, current):
                        current.update(phase="cancelled", status="blocked")
                    else:
                        previous = current.setdefault("retry_state", {}).get(node or "local", {})
                        attempt = previous.get("attempt", 0) + 1
                        current["retry_state"][node or "local"] = {"attempt": attempt, "next_attempt_at": stamp(now() + timedelta(seconds=min(60, 5 * 2 ** min(attempt - 1, 4))))}
                    _control_put(db, current)
                    _local_save(manager, current)
                    if current["phase"] == "cancelled":
                        (manager.root / LOCAL_FENCE).unlink(missing_ok=True)
                        return False
        except Exception:
            pass
        return True
