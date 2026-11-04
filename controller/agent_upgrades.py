"""Review and publish exact signed upgrade intent for enrolled endpoints."""
from __future__ import annotations

from collections import Counter
from contextlib import contextmanager
from datetime import timedelta
import json
import re
import uuid

from . import agent_release_downloads as releases
from .firewall import WorkflowConflict
from .inventory_views import server_rows
from .locations import reserved, selector as normalize_selector
from .store import digest, matches, now, stamp, validate_tags

CAPABILITY = "agent_pull_upgrade_v1"
IDENTIFIER = re.compile(r"[a-f0-9]{32}")
VERSION = re.compile(r"(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})")
ROLLOUTS = "agent_upgrade_rollouts"
PENDING = ("queued", "staging", "upgrading")
REPORT_STATES = frozenset(("staging", "upgrading", "applied", "blocked", "rolled_back", "error"))
MAX_TARGETS = 20000


def initialize(db):
    db.execute("CREATE TABLE IF NOT EXISTS agent_upgrade_rollouts (id TEXT PRIMARY KEY, data TEXT NOT NULL)")
    db.execute("""
        CREATE TABLE IF NOT EXISTS agent_upgrade_targets (
            id TEXT PRIMARY KEY,
            rollout_id TEXT NOT NULL, server_id TEXT NOT NULL,
            expires_at TEXT NOT NULL, status TEXT NOT NULL, data TEXT NOT NULL,
            UNIQUE (rollout_id, server_id)
        )
    """)
    db.execute("""
        CREATE INDEX IF NOT EXISTS agent_upgrade_target_lookup
            ON agent_upgrade_targets(server_id, expires_at, status)
    """)


def _version(value):
    match = VERSION.fullmatch(value) if isinstance(value, str) else None
    return tuple(map(int, match.groups())) if match else None


def _valid_id(value):
    return isinstance(value, str) and IDENTIFIER.fullmatch(value) is not None


def _require_super(app, db, principal):
    if not app.platform or app.demo or principal.get("role") != "super_admin" or principal.get("auth_type") != "session":
        raise PermissionError("An installed controller and a Super Admin session are required to upgrade agents")
    app.auth._require_super(principal, db)


@contextmanager
def _writer(store):
    with store.lock, store.meta() as db:
        if getattr(db, "dialect", "sqlite") == "sqlite":
            db.execute("BEGIN IMMEDIATE")
        yield db


def _scope(store, db, value, servers):
    all_selected = value.get("all", False)
    if not isinstance(all_selected, bool):
        raise ValueError("Select a rollout scope")
    server_ids = value.get("server_ids", [])
    group_ids = value.get("group_ids", [])
    for items in (server_ids, group_ids):
        if not isinstance(items, list) or len(items) > MAX_TARGETS or any(
                not isinstance(item, str) or not item or len(item) > 100 for item in items):
            raise ValueError("Choose existing endpoints or groups")
    selector = validate_tags(value.get("selector", {}))
    if sum(map(bool, (all_selected, server_ids, group_ids, selector))) != 1:
        raise ValueError("Choose exactly one fleet, endpoint, group, tag or saved location scope")
    if all_selected:
        return servers
    if server_ids:
        ids = set(server_ids)
        if ids - {server["id"] for server in servers}:
            raise ValueError("Choose existing endpoints")
        return [server for server in servers if server["id"] in ids]
    locations = store._all(db, "locations")
    if group_ids:
        groups = {group["id"]: group for group in store._all(db, "groups")}
        if set(group_ids) - groups.keys():
            raise ValueError("Choose existing groups")
        ids = set().union(*(store._group_members(groups[identifier], servers, locations) for identifier in set(group_ids)))
        return [server for server in servers if server["id"] in ids]
    selector = normalize_selector(selector, locations)
    return [server for server in servers if matches(
        {**{key: value for key, value in server.get("tags", {}).items() if not reserved(key)},
         "location_id": server.get("location_id")}, selector)]


def _active(db, server_id, at):
    row = db.execute(
        "SELECT data FROM agent_upgrade_targets WHERE server_id=? AND expires_at>? "
        "AND status IN ('queued','staging','upgrading') ORDER BY expires_at DESC LIMIT 1",
        (server_id, at),
    ).fetchone()
    return json.loads(row[0]) if row else None


def _busy_endpoints(db, at):
    return {row[0] for row in db.execute(
        "SELECT server_id FROM agent_upgrade_targets WHERE expires_at>? AND status IN ('queued','staging','upgrading')",
        (at,),
    )}


def _bindings(server):
    return {
        "server_id": server["id"],
        "hostname": server["hostname"],
        "previous_version": server.get("agent_version", ""),
        "architecture": server.get("agent_architecture", ""),
    }


def _unavailable(server, version, assets):
    current = _version(server.get("agent_version"))
    if server.get("synthetic") or CAPABILITY not in server.get("capabilities", []) or current is None:
        return "Install the updater-enabled agent once on this endpoint"
    if _version(version) <= current:
        return "The selected version is not newer than the installed agent"
    if server.get("agent_architecture") not in assets:
        return "The selected release has no signed package for this architecture"
    return None


def _rows(db, identifier, at):
    for row in db.execute("SELECT data, status, expires_at FROM agent_upgrade_targets WHERE rollout_id=? ORDER BY server_id", (identifier,)):
        target = json.loads(row[0])
        target.pop("assignment", None)
        target["status"] = "expired" if row[1] in PENDING and row[2] <= at else row[1]
        yield target


def _counts(db, identifier, at):
    counts = Counter()
    for row in db.execute(
        "SELECT status, expires_at, COUNT(*) FROM agent_upgrade_targets WHERE rollout_id=? GROUP BY status,expires_at",
        (identifier,),
    ):
        status, expiry, count = row[0], row[1], row[2]
        counts["expired" if status in PENDING and expiry <= at else status] += count
    return dict(counts)


def _public(db, record, *, detailed):
    at = stamp()
    status = record["status"]
    targets = record["scope"]["targets"]
    outcomes = {}
    if status == "reviewed":
        if record["expires_at"] <= at:
            status = "expired"
    else:
        outcomes = _counts(db, record["id"], at)
        if detailed:
            targets = list(_rows(db, record["id"], at))
        if status == "active" and not any(outcomes.get(value) for value in PENDING):
            status = "expired" if outcomes.get("expired") else "completed"
    public = {key: record[key] for key in ("id", "version", "created_at", "expires_at", "target_count")}
    public.update(status=status, outcomes=outcomes)
    if "confirmed_at" in record:
        public["confirmed_at"] = record["confirmed_at"]
    if detailed:
        public.update(
            digest=record["digest"],
            targets=targets,
            exclusions=record["exclusions"],
            can_apply=status == "reviewed" and bool(targets),
        )
    return public


def listing(app, principal):
    with app.store.read_meta() as db:
        _require_super(app, db, principal)
        inventory = sorted(server_rows(db), key=lambda server: (server["hostname"].casefold(), server["id"]))
        confirmed = "data::jsonb->>'confirmed_at'" if getattr(db, "dialect", "sqlite") == "postgresql" else "json_extract(data,'$.confirmed_at')"
        rollouts = [json.loads(row[0]) for row in db.execute(
            f"SELECT data FROM {ROLLOUTS} WHERE ({confirmed}) IS NOT NULL ORDER BY ({confirmed}) DESC,id DESC LIMIT 20"
        )]
        return {
            "capability": CAPABILITY,
            "releases": releases.available_versions(),
            "servers": [
                {
                    "id": server["id"],
                    "hostname": server["hostname"],
                    "agent_version": server.get("agent_version", ""),
                    "agent_architecture": server.get("agent_architecture", ""),
                    "supported": CAPABILITY in server.get("capabilities", []) and not server.get("synthetic", False),
                }
                for server in inventory
            ],
            "rollouts": [_public(db, rollout, detailed=False) for rollout in rollouts],
        }


def detail(app, identifier, principal):
    if not _valid_id(identifier):
        raise KeyError(identifier)
    with app.store.read_meta() as db:
        _require_super(app, db, principal)
        record = app.store._get(db, ROLLOUTS, identifier)
        if not record:
            raise KeyError(identifier)
        return _public(db, record, detailed=True)


def _assets(version, *, verify=False):
    return next((row["architectures"] for row in releases.available_versions(verify=verify, version=version)), {})


def preview(app, value, principal):
    if not isinstance(value, dict) or set(value) - {"version", "server_ids", "group_ids", "selector", "all"}:
        raise ValueError("Choose a signed agent release and an endpoint scope")
    version = value.get("version")
    if _version(version) is None:
        raise ValueError("Choose an available signed agent release")
    with app.store.read_meta() as db:
        _require_super(app, db, principal)
    assets = _assets(version, verify=True)
    if not assets:
        raise ValueError("The selected signed agent release is unavailable")
    with _writer(app.store) as db:
        _require_super(app, db, principal)
        servers = _scope(app.store, db, value, list(server_rows(db)))
        if len(servers) > MAX_TARGETS:
            raise ValueError("Use a rollout scope with at most 20000 endpoints")
        at = now()
        created = stamp(at)
        busy = _busy_endpoints(db, created)
        targets, exclusions = [], []
        for server in sorted(servers, key=lambda item: item["id"]):
            target = _bindings(server)
            reason = _unavailable(server, version, assets)
            if not reason and server["id"] in busy:
                reason = "An agent rollout is already active for this endpoint"
            if reason:
                exclusions.append({**target, "reason": reason})
            else:
                targets.append({**target, "status": "queued"})
        scope = {"version": version, "assets": assets, "targets": targets}
        identifier = uuid.uuid4().hex
        record = {
            "id": identifier,
            "version": version,
            "scope": scope,
            "digest": digest(scope),
            "status": "reviewed",
            "created_at": created,
            "created_by": principal["actor"],
            "expires_at": stamp(at + timedelta(minutes=15)),
            "target_count": len(targets),
            "exclusions": exclusions,
        }
        app.store._put(db, ROLLOUTS, record)
        app.store.audit("agent_upgrade.preview", principal["actor"], {
            "rollout_id": identifier, "version": version, "target_count": len(targets), "digest": record["digest"],
        }, db)
        return _public(db, record, detailed=True)


def confirm(app, identifier, value, principal):
    if not _valid_id(identifier):
        raise KeyError(identifier)
    if not isinstance(value, dict) or set(value) != {"digest"}:
        raise ValueError("Confirm the exact reviewed rollout")
    with app.store.read_meta() as db:
        _require_super(app, db, principal)
        record = app.store._get(db, ROLLOUTS, identifier)
    if not record:
        raise KeyError(identifier)
    assets = _assets(record["version"], verify=True) if record["status"] == "reviewed" else {}
    with _writer(app.store) as db:
        _require_super(app, db, principal)
        record = app.store._get(db, ROLLOUTS, identifier)
        if not record:
            raise KeyError(identifier)
        if principal["actor"] != record["created_by"]:
            raise PermissionError("The Super Admin who created the review must confirm it")
        if value["digest"] != record["digest"]:
            raise WorkflowConflict("Confirm the exact reviewed agent version and target count", {})
        if record["status"] == "active":
            return _public(db, record, detailed=True)
        at = now()
        scope = record["scope"]
        targets = scope["targets"]
        if (record["status"] != "reviewed" or record["expires_at"] <= stamp(at) or
                record["digest"] != digest(scope) or not targets or assets != scope["assets"]):
            raise WorkflowConflict("The rollout review is expired or its signed packages changed. Create a new review.", {})
        servers = {server["id"]: server for server in server_rows(db)}
        busy = _busy_endpoints(db, stamp(at))
        for target in targets:
            server = servers.get(target["server_id"])
            if not server or _unavailable(server, record["version"], assets) or target["server_id"] in busy:
                raise WorkflowConflict("An endpoint's identity, version or rollout changed. Create a new review.", {})
            if any(target[key] != value for key, value in _bindings(server).items()):
                raise WorkflowConflict("An endpoint's identity, version or rollout changed. Create a new review.", {})
        expiry = stamp(at + timedelta(hours=24))
        db.executemany(
            "INSERT INTO agent_upgrade_targets(id,rollout_id,server_id,expires_at,status,data) VALUES(?,?,?,?,?,?)",
            ((identifier + ":" + target["server_id"], identifier, target["server_id"], expiry, "queued", json.dumps({
                **target, "assignment": {
                    "id": identifier, "version": record["version"], "architecture": target["architecture"],
                    **assets[target["architecture"]], "expires_at": expiry,
                },
            })) for target in targets),
        )
        record.update(status="active", expires_at=expiry, confirmed_at=stamp(at))
        app.store._put(db, ROLLOUTS, record)
        app.store.audit("agent_upgrade.confirmed", principal["actor"], {
            "rollout_id": identifier, "version": record["version"], "target_count": len(targets), "digest": record["digest"],
        }, db)
        return _public(db, record, detailed=True)


def assignment(db, server):
    if CAPABILITY not in server.get("capabilities", []) or server.get("synthetic"):
        return None
    target = _active(db, server["id"], stamp())
    if not target or target["architecture"] != server.get("agent_architecture"):
        return None
    desired = target["assignment"]
    if server.get("agent_version") not in (target["previous_version"], desired["version"]):
        return None
    return desired


@contextmanager
def download(app, server_id, identifier, asset):
    if app.demo or not app.platform:
        raise PermissionError("Agent upgrade downloads require an installed controller")
    if not _valid_id(identifier) or asset not in ("archive", "signature"):
        raise KeyError(identifier)
    with app.store.read_meta() as db:
        server = app.store._get(db, "servers", server_id)
        desired = assignment(db, server) if server else None
        if not desired or desired["id"] != identifier:
            raise KeyError(identifier)
    try:
        with releases.open_exact_download(desired["architecture"], desired["version"], asset, desired) as file:
            yield file
    except FileNotFoundError:
        raise KeyError(identifier) from None


def report(store, db, server, value):
    architecture = value.get("agent_architecture", "")
    if not isinstance(architecture, str) or architecture and not re.fullmatch(r"[A-Za-z0-9_]{1,20}", architecture):
        raise ValueError("Invalid endpoint architecture")
    if architecture:
        server["agent_architecture"] = architecture
    else:
        server.pop("agent_architecture", None)
    receipt = value.get("agent_upgrade")
    if receipt is None:
        return
    if not isinstance(receipt, dict) or set(receipt) - {"id", "version", "status", "error"}:
        raise ValueError("Invalid agent upgrade outcome")
    identifier, version, status, error = (receipt.get("id"), receipt.get("version"), receipt.get("status"), receipt.get("error", ""))
    if (not _valid_id(identifier) or _version(version) is None or not isinstance(status, str) or status not in REPORT_STATES or
            not isinstance(error, str) or len(error) > 1000):
        raise ValueError("Invalid agent upgrade outcome")
    row = db.execute("SELECT data,status FROM agent_upgrade_targets WHERE rollout_id=? AND server_id=?",
                     (identifier, server["id"])).fetchone()
    if not row or row[1] not in PENDING or row[1] == status or (row[1] == "upgrading" and status == "staging"):
        return
    target = json.loads(row[0])
    if (version != target["assignment"]["version"] or architecture != target["architecture"] or
            (status == "applied" and server["agent_version"] != version) or
            (status == "rolled_back" and server["agent_version"] != target["previous_version"])):
        return
    target.update(status=status, error=error, reported_at=stamp(), reported_version=server["agent_version"])
    db.execute("UPDATE agent_upgrade_targets SET data=?,status=? WHERE rollout_id=? AND server_id=?",
               (json.dumps(target), status, identifier, server["id"]))
    store.audit("agent_upgrade.reported", "agent:" + server["id"], {
        "rollout_id": identifier, "version": version, "status": status,
    }, db)


def invalidate_after_recovery(store, db):
    for record in store._all(db, ROLLOUTS):
        if record["status"] == "reviewed" or (
                record["status"] == "active" and db.execute(
                    "SELECT 1 FROM agent_upgrade_targets WHERE rollout_id=? AND status IN ('queued','staging','upgrading')",
                    (record["id"],),
                ).fetchone()):
            record["status"] = "revoked"
            store._put(db, ROLLOUTS, record)
    db.execute("UPDATE agent_upgrade_targets SET status='revoked' WHERE status IN ('queued','staging','upgrading')")
