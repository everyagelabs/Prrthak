"""Durable OS-neutral delivery tracking and bounded native traffic evidence.

This module observes an already-authorized bundle. It grants no firewall access,
starts no learning and never promotes generic flow history into rollout proof.
"""
from contextlib import contextmanager
import copy
from datetime import timedelta
import ipaddress
import json
import re
import uuid

from .approval_views import _expression
from .store import digest, now, parse_time, stamp

CAPABILITY = "policy_verification_v1"
MAX_TARGETS = 20000
MAX_PORTS = 64
MAX_RECEIPT_BYTES = 256 * 1024
UPLOAD_GRACE_SECONDS = 120
IDENTIFIER = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
HEX = re.compile(r"[a-f0-9]{64}\Z")
GENERATION = re.compile(r"[a-f0-9]{32}\Z")
ASSIGNMENT_FIELDS = {"schema_version", "id", "deployment_id", "server_id", "version", "digest", "approval_id", "protection_digest", "target_ips_digest", "ports", "starts_at", "expires_at", "window_seconds"}
REPORT_FIELDS = ASSIGNMENT_FIELDS | {"sequence", "state", "applied_generation", "armed_at", "committed_at", "checked_at", "error"}
CASE_STATES = {"awaiting", "verified", "unavailable", "not_applicable", "unverified"}
REPORT_STATES = {"waiting_apply", "observing", "verified", "expired", "unavailable", "superseded", "error"}
ACTIVE_APPLY = {"pending", "applying"}
ACTIVE_TRAFFIC = {"awaiting_apply", "awaiting"}


def initialize(db):
    db.executescript("""
      CREATE TABLE IF NOT EXISTS policy_deployments(id TEXT PRIMARY KEY,created_at TEXT NOT NULL,deadline_at TEXT NOT NULL,data TEXT NOT NULL);
      CREATE INDEX IF NOT EXISTS policy_deployments_created ON policy_deployments(created_at,id);
      CREATE TABLE IF NOT EXISTS policy_deployment_targets(id TEXT PRIMARY KEY,deployment_id TEXT NOT NULL,server_id TEXT NOT NULL,created_at TEXT NOT NULL,deadline_at TEXT NOT NULL,apply_status TEXT NOT NULL,traffic_status TEXT NOT NULL,data TEXT NOT NULL,UNIQUE(deployment_id,server_id));
      CREATE INDEX IF NOT EXISTS policy_deployment_run ON policy_deployment_targets(deployment_id,server_id);
      CREATE INDEX IF NOT EXISTS policy_deployment_endpoint ON policy_deployment_targets(server_id,created_at,id);
      CREATE INDEX IF NOT EXISTS policy_deployment_active ON policy_deployment_targets(deadline_at,apply_status,traffic_status);
    """)


def _identifier(value):
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise ValueError("Invalid deployment or endpoint identity")
    return value


def _page(limit, offset, maximum):
    if type(limit) is not int or not 1 <= limit <= maximum or type(offset) is not int or not 0 <= offset <= 10000000:
        raise ValueError("Invalid bounded deployment page")


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _time(value=None):
    return (value or now()).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _put_target(db, target):
    raw = _json(target)
    if len(raw.encode()) > MAX_RECEIPT_BYTES:
        raise ValueError("Deployment target evidence exceeds its byte bound")
    db.execute("INSERT INTO policy_deployment_targets(id,deployment_id,server_id,created_at,deadline_at,apply_status,traffic_status,data) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET apply_status=excluded.apply_status,traffic_status=excluded.traffic_status,data=excluded.data",
               (target["id"], target["deployment_id"], target["server_id"], target["created_at"], target["deadline_at"], target["apply_status"], target["traffic_status"], raw))


def _ports(value):
    if not isinstance(value, list) or any(not isinstance(p, dict) or set(p) != {"port", "protocol"} or type(p["port"]) is not int or not 1 <= p["port"] <= 65535 or p["protocol"] not in ("tcp", "udp") for p in value):
        raise ValueError("Deployment ports must be exact TCP/UDP pairs")
    return [{"port": port, "protocol": proto} for proto, port in sorted({(p["protocol"], p["port"]) for p in value})]


def _pairs(bundle):
    return _ports([{key: s[key] for key in ("port", "protocol")} for s in bundle.get("services", []) if (s.get("mode") or bundle.get("mode")) == "enforce"])


def _servers(db, ids):
    fields = (("hostname",), ("ips",), ("_compiled", "version"), ("_compiled", "digest"), ("_compiled", "mode"), ("protection",), ("capabilities",), ("last_seen",))
    sql = "SELECT id," + ",".join(_expression(db, field) for field in fields) + " FROM servers WHERE id IN (" + ",".join("?" for _ in ids) + ")"
    result = {}
    for row in db.execute(sql, tuple(ids)):
        result[row[0]] = {"id": row[0], "hostname": row[1], "ips": json.loads(row[2] or "[]"), "_compiled": {"version": int(row[3] or 0), "digest": row[4] or "", "mode": row[5] or "monitor"}, "protection": json.loads(row[6] or "{}"), "capabilities": json.loads(row[7] or "[]"), "last_seen": row[8]}
    return result


def _supersede(db, ids, reason):
    if not ids:
        return
    # Only bounded active receipts are decoded, never whole rollout matrices.
    placeholders = ",".join("?" for _ in ids)
    rows = db.execute("SELECT data FROM policy_deployment_targets WHERE server_id IN (" + placeholders + ") AND deadline_at>? AND (apply_status IN ('pending','applying') OR traffic_status IN ('awaiting_apply','awaiting'))", (*ids, _time())).fetchall()
    for row in rows:
        target = json.loads(row[0])
        target.update(apply_status="superseded", traffic_status="superseded", reason=reason)
        _put_target(db, target)


def create(store, db, publications, actor, label, *, policy_id=None, origin="policy", window_seconds=600):
    """Called in the publishing transaction; returned ID is a GUI tracker key."""
    if not publications:
        return None
    if not isinstance(publications, list) or len(publications) > MAX_TARGETS or type(window_seconds) is not int or window_seconds != 600:
        raise ValueError("Deployment publication exceeds its supported scope")
    by_id = {}
    for ref in publications:
        if not isinstance(ref, dict):
            raise ValueError("Invalid deployment publication reference")
        identifier = _identifier(ref.get("server_id"))
        if type(ref.get("version")) is not int or ref["version"] < 1 or not isinstance(ref.get("digest"), str) or not HEX.fullmatch(ref["digest"]):
            raise ValueError("Deployment needs immutable compiled bundle references")
        by_id[identifier] = ref
    created = now()
    run = {"id": str(uuid.uuid4()), "label": str(label)[:120], "origin": str(origin)[:64], "policy_id": policy_id, "created_by": str(actor)[:256], "created_at": _time(created), "deadline_at": _time(created + timedelta(seconds=window_seconds)), "target_count": len(by_id)}
    db.execute("INSERT INTO policy_deployments(id,created_at,deadline_at,data) VALUES(?,?,?,?)", (run["id"], run["created_at"], run["deadline_at"], _json(run)))
    ordered = sorted(by_id)
    for start in range(0, len(ordered), 200):
        ids = ordered[start:start + 200]
        servers = _servers(db, ids)
        _supersede(db, ids, "A newer publication replaced this observation lease")
        approvals = {}
        for row in db.execute("SELECT server_id,version,digest,approval_id,protection_digest FROM managed_approvals WHERE active=1 AND server_id IN (" + ",".join("?" for _ in ids) + ") ORDER BY id", tuple(ids)):
            approvals[row[0]] = tuple(row[index] for index in range(1, 5))
        for identifier in ids:
            ref, server = by_id[identifier], servers.get(identifier)
            if not server or (server["_compiled"]["version"], server["_compiled"]["digest"]) != (ref["version"], ref["digest"]):
                raise ValueError("Publication changed before its tracker was recorded")
            ports = _ports(ref.get("ports", []))
            if "ports" not in ref:
                raw = db.execute("SELECT " + _expression(db, ("_compiled",)) + " FROM servers WHERE id=?", (identifier,)).fetchone()
                ports = _pairs(json.loads(raw[0]))
            approved = approvals.get(identifier)
            protected = server["protection"].get("digest", "")
            reason = ""
            if len(ports) > MAX_PORTS:
                reason = "Traffic verification supports at most64 enforced port/protocol pairs; policy delivery remains independent"
            elif not ports or not approved or approved[:2] != (ref["version"], ref["digest"]):
                reason = "No exact authorized enforcing bundle is available for observational verification"
            elif not {CAPABILITY, "signed_assignments_v1"} <= set(server["capabilities"]):
                reason = "Upgrade this endpoint to policy_verification_v1; delivery evidence remains independent"
            elif not HEX.fullmatch(protected or "") or approved[3] != protected or not server["ips"]:
                reason = "A current protected endpoint address binding is required"
            lease = {"schema_version": 1, "id": str(uuid.uuid4()), "deployment_id": run["id"], "server_id": identifier, "version": ref["version"], "digest": ref["digest"], "approval_id": approved[2] if approved else "", "protection_digest": protected, "target_ips_digest": digest(sorted(set(server["ips"]))), "ports": ports[:MAX_PORTS], "starts_at": run["created_at"], "expires_at": run["deadline_at"], "window_seconds": window_seconds}
            target = {"id": lease["id"], "deployment_id": run["id"], "server_id": identifier, "hostname": server["hostname"], "version": ref["version"], "digest": ref["digest"], "approval_id": lease["approval_id"], "ips": server["ips"], "unchanged_intent": ref.get("unchanged_intent") is True, "created_at": run["created_at"], "deadline_at": run["deadline_at"], "lease": lease, "apply_status": "pending" if approved else "unavailable", "traffic_status": "unavailable" if reason else "awaiting_apply", "reason": reason, "port_count": len(ports), "verified_port_count": 0, "readback_at": None, "armed_at": None, "last_seen": server["last_seen"], "checked_at": None, "sequence": 0, "ports": [{**port, "allow": {"status": "unavailable" if reason else "awaiting", "reason": reason}, "deny": {"status": "unavailable" if reason else "awaiting", "reason": reason}} for port in ports[:MAX_PORTS]]}
            _put_target(db, target)
    return _summary(db, run)


def _matches(server, lease):
    bundle = server.get("_compiled") or {}
    return bundle.get("version") == lease["version"] and bundle.get("digest") == lease["digest"] and (server.get("protection") or {}).get("digest") == lease["protection_digest"] and digest(sorted(set(server.get("ips", [])))) == lease["target_ips_digest"]


def _authorized(store, db, lease, server):
    row = db.execute("SELECT data FROM managed_approvals WHERE server_id=? AND approval_id=? AND version=? AND digest=? AND active=1 LIMIT 1", (lease["server_id"], lease["approval_id"], lease["version"], lease["digest"])).fetchone()
    if row is None:
        return False
    from .approvals import authorized
    from .managed import direct_authorities_valid
    approval = json.loads(row[0])
    return direct_authorities_valid(store, db, server, approval) and authorized(store, db, approval.get("approval_proof"), server_id=lease["server_id"])


def assignment(store, db, server, at=None):
    at = at or now()
    if not {CAPABILITY, "signed_assignments_v1"} <= set(server.get("capabilities", [])):
        return None
    rows = db.execute("SELECT data FROM policy_deployment_targets WHERE server_id=? AND deadline_at>? AND traffic_status IN ('awaiting_apply','awaiting') AND apply_status NOT IN ('failed','rolled_back','superseded','unavailable') ORDER BY created_at DESC,id DESC LIMIT 2", (server["id"], _time(at))).fetchall()
    for row in rows:
        target = json.loads(row[0])
        if not _matches(server, target["lease"]):
            continue
        if _authorized(store, db, target["lease"], server):
            return copy.deepcopy(target["lease"])
    return None


def _applicable(server, port):
    families = {ipaddress.ip_address(ip).version for ip in server.get("ips", [])}
    services = [s for s in server.get("_compiled", {}).get("services", []) if s["port"] == port["port"] and s["protocol"] == port["protocol"] and (s.get("mode") or server["_compiled"].get("mode")) == "enforce"]
    sources = [ipaddress.ip_network(source) for service in services for source in service.get("sources", [])]
    allowed = any(network.version in families for network in sources)
    protected = server.get("protection") or {}
    exceptions = [ipaddress.ip_network(source) for source in protected.get("management_sources", [])] if port["protocol"] == "tcp" and port["port"] in protected.get("ssh_ports", []) else []
    denied = False
    for family in families:
        collapsed = list(ipaddress.collapse_addresses([network for network in sources + exceptions if network.version == family]))
        if not any(network.prefixlen == 0 for network in collapsed):
            denied = True
    return {"allow": allowed, "deny": denied}, sources, exceptions


def _native_address(value):
    if not isinstance(value, str):
        raise ValueError("Native verification addresses are required")
    address = ipaddress.ip_address(value)
    if getattr(address, "scope_id", None) or getattr(address, "ipv4_mapped", None) or address.is_unspecified or address.is_multicast or address.is_loopback:
        raise ValueError("Verification needs native, non-loopback addresses")
    return address


def _evidence(value, action, port, lease, report, server, sources, exceptions):
    base = {"event_id", "source_ip", "destination_ip", "port", "protocol", "address_family", "capture_kind", "capture_backend", "count_unit", "expected_action", "observed_at", "received_at", "capture_epoch"}
    extra = {"connection_started_at"} if action == "allow" else {"rule_prefix"}
    if not isinstance(value, dict) or set(value) != base | extra or any(not isinstance(value.get(key), str) or not HEX.fullmatch(value[key]) for key in ("event_id", "capture_epoch")):
        raise ValueError("A complete bounded native verification witness is required")
    if {key: value[key] for key in ("port", "protocol")} != port or value["expected_action"] != {"allow": "allowed", "deny": "denied"}[action]:
        raise ValueError("Verification evidence has a different port or action")
    expected = ("accepted_connection", "conntrack", "connections") if action == "allow" else ("denied_packet", "nflog", "packets")
    if tuple(value[key] for key in ("capture_kind", "capture_backend", "count_unit")) != expected:
        raise ValueError("Generic traffic cannot verify an expected firewall decision")
    source, destination = _native_address(value["source_ip"]), _native_address(value["destination_ip"])
    if source.version != destination.version or value["address_family"] != ("ipv4" if source.version == 4 else "ipv6") or str(destination) not in lease.get("_ips", server.get("ips", [])) or str(source) in server.get("ips", []):
        raise ValueError("Verification is not native external traffic to this endpoint")
    matches = any(source in network for network in sources)
    if action == "allow" and not matches or action == "deny" and (matches or any(source in network for network in exceptions)):
        raise ValueError("Verification source does not match the expected decision")
    armed = parse_time(report["armed_at"])
    observed, received = parse_time(value["observed_at"]), parse_time(value["received_at"])
    if not armed < observed <= received <= parse_time(report["checked_at"]) or observed >= parse_time(lease["expires_at"]) or received > now() + timedelta(seconds=60):
        raise ValueError("Verification event was not observed inside its post-arm window")
    if action == "allow":
        started = parse_time(value["connection_started_at"])
        if not armed < started <= observed:
            raise ValueError("An old or undated connection cannot verify a new policy")
    else:
        material = "\x00".join(("prthak-policy-verification-deny-v1", lease["id"], report["applied_generation"], value["capture_epoch"], port["protocol"], str(port["port"]), value["address_family"]))
        import hashlib
        prefix = "PRTV" + hashlib.sha256(material.encode()).hexdigest()[:16] + ":"
        if value["rule_prefix"] != prefix:
            raise ValueError("Denied observation does not belong to this armed generation")
    return copy.deepcopy(value)


def _readback_matches(server, target, generation=None):
    result = server.get("managed_enforcement") or {}
    lease = target["lease"]
    if not _matches(server, lease) or result.get("status") != "enforced" or any(result.get(key) != lease[key] for key in ("version", "digest", "approval_id", "protection_digest")) or sorted(result.get("approved_ips", [])) != sorted(target["ips"]):
        return False
    if not GENERATION.fullmatch(result.get("generation", "")) or generation is not None and result["generation"] != generation:
        return False
    try:
        return parse_time(result["updated_at"]) > parse_time(target["created_at"])
    except (KeyError, ValueError, TypeError):
        return False


def _readback_boundary(server, target, generation):
    result = server.get("managed_enforcement") or {}
    if result.get("verification_id") == target["lease"]["id"] and result.get("verification_readback_at"):
        return result["verification_readback_at"]
    return None


def report(store, db, server, receipt):
    if not isinstance(receipt, dict) or set(receipt) - REPORT_FIELDS or REPORT_FIELDS - {"error"} - set(receipt) or len(_json(receipt).encode()) > MAX_RECEIPT_BYTES:
        raise ValueError("Invalid bounded policy verification receipt")
    _identifier(receipt.get("id"))
    row = db.execute("SELECT data FROM policy_deployment_targets WHERE id=? AND server_id=?", (receipt["id"], server["id"])).fetchone()
    if row is None:
        return False
    target = json.loads(row[0]); lease = target["lease"]
    if any(type(receipt.get(key)) is not int for key in ("schema_version", "version", "window_seconds")):
        raise ValueError("Verification lease numbers must be exact integers")
    for key in ASSIGNMENT_FIELDS - {"ports", "starts_at", "expires_at"}:
        if receipt.get(key) != lease[key]:
            raise ValueError("Verification receipt differs from its signed lease")
    if any(parse_time(receipt[key]) != parse_time(lease[key]) for key in ("starts_at", "expires_at")):
        raise ValueError("Verification receipt differs from its signed lease interval")
    if type(receipt["sequence"]) is not int or not 1 <= receipt["sequence"] <= 2147483647 or not isinstance(receipt["state"], str) or receipt["state"] not in REPORT_STATES or not isinstance(receipt.get("error", ""), str) or len(receipt.get("error", "").encode()) > 1024:
        raise ValueError("Invalid verification sequence/state")
    fingerprint = digest(receipt)
    if receipt["sequence"] < target["sequence"]:
        return False
    if receipt["sequence"] == target["sequence"]:
        if fingerprint != target.get("receipt_digest"):
            raise ValueError("Verification sequence reused for different evidence")
        return False
    invalidation = receipt["state"] in ("superseded", "error")
    if target["apply_status"] in ("failed", "rolled_back") or not invalidation and (not _matches(server, lease) or not _authorized(store, db, lease, server) or target["apply_status"] == "superseded" or target["traffic_status"] == "failed"):
        return False
    checked = parse_time(receipt["checked_at"])
    if checked > now() + timedelta(seconds=60) or checked < parse_time(lease["starts_at"]) - timedelta(seconds=60) or not invalidation and now() > parse_time(lease["expires_at"]) + timedelta(seconds=UPLOAD_GRACE_SECONDS):
        raise ValueError("Verification receipt is outside its bounded upload window")
    generation = receipt["applied_generation"]
    if not isinstance(generation, str) or generation and not GENERATION.fullmatch(generation):
        raise ValueError("Invalid applied firewall generation")
    armed = parse_time(receipt["armed_at"]) if receipt["armed_at"] is not None else None
    if armed and (not generation or armed < parse_time(lease["starts_at"]) or armed >= parse_time(lease["expires_at"]) or armed > checked):
        raise ValueError("Invalid fresh-readback/arming boundary")
    if receipt["committed_at"] is not None and parse_time(receipt["committed_at"]) > (armed or checked):
        raise ValueError("Commit cannot follow verification arming")
    if armed and not invalidation:
        boundary = _readback_boundary(server, target, generation)
        if not _readback_matches(server, target, generation) or not boundary or not parse_time(target["created_at"]) <= parse_time(boundary) <= armed or parse_time(server["managed_enforcement"]["updated_at"]) < parse_time(boundary):
            raise ValueError("Verification arming lacks its accepted exact fresh managed readback")
        if target.get("verification_readback_at") and parse_time(target["verification_readback_at"]) != parse_time(boundary):
            raise ValueError("A verification lease cannot replace its immutable readback boundary")
        accepted_commit = server["managed_enforcement"].get("committed_at")
        if (receipt["committed_at"] is None) != (accepted_commit is None) or accepted_commit is not None and parse_time(receipt["committed_at"]) != parse_time(accepted_commit):
            raise ValueError("Verification commit boundary differs from the accepted managed receipt")
    received_ports = receipt["ports"]
    if not isinstance(received_ports, list) or len(received_ports) != len(lease["ports"]) or _ports([{key: p.get(key) for key in ("port", "protocol")} for p in received_ports if isinstance(p, dict)]) != lease["ports"]:
        raise ValueError("Verification receipt must cover every frozen port exactly once")
    if invalidation:
        # A changed/revoked context may only downgrade this lease. Preserve the
        # witnesses admitted under the original context; never reclassify old
        # native events against the new source matrix or admit new positives.
        target.update(sequence=receipt["sequence"], receipt_digest=fingerprint, checked_at=receipt["checked_at"], traffic_status="superseded" if receipt["state"] == "superseded" else "failed", historical_only=True, reason=receipt.get("error", "") or "Observation authority was invalidated")
        if receipt["state"] == "superseded":
            target["apply_status"] = "superseded"
        _put_target(db, target)
        return True
    ports, events, epochs = [], set(), set()
    for item in received_ports:
        if not isinstance(item, dict) or set(item) != {"port", "protocol", "allow", "deny"}:
            raise ValueError("Invalid per-port verification receipt")
        port = {key: item[key] for key in ("port", "protocol")}
        applicable, sources, exceptions = _applicable(server, port)
        result = dict(port)
        for action in ("allow", "deny"):
            case = item[action]
            if not isinstance(case, dict) or set(case) - {"status", "reason", "evidence"} or not {"status", "reason"} <= set(case) or not isinstance(case["status"], str) or case["status"] not in CASE_STATES or not isinstance(case["reason"], str) or len(case["reason"].encode()) > 1024:
                raise ValueError("Invalid expected-decision verification case")
            if case["status"] == "not_applicable" and applicable[action] or not applicable[action] and armed and case["status"] != "not_applicable" and not invalidation:
                raise ValueError("Not-applicable verdict differs from the exact effective policy")
            result[action] = copy.deepcopy(case)
            if case["status"] == "verified":
                if not armed:
                    raise ValueError("Traffic cannot be verified before exact readback/arming")
                witness = _evidence(case.get("evidence"), action, port, lease, receipt, server, sources, exceptions)
                if witness["event_id"] in events:
                    raise ValueError("One native event cannot verify multiple cases")
                events.add(witness["event_id"]); epochs.add(witness["capture_epoch"])
                result[action]["evidence"] = witness
            elif "evidence" in case:
                raise ValueError("Only a verified case may attach a witness")
        ports.append(result)
    if len(epochs) > 1:
        raise ValueError("Verification cases cross armed capture epochs")
    verified_count = sum(all(item[action]["status"] in ("verified", "not_applicable") for action in ("allow", "deny")) for item in ports)
    if receipt["state"] == "verified" and (not armed or not ports or verified_count != len(ports)):
        raise ValueError("Every applicable case on every port requires evidence")
    if target["traffic_status"] == "verified" and receipt["state"] != "verified" and not invalidation:
        return False
    old_ports = {(item["protocol"], item["port"]): item for item in target["ports"]}
    if not invalidation:
        for item in ports:
            old = old_ports.get((item["protocol"], item["port"]), {})
            for action in ("allow", "deny"):
                if old.get(action, {}).get("status") == "verified" and old[action] != item[action]:
                    raise ValueError("A higher receipt sequence cannot replace the first admitted witness")
    state = receipt["state"]
    target.update(sequence=receipt["sequence"], receipt_digest=fingerprint, checked_at=receipt["checked_at"], last_seen=server.get("last_seen"), ports=ports, verified_port_count=verified_count, reason=receipt.get("error", ""), applied_generation=generation, armed_at=receipt["armed_at"], committed_at=receipt["committed_at"], controller_received_at=stamp(now()))
    if armed and not invalidation:
        target.update(apply_status="applied", verification_readback_at=boundary)
        if not target.get("readback_at"):
            target["readback_at"] = boundary
        if not target.get("_applied_receipt_seen"):
            target.update(already_present=server["managed_enforcement"].get("already_present") is True, _applied_receipt_seen=True)
    target["traffic_status"] = {"waiting_apply": "awaiting_apply", "observing": "awaiting", "verified": "verified", "expired": "unverified", "unavailable": "unavailable", "superseded": "superseded", "error": "failed"}[state]
    if state == "superseded":
        target["apply_status"] = "superseded"
    _put_target(db, target)
    return True


def outcome(store, db, server, result):
    row = db.execute("SELECT data FROM policy_deployment_targets WHERE server_id=? ORDER BY created_at DESC,id DESC LIMIT 1", (server["id"],)).fetchone()
    if row is None:
        return
    target = json.loads(row[0]); lease = target["lease"]
    if target["apply_status"] in ("failed", "rolled_back", "superseded"):
        return
    if not _matches(server, lease) or any(result.get(key) != lease[key] for key in ("version", "digest", "approval_id", "protection_digest")) or sorted(result.get("approved_ips", [])) != sorted(target["ips"]):
        return
    try:
        if parse_time(result["updated_at"]) <= parse_time(target["created_at"]):
            return
    except (KeyError, ValueError, TypeError):
        return
    status = result.get("status")
    if status == "enforced" and _readback_matches(server, target):
        boundary = target.get("readback_at") if target.get("applied_generation") == result["generation"] else None
        boundary = boundary or _readback_boundary(server, target, result["generation"]) or result["updated_at"]
        target.update(apply_status="applied", readback_at=boundary, applied_generation=result["generation"])
        if not target.get("_applied_receipt_seen"):
            target.update(already_present=result.get("already_present") is True, _applied_receipt_seen=True)
    elif status in ("error", "rolled_back"):
        target.update(apply_status="rolled_back" if status == "rolled_back" else "failed", traffic_status="failed", reason=result.get("rollback_reason") or result.get("error") or "Firewall application failed")
    elif status in ("staging", "runtime_healthchecking", "committing"):
        target["apply_status"] = "applying"
    _put_target(db, target)


def invalidate_after_recovery(store, db):
    # store is deliberately optional: recovery overlays operate on a verified
    # database transaction before a new Store instance can be constructed.
    for row in db.execute("SELECT data FROM policy_deployment_targets"):
        target = json.loads(row[0]); target.update(apply_status="superseded", traffic_status="superseded", historical_only=True, reason="Database recovery made retained evidence historical; fresh readback and observation are required")
        _put_target(db, target)


def recheck(store, deployment_id, server_id, actor):
    """Fresh observation lease only; existing policy authority is not extended."""
    _identifier(deployment_id); _identifier(server_id)
    from .firewall import WorkflowConflict
    from .managed import authorization
    with store.lock, store.meta() as db:
        if getattr(db, "dialect", "sqlite") == "sqlite":
            db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT data FROM policy_deployment_targets WHERE deployment_id=? AND server_id=?", (deployment_id, server_id)).fetchone()
        if not row:
            raise KeyError(server_id)
        previous = json.loads(row[0])
        server = store._get(db, "servers", server_id)
        if not server or not _matches(server, previous["lease"]):
            raise WorkflowConflict("Policy, addresses or protection changed; inspect the new publication", {"server_id": server_id})
        current = authorization(store, db, server)
        if not current.get("authorized"):
            raise WorkflowConflict("The existing exact policy has no current authorization", {"server_id": server_id})
        run = create(store, db, [{"server_id": server_id, "version": previous["version"], "digest": previous["digest"], "ports": _pairs(server["_compiled"]), "unchanged_intent": True}], actor, "Recheck " + previous["hostname"], origin="recheck")
        store.audit("policy_deployment.recheck", actor, {"deployment_id": run["id"], "previous_deployment_id": deployment_id, "server_id": server_id}, db)
        return run


@contextmanager
def _snapshot(store):
    with store.read_meta() as db:
        if getattr(db, "dialect", "sqlite") == "sqlite":
            db.execute("BEGIN")
        yield db


def _public(target, *, detail=False):
    value = copy.deepcopy(target)
    if value["traffic_status"] in ACTIVE_TRAFFIC and parse_time(value["deadline_at"]) <= now():
        value.update(traffic_status="unverified", reason="Observation window expired without all required native witnesses")
    keys = ("server_id", "hostname", "version", "digest", "approval_id", "unchanged_intent", "already_present", "historical_only", "apply_status", "traffic_status", "readback_at", "armed_at", "last_seen", "reason", "port_count", "verified_port_count", "checked_at", "deadline_at")
    result = {key: value.get(key) for key in keys}
    if detail:
        result["ports"] = value["ports"]
        for port in result["ports"]:
            for action in ("allow", "deny"):
                if value["traffic_status"] in ("unverified", "superseded") and port[action]["status"] == "awaiting":
                    port[action] = {"status": "unverified", "reason": value["reason"]}
            port["status"] = "superseded" if value.get("historical_only") or value["traffic_status"] == "superseded" else "failed" if value["traffic_status"] == "failed" else "verified" if all(port[action]["status"] in ("verified", "not_applicable") for action in ("allow", "deny")) else "unavailable" if any(port[action]["status"] == "unavailable" for action in ("allow", "deny")) else "unverified" if any(port[action]["status"] == "unverified" for action in ("allow", "deny")) else "awaiting"
    return result


def _summary(db, run):
    counts = {key: 0 for key in ("applied_count", "traffic_verified_count", "active_count", "failed_count", "awaiting_count", "unverified_count", "unavailable_count", "rolled_back_count", "superseded_count")}
    at = _time()
    for row in db.execute("SELECT apply_status,traffic_status,CASE WHEN deadline_at>? THEN 1 ELSE 0 END,COUNT(*) FROM policy_deployment_targets WHERE deployment_id=? GROUP BY 1,2,3", (at, run["id"])):
        applied, traffic, live, count = (row[index] for index in range(4))
        if applied == "applied": counts["applied_count"] += count
        if traffic == "verified": counts["traffic_verified_count"] += count
        active = bool(live and (applied in ACTIVE_APPLY or traffic in ACTIVE_TRAFFIC))
        if active: counts["active_count"] += count
        if traffic in ACTIVE_TRAFFIC and live: counts["awaiting_count"] += count
        if traffic == "unverified" or traffic in ACTIVE_TRAFFIC and not live: counts["unverified_count"] += count
        if applied == "failed" or traffic == "failed" and applied != "rolled_back": counts["failed_count"] += count
        if applied == "rolled_back": counts["rolled_back_count"] += count
        if applied == "superseded" or traffic == "superseded": counts["superseded_count"] += count
        if applied == "unavailable" or traffic == "unavailable": counts["unavailable_count"] += count
    state = "active" if counts["active_count"] else "verified" if run["target_count"] and counts["traffic_verified_count"] == run["target_count"] and counts["applied_count"] == run["target_count"] else "attention"
    return {**run, **counts, "state": state}


def summary(store, deployment_id):
    _identifier(deployment_id)
    with _snapshot(store) as db:
        row = db.execute("SELECT data FROM policy_deployments WHERE id=?", (deployment_id,)).fetchone()
        if not row: raise KeyError(deployment_id)
        return _summary(db, json.loads(row[0]))


def listing(store, limit=10, offset=0):
    _page(limit, offset, 10)
    with _snapshot(store) as db:
        total = db.execute("SELECT COUNT(*) FROM policy_deployments").fetchone()[0]
        active = db.execute("SELECT COUNT(DISTINCT deployment_id) FROM policy_deployment_targets WHERE deadline_at>? AND (apply_status IN ('pending','applying') OR traffic_status IN ('awaiting_apply','awaiting'))", (_time(),)).fetchone()[0]
        items = [_summary(db, json.loads(row[0])) for row in db.execute("SELECT data FROM policy_deployments ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?", (limit, offset))]
    return {"items": items, "total": int(total), "active_total": int(active), "limit": limit, "offset": offset, "has_more": offset + len(items) < total}


def targets(store, deployment_id, limit=50, offset=0):
    _identifier(deployment_id); _page(limit, offset, 50)
    with _snapshot(store) as db:
        if not db.execute("SELECT 1 FROM policy_deployments WHERE id=?", (deployment_id,)).fetchone(): raise KeyError(deployment_id)
        total = db.execute("SELECT COUNT(*) FROM policy_deployment_targets WHERE deployment_id=?", (deployment_id,)).fetchone()[0]
        # A target row is bounded by MAX_RECEIPT_BYTES; no whole-run JSON load.
        items = [_public(json.loads(row[0])) for row in db.execute("SELECT data FROM policy_deployment_targets WHERE deployment_id=? ORDER BY server_id LIMIT ? OFFSET ?", (deployment_id, limit, offset))]
    return {"items": items, "total": int(total), "limit": limit, "offset": offset, "has_more": offset + len(items) < total}


def detail(store, deployment_id, server_id):
    _identifier(deployment_id); _identifier(server_id)
    with _snapshot(store) as db:
        row = db.execute("SELECT data FROM policy_deployment_targets WHERE deployment_id=? AND server_id=?", (deployment_id, server_id)).fetchone()
        if not row: raise KeyError(server_id)
        return _public(json.loads(row[0]), detail=True)
