"""Durable exact-tuple recommendations and separately authorized accept-only overlays.

This authority never authorizes a compiled managed-policy bundle. Cross-store
delivery uses a metadata receipt before marking its traffic batch as evidenced.
"""
from __future__ import annotations

import csv
import io
import ipaddress
import json
import uuid
import secrets
from contextlib import nullcontext
from datetime import timedelta
from urllib.parse import urlsplit

from .firewall import WorkflowConflict
from .learning import is_policy_session, require_policy_session
from .store import digest, now, parse_time, stamp, validate_port

MAX_RULES = 64
MAX_IPSET_SOURCES = 10000
FOREVER = "9999-12-31T23:59:59Z"
TABLES = ("learning_evidence_receipts", "learning_allow_policies", "learning_allow_hosts", "learning_allow_history", "learning_policy_previews")


def _capacity(server):
    return MAX_IPSET_SOURCES if "learning_ipsets_v1" in server.get("capabilities", []) else MAX_RULES


def _capacity_error(server, services):
    count = len(_triples(services))
    if count > _capacity(server):
        return f"{_capacity(server)} exact-source endpoint capacity would be exceeded"
    if len(services) > 64:
        return "Learning overlay exceeds 64 distinct services"
    if count > MAX_RULES:
        lists = {4: set(), 6: set()}
        for service in services:
            for family in (4, 6):
                values = tuple(sorted(source for source in service["sources"] if ipaddress.ip_network(source).version == family))
                if values:
                    lists[family].add(values)
        if any(len(values) > 32 for values in lists.values()):
            return "Learning source bank exceeds 32 distinct source sets per address family"
    return ""


def initialize(db):
    for table in TABLES:
        db.execute(f"CREATE TABLE IF NOT EXISTS {table} (id TEXT PRIMARY KEY, data TEXT NOT NULL)")
    db.execute("CREATE TABLE IF NOT EXISTS learning_evidence (id TEXT PRIMARY KEY, session_id TEXT NOT NULL, server_id TEXT NOT NULL, data TEXT NOT NULL)")
    db.execute("CREATE INDEX IF NOT EXISTS learning_evidence_session ON learning_evidence(session_id,server_id)")
    from .approval_views import _expression
    db.execute("CREATE INDEX IF NOT EXISTS learning_evidence_receipt_session ON learning_evidence_receipts ((" + _expression(db, ("session_id",)) + "))")
    if getattr(db, "dialect", "sqlite") == "postgresql":
        db.execute("ALTER TABLE learning_allow_policies ADD COLUMN IF NOT EXISTS server_id TEXT NOT NULL DEFAULT ''")
        db.execute("ALTER TABLE learning_allow_policies ADD COLUMN IF NOT EXISTS session_id TEXT NOT NULL DEFAULT ''")
    else:
        columns = {row[1] for row in db.execute("PRAGMA table_info(learning_allow_policies)").fetchall()}
        for field in ("server_id", "session_id"):
            if field not in columns:
                db.execute(f"ALTER TABLE learning_allow_policies ADD COLUMN {field} TEXT NOT NULL DEFAULT ''")
    for row in db.execute("SELECT id,data FROM learning_allow_policies WHERE server_id='' OR session_id=''").fetchall():
        policy = json.loads(row[1])
        db.execute("UPDATE learning_allow_policies SET server_id=?,session_id=? WHERE id=?", (policy["server_id"], policy["session_id"], row[0]))
    db.execute("CREATE INDEX IF NOT EXISTS learning_allow_policy_server ON learning_allow_policies(server_id)")
    db.execute("CREATE INDEX IF NOT EXISTS learning_allow_policy_session ON learning_allow_policies(session_id)")
    from .approval_views import initialize as initialize_approval_views
    initialize_approval_views(db)
    from .session_views import initialize as initialize_session_views
    initialize_session_views(db)
    from .policy_views import initialize as initialize_policy_views
    initialize_policy_views(db)


def initialize_traffic(db):
    if getattr(db, "dialect", "sqlite") == "postgresql":
        db.execute("ALTER TABLE batches ADD COLUMN IF NOT EXISTS evidence_processed INTEGER NOT NULL DEFAULT 0")
    elif "evidence_processed" not in {row[1] for row in db.execute("PRAGMA table_info(batches)").fetchall()}:
        db.execute("ALTER TABLE batches ADD COLUMN evidence_processed INTEGER NOT NULL DEFAULT 0")
    db.execute("CREATE INDEX IF NOT EXISTS batches_evidence ON batches(processed,evidence_processed)")


def _evidence(db, session_id, server_id=None):
    clause, args = "session_id=?", [session_id]
    if server_id is not None:
        clause += " AND server_id=?"
        args.append(server_id)
    return [json.loads(row[0]) for row in db.execute("SELECT data FROM learning_evidence WHERE " + clause + " ORDER BY id", args).fetchall()]


def _put_evidence(db, row):
    db.execute("INSERT INTO learning_evidence(id,session_id,server_id,data) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data", (row["id"], row["session_id"], row["server_id"], json.dumps(row, sort_keys=True)))


def _source(value):
    try:
        if not isinstance(value, str) or "%" in value:
            raise ValueError()
        ip = ipaddress.ip_address(value)
        if ip.is_unspecified or ip.is_multicast or ip.is_loopback or ip.is_link_local or getattr(ip, "ipv4_mapped", None) or str(ip) == "255.255.255.255":
            return str(ip), "", "Source is not an eligible unicast host address"
        return str(ip), str(ipaddress.ip_network(str(ip))), ""
    except ValueError:
        return str(value), "", "Source is not a valid numeric unicast IP address"


def _triples(services):
    return {(row["protocol"], row["port"], source) for row in services for source in row.get("sources", [])}


def _services(triples):
    result = {}
    for protocol, port, source in triples:
        result.setdefault((protocol, port), set()).add(source)
    return [{"port": port, "protocol": protocol, "sources": sorted(sources)} for (protocol, port), sources in sorted(result.items())]


def _validate_services(value):
    if not isinstance(value, list) or len(value) > 64:
        raise ValueError("Provide an exact service/source matrix of at most 64 rules")
    triples = set()
    for row in value:
        if isinstance(row,dict) and row.get("sources_omitted"):
            raise ValueError("Policy navigation omits sources; fetch exact canonical detail before editing")
        item = validate_port(row)
        sources = row.get("sources")
        if not isinstance(sources, list) or len(sources) > MAX_IPSET_SOURCES:
            raise ValueError("Each service needs a list of exact host sources")
        for source in sources:
            try:
                if not isinstance(source, str):
                    raise ValueError()
                network = ipaddress.ip_network(source, strict=True)
            except (ValueError, TypeError):
                raise ValueError("Learning policies require /32 or /128 host sources")
            ip, cidr, error = _source(str(network.network_address))
            if error or network.prefixlen != network.max_prefixlen:
                raise ValueError("Learning policies require eligible /32 or /128 host sources")
            triples.add((item["protocol"], item["port"], cidr))
    if len(triples) > MAX_IPSET_SOURCES:
        raise ValueError("An endpoint learning overlay may contain at most 10000 exact sources")
    return _services(triples)


def _bindings(server):
    return {"protection_digest": server.get("protection", {}).get("digest", ""), "target_ips_digest": digest(sorted(server.get("ips", [])))}


def _protected(server, port, protocol):
    if protocol != "tcp":
        return ""
    protection = server.get("protection", {})
    ssh = set(protection.get("ssh_ports", []))
    for listener in server.get("listeners", []):
        identity = " ".join(str(listener.get(key, "")) for key in ("service", "process", "systemd_unit")).casefold()
        if "sshd" in identity or listener.get("service", "").casefold() == "ssh":
            ssh.add(listener["port"])
    if port in ssh or port == 22:
        return "SSH access requires the ordinary protected managed-policy review"
    from .channels import protected_origins
    for origin in protected_origins(server):
        try:
            controller = urlsplit(origin)
            controller_port = controller.port or 443
        except ValueError:
            return "Controller protection is invalid"
        if controller.hostname and port == controller_port:
            local = set(server.get("ips", [])) | {server.get("hostname", "").casefold(), "localhost", "127.0.0.1", "::1"}
            if controller.hostname.casefold() in local or set(protection.get("controller_addresses", [])) & set(server.get("ips", [])):
                return "Protected local controller ingress cannot be opened by learning"
    return ""


def _row_public(row, server, *, policy_session=True):
    from .traffic_capture import SAMPLE_UNIT, public as capture_public
    result = capture_public(row)
    result["hostname"] = server.get("hostname", row["server_id"])
    if not policy_session or result.get("count_unit") == SAMPLE_UNIT:
        result["eligible_for_auto"] = False
        result["excluded_reason"] = "Discover traffic is observe-only"
        return result
    frozen_ssh = row["protocol"] == "tcp" and (row.get("service", "").casefold() == "ssh" or "sshd" in row.get("process", "").casefold())
    reason = row.get("source_error", "") or ("SSH access requires the ordinary protected managed-policy review" if frozen_ssh else _protected(server, row["port"], row["protocol"]))
    result["eligible_for_auto"] = not bool(reason)
    result["excluded_reason"] = reason
    return result


def _policy_id(session_id, server_id):
    return "learn-" + digest([session_id, server_id])[:32]


def _all_policies(store, db, server_id=None, include_removed=False):
    policies = store._all(db, "learning_allow_policies") if server_id is None else [json.loads(row[0]) for row in db.execute("SELECT data FROM learning_allow_policies WHERE server_id=?", (server_id,)).fetchall()]
    return [policy for policy in policies if include_removed or not policy.get("removed", policy["status"] == "removed")]


def _put_policy(store, db, policy):
    from .policy_views import encoded_policy
    db.execute("INSERT INTO learning_allow_policies(id,server_id,session_id,data) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET server_id=excluded.server_id,session_id=excluded.session_id,data=excluded.data", (policy["id"], policy["server_id"], policy["session_id"], encoded_policy(policy)))


def _active(session):
    return session.get("status") == "active" and parse_time(session["starts_at"]) <= now() < parse_time(session["expires_at"])


def _automatic(store, db, session, server, rows, evidence_overflow=False):
    from .host_default_deny import guarded
    if guarded(server) or not is_policy_session(session):
        return
    if session.get("policy_action", "observe") != "auto_allow" or session.get("selection_mode") != "discovered" or session.get("auto_allow_confirmed") is not True or server["id"] in session.get("auto_allow_paused_server_ids", []) or not _active(session):
        return
    from . import approvals
    if not approvals.learning_authorized(store, db, session, server):
        return
    from .learning import ports_for
    frozen = {(item["protocol"], item["port"]) for item in ports_for(session, server["id"])}
    if not frozen or "learning_auto_allow_v1" not in server.get("capabilities", []):
        return
    identifier = _policy_id(session["id"], server["id"])
    old = store._get(db, "learning_allow_policies", identifier)
    if old and (old.get("removed") or old["status"] == "removed" or not old.get("auto_updates", False)):
        return
    from .traffic_capture import observation_kinds
    kinds = observation_kinds(session["observation_kinds"]) if 'observation_kinds' in session else ['legacy_log']
    eligible = {_triple(row) for row in rows if row["server_id"] == server["id"] and (row["protocol"], row["port"]) in frozen and row.get("capture_kind","legacy_log") in kinds and _row_public(row, server)["eligible_for_auto"]}
    if not eligible and old is None and not evidence_overflow:
        return
    policy = dict(old or {"id": identifier, "name": "Learned · " + server.get("hostname", server["id"]), "session_id": session["id"], "server_id": server["id"], "hostname": server.get("hostname", server["id"]), "origin": "auto", "revision": 0, "services": [], "status": "generated", "error": "", "auto_updates": True, "suppressed_tuples": [], "created_at": stamp(), "created_by": session.get("created_by", "automation"), "authority_expires_at": session["expires_at"]})
    existing = _triples(policy["services"])
    suppressed = {(row["protocol"], row["port"], row["source_cidr"]) for row in policy.get("suppressed_tuples", [])}
    proposed = existing | (eligible - suppressed)
    others = set().union(*(_triples(item["services"]) for item in _all_policies(store, db, server["id"]) if item["id"] != identifier)) if _all_policies(store, db, server["id"]) else set()
    capacity_error = "Observed evidence exceeds the bounded automatic-source review capacity" if evidence_overflow else _capacity_error(server, _services(proposed | others))
    if capacity_error:
        policy.update({"status": "blocked", "automation_error": capacity_error + "; new observed sources remain recommendations"})
        policy["error"] = policy.get("endpoint_error") or policy["automation_error"]
    else:
        policy["services"] = _services(proposed)
        if proposed != existing or policy.get("automation_error"):
            policy.update({"status": "pending", "automation_error": "", "endpoint_error": "", "error": ""})
    policy.update(_bindings(server))
    if old is None or any(policy.get(key) != old.get(key) for key in ("services", "status", "error", "automation_error", "protection_digest", "target_ips_digest")):
        policy["revision"] += 1
        policy["updated_at"] = stamp()
        _put_policy(store, db, policy)
        store.audit("learning_policy.generated" if old is None else "learning_policy.updated_automatically", "learning:" + session["id"], {"policy_id": identifier, "server_id": server["id"], "revision": policy["revision"], "status": policy["status"]}, db)
        refresh_host(store, db, server)


def _triple(row):
    return row["protocol"], row["port"], row["source_cidr"]


def reconcile(store, limit=100):
    """Replay-safe durable evidence transfer; never hold both database transactions."""
    from .approval_views import _expression
    from .evidence_views import traffic_evidence_available
    from .learning import TRAFFIC_PURPOSE
    from .traffic_capture import batch_peaks, public as capture_public, record_burst
    with store.flow_lock, store.read_traffic() as db:
        batches = [dict(row) for row in db.execute("SELECT * FROM batches WHERE processed=1 AND evidence_processed=0 ORDER BY received_at,batch_key LIMIT ?", (limit,)).fetchall()]
    if not batches:
        return 0
    session_ids = sorted({batch["session_id"] for batch in batches})
    with store.read_meta() as db:
        purpose = _expression(db, ("purpose",))
        collection_mode = _expression(db, ("traffic_collection_mode",))
        markers = ",".join("?" for _ in session_ids)
        traffic_sessions = {row[0] for row in db.execute(
            f"SELECT id FROM sessions WHERE id IN ({markers}) AND {purpose}=? AND COALESCE({collection_mode},'hits')<>'sampled'",
            (*session_ids, TRAFFIC_PURPOSE))}
    with store.flow_lock, store.read_traffic() as db:
        for batch in batches:
            batch["accepted_capture_ids"]={row[0] for row in db.execute("SELECT event_id FROM flows WHERE batch_key=? AND event_id<>'' AND capture_processed=1",(batch["batch_key"],))}
            batch["peaks"] = batch_peaks(db, batch) if batch["session_id"] in traffic_sessions else {}
    for batch in batches:
        receipt_id = digest(batch["batch_key"])
        with store.lock, store.meta() as db:
            if getattr(db, "dialect", "sqlite") == "sqlite":
                db.execute("BEGIN IMMEDIATE")
            if store._get(db, "learning_evidence_receipts", receipt_id) is None:
                session = store._get(db, "sessions", batch["session_id"])
                server = store._get(db, "servers", batch["server_id"])
                available = not session or traffic_evidence_available(session)
                if session and server and available:
                    frozen = session.get("discovery_results", {}).get(server["id"], {}).get("listeners", server.get("listeners", []))
                    for event in json.loads(batch["data"]):
                        if event.get("capture_kind") in ("accepted_connection","denied_packet") and event["event_id"] not in batch["accepted_capture_ids"]:
                            continue
                        captured = capture_public(event)
                        source, cidr, source_error = _source(event["source_ip"])
                        identity=[session["id"], server["id"], source, event["protocol"], event["port"]]
                        if captured["capture_kind"]!="legacy_log":identity.extend(captured[key] for key in ("capture_kind","capture_backend","count_unit"))
                        identifier = digest(identity)
                        row = store._get(db, "learning_evidence", identifier)
                        if row is None:
                            matches = [listener for listener in frozen if listener["port"] == event["port"] and listener["protocol"] == event["protocol"]]
                            listener = next((listener for listener in matches if listener.get("service") or listener.get("process")), matches[0] if matches else {})
                            row = {"id": identifier, "session_id": session["id"], "server_id": server["id"], "hostname": server.get("hostname", server["id"]), "source_ip": source, "source_cidr": cidr, "source_error": source_error, "port": event["port"], "protocol": event["protocol"], "service": listener.get("service", listener.get("application", "")), "process": listener.get("process", ""), "count": 0, "verdicts": [], "first_seen": event["first_seen"], "last_seen": event["last_seen"], **{key:captured[key] for key in ("capture_kind","capture_backend","count_unit","address_family")}}
                        row.update({"count": row["count"] + event["count"], "verdicts": sorted(set(row["verdicts"]) | {event["verdict"]}), "first_seen": min(row["first_seen"], event["first_seen"]), "last_seen": max(row["last_seen"], event["last_seen"])})
                        peak = batch["peaks"].get((source, event["protocol"], event["port"], captured["capture_kind"]))
                        if peak and (peak[0] > row.get("peak_observed_per_second", 0) or (peak[0] == row.get("peak_observed_per_second") and peak[1] < row["peak_observed_at"])):
                            row.update(peak_observed_per_second=peak[0], rate_window_seconds=1,
                                       peak_observed_at=peak[1], rate_is_lower_bound=True)
                        _put_evidence(db, row)
                    if session.get("purpose") == TRAFFIC_PURPOSE:
                        for (source, protocol, port, kind), (count, second) in batch["peaks"].items():
                            record_burst(store, db, server, source, protocol, port, kind, second, count)
                    policy_session = is_policy_session(session)
                    if policy_session:
                        session["evidence_revision"] = session.get("evidence_revision", 0) + 1
                        store._put(db, "sessions", session)
                    if policy_session and session.get("policy_action")=="auto_allow":
                        count=db.execute("SELECT COUNT(*) FROM learning_evidence WHERE session_id=? AND server_id=?",(session["id"],server["id"])).fetchone()[0]
                        overflow=count>3*MAX_IPSET_SOURCES
                        if count>MAX_IPSET_SOURCES and not overflow:
                            from .approval_views import _expression
                            fields=','.join(_expression(db,(key,)) for key in ('source_cidr','protocol','port'))
                            tuples=db.execute('SELECT COUNT(*) FROM (SELECT '+fields+' FROM learning_evidence WHERE session_id=? AND server_id=? GROUP BY '+fields+') evidence_tuples',(session['id'],server['id'])).fetchone()[0]
                            overflow=tuples>MAX_IPSET_SOURCES
                        _automatic(store, db, session, server, [] if overflow else _evidence(db, session["id"], server["id"]), evidence_overflow=overflow)
                if available:
                    store._put(db, "learning_evidence_receipts", {"id": receipt_id, "batch_key": batch["batch_key"], "session_id": batch["session_id"], "server_id": batch["server_id"], "processed_at": stamp()})
        # If this write fails, the committed metadata receipt makes a retry safe.
        with store.flow_lock, store.traffic() as db:
            db.execute("UPDATE batches SET evidence_processed=1 WHERE batch_key=?", (batch["batch_key"],))
    return len(batches)


def _authority(store, db, policy):
    session = store._get(db, "sessions", policy["session_id"]) or {}
    removed = policy.get("removed", policy["status"] == "removed")
    automatic = policy["origin"] == "auto" and not removed
    from .approvals import delivery
    return {"policy_id": policy["id"], "session_id": policy["session_id"], "kind": "auto" if automatic else "reviewed", "expires_at": policy.get("authority_expires_at", session.get("expires_at", FOREVER)) if automatic else FOREVER,
            **({"observation_kinds":session["observation_kinds"]} if automatic and "observation_kinds" in session else {}),
            "ports": session.get("server_ports", {}).get(policy["server_id"], []) if automatic else [{"port": row["port"], "protocol": row["protocol"]} for row in policy["services"]],
            "services": policy["services"] if not removed else [], "approval_proof": delivery(session.get("initial_approval_proof") if automatic else policy.get("approval_proof"))}


def refresh_host(store, db, server):
    policies = _all_policies(store, db, server["id"], include_removed=True)
    old = store._get(db, "learning_allow_hosts", server["id"])
    if not policies and old is None:
        return None
    services = _services(set().union(*(_triples(policy["services"]) for policy in policies if not policy.get("removed", policy["status"] == "removed"))))
    # Health metadata is a compact expectation only; it grants no access and
    # cannot turn a desired overlay into an applied receipt.
    from .service_health import sync as sync_service_expectations
    if sync_service_expectations(server, services, "learned"):
        store._put(db, "servers", server)
    active_ids = {policy["id"] for policy in policies if not policy.get("removed", policy["status"] == "removed")}
    policy_ids = sorted(active_ids)
    authorities = [_authority(store, db, policy) for policy in sorted(policies, key=lambda row: row["id"])]
    bindings = _bindings(server)
    fingerprint = digest({"services": services, "policy_ids": policy_ids, "authorities": authorities, **bindings})
    if old and old.get("fingerprint") == fingerprint:
        return old
    generation = (old or {}).get("generation", 0) + 1
    body_digest = digest({"services": services, "policy_ids": policy_ids})
    binding = digest_binding(server["id"], generation, body_digest, bindings["protection_digest"], bindings["target_ips_digest"])
    host = {**(old or {}), "id": server["id"], "server_id": server["id"], "generation": generation, "digest": body_digest, "services": services, "policy_ids": policy_ids, "authorities": authorities, **bindings, "binding_digest": binding, "fingerprint": fingerprint, "updated_at": stamp(), "status": "pending"}
    store._put(db, "learning_allow_hosts", host)
    names = {policy["id"]: policy["name"] for policy in policies if policy["id"] in active_ids and policy.get("name")}
    store._put(db, "learning_allow_history", {**host, "id": server["id"] + ":" + str(generation), "policy_names": names})
    return host


def digest_binding(server_id, generation, body_digest, protection_digest, target_ips_digest):
    import hashlib
    return hashlib.sha256("\0".join(("prthak-learning-allow-v1", server_id, str(generation), body_digest, protection_digest, target_ips_digest)).encode()).hexdigest()


def assignment(store, db, server):
    from . import approvals
    host = store._get(db, "learning_allow_hosts", server["id"])
    if host is None:
        body_digest = digest({"services": [], "policy_ids": []})
        bindings = _bindings(server)
        return {"server_id": server["id"], "generation": 0, "digest": body_digest, "services": [], "policy_ids": [], "authorities": [], **bindings, "binding_digest": digest_binding(server["id"], 0, body_digest, bindings["protection_digest"], bindings["target_ips_digest"]), "authorized": False, "reason": "No learning-owned policy is assigned", "expires_at": "1970-01-01T00:00:00Z"}
    from .host_default_deny import guarded
    if guarded(server):return {**host,"authorized":False,"reason":"Learning mutations are held while whole-server deny is enabled or being removed","expires_at":"1970-01-01T00:00:00Z"}
    current = now()
    policies = _all_policies(store, db, server["id"], include_removed=True)
    by_id = {policy["id"]: policy for policy in policies}
    active = []
    for authority in host["authorities"]:
        if parse_time(authority["expires_at"]) <= current:
            continue
        if authority["kind"] == "reviewed":
            from . import approvals
            policy = by_id.get(authority["policy_id"], {})
            if approvals.authorized(store, db, policy.get("approval_proof"), server_id=server["id"]):
                active.append(authority)
            continue
        session = store._get(db, "sessions", authority["session_id"]) or {"status": "missing"}
        from . import approvals
        if _active(session) and approvals.learning_authorized(store, db, session, server) and not by_id.get(authority["policy_id"], {}).get("auto_held") and server["id"] not in session.get("auto_allow_paused_server_ids", []):
            active.append(authority)
    allowed = set().union(*(_triples(authority["services"]) for authority in active)) if active else set()
    applied = _triples(host.get("applied_services", []))
    desired = _triples(host["services"])
    removals = set(host.get("applied_policy_ids", [])) - set(host["policy_ids"])
    reviewed_ids = {authority["policy_id"] for authority in active if authority["kind"] == "reviewed"}
    reason = "Exact learning-owned overlay is authorized independently of normal managed policy"
    authorized = True
    if "learning_auto_allow_v1" not in server.get("capabilities", []):
        authorized, reason = False, "Upgrade the endpoint to an agent supporting learning_auto_allow_v1"
    elif not approvals.signed_target(store, server):
        authorized, reason = False, "Upgrade the endpoint to signed_assignments_v1 before live learning allowances"
    elif not server.get("protection", {}).get("ready"):
        authorized, reason = False, "Protected management configuration is incomplete"
    elif _bindings(server) != {key: host[key] for key in ("protection_digest", "target_ips_digest")}:
        authorized, reason = False, "Endpoint protection or addresses changed; refresh the exact overlay review"
    elif any(policy.get(key) != host[key] for policy in policies if not policy.get("removed") or policy.get("removal_pending") for key in ("protection_digest", "target_ips_digest")):
        authorized, reason = False, "A learning policy is bound to another endpoint protection/address baseline"
    elif _capacity_error(server, host["services"]):
        authorized, reason = False, _capacity_error(server, host["services"])
    elif not (desired - applied) <= allowed or not removals <= reviewed_ids:
        authorized, reason = False, "New allows require an active auto grant or exact reviewed authority; committed allows remain unchanged"
    elif not active:
        authorized, reason = False, "Learning authority has ended; existing committed allows remain until reviewed removal"
    return {key: host[key] for key in ("server_id", "generation", "digest", "services", "policy_ids", "authorities", "protection_digest", "target_ips_digest", "binding_digest")} | {"authorized": authorized, "reason": reason, "expires_at": min((authority["expires_at"] for authority in active), default="1970-01-01T00:00:00Z")}


def verify_assignment(store, identifier, payload):
    with store.read_meta() as db:
        server = store._get(db, "servers", identifier)
        if server is None:
            raise PermissionError("Endpoint is not enrolled")
        approved = assignment(store, db, server)
        if not approved["authorized"] or any(payload.get(key) != approved[key] for key in ("generation", "digest", "protection_digest", "target_ips_digest", "binding_digest")):
            raise PermissionError("Current exact learning-owned overlay is not authorized")
        protection = server["protection"]
        return {**approved, "version": approved["generation"], "ips": sorted(server.get("ips", [])), "ssh_ports": protection["ssh_ports"], "management_sources": protection["management_sources"], "controller_origin": protection["controller_url"], "controller_addresses": protection.get("controller_addresses", [])}


def report_outcome(store, db, server, value):
    if not isinstance(value, dict) or value.get("status") not in ("applied", "preview", "blocked", "rolled_back", "error"):
        raise ValueError("Invalid learning allow outcome")
    generation = value.get("generation")
    if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
        raise ValueError("Invalid learning allow generation")
    historical = store._get(db, "learning_allow_history", server["id"] + ":" + str(generation))
    if historical is None or any(value.get(key) != historical[key] for key in ("digest", "binding_digest")):
        raise PermissionError("Learning allow outcome does not match its exact historical assignment")
    error = value.get("error", "")
    if not isinstance(error, str) or len(error) > 4096:
        raise ValueError("Invalid learning allow outcome error")
    result = {"generation": generation, "digest": historical["digest"], "binding_digest": historical["binding_digest"], "status": value["status"], "error": error, "updated_at": stamp()}
    applied_generation = value.get("applied_generation", generation if value["status"] == "applied" else 0)
    applied_digest = value.get("applied_digest", historical["digest"] if value["status"] == "applied" else "")
    if isinstance(applied_generation, bool) or not isinstance(applied_generation, int) or applied_generation < 0 or not isinstance(applied_digest, str):
        raise ValueError("Invalid last-applied learning overlay")
    if applied_generation:
        last_good = store._get(db, "learning_allow_history", server["id"] + ":" + str(applied_generation))
        if not last_good or last_good["digest"] != applied_digest or applied_generation > generation:
            raise PermissionError("Last-applied learning overlay has no matching historical assignment")
    if value["status"] == "applied" and (applied_generation != generation or applied_digest != historical["digest"]):
        raise ValueError("Applied outcome must acknowledge the exact desired generation and digest")
    result.update({"applied_generation": applied_generation, "applied_digest": applied_digest})
    previous = server.get("learning_allow_outcome", {})
    if any(previous.get(key) != result.get(key) for key in ("generation", "digest", "binding_digest", "status", "error", "applied_generation", "applied_digest")):
        store.audit("learning_allow." + result["status"], "agent:" + server["id"], result, db)
    if generation >= previous.get("generation", 0):
        server["learning_allow_outcome"] = result
    host = store._get(db, "learning_allow_hosts", server["id"])
    if host:
        if value["status"] == "applied" and applied_generation > host.get("applied_generation", 0):
            from .notification_events import port_allowed, subscribed_revision
            revision = subscribed_revision(store, db, "port_allowed")
            if revision is not None:
                new = _triples(last_good["services"]) - _triples(host.get("applied_services", []))
                port_allowed(db, revision, server, "learned policy", applied_generation, ((protocol, port) for protocol, port, _ in new))
        if value["status"] in ("rolled_back", "error") and generation >= host.get("applied_generation", 0):
            for policy in _all_policies(store, db, server["id"]):
                if policy["origin"] == "auto" and policy["id"] in historical["policy_ids"]:
                    session = store._get(db, "sessions", policy["session_id"])
                    if session:
                        session["auto_allow_paused_server_ids"] = sorted(set(session.get("auto_allow_paused_server_ids", [])) | {server["id"]})
                        store._put(db, "sessions", session)
                    policy.update({"auto_held": True, "auto_updates": False})
                    if generation == host["generation"]:
                        policy.update({"status": value["status"], "endpoint_error": error or "Failed automatic authority is held for administrative review", "error": error or "Failed automatic authority is held for administrative review"})
                    _put_policy(store, db, policy)
        if applied_generation and applied_generation >= host.get("applied_generation", 0):
            host.update({"applied_generation": applied_generation, "applied_services": last_good["services"], "applied_policy_ids": last_good["policy_ids"]})
        if generation == host["generation"]:
            host["status"] = value["status"]
            host["error"] = error
            for policy in _all_policies(store, db, server["id"], include_removed=True):
                if policy.get("removed"):
                    if not any(authority["policy_id"] == policy["id"] for authority in historical["authorities"]):
                        continue
                    policy["last_outcome"] = result
                    policy["removal_pending"] = value["status"] != "applied" or policy["id"] in historical["policy_ids"]
                    policy["status"] = "removed" if not policy["removal_pending"] else value["status"]
                    policy["error"] = error
                    _put_policy(store, db, policy)
                    continue
                if policy["id"] not in historical["policy_ids"]:
                    continue
                policy["last_outcome"] = result
                policy["endpoint_error"] = "" if value["status"] == "applied" else error
                policy["error"] = policy["endpoint_error"] or policy.get("automation_error", "")
                policy["status"] = "blocked" if policy.get("automation_error") and value["status"] == "applied" else value["status"]
                _put_policy(store, db, policy)
        store._put(db, "learning_allow_hosts", host)


def listing(store, session_id=None):
    with store.read_meta() as db:
        return sorted((policy for policy in _all_policies(store, db, include_removed=True) if (not policy.get("removed") or policy.get("removal_pending")) and (session_id is None or policy["session_id"] == session_id)), key=lambda row: (row["created_at"], row["id"]), reverse=True)


def get(store, identifier):
    return store.get("learning_allow_policies", identifier)


def recommendations(store, session_id, limit=200, offset=0, server_id=None):
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 2000 or isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise ValueError("Recommendation pagination requires limit 1..2000 and nonnegative offset")
    with store.read_meta() as db:
        # SQLite otherwise opens a new snapshot for each SELECT. Keep the total,
        # evidence page and metadata coherent while ingestion continues.
        if getattr(db, 'dialect', 'sqlite') == 'sqlite':
            db.execute('BEGIN')
        from .session_views import header, discovery_statuses
        session = header(db, session_id)
        from .evidence_views import clause,server_filter,server_view,evidence_rows,policy_summaries,pending_summaries,pending_summary,traffic_evidence_available
        server_filter(session,server_id)
        where,args=clause(session_id,server_id)
        available = traffic_evidence_available(session)
        total = int(db.execute("SELECT COUNT(*) FROM learning_evidence WHERE " + where, args).fetchone()[0]) if available else 0
        page = list(evidence_rows(db, session_id, server_id, limit, offset)) if available else []
        coverage_all=[server_id] if server_id is not None else session['server_ids']
        coverage_ids=coverage_all[:100]
        servers={identifier:server_view(db,identifier,ssh=False) for identifier in coverage_ids}
        for identifier in {row['server_id'] for row in page}:servers[identifier]=server_view(db,identifier)
        policy_session = is_policy_session(session)
        rows=[_row_public(row,servers.get(row['server_id'],{}), policy_session=policy_session) for row in page]
        policies, policy_total, pending, pending_total = [], 0, [], 0
        if policy_session:
            policies,policy_total=policy_summaries(db,session_id)
            initial = session.get("initial_approval_plan")
            initial_pending = initial and session.get("status") == "active" and initial.get("status") in ("draft", "awaiting_second_confirmation") and parse_time(initial["expires_at"]) > now()
            pending,pending_total=pending_summaries(db,session_id,99 if initial_pending else 100)
            if initial_pending:
                pending.append(pending_summary({**initial, "kind": "initial_learning"}));pending_total+=1
        statuses=discovery_statuses(db,session_id,coverage_ids)
        coverage = []
        for identifier in coverage_ids:
            server = servers[identifier]
            receipt = server.get("learning_coverage") or {}
            matches_session = receipt.get("session_id") == session_id
            coverage.append({"server_id": identifier, "hostname": server.get("hostname", identifier),
                             "learning_coverage": receipt if matches_session else None,
                             "collector_state": server.get("collector_state", "unknown") if matches_session else "unknown",
                             "discovery_status": statuses.get(identifier, "manual")})
        return {"session_id": session_id, "purpose": session["purpose"], **({"traffic_collection_mode": session["traffic_collection_mode"]} if "traffic_collection_mode" in session else {}), "evidence_expires_at": session["evidence_expires_at"], "evidence_expired": not available, "policy_action": session.get("policy_action", "observe"), "observation_kinds":session.get("observation_kinds",[]), "evidence_revision": session.get("evidence_revision", 0), "rows": rows, "total_rows": total, "limit": limit, "offset": offset, "has_more": offset + limit < total, "order": "server_id,id", "server_id": server_id, "coverage": {"servers": coverage, "total_servers":len(coverage_all),"limit":100,"offset":0,"has_more":len(coverage_all)>100,"rate_limited": any((row["learning_coverage"] or {}).get("rate_limited", True) for row in coverage), "message": "Transport connections, denied packets, sampled minutes and legacy logs have separate count units. Backend support, loss and gaps limit coverage; empty evidence does not prove no hits or application success. Coverage status lists up to 100 hosts; use server_id for another exact member."}, "generated_policies": policies, "generated_policy_total": policy_total, "pending_approvals": pending,"pending_approval_total":pending_total}



def export_csv(store, session_id, server_id=None):
    """Bounded compatibility wrapper; HTTP delivery streams the private spool."""
    from .evidence_views import csv_spool
    with csv_spool(store,session_id,server_id) as (source,_):
        return source.read().decode('utf-8-sig')


def _selection(store, db, value):
    ids, groups = value.get("server_ids", []), value.get("group_ids", [])
    if not isinstance(ids, list) or not isinstance(groups, list) or len(ids) > 20000 or len(groups) > 100 or any(not isinstance(identifier, str) or not identifier for identifier in ids + groups):
        raise ValueError("Select explicit enrolled servers and/or saved server groups")
    from .inventory_views import server_rows
    from .review_limits import MAX_REVIEW_BYTES, encoded_size
    # Target fingerprints use listeners/protection/identity, never a complete
    # imported firewall snapshot or the unrelated compiled-policy matrix.
    servers = list(server_rows(db))
    selected = set(ids)
    group_state = []
    remaining = MAX_REVIEW_BYTES
    locations = store._all(db, "locations")
    for identifier in sorted(set(groups)):
        group = store._get(db, "groups", identifier)
        if group is None:
            raise ValueError("Selected server group does not exist")
        members = store._group_members(group, servers, locations)
        selected.update(members)
        entry = {"id": identifier, "definition": group, "member_ids": sorted(members)}
        remaining -= encoded_size(entry, remaining)
        group_state.append(entry)
    by_id = {server["id"]: server for server in servers}
    if not selected or selected - set(by_id):
        raise ValueError("Select at least one enrolled target server")
    return [by_id[identifier] for identifier in sorted(selected)], group_state


def _target_fingerprint(server):
    return digest({"id": server["id"], "ips": sorted(server.get("ips", [])), "protection": server.get("protection", {}), "listeners": server.get("listeners", []), "capabilities": server.get("capabilities", []), "tags": server.get("tags", {}), "location_id": server.get("location_id")})


def preview(store, session_id, value, actor, *, principal=None):
    from .review_limits import MAX_REVIEW_BYTES, encoded_size
    from .traffic_capture import SAMPLE_UNIT
    if not isinstance(value, dict):
        raise ValueError("Recommendation preview must be an object")
    rows = value.get("row_ids", [])
    if not isinstance(rows, list) or not rows or len(rows) > 10000 or any(not isinstance(row, str) for row in rows):
        raise ValueError("Select one or more exact recommendation rows")
    name = value.get("name", "Learned access")
    if not isinstance(name, str) or not name.strip() or len(name) > 120:
        raise ValueError("A policy name of up to 120 characters is required")
    with store.lock, store.meta() as db:
        session = store._get(db, "sessions", session_id)
        if session is None:
            raise KeyError(session_id)
        require_policy_session(session)
        if isinstance(value.get("expected_evidence_revision"), bool) or not isinstance(value.get("expected_evidence_revision"), int) or value.get("expected_evidence_revision") != session.get("evidence_revision", 0):
            raise WorkflowConflict("Observed evidence changed; reload and review again", {})
        chosen_ids=sorted(set(rows))
        evidence={json.loads(row[0])["id"]:json.loads(row[0]) for row in db.execute("SELECT data FROM learning_evidence WHERE session_id=? AND id IN ("+",".join("?" for _ in chosen_ids)+")",(session_id,*chosen_ids))}
        if set(rows) - set(evidence):
            raise ValueError("Selected recommendation rows do not belong to this session")
        chosen = [evidence[identifier] for identifier in sorted(set(rows))]
        if any(row.get("count_unit") == SAMPLE_UNIT for row in chosen):
            raise PermissionError("Sampled traffic evidence cannot create firewall policy")
        if any(row.get("source_error") for row in chosen):
            raise ValueError("Non-unicast/invalid source evidence cannot become a learning policy")
        services = _services({_triple(row) for row in chosen})
        targets, group_state = _selection(store, db, value)
        target_rows, warnings = [], []
        remaining = MAX_REVIEW_BYTES
        for target in targets:
            reasons = sorted({_protected(target, row["port"], row["protocol"]) for row in services} - {""})
            existing = set().union(*(_triples(policy["services"]) for policy in _all_policies(store, db, target["id"])))
            capacity_error = _capacity_error(target, _services(existing | _triples(services)))
            if capacity_error:
                reasons.append(capacity_error)
            if not target.get("protection", {}).get("ready"):
                reasons.append("Protected management configuration is incomplete")
            if "learning_auto_allow_v1" not in target.get("capabilities", []):
                reasons.append("Upgrade the endpoint to an agent supporting learning_auto_allow_v1")
            from . import approvals
            if not approvals.signed_target(store, target):
                reasons.append("Upgrade the endpoint to signed_assignments_v1 before live learning allowances")
            entry = {"server_id": target["id"], "hostname": target["hostname"], "services": services, "blocked_reasons": reasons}
            remaining -= encoded_size(entry, remaining)
            target_rows.append(entry)
            warnings.extend(f"{target['hostname']}: {reason}" for reason in reasons)
        plan = {"id": str(uuid.uuid4()), "session_id": session_id, "name": name.strip(), "evidence_revision": session.get("evidence_revision", 0), "row_ids": sorted(set(rows)), "selection": {"server_ids": value.get("server_ids", []), "group_ids": value.get("group_ids", [])}, "group_state": group_state, "services": services, "target_server_ids": [target["id"] for target in targets], "targets": target_rows, "target_fingerprints": {target["id"]: _target_fingerprint(target) for target in targets}, "warnings": warnings, "expires_at": stamp(now() + timedelta(minutes=10)), "created_by": actor, "created_at": stamp(), "status": "reviewed"}
        plan["digest"] = digest(plan)
        plan.update(plan_digest=plan["digest"], confirmation_count=0, confirmation_nonce=secrets.token_urlsafe(24), confirmation_phrase="ALLOW LEARNED " + plan["digest"][:12])
        approvals.request(store, db, plan, actor, principal, endpoint_ids=plan.get("target_server_ids") or [server["id"]], scope_kind="learning")
        # Reserve the complete final receipt IDs and approval envelope before
        # accepting a review; no partial matrix or source grant is persisted.
        encoded_size({**plan, "policy_ids": ["0" * 36 for _ in targets]}, MAX_REVIEW_BYTES - 65536)
        store._put(db, "learning_policy_previews", plan)
        return plan


def apply(store, session_id, value, actor, *, principal=None):
    if not isinstance(value, dict) or value.get("confirm") is not True:
        raise ValueError("Explicit confirmation of the exact reviewed suggestion is required")
    with store.lock, store.meta() as db:
        plan = store._get(db, "learning_policy_previews", value.get("preview_id"))
        if plan is None or plan["session_id"] != session_id or plan["digest"] != value.get("digest"):
            raise WorkflowConflict("Suggestion preview is missing or does not match", {})
        session = store._get(db, "sessions", session_id)
        if session is None:
            raise KeyError(session_id)
        require_policy_session(session)
        if plan.get("kind") == "policy_change":
            raise ValueError("Use the learned-policy change confirmation route for this preview")
        if plan["status"] == "applied":
            return {"policies": [store._get(db, "learning_allow_policies", identifier) for identifier in plan["policy_ids"]], "target_server_ids": plan["target_server_ids"], "duplicate": True}
        targets, group_state = _selection(store, db, plan["selection"])
        from .host_default_deny import guarded
        if any(guarded(target) for target in targets):raise ValueError("Learning mutations are held while whole-server deny is enabled or being removed")
        if parse_time(plan["expires_at"]) <= now() or session.get("evidence_revision", 0) != plan["evidence_revision"] or group_state != plan["group_state"] or [target["id"] for target in targets] != plan["target_server_ids"] or any(_target_fingerprint(target) != plan["target_fingerprints"][target["id"]] for target in targets):
            raise WorkflowConflict("Evidence, target membership or protected state changed; preview again", {})
        if plan["warnings"]:
            raise ValueError("Resolve blocked target reasons before applying suggestions")
        from . import approvals
        if plan.get("approval", {}).get("mode") == "lab_only":
            decision = approvals.lab_decision(store, db, plan, actor, principal)
        else:
            if not isinstance(value.get("confirmation_nonce"), str) or not secrets.compare_digest(value["confirmation_nonce"], plan.get("confirmation_nonce", "")):
                raise WorkflowConflict("The learned-policy approval nonce changed; refresh the review", {})
            approvals.decide(store, db, plan, actor, principal)
            plan["confirmation_count"] = 1
            plan["confirmation_nonce"] = ""
            decision = approvals.proof(plan)
        policies = []
        for target in targets:
            existing = set().union(*(_triples(policy["services"]) for policy in _all_policies(store, db, target["id"])))
            if _capacity_error(target, _services(existing | _triples(plan["services"]))):
                raise WorkflowConflict("Endpoint overlay capacity changed; preview again", {})
            policy = {"id": str(uuid.uuid4()), "name": plan["name"], "session_id": session_id, "server_id": target["id"], "hostname": target["hostname"], "origin": "reviewed", "revision": 1, "services": plan["services"], "status": "pending", "error": "", "auto_updates": False, "suppressed_tuples": [], "created_at": stamp(), "updated_at": stamp(), "created_by": actor, "authority_expires_at": FOREVER, "approval_proof": decision, **_bindings(target)}
            _put_policy(store, db, policy)
            refresh_host(store, db, target)
            store.audit("learning_policy.applied_from_review", actor, {"policy_id": policy["id"], "preview_id": plan["id"], "server_id": target["id"]}, db)
            policies.append(policy)
        plan.update({"status": "applied", "policy_ids": [policy["id"] for policy in policies]})
        store._put(db, "learning_policy_previews", plan)
        return {"policies": policies, "target_server_ids": plan["target_server_ids"], "duplicate": False, "pending_approval": False, "preview": plan}


def _edit(store, identifier, value, actor, removing=False, *, principal=None, review_plan=None, db=None):
    if not isinstance(value, dict):
        raise ValueError("Learning policy change must be an object")
    if value.get("summary_only"):
        raise ValueError("Policy navigation cannot authorize a source edit or removal")
    with store.lock, (nullcontext(db) if db is not None else store.meta()) as db:
        policy = store._get(db, "learning_allow_policies", identifier)
        if policy is None:
            raise KeyError(identifier)
        if isinstance(value.get("expected_revision"), bool) or value.get("expected_revision") != policy["revision"]:
            raise WorkflowConflict("Learning policy changed; reload before editing", {})
        if policy.get("removed") or policy["status"] == "removed":
            raise ValueError("A removed policy cannot be silently reactivated")
        server = store._get(db, "servers", policy["server_id"])
        if server is None:
            raise ValueError("Target endpoint is no longer enrolled")
        from .host_default_deny import guarded
        if guarded(server):raise ValueError("Learning mutations are held while whole-server deny is enabled or being removed")
        name = value.get("name", policy["name"])
        if not isinstance(name, str) or not name.strip() or len(name) > 120:
            raise ValueError("A policy name of up to 120 characters is required")
        services = [] if removing else _validate_services(value.get("services", policy["services"]))
        if any(_protected(server, row["port"], row["protocol"]) for row in services):
            raise ValueError("Protected SSH/controller ingress requires ordinary managed-policy review")
        others = set().union(*(_triples(item["services"]) for item in _all_policies(store, db, server["id"]) if item["id"] != identifier))
        capacity_error = _capacity_error(server, _services(others | _triples(services)))
        if capacity_error:
            raise ValueError(capacity_error)
        from . import approvals
        if not approvals.signed_target(store, server):
            raise ValueError("Upgrade the endpoint to signed_assignments_v1 before changing learned allowances")
        change = {"policy_id": identifier, "expected_revision": policy["revision"], "name": name.strip(), "services": services, "remove": removing, "target_fingerprint": _target_fingerprint(server)}
        if review_plan is not None:
            if review_plan.get("change") != change:
                raise WorkflowConflict("Learned-policy change or protected target state changed; review again", {})
            decision = approvals.proof(review_plan)
            if not approvals.authorized(store, db, decision, plan_id=review_plan["id"], plan_digest=review_plan["digest"]):
                raise PermissionError("The learned-policy change no longer has current Admin authority")
        else:
            lab_plan = {"id": str(uuid.uuid4()), "plan_digest": digest(change)}
            if principal is not None:
                if removing or _triples(policy["services"]) - _triples(services):raise ValueError("Use the exact two-confirmation review before removing learned access")
                approvals.request(store, db, lab_plan, actor, principal, endpoint_ids=[server["id"]], scope_kind="learning")
                decision = approvals.decide(store, db, lab_plan, actor, principal)
            else:decision = approvals.lab_decision(store, db, lab_plan, actor, principal)
        suppressed = {(row["protocol"], row["port"], row["source_cidr"]) for row in policy.get("suppressed_tuples", [])} | (_triples(policy["services"]) - _triples(services))
        policy.update({"name": name.strip(), "services": services, "origin": "reviewed", "auto_updates": False, "auto_held": False, "revision": policy["revision"] + 1, "status": "pending", "removed": removing, "removal_pending": removing, "error": "", "endpoint_error": "", "automation_error": "", "authority_expires_at": FOREVER, "approval_proof": decision, "suppressed_tuples": [{"protocol": protocol, "port": port, "source_cidr": source} for protocol, port, source in sorted(suppressed)], "updated_at": stamp(), "updated_by": actor, **_bindings(server)})
        _put_policy(store, db, policy)
        refresh_host(store, db, server)
        store.audit("learning_policy.removed" if removing else "learning_policy.edited", actor, {"policy_id": identifier, "revision": policy["revision"], "suppressed_count": len(suppressed)}, db)
        return policy


def update(store, identifier, value, actor, *, principal=None):
    return _edit(store, identifier, value, actor, principal=principal)


def remove(store, identifier, value, actor, *, principal=None):
    return _edit(store, identifier, value, actor, removing=True, principal=principal)


def change_preview(store, identifier, value, actor, *, principal=None):
    from . import approvals
    if not isinstance(value, dict) or set(value) - {"expected_revision", "services", "name", "remove"} or not isinstance(value.get("remove", False), bool):
        raise ValueError("Provide a revision and exact proposed learned-policy change")
    with store.lock, store.meta() as db:
        policy = store._get(db, "learning_allow_policies", identifier)
        if not policy:
            raise KeyError(identifier)
        if isinstance(value.get("expected_revision"), bool) or value.get("expected_revision") != policy["revision"] or policy.get("removed"):
            raise WorkflowConflict("Learning policy changed or was removed; refresh before review", {})
        server = store._get(db, "servers", policy["server_id"])
        if not server or not server.get("protection", {}).get("ready") or not approvals.signed_target(store, server):
            raise ValueError("The signed-assignment target needs a ready protected management baseline")
        removing, name = value.get("remove", False), value.get("name", policy["name"])
        if not isinstance(name, str) or not name.strip() or len(name) > 120:
            raise ValueError("A policy name of up to 120 characters is required")
        services = [] if removing else _validate_services(value.get("services", policy["services"]))
        if any(_protected(server, row["port"], row["protocol"]) for row in services):
            raise ValueError("Protected SSH/controller ingress cannot be opened by learned policy")
        others = set().union(*(_triples(item["services"]) for item in _all_policies(store, db, server["id"]) if item["id"] != identifier))
        error = _capacity_error(server, _services(others | _triples(services)))
        if error:
            raise ValueError(error)
        change = {"policy_id": identifier, "expected_revision": policy["revision"], "name": name.strip(), "services": services, "remove": removing, "target_fingerprint": _target_fingerprint(server)}
        plan = {"id": str(uuid.uuid4()), "kind": "policy_change", "policy_id": identifier, "session_id": policy["session_id"], "change": change,
                "status": "reviewed", "confirmation_count": 0, "confirmation_nonce": secrets.token_urlsafe(24), "created_by": actor, "created_at": stamp(), "expires_at": stamp(now() + timedelta(minutes=10))}
        plan["requires_double_confirmation"] = bool(removing or _triples(policy["services"]) - _triples(services))
        plan["digest"] = digest(plan)
        plan.update(plan_digest=plan["digest"], confirmation_phrase=("REMOVE LEARNED " if removing else "CHANGE LEARNED ") + plan["digest"][:12])
        approvals.request(store, db, plan, actor, principal, endpoint_ids=plan.get("target_server_ids") or [server["id"]], scope_kind="learning")
        store._put(db, "learning_policy_previews", plan)
        return plan


def change_confirm(store, identifier, value, actor, *, principal=None):
    from . import approvals
    if not isinstance(value, dict) or value.get("confirm") is not True:
        raise ValueError("Confirm the exact learned-policy change review")
    with store.lock, store.meta() as db:
        plan = store._get(db, "learning_policy_previews", value.get("preview_id"))
        if not plan or plan.get("kind") != "policy_change" or plan.get("policy_id") != identifier or plan.get("digest") != value.get("digest"):
            raise WorkflowConflict("Learned-policy change preview is missing or mismatched", {})
        if plan.get("status") == "applied":
            return {"policy": store._get(db, "learning_allow_policies", identifier), "preview": plan, "pending_approval": False, "duplicate": True}
        if parse_time(plan["expires_at"]) <= now() or not isinstance(value.get("confirmation_nonce"), str) or not secrets.compare_digest(value["confirmation_nonce"], plan["confirmation_nonce"]):
            raise WorkflowConflict("Learned-policy change review expired or its nonce changed", {})
        current_policy = store._get(db, "learning_allow_policies", identifier)
        target = store._get(db, "servers", current_policy["server_id"]) if current_policy else None
        if not current_policy or current_policy["revision"] != plan["change"]["expected_revision"] or not target or _target_fingerprint(target) != plan["change"]["target_fingerprint"]:
            raise WorkflowConflict("Learned-policy revision or protected target changed; create a fresh review", {})
        destructive = plan.get("requires_double_confirmation", True)
        final = not destructive or plan["confirmation_count"] == 1
        if destructive and final and value.get("challenge") != plan["confirmation_phrase"]:
            raise WorkflowConflict("Type the exact learned-policy change phrase", {})
        if destructive:approvals.confirm(store, db, plan, actor, principal, final=final)
        else:approvals.decide(store, db, plan, actor, principal)
        plan["confirmation_count"] += 1
        plan["confirmation_nonce"] = "" if final else secrets.token_urlsafe(24)
        if not final:
            plan["status"] = "awaiting_second_confirmation"
            store._put(db, "learning_policy_previews", plan)
            return {"policy": None, "preview": plan, "pending_approval": True}
        policy = _edit(store, identifier, plan["change"], actor, removing=plan["change"]["remove"], principal=principal, review_plan=plan, db=db)
        plan["status"] = "applied"
        store._put(db, "learning_policy_previews", plan)
        return {"policy": policy, "preview": plan, "pending_approval": False, "duplicate": False}


def approval_reviews(store, session_id=None, limit=200, offset=0):
    from .approval_views import listing
    return listing(store, session_id, limit, offset)


def approval_review(store, identifier):
    from .approval_views import detail
    return detail(store, identifier)


def retirement_blockers(store, db, server):
    policies = _all_policies(store, db, server["id"], include_removed=True)
    host = store._get(db, "learning_allow_hosts", server["id"])
    reasons = []
    if any(not policy.get("removed", policy["status"] == "removed") for policy in policies):
        reasons.append("Learning-owned allow policies must be explicitly removed before retirement")
    if host and (host.get("services") or host.get("applied_services")):
        reasons.append("Learning-owned firewall allows are committed or pending; apply reviewed cleanup first")
    if host and (host.get("status") != "applied" or host.get("applied_generation") != host["generation"]):
        reasons.append("An applied acknowledgement of the exact empty learning overlay is required before retirement")
    return reasons
