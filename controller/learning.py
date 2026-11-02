"""Learning scope is frozen per endpoint after an explicitly requested fresh scan.

Inventory is only a preview. It never authorizes collection, opens a port, or
changes an access policy. Session state lives in the existing durable store.
"""
from __future__ import annotations

import ipaddress
import re
import uuid
from datetime import timedelta

from .store import now, parse_time, stamp, validate_port

CAPABILITY = "learning_discovery_v1"
AUTO_ALLOW_CAPABILITY = "learning_auto_allow_v1"
IDENTIFIER = re.compile(r"[A-Za-z0-9_.:-]{1,128}")


def server_ids(value):
    ids = value.get("server_ids")
    if not isinstance(ids, list) or not ids or len(ids) > 20000 or any(not isinstance(item, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", item) for item in ids):
        raise ValueError("Select at least one valid server (maximum 20000)")
    return sorted(set(ids))


def discovered_ports(listeners):
    """Only concrete non-loopback or wildcard TCP/UDP binds are collectible."""
    pairs = set()
    for listener in listeners:
        address = listener.get("address", "").strip().strip("[]")
        if address != "*":
            try:
                ip = ipaddress.ip_address(address.split("%", 1)[0])
            except ValueError:
                # Unknown/missing bind addresses cannot establish network exposure.
                continue
            if ip.is_loopback or (getattr(ip, "ipv4_mapped", None) is not None and ip.ipv4_mapped.is_loopback):
                continue
        pairs.add((listener["protocol"], listener["port"]))
    return [{"port": port, "protocol": protocol} for protocol, port in sorted(pairs)]


def requested_port_filter(value):
    if "port_filter" not in value:
        return []
    ports = value["port_filter"]
    if not isinstance(ports, list) or not 1 <= len(ports) <= 100:
        raise ValueError("port_filter must contain 1 to 100 exact TCP/UDP ports; omit it to discover all ports")
    pairs = {(item["protocol"], item["port"]) for item in map(validate_port, ports)}
    return [{"protocol": protocol, "port": port} for protocol, port in sorted(pairs)]


def selected_discovered_ports(listeners, port_filter):
    ports = discovered_ports(listeners)
    if port_filter:
        selected = {(item["protocol"], item["port"]) for item in port_filter}
        ports = [item for item in ports if (item["protocol"], item["port"]) in selected]
    return ports


def ports_for(session, identifier):
    if identifier not in session["server_ids"]:
        return []
    if session.get("selection_mode", "manual") == "discovered":
        return session.get("server_ports", {}).get(identifier, [])
    return session.get("ports", [])


def assignment(session, identifier):
    result = dict(session)
    # The host must never receive another endpoint's snapshot, including on stop.
    result.pop("server_ports", None)
    result.pop("discovery_results", None)
    result.pop("discovery_pending_server_ids", None)
    for private_scope in ("initial_approval_plan", "initial_approval_proof", "initial_approval_scope", "initial_approval_requester", "initial_approval_target_bindings"):
        result.pop(private_scope, None)
    result["ports"] = ports_for(session, identifier)
    if session.get("selection_mode") == "discovered":
        result["discovery_pending"] = identifier in session.get("discovery_pending_server_ids", [])
    return result


def preview(store, value):
    ids = server_ids(value)
    port_filter = requested_port_filter(value)
    hosts = []
    with store.read_meta() as db:
        for identifier in ids:
            server = store._get(db, "servers", identifier)
            if server is None:
                raise ValueError(f"Unknown server: {identifier}")
            hosts.append({"server_id": identifier, "hostname": server["hostname"], "ports": selected_discovered_ports(server.get("listeners", []), port_filter), "last_discovery_at": server.get("last_discovery_at"), "freshness": "cached_preview", "discovery_pending": True, "supported": CAPABILITY in server.get("capabilities", []), "capture_supported":"traffic_capture_v1" in server.get("capabilities",[]), "offline": store._heartbeat_stale(server), "synthetic": server.get("synthetic", False)})
    return {"selection_mode": "discovered", "server_ids": ids, "port_filter": port_filter, "servers": hosts, "freshness": "cached_preview", "message": "Cached inventory preview. Start learning requests a fresh scan on every selected server and freezes each server's own selected ports for this learning window."}


def create_session(store, value, actor, *, principal=None):
    ids = server_ids(value)
    mode = value.get("selection_mode", "manual")
    if mode not in ("manual", "discovered"):
        raise ValueError("selection_mode must be manual or discovered")
    port_filter = requested_port_filter(value)
    if mode == "manual" and port_filter:
        raise ValueError("port_filter is for fresh discovery; manual learning uses ports")
    policy_action = value.get("policy_action", "observe")
    from .traffic_capture import observation_kinds
    kinds = observation_kinds(value.get("observation_kinds"))
    if policy_action not in ("observe", "auto_allow"):
        raise ValueError("policy_action must be observe or auto_allow")
    if policy_action == "auto_allow" and (mode != "discovered" or value.get("auto_allow_confirmed") is not True):
        raise ValueError("Automatic source allows require fresh service discovery and explicit auto_allow_confirmed consent")
    duration = value.get("duration_seconds", 3600)
    if isinstance(duration, bool) or not isinstance(duration, int) or not 60 <= duration <= 604800:
        raise ValueError("Duration must be 60 to 604800 seconds")
    ports = value.get("ports", [])
    if not isinstance(ports, list) or len(ports) > 100 or (mode == "manual" and not ports):
        raise ValueError("Select between 1 and 100 service ports")
    if mode == "discovered" and ports:
        raise ValueError("Automatic learning discovers each server's ports; do not supply manual ports")
    ports = [validate_port(port) for port in ports]
    with store.lock, store.meta() as db:
        servers = []
        for identifier in ids:
            server = store._get(db, "servers", identifier)
            if server is None:
                raise ValueError(f"Unknown server: {identifier}")
            servers.append(server)
        capture_unsupported=[server['hostname'] for server in servers if 'traffic_capture_v1' not in server.get('capabilities',[])]
        if capture_unsupported:
            raise ValueError('New capture scopes require traffic_capture_v1; upgrade these agents: '+', '.join(capture_unsupported[:20]))
        unsupported = [server["hostname"] for server in servers if CAPABILITY not in server.get("capabilities", [])]
        if mode == "discovered" and unsupported:
            raise ValueError("Automatic learning requires an agent supporting learning_discovery_v1 (0.3.0 or later). Upgrade these agents or use manual ports: " + ", ".join(unsupported[:20]))
        if policy_action == "auto_allow":
            from .host_default_deny import guarded
            if any(guarded(server) for server in servers):raise ValueError("Disable whole-server deny through its acknowledged flow before automatic source grants")
            unsupported = [server["hostname"] for server in servers if AUTO_ALLOW_CAPABILITY not in server.get("capabilities", [])]
            if unsupported:
                raise ValueError("Automatic source allows require learning_auto_allow_v1 (agent 0.4.0 or later). Upgrade: " + ", ".join(unsupported[:20]))
        at = now()
        for current in store._all(db, "sessions"):
            if current["status"] == "active" and parse_time(current["expires_at"]) > at and set(ids) & set(current["server_ids"]):
                raise ValueError("A selected server already has an active learning session")
        session = {"id": str(uuid.uuid4()), "server_ids": ids, "selection_mode": mode, "policy_action": policy_action, "observation_kinds": kinds, "ports": ports, "starts_at": stamp(at), "expires_at": stamp(at + timedelta(seconds=duration)), "status": "active", "created_by": actor}
        if port_filter:
            session["port_filter"] = port_filter
        if policy_action == "auto_allow":
            session["auto_allow_confirmed"] = True
            session["auto_allow_authorized_by"] = actor
            from . import approvals
            approvals.learning_requester(store, db, session, actor, principal)
        if all(server.get("synthetic") is True for server in servers):
            session["synthetic"] = True
        if mode == "discovered":
            session.update({"server_ports": {identifier: [] for identifier in ids}, "discovery_pending_server_ids": ids.copy(), "discovery_results": {identifier: {"status": "pending", "ports": []} for identifier in ids}})
        store._put(db, "sessions", session)
        sessions = store._all(db, "sessions")
        for server in servers:
            store._collector_state(server, sessions, at)
            store._put(db, "servers", server)
        store.audit("learning.started", actor, {"session_id": session["id"], "server_ids": ids, "duration_seconds": duration, "selection_mode": mode, "policy_action": policy_action, "port_filter": port_filter, "observation_kinds":kinds}, db)
    return session


def report_fields(value):
    version = value.get("agent_version", "")
    if not isinstance(version, str) or len(version) > 128:
        raise ValueError("Invalid agent version")
    capabilities = value.get("capabilities", [])
    if not isinstance(capabilities, list) or len(capabilities) > 64 or any(not isinstance(item, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,100}", item) for item in capabilities):
        raise ValueError("Invalid agent capabilities")
    ids = value.get("learning_discovery_session_ids", [])
    if not isinstance(ids, list) or len(ids) > 100 or any(not isinstance(item, str) or not IDENTIFIER.fullmatch(item) for item in ids):
        raise ValueError("Invalid learning discovery session IDs (maximum 100)")
    return version, sorted(set(capabilities)), sorted(set(ids))


def acknowledge_discovery(store, db, server, value, ids, listeners, scanned_at, at=None):
    """Acknowledge only a scan bound to this endpoint's pending request.

    HTTP retries are idempotent; the first successful snapshot never changes.
    Failed actual scans retain the pending request for the next control cycle.
    """
    at = at or now()
    if ids and CAPABILITY not in server.get("capabilities", []):
        raise ValueError("Learning discovery acknowledgement requires learning_discovery_v1 capability")
    for identifier in ids:
        session = store._get(db, "sessions", identifier)
        if session is None or server["id"] not in session["server_ids"]:
            raise ValueError("Learning discovery session does not belong to endpoint")
        if session.get("selection_mode") != "discovered":
            raise ValueError("Learning discovery acknowledgement requires an automatic session")
        if session["status"] != "active" or not parse_time(session["starts_at"]) <= at < parse_time(session["expires_at"]):
            continue
        if server["id"] not in session.get("discovery_pending_server_ids", []):
            continue
        if not value.get("discovery_performed", False):
            raise ValueError("Learning discovery requires a fresh discovery_performed scan")
        result = {"status": "error", "ports": [], "attempted_at": stamp(at)}
        if server.get("synthetic") is True:
            result["synthetic"] = True
        error = value.get("discovery_error", "")
        if not error:
            if not value.get("discovered_at") or not scanned_at or parse_time(scanned_at) < parse_time(session["starts_at"]):
                raise ValueError("Learning discovery scan predates the session; perform a fresh scan")
            ports = selected_discovered_ports(listeners, session.get("port_filter", []))
            if len(ports) > 100:
                error = "Fresh scan found more than 100 network service ports; use a manual learning selection of up to 100 ports."
            else:
                result.update({"status": "ready" if ports else "no_listeners", "ports": ports, "discovered_at": scanned_at})
                selected_pairs = {(item["protocol"], item["port"]) for item in ports}
                result["listeners"] = [{key: listener[key] for key in ("port", "protocol", "address", "service", "process", "application", "systemd_unit") if key in listener} for listener in listeners if (listener["protocol"], listener["port"]) in selected_pairs]
                session["server_ports"][server["id"]] = ports
                session["discovery_pending_server_ids"].remove(server["id"])
                session["ports"] = [{"protocol": protocol, "port": port} for protocol, port in sorted({(item["protocol"], item["port"]) for host_ports in session["server_ports"].values() for item in host_ports})]
        if error:
            result["error"] = error
        session["discovery_results"][server["id"]] = result
        store._put(db, "sessions", session)


def collector_state(store, server, sessions, at):
    selected = [session for session in sessions if session["status"] == "active" and server["id"] in session["server_ids"] and parse_time(session["starts_at"]) <= at < parse_time(session["expires_at"])]
    supported = CAPABILITY in server.get("capabilities", [])
    ready = [session for session in selected if ports_for(session, server["id"]) and (session.get("selection_mode") != "discovered" or supported)]
    pending = [session for session in selected if session.get("selection_mode") == "discovered" and server["id"] in session.get("discovery_pending_server_ids", [])]
    stale = store._heartbeat_stale(server, at)
    reported = server.get("collector_status", "off")
    server["collector_desired_status"] = "learning" if ready else "off"
    server["learning_stop_pending"] = not ready and reported == "learning"
    server["collector_status_stale"] = stale
    server["collector_state"] = "unknown" if stale else reported
    server["learning_discovery_pending"] = bool(pending)
    if pending:
        result = pending[0].get("discovery_results", {}).get(server["id"], {})
        server["learning_discovery_status"] = "unsupported" if not supported else "offline" if stale else result.get("status", "pending")
        server["learning_discovery_error"] = result.get("error", "")
    elif selected and selected[0].get("selection_mode") == "discovered":
        server["learning_discovery_status"] = "unsupported" if not supported else selected[0].get("discovery_results", {}).get(server["id"], {}).get("status", "pending")
        server["learning_discovery_error"] = ""
    else:
        server["learning_discovery_status"] = "off"
        server["learning_discovery_error"] = ""
