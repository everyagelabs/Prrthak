"""Explicit synthetic fleet used only by --demo. Never touches an endpoint."""
from datetime import timedelta
import uuid

from .store import now, parse_time, stamp


SEEDED_SERVER_IDS = frozenset({
    "srv-web-01", "srv-web-02", "srv-api-01", "srv-api-02", "srv-db-01", "srv-db-02",
    "srv-bill-01", "srv-bill-02", "srv-lb-01", "srv-lb-02", "srv-dev-01", "srv-mon-01",
    "srv-cloud-01", "srv-cloud-02",
})


DEMO_LOCATIONS = {
    name: {"id": str(uuid.uuid5(uuid.NAMESPACE_URL, "prthak:demo:location:" + name)), "name": name, "location": place, "type": kind, "provider": provider, "region": region}
    for name, place, kind, provider, region in (
        ("Mumbai", "Mumbai, India · synthetic fixture", "datacenter", "", ""),
        ("Hyderabad", "Hyderabad, India · synthetic fixture", "datacenter", "", ""),
        ("Bengaluru", "Bengaluru, India · synthetic fixture", "datacenter", "", ""),
        ("Cloud region-1", "Cloud region-1 · synthetic fixture", "cloud", "other", "region-1"),
    )
}
DEMO_HOST_LOCATIONS = {
    **{identifier: "Mumbai" for identifier in ("srv-web-01", "srv-web-02", "srv-api-01", "srv-api-02", "srv-db-01", "srv-lb-01", "srv-mon-01")},
    **{identifier: "Hyderabad" for identifier in ("srv-db-02", "srv-bill-01", "srv-bill-02", "srv-lb-02")},
    "srv-dev-01": "Bengaluru", "srv-cloud-01": "Cloud region-1", "srv-cloud-02": "Cloud region-1",
}


def seed_locations(store):
    """Explicit named demo fixtures; never infer real locations from endpoint tags."""
    from .maintenance import seed_disabled
    if seed_disabled(store):
        return
    with store.lock, store.meta() as db:
        for value in DEMO_LOCATIONS.values():
            if not store._get(db, "locations", value["id"]):
                store._put(db, "locations", {**value, "key": "location:" + value["id"], "aliases": [value["name"]], "synthetic": True, "created_at": stamp(), "updated_at": stamp()})


def seed_cloud_hosts(store):
    """Add explicit demo cloud examples without changing existing enrolled agents."""
    from .maintenance import seed_disabled
    if seed_disabled(store):
        return
    for number in (1, 2):
        identifier = f"srv-cloud-{number:02}"
        if any(server["id"] == identifier for server in store.servers()):
            continue
        ssh_port = 2022 if number == 1 else 22
        store.report(identifier, {
            "hostname": f"cloud-{'orders' if number == 1 else 'billing'}-{number:02}",
            "ips": [f"10.60.20.{10 + number}"], "os": "ubuntu" if number == 1 else "rhel",
            "os_version": "24.04" if number == 1 else "9.4", "firewalld_state": "running",
            "firewalld_version": "2.1.1", "firewall_backend": "nftables", "apply_status": "preview",
            "discovery_interval_seconds": 900,
            "listeners": [
                {"port": ssh_port, "protocol": "tcp", "address": "0.0.0.0", "process": "sshd", "service": "ssh", "application": "OpenSSH", "systemd_unit": "ssh.service" if number == 1 else "sshd.service", "pid": 1201},
                {"port": 8080 if number == 1 else 8443, "protocol": "tcp", "address": "0.0.0.0", "process": "nginx" if number == 1 else "billing-api", "service": "nginx" if number == 1 else "billing-api", "application": "Nginx" if number == 1 else "Billing API", "systemd_unit": "nginx.service" if number == 1 else "billing-api.service", "pid": 1500},
            ],
        })
        store.update_server(identifier, {
            "location_id": DEMO_LOCATIONS["Cloud region-1"]["id"],
            "tags": {"application": "orders" if number == 1 else "billing", "cloud_provider": "other", "region": "region-1", "account": "demo-account", "network_zone": "production", "criticality": "high", "role": "api"},
            "expected_services": [{"port": ssh_port, "protocol": "tcp"}, {"port": 8080 if number == 1 else 8443, "protocol": "tcp"}],
        }, "demo.seed")



def synthetic_firewall_snapshot(server):
    """Exact synthetic inventory for UI review; never fabricates endpoint results."""
    from .firewall import normalize_snapshot
    ssh = next((item["port"] for item in server.get("listeners", []) if item.get("process") == "sshd"), 22)
    rules = []
    for scope in ("runtime", "permanent"):
        rules += [
            {"scope": scope, "zone": "public", "kind": "target", "value": "default", "editable": False},
            {"scope": scope, "zone": "public", "kind": "service", "value": "ssh", "ports": [{"port": str(ssh), "protocol": "tcp"}], "editable": True},
            {"scope": scope, "zone": "", "kind": "service_definition", "value": f"ssh\nports: {ssh}/tcp\nprotocols:\nsource-ports:", "editable": False},
        ]
        for listener in server.get("listeners", []):
            if listener.get("process") != "sshd":
                rules.append({"scope": scope, "zone": "public", "kind": "port", "value": f"{listener['port']}/{listener['protocol']}", "editable": True})
        if server["id"] in ("srv-web-01", "srv-web-02", "srv-api-01"):
            rules.append({"scope": scope, "zone": "public", "kind": "rich_rule", "value": 'rule family="ipv4" source address="192.0.2.0/24" log prefix="LEGACY_OBS: " limit value="5/m"', "editable": True})
        if server["id"] in ("srv-api-02", "srv-db-01"):
            rules.append({"scope": scope, "zone": "public", "kind": "rich_rule", "value": 'rule family="ipv4" source address="198.51.100.0/24" drop', "editable": True})
    result = normalize_snapshot({"status": "ok", "collected_at": stamp(), "rules": rules, "capabilities": ["synthetic-review-only", "runtime-zones", "permanent-zones"]})
    return {**result, "synthetic": True}


def synthetic_capture_coverage():
    """UI-only fixture facts; never claim a connected native capture backend."""
    return {"capture_backends":[{"backend":backend,"status":"unsupported","ipv4":False,"ipv6":False,"lost_events":None,"error":"Synthetic demo: no native capture backend is connected"} for backend in ("conntrack","nflog")],
            "capture_gaps":["Synthetic demo only; no kernel connections or denied packets are being captured"]}


def mark_synthetic_hosts(store):
    """Migrate only the known demo seed IDs; never mark arbitrary reported agents."""
    from .learning import TRAFFIC_SAMPLING_CAPABILITY
    from .maintenance import seed_disabled
    if seed_disabled(store):
        return
    with store.lock, store.meta() as db:
        for identifier in SEEDED_SERVER_IDS:
            server = store._get(db, "servers", identifier)
            if server:
                server["synthetic"] = True
                server["agent_version"] = "0.9.0-synthetic"
                server["capabilities"] = ["learning_discovery_v1", "traffic_capture_v1", TRAFFIC_SAMPLING_CAPABILITY]
                if server.get('learning_coverage'):server['learning_coverage'].update(synthetic_capture_coverage())
                server.setdefault("discovery_interval_seconds", 900)
                if not server.get("firewall_snapshot"):
                    server["firewall_snapshot"] = synthetic_firewall_snapshot(server)
                server.setdefault("security_monitor", {"enabled": False, "status": "off", "error": "", "rate_limited": True, "dropped_events": 0})
                tags = server.setdefault("tags", {})
                if not server.get("_demo_location_migrated"):
                    if not server.get("location_id"):
                        server["location_id"] = DEMO_LOCATIONS[DEMO_HOST_LOCATIONS[identifier]]["id"]
                    from .locations import reserved
                    server["tags"] = {key: val for key, val in tags.items() if not reserved(key)}
                    server["_demo_location_migrated"] = True
                for listener in server.get("listeners", []):
                    process = listener.get("process", "")
                    listener.setdefault("service", "ssh" if process == "sshd" else process)
                    listener.setdefault("application", {"sshd": "OpenSSH", "nginx": "Nginx", "postgres": "PostgreSQL"}.get(process, process))
                    listener.setdefault("systemd_unit", ("ssh.service" if server.get("os") == "ubuntu" else "sshd.service") if process == "sshd" else ("postgresql.service" if process == "postgres" else f"{process}.service"))
                    listener.setdefault("first_seen", server.get("last_discovery_at", server["created_at"]))
                    listener.setdefault("last_seen", server.get("last_discovery_at", server["created_at"]))
                    listener.setdefault("is_new", False)
                store._put(db, "servers", server)


def tick_synthetic_hosts(store, at=None):
    """Refresh explicit demo scenarios. Caller must invoke only in --demo mode."""
    from .maintenance import seed_disabled
    if seed_disabled(store):
        return
    from .learning import acknowledge_discovery, ports_for
    at = at or now()
    with store.lock, store.meta() as db:
        sessions = store._all(db, "sessions")
        for identifier in SEEDED_SERVER_IDS:
            server = store._get(db, "servers", identifier)
            if not server or server.get("synthetic") is not True:
                continue
            offline = identifier == "srv-db-02"
            server["last_seen"] = stamp(at - timedelta(minutes=8) if offline else at)
            if identifier == "srv-api-02":
                server["apply_status"] = "error"
                server["applied_version"] = max(0, server.get("desired_version", 0) - 1)
                server["apply_error"] = "Unrestricted 8080/tcp opening conflicts with source policy; enforcement refused."
            else:
                server["applied_version"] = server.get("desired_version", 0)
                server["apply_status"] = "synced"
                server["apply_error"] = ""
            active = [session for session in sessions if session["status"] == "active" and identifier in session["server_ids"] and parse_time(session["starts_at"]) <= at < parse_time(session["expires_at"])]
            # Only named synthetic fixtures may simulate a fresh request. Never
            # fabricate scan acknowledgement for an arbitrary reported endpoint.
            if not offline:
                for session in active:
                    if identifier in session.get("discovery_pending_server_ids", []):
                        acknowledge_discovery(store, db, server, {"discovery_performed": True, "discovered_at": stamp(at)}, [session["id"]], server.get("listeners", []), stamp(at), at)
                        server["last_discovery_at"] = stamp(at)
                        server["discovered_at"] = stamp(at)
                        server["discovery_error"] = ""
                        server["discovery_performed"] = True
            active = [store._get(db, "sessions", session["id"]) for session in active]
            active = [session for session in active if ports_for(session, identifier)]
            server["collector_status"] = "learning" if active and not offline else "off"
            if active and not offline:
                session = active[0]
                server["last_learning_at"] = session["starts_at"]
                coverage = server.get("learning_coverage", {})
                if coverage.get("session_id") != session["id"]:
                    server["learning_coverage"] = {"session_id": session["id"], "started_at": stamp(max(at, parse_time(session["starts_at"]))), "dropped_events": 0, "rate_limited": True, "error": "Synthetic demo: no native capture backend is connected", **synthetic_capture_coverage()}
            if not offline and (not server.get("last_discovery_at") or (at - parse_time(server["last_discovery_at"])).total_seconds() >= server.get("discovery_interval_seconds", 900)):
                server["last_discovery_at"] = stamp(at)
                server["discovered_at"] = stamp(at)
                server["discovery_error"] = ""
                server["discovery_performed"] = True
                server["discovery_changes"] = []
                if server.get("firewall_snapshot", {}).get("synthetic"):
                    server["firewall_snapshot"]["collected_at"] = stamp(at)
                for listener in server.get("listeners", []):
                    listener["last_seen"] = stamp(at)
            store._collector_state(server, store._all(db, "sessions"), at)
            store._put(db, "servers", server)


def seed_traffic_discovery(store):
    from .learning import TRAFFIC_PURPOSE, evidence_expiry

    session_id, server_id = "discover-traffic-billing", "srv-bill-01"
    at = now()
    end = at - timedelta(minutes=1)
    port = {"port": 8443, "protocol": "tcp"}
    with store.lock, store.meta() as db:
        baseline = store._get(db, "sessions", "learn-payments-web") or {}
        server = store._get(db, "servers", server_id) or {}
        if baseline.get("created_by") != "demo.seed" or not server.get("synthetic") or store._get(db, "sessions", session_id):
            return False
        store._put(db, "sessions", {
            "id": session_id, "name": "Billing API traffic · synthetic", "server_ids": [server_id],
            "purpose": TRAFFIC_PURPOSE, "policy_action": "observe", "traffic_collection_mode": "hits",
            "selection_mode": "manual", "ports": [port], "status": "expired", "synthetic": True,
            "starts_at": stamp(at-timedelta(minutes=18)), "expires_at": stamp(end),
            "ended_at": stamp(end), "evidence_expires_at": evidence_expiry(end), "created_by": "demo.seed",
        })
    for index, (source, count) in enumerate((("10.24.20.21", 31), ("10.32.5.10", 12), ("192.0.2.54", 4))):
        observed = stamp(at - timedelta(minutes=5 + 2 * index))
        store.enqueue_flows(server_id, {
            "batch_id": f"demo-traffic-{index}", "session_id": session_id,
            "events": [{**port, "source_ip": source, "count": count, "first_seen": observed, "last_seen": observed}],
        })
    return True


def seed(store):
    from .maintenance import seed_disabled
    if seed_disabled(store):
        return
    seed_locations(store)
    if store.all("servers"):
        seed_cloud_hosts(store)
        mark_synthetic_hosts(store)
        if seed_traffic_discovery(store):
            store.process_flows()
        return
    records = [
        ("srv-web-01", "pay-web-01", "10.24.10.11", "rhel", "9.4", "payments", "Mumbai", "production", "web", [22, 80, 443]),
        ("srv-web-02", "pay-web-02", "10.24.10.12", "ubuntu", "24.04", "payments", "Mumbai", "production", "web", [22, 80, 443]),
        ("srv-api-01", "pay-api-01", "10.24.20.21", "rhel", "9.4", "payments", "Mumbai", "production", "api", [22, 8080]),
        ("srv-api-02", "pay-api-02", "10.24.20.22", "ubuntu", "22.04", "payments", "Mumbai", "production", "api", [22, 8080]),
        ("srv-db-01", "pay-db-01", "10.24.30.31", "rhel", "8.10", "payments", "Mumbai", "production", "database", [22, 5432]),
        ("srv-db-02", "pay-db-02", "10.24.30.32", "rhel", "9.4", "payments", "Hyderabad", "production", "database", [22, 5432]),
        ("srv-bill-01", "billing-api-01", "10.32.20.11", "ubuntu", "24.04", "billing", "Hyderabad", "production", "api", [22, 8443]),
        ("srv-bill-02", "billing-api-02", "10.32.20.12", "rhel", "9.4", "billing", "Hyderabad", "production", "api", [22]),
        ("srv-lb-01", "edge-lb-01", "10.24.5.10", "rhel", "9.4", "platform", "Mumbai", "dmz", "load-balancer", [22, 80, 443]),
        ("srv-lb-02", "edge-lb-02", "10.32.5.10", "ubuntu", "24.04", "platform", "Hyderabad", "dmz", "load-balancer", [22, 80, 443]),
        ("srv-dev-01", "orders-dev-01", "10.40.10.11", "ubuntu", "24.04", "orders", "Bengaluru", "development", "web", [22, 3000]),
        ("srv-mon-01", "observability-01", "10.24.40.10", "rhel", "9.4", "platform", "Mumbai", "management", "monitoring", [22, 9090]),
    ]
    for index, (identifier, hostname, ip, os_name, version, app, dc, zone, role, ports) in enumerate(records):
        listeners = [{"port": port, "protocol": "tcp", "address": "0.0.0.0", "process": {22: "sshd", 80: "nginx", 443: "nginx", 8080: "payment-api", 8443: "billing-api", 5432: "postgres", 9090: "prometheus", 3000: "node"}.get(port, "service")} for port in ports]
        for listener in listeners:
            process = listener["process"]
            listener.update({"service": "ssh" if process == "sshd" else process, "application": {"sshd": "OpenSSH", "nginx": "Nginx", "postgres": "PostgreSQL"}.get(process, process), "systemd_unit": ("ssh.service" if os_name == "ubuntu" else "sshd.service") if process == "sshd" else ("postgresql.service" if process == "postgres" else f"{process}.service"), "pid": 1000 + listener["port"] % 1000})
        store.report(identifier, {"hostname": hostname, "ips": [ip], "os": os_name, "os_version": version, "firewalld_version": "1.3.4" if os_name == "rhel" else "2.1.1", "firewall_backend": "nftables", "firewalld_state": "running", "listeners": listeners, "applied_version": 0, "apply_status": "preview", "collector_status": "off"})
        store.update_server(identifier, {"location_id": DEMO_LOCATIONS[dc]["id"], "tags": {"application": app, "network_zone": zone, "criticality": "high" if zone == "production" else "medium", "role": role}, "expected_services": [{"port": port, "protocol": "tcp"} for port in ports + ([8443] if identifier == "srv-bill-02" else [])]}, "demo.seed")
    policies = [
        {"name": "Management · SSH access", "selector": {}, "mode": "monitor", "services": [{"port": 22, "protocol": "tcp", "sources": ["10.24.40.0/24", "10.99.0.0/24"]}]},
        {"name": "Payments · Web tier", "selector": {"application": "payments", "role": "web"}, "mode": "enforce", "services": [{"port": 80, "protocol": "tcp", "sources": [], "source_selector": {"role": "load-balancer"}}, {"port": 443, "protocol": "tcp", "sources": [], "source_selector": {"role": "load-balancer"}}]},
        {"name": "Payments · API tier", "selector": {"application": "payments", "role": "api"}, "mode": "enforce", "services": [{"port": 8080, "protocol": "tcp", "sources": [], "source_selector": {"application": "payments", "role": "web"}}]},
        {"name": "Payments · Database tier", "selector": {"role": "database"}, "mode": "enforce", "services": [{"port": 5432, "protocol": "tcp", "sources": [], "source_selector": {"application": "payments", "role": "api"}}]},
        {"name": "Billing · Discovery baseline", "selector": {"application": "billing"}, "mode": "monitor", "services": [{"port": 8443, "protocol": "tcp", "sources": ["10.24.20.0/24"]}]},
    ]
    for policy in policies:
        store.save_policy(policy, "demo.seed")
    seed_cloud_hosts(store)
    mark_synthetic_hosts(store)
    with store.lock, store.meta() as db:
        for server in store._all(db, "servers"):
            server["synthetic"] = server["id"] in SEEDED_SERVER_IDS
            server["applied_version"] = server["desired_version"]
            server["apply_status"] = "synced"
            server["last_seen"] = stamp(now() - timedelta(seconds=15))
            if server["id"] == "srv-api-02":
                server["apply_status"] = "error"
                server["applied_version"] -= 1
                server["apply_error"] = "Unrestricted 8080/tcp opening conflicts with source policy; enforcement refused."
            if server["id"] == "srv-db-02":
                server["last_seen"] = stamp(now() - timedelta(minutes=8))
            store._put(db, "servers", server)
        session = {"id": "learn-payments-web", "server_ids": ["srv-web-01", "srv-web-02", "srv-api-01"], "ports": [{"port": 80, "protocol": "tcp"}, {"port": 443, "protocol": "tcp"}, {"port": 8080, "protocol": "tcp"}, {"port": 22, "protocol": "tcp"}], "starts_at": stamp(now() - timedelta(minutes=48)), "expires_at": stamp(now() + timedelta(minutes=72)), "status": "active", "created_by": "demo.seed"}
        store._put(db, "sessions", session)
        historical = {"id": "learn-billing-baseline", "server_ids": ["srv-bill-01"], "ports": [{"port": 8443, "protocol": "tcp"}], "starts_at": stamp(now() - timedelta(hours=3)), "expires_at": stamp(now() - timedelta(hours=1)), "status": "expired", "created_by": "demo.seed"}
        store._put(db, "sessions", historical)
        for identifier in session["server_ids"]:
            server = store._get(db, "servers", identifier)
            server["collector_status"] = "learning"
            server["last_learning_at"] = session["starts_at"]
            server["learning_coverage"] = {"session_id": session["id"], "started_at": session["starts_at"], "dropped_events": 0}
            store._put(db, "servers", server)
    sources = ["10.24.5.10", "10.32.5.10", "10.24.40.18", "10.99.0.12", "192.0.2.87", "198.51.100.44"]
    for index in range(36):
        identifier = ["srv-web-01", "srv-web-02", "srv-api-01"][index % 3]
        source = sources[index % len(sources)]
        port = 8080 if identifier == "srv-api-01" else [80, 443, 22][index % 3]
        event_time = now() - timedelta(minutes=1 + index)
        store.enqueue_flows(identifier, {"batch_id": f"demo-{index}", "session_id": session["id"], "events": [{"source_ip": source, "port": port, "protocol": "tcp", "verdict": "denied" if source.startswith(("192.0.2.", "198.51.100.")) else "allowed", "count": 12 + (index * 71) % 1800, "first_seen": stamp(event_time - timedelta(minutes=2)), "last_seen": stamp(event_time)}]})
    seed_traffic_discovery(store)
    store.process_flows()
    store.evaluate_health()
    store.audit("demo.initialized", "system", {"synthetic": True, "servers": len(records)})
