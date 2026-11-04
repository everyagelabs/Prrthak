"""Imported firewall inventory and explicitly reviewed bulk operations.

This controller drafts operations only; an opted-in endpoint remains the sole
executor and must check its exact snapshot again before changing anything.
"""
import hashlib
import ipaddress
import re
import secrets
import shlex
import uuid
from datetime import timedelta

from .store import digest, now, parse_time, stamp


class WorkflowConflict(ValueError):
    def __init__(self, message, plan=None):
        super().__init__(message)
        self.plan = plan


EXTENDED_CAPABILITIES = {"target": "imported_zone_target_v1", "forward_port": "imported_nat_v1", "direct": "imported_direct_v1"}


def direct_fields(value):
    """A deliberately small INPUT filter grammar, passed as argv by endpoints."""
    fields = value.split()
    if any(char in value for char in "'\";`$\\") or len(fields) < 10 or fields[0] not in ("ipv4", "ipv6") or fields[1:3] != ["filter", "INPUT"]:
        raise ValueError("Direct editing supports numeric TCP/UDP INPUT filter rules only")
    if not re.fullmatch(r"\d{1,5}", fields[3]) or not 0 <= int(fields[3]) <= 32767:
        raise ValueError("Direct rule priority must be 0..32767")
    options = {}
    for index in range(4, len(fields), 2):
        if index + 1 >= len(fields) or fields[index] not in ("-s", "-p", "-m", "--dport", "-j") or fields[index] in options:
            raise ValueError("Unsupported or duplicate direct-rule option")
        options[fields[index]] = fields[index + 1]
    if options.get("-p") not in ("tcp", "udp") or options.get("-j") not in ("ACCEPT", "DROP", "REJECT") or "--dport" not in options:
        raise ValueError("Direct rule requires TCP/UDP, a destination port and ACCEPT/DROP/REJECT")
    if "-m" in options and options["-m"] != options["-p"]:
        raise ValueError("Direct match module must equal the transport")
    typed_value("port", options["--dport"].replace(":", "-") + "/" + options["-p"])
    if "-s" in options:
        try:
            source = ipaddress.ip_network(options["-s"], strict=False)
        except ValueError:
            raise ValueError("Direct source must be a numeric IP or CIDR")
        if (source.version == 4) != (fields[0] == "ipv4"):
            raise ValueError("Direct source family does not match")
    return options


def extended_identity(kind, value):
    """Semantic identity prevents textual add/remove aliases deleting themselves."""
    if kind == "direct":
        fields, options = value.split(), direct_fields(value)
        first, _, last = options["--dport"].replace(":", "-").partition("-")
        source = str(ipaddress.ip_network(options.get("-s", "0.0.0.0/0" if fields[0] == "ipv4" else "::/0"), strict=False))
        return (fields[0], int(fields[3]), source, options["-p"], int(first), int(last or first), options["-j"])
    if kind == "forward_port":
        typed_value(kind, value)
        fields = dict(part.split("=", 1) for part in value.split(":"))
        first, _, last = fields["port"].partition("-")
        return (int(first), int(last or first), fields["proto"], int(fields["toport"]))
    return value


def fingerprints(scope, zone, kind, value):
    logical = hashlib.sha256("\0".join((zone, kind, value)).encode()).hexdigest()
    full = hashlib.sha256("\0".join((scope, zone, kind, value)).encode()).hexdigest()
    return full, logical


def rich_tokens(value):
    try:
        tokens = shlex.split(value)
    except ValueError:
        raise ValueError("Rich rule has unbalanced quotes")
    if not tokens or tokens[0] != "rule" or len(tokens) > 120:
        raise ValueError("A bounded rich rule must start with rule")
    return tokens


def classify(kind, value):
    if kind == "direct":
        try:
            return direct_fields(value)["-j"].lower(), "high"
        except ValueError:
            return "unknown", "high"
    if kind == "forward_port":
        return "redirect", "high"
    if kind in ("service", "port"):
        return "accept", "high" if kind == "port" and re.fullmatch(r"1-65535/(tcp|udp|sctp|dccp)", value) else "low"
    if kind == "rich_rule":
        try:
            tokens = rich_tokens(value)
        except ValueError:
            return "unknown", "medium"
        if "drop" in tokens:
            return "drop", "high"
        if "reject" in tokens:
            return "reject", "high"
        if "accept" in tokens:
            if any(token == "port=1-65535" for token in tokens):
                return "accept", "high"
            if "port" not in tokens and "service" not in tokens:
                source_value = None
                if "source" in tokens:
                    tail = tokens[tokens.index("source") + 1:]
                    for token in tail:
                        if token in ("destination", "service", "port", "log", "audit", "accept"):
                            break
                        if token.startswith("address="):
                            source_value = token.split("=", 1)[1]
                        elif token.startswith("ipset="):
                            source_value = "ipset"
                if source_value is None:
                    return "accept", "high"
                if source_value != "ipset":
                    try:
                        if ipaddress.ip_network(source_value, strict=False).prefixlen == 0:
                            return "accept", "high"
                    except ValueError:
                        return "accept", "high"
                return "accept", "medium"
            return "accept", "low"
        if "log" in tokens or "audit" in tokens:
            return "log", "low"
        return "unknown", "medium"
    if kind in ("target", "zone_target", "policy_target", "icmp_block"):
        if value.upper() in ("DROP", "REJECT") or kind == "icmp_block":
            return "drop" if value.upper() != "REJECT" else "reject", "high"
        if value.upper() == "ACCEPT":
            return "accept", "high"
    if re.search(r"\b(?:DROP|REJECT)\b", value, re.IGNORECASE):
        return "drop" if re.search(r"\bDROP\b", value, re.IGNORECASE) else "reject", "high"
    return "unknown", "medium"


def typed_value(kind, value):
    if not isinstance(value, str) or not value or len(value) > 2048 or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("Rule value must be a bounded, single-line string")
    if kind == "service":
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value):
            raise ValueError("Invalid firewalld service name")
    elif kind == "port":
        match = re.fullmatch(r"(\d+)(?:-(\d+))?/(tcp|udp)", value)
        if not match or not 1 <= int(match[1]) <= int(match[2] or match[1]) <= 65535:
            raise ValueError("Port must be PORT[/tcp|/udp] or START-END/protocol")
    elif kind == "rich_rule":
        tokens = rich_tokens(value)
        words = {"rule", "source", "destination", "not", "service", "port", "log", "audit", "limit", "accept", "drop", "reject"}
        keys = {"family", "priority", "address", "ipset", "name", "port", "protocol", "prefix", "level", "value", "type"}
        if any((token.split("=", 1)[0] not in keys if "=" in token else token not in words) for token in tokens):
            raise ValueError("This rich-rule feature is view-only in the current bulk editor")
        assignments = [token.split("=", 1) for token in tokens if "=" in token]
        family = next((val for key, val in assignments if key == "family"), None)
        if family is not None and family not in ("ipv4", "ipv6"):
            raise ValueError("Rich rule family must be ipv4 or ipv6")
        for key, val in assignments:
            if key == "port":
                typed_value("port", val + "/tcp")
            elif key == "protocol" and val not in ("tcp", "udp"):
                raise ValueError("Bulk rich-rule transport must be tcp or udp")
            elif key == "priority":
                if not re.fullmatch(r"-?\d+", val) or int(val) != 0:
                    raise ValueError("Nonzero-priority rich rules require manual review")
            elif key == "address":
                try:
                    network = ipaddress.ip_network(val, strict=False)
                except ValueError:
                    raise ValueError("Rich rule address must be numeric IP or CIDR")
                if family not in ("ipv4", "ipv6") or (network.version == 4) != (family == "ipv4"):
                    raise ValueError("Rich rule address family must be explicit and match its source")
            elif key in ("name", "ipset") and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", val):
                raise ValueError("Invalid rich-rule service or IP-set name")
        if sum(token in ("accept", "drop", "reject") for token in tokens) > 1:
            raise ValueError("Rich rule must have at most one terminal action")
        if not any(token in ("accept", "drop", "reject", "log", "audit") for token in tokens):
            raise ValueError("Rich rule requires a supported action")
    elif kind == "target":
        if value not in ("ACCEPT", "DROP", "REJECT", "default"):
            raise ValueError("Zone target must be ACCEPT, DROP, REJECT or default")
    elif kind == "forward_port":
        match = re.fullmatch(r"port=(\d+(?:-\d+)?):proto=(tcp|udp):toport=(\d+):toaddr=", value)
        if not match:
            raise ValueError("NAT editing supports local redirects only: port=N:proto=tcp|udp:toport=N:toaddr=")
        typed_value("port", match[1] + "/" + match[2])
        typed_value("port", match[3] + "/" + match[2])
    elif kind == "direct":
        direct_fields(value)
    else:
        raise ValueError("This rule kind is view-only")
    return value



def normalize_ports(values):
    if not isinstance(values, list) or len(values) > 256:
        raise ValueError("Resolved service ports must be a bounded list")
    result = {}
    for value in values:
        if not isinstance(value, dict):
            raise ValueError("Invalid resolved service port")
        port, protocol = value.get("port"), value.get("protocol")
        if isinstance(port, bool) or not isinstance(port, (int, str)) or not isinstance(protocol, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,15}", protocol):
            raise ValueError("Invalid resolved service transport")
        text = str(port)
        match = re.fullmatch(r"(\d+)(?:-(\d+))?", text)
        if not match or not 1 <= int(match[1]) <= int(match[2] or match[1]) <= 65535:
            raise ValueError("Invalid resolved service port range")
        result[(text, protocol)] = {"port": text, "protocol": protocol}
    return [result[key] for key in sorted(result)]


def resolved_ports(kind, text, provided):
    if provided:
        return normalize_ports(provided)
    if kind == "port" and "/" in text:
        port, protocol = text.rsplit("/", 1)
        try:
            return normalize_ports([{"port": port, "protocol": protocol}])
        except ValueError:
            return []
    if kind in ("direct", "forward_port"):
        try:
            if kind == "direct":
                options = direct_fields(text)
                port, protocol = options["--dport"].replace(":", "-"), options["-p"]
            else:
                typed_value(kind, text)
                fields = dict(part.split("=", 1) for part in text.split(":"))
                port, protocol = fields["port"], fields["proto"]
            return normalize_ports([{"port": port, "protocol": protocol}])
        except ValueError:
            return []
    if kind == "rich_rule":
        try:
            tokens = rich_tokens(text)
            port = next((token.split("=", 1)[1] for token in tokens if token.startswith("port=")), None)
            protocol = next((token.split("=", 1)[1] for token in tokens if token.startswith("protocol=")), None)
            return normalize_ports([{"port": port, "protocol": protocol}]) if port and protocol else []
        except ValueError:
            return []
    return []


def normalize_snapshot(value):
    if not isinstance(value, dict):
        raise ValueError("firewall_snapshot must be an object")
    status = value.get("status")
    if status not in ("ok", "partial", "error"):
        raise ValueError("Invalid firewall snapshot status")
    collected = parse_time(value.get("collected_at"))
    if collected > now() + timedelta(seconds=60):
        raise ValueError("Firewall snapshot timestamp is in the future")
    rules = value.get("rules", [])
    if not isinstance(rules, list) or len(rules) > 4000:
        raise ValueError("Firewall inventory is limited to 4000 rule entries")
    error = value.get("error", "")
    capabilities = value.get("capabilities", [])
    if not isinstance(error, str) or len(error) > 4096 or not isinstance(capabilities, list) or len(capabilities) > 100 or any(not isinstance(item, str) or len(item) > 128 for item in capabilities):
        raise ValueError("Invalid firewall inventory coverage metadata")
    normalized = {}
    for rule in rules:
        if not isinstance(rule, dict):
            raise ValueError("Rule inventory entries must be objects")
        scope, zone, kind, text = (rule.get(key, "") for key in ("scope", "zone", "kind", "value"))
        if scope not in ("runtime", "permanent") or not isinstance(zone, str) or len(zone) > 128 or (zone and not re.fullmatch(r"[A-Za-z0-9_.-]+", zone)) or not isinstance(kind, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", kind) or not isinstance(text, str) or len(text) > 4096 or any((ord(char) < 32 and char not in "\n\r\t") or ord(char) == 127 for char in text):
            raise ValueError("Invalid imported firewall rule")
        fingerprint, logical = fingerprints(scope, zone, kind, text)
        action, risk = classify(kind, text)
        editable, reason = False, "This rule kind or scope is view-only"
        supported = kind in ("service", "port", "rich_rule") and bool(zone)
        if kind in EXTENDED_CAPABILITIES:
            supported = EXTENDED_CAPABILITIES[kind] in capabilities and (not zone if kind == "direct" else bool(zone))
            if kind == "target" and scope != "permanent":
                supported = False
        if supported and rule.get("editable") is True:
            try:
                typed_value(kind, text)
                editable, reason = True, ""
            except ValueError as failure:
                reason = str(failure)
        elif kind in ("service", "port", "rich_rule") or kind in EXTENDED_CAPABILITIES:
            reason = str(rule.get("reason", "Endpoint has marked this entry view-only"))[:512]
            if kind == "target" and scope != "permanent":
                reason = "Runtime zone targets require a broader firewalld reload; only exact permanent target replacement is supported"
        normalized[fingerprint] = {"fingerprint": fingerprint, "logical_key": logical, "scope": scope, "zone": zone, "kind": kind, "value": text, "action": action, "risk": risk, "editable": editable, "reason": reason, "ports": resolved_ports(kind, text, rule.get("ports", []))}
    ordered = [normalized[key] for key in sorted(normalized)]
    snapshot_digest = hashlib.sha256("\n".join(sorted(normalized)).encode()).hexdigest()
    return {"collected_at": stamp(collected), "status": status, "digest": snapshot_digest, "rules": ordered, "error": error, "capabilities": sorted(set(capabilities))}


def ingest_snapshot(server, value):
    snapshot = normalize_snapshot(value)
    old = server.get("firewall_snapshot")
    if old and parse_time(snapshot["collected_at"]) < parse_time(old.get("last_attempt_at", old["collected_at"])):
        return
    if old and snapshot["status"] != "ok":
        server["firewall_snapshot"] = {**old, "status": snapshot["status"], "error": snapshot["error"] or "Firewall inventory collection incomplete", "last_attempt_at": snapshot["collected_at"], "reported_rule_count": len(snapshot["rules"])}
    elif old and parse_time(snapshot["collected_at"]) < parse_time(old["collected_at"]):
        return
    else:
        snapshot["last_attempt_at"] = snapshot["collected_at"]
        server["firewall_snapshot"] = snapshot


def snapshot_view(server):
    snapshot = server.get("firewall_snapshot")
    if not snapshot:
        return {"status": "missing", "rules": [], "stale": True, "error": "No firewall inventory received"}
    limit = max(1800, 2 * server.get("discovery_interval_seconds", 900))
    return {**snapshot, "stale": (now() - parse_time(snapshot["collected_at"])).total_seconds() > limit}


def target_digest(server):
    configuration = server.get("configuration_state", {})
    return digest({"id": server["id"], "hostname": server.get("hostname"), "ips": server.get("ips", []), "tags": server.get("tags", {}),
                   "protection_digest": server.get("protection_digest", ""),
                   "extended_capabilities": sorted(set(server.get("capabilities", [])) & set(EXTENDED_CAPABILITIES.values())),
                   "configuration": {key: configuration.get(key, "") for key in ("config_digest", "controller_url", "control_url", "discovery_url")}})


def public_plan(plan):
    return {key: value for key, value in plan.items() if not key.startswith("_")}


def plan_drift(store, db, plan):
    for identifier in plan["server_ids"]:
        server = store._get(db, "servers", identifier)
        if not server:
            return "A selected endpoint no longer exists"
        snapshot = snapshot_view(server)
        if snapshot.get("status") != "ok" or snapshot.get("stale") or snapshot.get("digest") != plan["snapshot_digests"][identifier]:
            return "Firewall inventory changed or is unavailable; create a fresh preview"
        if target_digest(server) != plan["target_digests"][identifier]:
            return "Selected endpoint identity or tags changed; create a fresh preview"
    return None


def refresh_plans(store, db):
    for plan in store._all(db, "firewall_changes"):
        if plan["status"] in ("draft", "awaiting_second_confirmation", "queued"):
            problem = "Review or delivery window expired" if parse_time(plan["expires_at"]) <= now() else None
            if not problem and plan["status"] in ("draft", "awaiting_second_confirmation"):
                problem = plan_drift(store, db, plan)
            if problem:
                plan["status"] = "expired" if parse_time(plan["expires_at"]) <= now() else "invalidated"
                plan["confirmation_nonce"] = ""
                plan["error"] = problem
                store._put(db, "firewall_changes", plan)
                store.audit("firewall_change." + plan["status"], "system", {"change_id": plan["id"], "reason": problem}, db)


def inventory(store, selected=None, **options):
    from .firewall_views import inventory as view
    return view(store, selected, **options)



def replacement_ports(snapshot, rule, new_value):
    direct = resolved_ports(rule["kind"], new_value, [])
    if direct:
        return direct
    service = new_value if rule["kind"] == "service" else None
    if rule["kind"] == "rich_rule":
        try:
            tokens = rich_tokens(new_value)
            service = next((token.split("=", 1)[1] for token in tokens if token.startswith("name=")), None) if "service" in tokens else None
        except ValueError:
            pass
    if service:
        candidates = [candidate["ports"] for candidate in snapshot["rules"] if candidate["kind"] == "service" and candidate["value"] == service and candidate["scope"] == rule["scope"] and candidate.get("ports")]
        if candidates and all(candidate == candidates[0] for candidate in candidates):
            return candidates[0]
    return []


def create_change(store, value, actor, *, principal=None):
    name = value.get("name", "")
    ids, key, scopes = value.get("server_ids"), value.get("rule_key"), value.get("scopes", ["runtime", "permanent"])
    operation = value.get("operation")
    if not isinstance(name, str) or not name.strip() or len(name) > 120 or not isinstance(ids, list) or not ids or len(ids) > 20000 or any(not isinstance(item, str) for item in ids):
        raise ValueError("Provide a name and explicit enrolled endpoint IDs")
    if not isinstance(key, str) or not re.fullmatch(r"[a-f0-9]{64}", key) or operation not in ("replace", "remove") or not isinstance(scopes, list) or not scopes or set(scopes) - {"runtime", "permanent"}:
        raise ValueError("Invalid exact rule key, operation or scopes")
    ids, scopes = sorted(set(ids)), sorted(set(scopes))
    with store.lock, store.meta() as db:
        operations, snapshots, targets, before, after, unmatched = {}, {}, {}, [], [], []
        risky = False
        for identifier in ids:
            server = store._get(db, "servers", identifier)
            if not server:
                raise ValueError("Selected endpoint does not exist")
            from .host_default_deny import guarded
            if guarded(server):raise ValueError("Disable whole-server deny through its acknowledged flow before imported-rule mutations")
            from . import approvals
            if not approvals.signed_target(store, server):
                raise ValueError("Upgrade the endpoint to signed_assignments_v1 before imported-rule mutations")
            snapshot = snapshot_view(server)
            if snapshot["status"] != "ok" or snapshot["stale"]:
                raise ValueError("Every selected endpoint requires a fresh complete firewall inventory")
            snapshots[identifier], targets[identifier] = snapshot["digest"], target_digest(server)
            risky = risky or any(rule["action"] in ("drop", "reject") for rule in snapshot["rules"])
            selected_rules = [rule for rule in snapshot["rules"] if rule["logical_key"] == key and rule["scope"] in scopes]
            if not selected_rules:
                unmatched.append(identifier)
                continue
            commands = []
            for rule in selected_rules:
                if not rule["editable"]:
                    raise ValueError("Selected rule is view-only on one or more endpoints")
                if rule["kind"] in EXTENDED_CAPABILITIES:
                    capability = EXTENDED_CAPABILITIES[rule["kind"]]
                    if capability not in server.get("capabilities", []) or capability not in snapshot.get("capabilities", []):
                        raise ValueError("Upgrade the endpoint to " + capability + " before this imported-rule mutation")
                    if rule["kind"] == "target" and (rule["scope"] != "permanent" or operation != "replace"):
                        raise ValueError("Zone targets support permanent replacement only; a zone target cannot be removed")
                    if rule["kind"] == "direct":
                        if not {"runtime-direct-visible", "permanent-direct-visible"} <= set(snapshot.get("capabilities", [])):
                            raise ValueError("Direct editing requires complete runtime and permanent direct inventories")
                    elif not all(any(candidate["kind"] == "target" and candidate["zone"] == rule["zone"] and candidate["scope"] == scope for candidate in snapshot["rules"]) for scope in ("runtime", "permanent")):
                        raise ValueError("Extended zone editing requires matching runtime and permanent zone evidence")
                    risky = True
                new_value = typed_value(rule["kind"], value.get("new_value")) if operation == "replace" else ""
                new_action = classify(rule["kind"], new_value)[0] if operation == "replace" else ""
                if operation == "replace" and new_value == rule["value"]:
                    raise ValueError("Replacement must differ from the current rule")
                if operation == "replace" and rule["kind"] in EXTENDED_CAPABILITIES and extended_identity(rule["kind"], new_value) == extended_identity(rule["kind"], rule["value"]):
                    raise ValueError("Replacement is only a textual alias of the current rule")
                risky = risky or rule["action"] in ("accept", "unknown") or new_action in ("drop", "reject", "unknown")
                commands.append({"scope": rule["scope"], "zone": rule["zone"], "kind": rule["kind"], "old_value": rule["value"], "new_value": new_value, "operation": operation})
                row = {"server_id": identifier, "hostname": server["hostname"], "scope": rule["scope"], "zone": rule["zone"], "kind": rule["kind"], "value": rule["value"], "ports": rule.get("ports", [])}
                before.append(row)
                if operation == "replace":
                    after.append({**row, "value": new_value, "ports": replacement_ports(snapshot, rule, new_value)})
            operations[identifier] = commands
        if not operations:
            raise ValueError("No selected endpoints contain the exact selected rule in these scopes")
        identifier = str(uuid.uuid4())
        immutable = {"id": identifier, "name": name.strip(), "server_ids": ids, "snapshot_digests": snapshots, "target_digests": targets, "operations_by_server": operations, "rule_key": key, "scopes": scopes, "requires_double_confirmation": bool(risky)}
        plan_digest = digest(immutable)
        plan = {**immutable, "plan_digest": plan_digest, "status": "draft", "confirmation_count": 0, "confirmation_nonce": secrets.token_urlsafe(24), "confirmation_phrase": "CONFIRM " + plan_digest[:12], "created_at": stamp(), "created_by": actor, "expires_at": stamp(now() + timedelta(minutes=10)), "results": {}, "preview": {"matched_host_count": len(operations), "unmatched_host_count": len(unmatched), "unmatched_server_ids": unmatched, "before": before, "after": after, "impact": "Access rules may be removed or changed; management connectivity must be reviewed" if risky else "Observation-only rule changes; review all exact matches"}}
        if any(row["kind"] == "target" for row in before):
            plan["preview"]["warnings"] = ["Only the permanent zone target is replaced. The running target remains unchanged; this plan performs no firewalld reload."]
        from . import approvals
        approvals.request(store, db, plan, actor, principal, endpoint_ids=sorted(operations), scope_kind="imported_firewall")
        store._put(db, "firewall_changes", plan)
        store.audit("firewall_change.drafted", actor, {"change_id": identifier, "plan_digest": plan_digest, "server_ids": ids, "requires_double_confirmation": risky}, db)
        return public_plan(plan)


def confirm_change(store, identifier, value, actor, *, principal=None):
    problem = None
    with store.lock, store.meta() as db:
        refresh_plans(store, db)
        plan = store._get(db, "firewall_changes", identifier)
        if not plan:
            raise KeyError(identifier)
        from .host_default_deny import guarded
        if any(guarded(store._get(db,"servers",server_id) or {}) for server_id in plan.get("operations_by_server",{})):
            raise ValueError("Disable whole-server deny through its acknowledged flow before imported-rule mutations")
        if plan["status"] not in ("draft", "awaiting_second_confirmation"):
            problem = "This change is no longer awaiting confirmation"
        elif not isinstance(value.get("confirmation_nonce"), str) or not secrets.compare_digest(value["confirmation_nonce"], plan["confirmation_nonce"]):
            problem = "Confirmation nonce is no longer current; refresh the change"
        elif plan["status"] == "awaiting_second_confirmation" and value.get("challenge") != plan["confirmation_phrase"]:
            problem = "Typed confirmation phrase does not match this exact plan"
        else:
            if plan["requires_double_confirmation"]:
                from . import approvals
                approvals.confirm(store, db, plan, actor, principal, final=plan["confirmation_count"] == 1, pilot_nonce=value.get("pilot_confirmation_nonce"))
            plan["confirmation_count"] += 1
            plan["confirmation_nonce"] = secrets.token_urlsafe(24)
            if plan["requires_double_confirmation"] and plan["confirmation_count"] == 1:
                plan["status"] = "awaiting_second_confirmation"
            else:
                plan["status"] = "queued"
                from . import approvals
                if not plan["requires_double_confirmation"]:
                    approvals.decide(store, db, plan, actor, principal)
                plan["approval_proof"] = approvals.proof(plan)
                plan["confirmation_nonce"] = ""
                plan["confirmed_at"] = stamp()
                plan["expires_at"] = stamp(now() + timedelta(hours=24))
            store._put(db, "firewall_changes", plan)
            store.audit("firewall_change.confirmed", actor, {"change_id": identifier, "step": plan["confirmation_count"], "plan_digest": plan["plan_digest"], "status": plan["status"]}, db)
        response = public_plan(plan)
    if problem:
        raise WorkflowConflict(problem, response)
    return response


def cancel_change(store, identifier, actor):
    with store.lock, store.meta() as db:
        plan = store._get(db, "firewall_changes", identifier)
        if not plan:
            raise KeyError(identifier)
        if plan["status"] in ("draft", "awaiting_second_confirmation", "queued"):
            plan.update({"status": "cancelled", "confirmation_nonce": "", "cancelled_at": stamp()})
            store._put(db, "firewall_changes", plan)
            store.audit("firewall_change.cancelled", actor, {"change_id": identifier}, db)
        return public_plan(plan)


def assignments(store, db, identifier):
    result = []
    from . import approvals
    server = store._get(db, "servers", identifier) or {}
    from .host_default_deny import guarded
    if guarded(server):return result
    if not approvals.signed_target(store, server):
        return result
    for plan in store._all(db, "firewall_changes"):
        if not approvals.authorized(store, db, plan.get("approval_proof"), plan_id=plan["id"], plan_digest=plan["plan_digest"], server_id=identifier):
            continue
        required = 2 if plan["requires_double_confirmation"] else 1
        if plan["status"] != "queued" or plan["confirmation_count"] < required or identifier not in plan["operations_by_server"] or identifier in plan.get("results", {}) or parse_time(plan["expires_at"]) <= now():
            continue
        result.append({"id": plan["id"], "plan_digest": plan["plan_digest"], "expected_snapshot_digest": plan["snapshot_digests"][identifier], "requires_double_confirmation": plan["requires_double_confirmation"], "confirmation_count": plan["confirmation_count"], "operations": plan["operations_by_server"][identifier], "expires_at": plan["expires_at"], "approval_proof": approvals.delivery(plan.get("approval_proof"))})
    return sorted(result, key=lambda plan: plan["id"])


def ingest_results(store, db, identifier, values):
    acknowledged = []
    if not isinstance(values, list) or len(values) > 100:
        raise ValueError("At most 100 firewall change results may be reported")
    for value in values:
        if not isinstance(value, dict):
            raise ValueError("Invalid firewall change result")
        plan = store._get(db, "firewall_changes", value.get("id"))
        if not plan or identifier not in plan["operations_by_server"] or value.get("plan_digest") != plan["plan_digest"] or plan["confirmation_count"] < (2 if plan["requires_double_confirmation"] else 1):
            raise PermissionError("Firewall change result is not authorized for this endpoint and plan")
        status = value.get("status")
        message = value.get("message", value.get("error", ""))
        if status not in ("applied", "failed", "conflict", "preview") or not isinstance(message, str) or len(message) > 4096:
            raise ValueError("Invalid firewall change result status or message")
        completed = parse_time(value["completed_at"]) if value.get("completed_at") else now()
        if completed > now() + timedelta(seconds=60):
            raise ValueError("Result completion timestamp is in the future")
        snapshot_digest = value.get("snapshot_digest", "")
        if not isinstance(snapshot_digest, str) or (snapshot_digest and not re.fullmatch(r"[a-f0-9]{64}", snapshot_digest)):
            raise ValueError("Invalid resulting snapshot digest")
        outcome = {"status": status, "message": message, "completed_at": stamp(completed), "snapshot_digest": snapshot_digest}
        old = plan.setdefault("results", {}).get(identifier)
        if old:
            if old["status"] != status or old["message"] != message:
                raise WorkflowConflict("Endpoint already reported a terminal result for this plan")
            acknowledged.append(plan["id"])
            continue
        plan["results"][identifier] = outcome
        if plan["status"] == "queued" and set(plan["operations_by_server"]) <= set(plan["results"]):
            statuses = {result["status"] for result in plan["results"].values()}
            plan["status"] = "completed_with_errors" if statuses & {"failed", "conflict"} else (next(iter(statuses)) if len(statuses) == 1 else "completed")
        store._put(db, "firewall_changes", plan)
        store.audit("firewall_change.result", "agent:" + identifier, {"change_id": plan["id"], "status": status}, db)
        if status == "applied":
            from .notification_events import port_allowed, subscribed_revision
            revision = subscribed_revision(store, db, "port_allowed")
            if revision is not None:
                ports = [(port["protocol"], port["port"]) for row in plan.get("preview", {}).get("after", [])
                         if row["server_id"] == identifier and row["scope"] == "runtime"
                         and classify(row["kind"], row["value"])[0] == "accept" for port in row["ports"]]
                if ports:
                    server = store._get(db, "servers", identifier)
                    if server:
                        port_allowed(db, revision, server, "discovered firewall rule", plan["id"], ports)
        acknowledged.append(plan["id"])
    return acknowledged
