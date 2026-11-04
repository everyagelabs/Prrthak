"""Bounded native rule packet/byte samples; never connection/policy totals.

Only the newest sample and its immediately preceding observation are used.
No history before enrollment, reset, or an unavailable sample is invented.
"""
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone

CAPABILITY = "firewall_rule_counters_v1"
MAX_RULES = 512
MAX_BYTES = 256 * 1024
UINT64 = 2**64 - 1
HASH = re.compile(r"[a-f0-9]{64}\Z")
NAME = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
BOOT = re.compile(r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\Z")
DECIMAL = re.compile(r"(?:0|[1-9][0-9]{0,19})\Z")
TOP_FIELDS = {"schema_version", "backend", "status", "collected_at", "boot_id", "rules", "reason", "truncated"}
RULE_FIELDS = {"id", "instance_id", "family", "table", "table_handle", "chain", "handle", "ordinal", "zone", "kind", "basis", "provenance", "expression", "action", "counter_status", "packets", "bytes", "reason"}


def _now():
    return datetime.now(timezone.utc)


def _time(value):
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError("A native counter sample timestamp is required")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("Invalid native counter timestamp") from None
    if parsed.tzinfo is None or parsed.year < 2000:
        raise ValueError("A timezone-aware native counter timestamp is required")
    return parsed.astimezone(timezone.utc)


def _stamp(value):
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _text(value, limit, label, empty=True):
    if not isinstance(value, str) or len(value.encode("utf-8")) > limit or any(ord(char) < 32 or ord(char) == 127 for char in value) or not empty and not value:
        raise ValueError("Invalid native counter " + label)
    return value


def _decimal(value, label, empty=False):
    if empty and value == "":
        return value
    if not isinstance(value, str) or not DECIMAL.fullmatch(value) or int(value) > UINT64:
        raise ValueError("Native counter " + label + " must be an exact unsigned 64-bit decimal string")
    return value


def _hash(parts):
    return hashlib.sha256("\0".join(parts).encode()).hexdigest()


def _expression(value):
    def pairs(items):
        result = {}
        for key, item in items:
            if key in result:
                raise ValueError("Duplicate native expression key")
            result[key] = item
        return result
    def invalid_constant(_):
        raise ValueError("Non-finite native expression number")
    parsed = json.loads(value, object_pairs_hook=pairs, parse_constant=invalid_constant)
    def bounded(item, depth=0):
        if depth > 24:
            raise ValueError("Native expression exceeds depth bound")
        if isinstance(item, dict):
            for key, child in item.items():
                _text(key, 128, "expression key")
                bounded(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                bounded(child, depth + 1)
    bounded(parsed)
    return parsed


def _iptables_chain(chain, zone):
    if not isinstance(chain, str) or not isinstance(zone, str):
        return False
    if chain in {"INPUT_direct", "OUTPUT_direct", "FORWARD_direct", "INPUT_ZONES", "INPUT_ZONES_SOURCE", "OUTPUT_ZONES", "OUTPUT_ZONES_SOURCE", "FORWARD_IN_ZONES", "FORWARD_IN_ZONES_SOURCE", "FORWARD_OUT_ZONES", "FORWARD_OUT_ZONES_SOURCE"}:
        return True
    return bool(zone) and any(chain == prefix + zone or chain.startswith(prefix + zone + "_") for prefix in ("IN_", "OUT_", "FWDI_", "FWDO_", "PRE_", "POST_"))


def normalize(value, now=None):
    current = now or _now()
    if not isinstance(value, dict) or set(value) != TOP_FIELDS:
        raise ValueError("Invalid native firewall counter snapshot fields")
    try:
        raw = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode()
    except (ValueError, TypeError, RecursionError):
        raise ValueError("Invalid native firewall counter snapshot") from None
    if len(raw) > MAX_BYTES or type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise ValueError("Native firewall counter snapshot exceeds its supported schema/budget")
    if value["backend"] not in ("nftables", "iptables", "unknown") or value["status"] not in ("ok", "partial", "unavailable") or type(value["truncated"]) is not bool:
        raise ValueError("Invalid native counter backend/status")
    sampled = _time(value["collected_at"])
    if sampled > current + timedelta(minutes=5):
        raise ValueError("Native counter timestamp is in the future")
    boot = value["boot_id"]
    if not isinstance(boot, str) or boot and not BOOT.fullmatch(boot):
        raise ValueError("Invalid native counter boot identity")
    reason = _text(value["reason"], 512, "availability reason")
    if value["status"] != "ok" and not reason or value["truncated"] and value["status"] != "partial":
        raise ValueError("Incomplete native counter coverage requires an explicit reason")
    rows = value["rules"]
    if not isinstance(rows, list) or len(rows) > MAX_RULES:
        raise ValueError("Native counter rules exceed the bounded snapshot")
    result = {**value, "reason": reason, "collected_at": _stamp(sampled), "rules": []}
    identifiers = set()
    physical = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != RULE_FIELDS:
            raise ValueError("Invalid native counter rule fields")
        nft = value["backend"] == "nftables"
        if nft and (row["family"] not in ("inet", "ip", "ip6") or row["table"] != "firewalld" or row["provenance"] != "firewalld_table") or not nft and (value["backend"] != "iptables" or row["family"] not in ("ipv4", "ipv6") or row["table"] != "filter" or row["provenance"] not in ("firewalld_chain", "firewalld_builtin_pattern")):
            raise ValueError("Foreign firewall tables cannot be reported as firewalld counters")
        if not isinstance(row["chain"], str) or not NAME.fullmatch(row["chain"]) or not isinstance(row["zone"], str) or row["zone"] and not NAME.fullmatch(row["zone"]):
            raise ValueError("Invalid native firewalld chain/zone")
        if row["kind"] not in ("base", "zone", "policy", "direct") or row["basis"] not in ("kernel_rule", "chain_policy") or row["action"] not in ("accept", "drop", "reject", "return", "jump", "goto", "dnat", "snat", "masquerade", "redirect", "continue"):
            raise ValueError("Invalid native rule classification")
        if type(row["ordinal"]) is not int or not 0 <= row["ordinal"] < MAX_RULES:
            raise ValueError("Invalid duplicate native rule ordinal")
        _decimal(row["table_handle"], "table handle", empty=True)
        _decimal(row["handle"], "rule handle")
        expression = _text(row["expression"], 1536, "expression", empty=False)
        # Expression is display-only and is never used as a command or edited.
        try:
            parsed = _expression(expression)
        except (ValueError, RecursionError):
            raise ValueError("Invalid normalized native expression JSON") from None
        if not isinstance(parsed, (list, dict)):
            raise ValueError("Invalid normalized native expression")
        if row["basis"] == "chain_policy" and (parsed != {"policy": row["action"]} or row["action"] not in ("accept", "drop")):
            raise ValueError("Invalid native chain policy expression")
        if not nft:
            if row["provenance"] == "firewalld_chain":
                if not _iptables_chain(row["chain"], row["zone"]):
                    raise ValueError("Foreign iptables chains cannot be reported as firewalld counters")
            elif row["chain"] not in ("INPUT", "OUTPUT", "FORWARD"):
                raise ValueError("Native default policy counters must belong to a builtin chain")
            elif row["basis"] == "kernel_rule":
                plain = " ".join(parsed) if isinstance(parsed, list) and all(isinstance(item, str) for item in parsed) else ""
                base = {"-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", "-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT", "-m conntrack --ctstate INVALID -j DROP", "-i lo -j ACCEPT", "-o lo -j ACCEPT", "-j REJECT --reject-with icmp-host-prohibited", "-j REJECT --reject-with icmp6-adm-prohibited"}
                if plain not in base and not (isinstance(parsed, list) and len(parsed) == 2 and parsed[0] in ("-j", "-g") and _iptables_chain(parsed[1], row["zone"])):
                    raise ValueError("Unrecognized iptables builtin rules are outside firewalld counter scope")
        expected = _hash([row["family"], row["table"], row["chain"], row["basis"], expression, str(row["ordinal"])])
        instance = _hash([boot, row["family"], row["table"], row["table_handle"], row["chain"], row["handle"]])
        if row["id"] != expected or row["instance_id"] != instance or row["id"] in identifiers:
            raise ValueError("Native counter identities do not match their exact rule")
        key = (row["family"], row["table"], row["chain"], row["handle"], row["basis"])
        if key in physical:
            raise ValueError("Duplicate native counter physical rule")
        physical.add(key)
        identifiers.add(expected)
        message = _text(row["reason"], 512, "rule availability reason")
        if row["counter_status"] == "available":
            _decimal(row["packets"], "packets")
            _decimal(row["bytes"], "bytes")
            if message:
                raise ValueError("Available counters cannot carry an unavailable reason")
        elif row["counter_status"] != "unavailable" or row["packets"] is not None or row["bytes"] is not None or not message:
            raise ValueError("Unavailable native counters require null values and a reason")
        result["rules"].append({**row, "reason": message})
    if value["status"] == "ok" and (not rows or any(row["counter_status"] != "available" for row in rows)):
        raise ValueError("Complete native counter coverage requires available rules")
    result["rules"].sort(key=lambda row: row["id"])
    result["digest"] = hashlib.sha256(json.dumps(result, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
    return result


def ingest(server, value, now=None):
    """Return False for an identical cached sample or an older sample.

    Missing fields are handled by the caller by not calling this function.
    Resets detected through boot/handle changes or decreasing values start a new
    baseline. A reset and catch-up entirely between samples cannot be detected.
    """
    current = now or _now()
    sample = normalize(value, current)
    old = server.get("firewall_counters") or {}
    if old.get("collected_at"):
        previous = _time(old["collected_at"])
        if _time(sample["collected_at"]) < previous:
            return False
        if sample["collected_at"] == old["collected_at"]:
            if sample["digest"] != old.get("digest"):
                raise ValueError("A cached native counter sample changed without a new sample time")
            return False
    by_id = {row["id"]: row for row in old.get("rules", [])}
    for row in sample["rules"]:
        previous = by_id.get(row["id"])
        row.update(delta_packets=None, delta_bytes=None, delta_since=None, reset_detected=False, delta_status="unavailable")
        if row["counter_status"] != "available":
            continue
        row["delta_status"] = "baseline"
        if not sample["boot_id"]:
            row["delta_status"] = "generation_unknown"
        elif previous and previous.get("counter_status") == "available":
            if not old.get("boot_id"):
                row["delta_status"] = "baseline"
            elif old.get("boot_id") != sample["boot_id"] or previous.get("instance_id") != row["instance_id"] or int(row["packets"]) < int(previous["packets"]) or int(row["bytes"]) < int(previous["bytes"]):
                row.update(reset_detected=True, delta_status="reset")
            else:
                row.update(delta_packets=str(int(row["packets"]) - int(previous["packets"])), delta_bytes=str(int(row["bytes"]) - int(previous["bytes"])), delta_since=old["collected_at"], delta_status="observed")
    sample["received_at"] = _stamp(current)
    server["firewall_counters"] = sample
    return True


def view(server, *, after="", limit=50, search="", now=None):
    """Read-only endpoint view; paginate before sending bounded display data."""
    if not isinstance(after, str) or after and not HASH.fullmatch(after) or type(limit) is not int or not 1 <= limit <= 100 or not isinstance(search, str) or len(search) > 256:
        raise ValueError("Invalid native counter page options")
    sample = server.get("firewall_counters")
    interval = server.get("discovery_interval_seconds", 900)
    interval = interval if type(interval) is int and 60 <= interval <= 86400 else 900
    if not sample:
        return {"server_id": server.get("id"), "status": "unavailable", "reason": "This endpoint has not reported native firewall counters. An agent supporting the counter protocol is required.", "items": [], "total": 0, "next_after": None, "has_more": False, "stale": True, "sample_interval_seconds": interval}
    # Sample content is already validated at authenticated report ingestion.
    current = now or _now()
    stale = (current - _time(sample["collected_at"])).total_seconds() > max(180, interval * 2) or server.get("status") in ("offline", "retired")
    rows = [row for row in sample["rules"] if not search or search.casefold() in " ".join(str(row.get(key, "")) for key in ("chain", "zone", "expression", "action", "kind")).casefold()]
    eligible = [row for row in rows if not after or row["id"] > after]
    items = eligible[:limit]
    more = len(eligible) > len(items)
    return {"server_id": server.get("id"), **{key: value for key, value in sample.items() if key != "rules"}, "items": items, "total": len(rows), "next_after": items[-1]["id"] if more and items else None, "has_more": more, "stale": stale, "sample_interval_seconds": interval, "count_unit": "packets", "byte_unit": "bytes", "coverage_note": "Native runtime rule counters include existing firewalld base/zone rules. One service may compile to several rules; do not sum rows as connections. No historical counts are reconstructed. Resets entirely between samples may be missed."}
