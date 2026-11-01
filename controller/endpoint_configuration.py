"""Signed single-admin authority for explicit local endpoint reconfiguration.

This does not place privileged settings in polling responses. A privileged
operator must transfer/apply the signed, private data-only kit on its exact host.
"""
from __future__ import annotations

import copy
import ipaddress
import re
import uuid
from datetime import timedelta

from . import approvals
from .appliance import origin
from .firewall import WorkflowConflict
from .store import digest, now, parse_time, stamp

TABLE = "endpoint_configuration_reviews"
CAPABILITY = "endpoint_configuration_v1"
HOST_DENY_FLAG = "allow_host_default_deny"
HOST_DENY_CAPABILITY = "host_default_deny_v1"
SECURITY_FLAGS = ("enforce", "allow_firewall_changes", "learning_auto_allow", "unexpected_port_monitor_enabled", HOST_DENY_FLAG)
FLAGS = SECURITY_FLAGS
URLS = ("controller_url", "control_url", "discovery_url")
FIELDS = (*FLAGS, *URLS, "management_sources", "protected_ssh_ports", "zone")
LEGACY_FIELDS = tuple(key for key in FIELDS if key != HOST_DENY_FLAG)
HEX = re.compile(r"[a-f0-9]{64}\Z")


def _public_ca(value):
    from .agent_installation import _public_ca as validate_ca
    return validate_ca(value)


def initialize(db):
    db.execute("CREATE TABLE IF NOT EXISTS endpoint_configuration_reviews(id TEXT PRIMARY KEY,data TEXT NOT NULL)")


def report(value):
    """Bound public evidence; no credential or arbitrary path is accepted."""
    if isinstance(value,dict) and "allow_single_admin_pilot" in value:
        if not isinstance(value["allow_single_admin_pilot"],bool):
            raise ValueError("Invalid retired endpoint setting")
        value={key:item for key,item in value.items() if key!="allow_single_admin_pilot"}
    if not isinstance(value, dict) or set(value) not in ({"digest", *FIELDS}, {"digest", *LEGACY_FIELDS}) or not isinstance(value.get("digest"), str) or not HEX.fullmatch(value["digest"]):
        raise ValueError("Invalid endpoint configuration receipt")
    return {"digest": value["digest"], **normalize({key: value[key] for key in FIELDS if key in value}, protect=False)}


def normalize(value, *, protect=True):
    if not isinstance(value, dict) or set(value) not in (set(FIELDS), set(LEGACY_FIELDS)):
        raise ValueError("Provide the exact security settings, controller channels and management scope")
    result = {}
    for key in FLAGS:
        flag = value.get(key, False)
        if not isinstance(flag, bool):
            raise ValueError("Security opt-ins must be explicit booleans")
        result[key] = flag
    if protect and result["learning_auto_allow"] and not result["enforce"]:
        raise ValueError("Automatic learned access requires the managed-enforcement local opt-in too")
    if protect and result[HOST_DENY_FLAG] and (not result["enforce"] or result["learning_auto_allow"]):
        raise ValueError("Whole-server default deny requires managed enforcement and automatic learning disabled")
    for key in URLS:
        result[key] = origin(value[key]) if value[key] else ""
    if not result["controller_url"]:
        raise ValueError("A trusted public controller origin is required")
    sources = value["management_sources"]
    ports = value["protected_ssh_ports"]
    if not isinstance(sources, list) or len(sources) > 128 or any(not isinstance(item, str) for item in sources):
        raise ValueError("Choose at most 128 exact management source networks")
    try:
        networks = [ipaddress.ip_network(item, strict=False) if "/" in item else ipaddress.ip_network(item + ("/128" if ":" in item else "/32")) for item in sources]
    except ValueError:
        raise ValueError("Management sources must be valid IP addresses or networks") from None
    if protect and any(network.prefixlen == 0 for network in networks):
        raise ValueError("An unrestricted network cannot be the protected management scope")
    result["management_sources"] = sorted(set(map(str, networks)))
    if not isinstance(ports, list) or len(ports) > 32 or any(isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535 for port in ports) or len(set(ports)) != len(ports):
        raise ValueError("Choose at most 32 distinct actual SSH ports")
    result["protected_ssh_ports"] = sorted(ports)
    zone = value["zone"]
    if not isinstance(zone, str) or zone and not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", zone):
        raise ValueError("Choose a valid firewalld zone name")
    result["zone"] = zone
    if protect and any(result[key] for key in SECURITY_FLAGS) and (not result["management_sources"] or not ports or not zone):
        raise ValueError("Security opt-ins require explicit management sources, actual SSH ports and a firewalld zone")
    return result


def _wire_settings(value):
    """Keep the false opt-in absent from legacy signed configuration scopes."""
    result = normalize(value)
    if result[HOST_DENY_FLAG] is False:
        result.pop(HOST_DENY_FLAG)
    return result


def _server(store, db, identifier):
    server = store._get(db, "servers", identifier)
    if not server or CAPABILITY not in server.get("capabilities", []) or not server.get("configuration_state") or not server.get("ips"):
        raise ValueError("Choose an enrolled endpoint reporting endpoint_configuration_v1")
    if parse_time(server["last_seen"]) < now() - timedelta(seconds=180):
        raise WorkflowConflict("Wait for a fresh authenticated endpoint report", {})
    server["configuration_state"]=report(server["configuration_state"])
    return server


def _binding(server):
    return digest({"server_id": server["id"], "hostname": server["hostname"], "ips": sorted(server.get("ips", [])), "configuration_state": server["configuration_state"], "ssh_ports": _ssh(server), "firewalld_state": server.get("firewalld_state"), "ufw_active": bool(server.get("ufw_active"))})


def _ssh(server):
    return sorted({item["port"] for item in server.get("listeners", []) if item.get("protocol") == "tcp" and any("ssh" in str(item.get(key, "")).lower() for key in ("process", "service", "application", "systemd_unit"))})


def _can_enable(server, settings):
    if settings.get(HOST_DENY_FLAG, False) and HOST_DENY_CAPABILITY not in server.get("capabilities", []):
        raise ValueError("Upgrade this endpoint to host_default_deny_v1 before enabling whole-server default deny")
    if any(settings.get(key, False) for key in SECURITY_FLAGS) and (server.get("firewalld_state") != "running" or server.get("ufw_active")):
        raise ValueError("Prepare running firewalld and resolve UFW coexistence before enabling endpoint firewall opt-ins")


def preview(app, value, actor, principal):
    if app.demo or not app.platform or not isinstance(value, dict) or set(value) != {"server_id", "settings", "controller_ca_pem", "retain_old_origin"} or not isinstance(value["retain_old_origin"], bool):
        raise ValueError("An installed HTTPS controller and exact endpoint review fields are required")
    settings = normalize(value["settings"])
    certificate = _public_ca(value["controller_ca_pem"]) if value["controller_ca_pem"] else ""
    with app.store.lock, app.store.meta() as db:
        server = _server(app.store, db, value["server_id"])
        if settings[HOST_DENY_FLAG] and HOST_DENY_CAPABILITY not in server.get("capabilities", []):
            raise ValueError("Upgrade this endpoint to host_default_deny_v1 before enabling whole-server default deny")
        if server["configuration_state"].get(HOST_DENY_FLAG) is True and HOST_DENY_FLAG not in value["settings"]:
            raise ValueError("Explicitly preserve or disable the existing whole-server default-deny opt-in")
        _can_enable(server, settings)
        if any(settings[key] != server["configuration_state"][key] for key in URLS) and not value["retain_old_origin"]:
            raise ValueError("Confirm that old and proposed origins remain reachable for the same deployment during migration")
        if any(settings[key] for key in SECURITY_FLAGS) and not set(_ssh(server)) <= set(settings["protected_ssh_ports"]):
            raise ValueError("Protect every currently discovered SSH listener")
        scope = {"server_id": server["id"], "hostname": server["hostname"], "ips": sorted(server.get("ips", [])),
                 "expected_config_digest": server["configuration_state"]["digest"], "target_binding": _binding(server),
                 "settings": _wire_settings(settings), "controller_ca_pem": certificate, "retain_old_origin": value["retain_old_origin"]}
        plan = {"id": str(uuid.uuid4()), "created_at": stamp(), "expires_at": stamp(now() + timedelta(minutes=30)), "scope": scope,
                "plan_digest": digest(scope), "status": "draft"}
        approvals.request(app.store, db, plan, actor, principal, endpoint_ids=[server["id"]],scope_kind="endpoint_configuration")
        approvals.decide(app.store,db,plan,actor,principal)
        plan["status"]="approved"
        app.store._put(db, TABLE, plan)
        app.store.audit("endpoint.configuration.preview", actor, {"review_id": plan["id"], "server_id": server["id"], "plan_digest": plan["plan_digest"]}, db)
        return plan


def _plan(app, db, identifier, *, candidate=None):
    plan = app.store._get(db, TABLE, identifier)
    if not plan or plan.get("status") == "revoked" or parse_time(plan["expires_at"]) <= now():
        raise ValueError("The endpoint review is missing or expired")
    if plan.get("plan_digest") != digest(plan["scope"]):
        raise PermissionError("The immutable endpoint configuration scope changed")
    server = _server(app.store, db, plan["scope"]["server_id"])
    _can_enable(server, plan["scope"]["settings"])
    if candidate is None and _binding(server) != plan["scope"]["target_binding"]:
        raise WorkflowConflict("Endpoint identity, addresses or configuration changed; create a new review", {})
    if candidate is not None:
        if server["hostname"] != plan["scope"]["hostname"] or sorted(server.get("ips", [])) != plan["scope"]["ips"]:
            raise WorkflowConflict("Endpoint identity or addresses changed", {})
        observed = server["configuration_state"]
        if any(plan["scope"]["settings"].get(key, False) for key in SECURITY_FLAGS) and not set(_ssh(server)) <= set(plan["scope"]["settings"]["protected_ssh_ports"]):
            raise WorkflowConflict("SSH listeners changed; review the current protection scope", {})
        if observed["digest"] != candidate or normalize({key: observed[key] for key in FIELDS}, protect=False) != normalize(plan["scope"]["settings"], protect=False):
            raise WorkflowConflict("Waiting for the exact candidate's fresh authenticated report", {})
    return plan, server


def confirm(app, identifier, body, actor, principal):
    if not isinstance(body, dict) or set(body) != {"plan_digest", "confirmation"}:
        raise ValueError("Confirm the exact frozen endpoint review")
    with app.store.lock, app.store.meta() as db:
        plan, _ = _plan(app, db, identifier)
        if body["plan_digest"] != plan["plan_digest"] or body["confirmation"] != "CONFIGURE " + identifier:
            raise ValueError("Type the exact endpoint review confirmation")
        approvals.decide(app.store,db,plan,actor,principal)
        plan["status"] = plan["approval"]["stage"]
        app.store._put(db, TABLE, plan)
        app.store.audit("endpoint.configuration." + plan["status"], actor, {"review_id": identifier, "plan_digest": plan["plan_digest"]}, db)
        return plan


def listing(app, server_id=None, limit=20, offset=0):
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 50 or isinstance(offset, bool) or not isinstance(offset, int) or not 0 <= offset <= 1000000 or server_id is not None and (not isinstance(server_id, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", server_id)):
        raise ValueError("Choose a valid endpoint and bounded review page")
    from .approval_views import _expression
    with app.store.read_meta() as db:
        where = " WHERE " + _expression(db, ("scope", "server_id")) + "=?" if server_id is not None else ""
        args = (server_id,) if server_id is not None else ()
        rows = db.execute("SELECT data FROM endpoint_configuration_reviews" + where + " ORDER BY " + _expression(db, ("created_at",)) + " DESC,id DESC LIMIT ? OFFSET ?", (*args, limit + 1, offset)).fetchall()
        import json
        return {"items": [json.loads(row[0]) for row in rows[:limit]], "has_more": len(rows) > limit, "offset": offset, "limit": limit}


def revoke(app, identifier, actor, principal):
    with app.store.lock, app.store.meta() as db:
        plan = app.store._get(db, TABLE, identifier)
        if not plan:
            raise KeyError(identifier)
        person = approvals.identity(app.store, db, actor, principal)
        if person["user_id"] != plan["approval"]["requester"]["user_id"] and person["role"] != "super_admin":
            raise PermissionError("Only the requester or a Super Admin can revoke configuration authority")
        plan.update(status="revoked", revoked_at=stamp(), revoked_by=person)
        app.store._put(db, TABLE, plan)
        app.store.audit("endpoint.configuration.revoked", actor, {"review_id": identifier}, db)
        return plan


def kit(app, identifier, actor):
    with app.store.lock, app.store.meta() as db:
        plan, _ = _plan(app, db, identifier)
        proof = approvals.proof(plan)
        if not approvals.authorized(app.store, db, proof, plan_id=plan["id"], plan_digest=plan["plan_digest"],server_id=plan["scope"]["server_id"]):
            raise PermissionError("The administrator's configuration authority is no longer authorized")
        if plan["scope"]["controller_ca_pem"]:
            _public_ca(plan["scope"]["controller_ca_pem"])
        signer = app.platform.policy_signer()
        if not hasattr(signer, "sign_package"):
            raise ValueError("This configuration-kit workflow requires an approved online signing service; the deployment currently serves offline policy artifacts")
        issued=now()
        manifest = {"kind": "prthak-endpoint-configuration-v1", "review_id": plan["id"], "issued_at": stamp(issued),
                    "expires_at": min(plan["expires_at"], stamp(issued + timedelta(minutes=15))), "scope": copy.deepcopy(plan["scope"]), "approval": proof,
                    "deployment_id": signer.public_trust()["deployment_id"]}
        signed = signer.sign_package(manifest)
        app.store.audit("endpoint.configuration.kit", actor, {"review_id": identifier, "plan_digest": plan["plan_digest"]}, db)
        return {"schema_version": 1, "manifest": manifest, "signature": signed}


def check(app, server_id, body):
    if not isinstance(body, dict) or set(body) != {"review_id", "plan_digest", "candidate_digest", "phase", "nonce"} or body["phase"] not in ("before", "after") or not HEX.fullmatch(str(body["candidate_digest"])) or not isinstance(body["nonce"],str) or not re.fullmatch(r"[a-f0-9]{32}",body["nonce"]):
        raise ValueError("Provide the exact configuration witness binding")
    with app.store.meta() as db:
        plan, _ = _plan(app, db, body["review_id"], candidate=body["candidate_digest"] if body["phase"] == "after" else None)
        proof = approvals.proof(plan)
        if server_id != plan["scope"]["server_id"] or body["plan_digest"] != plan["plan_digest"] or not approvals.authorized(app.store, db, proof, plan_id=plan["id"], plan_digest=plan["plan_digest"],server_id=server_id):
            raise PermissionError("Configuration authority was revoked or belongs to another endpoint")
        signer=app.platform.policy_signer()
        if not hasattr(signer,"sign_package"):
            raise ValueError("Fresh configuration witnesses require the approved online signing service")
        issued=now()
        value={"kind":"prthak-endpoint-configuration-witness-v1","nonce":body["nonce"],"server_id": server_id, "review_id": plan["id"], "plan_digest": plan["plan_digest"], "candidate_digest": body["candidate_digest"],
                "phase": body["phase"], "deployment_id": signer.public_trust()["deployment_id"],"issued_at":stamp(issued),"expires_at":stamp(issued+timedelta(seconds=30))}
        return {**value,"signature":signer.sign_package(value)}
