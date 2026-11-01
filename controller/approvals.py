"""Current Admin authority bound to immutable intent and signed delivery.

Ordinary authenticated changes publish directly. Explicit destructive actions
retain two same-actor nonce steps. Historical decisions remain audit evidence;
old pending maker/checker and pilot reviews cannot be promoted.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import secrets
import uuid
from datetime import timedelta

from .store import digest, now, parse_time, stamp
from .firewall import WorkflowConflict

SCHEME = "prthak-maker-checker-v1"
ROLES = frozenset(("admin", "super_admin"))


def _lab(store):
    return getattr(store, "lab_approvals", False) is True and (
        getattr(store, "approval_production", False) is not True or getattr(store, "approval_demo", False) is True)


def signed_target(store, server):
    return _lab(store) or "signed_assignments_v1" in server.get("capabilities", [])


def lab_decision(store, db, plan, actor, principal=None):
    """One explicit legacy lab action, never a fabricated two-person decision."""
    if not _lab(store) or isinstance(principal, dict) and principal.get("auth_type") == "session":
        raise PermissionError("Independent Entra preview and approval are required")
    if not plan.get("approval"):
        request(store, db, plan, actor, principal)
    value = _bound(plan)
    if value.get("mode") != "lab_only" or value["requester"]["actor"] != actor:
        raise PermissionError("This lab action belongs to a different review actor")
    subject = copy.deepcopy(value["requester"])
    value.update(stage="approved", submitted_by=subject, approved_by=subject, submitted_at=stamp(), approved_at=stamp(), lab_single_action=True)
    return proof(plan)


def _guid(value):
    try:
        if not isinstance(value, str):
            raise ValueError()
        return str(uuid.UUID(value))
    except (ValueError, AttributeError):
        raise PermissionError("Administrative changes require a verified Microsoft Entra person") from None


def _active_user(store, db, identifier):
    value = store._get(db, "auth_users", identifier)
    return bool(value and value.get("enabled") is True and value.get("role") in ROLES and
                value.get("id") == identifier and identifier == value.get("tenant_id", "") + ":" + value.get("object_id", ""))


def identity(store, db, actor, principal):
    """Validate a current, individually attributed Entra admin session."""
    if not isinstance(principal, dict) or principal.get("auth_type") != "session":
        raise PermissionError("Live firewall changes require an authenticated Microsoft Entra Admin; shared role tokens cannot identify the current person")
    user = principal.get("user") or {}
    if not isinstance(user, dict):
        raise PermissionError("A verified Entra user identity is required")
    tenant, person = _guid(user.get("tenant_id")), _guid(user.get("object_id"))
    identifier = tenant + ":" + person
    if user.get("id") != identifier or actor != "entra:" + identifier or principal.get("actor") != actor or principal.get("role") not in ROLES:
        raise PermissionError("The approval identity does not match the authenticated Entra principal")
    session_id = principal.get("_session_id")
    if not isinstance(session_id, str) or not re.fullmatch(r"[a-f0-9]{64}", session_id):
        raise PermissionError("A live authenticated Entra session is required")
    session = store._get(db, "auth_sessions", session_id)
    if not session or session.get("user_id") != identifier or parse_time(session.get("expires_at", "1970-01-01T00:00:00Z")) <= now() or not _active_user(store, db, identifier):
        raise PermissionError("The rollout requester or approver session was revoked, expired or no longer has administrative access")
    fingerprint = getattr(store, "approval_auth_fingerprint", None)
    expected_tenant = getattr(store, "approval_tenant_id", None)
    if not session.get("config") or fingerprint and session.get("config") != fingerprint or expected_tenant and tenant != expected_tenant:
        raise PermissionError("The approval session belongs to a different Entra configuration")
    current = store._get(db, "auth_users", identifier)
    return {"actor": actor, "user_id": identifier, "tenant_id": tenant, "object_id": person,
            "display_name": current.get("display_name", ""), "role": current["role"], "auth_config": session["config"]}


def authority(store, db):
    value = store._get(db, "maintenance_settings", "controller_provider_authority")
    return {"fingerprint": value["fingerprint"], "epoch": value.get("epoch", "")} if value else {
        "fingerprint": getattr(store, "approval_auth_fingerprint", "") or "", "epoch": os.environ.get("PRTHAK_PROVIDER_EPOCH", "")}


def request(store, db, plan, actor, principal=None, *, endpoint_ids=None, scope_kind=None):
    """Bind a direct administrative action to its current actor and exact intent."""
    if isinstance(principal, dict) and principal.get("auth_type") == "session":
        requester, mode = identity(store, db, actor, principal), "single_admin"
    elif _lab(store):
        requester, mode = {"actor": actor, "user_id": None, "display_name": "Explicit lab actor"}, "lab_only"
    else:
        raise PermissionError("An authenticated Microsoft Entra Admin is required for live firewall changes")
    scope = {"kind": scope_kind or str(plan.get("kind") or "administrative_action")}
    if endpoint_ids is not None:
        targets = sorted(set(endpoint_ids))
        if len(targets) == 1:scope["server_ids"] = targets
        else:scope.update(target_count=len(targets), target_digest=digest(targets))
    plan["approval"] = {"scheme": SCHEME, "mode": mode, "stage": "draft", "plan_id": plan["id"],
                        "plan_digest": plan["plan_digest"], "requester": requester, "requested_at": stamp(),
                        "provider_authority": authority(store, db), "scope": scope}
    return plan["approval"]


def decide(store, db, plan, actor, principal=None):
    """Publish an ordinary action in one authenticated request; no checker."""
    value = _bound(plan)
    if value.get("mode") == "lab_only":
        return lab_decision(store, db, plan, actor, principal)
    if value.get("mode") != "single_admin":
        raise PermissionError("This old pending review cannot be promoted; create a fresh direct action")
    subject = identity(store, db, actor, principal)
    if subject["user_id"] != value["requester"].get("user_id") or value.get("provider_authority") != authority(store, db):
        raise PermissionError("The action belongs to another or superseded administrative identity")
    value.update(stage="approved", submitted_by=subject, approved_by=subject, submitted_at=stamp(), approved_at=stamp())
    return proof(plan)


def derived(store, db, plan, subject, scope, provider_authority):
    """Resolve previously saved intent; never fabricate a fresh human action."""
    if not _active_user(store, db, subject.get("user_id", "")) or provider_authority != authority(store, db):
        raise PermissionError("The saved administrative intent was revoked or superseded")
    value = {"scheme": SCHEME, "mode": "single_admin", "stage": "approved", "plan_id": plan["id"],
             "plan_digest": plan["plan_digest"], "requester": copy.deepcopy(subject), "submitted_by": copy.deepcopy(subject),
             "approved_by": copy.deepcopy(subject), "requested_at": plan.get("created_at", stamp()),
             "submitted_at": plan.get("created_at", stamp()), "approved_at": plan.get("created_at", stamp()),
             "provider_authority": copy.deepcopy(provider_authority), "scope": copy.deepcopy(scope)}
    plan["approval"] = value
    return proof(plan)


def _bound(plan):
    value = plan.get("approval")
    if not isinstance(value, dict) or value.get("scheme") != SCHEME or value.get("plan_id") != plan.get("id") or value.get("plan_digest") != plan.get("plan_digest"):
        raise PermissionError("This legacy or changed review has no bound current requester; create a fresh preview")
    return value


def confirm(store, db, plan, actor, principal=None, *, final=False, pilot_nonce=None):
    value = _bound(plan)
    if value.get("mode") == "lab_only":
        if not _lab(store) or isinstance(principal, dict) and principal.get("auth_type") == "session":
            raise PermissionError("Lab-only confirmation cannot authorize this production or Entra rollout; create a fresh Entra preview")
        if actor != value["requester"]["actor"]:
            raise PermissionError("Shared role tokens cannot manufacture a distinct approver; the explicitly labelled lab review belongs to its single actor")
        subject = copy.deepcopy(value["requester"])
    elif value.get("mode") == "single_admin":
        subject = identity(store, db, actor, principal)
        if subject["user_id"] != value["requester"].get("user_id") or subject["auth_config"] != value["requester"].get("auth_config") or value.get("provider_authority") != authority(store, db):
            raise PermissionError("Use the same current Admin for both explicit confirmations")
    elif value.get("mode") in ("independent_entra", "single_admin_pilot"):
        raise PermissionError("This old pending approval is no longer applicable; create a fresh direct action")
    else:
        raise PermissionError("Unknown approval identity mode")
    if final:
        if value.get("stage") != "submitted" or not value.get("submitted_by"):
            raise PermissionError("The exact review must be confirmed by its requester before the final explicit step")
        value.update(stage="approved", approved_by=subject, approved_at=stamp())
    else:
        if value.get("stage") != "draft":
            raise PermissionError("This requester submission is no longer current")
        value.update(stage="submitted", submitted_by=subject, submitted_at=stamp())
    return value


def proof(plan):
    value = copy.deepcopy(_bound(plan))
    if value.get("stage") != "approved":
        raise PermissionError("The administrative action is incomplete")
    value["binding_digest"] = digest(value)
    return value


def authorized(store, db, value, *, plan_id=None, plan_digest=None, server_id=None):
    """Constant-sized normalized proof check on endpoint delivery/witness paths.

    Sessions were authenticated at approval time; normal session expiry does
    not erase that audit decision. Disabled/downgraded people revoke further
    admission. Already committed endpoint rules remain unchanged.
    """
    if not isinstance(value, dict) or value.get("scheme") != SCHEME or value.get("stage") != "approved":
        return False
    if value.get("binding_digest") != digest({k: v for k, v in value.items() if k != "binding_digest"}):
        return False
    if plan_id is not None and value.get("plan_id") != plan_id or plan_digest is not None and value.get("plan_digest") != plan_digest:
        return False
    maker, submitted, checker = value.get("requester", {}), value.get("submitted_by", {}), value.get("approved_by", {})
    if any(not isinstance(person, dict) for person in (maker, submitted, checker)):
        return False
    if not value.get("submitted_at") or not value.get("approved_at") or submitted.get("actor") != maker.get("actor"):
        return False
    if value.get("mode") == "lab_only":
        return _lab(store) and maker.get("actor") == checker.get("actor")
    if value.get("mode") == "single_admin":
        scope = value.get("scope", {})
        current = authority(store, db)
        # Recovery validates from retained current rows using an unconfigured
        # Store proxy; the live shared authority remains mandatory when present.
        expected = value.get("provider_authority")
        if not current["fingerprint"] and isinstance(expected, dict):current = {**current, "fingerprint": expected.get("fingerprint", "")}
        return (isinstance(scope, dict) and isinstance(scope.get("kind"), str)
                and expected == current and bool(current["fingerprint"])
                and (server_id is None or "server_ids" not in scope or server_id in scope["server_ids"])
                and maker == submitted == checker
                and maker.get("user_id") == maker.get("tenant_id", "") + ":" + maker.get("object_id", "")
                and maker.get("actor") == "entra:" + maker.get("user_id", "")
                and maker.get("auth_config") == current["fingerprint"]
                and (not getattr(store,"approval_tenant_id",None) or maker.get("tenant_id") == store.approval_tenant_id)
                and _active_user(store, db, maker.get("user_id", "")))
    if value.get("mode") == "single_admin_pilot":
        # Retain archived evidence, but never rearm a retired pilot grant.
        return False
    if value.get("mode") != "independent_entra" or not maker.get("user_id") or maker.get("user_id") == checker.get("user_id") or maker.get("tenant_id") != checker.get("tenant_id"):
        return False
    for person in (maker, checker):
        if not isinstance(person.get("user_id"), str) or person.get("user_id") != person.get("tenant_id", "") + ":" + person.get("object_id", "") or person.get("actor") != "entra:" + person["user_id"]:
            return False
    if not maker.get("auth_config") or checker.get("auth_config") != maker["auth_config"]:
        return False
    if getattr(store, "approval_tenant_id", None) and maker["tenant_id"] != store.approval_tenant_id:
        return False
    if getattr(store, "approval_auth_fingerprint", None) and maker["auth_config"] != store.approval_auth_fingerprint:
        return False
    return _active_user(store, db, maker["user_id"]) and _active_user(store, db, checker.get("user_id", ""))


def learning_requester(store, db, session, actor, principal=None):
    """Capture who requested automation before discovery; no access grant yet."""
    if isinstance(principal, dict) and principal.get("auth_type") == "session":
        requester, mode = identity(store, db, actor, principal), "single_admin"
    elif _lab(store):
        requester, mode = {"actor": actor}, "lab_only"
    else:
        raise PermissionError("Automatic learning requires an authenticated Entra Admin; shared-token production grants are disabled")
    session.update(initial_approval_mode=mode, initial_approval_requester=requester, initial_provider_authority=authority(store, db),
                   initial_approval_state="lab_only" if mode == "lab_only" else "waiting_for_discovery")


def _learning_target(session, server):
    from .learning_policies import _bindings, _protected
    identifier = server["id"]
    from .host_default_deny import guarded
    if guarded(server):raise ValueError("Whole-server deny requires its own acknowledged push; automatic grants are held")
    ports = session.get("server_ports", {}).get(identifier, [])
    result = session.get("discovery_results", {}).get(identifier, {})
    if result.get("status") != "ready" or not ports:
        raise ValueError("Every selected endpoint needs a fresh nonempty frozen port scope")
    if not server.get("protection", {}).get("ready") or not server.get("ips") or "learning_auto_allow_v1" not in server.get("capabilities", []):
        raise ValueError("Every target needs complete protection, reported addresses and an auto-allow-capable agent")
    normalized = sorted(({"protocol": item["protocol"], "port": item["port"]} for item in ports), key=lambda item: (item["protocol"], item["port"]))
    return {"server_id": identifier, "ports": normalized,
            "excluded_protected_ports": [{**port, "reason": _protected(server, port["port"], port["protocol"])} for port in normalized if _protected(server, port["port"], port["protocol"])],
            "ips": sorted(server["ips"]), **_bindings(server)}


def _learning_scope(store, db, session):
    from .review_limits import MAX_REVIEW_BYTES, encoded_size
    if session.get("policy_action") != "auto_allow" or session.get("selection_mode") != "discovered" or session.get("status") != "active" or not parse_time(session["starts_at"]) <= now() < parse_time(session["expires_at"]):
        raise ValueError("Only an active discovered auto-allow session can receive initial authority")
    if session.get("discovery_pending_server_ids"):
        raise ValueError("Wait for a fresh discovery result from every selected endpoint before reviewing automatic access")
    matrix = []
    remaining = MAX_REVIEW_BYTES
    for identifier in sorted(session["server_ids"]):
        server = store._get(db, "servers", identifier)
        if not server:
            raise ValueError("Every selected endpoint needs a fresh nonempty frozen port scope")
        if not signed_target(store, server):
            raise ValueError("Upgrade every automatic-access target to signed_assignments_v1 before reviewing authority")
        target = _learning_target(session, server)
        remaining -= encoded_size(target, remaining)
        matrix.append(target)
    return {"session_id": session["id"], "policy_action": "auto_allow", "selection_mode": "discovered",
            "server_ids": session["server_ids"], "starts_at": session["starts_at"], "expires_at": session["expires_at"], "targets": matrix}


def learning_authorized(store, db, session, server=None):
    if session.get("initial_approval_mode") == "lab_only":
        return _lab(store)
    proof_value = session.get("initial_approval_proof")
    scope = session.get("initial_approval_scope")
    if not isinstance(scope, dict) or not authorized(store, db, proof_value, server_id=server["id"] if server is not None else None):
        return False
    try:
        if server is not None:
            # Scope/proof are created atomically from the complete review. A
            # per-host poll validates its normalized target binding without
            # querying every other host in a large learning session.
            if session.get("status") != "active" or not parse_time(session["starts_at"]) <= now() < parse_time(session["expires_at"]):
                return False
            if any(scope[key] != session[key] for key in ("policy_action", "selection_mode", "server_ids", "starts_at", "expires_at")):
                return False
            if not signed_target(store, server):
                return False
            return proof_value["plan_digest"] == session.get("initial_approval_plan_digest") and session.get("initial_approval_target_bindings", {}).get(server["id"]) == digest(_learning_target(session, server))
        return scope == _learning_scope(store, db, session) and proof_value["plan_digest"] == digest({"session_id": session["id"], "scope": scope})
    except (KeyError, TypeError, ValueError):
        return False


def activate_learning(store, db, session):
    """The Admin's Start-learning consent covers its frozen discovery result."""
    if session.get("initial_approval_mode") != "single_admin" or session.get("initial_approval_state") == "approved" or session.get("status") != "active" or session.get("discovery_pending_server_ids"):
        return False
    try:
        scope = _learning_scope(store, db, session)
        subject = session["initial_approval_requester"]
        if session.get("initial_provider_authority") != authority(store, db):return False
        plan = {"id":str(uuid.uuid4()), "session_id":session["id"], "plan_digest":digest({"session_id":session["id"],"scope":scope}),
                "scope":scope, "status":"approved", "confirmation_count":1, "confirmation_nonce":"", "created_by":session["created_by"],
                "created_at":session["starts_at"], "expires_at":session["expires_at"]}
        ids = sorted(session["server_ids"])
        proof_scope = {"kind":"learning", **({"server_ids":ids} if len(ids)==1 else {"target_count":len(ids),"target_digest":digest(ids)})}
        decision = derived(store, db, plan, subject, proof_scope, session["initial_provider_authority"])
        session.update(initial_approval_plan=plan, initial_approval_state="approved", initial_approval_scope=scope,
                       initial_approval_proof=decision, initial_approval_plan_digest=plan["plan_digest"],
                       initial_approval_target_bindings={row["server_id"]:digest(row) for row in scope["targets"]})
        store._put(db,"sessions",session)
        store.audit("learning.automatic_access_authorized",subject["actor"],{"session_id":session["id"],"scope_digest":plan["plan_digest"]},db)
        return True
    except (KeyError,ValueError,PermissionError):
        return False


def learning_preview(store, session_id, value, actor, principal=None):
    from .review_limits import MAX_REVIEW_BYTES, encoded_size
    if not isinstance(value, dict) or value:
        raise ValueError("Initial learning review uses the exact stored session scope; provide an empty object")
    with store.lock, store.meta() as db:
        session = store._get(db, "sessions", session_id)
        if not session:
            raise KeyError(session_id)
        maker = identity(store, db, actor, principal)
        requester = session.get("initial_approval_requester", {})
        scope = _learning_scope(store, db, session)
        existing = session.get("initial_approval_plan")
        if existing and existing.get("scope") == scope and parse_time(existing["expires_at"]) > now():
            encoded_size(existing)
            encoded_size(session)
            return existing
        if session.get("initial_approval_mode") not in ("single_admin",) or maker["user_id"] != requester.get("user_id") or actor != session.get("created_by"):
            raise PermissionError("Only the authenticated session requester can prepare its initial automatic-access review")
        identifier = str(uuid.uuid4())
        plan_digest = digest({"session_id": session_id, "scope": scope})
        plan = {"id": identifier, "session_id": session_id, "plan_digest": plan_digest, "scope": scope,
                "status": "draft", "confirmation_count": 0, "confirmation_nonce": secrets.token_urlsafe(24),
                "confirmation_phrase": "ALLOW LEARNING " + plan_digest[:12], "created_by": actor, "created_at": stamp(),
                "expires_at": stamp(min(now() + timedelta(minutes=10), parse_time(session["expires_at"])))}
        request(store, db, plan, actor, principal, endpoint_ids=scope["server_ids"])
        session["initial_approval_mode"] = plan["approval"]["mode"]
        encoded_size(plan)
        # Initial exact detail is nested in the session. Admit the eventual
        # approved scope/bindings as well, leaving room for both identities.
        encoded_size({**session, "initial_approval_plan": plan, "initial_approval_scope": scope,
                      "initial_approval_plan_digest": plan_digest,
                      "initial_approval_target_bindings": {row["server_id"]: digest(row) for row in scope["targets"]}},
                     MAX_REVIEW_BYTES - 65536)
        session.update(initial_approval_plan=plan, initial_approval_state="awaiting_review")
        encoded_size(session)
        store._put(db, "sessions", session)
        store.audit("learning.initial_authority_previewed", actor, {"session_id": session_id, "preview_id": identifier, "scope_digest": plan_digest}, db)
        return plan


def learning_confirm(store, session_id, value, actor, principal=None):
    from . import learning_policies as policies
    from .review_limits import encoded_size
    if not isinstance(value, dict):
        raise ValueError("Provide the current initial-authority preview and nonce")
    with store.lock, store.meta() as db:
        session = store._get(db, "sessions", session_id)
        if not session:
            raise KeyError(session_id)
        plan = session.get("initial_approval_plan")
        if not plan or value.get("preview_id") != plan["id"] or plan["status"] not in ("draft", "awaiting_second_confirmation") or parse_time(plan["expires_at"]) <= now() or plan["scope"] != _learning_scope(store, db, session):
            raise WorkflowConflict("Initial auto-allow scope changed, expired or no longer awaits approval; prepare a fresh review", {})
        if not isinstance(value.get("confirmation_nonce"), str) or not secrets.compare_digest(value["confirmation_nonce"], plan["confirmation_nonce"]):
            raise WorkflowConflict("The initial-authority confirmation nonce changed; refresh the review", {})
        final = True if plan.get("approval", {}).get("mode") == "single_admin" else plan["confirmation_count"] == 1
        if final and plan.get("approval", {}).get("mode") != "single_admin" and value.get("challenge") != plan["confirmation_phrase"]:
            raise WorkflowConflict("Type the exact initial auto-allow authority phrase", {})
        decide(store, db, plan, actor, principal) if plan.get("approval", {}).get("mode") == "single_admin" else confirm(store, db, plan, actor, principal, final=final, pilot_nonce=value.get("pilot_confirmation_nonce"))
        plan["confirmation_count"] += 1
        plan.update(status="approved" if final else "awaiting_second_confirmation", confirmation_nonce="" if final else secrets.token_urlsafe(24))
        session["initial_approval_state"] = "approved" if final else "submitted"
        if final:
            session.update(initial_approval_scope=plan["scope"], initial_approval_proof=proof(plan), initial_approval_plan_digest=plan["plan_digest"],
                           initial_approval_target_bindings={target["server_id"]: digest(target) for target in plan["scope"]["targets"]})
        encoded_size(plan)
        encoded_size(session)
        store._put(db, "sessions", session)
        if final:
            # Pending observations remain durable evidence and can now be
            # admitted automatically under the exact initial authority.
            for identifier in session["server_ids"]:
                server = store._get(db, "servers", identifier)
                policies._automatic(store, db, session, server, policies._evidence(db, session_id, identifier))
                policies.refresh_host(store, db, server)
        store.audit("learning.initial_authority_approved" if final else "learning.initial_authority_submitted", actor,
                    {"session_id": session_id, "preview_id": plan["id"], "scope_digest": plan["plan_digest"]}, db)
        return plan


def delivery(value):
    """Bounded signed identity/mode evidence, never a duplicated policy matrix."""
    if not isinstance(value, dict):
        return None
    if len(json.dumps(value,separators=(",",":"),ensure_ascii=False).encode()) > 16384:
        raise ValueError("Approval identity proof exceeds the delivery bound")
    return copy.deepcopy(value)
