"""Authenticated GUI configuration; candidate OIDC never grants application access.

Only fixed, typed settings reach the local privileged manager. Secrets remain
in its private channel and the controller vault, never public plans or URLs.
"""
from __future__ import annotations

from datetime import timedelta
import hashlib
import hmac
import json
import os
import re
import secrets

from .appliance import NodeClient, ManagerUnavailable
from .auth import EntraAuth, EntraConfig, AuthDenied, _set_cookie, STATE_COOKIE, TOKEN_PATTERN
from .firewall import WorkflowConflict
from .platform import _private_json, _read_json
from .store import digest, now, parse_time, stamp

AUTH_PUBLIC = ("SEG_ENTRA_TENANT_ID", "SEG_ENTRA_CLIENT_ID", "SEG_ENTRA_REDIRECT_URI", "SEG_BOOTSTRAP_SUPER_ADMIN_OID")
RUNTIME = {"SEG_HTTP_WORKERS": (1, 16), "SEG_HTTP_THREADS": (2, 128),
           "SEG_DB_POOL_META_MAX": (1, 64), "SEG_DB_POOL_TRAFFIC_MAX": (1, 16),
           "SEG_DB_POOL_WAIT_SECONDS": (1, 15), "SEG_CONTROL_PORT": (1, 65535), "SEG_DISCOVERY_PORT": (1, 65535)}
ID = re.compile(r"[a-f0-9]{32}")


def _guard(manager):
    if not manager or not manager.app or manager.app.demo:
        raise ValueError("GUI configuration requires an installed controller and its local manager")


def _state(manager, client=None):
    _guard(manager)
    value = (client or NodeClient()).status()
    config = value.get("controller_configuration")
    if not isinstance(config, dict) or not isinstance(config.get("digest"), str):
        raise ManagerUnavailable("Upgrade the installed manager to enable GUI controller configuration")
    return config


def _convergence_needed(manager, state):
    auth = manager.app.auth.config
    environment = state.get("environment", {})
    return auth.enabled and (not state.get("entra_configured") or bool(manager.active_profile()) and not state.get("provider_managed") or any(
        environment.get(key, "") != value for key, value in zip(AUTH_PUBLIC[:3], (auth.tenant_id, auth.client_id, auth.redirect_uri))))


def _effective_blockers(manager, state):
    if not manager.app.auth.enabled and state.get("entra_configured"):
        return ["Wait for the configured sign-in provider to finish restarting before another change"]
    return []


def _effective_environment(manager, state):
    result = dict(state.get("environment", {}))
    config = manager.app.auth.config
    if config.enabled:
        result.update(dict(zip(AUTH_PUBLIC, (config.tenant_id, config.client_id, config.redirect_uri, config.bootstrap_oid))))
    return result


def _save(manager, plan):
    _private_json(_path(manager, plan["id"]), plan)
    from .provider_lifecycle import update_plan
    update_plan(manager, plan)


def _path(manager, identifier):
    if not isinstance(identifier, str) or not ID.fullmatch(identifier):
        raise ValueError("A current setup review is required")
    return manager.root / "setup-plans" / (identifier + ".json")


def _latest_path(manager, authority):
    return manager.root / "setup-plans" / ("latest-" + authority + ".json")


def _prune(manager):
    # Unapplied expired proposals have no operational/recovery use. Their
    # encrypted client-secret copy is removed along with the proposal.
    for path in (manager.root / "setup-plans").glob("*.json"):
        if not ID.fullmatch(path.stem):
            continue
        plan = _read_json(path)
        if plan and plan.get("expires_at") and parse_time(plan["expires_at"]) <= now() and not plan.get("job_id"):
            reference = plan.get("request_ref", "")
            if re.fullmatch(r"secret:[a-f0-9]{32}", reference):
                (manager.vault.root / (reference[7:] + ".json")).unlink(missing_ok=True)
            path.unlink(missing_ok=True)


def _authority(manager, principal):
    if principal.get("role") != "super_admin":
        raise PermissionError("Only Super Admin can configure the controller")
    if principal.get("auth_type") == "token":
        token = manager.app.tokens.get("super_admin", "")
        if not token or manager.app.auth.enabled:
            raise PermissionError("The initial setup credential is no longer active")
        return digest([principal["actor"], hashlib.sha256(token.encode()).hexdigest()])
    if principal.get("auth_type") != "session":
        raise PermissionError("Use an authenticated Super Admin")
    with manager.app.store.read_meta() as db:
        manager.app.auth._require_super(principal, db)
    return digest([principal["actor"], manager.app.auth.config.fingerprint])


def _public(plan):
    return {key: plan.get(key) for key in ("id", "digest", "confirmation_nonce", "confirmation_phrase", "expires_at",
        "can_apply", "blockers", "summary", "candidate_login_required", "candidate_login_verified", "login_url", "job_id", "requires_independent", "approval", "cross_origin_verification")}


def status(manager, principal, client=None):
    try:
        state = _state(manager, client)
    except (ValueError, ManagerUnavailable) as error:
        return {"installed": False, "capabilities": {"configuration": False}, "environment": {},
                "entra_configured": bool(manager and manager.app and manager.app.auth.enabled),
                "setup_pending": None, "blockers": [str(error)]}
    authority = _authority(manager, principal)
    blockers = _effective_blockers(manager, state)
    with manager.lock:
        _prune(manager)
        pointer = _read_json(_latest_path(manager, authority)) or {}
        try:
            latest = _load(manager, pointer["id"]) if pointer.get("id") and _read_json(_path(manager, pointer["id"])) and parse_time(_read_json(_path(manager, pointer["id"]))["expires_at"]) > now() else None
        except WorkflowConflict:
            latest = None
        if latest and (latest.get("authority") != authority or parse_time(latest["expires_at"]) <= now()):
            latest = None
    identifiers = {path.stem for path in (manager.root / "setup-plans").glob("*.json") if ID.fullmatch(path.stem)}
    if manager.app.store.ha:
        with manager.app.store.read_meta() as db:
            identifiers.update(row["id"].split(":", 1)[1] for row in manager.app.store._all(db, "maintenance_settings") if row["id"].startswith("controller_provider_plan:"))
    reviews = []
    for identifier in sorted(identifiers):
        try:
            plan = _load(manager, identifier)
            if plan.get("summary", {}).get("provider_change") and not plan.get("job_id") and plan.get("approval", {}).get("mode") == "single_admin":
                reviews.append(_public(plan))
        except WorkflowConflict:
            pass
    return {"installed": True, "reviews": reviews, "capabilities": {"configuration": not blockers},
            "revision": state["expected_revision"], "configuration_digest": state["digest"],
            "environment": {key: value for key, value in _effective_environment(manager, state).items() if key in (*AUTH_PUBLIC, *RUNTIME)},
            "convergence_required": _convergence_needed(manager, state), "transition": __import__("controller.provider_lifecycle", fromlist=["get"]).get(manager),
            "entra_configured": bool(manager.app.auth.enabled or state.get("entra_configured")), "setup_pending": _public(latest) if latest else None,
            "blockers": blockers}


def _environment(value, current):
    if not isinstance(value, dict) or set(value) - set((*AUTH_PUBLIC, *RUNTIME)):
        raise ValueError("Provide only supported controller setup fields")
    result = {key: str(current.get(key, "")) for key in (*AUTH_PUBLIC, *RUNTIME)}
    for key, value in value.items():
        if not isinstance(value, str) or len(value) > 2048 or "\x00" in value or "\n" in value or "\r" in value:
            raise ValueError("Controller settings must be bounded single-line strings")
        result[key] = value.strip()
    for key, (low, high) in RUNTIME.items():
        if not result[key]:
            continue
        if not result[key].isdigit() or not low <= int(result[key]) <= high:
            raise ValueError(f"{key} must be empty for automatic defaults or between {low} and {high}")
        result[key] = str(int(result[key]))
    return result


def binding(request):
    return digest({"kind": "prthak-controller-config-v1", "operation_id": request["operation_id"],
                   "expected_revision": request["expected_revision"], "expected_config_digest": request["expected_config_digest"],
                   "environment": request["environment"],
                   "client_secret_sha256": hashlib.sha256(request.get("client_secret", "").encode()).hexdigest(),
                   "binding_salt": request.get("binding_salt", ""), "provider_epoch": request.get("provider_epoch", ""),
                   "provider_change": request.get("provider_change", False), "profile_convergence": request.get("profile_convergence", False),
                   "acknowledge_agent_aliases": request.get("acknowledge_agent_aliases", False)})


def preview(manager, body, principal, client=None):
    _guard(manager)
    if not isinstance(body, dict) or set(body) - {"expected_revision", "expected_config_digest", "environment", "client_secret", "candidate_object_id", "converge_profile", "retain_old_origin", "acknowledge_agent_aliases"}:
        raise ValueError("Provide a typed controller setup request")
    for key in ("converge_profile", "retain_old_origin", "acknowledge_agent_aliases"):
        if key in body and type(body[key]) is not bool:
            raise ValueError("Review acknowledgements must be booleans")
    authority = _authority(manager, principal)
    state = _state(manager, client)
    blockers = _effective_blockers(manager, state)
    if blockers:
        raise ValueError(blockers[0])
    if isinstance(body.get("expected_revision"), bool) or body.get("expected_revision") != state["expected_revision"] or body.get("expected_config_digest") != state["digest"]:
        raise WorkflowConflict("Installed configuration changed; refresh setup before reviewing", {})
    environment = _environment(body.get("environment"), _effective_environment(manager, state))
    if not manager.app.store.ha and environment["SEG_HTTP_WORKERS"] not in ("", "1"):
        raise ValueError("Standalone SQLite uses one worker; select AUTO or 1 until PostgreSQL activation")
    secret = body.get("client_secret", "")
    if not isinstance(secret, str) or len(secret) > 16384 or any(c in secret for c in ("\x00", "\n", "\r")):
        raise ValueError("Use a bounded Entra client secret without control characters")
    previous_ports = {key: state.get("environment", {}).get(key) or str(default) for key, default in (("SEG_CONTROL_PORT", 8788), ("SEG_DISCOVERY_PORT", 8789))}
    desired_ports = {key: environment.get(key) or str(default) for key, default in (("SEG_CONTROL_PORT", 8788), ("SEG_DISCOVERY_PORT", 8789))}
    changing_ports = previous_ports != desired_ports
    endpoint_count = len(manager.app.store.all("servers")) if changing_ports else 0
    if changing_ports and endpoint_count and body.get("acknowledge_agent_aliases") is not True:
        raise ValueError("Retain both old and new agent URLs through an external load balancer until signed endpoint transition kits are verified; acknowledge that dependency before changing live agent ports")
    current = manager.app.auth.config
    effective = _effective_environment(manager, state)
    converging = bool(body.get("converge_profile")) or _convergence_needed(manager, state)
    if converging and not current.enabled:
        raise ValueError("Profile convergence requires the current Entra Super Admin")
    changed_auth = any(environment[key] != effective.get(key, "") for key in AUTH_PUBLIC) or bool(secret)
    candidate = False
    expected_oid = ""
    if current.enabled:
        if principal.get("auth_type") != "session":
            raise PermissionError("Use a live Entra Super Admin session for provider changes")
        candidate = changed_auth or converging
        if candidate:
            same_tenant = environment[AUTH_PUBLIC[0]].lower() == current.tenant_id
            expected_oid = (principal.get("user") or {}).get("object_id", "") if same_tenant else body.get("candidate_object_id", "")
            from .auth import _guid
            expected_oid = _guid(expected_oid, "Reviewed candidate Super Admin Object ID")
            if not secret:
                if environment[AUTH_PUBLIC[0]] != current.tenant_id or environment[AUTH_PUBLIC[1]] != current.client_id:
                    raise ValueError("A different tenant/client needs its reviewed client secret")
                secret = current.client_secret
            config = EntraConfig(environment[AUTH_PUBLIC[0]], environment[AUTH_PUBLIC[1]], environment[AUTH_PUBLIC[2]], secret, expected_oid)
            if config.origin != current.origin and body.get("retain_old_origin") is not True:
                raise ValueError("Confirm that old and candidate HTTPS aliases remain reachable through migration")
            environment[AUTH_PUBLIC[3]] = ""
    elif any(environment[key] for key in AUTH_PUBLIC) or secret:
        if manager.app.store.ha or manager.active_profile() or manager.app.store.all("auth_users"):
            raise ValueError("Initial Entra setup requires the standalone bootstrap controller with no application users")
        config = EntraConfig(environment[AUTH_PUBLIC[0]], environment[AUTH_PUBLIC[1]], environment[AUTH_PUBLIC[2]], secret, environment[AUTH_PUBLIC[3]])
        if not config.enabled or not config.bootstrap_oid:
            raise ValueError("Select the existing Entra Object ID of the first Super Admin")
        expected_oid = config.bootstrap_oid
        candidate = True
    identifier = secrets.token_hex(16)
    from .provider_lifecycle import authority_binding, assert_current
    with manager.app.store.read_meta() as db:
        assert_current(manager.app, db)
        provider_authority = authority_binding(manager.app, db)
    request = {"action": "controller-config", "operation_id": identifier,
               "expected_revision": state["expected_revision"], "expected_config_digest": state["digest"], "environment": environment,
               "binding_salt": secrets.token_hex(32), "acknowledge_agent_aliases": body.get("acknowledge_agent_aliases", False), "profile_convergence": converging, "provider_change": bool(current.enabled and changed_auth)}
    if converging and os.environ.get("PRTHAK_PROVIDER_EPOCH"):
        request["provider_epoch"] = os.environ["PRTHAK_PROVIDER_EPOCH"]
    if secret:
        request["client_secret"] = secret
    plan = {"id": identifier, "created_at": now().isoformat(timespec="microseconds"), "expires_at": stamp(now() + timedelta(minutes=10)),
            "authority": authority, "created_by": principal["actor"], "can_apply": True, "blockers": [],
            "confirmation_nonce": secrets.token_urlsafe(24), "confirmation_phrase": "APPLY CONTROLLER SETUP " + identifier[:8].upper(),
            "candidate_login_required": candidate, "candidate_login_verified": False,
            "login_url": "/api/v1/platform/setup/login" if candidate else None,
            "binding_digest": binding(request), "request_ref": manager.vault.put(json.dumps(request)),
            "candidate_oid": expected_oid, "maker_session_id": principal.get("_session_id"), "maker_user_id": (principal.get("user") or {}).get("id"),
            "previous_auth_fingerprint": current.fingerprint, "provider_authority": provider_authority, "previous_origin": current.origin if current.enabled else "",
            "requires_independent": False,
            "cross_origin_verification": bool(candidate and current.enabled and config.origin != current.origin),
            "summary": {"environment": environment, "client_secret_supplied": bool(body.get("client_secret")), "agent_ports": {"changed": changing_ports, "previous": previous_ports, "desired": desired_ports, "enrolled_endpoints": endpoint_count, "external_aliases_acknowledged": body.get("acknowledge_agent_aliases", False), "requirement": "Keep both old and new agent URLs alive through an external load balancer until signed endpoint transition kits are applied and verified. This change updates this node publisher; it does not configure external routing."}, "runtime_controller": manager.app.controller_id, "retire_previous_tenant": bool(current.enabled and environment[AUTH_PUBLIC[0]].lower() != current.tenant_id), "candidate_object_id": expected_oid, "initial_entra": bool(candidate and not current.enabled), "provider_change": bool(current.enabled and changed_auth), "converge_profile": converging,
                        "message": "The provider changes across all registered controllers after the current Super Admin applies the verified candidate. Runtime and listener changes apply only to this controller; other controllers retain their local runtime ports and pools. Failed activation rolls back retained configuration." if current.enabled and changed_auth else "Configuration is generated privately. The owned controller restarts with verified rollback on failure."}}
    plan["digest"] = digest({key: value for key, value in plan.items() if key not in ("request_ref", "authority")})
    if plan["summary"]["provider_change"]:
        from . import approvals
        plan["plan_digest"] = plan["digest"]
        with manager.app.store.lock, manager.app.store.meta() as db:
            manager.app.auth._require_super(principal, db)
            approvals.request(manager.app.store, db, plan, principal["actor"], principal)
    from .provider_lifecycle import publish_plan
    publish_plan(manager, plan, request)
    with manager.lock:
        _prune(manager)
        _private_json(_path(manager, identifier), plan)
        _private_json(_latest_path(manager, authority), {"id": identifier})
        manager.app.store.audit("platform.setup.reviewed", principal["actor"], {"preview_id": identifier, "initial_entra": bool(candidate and not current.enabled), "provider_change": bool(current.enabled and changed_auth), "convergence": converging})
    return _public(plan)


def _load(manager, identifier):
    _path(manager, identifier)
    from .provider_lifecycle import shared_plan
    plan = shared_plan(manager, identifier) or _read_json(_path(manager, identifier))
    if not plan or parse_time(plan["expires_at"]) <= now():
        raise WorkflowConflict("Setup review expired; create a fresh review", {})
    if not plan.get("job_id"):
        from .provider_lifecycle import assert_review_current
        with manager.app.store.read_meta() as db:
            assert_review_current(manager.app, db, plan)
    return plan


def _candidate(manager, plan, provider=None):
    request = json.loads(manager.vault.get(plan["request_ref"]))
    environment = request["environment"]
    config = EntraConfig(*(environment[key] for key in AUTH_PUBLIC[:3]), request.get("client_secret", ""), plan.get("candidate_oid") or environment[AUTH_PUBLIC[3]])
    return EntraAuth(manager.app.store, config, provider, purpose="setup:" + plan["id"])


def begin_login(manager, body, principal, headers, provider=None):
    _guard(manager)
    if not isinstance(body, dict) or set(body) != {"preview_id"}:
        raise ValueError("A setup review identity is required")
    with manager.lock:
        plan = _load(manager, body["preview_id"])
        if plan["authority"] != _authority(manager, principal) or not plan["candidate_login_required"] or plan.get("job_id"):
            raise PermissionError("This setup sign-in is not authorized")
        auth = _candidate(manager, plan, provider)
        # A host-only Secure state cookie must return to this exact HTTPS origin.
        from .auth import _origin
        if _origin("https://" + headers.get("Host", "")) != auth.config.origin:
            if not plan.get("cross_origin_verification"):
                raise ValueError("Open the dashboard at the exact configured HTTPS callback origin before testing sign-in")
            raw = secrets.token_urlsafe(32)
            with manager.app.store.lock, manager.app.store.meta() as db:
                manager.app.store._put(db, "maintenance_settings", {"id": "provider_bridge:" + plan["id"], "hash": hashlib.sha256(raw.encode()).hexdigest(), "expires_at": stamp(now() + timedelta(minutes=2)), "used": False})
            return {"verification_url": auth.config.origin + "/provider-verification.html", "verification_code": plan["id"] + "." + raw}
        return auth.begin_login(headers)


def callback_plan(manager, query):
    values = query.get("state", [])
    if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], str) or not TOKEN_PATTERN.fullmatch(values[0]):
        return None
    with manager.app.store.read_meta() as db:
        state = manager.app.store._get(db, "auth_states", hashlib.sha256(values[0].encode()).hexdigest())
    purpose = (state or {}).get("purpose", "")
    return purpose[6:] if purpose.startswith("setup:") and ID.fullmatch(purpose[6:]) else None


def finish_login(manager, identifier, query, headers, provider=None):
    _guard(manager)
    with manager.lock:
        plan = _load(manager, identifier)
        if plan.get("job_id") or not plan["candidate_login_required"]:
            raise AuthDenied("This candidate setup is no longer active")
        if plan.get("maker_session_id"):
            _live_maker(manager, plan)
        else:
            current = {"role": "super_admin", "actor": plan["created_by"], "auth_type": "token"}
            if plan["authority"] != _authority(manager, current):
                raise AuthDenied("The setup credential changed; create a fresh review")
        auth = _candidate(manager, plan, provider)
        claims, verified = auth.verify_callback_identity(query, headers)
        if verified != auth.config.tenant_id + ":" + auth.config.bootstrap_oid:
            raise AuthDenied("Sign in as the exact reviewed initial Super Admin")
        plan.update(candidate_login_verified=True, candidate_verified_at=stamp(), candidate_identity=verified)
        _save(manager, plan)
        manager.app.store.audit("platform.setup.candidate_verified", plan["created_by"], {"preview_id": identifier, "identity": verified})
    return {"location": (plan.get("previous_origin", "") if plan.get("cross_origin_verification") else "") + "/settings?setup=verified", "cookies": [_set_cookie(STATE_COOKIE)]}


def apply(manager, body, principal, client=None):
    _guard(manager)
    if not isinstance(body, dict) or set(body) != {"preview_id", "digest", "confirmation_nonce", "confirmation_phrase"}:
        raise ValueError("Confirm the exact reviewed controller configuration")
    with manager.lock:
        plan = _load(manager, body["preview_id"])
        authority = _authority(manager, principal)
        if plan["authority"] != authority or any(not isinstance(body.get(key), str) or not hmac.compare_digest(body[key], plan[key]) for key in ("digest", "confirmation_nonce", "confirmation_phrase")):
            raise WorkflowConflict("Setup review changed or was not confirmed exactly", {})
        if plan.get("job_id"):
            if plan["job_id"].startswith("provider:"):
                from .provider_lifecycle import get
                return {"provider_transition": get(manager), "preview": _public(plan)}
            return manager.job(plan["job_id"])
        if plan["candidate_login_required"] and not plan["candidate_login_verified"]:
            raise ValueError("Complete the reviewed initial Super Admin's Entra sign-in before activation")
        if plan.get("summary", {}).get("provider_change"):
            from . import approvals
            with manager.app.store.lock, manager.app.store.meta() as db:
                manager.app.auth._require_super(principal, db)
                approvals.decide(manager.app.store, db, plan, principal["actor"], principal)
            _save(manager, plan)
        request = json.loads(manager.vault.get(plan["request_ref"]))
        state = _state(manager, client)
        blockers = _effective_blockers(manager, state)
        if blockers:
            raise ValueError(blockers[0])
        if not plan.get("summary", {}).get("provider_change") and (request["expected_revision"] != state["expected_revision"] or request["expected_config_digest"] != state["digest"]):
            raise WorkflowConflict("Installed controller changed; review it again", {})
        if plan["binding_digest"] != binding(request):
            raise ValueError("Private setup material no longer matches its review")
        if plan["candidate_login_required"]:
            request.update(candidate_login_verified=True, candidate_binding_digest=plan["binding_digest"])
        if plan.get("summary", {}).get("provider_change"):
            from .provider_lifecycle import queue
            transition = queue(manager, plan, request)
            plan["job_id"] = "provider:" + plan["id"]
            _save(manager, plan)
            return {"provider_transition": transition, "preview": _public(plan)}
        reference = manager.vault.put(json.dumps(request))
        job = manager._queue("appliance", {"request_ref": reference}, principal["actor"])
        plan["job_id"] = job["id"]
        _save(manager, plan)
        return job


def _live_maker(manager, plan):
    with manager.app.store.read_meta() as db:
        session = manager.app.store._get(db, "auth_sessions", plan.get("maker_session_id", ""))
        user = manager.app.store._get(db, "auth_users", plan.get("maker_user_id", ""))
        if not session or not user or user.get("enabled") is not True or user.get("role") != "super_admin" or session.get("user_id") != user.get("id") or parse_time(session["expires_at"]) <= now() or session.get("config") != plan["previous_auth_fingerprint"]:
            raise AuthDenied("The reviewing Super Admin session is no longer live")


def reconcile(manager, client=None):
    from .provider_lifecycle import reconcile as advance
    return advance(manager, client)


def bridge_login(manager, body, headers, provider=None):
    _guard(manager)
    if not isinstance(body, dict) or set(body) != {"verification_code"} or not isinstance(body["verification_code"], str) or not re.fullmatch(r"[a-f0-9]{32}\.[A-Za-z0-9_-]{43}", body["verification_code"]):
        raise AuthDenied("Enter the current one-time verification code")
    identifier, raw = body["verification_code"].split(".")
    plan = _load(manager, identifier)
    if plan.get("job_id") or not plan.get("cross_origin_verification") or plan.get("candidate_login_verified"):
        raise AuthDenied("This candidate verification is no longer current")
    _live_maker(manager, plan)
    auth = _candidate(manager, plan, provider)
    from .auth import _origin
    if _origin("https://" + headers.get("Host", "")) != auth.config.origin or headers.get("Origin") != auth.config.origin:
        raise AuthDenied("Open the exact reviewed candidate HTTPS origin")
    with manager.app.store.lock, manager.app.store.meta() as db:
        bridge = manager.app.store._get(db, "maintenance_settings", "provider_bridge:" + identifier)
        if not bridge or bridge.get("used") or parse_time(bridge["expires_at"]) <= now() or not hmac.compare_digest(bridge["hash"], hashlib.sha256(raw.encode()).hexdigest()):
            raise AuthDenied("The verification code expired or was already used")
        bridge["used"] = True
        manager.app.store._put(db, "maintenance_settings", bridge)
    return auth.begin_login(headers)
