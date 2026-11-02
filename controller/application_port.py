"""Reviewed, node-local application listener changes through the supervisor.

Standalone changes retain their exact bind address. Appliance changes affect
only the fixed host publisher; database/backend/container ports stay separate.
Public origins, Entra registrations and agent URLs are never rewritten here.
"""
from __future__ import annotations

from contextlib import contextmanager
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import time
from datetime import timedelta
from urllib.parse import urlsplit

from .firewall import WorkflowConflict
from .platform import _private_json, _read_json
from .store import digest, now, parse_time, stamp

STATE = "application-port.json"
CONTEXT = "application-listen-context.json"
OBSERVED = "application-listen-observed.json"
SCHEME = "prthak-application-port-v1"
TERMINAL = frozenset(("applied", "rolled_back", "blocked", "failed", "error", "cancelled"))
DEPENDENCIES = [
    "Only this node's listener/published port changes; its bind address and TLS identity remain unchanged.",
    "The configured public controller and SSO origin are preserved. Keep that origin routable through your external load balancer, or separately update controller Entra configuration and the registered callback before relying on a direct new URL.",
    "Existing cookies may read the direct new URL but authenticated changes/sign-in can fail until their configured SSO origin is routable. TLS/database readiness does not verify Microsoft sign-in.",
    "Update direct agent/peer bookmarks, host/network firewalls, DNS and load-balancer backend configuration separately when they use the old port. No external configuration is changed automatically.",
]


class PortError(ValueError):
    pass


@contextmanager
def _lock(manager):
    descriptor = os.open(manager.root / ".application-port.lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def _port(value):
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise ValueError("Application port must be an integer from 1 to 65535")
    return value


def _listen(value):
    if not isinstance(value, str):
        raise PortError("The current supervised listener is unavailable")
    try:
        from .listener_address import split_listener
        host, port = split_listener(value)
        return ('[' + host + ']' if ':' in host else host), port
    except (ValueError, TypeError):
        raise PortError("The supervised listener address is invalid") from None


def record_context(manager, arguments):
    from .platform_runtime import _argument
    address = _argument(arguments, "--listen", "127.0.0.1:8787")
    host, port = _listen(address)
    _private_json(manager.root / CONTEXT, {"bind_address": host, "base_port": port, "base_listen": address, "scheme": "http" if "--demo" in arguments else "https", "demo": "--demo" in arguments, "supervised": True, "mode": "appliance_public" if os.environ.get("PRTHAK_APPLIANCE") == "1" and "--demo" not in arguments else "standalone"})


def record_observed(manager, listen):
    host, port = _listen(listen)
    _private_json(manager.root / OBSERVED, {"bind_address": host, "port": port, "pid": os.getpid(), "observed_at": stamp()})


def _state(manager):
    return _read_json(manager.root / STATE, {"revision": 0, "applied": None, "pending": None, "last_job_id": None})


def _context(manager):
    return _read_json(manager.root / CONTEXT, {})


def committed_binding(manager):
    state = _state(manager)
    return copy.deepcopy(state.get("applied"))


def launch_arguments(manager, arguments, override=None):
    from .platform_runtime import _argument, _set_argument
    if _context(manager).get("mode") == "appliance_public":
        if override is not None:
            raise PortError("An appliance public-port change cannot alter the container listener")
        return list(arguments)
    saved = committed_binding(manager)
    if not saved and override is None:
        return list(arguments)
    host, _ = _listen(_argument(arguments, "--listen", "127.0.0.1:8787"))
    expected = (saved or {}).get("bind_address", _context(manager).get("bind_address"))
    if host != expected:
        raise PortError("The saved GUI port is bound to a different CLI address; no host exposure expansion is allowed")
    return _set_argument(arguments, "--listen", host + ":" + str(_port(override if override is not None else saved["port"])))


def advertised_origin(manager, node_ip):
    applied = committed_binding(manager)
    if not applied or _context(manager).get("mode") != "appliance_public":
        return None
    host = "[" + node_ip + "]" if ":" in node_ip else node_ip
    return "https://" + host + ":" + str(applied["port"])


def _manager_client(manager):
    from .appliance import NodeClient
    return getattr(manager, "application_port_client", None) or NodeClient()


def _runtime_store(manager):
    app = getattr(manager, "app", None)
    if app:
        return app.store
    profile = manager.active_profile()
    if profile:
        from .postgres import PostgresStore
        return PostgresStore(profile["metadata_dsn"], profile["traffic_dsn"], initialize=False, deployment_id=profile["deployment_id"], epoch=profile["epoch"])
    from .recovery import _facade
    return _facade(manager.data_dir)


def _node(manager):
    app = getattr(manager, "app", None)
    return app.controller_id if app else _read_json(manager.root / "controller-identity.json", {}).get("controller_id")


def in_progress(store, db):
    return [record for record in store._all(db, "maintenance_settings") if record.get("id", "").startswith("application_port:") and record.get("status") not in TERMINAL]


def _reserve(manager, job):
    store = _runtime_store(manager)
    node = _node(manager)
    if not node:
        raise PortError("A persisted local controller identity is required")
    with store.lock, store.meta() as db:
        if getattr(db, "dialect", "sqlite") != "postgresql":
            db.execute("BEGIN IMMEDIATE")
        recovery = store._get(db, "maintenance_settings", "recovery_control:active")
        if recovery and recovery.get("phase") not in ("completed", "cancelled"):
            raise WorkflowConflict("Recovery already owns this deployment transition", {})
        current = store._get(db, "maintenance_settings", "application_port:" + node)
        if current and current.get("status") not in TERMINAL and current.get("job_id") != job["id"]:
            raise WorkflowConflict("This node already has a pending port operation", {})
        store._put(db, "maintenance_settings", {"id": "application_port:" + node, "node_id": node, "job_id": job["id"], "status": "pending", "digest": job["private"]["plan"]["digest"], "updated_at": stamp()})


def recover_incomplete(manager):
    """Recover only committed reservations; an uncommitted file grants nothing."""
    paths = [path for path in (manager.root / "jobs").glob("*.json") if (record := _read_json(path)) and record.get("operation") == "application-port" and record.get("status") == "reserving"]
    if not paths:
        return
    with _lock(manager):
        store = _runtime_store(manager)
        for path in paths:
            job = _read_json(path)
            if job.get("status") != "reserving":
                continue
            with store.read_meta() as db:
                reservation = store._get(db, "maintenance_settings", "application_port:" + str(_node(manager)))
            if not reservation or reservation.get("job_id") != job["id"] or reservation.get("digest") != job["private"]["plan"]["digest"]:
                job.update(status="blocked", phase="reservation_not_committed", error="Port authority did not commit; no listener change was attempted")
                _private_json(path, job)
                continue
            state = _state(manager)
            private = job["private"]
            if state["revision"] == private["plan"]["expected_revision"]:
                state.update(revision=private["target_revision"], pending={"job_id": job["id"], "port": private["plan"]["new_port"]}, last_job_id=job["id"])
                _private_json(manager.root / STATE, state)
            if state.get("last_job_id") != job["id"]:
                job.update(status="blocked", phase="reservation_changed", error="A newer local port revision owns this node")
            else:
                job.update(status="queued", phase="queued")
                plan_path = manager.root / "application-port-plans" / (private["plan"]["id"] + ".json")
                plan = _read_json(plan_path)
                if plan and plan.get("digest") == private["plan"]["digest"]:
                    plan["job_id"] = job["id"]
                    _private_json(plan_path, plan)
            _private_json(path, job)


def _runtime_busy(manager, exclude=None):
    return [record for path in (manager.root / "jobs").glob("*.json") if (record := _read_json(path)) and record.get("id") != exclude and record.get("operation") in ("activate", "join", "certificate", "application-port", "recovery", "appliance", "preflight", "provision") and record.get("status") in ("reserving", "queued", "running", "stopping", "verified", "draining")]


def _recovery_binding(manager):
    if (manager.root / "recovery-writer-fence.json").exists():
        raise PortError("Reviewed recovery owns the writer fence; port changes are paused")
    completed = []
    for path in (manager.root / "recovery").glob("*/control.json"):
        value = _read_json(path)
        if value and value.get("phase") == "completed":
            completed.append(value["recovery_id"])
    return sorted(completed)


def _details(manager):
    context, state = _context(manager), _state(manager)
    if not context:
        raise PortError("Restart this node with the updated supervisor before configuring its application port")
    tls = manager.certificate_context()
    profile = manager.active_profile()
    source = {"mode": context["mode"], "bind_address": context["bind_address"], "scheme": context["scheme"], "base_port": context["base_port"], "applied": state.get("applied"), "profile_digest": digest(profile), "tls_digest": digest({key: tls.get(key) for key in ("cert_path", "key_path", "ca_path", "hostname", "current_fingerprint")}), "tls_overlay_digest": digest(manager.launch_tls()), "recoveries": _recovery_binding(manager)}
    native = None
    if context["mode"] == "appliance_public":
        try:
            native = _manager_client(manager).status()
        except Exception:
            raise PortError("The fixed node manager public listener state is unavailable") from None
        if "public_port_v1" not in native.get("capabilities", []):
            raise PortError("Upgrade the fixed node manager before changing its public application port")
        port = _port(native.get("public_port"))
        source.update(bind_address=native.get("bind_address"), public_port=port, appliance_id=native.get("appliance_id"), manager_revision=native.get("revision"))
        source.update(public_fingerprint=tls.get("current_fingerprint"), public_server_name=manager.launch_tls().get("hostname") or tls.get("hostname"))
        if not isinstance(source["bind_address"], str) or not source["appliance_id"]:
            raise PortError("The fixed node manager did not report a bound local publication identity")
        if not re.fullmatch(r"[a-f0-9]{64}", str(source["public_fingerprint"] or "")) or not source["public_server_name"]:
            raise PortError("The exact current public HTTPS fingerprint/name is required before reviewing its port")
    else:
        port = (state.get("applied") or {}).get("port", context["base_port"])
    app = getattr(manager, "app", None)
    configured_origin = (profile or {}).get("controller_origin") or os.environ.get("CONTROLLER_ORIGIN", "")
    sso_origin = None
    directory = getattr(getattr(app, "auth", None), "config", None)
    if directory is not None and directory.enabled:
        sso_origin = directory.origin
    elif not context.get("demo"):
        from .auth import EntraConfig
        auth = EntraConfig.from_env({**os.environ, **(profile or {}).get("controller_env", {})})
        sso_origin = auth.origin if auth.enabled else None
    if not configured_origin or not sso_origin:
        if app:
            store = app.store
        elif profile:
            from .postgres import PostgresStore
            store = PostgresStore(profile["metadata_dsn"], profile["traffic_dsn"], initialize=False, deployment_id=profile["deployment_id"], epoch=profile["epoch"])
        else:
            from .recovery import _facade
            store = _facade(manager.data_dir)
        with store.read_meta() as db:
            if not configured_origin:
                config = store._get(db, "maintenance_settings", "appliance_cluster") or {}
                configured_origin = config.get("controller_origin", "")
            if not sso_origin:
                record = store._get(db, "maintenance_settings", "saml_configuration") or {}
                config = record.get("config", record) if isinstance(record, dict) else {}
                if isinstance(config, dict) and config.get("enabled") is True:
                    from .local_auth import LocalAuth
                    sso_origin = LocalAuth._origin(config.get("origin"))
    source["controller_origin"] = configured_origin
    source["sso_origin"] = sso_origin
    return context, state, source, tls, native, port


def _url(context, source, tls, port):
    host = tls.get("hostname") or urlsplit(source.get("controller_origin", "")).hostname or context.get("bind_address")
    host = {"0.0.0.0": "127.0.0.1", "::": "::1"}.get(host, host)
    if not host:
        return None
    if ":" in host and not host.startswith("["):
        host = "[" + host + "]"
    return context["scheme"] + "://" + host + ":" + str(port)


def _cluster_blockers(manager):
    app = getattr(manager, "app", None)
    if not app:
        return []
    with app.store.read_meta() as db:
        config = app.store._get(db, "maintenance_settings", "appliance_cluster") or {}
        control = app.store._get(db, "maintenance_settings", "recovery_control:active")
    result = []
    if control and control.get("phase") not in ("completed", "cancelled"):
        result.append("Database recovery is pending; finish it before changing the listener")
    local = _read_json(manager.root / "appliance-local.json", {})
    if not app.store.ha and (len(config.get("members", [])) > 1 or local.get("authorized_join")):
        result.append("Finish shared database activation first: pre-active peers still use their pinned seed URL")
    return result


def status(manager):
    if not manager:
        return {"revision": 0, "current_port": None, "desired_port": None, "applied_port": None, "can_apply": False, "blockers": ["A local supervised controller is required"], "allowed_range": {"min": 1, "max": 65535}}
    try:
        context, state, source, tls, native, port = _details(manager)
    except Exception as error:
        return {"revision": _state(manager)["revision"], "current_port": None, "desired_port": None, "applied_port": None, "can_apply": False, "blockers": [str(error) if isinstance(error, PortError) else "Local listener state could not be verified"], "allowed_range": {"min": 1, "max": 65535}}
    app = getattr(manager, "app", None)
    blockers = _cluster_blockers(manager)
    if context.get("demo") or app and app.demo:
        blockers.append("Synthetic demo can review the setting but cannot restart or republish the application")
    if state.get("pending") or _runtime_busy(manager):
        blockers.append("A runtime operation is pending; wait for its verified result")
    current = port
    if source["mode"] == "standalone" and app and getattr(app, "application_listen", None):
        current = _listen(app.application_listen)[1]
    pending = state.get("pending") or {}
    job = None
    if state.get("last_job_id"):
        try:
            job = manager.job(state["last_job_id"])
        except KeyError:
            pass
    return {"revision": state["revision"], "mode": source["mode"], "current_port": current, "desired_port": pending.get("port", port), "applied_port": port, "bind_address": source["bind_address"], "current_url": _url(context, source, tls, current), "new_url": _url(context, source, tls, pending.get("port", port)), "controller_origin": source["controller_origin"], "sso_origin": source["sso_origin"], "origin_mode": "preserve", "can_apply": not blockers, "blockers": blockers, "last_job": job, "allowed_range": {"min": 1, "max": 65535}, "dependencies": DEPENDENCIES, "readiness_scope": "Local bind/TLS/database readiness only; external routing and SSO sign-in are not verified"}


def _bind_check(host, port):
    address = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        values = socket.getaddrinfo(address, port, socket.AF_UNSPEC, socket.SOCK_STREAM, 0, socket.AI_PASSIVE)
        family, kind, protocol, _, sockaddr = values[0]
        with socket.socket(family, kind, protocol) as candidate:
            candidate.bind(sockaddr)
    except OSError:
        raise PortError("The proposed port is occupied, unavailable on the existing bind address, or not permitted for this service account") from None


def preview(manager, body, actor):
    if not isinstance(body, dict) or set(body) - {"expected_revision", "port"}:
        raise ValueError("Port review accepts expected_revision and port only")
    port = _port(body.get("port"))
    with _lock(manager):
        context, state, source, tls, native, current = _details(manager)
        if body.get("expected_revision") != state["revision"] or isinstance(body.get("expected_revision"), bool):
            raise WorkflowConflict("Application port settings changed; reload before review", {})
        if port == current:
            raise ValueError("Choose a port different from the currently applied port")
        blockers = status(manager)["blockers"]
        if native and port in native.get("agent_channel_ports", {}).values():
            blockers.append("The proposed port is reserved for the agent control or discovery listener")
        if source["mode"] == "standalone":
            try:
                _bind_check(source["bind_address"], port)
            except PortError as error:
                blockers.append(str(error))
        identifier = secrets.token_hex(16)
        plan = {"id": identifier, "preview_id": identifier, "kind": SCHEME, "expected_revision": state["revision"], "source": source, "current_port": current, "new_port": port, "bind_address": source["bind_address"], "current_url": _url(context, source, tls, current), "new_url": _url(context, source, tls, port), "controller_origin": source["controller_origin"], "sso_origin": source["sso_origin"], "origin_mode": "preserve", "dependency_ack_required": True, "dependencies": DEPENDENCIES, "can_apply": not blockers, "blockers": blockers, "created_at": stamp(), "created_by": actor, "expires_at": stamp(now() + timedelta(minutes=10)), "confirmation_nonce": secrets.token_urlsafe(24)}
        plan["digest"] = digest({key: plan[key] for key in ("id", "expected_revision", "source", "current_port", "new_port", "created_by")})
        plan["confirmation_phrase"] = "CHANGE PORT " + str(current) + " TO " + str(port) + " " + plan["digest"][:8]
        _private_json(manager.root / "application-port-plans" / (identifier + ".json"), plan)
        if getattr(manager, "app", None):
            manager.app.store.audit("application_port.previewed", actor, {"preview_id": identifier, "old_port": current, "new_port": port, "digest": plan["digest"]})
        return {key: copy.deepcopy(value) for key, value in plan.items() if key != "source"}


def apply(manager, body, actor):
    if not isinstance(body, dict) or not re.fullmatch(r"[a-f0-9]{32}", str(body.get("preview_id", ""))):
        raise ValueError("Choose the exact reviewed application port preview")
    with _lock(manager):
        path = manager.root / "application-port-plans" / (body["preview_id"] + ".json")
        plan = _read_json(path)
        if not plan or plan.get("kind") != SCHEME:
            raise ValueError("Unknown application port review")
        if plan.get("job_id"):
            return manager.job(plan["job_id"])
        context, state, source, tls, native, current = _details(manager)
        if context.get("demo") or getattr(getattr(manager, "app", None), "demo", False):
            raise PermissionError("Synthetic demo cannot change the running application port")
        if not plan["can_apply"] or parse_time(plan["expires_at"]) <= now() or any(body.get(key) != plan[key] for key in ("digest", "expected_revision", "confirmation_nonce", "confirmation_phrase")):
            raise WorkflowConflict("The exact unexpired port review and typed phrase are required", {})
        if body.get("acknowledge_dependencies") is not True:
            raise ValueError("Acknowledge the public-origin, Entra, agent and external routing dependencies")
        if state["revision"] != plan["expected_revision"] or digest(source) != digest(plan["source"]) or _runtime_busy(manager) or _cluster_blockers(manager):
            raise WorkflowConflict("Runtime, TLS, recovery, membership or port state changed; review again", {})
        if source["mode"] == "standalone":
            _bind_check(source["bind_address"], plan["new_port"])
        private = {"plan": plan, "target_revision": state["revision"] + 1, "original_applied": copy.deepcopy(state.get("applied"))}
        job = {"id": secrets.token_hex(16), "operation": "application-port", "status": "reserving", "phase": "reserving", "created_at": stamp(), "updated_at": stamp(), "created_by": actor, "private": private}
        _private_json(manager._job_path(job["id"]), job)
        try:
            _reserve(manager, job)
        except Exception:
            manager.runtime_job_update(job["id"], "blocked", {"phase": "reservation_rejected", "error": "Recovery or another local operation owns the runtime; no port change was queued"})
            raise
        state.update(revision=private["target_revision"], pending={"job_id": job["id"], "port": plan["new_port"]}, last_job_id=job["id"])
        _private_json(manager.root / STATE, state)
        plan["job_id"] = job["id"]
        _private_json(path, plan)
        manager.runtime_job_update(job["id"], "queued", {"phase": "queued"})
        if getattr(manager, "app", None):
            manager.app.store.audit("application_port.queued", actor, {"job_id": job["id"], "old_port": current, "new_port": plan["new_port"], "digest": plan["digest"]})
        return manager.job(job["id"])


def _finish(manager, job, applied, status_value, phase, error=None):
    with _lock(manager):
        state = _state(manager)
        owns = state.get("last_job_id") == job["id"]
        if owns:
            state.update(applied=applied, pending={"job_id": job["id"], "port": job["private"]["plan"]["new_port"]})
            _private_json(manager.root / STATE, state)
        store = _runtime_store(manager)
        with store.lock, store.meta() as db:
            marker = store._get(db, "maintenance_settings", "application_port:" + str(_node(manager)))
            if not marker or marker.get("job_id") != job["id"]:
                raise PortError("The committed port reservation no longer belongs to this operation")
            marker.update(status=status_value, updated_at=stamp())
            store._put(db, "maintenance_settings", marker)
        if owns:
            state["pending"] = None
            _private_json(manager.root / STATE, state)
        context = _context(manager)
        plan = job["private"]["plan"]
        original_port = plan["current_port"] if plan["source"]["mode"] == "appliance_public" else context.get("base_port", plan["current_port"])
        port = (applied or {}).get("port", original_port)
        result = {"applied_port": port, "current_url": plan["new_url"] if port == plan["new_port"] else plan["current_url"], "new_url": plan["new_url"], "verified": status_value in ("applied", "rolled_back"), "controller_origin": plan["controller_origin"], "readiness_scope": "Local bind/TLS/database readiness only", "external_updates_required": True}
        manager.runtime_job_update(job["id"], status_value, {"phase": phase, "result": result, **({"error": error} if error else {})})


def _wait(supervisor, arguments, profile, fingerprint, hostname):
    from .platform_runtime import probe_readiness
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline and not supervisor.stopping.is_set():
        if supervisor.child is None or supervisor.child.poll() is not None:
            return False
        ready = supervisor.probe(arguments, profile, tls_hostname=hostname) if supervisor.probe is probe_readiness else supervisor.probe(arguments, profile)
        if ready and (not fingerprint or supervisor._certificate_matches(arguments, hostname, fingerprint)):
            return True
        supervisor.stopping.wait(.15)
    return False


def _source_valid(source, state, job):
    expected = job["private"]["plan"]["source"]
    actual = copy.deepcopy(source)
    applied = state.get("applied") or {}
    if state.get("last_job_id") == job["id"] and applied.get("revision") == job["private"]["target_revision"] and applied.get("port") == job["private"]["plan"]["new_port"]:
        actual["applied"] = expected["applied"]
    return digest(actual) == digest(expected)


def _rollback(supervisor, job, path, journal, message):
    manager, private = supervisor.manager, job["private"]
    plan = private["plan"]
    journal.update(phase="rolling_back", error=message)
    _private_json(path, journal)
    try:
        if supervisor.child is not None:
            if supervisor.stop(supervisor.child) is not True:
                raise PortError("Candidate process group is still active")
            supervisor.child = None
        with _lock(manager):
            state = _state(manager)
            state["applied"] = private.get("original_applied")
            _private_json(manager.root / STATE, state)
        profile = manager.active_profile() or supervisor.current_profile
        arguments = supervisor.start_child(profile, application_port_override=plan["current_port"])
        if not _wait(supervisor, arguments, profile, journal.get("tls_fingerprint"), journal.get("tls_hostname")):
            raise PortError("Original listener did not verify")
        _queue_outcome(supervisor, job, path, journal, private.get("original_applied"), "rolled_back", "previous_port_restored", message)
    except Exception:
        journal["retry_after"] = stamp(now() + timedelta(seconds=5))
        _private_json(path, journal)
        manager.runtime_job_update(job["id"], "queued", {"phase": "rollback_unverified", "error": "Original listener readiness is unverified; the same rollback will retry and new runtime work remains paused"})


def _queue_outcome(supervisor, job, path, journal, applied, status_value, phase, error=None):
    journal.update(phase="finishing", finish={"applied": applied, "status": status_value, "phase": phase, "error": error})
    journal.pop("retry_after", None)
    _private_json(path, journal)
    return _finish_pending(supervisor, job, path, journal)


def _finish_pending(supervisor, job, path, journal):
    manager, finish = supervisor.manager, journal["finish"]
    if journal.get("retry_after") and parse_time(journal["retry_after"]) > now():
        manager.runtime_job_update(job["id"], "queued", {"phase": "finalization_pending"})
        return
    try:
        if finish["status"] in ("applied", "rolled_back") and _context(manager).get("mode") == "standalone":
            port = (finish["applied"] or {}).get("port", job["private"]["plan"]["current_port"])
            profile = manager.active_profile() or supervisor.current_profile
            arguments = supervisor.start_child(profile, application_port_override=port) if supervisor.child is None else getattr(supervisor, "last_launch_arguments", supervisor.arguments)
            if not _wait(supervisor, arguments, profile, journal.get("tls_fingerprint"), journal.get("tls_hostname")):
                raise PortError("Final listener readiness is not currently verified")
        _finish(manager, job, finish["applied"], finish["status"], finish["phase"], finish.get("error"))
        journal["phase"] = "committed" if finish["status"] == "applied" else "rolled_back" if finish["status"] == "rolled_back" else "blocked"
        _private_json(path, journal)
    except Exception:
        journal["retry_after"] = stamp(now() + timedelta(seconds=5))
        _private_json(path, journal)
        manager.runtime_job_update(job["id"], "queued", {"phase": "finalization_pending", "error": "Verified local port state is preserved; its exact metadata receipt will retry before other runtime work"})


def execute(supervisor, job):
    """Own supervisor thread; never called in a request or a worker process."""
    manager, private = supervisor.manager, job["private"]
    plan = private["plan"]
    journal_path = manager.root / "application-port-journals" / (job["id"] + ".json")
    journal = _read_json(journal_path, {"phase": "prepared"})
    try:
        if journal["phase"] == "finishing":
            return _finish_pending(supervisor, job, journal_path, journal)
        # Dispatch by the reviewed immutable runtime mode. A temporary host
        # status failure must never turn a public mapping into an internal
        # standalone restart or publish-port override.
        if plan["source"]["mode"] == "appliance_public":
            try:
                native = _manager_client(manager).status()
            except Exception:
                manager.runtime_job_update(job["id"], "queued", {"phase": "public_manager_unavailable", "error": "Fixed host state is unavailable; this exact operation will retry without changing the internal listener"})
                return
            return _execute_appliance(supervisor, job, journal_path, journal, native)
        context, state, source, tls, native, current = _details(manager)
        if journal["phase"] == "rolling_back":
            if journal.get("retry_after") and parse_time(journal["retry_after"]) > now():
                manager.runtime_job_update(job["id"], "queued", {"phase": "waiting_for_rollback"})
                return
            return _rollback(supervisor, job, journal_path, journal, journal.get("error", "Interrupted candidate requires compensation"))
        if not _source_valid(source, state, job):
            raise PortError("Listener, TLS, database profile or recovery state changed before execution")
        if journal["phase"] == "prepared":
            if (state.get("pending") or {}).get("job_id") != job["id"]:
                raise PortError("Listener, TLS, database profile or recovery state changed before execution")
            _bind_check(source["bind_address"], plan["new_port"])
            journal.update(phase="draining", tls_fingerprint=tls.get("current_fingerprint"), tls_hostname=manager.launch_tls().get("hostname") or tls.get("hostname"))
            _private_json(journal_path, journal)
        profile = manager.active_profile() or supervisor.current_profile
        manager.runtime_job_update(job["id"], "stopping", {"phase": "listener_restart"})
        if supervisor.child is not None:
            if supervisor.stop(supervisor.child) is not True:
                journal["phase"] = "prepared"
                raise PortError("The previous controller process group did not drain; no new listener was started")
            supervisor.child = None
        journal["phase"] = "starting"
        _private_json(journal_path, journal)
        arguments = supervisor.start_child(profile, application_port_override=plan["new_port"])
        if not _wait(supervisor, arguments, profile, journal.get("tls_fingerprint"), journal.get("tls_hostname")):
            raise PortError("The candidate listener failed exact local TLS/database readiness")
        applied = {"port": plan["new_port"], "bind_address": plan["bind_address"], "revision": private["target_revision"]}
        _queue_outcome(supervisor, job, journal_path, journal, applied, "applied", "active")
    except Exception as error:
        message = str(error) if isinstance(error, PortError) else "Application listener change failed; no external URLs were rewritten"
        if plan["source"]["mode"] == "appliance_public":
            manager.runtime_job_update(job["id"], "queued", {"phase": "public_state_unverified", "error": "Fixed host state could not be reconciled; internal listener changes are forbidden and the exact host operation will retry"})
            return
        if journal["phase"] == "prepared":
            _queue_outcome(supervisor, job, journal_path, journal, private.get("original_applied"), "blocked", "preflight_blocked", message)
            return
        return _rollback(supervisor, job, journal_path, journal, message)


class _HostFailure(PortError):
    def __init__(self, phase, terminal=False):
        self.phase, self.terminal = phase, terminal
        super().__init__("Fixed public-port " + phase + " did not return an exact verified receipt")


def _host_request(supervisor, job, phase, binding, attempt=0):
    manager, plan = supervisor.manager, job["private"]["plan"]
    source = plan["source"]
    client = _manager_client(manager)
    identifier = digest({"application_port_job": job["id"], "phase": phase, **({"attempt": attempt} if attempt else {})})[:32]
    request = {"action": "public-port", "request_id": identifier, "operation_id": plan["id"], "phase": phase, "expected_revision": source["manager_revision"], "old_port": plan["current_port"], "new_port": plan["new_port"], "expected_fingerprint": source["public_fingerprint"], "server_name": source["public_server_name"], "controller_origin": plan["controller_origin"], "origin_mode": "preserve"}
    try:
        try:
            result = client.job(identifier)
        except KeyError:
            result = client.submit(request)
        deadline = time.monotonic() + 100
        while result.get("status") in ("queued", "running") and time.monotonic() < deadline and not supervisor.stopping.is_set():
            supervisor.stopping.wait(.25)
            result = client.job(identifier)
    except Exception:
        raise _HostFailure(phase) from None
    value = result.get("result", {})
    flag = {"prepare": "prepared", "activate": "activated", "verify": "verified", "commit": "committed", "abort": "rolled_back"}[phase]
    expected_phase = {"prepare": "prepared", "activate": "activated", "verify": "verified", "commit": "committed", "abort": "aborted"}[phase]
    accepted = result.get("status") in ("completed", "succeeded", "applied") and value.get("binding_digest") == binding and value.get("phase") == expected_phase and value.get(flag) is True
    if phase == "verify":
        accepted = accepted and value.get("tls_verified") is True and value.get("readiness_verified") is True and value.get("observed_port") == plan["new_port"]
    if phase in ("commit", "abort"):
        accepted = accepted and value.get("verified") is True and value.get("applied_port") == (plan["new_port"] if phase == "commit" else plan["current_port"])
    if not accepted:
        raise _HostFailure(phase, terminal=result.get("status") not in ("queued", "running"))
    return value


def _execute_appliance(supervisor, job, path, journal, native):
    manager, plan = supervisor.manager, job["private"]["plan"]
    source, private = plan["source"], job["private"]
    binding = digest({"kind": "prthak-public-port-v1", "operation_id": plan["id"], "appliance_id": source["appliance_id"], "base_revision": source["manager_revision"], "old_port": plan["current_port"], "new_port": plan["new_port"], "bind_address": source["bind_address"], "expected_fingerprint": source["public_fingerprint"], "server_name": source["public_server_name"], "controller_origin": plan["controller_origin"], "origin_mode": "preserve"})
    listener = native.get("public_listener", {})
    applied = {"port": plan["new_port"], "bind_address": plan["bind_address"], "revision": private["target_revision"]}

    def committed_readback():
        # The host may have committed before its manager job receipt survived.
        # A failed request ID is immutable there. A new read-back ID is allowed
        # ONLY after this exact operation is observed committed; the fixed
        # adapter freshly verifies it and cannot re-apply an aborted operation.
        if journal.get("phase") == "public_committed_receipt_pending" and journal.get("retry_after") and parse_time(journal["retry_after"]) > now():
            manager.runtime_job_update(job["id"], "queued", {"phase": "public_committed_receipt_pending"})
            return
        try:
            _host_request(supervisor, job, "commit", binding, journal.get("commit_readback_attempt", 0))
            return _queue_outcome(supervisor, job, path, journal, applied, "applied", "active")
        except Exception as error:
            if isinstance(error, _HostFailure) and error.terminal:
                journal["commit_readback_attempt"] = journal.get("commit_readback_attempt", 0) + 1
            journal.update(phase="public_committed_receipt_pending", retry_after=stamp(now() + timedelta(seconds=5)))
            _private_json(path, journal)
            manager.runtime_job_update(job["id"], "queued", {"phase": "public_committed_receipt_pending", "error": "The exact host operation is committed; a fresh bound TLS/readiness receipt is pending. No rollback or unrelated action will run."})

    if listener.get("operation_id") == plan["id"] and listener.get("phase") == "committed":
        return committed_readback()
    if journal.get("phase") == "rolling_back":
        if journal.get("retry_after") and parse_time(journal["retry_after"]) > now():
            manager.runtime_job_update(job["id"], "queued", {"phase": "waiting_for_public_rollback"})
            return
        try:
            _host_request(supervisor, job, "abort", binding, journal.get("abort_attempt", 0))
            return _queue_outcome(supervisor, job, path, journal, private.get("original_applied"), "rolled_back", "previous_port_restored", journal.get("error"))
        except Exception as error:
            if isinstance(error, _HostFailure) and error.terminal:
                # A failed fixed-manager request ID is terminal there. A new
                # attempt retries compensation only, against the SAME reviewed
                # operation/binding; it can never re-prepare the failed port.
                journal["abort_attempt"] = journal.get("abort_attempt", 0) + 1
            delay = min(60, 5 * 2 ** min(journal.get("abort_attempt", 0), 4))
            journal["retry_after"] = stamp(now() + timedelta(seconds=delay))
            _private_json(path, journal)
            manager.runtime_job_update(job["id"], "queued", {"phase": "public_rollback_unverified", "error": "Fixed host rollback is unverified; the same exact compensation will retry"})
            return
    try:
        if listener.get("operation_id") == plan["id"] and listener.get("phase") == "aborted":
            _host_request(supervisor, job, "abort", binding)
            return _queue_outcome(supervisor, job, path, journal, private.get("original_applied"), "rolled_back", "previous_port_restored", "The host recovered an interrupted candidate; a fresh review is required to retry")
        if journal.get("phase") == "prepared":
            _, state, actual, _, _, _ = _details(manager)
            if not _source_valid(actual, state, job):
                raise PortError("The fixed host publication/TLS/revision changed before execution")
        for phase in ("prepare", "activate", "verify", "commit"):
            if phase in journal.get("acks", {}):
                continue
            journal["requested_phase"] = phase
            _private_json(path, journal)
            manager.runtime_job_update(job["id"], "running", {"phase": "public_port_" + phase})
            receipt = _host_request(supervisor, job, phase, binding)
            journal.setdefault("acks", {})[phase] = receipt
            journal["phase"] = "public_transition"
            _private_json(path, journal)
        return _queue_outcome(supervisor, job, path, journal, applied, "applied", "active")
    except Exception as error:
        if not journal.get("requested_phase") and not journal.get("acks"):
            return _queue_outcome(supervisor, job, path, journal, private.get("original_applied"), "blocked", "preflight_blocked", str(error) if isinstance(error, PortError) else "Fixed host state changed before execution")
        # A lost COMMIT reply is resolved before any compensation. Committed
        # host authority is never silently undone by a network timeout.
        try:
            actual = _manager_client(manager).status().get("public_listener", {})
            if actual.get("operation_id") == plan["id"] and actual.get("phase") == "committed":
                return committed_readback()
            if journal.get("requested_phase") == "prepare" and isinstance(error, _HostFailure) and error.terminal and actual.get("operation_id") != plan["id"]:
                return _queue_outcome(supervisor, job, path, journal, private.get("original_applied"), "blocked", "preflight_blocked", str(error))
        except Exception:
            pass
        journal.update(phase="rolling_back", error=str(error) if isinstance(error, PortError) else "Fixed host port transition could not be verified")
        _private_json(path, journal)
        return _execute_appliance(supervisor, job, path, journal, native)
