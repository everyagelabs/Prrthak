"""Role-gated appliance configuration and a narrow local service-manager client.

Private requests are encrypted in the controller vault. The controller never
gets a Docker socket, constructs shell commands, or copies a running database.
"""
from __future__ import annotations

import copy
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import time
import uuid
from datetime import timedelta
from urllib.parse import urlsplit

from .firewall import WorkflowConflict
from .platform import _private_json, _read_json
from .store import digest, now, parse_time, stamp

CONFIG_ID = "appliance_cluster"
SERVICES = frozenset(("controller", "database", "etcd", "router", "all"))
ACTIONS = frozenset(("start", "stop", "restart"))


class ManagerUnavailable(RuntimeError):
    pass


class NodeClient:
    def __init__(self, socket_path=None, token_file=None):
        self.socket_path = socket_path or os.environ.get("PRTHAK_APPLIANCE_MANAGER_SOCKET", "/run/prthak-appliance/manager.sock")
        self.token_file = token_file or os.environ.get("PRTHAK_APPLIANCE_MANAGER_TOKEN_FILE", "/run/prthak-appliance/manager-token")

    def request(self, method, path, body=None):
        token_path = Path(self.token_file)
        if token_path.is_symlink() or not token_path.is_file() or token_path.stat().st_mode & 0o007:
            raise ManagerUnavailable("The private node-manager credential is unavailable")
        token = token_path.read_text().strip()
        if not 32 <= len(token) <= 256:
            raise ManagerUnavailable("The private node-manager credential is invalid")
        connection = http.client.HTTPConnection("localhost", timeout=15)
        try:
            connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            connection.sock.settimeout(15)
            connection.sock.connect(self.socket_path)
            headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
            connection.request(method, path, json.dumps(body).encode() if body is not None else None, headers)
            response = connection.getresponse()
            raw = response.read(8 * 1024 * 1024 + 1)
            if len(raw) > 8 * 1024 * 1024:
                raise ManagerUnavailable("Node-manager response exceeds its limit")
            value = json.loads(raw)
            if response.status == 404:
                raise KeyError("Unknown node-manager operation")
            if response.status >= 400:
                raise ManagerUnavailable(value.get("error", "The node manager refused the reviewed operation"))
            return value
        except ManagerUnavailable:
            raise
        except (OSError, ValueError, http.client.HTTPException):
            raise ManagerUnavailable("The local node manager is unavailable; no service change was assumed") from None
        finally:
            connection.close()

    def status(self):
        return self.request("GET", "/v1/status")

    def submit(self, request):
        return self.request("POST", "/v1/jobs", request)

    def job(self, identifier):
        if not isinstance(identifier, str) or not re.fullmatch(r"[a-f0-9]{32}", identifier):
            raise ValueError("Invalid node-manager operation identity")
        return self.request("GET", "/v1/jobs/" + identifier)


def origin(value, *, allow_empty=False):
    if allow_empty and not value:
        return ""
    if not isinstance(value, str) or len(value) > 512:
        raise ValueError("Use an HTTPS controller origin")
    try:
        parsed = urlsplit(value)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment or any(c.isspace() for c in value):
            raise ValueError()
        port = parsed.port
    except ValueError:
        raise ValueError("Use an HTTPS origin without credentials, path or query") from None
    host = "[" + parsed.hostname + "]" if ":" in parsed.hostname else parsed.hostname.lower()
    return "https://" + host + (":" + str(port) if port and port != 443 else "")


def hash_password(value):
    if not isinstance(value, str) or not 16 <= len(value) <= 256:
        raise ValueError("Cluster passwords must contain 16 to 256 characters")
    salt = secrets.token_bytes(24)
    return {"algorithm": "pbkdf2-sha256", "iterations": 600000, "salt": salt.hex(),
            "hash": hashlib.pbkdf2_hmac("sha256", value.encode(), salt, 600000).hex()}


def verify_password(value, record):
    import hmac
    if not isinstance(value, str) or len(value) > 256 or not isinstance(record, dict):
        return False
    try:
        if record.get("algorithm") != "pbkdf2-sha256" or record.get("iterations") != 600000:
            return False
        actual = hashlib.pbkdf2_hmac("sha256", value.encode(), bytes.fromhex(record["salt"]), 600000).hex()
        return hmac.compare_digest(actual, record["hash"])
    except (ValueError, KeyError, TypeError):
        return False


class Appliance:
    def __init__(self, manager, *, client=None):
        self.manager = manager
        self.app = manager.app if manager else None
        self.client = client or NodeClient()

    def _config(self, db=None):
        if not self.app:
            return {"revision": 0, "members": [], "voters": []}
        if db is not None:
            return self.app.store._get(db, "maintenance_settings", CONFIG_ID) or {"revision": 0, "members": [], "voters": []}
        with self.app.store.read_meta() as connection:
            return self._config(connection)

    def _local(self):
        if not self.manager:
            return {}
        return _read_json(self.manager.root / "appliance-local.json", {})

    def _identity(self):
        local = self._local()
        return {"id": os.environ.get("PRTHAK_APPLIANCE_NODE_ID") or (self.app.controller_id if self.app else ""),
                "site": local.get("site") or os.environ.get("PRTHAK_APPLIANCE_SITE") or (self.app.site if self.app else ""),
                "ip": local.get("node_ip") or os.environ.get("PRTHAK_APPLIANCE_NODE_IP", "")}

    def _installed(self):
        return os.environ.get("PRTHAK_APPLIANCE") == "1" and not bool(self.app and self.app.demo)

    def _database_runtime(self):
        """Read host-owned compatibility over the authenticated private socket.

        GUI settings, environment claims and imported manifests never supply
        this value. Management-only members may lack database compatibility.
        """
        if not self._installed():
            return {}
        state = self.client.status()
        if not isinstance(state, dict):
            raise ManagerUnavailable("The private manager did not report its database runtime")
        return {"database_runtime_profile": state.get("database_runtime_profile"),
                "database_storage_compatible": state.get("database_storage_compatible") is True}

    def status(self):
        config, local, identity = self._config(), self._local(), self._identity()
        from .replication_rotation import status as rotation_status
        rotation = rotation_status(self, config)
        node = {}
        error = ""
        if self._installed():
            try:
                node = self.client.status()
            except ManagerUnavailable as failure:
                error = str(failure)
        live = {member["id"]: member for member in self.app.cluster().get("nodes", [])} if self.app else {}
        public_members = []
        for member in config.get("members", []):
            public = {key: member[key] for key in ("id", "site", "ip", "role", "origin", "state", "last_seen") if key in member}
            public.update({key: live[member["id"]][key] for key in ("ready", "status", "last_seen") if key in live.get(member["id"], {})})
            public_members.append(public)
        if not public_members:
            public_members = list(live.values())
        services = [{key: service[key] for key in ("id", "name", "state", "enabled", "can_restart", "can_stop") if key in service}
                    for service in node.get("services", []) if isinstance(service, dict)]
        routing = {"mode": "site_affinity", "site": identity["site"],
                   "preferred_controller_url": local.get("preferred_controller_url", ""),
                   "fallback_controller_url": local.get("fallback_controller_url", ""),
                   "failover_state": node.get("routing", {}).get("failover_state", "not_configured"),
                   "pools": node.get("routing", {}).get("pools", [])}
        return {"revision": config["revision"], "installed": self._installed(), "manager_available": bool(node), "error": error,
                "demo": bool(self.app and self.app.demo), "identity": identity,
                "data_root": node.get("data_root") or os.environ.get("PRTHAK_APPLIANCE_DATA_ROOT") or (str(self.manager.data_dir) if self.manager else ""),
                "database_runtime_profile": node.get("database_runtime_profile"),
                "database_storage_compatible": node.get("database_storage_compatible") is True,
                "cluster": {"configured": bool(self.app and self.app.store.ha), "settings_saved": bool(config.get("deployment_id")), "status": node.get("cluster", {}).get("status", "not_connected"), "name": config.get("cluster_name", ""),
                            "origin": config.get("controller_origin", ""), "deployment_id": config.get("deployment_id"),
                            "nodes": public_members,
                            "voter_count": len(config.get("voters", [])), "management_controller_limit": None,
                            "cluster_password_configured": bool(config.get("password_hash")),
                            "replication_password_configured": bool(config.get("replication_configured")),
                            "replication_state": node.get("replication_state", "not_reported"),
                            "replication_password_pending": bool(rotation and rotation["pending"]) if self.app and self.app.store.ha else bool(local.get("pending_replication_ref")),
                            "replication_rotation": rotation},
                "services": services, "routing": routing, "health": node.get("health", {}), "blockers": node.get("blockers", []), "pending_changes": node.get("pending_changes", []), "watchdog_approved": local.get("watchdog_approved", False),
                "capabilities": {"service_control": bool(node), "storage_migration": bool(node), "password_join": not bool(self.app and self.app.demo)}}

    def save(self, body, actor):
        if not self.manager or not self.app:
            raise ManagerUnavailable("Install the controller with a private state directory first")
        allowed = {"expected_revision", "cluster_name", "site", "node_ip", "controller_origin", "cluster_password", "replication_password", "preferred_controller_url", "fallback_controller_url", "watchdog_approved"}
        if not isinstance(body, dict) or set(body) - allowed:
            raise ValueError("Provide only supported appliance settings")
        runtime = self._database_runtime()
        with self.manager.lock, self.app.store.lock, self.app.store.meta() as db:
            old = self._config(db)
            if isinstance(body.get("expected_revision"), bool) or body.get("expected_revision") != old["revision"]:
                raise WorkflowConflict("Cluster settings changed; refresh before saving", {})
            local = self._local()
            cluster_name = body.get("cluster_name", old.get("cluster_name", ""))
            site = body.get("site", local.get("site", self._identity()["site"]))
            if not isinstance(cluster_name, str) or not 1 <= len(cluster_name.strip()) <= 100 or not isinstance(site, str) or not 1 <= len(site.strip()) <= 100:
                raise ValueError("Provide a cluster name and this node's site")
            node_ip = body.get("node_ip", local.get("node_ip", self._identity()["ip"]))
            try:
                address = ipaddress.ip_address(node_ip)
                if address.is_loopback or address.is_unspecified or address.is_multicast or address.is_link_local:
                    raise ValueError()
            except (ValueError, TypeError):
                raise ValueError("Provide this controller's unicast management IP") from None
            controller_origin = origin(body.get("controller_origin", old.get("controller_origin", "")))
            if self.app.store.ha and controller_origin != old.get("controller_origin"):
                raise ValueError("Changing the active cluster origin requires a reviewed ingress and identity migration; update local routing separately")
            preferred = origin(body.get("preferred_controller_url", local.get("preferred_controller_url", "")), allow_empty=True)
            fallback = origin(body.get("fallback_controller_url", local.get("fallback_controller_url", "")), allow_empty=True)
            updated = copy.deepcopy(old)
            password = body.get("cluster_password", "")
            cached_joiner = bool(old.get("bootstrap_seed_id") and old["bootstrap_seed_id"] != self._identity()["id"] and not self.app.store.ha)
            if cached_joiner and (cluster_name.strip() != old.get("cluster_name") or controller_origin != old.get("controller_origin") or password or body.get("replication_password")):
                raise ValueError("Until shared database activation, change shared cluster settings on the original bootstrap controller")
            if password:
                updated["password_hash"] = hash_password(password)
            elif not old.get("password_hash"):
                raise ValueError("Set the initial cluster password; blank preserves an existing password")
            replication = body.get("replication_password", "")
            if not isinstance(replication, str) or replication and (not 32 <= len(replication) <= 128 or any(ord(c) < 32 or ord(c) > 126 for c in replication)):
                raise ValueError("Replication passwords must contain 32 to 128 printable ASCII characters")
            if replication:
                if not self.app.store.ha:
                    local["pending_replication_ref"] = self.manager.vault.put(replication)
                updated["replication_configured"] = True
            local.update(site=site.strip(), node_ip=str(address), preferred_controller_url=preferred, fallback_controller_url=fallback)
            if "watchdog_approved" in body:
                if not isinstance(body["watchdog_approved"], bool):
                    raise ValueError("Host fencing approval must be true or false")
                local["watchdog_approved"] = body["watchdog_approved"]
            identity = {"id": self._identity()["id"], "site": site.strip(), "ip": str(address), "origin": controller_origin, "state": "registered"}
            members = [member for member in old.get("members", []) if member["id"] != identity["id"]]
            existing = next((member for member in old.get("members", []) if member["id"] == identity["id"]), {})
            if any(member["ip"] == identity["ip"] for member in members):
                raise ValueError("This management IP already belongs to another controller")
            if existing.get("role") == "database_voter" and any(member.get("role") == "database_voter" and member["site"].casefold() == identity["site"].casefold() for member in members):
                raise ValueError("Database voters must remain in distinct sites")
            if existing and (self.app.store.ha or existing.get("transport_public_key") or len(old.get("voters", [])) == 3) and (existing["ip"] != identity["ip"] or existing["site"] != identity["site"]):
                raise ValueError("Replacing a registered controller IP or site requires a reviewed membership replacement; its shared identity was not changed")
            identity = {**existing, **identity, "state": existing.get("state", "registered")}
            identity["role"] = existing.get("role", "database_voter" if len(old.get("voters", [])) < 3 and not any(member["site"].casefold() == identity["site"].casefold() and member.get("role") == "database_voter" for member in members) else "management")
            if identity["role"] == "database_voter" and self._installed():
                from .cluster_bootstrap import require_database_runtime
                require_database_runtime(runtime)
            identity.update(runtime)
            members.append(identity)
            updated.update(id=CONFIG_ID, revision=old["revision"] + (0 if cached_joiner else 1), cluster_name=cluster_name.strip(), controller_origin=controller_origin,
                           deployment_id=old.get("deployment_id") or str(uuid.uuid4()), members=members,
                           voters=[{key: member[key] for key in ("id", "site", "ip")} for member in members if member["role"] == "database_voter"],
                           bootstrap_seed_id=old.get("bootstrap_seed_id") or identity["id"], updated_at=stamp(), updated_by=actor)
            if replication and self.app.store.ha:
                from .replication_rotation import queue as queue_rotation
                queue_rotation(self, db, updated, replication, actor)
            _private_json(self.manager.root / "appliance-local.json", local)
            if not cached_joiner:
                self.app.store._put(db, "maintenance_settings", updated)
            self.app.store.audit("appliance.configuration_saved", actor, {"revision": updated["revision"], "node_id": identity["id"], "secret_fields_changed": [name for name in ("cluster_password", "replication_password") if body.get(name)]}, db)
        return {**self.status(), "message": "Settings saved privately. Database and service changes become active only after their verified operations."}

    def _require_operations(self):
        if not self.manager or not self._installed():
            raise ValueError("Service and storage operations require the installed production appliance; demo operations are blocked")

    def _review(self, kind, request, summary, blockers=()):
        plan = {"id": secrets.token_hex(16), "operation": kind, "digest": "", "confirmation_nonce": secrets.token_urlsafe(24),
                "confirmation_phrase": ("MOVE STORAGE TO " + request["data_root"]) if kind == "storage" else (request["action"].upper() + " " + request["service"]),
                "expires_at": stamp(now() + timedelta(minutes=10)), "summary": summary, "blockers": list(blockers), "can_apply": not blockers,
                "configuration_digest": self._configuration_digest(), "request_ref": self.manager.vault.put(json.dumps(request))}
        plan["digest"] = digest({key: value for key, value in plan.items() if key != "request_ref"})
        _private_json(self.manager.root / "appliance-plans" / (plan["id"] + ".json"), plan)
        return {key: value for key, value in plan.items() if key != "request_ref"}

    def service_review(self, body, actor):
        self._require_operations()
        service, action = body.get("service"), body.get("action")
        if service not in SERVICES or action not in ACTIONS:
            raise ValueError("Select an owned appliance service and start, stop or restart")
        state = self.client.status()
        return self._review("service", {"service": service, "action": action, "expected_revision": state.get("revision")},
                            {"node": self._identity(), "service": service, "action": action, "message": "The node manager rechecks dependencies and quorum before operating this owned service"})

    def storage_review(self, body, actor):
        self._require_operations()
        path = body.get("data_root")
        if not isinstance(path, str) or not path.startswith("/") or ".." in Path(path).parts or len(path) > 1024:
            raise ValueError("Use an absolute dedicated persistent storage path")
        request = {"action": "storage-review", "data_root": path, "request_id": secrets.token_hex(16)}
        result = self.client.submit(request)
        deadline = time.monotonic() + 10
        while result.get("status") in ("queued", "running") and time.monotonic() < deadline:
            time.sleep(0.1)
            result = self.client.job(result["id"])
        if result.get("status") not in ("succeeded", "completed", "applied", "ready"):
            raise ManagerUnavailable("The node manager could not complete the storage preflight; no files were moved")
        review = result.get("result", {})
        if not isinstance(review, dict) or not isinstance(review.get("review_id"), str) or not re.fullmatch(r"[a-f0-9]{32}", review["review_id"]) or not isinstance(review.get("confirmation_nonce"), str) or len(review["confirmation_nonce"]) < 20:
            raise ManagerUnavailable("The node manager did not provide a valid storage review; no move can be approved")
        operation = {"action": "storage-move", "data_root": path, "review_id": review.get("review_id", review.get("id")), "confirmation_nonce": review.get("confirmation_nonce")}
        return self._review("storage", operation, review, review.get("blockers", []))

    def _apply(self, body, actor, kind):
        self._require_operations()
        identifier = body.get("preview_id", "")
        if not isinstance(identifier, str) or not re.fullmatch(r"[a-f0-9]{32}", identifier):
            raise ValueError("A current appliance review is required")
        with self.manager.lock:
            path = self.manager.root / "appliance-plans" / (identifier + ".json")
            plan = _read_json(path)
            if not plan or plan["operation"] != kind or not plan["can_apply"] or parse_time(plan["expires_at"]) <= now() or plan["configuration_digest"] != self._configuration_digest() or any(body.get(key) != plan[key] for key in ("digest", "confirmation_nonce", "confirmation_phrase")):
                raise WorkflowConflict("Appliance review expired, changed or was not confirmed exactly", {})
            if plan.get("job_id"):
                return self.manager.job(plan["job_id"])
            request = json.loads(self.manager.vault.get(plan["request_ref"]))
            if kind == "service":
                local = self._local()
                local["auto_start_paused"] = request["action"] == "stop"
                _private_json(self.manager.root / "appliance-local.json", local)
            result = self.manager._queue("appliance", {"request_ref": plan["request_ref"]}, actor)
            plan["job_id"] = result["id"]
            _private_json(path, plan)
            return result

    def service_apply(self, body, actor):
        return self._apply(body, actor, "service")

    def _configuration_digest(self):
        config = self._config()
        return digest({"revision": config["revision"], "deployment_id": config.get("deployment_id"), "identity": self._identity()})

    def storage_apply(self, body, actor):
        return self._apply(body, actor, "storage")

    def abort_rotation(self, body, actor):
        from .replication_rotation import request_abort
        self._require_operations()
        return request_abort(self, actor)

    def join_preview(self, body, actor):
        from .cluster_bootstrap import preview
        return preview(self, body, actor)

    def join_apply(self, body, actor):
        from .cluster_bootstrap import apply
        return apply(self, body, actor)


def execute_job(manager, job):
    client = NodeClient()
    request = json.loads(manager.vault.get(job["private"]["request_ref"]))
    request["request_id"] = job["id"]
    result = client.submit(request)
    manager.runtime_job_update(job["id"], "running", {"phase": "node_manager", "result": {"node_job_id": result["id"]}})
    deadline = time.monotonic() + 1800
    while result.get("status") in ("queued", "running") and time.monotonic() < deadline:
        time.sleep(0.5)
        result = client.job(result["id"])
    if result.get("status") in ("succeeded", "completed", "applied"):
        actual = result.get("result", {})
        if request.get("action") == "controller-config":
            from .gui_setup import binding
            applied = actual.get("phase") == "controller_config_applied" and actual.get("applied") is True and actual.get("rolled_back") is not True
            rolled_back = actual.get("phase") == "controller_config_rolled_back" and actual.get("applied") is False and actual.get("rolled_back") is True
            if actual.get("verified") is not True or actual.get("binding_digest") != binding(request) or not (applied or rolled_back):
                manager.runtime_job_update(job["id"], "failed", {"phase": "node_manager", "error": "Controller configuration did not return a verified outcome"})
                return
            manager.runtime_job_update(job["id"], "applied" if actual.get("applied") is True else "rolled_back", {"phase": actual["phase"], "result": actual})
            return
        staged = actual.get("status") in ("configured", "waiting_for_voters") or actual.get("requires_service_start") is True
        manager.runtime_job_update(job["id"], "staged" if staged else "applied", {"phase": actual.get("status", "verified") if staged else "verified", "result": actual})
    else:
        manager.runtime_job_update(job["id"], "blocked" if result.get("status") == "blocked" else "failed", {"phase": "node_manager", "error": result.get("error", "The node operation did not reach verified completion")})
