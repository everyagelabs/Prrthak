from __future__ import annotations

import hmac
import json
import logging
import mimetypes
import os
import ssl
import socket
import uuid
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from .store import LearningExpired, Store, stamp
from .firewall import WorkflowConflict
from .management_health import ManagementHealth
from .auth import AuthConflict, EntraAuth
from .http_limits import RateLimited

LOG = logging.getLogger("Prṛthak.controller")


class App:
    def __init__(self, store, demo=False, signer=None, dashboard=None, tokens=None, controller_id=None, site=None, management_health=None, auth=None, platform_manager=None, state_dir=None, controller_certificate=None, controller_private_key=None, application_listen=None):
        if demo and getattr(store, "ha", False):
            raise ValueError("HA mode cannot use synthetic demo state")
        self.store = store
        self.management_health = management_health or ManagementHealth()
        self.controller_id = controller_id or os.environ.get("SEG_CONTROLLER_ID") or f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:8]}"
        self.site = site or os.environ.get("SEG_CONTROLLER_SITE") or os.environ.get("SEG_SITE") or "local"
        if not isinstance(self.controller_id, str) or not self.controller_id or len(self.controller_id) > 100 or not isinstance(self.site, str) or not self.site or len(self.site) > 100:
            raise ValueError("Controller ID and site must be nonempty strings of at most 100 characters")
        self.demo = demo
        self.application_listen = application_listen
        self.store.approval_demo = demo
        self.store.approval_production = os.environ.get("PRTHAK_APPLIANCE") == "1" and not demo
        if demo:
            self.store.lab_approvals = True
        self.signer = signer
        self.controller_certificate = Path(controller_certificate) if controller_certificate else None
        self.controller_private_key = Path(controller_private_key) if controller_private_key else None
        self.dashboard = Path(dashboard or Path(__file__).resolve().parent.parent / "dashboard").resolve()
        self.tokens = tokens if tokens is not None else {role: os.environ.get(f"SEG_{role.upper()}_TOKEN", "") for role in ("super_admin", "admin", "read_only")}
        self.auth = auth if auth is not None else EntraAuth(store)
        self.store.approval_auth_fingerprint = self.auth.config.fingerprint if self.auth.enabled else None
        self.store.approval_tenant_id = self.auth.config.tenant_id if self.auth.enabled else None
        self.stop = threading.Event()
        from .http_limits import RequestLimits
        self.limits = RequestLimits()
        self.threads = []
        self.platform = platform_manager
        if self.platform is None and (state_dir is not None or getattr(store, "path", None) is not None):
            from .platform import PlatformManager
            self.platform = PlatformManager(state_dir or store.path)
        if self.platform:
            self.platform.attach(self)
            self.controller_id = self.platform.local_controller_id(self.controller_id, explicit=bool(controller_id or os.environ.get("SEG_CONTROLLER_ID")))

    def recovering(self):
        return bool(self.platform and (self.platform.root / "recovery-writer-fence.json").exists())

    def readiness(self, recovery_nonce=None):
        try:
            checks = self.store.readiness()
        except Exception:
            checks = {"metadata": False, "traffic": False}
        try:
            from .provider_lifecycle import permitted
            checks["provider_authority"] = permitted(self)
        except Exception:
            checks["provider_authority"] = False
        if self.recovering():
            expected = os.environ.get("PRTHAK_RECOVERY_ADMISSION", "")
            if not expected or not isinstance(recovery_nonce, str) or not hmac.compare_digest(expected, recovery_nonce):
                checks["recovery_admission"] = False
        return {"status": "ready" if all(checks.values()) else "not_ready", "checks": checks, "ha": bool(self.store.ha), "controller_id": self.controller_id, "site": self.site,
                "deployment_id": getattr(self.store, "expected_deployment_id", None), "deployment_epoch": getattr(self.store, "expected_deployment_epoch", None), "active_revision": int(os.environ.get("SEG_ACTIVE_REVISION", "0"))}

    def cluster(self):
        readiness = self.readiness()
        if self.store.ha:
            nodes = self.store.cluster_nodes()
        else:
            ready = readiness["status"] == "ready"
            nodes = [{"id": self.controller_id, "site": self.site, "last_seen": stamp(), "status": "healthy" if ready else "unavailable", "role": "active" if ready else "unavailable", "ready": ready}]
        active = self.platform.active_profile() if self.platform else None
        mode = {"active_active": "active-active", "dc_dr": "dc-dr"}.get((active or {}).get("mode"), "active-active" if self.store.ha else "standalone")
        return {"ha": bool(self.store.ha), "mode": mode, "controller_id": self.controller_id, "site": self.site, "nodes": nodes, "storage": {"metadata": self.store.storage_kind, "traffic": self.store.storage_kind}, "ingress": {"managed": False, "state": "external_configuration_required" if self.store.ha else "standalone", "controller_origin": (active or {}).get("controller_origin")}}

    def heartbeat(self):
        if not self.store.ha:
            return
        readiness = self.readiness()
        ready = readiness["status"] == "ready"
        self.store.register_node({"id": self.controller_id, "site": self.site, "last_seen": stamp(), "ready": ready, "role": "active" if ready else "unavailable"})

    def start_jobs(self):
        if self.recovering():
            def after_recovery():
                while not self.stop.is_set():
                    if not self.recovering():
                        self.start_jobs()
                        return
                    self.stop.wait(.25)
            thread = threading.Thread(target=after_recovery, daemon=True)
            self.threads.append(thread)
            thread.start()
            return
        def health_job():
            if self.demo:
                from .seed import tick_synthetic_hosts
                tick_synthetic_hosts(self.store)
            self.store.evaluate_health()
            self.store.prune()

        def evaluate():
            while not self.stop.is_set():
                try:
                    self.store.run_job("health", health_job)
                except Exception:
                    LOG.warning("Health evaluation unavailable; no local storage fallback")
                self.stop.wait(30)

        def traffic():
            while not self.stop.is_set():
                try:
                    processed = self.store.run_job("traffic", self.store.process_flows)
                except Exception:
                    LOG.warning("Traffic processing unavailable; durable batches remain for retry")
                    processed = 0
                self.stop.wait(0.05 if processed else 0.5)

        def registry():
            while not self.stop.is_set():
                try:
                    self.heartbeat()
                except Exception:
                    LOG.warning("Cluster heartbeat unavailable; node readiness remains dependency based")
                self.stop.wait(10)

        def scheduled_backups():
            from .backup_schedule import run_due
            while not self.stop.is_set():
                try:
                    run_due(self.store)
                except Exception:
                    LOG.warning("Scheduled backup evaluation unavailable; retained backups were not removed")
                self.stop.wait(30)

        def appliance_reconcile():
            from .appliance import Appliance
            from .cluster_bootstrap import reconcile
            while not self.stop.is_set():
                try:
                    reconcile(Appliance(self.platform))
                except Exception:
                    LOG.warning("Appliance setup remains pending; no database activation or service success was assumed")
                try:
                    from .gui_setup import reconcile as reconcile_provider
                    reconcile_provider(self.platform)
                except Exception:
                    LOG.warning("Reviewed provider convergence remains pending; retained rollback context is unchanged")
                self.stop.wait(10)

        def notifications():
            from .notifications import enqueue_alerts, run_once
            while not self.stop.is_set():
                try:
                    if self.platform:
                        enqueue_alerts(self.platform)
                        run_once(self.platform)
                except Exception:
                    LOG.warning("Notification delivery is unavailable; durable outbox remains pending")
                self.stop.wait(1)

        targets = [evaluate, traffic, scheduled_backups, appliance_reconcile, notifications]
        if self.store.ha:
            targets.append(registry)
        for target in targets:
            thread = threading.Thread(target=target, daemon=True)
            thread.start()
            self.threads.append(thread)

    def role(self, headers):
        principal = self.principal(headers)
        return principal["role"] if principal else None

    def principal(self, headers):
        if self.demo:
            return {"role": "super_admin", "actor": "demo:super_admin", "auth_type": "demo", "user": {"id": "demo:super_admin", "display_name": "Demo Super Admin", "role": "super_admin"}}
        from .provider_lifecycle import assert_current
        assert_current(self)
        if self.auth.enabled:
            return self.auth.authenticate(headers)
        authorization = headers.get("Authorization", "")
        if not authorization.startswith("Bearer "):
            return None
        token = authorization[7:]
        for role, expected in self.tokens.items():
            if expected and hmac.compare_digest(token, expected):
                canonical = {"viewer": "read_only", "operator": "read_only"}.get(role, role)
                if canonical not in ("read_only", "admin", "super_admin"):
                    return None
                return {"role": canonical, "actor": "legacy-token:" + canonical, "auth_type": "token", "user": {"id": "legacy-token:" + canonical, "display_name": "Local " + canonical.replace("_", " "), "role": canonical}}
        return None

    def endpoint_identity(self, connection, headers):
        if self.demo:
            identity = headers.get("X-Agent-ID", "")
            if not identity:
                raise PermissionError("X-Agent-ID required in demo mode")
            return identity
        if not isinstance(connection, ssl.SSLSocket):
            raise PermissionError("Verified client certificate required")
        certificate = connection.getpeercert()
        if not certificate:
            raise PermissionError("Verified client certificate required")
        names = [value for section in certificate.get("subject", ()) for key, value in section if key == "commonName"]
        if len(names) != 1:
            raise PermissionError("Certificate endpoint identity missing")
        identity = names[0]
        from .endpoint_certificates import authorize
        authorize(self.store, identity, connection.getpeercert(binary_form=True))
        return identity


def handler_for(app):
    class Handler(BaseHTTPRequestHandler):
        server_version = "Prthak/0.6"
        protocol_version = "HTTP/1.1"

        def setup(self):
            super().setup()
            self.connection.settimeout(15)
            if isinstance(self.connection, ssl.SSLSocket):
                self.connection.do_handshake()

        def log_message(self, format, *args):
            # Query/body/token data are deliberately excluded from request logs.
            LOG.info("%s %s", self.command, urlsplit(self.path).path)

        def response(self, status, value=None, headers=None):
            if status >= 400:
                self.close_connection = True
            encoded = json.dumps(value, separators=(",", ":")).encode() if value is not None else b""
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Cache-Control", "no-store")
            if getattr(self, "close_connection", False):
                self.send_header("Connection", "close")
            self.security_headers()
            for key, val in (headers.items() if isinstance(headers, dict) else headers or []):
                self.send_header(key, val)
            self.end_headers()
            if encoded:
                self.wfile.write(encoded)

        def security_headers(self):
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "same-origin")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
            if isinstance(self.connection, ssl.SSLSocket):
                self.send_header("Strict-Transport-Security", "max-age=31536000")

        def body(self):
            if self.headers.get("Transfer-Encoding"):
                raise ValueError("Chunked request bodies are not supported")
            try:
                size = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                raise ValueError("Invalid Content-Length")
            limit = 4 * 1024 * 1024 if urlsplit(self.path).path == "/api/v1/platform/certificates/preview" else 2 * 1024 * 1024
            if not 0 < size <= limit:
                raise ValueError("JSON body required and request size must be within this operation's limit")
            if self.headers.get("Content-Type", "").split(";", 1)[0].strip() != "application/json":
                raise ValueError("Content-Type must be application/json")
            result = json.loads(self.rfile.read(size))
            if not isinstance(result, dict):
                raise ValueError("JSON body must be an object")
            return result

        def serve_static(self, path):
            requested = "index.html" if path in ("/", "/index.html", "/overview", "/servers", "/policies", "/traffic", "/risk", "/alerts", "/activity", "/firewall", "/locations", "/access", "/services", "/settings") else unquote(path).lstrip("/")
            target = (app.dashboard / requested).resolve()
            if not target.is_relative_to(app.dashboard) or not target.is_file() or target.suffix not in (".html", ".js", ".css", ".svg", ".ico", ".png", ".woff2", ".webmanifest"):
                self.response(404, {"error": "Not found"})
                return
            contents = target.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", mimetypes.guess_type(target)[0] or "application/octet-stream")
            self.send_header("Content-Length", str(len(contents)))
            self.send_header("Cache-Control", "no-cache")
            self.security_headers()
            self.end_headers()
            self.wfile.write(contents)

        def execute(self):
            parsed = urlsplit(self.path)
            path = parsed.path.rstrip("/") or "/"
            method = self.command
            query = parse_qs(parsed.query, keep_blank_values=True)
            app.limits.check("global", "controller")
            from .channels import admitted, request_channel
            if not admitted(request_channel(app, self.connection), method, path):
                self.response(404, {"error": "This operation is unavailable on this listener"})
                return
            if path in ("/api/v1/auth/login", "/api/v1/auth/callback", "/api/v1/platform/setup/verification"):
                app.limits.check("login", self.client_address[0])
            elif path in ("/api/v1/agent/enroll", "/api/v1/agent/certificates/recover", "/api/v1/platform/cluster/enroll"):
                app.limits.check("enrollment", self.client_address[0])
            if method == "GET" and path == "/healthz":
                self.response(200, {"status": "ok"})
                return
            if method == "GET" and path == "/readyz":
                result = app.readiness(self.headers.get("X-Prthak-Recovery-Admission"))
                self.response(200 if result["status"] == "ready" else 503, result)
                return
            if app.recovering() and path.startswith("/api/"):
                self.response(503, {"error": "Reviewed recovery is in progress; business access resumes after verification"}, {"Retry-After": "3"})
                return
            if not path.startswith("/api/"):
                if method == "GET":
                    self.serve_static(path)
                else:
                    self.response(405, {"error": "Method not allowed"})
                return
            if path == "/api/v1/auth/config" and method == "GET":
                status = app.auth.status()
                from .channels import public_status
                self.response(200, {**status, "agent_channels": public_status(app), "mode": "demo" if app.demo else "entra" if app.auth.enabled or not any(app.tokens.values()) else "tokens", "roles": ["read_only", "admin", "super_admin"]})
                return
            if path == "/api/v1/auth/login" and method == "GET":
                if app.demo:
                    raise ValueError("Synthetic demo does not authenticate directory users")
                if not isinstance(self.connection, ssl.SSLSocket):
                    raise PermissionError("HTTPS is required for Microsoft Entra sign-in")
                result = app.auth.begin_login(self.headers)
                self.response(302, headers=[("Location", result["location"]), *[("Set-Cookie", cookie) for cookie in result.get("cookies", [])]])
                return
            if path == "/api/v1/auth/callback" and method == "GET":
                if app.demo:
                    raise ValueError("Synthetic demo does not authenticate directory users")
                if not isinstance(self.connection, ssl.SSLSocket):
                    raise PermissionError("HTTPS is required for Microsoft Entra sign-in")
                from . import gui_setup
                candidate = gui_setup.callback_plan(app.platform, query) if app.platform else None
                result = gui_setup.finish_login(app.platform, candidate, query, self.headers) if candidate else app.auth.callback(query, self.headers)
                self.response(303, headers=[("Location", result["location"]), *[("Set-Cookie", cookie) for cookie in result.get("cookies", [])]])
                return
            if path == "/api/v1/platform/setup/verification" and method == "POST":
                if app.demo or not isinstance(self.connection, ssl.SSLSocket):
                    raise PermissionError("Candidate verification requires installed HTTPS")
                from . import gui_setup
                result = gui_setup.bridge_login(app.platform, self.body(), self.headers)
                self.response(200, {"location": result["location"]}, [("Set-Cookie", cookie) for cookie in result.get("cookies", [])])
                return
            if path == "/api/v1/agent/enroll" and method == "POST":
                if not app.signer:
                    self.response(503, {"error": "Enrollment is unavailable; configure the controller CA"})
                    return
                value = self.body()
                enrolled = app.store.enroll(value.get("token"), value.get("hostname"), value.get("csr"), app.signer)
                if app.platform:
                    enrolled["policy_signing_trust"] = app.platform.policy_signer().public_trust()
                self.response(201, enrolled)
                return
            if path == "/api/v1/agent/certificates/recover" and method == "POST":
                if app.demo or not isinstance(self.connection, ssl.SSLSocket):
                    raise PermissionError("Verified HTTPS is required for certificate recovery")
                from .endpoint_certificates import recover
                self.response(200, recover(app.store, self.body(), app.signer))
                return
            if path == "/api/v1/platform/cluster/enroll" and method == "POST":
                if app.demo or not isinstance(self.connection, ssl.SSLSocket) or not app.platform:
                    raise PermissionError("Controller joining requires trusted HTTPS and a one-time cluster join code")
                value = self.body()
                if value.get("action") in ("password-bootstrap", "node-sync"):
                    from .cluster_bootstrap import enroll
                    from .appliance import Appliance
                    self.response(200, enroll(Appliance(app.platform), value, self.client_address[0]))
                else:
                    self.response(200, app.platform.enroll_node(value))
                return
            if path.startswith("/api/v1/agent/"):
                identity = app.endpoint_identity(self.connection, self.headers)
                app.limits.check("agent", identity)
                from .channels import CONTROL
                if path in CONTROL:
                    from .provider_lifecycle import assert_current
                    assert_current(app)
                if path == "/api/v1/agent/certificates/renew" and method == "POST":
                    from .endpoint_certificates import renew
                    self.response(200, renew(app.store, identity, self.connection.getpeercert(binary_form=True), self.body(), app.signer))
                elif path == "/api/v1/agent/report" and method == "POST":
                    self.response(200, app.store.report(identity, self.body()))
                elif path == "/api/v1/agent/configuration/check" and method == "POST":
                    from .endpoint_configuration import check
                    self.response(200, check(app, identity, self.body()))
                elif path == "/api/v1/agent/policy" and method == "GET":
                    value, etag = app.store.assignment(identity)
                    if app.platform:
                        value = app.platform.policy_signer().sign(value)
                        from .store import digest
                        etag = digest([etag, value["signature"]])
                        if len(json.dumps(value, separators=(",", ":")).encode()) > 8 * 1024 * 1024:
                            raise RuntimeError("Signed policy exceeds the supported delivery size; reduce the per-server source matrix")
                    headers = {"ETag": f'"{etag}"'}
                    if self.headers.get("If-None-Match", "").strip('"') == etag:
                        self.response(304, headers=headers)
                    else:
                        self.response(200, value, headers)
                elif path == "/api/v1/agent/flows" and method == "POST":
                    self.response(202, app.store.enqueue_flows(identity, self.body()))
                elif path == "/api/v1/agent/hits" and method == "POST":
                    from .hit_monitoring import enqueue, MonitoringExpired
                    try:
                        self.response(202, enqueue(app.store, identity, self.body()))
                    except MonitoringExpired as error:
                        self.response(410, {"error": str(error)})
                elif path == "/api/v1/agent/firewall/check" and method == "POST":
                    from .firewall_authorization import check
                    self.response(200, check(app.store, identity, self.body()))
                elif path == "/api/v1/agent/learning-allow/check" and method == "POST":
                    if app.demo:
                        raise PermissionError("Real learning-allow management health evidence is unavailable in demo mode")
                    self.response(200, app.management_health.check_learning(app.store, identity, self.body()))
                elif path == "/api/v1/agent/enforcement/check" and method == "POST":
                    if app.demo:
                        raise PermissionError("Real management health evidence is unavailable in demo mode")
                    self.response(200, app.management_health.check(app.store, identity, self.body()))
                else:
                    self.response(404, {"error": "Unknown agent endpoint"})
                return
            principal = app.principal(self.headers)
            if not principal:
                app.limits.check("anonymous", self.client_address[0])
                self.response(401, {"error": "Sign-in required"})
                return
            role = principal["role"]
            app.limits.check("admin", principal["actor"])
            if principal.get("auth_type") == "session" and not isinstance(self.connection, ssl.SSLSocket):
                raise PermissionError("HTTPS is required for authenticated user sessions")
            if method in ("POST", "PUT", "PATCH", "DELETE"):
                if principal.get("auth_type") == "session":
                    app.auth.require_csrf(self.headers, principal)
                if path not in ("/api/v1/auth/logout", "/api/v1/firewall/query", "/api/v1/policies/query", "/api/v1/learning-policies/query", "/api/v1/policy-rollouts/query", "/api/v1/host-default-deny/query") and role not in ("admin", "super_admin"):
                    raise PermissionError("Admin or Super Admin role required")
                origin = self.headers.get("Origin")
                scheme = "https" if isinstance(self.connection, ssl.SSLSocket) else "http"
                if origin and origin != f"{scheme}://{self.headers.get('Host')}":
                    raise PermissionError("Cross-origin mutation rejected")
            actor = principal["actor"]
            prefix = "/api/v1/"
            tail = path[len(prefix):] if path.startswith(prefix) else ""
            parts = tail.split("/")
            if path == "/api/v1/auth" and method == "GET":
                self.response(200, {"role": role, "demo": app.demo, "user": principal.get("user"), "auth_type": principal["auth_type"], "csrf_token": principal.get("csrf_token")})
            elif parts == ["auth", "logout"] and method == "POST":
                self.body()
                result = app.auth.logout(self.headers)
                self.response(200, {"signed_out": True}, [("Set-Cookie", cookie) for cookie in result.get("cookies", [])])
            elif parts[:1] == ["risk"]:
                from . import risky_ports
                if parts == ["risk", "catalog"] and method == "GET":
                    self.response(200, risky_ports.public_catalog(app.store))
                elif parts == ["risk", "catalog"] and method == "PUT":
                    self.response(200, risky_ports.save(app.store, self.body(), actor))
                elif parts == ["risk", "findings"] and method == "GET":
                    self.response(200, risky_ports.findings(app.store, {key:values[-1] for key,values in query.items()}))
                elif parts == ["risk", "regulatory"] and method == "GET":
                    self.response(200, risky_ports.regulatory(app.store))
                else:
                    self.response(404, {"error":"Unknown risk endpoint"})
            elif parts[:2] == ["access", "users"]:
                if role != "super_admin":
                    raise PermissionError("Only Super Admin can create or manage users")
                if len(parts) == 2 and method == "GET":
                    self.response(200, app.auth.list_users(principal))
                elif len(parts) == 2 and method == "POST":
                    self.response(201, app.auth.create_user(self.body(), principal))
                elif len(parts) == 3 and method == "PATCH":
                    self.response(200, app.auth.update_user(unquote(parts[2]), self.body(), principal))
                elif len(parts) == 4 and parts[3] == "revoke-sessions" and method == "POST":
                    self.body()
                    self.response(200, app.auth.revoke_sessions(unquote(parts[2]), principal))
                else:
                    self.response(405, {"error": "Method not allowed"})
            elif path == "/api/v1/cluster" and method == "GET":
                self.response(200, app.cluster())
            elif path == "/api/v1/overview" and method == "GET":
                self.response(200, app.store.overview(app.demo))
            elif parts and parts[0] == "platform":
                if parts[:2] == ["platform", "approval-settings"]:
                    if parts == ["platform", "approval-settings"] and method == "GET":
                        self.response(200, {"mode":"single_admin", "effective_mode":"single_admin", "label":"Role-authorized direct changes", "selectable":False})
                    else:self.response(410, {"error":"Approval modes have been retired; authorized Admin changes apply directly"})
                    return
                if parts[:2] == ["platform", "setup"]:
                    if role != "super_admin":
                        raise PermissionError("Only Super Admin can configure controller setup")
                    from . import gui_setup
                    if parts == ["platform", "setup"] and method == "GET":
                        self.response(200, gui_setup.status(app.platform, principal))
                    elif len(parts) == 3 and method == "POST" and parts[2] in ("preview", "apply", "login"):
                        if app.demo or not isinstance(self.connection, ssl.SSLSocket):
                            raise PermissionError("GUI controller configuration requires installed HTTPS")
                        if parts[2] == "login":
                            result = gui_setup.begin_login(app.platform, self.body(), principal, self.headers)
                            self.response(200, {key: value for key, value in result.items() if key != "cookies"}, [("Set-Cookie", cookie) for cookie in result.get("cookies", [])])
                        else:
                            action = gui_setup.preview if parts[2] == "preview" else gui_setup.apply
                            self.response(200 if parts[2] == "preview" else 202, action(app.platform, self.body(), principal))
                    else:
                        self.response(405, {"error": "Method not allowed"})
                    return
                if parts == ["platform", "status"] and method == "GET":
                    self.response(200, app.platform.status() if app.platform else {"runtime": {"storage": app.store.storage_kind, "ha": app.store.ha, "demo": app.demo}, "cluster": app.cluster(), "configuration": {"revision": 0, "spec": None}, "capabilities": {"backups": False, "remote_provisioning": False, "supervised": False}, "blockers": ["Configure a private platform state directory on this controller"]})
                    return
                if parts == ["platform", "backup-schedule"] and method == "GET":
                    from .backup_schedule import get
                    self.response(200, get(app.store))
                    return
                if parts == ["platform", "agent-settings"] and method == "GET":
                    from .agent_settings import get
                    self.response(200, get(app.store))
                    return
                if parts == ["platform", "appliance"] and method == "GET":
                    from .appliance import Appliance
                    self.response(200, Appliance(app.platform).status())
                    return
                if parts == ["platform", "certificates"] and method == "GET":
                    from .certificates import status
                    self.response(200, status(app.platform))
                    return
                if parts == ["platform", "endpoint-certificates"] and method == "GET":
                    from .endpoint_certificates import listing
                    self.response(200, listing(app.store))
                    return
                if parts == ["platform", "internal-certificates"] and method == "GET":
                    from .internal_certificates import status
                    from .appliance import Appliance
                    self.response(200, status(Appliance(app.platform)))
                    return
                if parts == ["platform", "policy-signing-trust"] and method == "GET":
                    self.response(200, app.platform.policy_signer().public_trust())
                    return
                if parts == ["platform", "application-port"] and method == "GET":
                    from .application_port import status
                    self.response(200, status(app.platform))
                    return
                if role != "super_admin":
                    raise PermissionError("Only Super Admin can manage platform storage, backups, cluster installation or joining")
                if len(parts) == 3 and parts[:2] == ["platform", "application-port"] and parts[2] in ("preview", "apply") and method == "POST":
                    from .application_port import preview, apply
                    callback = preview if parts[2] == "preview" else apply
                    self.response(200 if parts[2] == "preview" else 202, callback(app.platform, self.body(), actor))
                    return
                if parts == ["platform", "recovery"] and method == "GET":
                    from .recovery import status
                    self.response(200, status(app.platform))
                    return
                if len(parts) == 3 and parts[:2] == ["platform", "recovery"] and parts[2] in ("preview", "confirm") and method == "POST":
                    from .recovery import preview, confirm
                    action = preview if parts[2] == "preview" else confirm
                    self.response(200, action(app.platform, self.body(), actor, principal=principal))
                    return
                if parts[:2] == ["platform", "notifications"]:
                    from . import notifications
                    if len(parts) == 2 and method == "GET":
                        self.response(200, notifications.get(app.platform))
                    elif parts[2:] == ["preview"] and method == "POST":
                        self.response(200, notifications.preview(app.platform, self.body(), actor))
                    elif parts[2:] == ["apply"] and method == "POST":
                        self.response(200, notifications.apply(app.platform, self.body(), actor))
                    elif parts[2:] == ["deliveries"] and method == "GET":
                        self.response(200, notifications.deliveries(app.store, limit=int(query.get("limit", [50])[0]), offset=int(query.get("offset", [0])[0])))
                    elif len(parts) == 5 and parts[2] == "channels" and parts[4] == "test" and method == "POST":
                        self.response(202, notifications.test(app.platform, parts[3], self.body(), actor))
                    elif len(parts) == 5 and parts[2] == "deliveries" and parts[4] == "retry" and method == "POST":
                        self.response(202, notifications.retry(app.platform, parts[3], self.body(), actor))
                    else:
                        self.response(404, {"error": "Notification operation not found"})
                    return
                if parts == ["platform", "endpoint-certificates", "revoke-preview"] and method == "POST":
                    from .endpoint_certificates import revoke_preview
                    self.response(200, revoke_preview(app.store, self.body(), actor))
                    return
                if parts == ["platform", "endpoint-certificates", "revoke-apply"] and method == "POST":
                    from .endpoint_certificates import revoke_apply
                    self.response(200, revoke_apply(app.store, self.body(), actor))
                    return
                if parts == ["platform", "endpoint-certificates", "recovery-token"] and method == "POST":
                    from .endpoint_certificates import recovery_token
                    self.response(201, recovery_token(app.store, self.body().get("server_id"), actor))
                    return
                if len(parts) == 3 and parts[:2] == ["platform", "internal-certificates"] and parts[2] in ("suspend-preview", "suspend-apply") and method == "POST":
                    from .internal_certificates import suspension_preview, suspension_apply
                    from .appliance import Appliance
                    action = suspension_preview if parts[2] == "suspend-preview" else suspension_apply
                    self.response(200, action(Appliance(app.platform), self.body(), actor))
                    return
                if not app.platform:
                    raise RuntimeError("Configure a private platform state directory on this controller")
                from . import maintenance
                if parts == ["platform", "backup-schedule"] and method in ("POST", "PUT"):
                    from .backup_schedule import save
                    self.response(200, save(app.store, self.body(), actor))
                elif parts == ["platform", "agent-settings"] and method == "POST":
                    from .agent_settings import save
                    self.response(200, save(app.store, self.body(), actor))
                elif parts == ["platform", "agent-settings", "preview"] and method == "POST":
                    from .agent_settings import preview
                    self.response(200, preview(app.store, self.body()))
                elif parts == ["platform", "agent-settings", "pilot-preview"] and method == "POST":
                    from .pilot_polling import preview
                    self.response(200, preview(app.store, self.body()))
                elif parts[:2] == ["platform", "appliance"]:
                    from .appliance import Appliance
                    api = Appliance(app.platform)
                    operations = {("config",): api.save, ("join", "preview"): api.join_preview,
                                  ("join", "apply"): api.join_apply, ("services", "review"): api.service_review,
                                  ("services", "apply"): api.service_apply, ("storage", "review"): api.storage_review,
                                  ("storage", "apply"): api.storage_apply, ("replication", "abort"): api.abort_rotation}
                    callback = operations.get(tuple(parts[2:]))
                    if method != "POST" or not callback:
                        raise ValueError("Unknown appliance operation")
                    self.response(202 if parts[-1] == "apply" else 200, callback(self.body(), actor))
                elif parts == ["platform", "certificates", "preview"] and method == "POST":
                    from .certificates import preview
                    self.response(201, preview(app.platform, self.body(), actor))
                elif parts == ["platform", "certificates", "apply"] and method == "POST":
                    from .certificates import apply
                    self.response(202, apply(app.platform, self.body(), actor))
                elif parts == ["platform", "backups"] and method == "GET":
                    self.response(200, {"items": maintenance.backup_listing(app.store)})
                elif parts == ["platform", "backups"] and method == "POST":
                    self.body()
                    self.response(201, maintenance.backup_create(app.store, actor))
                elif len(parts) == 4 and parts[:2] == ["platform", "backups"] and method == "GET" and parts[3] == "inspect":
                    self.response(200, maintenance.backup_inspect(app.store, parts[2]))
                elif len(parts) == 4 and parts[:2] == ["platform", "backups"] and method == "POST" and parts[3] == "restore-validation":
                    self.body()
                    self.response(200, maintenance.restore_validate(app.store, parts[2], actor))
                elif len(parts) == 4 and parts[:2] == ["platform", "backups"] and method == "GET" and parts[3] == "download":
                    path = maintenance.backup_download(app.store, parts[2])
                    with path.open("rb") as source:
                        self.send_response(200)
                        self.send_header("Content-Type", "application/zip")
                        self.send_header("Content-Disposition", 'attachment; filename="prthak-database-backup-' + parts[2] + '.zip"')
                        self.send_header("Content-Length", str(path.stat().st_size))
                        self.send_header("Cache-Control", "no-store")
                        self.security_headers()
                        self.end_headers()
                        while chunk := source.read(65536):
                            self.wfile.write(chunk)
                elif parts == ["platform", "demo", "preview"] and method == "POST":
                    self.body()
                    self.response(201, maintenance.clear_preview(app.store, actor))
                elif parts == ["platform", "demo", "clear"] and method == "POST":
                    self.response(200, maintenance.clear_confirm(app.store, self.body(), actor))
                elif parts == ["platform", "ha", "config"] and method == "POST":
                    self.response(200, app.platform.save_configuration(self.body(), actor))
                elif parts == ["platform", "ha", "test"] and method == "POST":
                    self.response(202, app.platform.test_configuration(self.body(), actor))
                elif parts == ["platform", "ha", "preview"] and method == "POST":
                    self.response(201, app.platform.preview(self.body(), actor))
                elif parts == ["platform", "ha", "apply"] and method == "POST":
                    self.response(202, app.platform.apply(self.body(), actor))
                elif parts == ["platform", "ha", "activate"] and method == "POST":
                    self.response(202, app.platform.activate(self.body(), actor))
                elif len(parts) == 3 and parts[:2] == ["platform", "jobs"] and method == "GET":
                    self.response(200, app.platform.job(parts[2]))
                elif parts == ["platform", "join-tokens"] and method == "POST":
                    self.response(201, app.platform.create_join_token(self.body(), actor))
                elif parts == ["platform", "join", "preview"] and method == "POST":
                    self.response(201, app.platform.join_preview(self.body(), actor))
                elif parts == ["platform", "join", "apply"] and method == "POST":
                    self.response(202, app.platform.join_apply(self.body(), actor))
                else:
                    self.response(405, {"error": "Unknown platform operation or method"})
            elif parts == ["servers"] and method == "GET":
                self.response(200, {"items": app.store.servers()})
            elif parts == ["servers"] and method == "POST":
                from .server_management import create
                self.response(201, create(app.store, self.body(), actor))
            elif parts == ["server-reservations"] and method == "GET":
                from .server_management import reservation_listing
                self.response(200, {"items": reservation_listing(app.store)})
            elif len(parts) == 3 and parts[0] == "servers" and parts[2] in ("delete-preview", "delete-confirm") and method == "POST":
                from .server_management import delete_preview, delete_confirm
                value = self.body()
                self.response(201 if parts[2] == "delete-preview" else 200,
                    delete_preview(app.store, parts[1], actor) if parts[2] == "delete-preview" else delete_confirm(app.store, parts[1], value, actor))
            elif parts and parts[0] == "metadata":
                from . import metadata
                if method == "GET" and parts == ["metadata", "subnets"]:
                    self.response(200, {"items": metadata.subnet_listing(app.store)})
                elif method == "GET" and parts == ["metadata", "imports", "profiles"]:
                    if role not in ("admin", "super_admin"):
                        raise PermissionError("Admin role required to manage imported IP profiles")
                    from .metadata_csv import listing
                    self.response(200, listing(app.store, int(query.get("limit", [100])[0]), int(query.get("offset", [0])[0])))
                elif method == "POST":
                    if role not in ("admin", "super_admin"):
                        raise PermissionError("Admin role required for central tags, CSV imports and subnet assignments")
                    if parts == ["metadata", "bulk", "preview"]:
                        self.response(201, metadata.bulk_preview(app.store, self.body()))
                    elif len(parts) == 4 and parts[:2] == ["metadata", "bulk"] and parts[3] == "apply":
                        self.response(200, metadata.bulk_apply(app.store, parts[2], self.body(), actor))
                    elif parts == ["metadata", "subnets", "preview"]:
                        self.response(201, metadata.subnet_preview(app.store, self.body()))
                    elif len(parts) == 4 and parts[:2] == ["metadata", "subnets"] and parts[3] == "delete-preview":
                        self.body()
                        self.response(201, metadata.subnet_preview(app.store, {}, remove_id=parts[2]))
                    elif len(parts) == 4 and parts[:2] == ["metadata", "subnets"] and parts[3] == "apply":
                        self.response(200, metadata.subnet_apply(app.store, parts[2], self.body(), actor))
                    elif parts == ["metadata", "imports", "preview"]:
                        from .metadata_csv import preview
                        self.response(201, preview(app.store, self.body(), actor))
                    elif len(parts) == 5 and parts[:3] == ["metadata", "imports", "profiles"] and parts[4] == "delete-preview":
                        from .metadata_csv import delete_preview
                        self.body()
                        self.response(201, delete_preview(app.store, unquote(parts[3]), actor))
                    elif len(parts) == 4 and parts[:2] == ["metadata", "imports"] and parts[3] == "apply":
                        from .metadata_csv import apply as apply_import
                        self.response(200, apply_import(app.store, parts[2], self.body(), actor))
                    else:
                        self.response(404, {"error": "Unknown metadata operation"})
                else:
                    self.response(405, {"error": "Method not allowed"})
            elif len(parts) == 2 and parts[0] == "servers":
                if method == "GET":
                    server = app.store.server(parts[1])
                    from .session_views import listing as public_sessions, compiled_policy
                    server["compiled_policy"] = compiled_policy(app.store, parts[1])
                    session_page = public_sessions(app.store,server_id=parts[1])
                    server["learning_sessions"] = session_page.pop("items")
                    server["learning_session_pagination"] = session_page
                    self.response(200, server)
                elif method == "PATCH":
                    value = self.body()
                    if set(value) & {"tags", "tag_updates", "reset_tag_keys", "location_id", "location_mode"} and role not in ("admin", "super_admin"):
                        raise PermissionError("Admin role required for server tags and location assignment")
                    self.response(200, app.store.update_server(parts[1], value, actor))
                else:
                    self.response(405, {"error": "Method not allowed"})
            elif parts == ["firewall"] and method == "GET":
                selected = query.get("server_id", []) + [identifier for part in query.get("server_ids", []) for identifier in part.split(",") if identifier]
                self.response(200, app.store.firewall_inventory(set(selected) if selected else None,after=query.get("after",[""])[0],limit=int(query.get("limit",["50"])[0])))
            elif parts == ["firewall", "query"] and method == "POST":
                from .firewall_views import options
                value=options(self.body())
                self.response(200,app.store.firewall_inventory(value.pop("server_ids"),include_snapshots=False,**value))
            elif parts == ["firewall", "changes"] and method == "GET":
                from .firewall_views import plan_summaries
                with app.store.read_meta() as db:
                    self.response(200, {"items": plan_summaries(app.store,db),"limit":20})
            elif len(parts)==3 and parts[:2]==["firewall","changes"] and method=="GET":
                from .firewall import public_plan
                plan=app.store.get("firewall_changes",parts[2])
                if not plan: raise KeyError(parts[2])
                self.response(200,public_plan(plan))
            elif parts == ["firewall", "changes"] and method == "POST":
                if role not in ("admin", "super_admin"):
                    raise PermissionError("Admin role required for imported firewall changes")
                self.response(201, app.store.create_firewall_change(self.body(), actor, principal=principal))
            elif len(parts) == 4 and parts[:2] == ["firewall", "changes"] and method == "POST" and parts[3] in ("confirm", "cancel"):
                if role not in ("admin", "super_admin"):
                    raise PermissionError("Admin role required for imported firewall changes")
                value = app.store.confirm_firewall_change(parts[2], self.body(), actor, principal=principal) if parts[3] == "confirm" else app.store.cancel_firewall_change(parts[2], actor)
                self.response(200, value)
            elif len(parts) in (3, 4, 5) and parts[0] == "servers" and parts[2] == "policy-history" and method == "GET":
                from . import managed_views
                if len(parts) == 3:
                    self.response(200, managed_views.history(app.store, parts[1], int(query.get("limit", [20])[0]), int(query.get("offset", [0])[0])))
                elif len(parts) == 4 and parts[3] == "diff":
                    self.response(200, managed_views.bundle_diff(app.store, parts[1], int(query.get("from", [0])[0]), int(query.get("to", [0])[0])))
                elif len(parts) == 5 and parts[4] == "outcomes":
                    self.response(200, managed_views.outcomes(app.store, parts[1], int(parts[3]), int(query.get("limit", [20])[0]), int(query.get("offset", [0])[0])))
                elif len(parts) == 4:
                    self.response(200, managed_views.bundle(app.store, parts[1], int(parts[3])))
                else:
                    self.response(404, {"error": "Managed history route not found"})
            elif len(parts) in (3, 4) and parts[0] == "policies" and parts[2] == "revisions" and method == "GET":
                from . import managed_views
                self.response(200, managed_views.revisions(app.store, parts[1], int(query.get("limit", [20])[0]), int(query.get("offset", [0])[0])) if len(parts) == 3 else managed_views.revision(app.store, parts[1], int(parts[3])))
            elif len(parts) == 3 and parts[0] == "policies" and parts[2] == "diff" and method == "GET":
                from .managed_views import revision_diff
                self.response(200, revision_diff(app.store, parts[1], int(query.get("from", [0])[0]), int(query.get("to", [0])[0])))
            elif len(parts) == 3 and parts[0] == "policies" and parts[2] == "rollback" and method == "POST":
                if role not in ("admin", "super_admin"):
                    raise PermissionError("Admin role required to restore a historical policy")
                value = self.body()
                if value.get("summary_only") is True:
                    raise ValueError("Open the exact immutable revision before requesting a restore")
                self.response(201, app.store.rollback_policy(parts[1], value.get("revision"), value.get("reason"), actor, principal=principal))
            elif parts and parts[0] == "host-default-deny":
                from . import host_default_deny
                if parts == ["host-default-deny"] and method == "GET":
                    self.response(200, host_default_deny.listing(app.store, {**{key:query[key][0] for key in ("server_id","search") if key in query},"limit":int(query.get("limit",[50])[0]),"offset":int(query.get("offset",[0])[0])}))
                elif parts == ["host-default-deny","query"] and method == "POST":
                    self.response(200,host_default_deny.listing(app.store,self.body()))
                elif parts == ["host-default-deny","preview"] and method == "POST":
                    self.response(201,host_default_deny.preview(app.store,self.body(),actor,principal))
                elif len(parts)==2 and method=="GET":
                    self.response(200,host_default_deny.get(app.store,parts[1]))
                elif len(parts)==3 and parts[2]=="confirm" and method=="POST":
                    self.response(200,host_default_deny.confirm(app.store,parts[1],self.body(),actor,principal))
                else:self.response(405,{"error":"Method not allowed"})
            elif parts == ["policy-rollouts"]:
                if method == "GET":
                    from .managed_views import rollouts
                    selected = query.get("server_id", [None])[0]
                    self.response(200, rollouts(app.store, int(query.get("limit", [20])[0]), int(query.get("offset", [0])[0]), [selected] if selected is not None else None, query.get("search", [""])[0]))
                elif method == "POST":
                    if role not in ("admin", "super_admin"):
                        raise PermissionError("Admin role required to review managed enforcement")
                    self.response(201, app.store.create_managed_rollout(self.body(), actor, principal=principal))
                else:
                    self.response(405, {"error": "Method not allowed"})
            elif parts == ["policy-rollouts", "query"] and method == "POST":
                from .managed_views import rollouts, rollout_options
                self.response(200, rollouts(app.store, **rollout_options(self.body())))
            elif len(parts) == 2 and parts[0] == "policy-rollouts" and method == "GET":
                from .managed_views import rollout
                self.response(200, rollout(app.store, parts[1]))
            elif len(parts) == 3 and parts[0] == "policy-rollouts" and parts[2] in ("confirm", "cancel") and method == "POST":
                if role not in ("admin", "super_admin"):
                    raise PermissionError("Admin role required to approve managed enforcement")
                value = self.body()
                if value.get("summary_only") is True:
                    raise ValueError("Open the exact managed review before authorizing it")
                result = app.store.confirm_managed_rollout(parts[1], value, actor, principal=principal) if parts[2] == "confirm" else app.store.cancel_managed_rollout(parts[1], actor)
                self.response(200, result)
            elif parts == ["locations"]:
                if method == "GET":
                    self.response(200, {"items": app.store.locations()})
                elif method == "POST":
                    if role not in ("admin", "super_admin"):
                        raise PermissionError("Admin role required for location catalogue changes")
                    self.response(201, app.store.save_location(self.body(), actor))
                else:
                    self.response(405, {"error": "Method not allowed"})
            elif len(parts) == 2 and parts[0] == "locations":
                if method == "GET":
                    self.response(200, app.store.get("locations", parts[1]))
                elif method in ("PUT", "DELETE"):
                    if role not in ("admin", "super_admin"):
                        raise PermissionError("Admin role required for location catalogue changes")
                    if method == "PUT":
                        self.response(200, app.store.save_location(self.body(), actor, parts[1]))
                    else:
                        app.store.delete_location(parts[1], actor)
                        self.response(204)
                else:
                    self.response(405, {"error": "Method not allowed"})
            elif parts == ["groups"]:
                if method == "GET":
                    self.response(200, {"items": app.store.groups()})
                elif method == "POST":
                    self.response(201, app.store.save_group(self.body(), actor))
                else:
                    self.response(405, {"error": "Method not allowed"})
            elif parts == ["service-groups"]:
                from . import service_groups
                if method == "GET":
                    from .policy_views import service_groups as public_service_groups
                    self.response(200, {"items": public_service_groups(app.store)})
                elif method == "POST":
                    self.response(201, service_groups.save(app.store, self.body(), actor))
                else:
                    self.response(405, {"error": "Method not allowed"})
            elif parts == ["service-groups", "preview"] and method == "POST":
                from .service_groups import preview
                value = self.body()
                self.response(200, preview(app.store, value, value.get("id")))
            elif len(parts) in (2, 3, 4) and parts[0] == "service-groups":
                from . import service_groups
                identifier = unquote(parts[1])
                if len(parts) == 2 and method == "GET":
                    from .policy_views import service_groups as public_service_groups
                    self.response(200, public_service_groups(app.store, identifier))
                elif len(parts) == 2 and method == "PUT":
                    self.response(200, service_groups.save(app.store, self.body(), actor, identifier))
                elif len(parts) == 2 and method == "DELETE":
                    service_groups.delete(app.store, identifier, actor)
                    self.response(204)
                elif len(parts) >= 3 and parts[2] == "revisions" and method == "GET":
                    self.response(200, {"items": service_groups.revisions(app.store, identifier)} if len(parts) == 3 else service_groups.revisions(app.store, identifier, int(parts[3])))
                else:
                    self.response(405, {"error": "Method not allowed"})
            elif len(parts) == 2 and parts[0] == "groups":
                if method == "GET":
                    group = next((item for item in app.store.groups() if item["id"] == parts[1]), None)
                    if not group:
                        raise KeyError(parts[1])
                    self.response(200, group)
                elif method == "PUT":
                    self.response(200, app.store.save_group(self.body(), actor, parts[1]))
                elif method == "DELETE":
                    app.store.delete_group(parts[1], actor)
                    self.response(204)
                else:
                    self.response(405, {"error": "Method not allowed"})
            elif parts == ["policies"]:
                if method == "GET":
                    from .policy_views import listing as public_policies
                    self.response(200, public_policies(app.store,"managed",{**{key:query[key][0] for key in ("search","mode","server_id") if key in query},"limit":int(query.get("limit",[20])[0]),"offset":int(query.get("offset",[0])[0])}))
                elif method == "POST":
                    self.response(201, app.store.save_policy(self.body(), actor, principal=principal))
                else:
                    self.response(405, {"error": "Method not allowed"})
            elif parts == ["policies", "query"] and method == "POST":
                from .policy_views import listing as public_policies
                self.response(200, public_policies(app.store,"managed",self.body()))
            elif len(parts) == 2 and parts[0] == "policies":
                if method == "GET":
                    from .policy_views import detail as public_policy_detail
                    self.response(200, public_policy_detail(app.store,"managed",unquote(parts[1])))
                elif method == "PUT":
                    self.response(200, app.store.save_policy(self.body(), actor, parts[1], principal=principal))
                elif method == "DELETE":
                    value=self.body() if self.headers.get("Content-Length") not in (None,"","0") else {}
                    if set(value)-{"expected_revision"}:raise ValueError("Delete requires only the exact policy revision")
                    app.store.delete_policy(parts[1], actor, expected_revision=value.get("expected_revision"))
                    self.response(204)
                else:
                    self.response(405, {"error": "Method not allowed"})
            elif parts == ["learning-policies"] and method == "GET":
                from .policy_views import listing as public_policies
                self.response(200, public_policies(app.store,"learned",{**{key:query[key][0] for key in ("search","status","server_id","session_id") if key in query},"limit":int(query.get("limit",[20])[0]),"offset":int(query.get("offset",[0])[0])}))
            elif parts == ["learning-policies", "query"] and method == "POST":
                from .policy_views import listing as public_policies
                self.response(200, public_policies(app.store,"learned",self.body()))
            elif parts == ["learning-policies", "approvals"] and method == "GET":
                from .learning_policies import approval_reviews
                self.response(200, approval_reviews(app.store, session_id=query.get("session_id", [None])[0], limit=int(query.get("limit", [200])[0]), offset=int(query.get("offset", [0])[0])))
            elif len(parts) == 3 and parts[:2] == ["learning-policies", "approvals"] and method == "GET":
                from .learning_policies import approval_review
                self.response(200, approval_review(app.store, parts[2]))
            elif len(parts) == 3 and parts[0] == "learning-policies" and parts[2] in ("change-preview", "change-confirm") and method == "POST":
                if role not in ("admin", "super_admin"):
                    raise PermissionError("Admin role is required for learned access changes")
                from .learning_policies import change_preview, change_confirm
                action = change_preview if parts[2] == "change-preview" else change_confirm
                self.response(200, action(app.store, parts[1], self.body(), actor, principal=principal))
            elif len(parts) == 2 and parts[0] == "learning-policies":
                from . import learning_policies
                if method == "GET":
                    from .policy_views import detail as public_policy_detail
                    self.response(200, public_policy_detail(app.store,"learned",unquote(parts[1])))
                elif method == "PATCH":
                    self.response(200, learning_policies.update(app.store, parts[1], self.body(), actor))
                elif method == "DELETE":
                    self.response(200, learning_policies.remove(app.store, parts[1], self.body(), actor))
                else:
                    self.response(405, {"error": "Method not allowed"})
            elif len(parts) in (3, 4) and parts[0] == "learning" and parts[2] == "recommendations":
                from . import learning_policies
                if len(parts) == 3 and method == "GET":
                    self.response(200, learning_policies.recommendations(app.store, parts[1], int(query.get("limit", [200])[0]), int(query.get("offset", [0])[0]),query.get("server_id",[None])[0]))
                elif len(parts) == 4 and method == "POST" and parts[3] == "preview":
                    self.response(201, learning_policies.preview(app.store, parts[1], self.body(), actor, principal=principal))
                elif len(parts) == 4 and method == "POST" and parts[3] == "apply":
                    self.response(201, learning_policies.apply(app.store, parts[1], self.body(), actor, principal=principal))
                else:
                    self.response(405, {"error": "Method not allowed"})
            elif len(parts) == 3 and parts[0] == "learning" and parts[2] == "export.csv" and method == "GET":
                from .evidence_views import csv_spool,ExportBusy
                try:
                    with csv_spool(app.store,parts[1],query.get("server_id",[None])[0]) as (source,size):
                        self.send_response(200)
                        self.send_header("Content-Type", "text/csv; charset=utf-8")
                        self.send_header("Content-Disposition", 'attachment; filename="prthak-observed-access.csv"')
                        self.send_header("Content-Length", str(size))
                        self.send_header("Cache-Control", "no-store")
                        self.security_headers()
                        self.end_headers()
                        while chunk:=source.read(65536):self.wfile.write(chunk)
                except ExportBusy as error:
                    self.response(503,{"error":str(error)},{"Retry-After":"2"})
            elif parts == ["hit-monitors"] and method == "GET":
                from .hit_monitoring import listing
                self.response(200, listing(app.store, int(query.get("limit", [20])[0]), int(query.get("offset", [0])[0])))
            elif parts == ["hit-monitors", "preview"] and method == "POST":
                from .hit_monitoring import preview
                self.response(201, preview(app.store, self.body(), actor))
            elif parts == ["hit-monitors", "apply"] and method == "POST":
                if app.demo:
                    raise PermissionError("Actual continuous capture cannot be enabled or stopped through the demo")
                from .hit_monitoring import apply
                self.response(200, apply(app.store, self.body(), actor))
            elif len(parts) == 3 and parts[0] == "hit-monitors" and parts[2] == "stop-preview" and method == "POST":
                from .hit_monitoring import stop_preview
                self.response(201, stop_preview(app.store, parts[1], self.body(), actor))
            elif len(parts) == 3 and parts[0] == "hit-monitors" and parts[2] == "hits" and method == "GET":
                from .hit_monitoring import hits
                self.response(200, hits(app.store, parts[1], int(query.get("window_hours", [1])[0]), int(query.get("limit", [100])[0]), int(query.get("offset", [0])[0]), query.get("server_id", [None])[0]))
            elif len(parts) == 3 and parts[0] == "hit-monitors" and parts[2] == "targets" and method == "GET":
                from .hit_monitoring import target_page
                self.response(200, target_page(app.store, parts[1], int(query.get("limit", [50])[0]), int(query.get("offset", [0])[0])))
            elif len(parts) == 3 and parts[0] == "hit-monitors" and parts[2] == "export.csv" and method == "GET":
                from .hit_monitoring import csv_spool
                with csv_spool(app.store, parts[1], int(query.get("window_hours", [1])[0]), query.get("server_id", [None])[0]) as (source, size):
                    self.send_response(200)
                    self.send_header("Content-Type", "text/csv; charset=utf-8")
                    self.send_header("Content-Disposition", 'attachment; filename="prthak-hit-observations.csv"')
                    self.send_header("Content-Length", str(size))
                    self.send_header("Cache-Control", "no-store")
                    self.security_headers()
                    self.end_headers()
                    while chunk := source.read(65536):
                        self.wfile.write(chunk)
            elif parts == ["learning", "preview"] and method == "POST":
                from .learning import preview
                self.response(200, preview(app.store, self.body()))
            elif parts == ["learning"] and method == "POST":
                self.response(201, app.store.create_session(self.body(), actor, principal=principal))
            elif parts == ["learning"] and method == "GET":
                from .session_views import listing as public_sessions
                self.response(200, public_sessions(app.store,limit=int(query.get("limit",[6])[0]),offset=int(query.get("offset",[0])[0]),server_id=query.get("server_id",[None])[0]))
            elif len(parts) == 3 and parts[0] == "learning" and parts[2] == "hosts" and method == "GET":
                from .session_views import hosts as public_session_hosts
                self.response(200, public_session_hosts(app.store,parts[1],limit=int(query.get("limit",[50])[0]),offset=int(query.get("offset",[0])[0])))
            elif len(parts) == 3 and parts[0] == "learning" and parts[2] == "stop" and method == "POST":
                self.response(200, app.store.stop_session(parts[1], actor))
            elif len(parts) == 3 and parts[0] == "learning" and parts[2] in ("approval-preview", "approval-confirm") and method == "POST":
                if role not in ("admin", "super_admin"):
                    raise PermissionError("Admin role is required for learning authorization")
                from .approvals import learning_preview, learning_confirm
                action = learning_preview if parts[2] == "approval-preview" else learning_confirm
                self.response(200, action(app.store, parts[1], self.body(), actor, principal=principal))
            elif parts == ["flows"] and method == "GET":
                window = int(query.get("window", [3600])[0])
                self.response(200, {"items": app.store.flows(window, query.get("server_id", [None])[0])})
            elif parts == ["alerts"] and method == "GET":
                self.response(200, {"items": sorted(app.store.all("alerts"), key=lambda item: item["created_at"], reverse=True)[:500]})
            elif len(parts) == 3 and parts[0] == "alerts" and parts[2] == "ack" and method == "POST":
                self.response(200, app.store.acknowledge(unquote(parts[1]), actor))
            elif parts == ["audit"] and method == "GET":
                self.response(200, {"items": sorted(app.store.all("audit"), key=lambda item: item["created_at"], reverse=True)[:500]})
            elif parts[:2] == ["agent-installation", "configuration"]:
                if role not in ("admin", "super_admin") or not isinstance(self.connection, ssl.SSLSocket):
                    raise PermissionError("Endpoint configuration requires Admin access over HTTPS")
                from . import endpoint_configuration as lifecycle
                if len(parts) == 2 and method == "GET":
                    self.response(200, lifecycle.listing(app,server_id=query.get("server_id",[None])[0],limit=int(query.get("limit",[20])[0]),offset=int(query.get("offset",[0])[0])))
                elif parts[2:] == ["preview"] and method == "POST":
                    self.response(201, lifecycle.preview(app, self.body(), actor, principal))
                elif len(parts) == 4 and parts[3] == "confirm" and method == "POST":
                    self.response(200, lifecycle.confirm(app, parts[2], self.body(), actor, principal))
                elif len(parts) == 4 and parts[3] == "revoke" and method == "POST":
                    self.body()
                    self.response(200, lifecycle.revoke(app, parts[2], actor, principal))
                elif len(parts) == 4 and parts[3] == "kit" and method == "POST":
                    self.body()
                    self.response(200, lifecycle.kit(app, parts[2], actor), {"Content-Disposition": 'attachment; filename="prthak-endpoint-configuration.json"'})
                else:
                    self.response(405, {"error": "Method not allowed"})
            elif parts[:2] == ["agent-installation", "fleet-profiles"]:
                if role not in ("admin", "super_admin") or not isinstance(self.connection, ssl.SSLSocket):
                    raise PermissionError("Fleet enrollment settings require Admin access over HTTPS")
                from . import fleet_enrollment
                if len(parts) == 2 and method == "GET":
                    self.response(200, fleet_enrollment.listing(app.store, limit=int(query.get("limit", [50])[0]), offset=int(query.get("offset", [0])[0])))
                elif len(parts) == 2 and method == "POST":
                    from .agent_installation import create_fleet_kit
                    self.response(201, create_fleet_kit(app, self.body(), actor), {"Content-Disposition": 'attachment; filename="prthak-agent-setup.json"'})
                elif len(parts) == 4 and parts[3] == "revoke" and method == "POST":
                    if self.body() != {}:
                        raise ValueError("Fleet profile revocation accepts an empty object only")
                    self.response(200, fleet_enrollment.revoke(app.store, parts[2], actor))
                else:
                    self.response(405, {"error": "Method not allowed"})
            elif parts == ["agent-installation", "kit"] and method == "POST":
                if role not in ("admin", "super_admin") or not isinstance(self.connection, ssl.SSLSocket):
                    raise PermissionError("Agent setup downloads require Admin access over HTTPS")
                from .agent_installation import create_kit
                self.response(201, create_kit(app, self.body(), actor), {"Content-Disposition": 'attachment; filename="prthak-agent-setup.json"'})
            elif parts == ["enrollment-tokens"] and method == "POST":
                if role not in ("admin", "super_admin"):
                    raise PermissionError("Admin role required")
                value = self.body()
                self.response(201, app.store.create_token(value.get("name", "endpoint"), actor, value.get("tags", {}), value.get("location_id"), value.get("server_id")))
            else:
                self.response(404, {"error": "Not found"})

        def dispatch(self):
            try:
                self.execute()
            except RateLimited:
                self.close_connection = True
                self.response(429, {"error": "Request limit reached; retry shortly"}, {"Retry-After": "2"})
            except AuthConflict as error:
                self.close_connection = True
                self.response(409, {"error": str(error)})
            except WorkflowConflict as error:
                self.response(409, {"error": str(error), "plan": error.plan})
            except LearningExpired as error:
                self.close_connection = True
                self.response(410, {"error": str(error)})
            except PermissionError as error:
                self.close_connection = True
                self.response(403, {"error": str(error)})
            except KeyError:
                self.close_connection = True
                self.response(404, {"error": "Record not found"})
            except (ValueError, TypeError, json.JSONDecodeError) as error:
                self.close_connection = True
                self.response(400, {"error": str(error) or "Invalid request"})
            except (BrokenPipeError, ConnectionResetError, TimeoutError):
                pass
            except RuntimeError as error:
                self.close_connection = True
                self.response(503, {"error": str(error)})
            except Exception:
                self.close_connection = True
                LOG.exception("Request failed")
                self.response(500, {"error": "Internal controller error"})

        do_GET = dispatch
        do_POST = dispatch
        do_PUT = dispatch
        do_PATCH = dispatch
        do_DELETE = dispatch
    return Handler


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 128

    def __init__(self, address, app):
        from .listener_address import bind_host
        host = bind_host(address[0])
        self.address_family = socket.AF_INET6 if ':' in host else socket.AF_INET
        self.app = app
        super().__init__((host, *address[1:]), handler_for(app))
