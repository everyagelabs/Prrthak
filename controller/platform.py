"""Private, revisioned platform configuration and durable bounded management jobs.

The HTTP process records reviewed intent. A separate supervisor executes jobs
and performs storage activation only after its application child has stopped.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import stat
import ssl
import threading
import uuid
from datetime import timedelta
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPSHandler, HTTPRedirectHandler

from .firewall import WorkflowConflict
from .store import digest, now, parse_time, stamp

PUBLIC_JOB_FIELDS = ("id", "operation", "status", "phase", "created_at", "updated_at", "result", "error")
IDENTIFIER = re.compile(r"[a-f0-9]{32}\Z")
SECRET_REFERENCE = re.compile(r"secret:[a-f0-9]{32}\Z")


def _private_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise ValueError("Platform state must not be a symlink")
    temporary = path.with_name(path.name + "." + secrets.token_hex(8) + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w") as output:
            json.dump(value, output, sort_keys=True)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def _read_json(path, default=None):
    path = Path(path)
    if not path.exists():
        return default
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 8 * 1024 * 1024:
        raise ValueError("Invalid private platform state")
    return json.loads(path.read_text())


class Vault:
    def __init__(self, directory):
        from cryptography.fernet import Fernet
        self.root = Path(directory)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.root.is_symlink():
            raise ValueError("Private vault must not be a symlink")
        self.root.chmod(0o700)
        key_path = self.root / "vault.key"
        if not key_path.exists():
            try:
                fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as output:
                    output.write(Fernet.generate_key())
            except FileExistsError:
                pass
        if key_path.is_symlink() or key_path.stat().st_mode & 0o077:
            raise ValueError("Vault key must be a private regular file")
        self.cipher = Fernet(key_path.read_bytes())

    def put(self, value):
        if not isinstance(value, (str, bytes)) or len(value) > 2 * 1024 * 1024:
            raise ValueError("Invalid private credential value")
        identifier = secrets.token_hex(16)
        raw = value.encode() if isinstance(value, str) else value
        _private_json(self.root / (identifier + ".json"), {"encrypted": self.cipher.encrypt(raw).decode()})
        return "secret:" + identifier

    def get(self, reference):
        if not isinstance(reference, str) or not SECRET_REFERENCE.fullmatch(reference):
            raise ValueError("Unknown credential reference")
        value = _read_json(self.root / (reference[7:] + ".json"))
        if not value:
            raise ValueError("Credential is unavailable on this controller")
        return self.cipher.decrypt(value["encrypted"].encode()).decode()


class PlatformManager:
    def policy_signer(self):
        from .policy_signing import PolicySigner, OfflinePolicySigner
        offline, trust = os.environ.get("SEG_POLICY_SIGNED_BUNDLES_DIR"), os.environ.get("SEG_POLICY_SIGNING_TRUST_FILE")
        if offline or trust:
            if not offline or not trust:
                raise ValueError("Offline policy signing requires both the protected bundle directory and public trust file")
            return OfflinePolicySigner(offline, trust)
        override = os.environ.get("SEG_POLICY_SIGNING_KEY_FILE")
        def fingerprint(path):
            try:
                value = Path(path).lstat()
                return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns,
                        value.st_mode, value.st_uid, value.st_gid, value.st_nlink)
            except OSError:
                return None
        def source_stamp(path):
            return (override, os.environ.get("SEG_POLICY_SIGNING_DEPLOYMENT_ID"),
                    fingerprint(self.root / "appliance-material.json"),
                    fingerprint(self.root / "appliance-authority.json"),
                    fingerprint(self.root / "demo-shared-seed.json"), fingerprint(path))
        with self.lock:
            previous = getattr(self, "_cached_policy_signer", None)
            if previous:
                try:info=previous.path.lstat()
                except OSError:raise ValueError("Cached signing authority is unavailable; restore its protected private seed") from None
                if not stat.S_ISREG(info.st_mode) or info.st_mode&0o077 or info.st_uid!=os.geteuid() or info.st_nlink!=1:
                    raise ValueError("Cached signing authority is no longer a protected owned private regular file")
            if previous and source_stamp(previous.path) == getattr(self, "_cached_policy_signer_stamp", None):
                return previous
            if override:
                domain = os.environ.get("SEG_POLICY_SIGNING_DEPLOYMENT_ID")
                if not domain:
                    raise ValueError("An external policy signing key requires SEG_POLICY_SIGNING_DEPLOYMENT_ID")
                signer = PolicySigner(override, domain)
            else:
                seed = self.shared_secret_key("policy-signing-v1")
                domain = str(uuid.UUID(bytes=hashlib.sha256(b"prthak-policy-domain-v1" + seed).digest()[:16]))
                path = self.root / "policy-signing" / (domain + ".seed")
                if not path.exists():
                    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    temporary = path.parent / (".seed-" + secrets.token_hex(16))
                    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                    try:
                        with os.fdopen(descriptor, "wb") as handle:
                            handle.write(seed)
                            handle.flush()
                            os.fsync(handle.fileno())
                        try:
                            os.link(temporary, path)
                        except FileExistsError:
                            pass
                    finally:
                        temporary.unlink(missing_ok=True)
                signer = PolicySigner(path, domain)
            self._cached_policy_signer = signer
            self._cached_policy_signer_stamp = source_stamp(signer.path)
            return signer

    def shared_secret_key(self, purpose):
        """Purpose-separated encryption material shared only with joined peers.

        Bind to the dedicated internal authority rather than mutable names or
        the endpoint issuer, so standalone-to-HA activation preserves access.
        """
        if purpose not in ("notifications-v1", "policy-signing-v1", "recovery-v1"):
            raise ValueError("Unsupported shared secret purpose")
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        with self.lock:
            if self.app and self.app.demo:
                path = self.root / "demo-shared-seed.json"
                record = _read_json(path)
                if not record:
                    record = {"seed_ref": self.vault.put(secrets.token_hex(32))}
                    _private_json(path, record)
                seed, authority = self.vault.get(record["seed_ref"]), "prthak-synthetic-demo"
            else:
                from .appliance import Appliance
                from .cluster_bootstrap import _material
                material = _material(Appliance(self))
                seed, authority = material["sync_key"], material["ca"]
            return HKDF(algorithm=hashes.SHA256(), length=32, salt=hashlib.sha256(authority.encode()).digest(),
                        info=("prthak/shared/" + purpose).encode()).derive(seed.encode())

    def __init__(self, data_dir, *, provisioner_factory=None):
        self.data_dir = Path(data_dir).absolute()
        self.root = self.data_dir / "platform"
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.root.is_symlink():
            raise ValueError("Platform state must not be a symlink")
        self.root.chmod(0o700)
        self._vault = None
        self.lock = threading.RLock()
        self.app = None
        self.provisioner_factory = provisioner_factory
        self._provision_thread = None
        self._appliance_thread = None

    @property
    def vault(self):
        if self._vault is None:
            try:
                self._vault = Vault(self.root / "vault")
            except ImportError:
                raise RuntimeError("Encrypted platform credentials require the controller requirements to be installed") from None
        return self._vault

    def attach(self, app):
        self.app = app
        app.store.backup_dir = self.root / "backups"
        if getattr(app, "controller_certificate", None) and getattr(app, "controller_private_key", None):
            _private_json(self.root / "controller-tls-context.json", {"cert_path": str(app.controller_certificate.absolute()), "key_path": str(app.controller_private_key.absolute()), "ca_path": str(app.signer.ca.absolute()) if app.signer else None})

    def certificate_context(self):
        context = _read_json(self.root / "controller-tls-context.json", {})
        profile = self.active_profile()
        if profile and profile.get("controller_tls"):
            for key, field in (("cert_path", "cert"), ("key_path", "key"), ("ca_path", "ca")):
                if field in profile["controller_tls"]:
                    context.setdefault(key, profile["controller_tls"][field])
        configured_origin = (profile or {}).get("controller_origin") or os.environ.get("CONTROLLER_ORIGIN", "")
        if self.app and not configured_origin:
            with self.app.store.read_meta() as db:
                settings = self.app.store._get(db, "maintenance_settings", "appliance_cluster") or {}
                configured_origin = settings.get("controller_origin", "")
        context["hostname"] = urlsplit(configured_origin).hostname or os.environ.get("PRTHAK_APPLIANCE_NODE_IP")
        if context.get("cert_path"):
            try:
                from cryptography import x509
                from cryptography.hazmat.primitives import hashes
                cert = x509.load_pem_x509_certificate(Path(context["cert_path"]).read_bytes())
                context["current_fingerprint"] = cert.fingerprint(hashes.SHA256()).hex()
                if not context["hostname"]:
                    names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                    context["hostname"] = next((str(name.value) for name in names if isinstance(name, x509.DNSName) and "*" not in name.value), None) or next((str(name.value) for name in names if isinstance(name, x509.IPAddress)), None)
            except (ValueError, OSError):
                context["current_fingerprint"] = None
        context["hostname"] = context["hostname"] or "localhost"
        context["managed_appliance"] = os.environ.get("PRTHAK_APPLIANCE") == "1"
        return context

    def launch_tls(self):
        return _read_json(self.root / "controller-tls-active.json", {})

    def commit_launch_tls(self, value):
        _private_json(self.root / "controller-tls-active.json", value)

    def local_controller_id(self, proposed, *, explicit=False):
        path = self.root / "controller-identity.json"
        saved = _read_json(path)
        if saved and not explicit:
            value = saved.get("controller_id")
            if not isinstance(value, str) or not value or len(value) > 100:
                raise ValueError("Local controller identity is invalid; restore its protected platform configuration")
            return value
        if not saved or saved.get("controller_id") != proposed:
            _private_json(path, {"controller_id": proposed})
        return proposed

    def _audit(self, kind, actor, details):
        if self.app:
            self.app.store.audit(kind, actor, details)

    def configuration(self, private=False):
        value = _read_json(self.root / "configuration.json", {"revision": 0, "spec": None})
        if private or not value.get("spec"):
            return value
        value = copy.deepcopy(value)
        for node in value["spec"]["nodes"]:
            ssh = node["ssh"]
            ssh["private_key_configured"] = bool(ssh.pop("private_key_ref", None))
        return value

    def save_configuration(self, body, actor):
        from .ha_setup import validate
        with self.lock:
            old = self.configuration(True)
            if isinstance(body.get("expected_revision"), bool) or body.get("expected_revision") != old["revision"]:
                raise WorkflowConflict("Platform configuration changed; reload before saving", {})
            spec = copy.deepcopy(body.get("spec"))
            if not isinstance(spec, dict):
                raise ValueError("A cluster specification is required")
            if not spec.get("cluster_id"):
                spec["cluster_id"] = (old.get("spec") or {}).get("cluster_id") or str(uuid.uuid4())
            old_nodes = {node["id"]: node for node in (old.get("spec") or {}).get("nodes", [])}
            nodes = spec.get("nodes")
            if not isinstance(nodes, list) or len(nodes) != 3 or any(not isinstance(node, dict) or not isinstance(node.get("ssh"), dict) for node in nodes):
                raise ValueError("Provide exactly three dedicated nodes and each node's SSH settings")
            for node in nodes:
                ssh = node.get("ssh", {})
                raw = ssh.pop("private_key", "")
                if not isinstance(raw, str) or len(raw) > 65536:
                    raise ValueError("SSH private keys must be text no larger than 64 KiB")
                ssh.pop("private_key_configured", None)
                # Browser-supplied vault references cannot select another key.
                ssh.pop("private_key_ref", None)
                if raw:
                    from cryptography.hazmat.primitives.serialization import load_ssh_private_key, load_pem_private_key
                    try:
                        try:
                            load_ssh_private_key(raw.encode(), password=None)
                        except ValueError:
                            load_pem_private_key(raw.encode(), password=None)
                    except (ValueError, TypeError):
                        raise ValueError("Provide an unencrypted SSH private key for the dedicated node; it is encrypted in the platform vault") from None
                    ssh["private_key_ref"] = self.vault.put(raw)
                else:
                    prior = old_nodes.get(node.get("id"), {}).get("ssh", {})
                    if prior.get("private_key_ref"):
                        ssh["private_key_ref"] = prior["private_key_ref"]
                node["ssh"] = ssh
            spec = validate(spec)
            value = {"revision": old["revision"] + 1, "spec": spec, "updated_at": stamp(), "updated_by": actor}
            _private_json(self.root / "configuration.json", value)
            self._audit("platform.configuration_saved", actor, {"revision": value["revision"], "cluster_id": spec["cluster_id"]})
            return self.configuration()

    def _job_path(self, identifier):
        if not isinstance(identifier, str) or not IDENTIFIER.fullmatch(identifier):
            raise KeyError(identifier)
        return self.root / "jobs" / (identifier + ".json")

    def _job(self, identifier):
        value = _read_json(self._job_path(identifier))
        if value is None:
            raise KeyError(identifier)
        return value

    @staticmethod
    def public_job(value):
        return {key: value[key] for key in PUBLIC_JOB_FIELDS if key in value}

    def job(self, identifier):
        return self.public_job(self._job(identifier))

    def _queue(self, operation, private, actor):
        value = {"id": secrets.token_hex(16), "operation": operation, "status": "queued", "phase": "queued", "created_at": stamp(), "updated_at": stamp(), "created_by": actor, "private": private}
        _private_json(self._job_path(value["id"]), value)
        self._audit("platform.job_queued", actor, {"job_id": value["id"], "operation": operation})
        return self.public_job(value)

    def _production(self):
        if self.app and self.app.demo:
            raise ValueError("Remote installation and HA activation require an authenticated HTTPS production controller; demo mode only previews configuration")
        if self.app and not self.app.signer:
            raise ValueError("Configure trusted controller TLS and endpoint issuance before HA installation")

    def test_configuration(self, body, actor):
        self._production()
        config = self.configuration(True)
        if not config.get("spec") or body.get("expected_revision") != config["revision"]:
            raise WorkflowConflict("Save and reload the current cluster configuration before testing", {})
        return self._queue("preflight", {"configuration": config}, actor)

    def preview(self, body, actor):
        config = self.configuration(True)
        job = self._job(body.get("test_job_id"))
        if config["revision"] != body.get("expected_revision") or job["operation"] != "preflight" or job["private"]["configuration"] != config or job["status"] != "ready":
            raise WorkflowConflict("A successful preflight of this exact configuration is required", {})
        if parse_time(job["updated_at"]) < now() - timedelta(minutes=10):
            raise WorkflowConflict("Node preflight has expired; test again", {})
        plan = {"id": secrets.token_hex(16), "revision": config["revision"], "configuration_digest": digest(config), "confirmation_nonce": secrets.token_urlsafe(24), "confirmation_phrase": "INSTALL " + config["spec"]["name"], "expires_at": stamp(now() + timedelta(minutes=10)), "summary": self.configuration()["spec"], "blockers": [], "warnings": job.get("result", {}).get("warnings", []), "configuration_recovery": job.get("result", {}).get("configuration_recovery", []), "created_by": actor, "test_job_id": job["id"]}
        plan["digest"] = digest(plan)
        _private_json(self.root / "plans" / (plan["id"] + ".json"), plan)
        return plan

    def apply(self, body, actor):
        self._production()
        identifier = body.get("preview_id")
        if not isinstance(identifier, str) or not IDENTIFIER.fullmatch(identifier):
            raise ValueError("A reviewed installation plan is required")
        with self.lock:
            plan = _read_json(self.root / "plans" / (identifier + ".json"))
            config = self.configuration(True)
            if not plan or parse_time(plan["expires_at"]) <= now() or plan["configuration_digest"] != digest(config) or any(body.get(key) != plan[key] for key in ("digest", "confirmation_nonce", "confirmation_phrase")):
                raise WorkflowConflict("Installation review expired, changed or was not confirmed exactly", {})
            if plan.get("job_id"):
                return self.job(plan["job_id"])
            result = self._queue("provision", {"configuration": config, "expected_recovery_snapshots": plan.get("configuration_recovery", [])}, actor)
            plan["job_id"] = result["id"]
            _private_json(self.root / "plans" / (identifier + ".json"), plan)
            return result

    def _provisioner(self):
        if self.provisioner_factory:
            return self.provisioner_factory(self)
        from .ha_setup import FileMaterialProvider, Provisioner, SSHRunner
        return Provisioner(SSHRunner(self.vault.get, self.root / "ssh"), FileMaterialProvider(self.root / "cluster-pki"))

    def run_pending_provisioning(self):
        if self._provision_thread and self._provision_thread.is_alive():
            return
        with self.lock:
            paths = sorted((self.root / "jobs").glob("*.json"))
            job = next((value for path in paths if (value := _read_json(path)).get("status") == "queued" and value.get("operation") in ("preflight", "provision")), None)
            if not job:
                return
            if job["private"]["configuration"] != self.configuration(True):
                job.update(status="blocked", phase="stale_configuration", error="Configuration changed before execution; test and review again", updated_at=stamp())
                _private_json(self._job_path(job["id"]), job)
                return
            job.update(status="running", phase="preflight", updated_at=stamp())
            _private_json(self._job_path(job["id"]), job)
        self._provision_thread = threading.Thread(target=self._execute_provisioning, args=(job,), daemon=True)
        self._provision_thread.start()

    def run_pending_appliance(self):
        if self._appliance_thread and self._appliance_thread.is_alive():
            return
        with self.lock:
            job = next((value for path in sorted((self.root / "jobs").glob("*.json")) if (value := _read_json(path)).get("operation") == "appliance" and value.get("status") == "queued"), None)
            if not job:
                return
            self.runtime_job_update(job["id"], "running", {"phase": "connecting_node_manager"})
        def execute():
            from .appliance import execute_job
            try:
                execute_job(self, job)
            except Exception:
                self.runtime_job_update(job["id"], "failed", {"phase": "node_manager", "error": "The node operation could not be verified. Current service and storage state must be refreshed; no success was assumed."})
        self._appliance_thread = threading.Thread(target=execute, daemon=True)
        self._appliance_thread.start()

    def _execute_provisioning(self, job):
        try:
            provisioner = self._provisioner()
            spec = job["private"]["configuration"]["spec"]
            def progress(value):
                self.runtime_job_update(job["id"], "running", {"phase": value.get("phase", "provisioning"), "result": value})
            result = provisioner.preview(spec) if job["operation"] == "preflight" else provisioner.apply(spec, progress=progress, expected_recovery_snapshots=job["private"].get("expected_recovery_snapshots", []))
            if result.get("status") not in ("ready", "preview") or result.get("blockers"):
                self.runtime_job_update(job["id"], "blocked", {"phase": "blocked", "result": result})
                return
            if job["operation"] == "provision":
                private = provisioner.private_connection_fields(spec)
                reference = self.vault.put(json.dumps(private))
                with self.lock:
                    current = self._job(job["id"])
                    current["private"]["connection_ref"] = reference
                    _private_json(self._job_path(job["id"]), current)
            self.runtime_job_update(job["id"], "ready", {"phase": "verified", "result": result})
        except Exception:
            self.runtime_job_update(job["id"], "error", {"phase": "failed", "error": "Dedicated-node operation failed. No local storage switch was made; inspect node prerequisites and retry a reviewed plan."})

    def activate(self, body, actor):
        self._production()
        if body.get("confirm") is not True:
            raise ValueError("Explicit storage migration and restart confirmation is required")
        with self.lock:
            source = self._job(body.get("provision_job_id"))
            if source["operation"] != "provision" or source["status"] != "ready" or source["private"]["configuration"] != self.configuration(True):
                raise WorkflowConflict("The current cluster must be provisioned and verified before activation", {})
            if source["private"].get("activation_job_id"):
                return self.job(source["private"]["activation_job_id"])
            if self.active_profile() or self.app and self.app.store.ha:
                raise ValueError("This controller already uses shared storage; replacing its active deployment requires a separate reviewed maintenance workflow")
            config = source["private"]["configuration"]
            connection = json.loads(self.vault.get(source["private"]["connection_ref"]))
            profile = self._runtime_profile(connection, config)
            backup_id = None
            if self.app:
                from .maintenance import backup_create
                backup_id = backup_create(self.app.store, actor, reason="before_ha_activation")["id"]
            result = self._queue("activate", {"profile_ref": self.vault.put(json.dumps(profile)), "configuration_digest": digest(config), "backup_id": backup_id}, actor)
            source["private"]["activation_job_id"] = result["id"]
            _private_json(self._job_path(source["id"]), source)
            return result

    def _runtime_profile(self, connection, configuration):
        from psycopg.conninfo import make_conninfo
        ca_file = self.root / "database-cas" / (hashlib.sha256(connection["ca"].encode()).hexdigest() + ".pem")
        self._private_text(ca_file, connection["ca"])
        parameters = {namespace: {**connection[namespace], "sslrootcert": str(ca_file)} for namespace in ("metadata", "traffic")}
        spec = configuration["spec"]
        result = {"metadata_dsn": make_conninfo(**parameters["metadata"]), "traffic_dsn": make_conninfo(**parameters["traffic"]), "deployment_id": spec["cluster_id"], "epoch": 1, "active_revision": configuration["revision"], "controller_origin": spec["controller_origin"], "mode": spec["mode"], "spec": spec}
        if self.app:
            result.update(controller_id=self.app.controller_id, site=self.app.site)
        return result

    @staticmethod
    def _private_text(path, value):
        path = Path(path)
        if path.is_symlink():
            raise ValueError("Private configuration must not be a symlink")
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as output:
            output.write(value)
            output.flush()
            os.fsync(output.fileno())
        path.chmod(0o600)

    def claim_runtime_job(self):
        with self.lock:
            from .application_port import _state
            pending = (_state(self).get("pending") or {}).get("job_id")
            paths = [self._job_path(pending)] if pending else sorted((self.root / "jobs").glob("*.json"))
            for path in paths:
                value = _read_json(path)
                if value.get("operation") in ("activate", "join", "certificate", "application-port") and value.get("status") == "queued":
                    if value["private"].get("configuration_digest") and value["private"]["configuration_digest"] != digest(self.configuration(True)):
                        value.update(status="blocked", phase="stale_configuration", error="Configuration changed before activation; review again", updated_at=stamp())
                        _private_json(path, value)
                        continue
                    value.update(status="running", phase="draining", updated_at=stamp())
                    _private_json(path, value)
                    if value["operation"] == "application-port":
                        return {"id": value["id"], "operation": value["operation"], "private": value["private"]}
                    if value["operation"] == "certificate":
                        return {"id": value["id"], "operation": value["operation"], "private": value["private"], "material": json.loads(self.vault.get(value["private"]["material_ref"]))}
                    return {"id": value["id"], "operation": value["operation"], "profile": json.loads(self.vault.get(value["private"]["profile_ref"]))}
        return None

    def recover_runtime_jobs(self):
        """Called only by the supervisor holding its exclusive process lock."""
        with self.lock:
            for path in (self.root / "jobs").glob("*.json"):
                value = _read_json(path)
                if value.get("operation") in ("activate", "join", "certificate", "application-port") and value.get("status") in ("running", "stopping", "verified", "draining"):
                    value.update(status="queued", phase="recovering", updated_at=stamp())
                    _private_json(path, value)
                elif value.get("operation") in ("preflight", "provision") and value.get("status") == "running":
                    value.update(status="error", phase="interrupted", error="Management worker restarted; inspect node state and run a fresh test/review before resuming", updated_at=stamp())
                    _private_json(path, value)
                elif value.get("operation") == "appliance" and value.get("status") == "running":
                    value.update(status="queued", phase="recovering_node_operation", updated_at=stamp())
                    _private_json(path, value)

    def runtime_job_update(self, identifier, status, details):
        with self.lock:
            value = self._job(identifier)
            value.update(status=status, updated_at=stamp())
            for key in ("phase", "result", "error"):
                if key in details:
                    value[key] = details[key]
            _private_json(self._job_path(identifier), value)

    def active_profile(self):
        value = _read_json(self.root / "active.json")
        return json.loads(self.vault.get(value["profile_ref"])) if value else None

    def commit_active_profile(self, profile):
        _private_json(self.root / "active.json", {"profile_ref": self.vault.put(json.dumps(profile)), "active_revision": profile["active_revision"], "deployment_id": profile["deployment_id"], "committed_at": stamp()})
        if profile.get("joined") and profile.get("spec"):
            _private_json(self.root / "configuration.json", {"revision": profile["active_revision"], "spec": profile["spec"], "updated_at": stamp(), "updated_by": "cluster-join"})

    def create_join_token(self, body, actor):
        self._production()
        profile = self.active_profile()
        if not profile or not self.app or not self.app.store.ha or not self.app.signer:
            raise ValueError("Activate the managed shared database cluster before issuing controller join codes")
        node_id, site, node_ip = self._join_identity(body)
        if node_id == self.app.controller_id or any(node["id"] == node_id for node in self.app.cluster()["nodes"]):
            raise ValueError("This controller identity already exists; fence and retire an old node before using a new join identity")
        token_id, secret = secrets.token_hex(16), secrets.token_urlsafe(48)
        record = {"id": "platform_join:" + token_id, "node_id": node_id, "site": site, "node_ip": node_ip,
                  "deployment_id": profile["deployment_id"], "secret_hash": hashlib.sha256(secret.encode()).hexdigest(),
                  "created_at": stamp(), "created_by": actor, "expires_at": stamp(now() + timedelta(minutes=30))}
        with self.app.store.lock, self.app.store.meta() as db:
            self.app.store._put(db, "maintenance_settings", record)
            self.app.store.audit("platform.join_code_created", actor, {"node_id": node_id, "site": site, "node_ip": node_ip}, db)
        ca = self.app.signer.ca.read_text()
        # The web certificate may use an enterprise CA separate from endpoint
        # issuance. The authorized one-time code also pins that exact public
        # certificate chain; the peer still enforces TLS hostname validation.
        certificate = getattr(self.app, "controller_certificate", None)
        if certificate:
            ca += "\n" + certificate.read_text()
        public = {"version": 1, "id": token_id, "secret": secret, "ca": ca, "deployment_id": profile["deployment_id"],
                  "node_id": node_id, "site": site, "node_ip": node_ip, "peer_url": profile["controller_origin"], "expires_at": record["expires_at"]}
        code = "PRTHAKJOIN1." + base64.urlsafe_b64encode(json.dumps(public).encode()).decode()
        return {"join_code": code, "peer_url": public["peer_url"], "node_id": node_id, "site": site, "node_ip": node_ip, "expires_at": record["expires_at"]}

    @staticmethod
    def _join_identity(body):
        node_id, site = body.get("node_id"), body.get("site")
        if not isinstance(node_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}", node_id) or not isinstance(site, str) or not site.strip() or len(site) > 100:
            raise ValueError("Provide a unique controller node ID and its DC/site")
        try:
            address = ipaddress.ip_address(body.get("node_ip", ""))
            if address.is_loopback or address.is_multicast or address.is_unspecified or address.is_link_local:
                raise ValueError()
        except ValueError:
            raise ValueError("Provide this new controller's unicast management IP") from None
        return node_id, site.strip(), str(address)

    @staticmethod
    def _join_code(value):
        if not isinstance(value, str) or not value.startswith("PRTHAKJOIN1.") or len(value) > 65536:
            raise ValueError("Provide the one-time join code from the existing cluster's Super Admin")
        try:
            code = json.loads(base64.urlsafe_b64decode(value[12:].encode()))
            if not isinstance(code, dict) or code["version"] != 1 or not isinstance(code["id"], str) or not IDENTIFIER.fullmatch(code["id"]) or not isinstance(code["secret"], str) or len(code["secret"]) < 43 or parse_time(code["expires_at"]) <= now():
                raise ValueError()
            PlatformManager._join_identity(code)
            if not isinstance(code["ca"], str) or len(code["ca"]) > 32768:
                raise ValueError()
            return code
        except (ValueError, KeyError, TypeError, AttributeError):
            raise ValueError("Join code is invalid or expired") from None

    def _join_source_preflight(self):
        """Reject a populated controller before consuming its one-time peer code.

        The stopped-source runtime repeats this check while holding the exclusive
        storage fence; this early check makes the GUI review useful to operators.
        """
        if not self.app:
            return
        from .platform_runtime import META_TABLES, TRAFFIC_TABLES
        setup_only = {"audit", "auth_users", "auth_sessions", "auth_states", "maintenance_backups", "maintenance_plans", "maintenance_settings"}
        store = self.app.store
        with store.lock, store.meta() as db:
            existing = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
            if any(db.execute('SELECT COUNT(*) FROM "' + table + '"').fetchone()[0] for table in META_TABLES if table in existing and table not in setup_only):
                raise ValueError("Join requires a new controller with no local servers, policies or traffic; existing controller data is never merged")
        with store.lock, store.traffic() as db:
            existing = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
            if any(db.execute('SELECT COUNT(*) FROM "' + table + '"').fetchone()[0] for table in TRAFFIC_TABLES if table in existing):
                raise ValueError("Join requires a new controller with no local traffic history")

    def join_preview(self, body, actor):
        self._production()
        if self.active_profile() or self.app and self.app.store.ha:
            raise ValueError("A controller already using shared storage cannot be silently rejoined or replaced")
        self._join_source_preflight()
        code = self._join_code(body.get("join_code"))
        node_id, site, node_ip = self._join_identity(body)
        if (node_id, site, node_ip) != (code["node_id"], code["site"], code["node_ip"]):
            raise ValueError("Join code is bound to another controller identity, site or IP")
        if not isinstance(body.get("peer_url", ""), str):
            raise ValueError("Provide the existing controller's IP or HTTPS URL")
        peer = body.get("peer_url", "").strip()
        if peer and not peer.startswith("https://"):
            try:
                address = ipaddress.ip_address(peer)
            except ValueError:
                raise ValueError("Use an IP address or a complete https:// controller origin, including its port") from None
            peer = "https://" + ("[" + str(address) + "]" if address.version == 6 else str(address)) + ":8787"
        peer = peer or code["peer_url"]
        remote = self._peer_request(peer, code["ca"], {"action": "inspect", "token_id": code["id"], "secret": code["secret"], "node_id": node_id, "site": site, "node_ip": node_ip})
        if not isinstance(remote, dict) or any(remote.get(key) != code[key] for key in ("deployment_id", "node_id", "site")):
            raise ValueError("Existing controller returned a different deployment or node authorization")
        profile = self.active_profile()
        if profile and profile["deployment_id"] != code["deployment_id"]:
            raise ValueError("This controller already belongs to another deployment")
        plan = {"id": secrets.token_hex(16), "operation": "join", "peer_url": peer, "node_id": node_id, "site": site, "node_ip": node_ip,
                "deployment_id": code["deployment_id"], "confirmation_nonce": secrets.token_urlsafe(24), "confirmation_phrase": "JOIN " + node_id,
                "expires_at": stamp(min(parse_time(code["expires_at"]), now() + timedelta(minutes=10))),
                "summary": {"peer_url": peer, "node_id": node_id, "site": site, "node_ip": node_ip, "deployment_id": code["deployment_id"], "local_snapshot_preserved": True},
                "code_ref": self.vault.put(json.dumps(code)), "created_by": actor}
        plan["digest"] = digest({key: value for key, value in plan.items() if key != "code_ref"})
        _private_json(self.root / "join-plans" / (plan["id"] + ".json"), plan)
        return {key: value for key, value in plan.items() if key != "code_ref"}

    def join_apply(self, body, actor):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization, hashes
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        self._production()
        identifier = body.get("preview_id", "")
        if not IDENTIFIER.fullmatch(identifier):
            raise ValueError("Review the new controller join before applying")
        with self.lock:
            plan = _read_json(self.root / "join-plans" / (identifier + ".json"))
            if not plan or parse_time(plan["expires_at"]) <= now() or any(body.get(key) != plan[key] for key in ("digest", "confirmation_nonce", "confirmation_phrase")):
                raise WorkflowConflict("Join review changed, expired or was not confirmed exactly", {})
            if plan.get("job_id"):
                return self.job(plan["job_id"])
            if self.active_profile() or self.app and self.app.store.ha:
                raise ValueError("An active controller cannot replace its identity or TLS files through the new-node join flow")
            self._join_source_preflight()
            code = json.loads(self.vault.get(plan["code_ref"]))
            if plan.get("transport_key_ref"):
                transport = serialization.load_pem_private_key(self.vault.get(plan["transport_key_ref"]).encode(), password=None)
                server_key = serialization.load_pem_private_key(self.vault.get(plan["server_key_ref"]).encode(), password=None)
            else:
                transport = rsa.generate_private_key(public_exponent=65537, key_size=3072)
                server_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
                for name, key in (("transport_key_ref", transport), ("server_key_ref", server_key)):
                    plan[name] = self.vault.put(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
                _private_json(self.root / "join-plans" / (identifier + ".json"), plan)
            public = transport.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
            csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, plan["node_id"])] )).sign(server_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()
            sealed = self._peer_request(plan["peer_url"], code["ca"], {"action": "enroll", "token_id": code["id"], "secret": code["secret"], "node_id": plan["node_id"], "site": plan["site"], "node_ip": plan["node_ip"], "transport_public_key": public, "server_csr": csr})
            payload = self._unseal(sealed, transport, plan["node_id"])
            profile = payload["profile"]
            if profile["deployment_id"] != code["deployment_id"]:
                raise ValueError("Peer returned another deployment identity")
            material_dir = self.root / "controller-pki" / identifier
            files = {"cert": payload["controller_certificate"], "ca": payload["endpoint_ca"], "ca_key": payload["endpoint_ca_key"],
                     "key": server_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()}
            tls = {}
            for key, value in files.items():
                path = material_dir / (key + ".pem")
                self._private_text(path, value)
                tls[key] = str(path)
            database_ca = self.root / "database-cas" / (hashlib.sha256(payload["database_ca"].encode()).hexdigest() + ".pem")
            self._private_text(database_ca, payload["database_ca"])
            from psycopg.conninfo import conninfo_to_dict, make_conninfo
            for namespace in ("metadata", "traffic"):
                parameters = conninfo_to_dict(profile[namespace + "_dsn"])
                parameters["sslrootcert"] = str(database_ca)
                profile[namespace + "_dsn"] = make_conninfo(**parameters)
            spec = profile["spec"]
            for node in spec["nodes"]:
                old_ref = node["ssh"]["private_key_ref"]
                node["ssh"]["private_key_ref"] = self.vault.put(payload["ssh_credentials"][old_ref])
            if payload.get("cluster_material"):
                _private_json(self.root / "cluster-pki" / "material.json", payload["cluster_material"])
            profile.update(controller_tls=tls, controller_id=plan["node_id"], site=plan["site"], controller_server_name=plan["node_ip"], joined=True, join_preserve_local_snapshot=True)
            profile.setdefault("controller_env", {})["SEG_MANAGEMENT_PROBE_SOURCE_IP"] = plan["node_ip"]
            result = self._queue("join", {"profile_ref": self.vault.put(json.dumps(profile))}, actor)
            plan["job_id"] = result["id"]
            _private_json(self.root / "join-plans" / (identifier + ".json"), plan)
            return result

    @staticmethod
    def _peer_request(peer, ca, body):
        class NoRedirect(HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None
        parsed = urlsplit(peer)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise ValueError("Existing node must be an HTTPS origin with no credentials or path")
        try:
            address = ipaddress.ip_address(parsed.hostname)
            if address.is_link_local or address.is_multicast or address.is_unspecified:
                raise ValueError("Invalid peer node address")
        except ValueError:
            if re.fullmatch(r"[0-9.:]+", parsed.hostname):
                raise ValueError("Invalid peer node address") from None
        context = ssl.create_default_context(cadata=ca)
        context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        request = Request(peer.rstrip("/") + "/api/v1/platform/cluster/enroll", data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
        try:
            with build_opener(NoRedirect(), HTTPSHandler(context=context)).open(request, timeout=15) as response:
                raw = response.read(2097153)
                if len(raw) > 2097152:
                    raise ValueError("Peer response exceeds the join limit")
                return json.loads(raw)
        except Exception:
            raise ValueError("Existing node join validation failed; verify its IP/HTTPS certificate, one-time code and connectivity") from None

    def enroll_node(self, body):
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization, hashes
        from cryptography.hazmat.primitives.asymmetric import rsa, padding
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.x509.oid import NameOID
        self._production()
        identifier = body.get("token_id", "")
        if not IDENTIFIER.fullmatch(identifier):
            raise PermissionError("Invalid join code")
        with self.app.store.lock, self.app.store.meta() as db:
            from .provider_lifecycle import assert_join_current
            assert_join_current(self.app, db)
            record = self.app.store._get(db, "maintenance_settings", "platform_join:" + identifier)
            secret = body.get("secret", "")
            if not record or not isinstance(secret, str) or not hmac.compare_digest(record["secret_hash"], hashlib.sha256(secret.encode()).hexdigest()) or parse_time(record["expires_at"]) <= now() or any(body.get(key) != record[key] for key in ("node_id", "site", "node_ip")):
                raise PermissionError("Join code expired or does not authorize this controller")
            profile = self.active_profile()
            if not profile or profile["deployment_id"] != record["deployment_id"]:
                raise PermissionError("Existing deployment changed; issue a new join code")
            if body.get("action") == "inspect":
                if record.get("consumed"):
                    raise PermissionError("Join code has already been consumed")
                return {"deployment_id": record["deployment_id"], "node_id": record["node_id"], "site": record["site"], "expires_at": record["expires_at"]}
            request_digest = digest({key: body.get(key) for key in ("node_id", "site", "node_ip", "transport_public_key", "server_csr")})
            if body.get("action") != "enroll":
                raise PermissionError("Invalid controller enrollment action")
            if record.get("consumed"):
                if record.get("request_digest") == request_digest and record.get("sealed_response"):
                    return record["sealed_response"]
                raise PermissionError("Join code has already been consumed by another node key")
            try:
                public = serialization.load_pem_public_key(body.get("transport_public_key", "").encode())
                csr = x509.load_pem_x509_csr(body.get("server_csr", "").encode())
                if not isinstance(public, rsa.RSAPublicKey) or public.key_size < 3072 or not csr.is_signature_valid or csr.public_key().key_size < 2048:
                    raise ValueError()
            except Exception:
                raise ValueError("A signed node CSR and strong transport public key are required") from None
            ca = x509.load_pem_x509_certificate(self.app.signer.ca.read_bytes())
            ca_key = serialization.load_pem_private_key(self.app.signer.ca_key.read_bytes(), password=None)
            host = urlsplit(profile["controller_origin"]).hostname
            try:
                san_host = x509.IPAddress(ipaddress.ip_address(host))
            except ValueError:
                san_host = x509.DNSName(host)
            server_public_key = csr.public_key()
            certificate = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, record["node_id"])]))
                .issuer_name(ca.subject).public_key(server_public_key).serial_number(x509.random_serial_number())
                .not_valid_before(now() - timedelta(minutes=2)).not_valid_after(now() + timedelta(days=90))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                    key_encipherment=isinstance(server_public_key, rsa.RSAPublicKey), data_encipherment=False,
                    key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=None, decipher_only=None), critical=True)
                .add_extension(x509.SubjectAlternativeName([san_host, x509.IPAddress(ipaddress.ip_address(record["node_ip"])), x509.DNSName(record["node_id"])]), critical=False)
                .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(server_public_key), critical=False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.public_key()), critical=False)
                .sign(ca_key, hashes.SHA256()))
            env_names = ("SEG_ENTRA_TENANT_ID", "SEG_ENTRA_CLIENT_ID", "SEG_ENTRA_REDIRECT_URI", "SEG_MANAGEMENT_PROBE_TARGET_CIDRS")
            private_profile = copy.deepcopy(profile)
            private_profile["controller_env"] = {key: os.environ[key] for key in env_names if os.environ.get(key)}
            config = getattr(self.app.auth, "config", None)
            if config and getattr(config, "client_secret", None):
                private_profile["controller_env"].update(SEG_ENTRA_TENANT_ID=config.tenant_id,
                    SEG_ENTRA_CLIENT_ID=config.client_id, SEG_ENTRA_REDIRECT_URI=config.redirect_uri)
                private_profile["controller_env"]["SEG_ENTRA_CLIENT_SECRET"] = config.client_secret
                private_profile["controller_env"]["SEG_ENTRA_CLIENT_SECRET_FILE"] = ""
                from .provider_lifecycle import AUTHORITY
                authority = self.app.store._get(db, "maintenance_settings", AUTHORITY)
                if authority:
                    private_profile["controller_env"]["PRTHAK_PROVIDER_EPOCH"] = authority["epoch"]
            private_profile["controller_env"]["SEG_BOOTSTRAP_SUPER_ADMIN_OID"] = ""
            if not self.app.auth.enabled:
                for role, value in self.app.tokens.items():
                    if value:
                        private_profile["controller_env"]["SEG_" + role.upper() + "_TOKEN"] = value
            from psycopg.conninfo import conninfo_to_dict
            ca_path = conninfo_to_dict(profile["metadata_dsn"])["sslrootcert"]
            payload = {"profile": private_profile, "controller_certificate": certificate.public_bytes(serialization.Encoding.PEM).decode(), "endpoint_ca": self.app.signer.ca.read_text(), "endpoint_ca_key": self.app.signer.ca_key.read_text(), "database_ca": Path(ca_path).read_text(), "ssh_credentials": {node["ssh"]["private_key_ref"]: self.vault.get(node["ssh"]["private_key_ref"]) for node in profile["spec"]["nodes"]}, "cluster_material": _read_json(self.root / "cluster-pki" / "material.json")}
            key, nonce = secrets.token_bytes(32), secrets.token_bytes(12)
            raw = json.dumps(payload).encode()
            result = {"encrypted_key": base64.b64encode(public.encrypt(key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))).decode(), "nonce": base64.b64encode(nonce).decode(), "ciphertext": base64.b64encode(AESGCM(key).encrypt(nonce, raw, record["node_id"].encode())).decode()}
            record.update(consumed=True, consumed_at=stamp(), request_digest=request_digest, sealed_response=result)
            self.app.store._put(db, "maintenance_settings", record)
            self.app.store.audit("platform.node_enrolled", "join-code", {"node_id": record["node_id"], "node_ip": record["node_ip"], "site": record["site"]}, db)
            return result

    @staticmethod
    def _unseal(sealed, transport, node_id):
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        try:
            key = transport.decrypt(base64.b64decode(sealed["encrypted_key"], validate=True), padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            nonce = base64.b64decode(sealed["nonce"], validate=True)
            ciphertext = base64.b64decode(sealed["ciphertext"], validate=True)
            if len(key) != 32 or len(nonce) != 12 or len(ciphertext) > 2097152:
                raise ValueError()
            return json.loads(AESGCM(key).decrypt(nonce, ciphertext, node_id.encode()))
        except Exception:
            raise ValueError("Join response does not match this controller's encrypted identity") from None

    def status(self):
        from .ha_setup import CAPABILITIES
        active = self.active_profile()
        jobs = [self.public_job(_read_json(path)) for path in sorted((self.root / "jobs").glob("*.json"))]
        runtime = {"storage": self.app.store.storage_kind, "ha": self.app.store.ha, "demo": self.app.demo, "controller_id": self.app.controller_id, "site": self.app.site} if self.app else {}
        return {"runtime": runtime, "cluster": self.app.cluster() if self.app else {}, "configuration": self.configuration(), "active": {key: active[key] for key in ("deployment_id", "active_revision", "mode", "controller_origin") if key in active} if active else None, "jobs": jobs[-30:], "capabilities": {**CAPABILITIES, "backups": True, "demo_cleanup": bool(self.app and self.app.demo), "remote_provisioning": bool(self.app and not self.app.demo and self.app.signer), "supervised": os.environ.get("PRTHAK_SUPERVISED_CHILD") == "1", "database": "PostgreSQL16 + Patroni + three etcd voters", "rpo": "synchronous_strict"}, "backup_storage": {"scope": "controller_local", "shared_storage_required_for_cross_node_download": True}}


def read_active_profile(platform_dir):
    return PlatformManager(Path(platform_dir).parent).active_profile()
