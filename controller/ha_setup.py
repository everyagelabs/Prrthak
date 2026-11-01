"""Bounded, pinned-SSH provisioning of a dedicated three-voter database cluster.

This module never executes a caller-supplied command. The public specification
contains references, not private keys/passwords. A platform job runner owns user
authorization, durable job records and the activation of controller storage.
"""
from __future__ import annotations

import base64
import copy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import tempfile
import time
from urllib.parse import urlsplit
import uuid


SCHEMA_VERSION = 1
SUPPORTED_PLATFORM = "ubuntu24.04-amd64"
CAPABILITIES = {"supported_installer": SUPPORTED_PLATFORM, "database": "PostgreSQL 16", "coordinator": "Patroni (Ubuntu package)", "dcs": "etcd3 (Ubuntu package)", "voters": 3, "database_nodes": 2, "witness_nodes": 1, "required_watchdog": True, "replication": "synchronous_strict", "arm64_database_installer": False, "controller_and_endpoint_architectures_unchanged": True}
ACTIONS = frozenset(("inspect", "install", "configure", "start_etcd", "start_database", "status", "create_roles", "backup"))
HELPER = Path(__file__).resolve().parent.parent / "deploy" / "cluster" / "node_helper.py"
NAME = re.compile(r"[a-z][a-z0-9_-]{0,47}\Z")
REFERENCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")


class SetupBlocked(ValueError):
    """A public-safe precondition failure; contains no command/driver output."""


class NodeUnavailable(RuntimeError):
    """A public-safe transport or helper failure."""


def canonical_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _name(value, label):
    if not isinstance(value, str) or not NAME.fullmatch(value):
        raise SetupBlocked(label + " must use lowercase letters, numbers, hyphens or underscores")
    return value


def _ip(value):
    try:
        ip = ipaddress.ip_address(value)
        if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local or ip.version != 4 or str(ip) == "255.255.255.255":
            raise ValueError()
        return str(ip)
    except (ValueError, TypeError):
        raise SetupBlocked("Dedicated node addresses must be unicast IPv4 addresses") from None


def _host_key(value):
    if not isinstance(value, str) or len(value) > 16384:
        raise SetupBlocked("Provide the independently verified SSH public host key")
    fields = value.strip().split()
    if len(fields) != 2 or fields[0] not in ("ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa"):
        raise SetupBlocked("SSH pin must be a complete supported public host key, without a hostname or comment")
    try:
        raw = base64.b64decode(fields[1], validate=True)
        size = int.from_bytes(raw[:4], "big")
        if len(raw) < 24 or raw[4:4 + size].decode("ascii") != fields[0]:
            raise ValueError()
    except (ValueError, UnicodeError):
        raise SetupBlocked("Invalid SSH host-key encoding") from None
    return " ".join(fields)


def validate(spec):
    """Return a normalized non-secret specification; reject unsafe defaults."""
    if not isinstance(spec, dict):
        raise SetupBlocked("Cluster configuration must be an object")
    try:
        cluster_id = str(uuid.UUID(spec.get("cluster_id", "")))
    except (ValueError, TypeError, AttributeError):
        raise SetupBlocked("A stable cluster UUID is required") from None
    origin = spec.get("controller_origin", "")
    try:
        parsed = urlsplit(origin)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment or any(char.isspace() for char in origin):
            raise ValueError()
        port = parsed.port
    except (ValueError, TypeError, AttributeError):
        raise SetupBlocked("Use one stable HTTPS controller origin") from None
    host = "[" + parsed.hostname.lower() + "]" if ":" in parsed.hostname else parsed.hostname.lower()
    origin = "https://" + host + (":" + str(port) if port and port != 443 else "")
    mode = spec.get("mode", "dc_dr")
    if mode not in ("active_active", "dc_dr"):
        raise SetupBlocked("Controller topology must be active_active or dc_dr")
    if spec.get("rpo", "synchronous_strict") != "synchronous_strict":
        raise SetupBlocked("This installer supports strict synchronous replication only")
    nodes = spec.get("nodes")
    if not isinstance(nodes, list) or len(nodes) != 3:
        raise SetupBlocked("Provide exactly three dedicated etcd voters: two database nodes and one witness")
    result_nodes = []
    for node in nodes:
        if not isinstance(node, dict):
            raise SetupBlocked("Invalid cluster node")
        ssh = node.get("ssh", {})
        if not isinstance(ssh, dict):
            raise SetupBlocked("Provide pinned SSH settings for each node")
        user = ssh.get("user", "")
        port = ssh.get("port", 22)
        if not isinstance(user, str) or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user):
            raise SetupBlocked("Invalid SSH account")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise SetupBlocked("Invalid SSH port")
        key_ref = ssh.get("private_key_ref", "")
        if not isinstance(key_ref, str) or not REFERENCE.fullmatch(key_ref):
            raise SetupBlocked("Select a private SSH key from the private vault")
        role = node.get("role")
        if role not in ("database", "witness"):
            raise SetupBlocked("Node role must be database or witness")
        result_nodes.append({"id": _name(node.get("id"), "Node ID"), "ip": _ip(node.get("ip")),
            "site": _name(node.get("site"), "Site"), "role": role,
            "ssh": {"user": user, "port": port, "host_key": _host_key(ssh.get("host_key")), "private_key_ref": key_ref}})
    if len({node["id"] for node in result_nodes}) != 3 or len({node["ip"] for node in result_nodes}) != 3 or len({node["site"] for node in result_nodes}) != 3:
        raise SetupBlocked("Voters require distinct IDs, addresses and failure-domain sites")
    if sum(node["role"] == "database" for node in result_nodes) != 2:
        raise SetupBlocked("Use two database nodes and one quorum-only witness")
    database = spec.get("database", {})
    if not isinstance(database, dict):
        raise SetupBlocked("Invalid database settings")
    database = {key: _name(database.get(key, default), key) for key, default in (
        ("metadata_name", "prthak_metadata"), ("traffic_name", "prthak_traffic"),
        ("metadata_user", "prthak_metadata"), ("traffic_user", "prthak_traffic"))}
    if database["metadata_name"] == database["traffic_name"] or database["metadata_user"] == database["traffic_user"]:
        raise SetupBlocked("Metadata and traffic require distinct databases and roles")
    if any(value in ("postgres", "template0", "template1", "prthak_admin", "prthak_replication") for value in database.values()):
        raise SetupBlocked("Database names and application roles must not use reserved cluster identities")
    cidrs = spec.get("controller_cidrs", [])
    if not isinstance(cidrs, list) or not 1 <= len(cidrs) <= 32:
        raise SetupBlocked("Provide the controller source CIDRs allowed to reach PostgreSQL")
    try:
        networks = [ipaddress.ip_network(value, strict=True) for value in cidrs]
        if any(network.version != 4 or network.prefixlen < 8 or network.is_multicast or network.is_loopback or network.is_unspecified for network in networks):
            raise ValueError()
    except (ValueError, TypeError):
        raise SetupBlocked("Controller CIDRs must be bounded unicast IPv4 networks, no wider than /8") from None
    watchdog = spec.get("watchdog", {})
    if not isinstance(watchdog, dict) or watchdog.get("mode") != "required" or watchdog.get("device", "/dev/watchdog") not in ("/dev/watchdog", "/dev/watchdog0") or watchdog.get("approved") is not True:
        raise SetupBlocked("Explicitly approve a dedicated host watchdog in required mode; no automatic software-watchdog loading")
    return {"schema_version": SCHEMA_VERSION, "cluster_id": cluster_id, "name": _name(spec.get("name"), "Cluster name"),
        "controller_origin": origin, "mode": mode, "rpo": "synchronous_strict", "nodes": result_nodes,
        "database": database, "controller_cidrs": sorted({str(network) for network in networks}),
        "watchdog": {"mode": "required", "device": watchdog.get("device", "/dev/watchdog"), "approved": True}}


def topology(spec):
    return {"cluster_id": spec["cluster_id"], "name": spec["name"], "nodes": [
        {key: node[key] for key in ("id", "ip", "site", "role")} for node in sorted(spec["nodes"], key=lambda value: value["id"])],
        "database": spec["database"], "controller_cidrs": spec["controller_cidrs"], "rpo": spec["rpo"], "watchdog": spec["watchdog"]}


def ca_fingerprint(pem):
    import ssl
    try:
        der = ssl.PEM_cert_to_DER_cert(pem)
    except (ValueError, TypeError):
        raise SetupBlocked("Invalid cluster CA certificate") from None
    return hashlib.sha256(der).hexdigest()


def _private_file(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    handle, temporary = tempfile.mkstemp(prefix=".pending-", dir=path.parent)
    try:
        with os.fdopen(handle, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(data if isinstance(data, bytes) else data.encode())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class FileMaterialProvider:
    """Private local PKI/password vault, usable by the platform job worker.

    The directory is installation controlled, never supplied by an HTTP body.
    Only signed per-node keys travel to nodes; the CA signing key stays here.
    """
    def __init__(self, directory, command=subprocess.run):
        self.directory = Path(directory)
        self.command = command

    def _openssl(self, args):
        result = self.command(["openssl", *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=30)
        if result.returncode:
            raise SetupBlocked("Cluster certificate generation failed; check the local OpenSSL installation")

    def __call__(self, specification):
        spec = validate(specification)
        directory = self.directory / spec["cluster_id"]
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if directory.is_symlink() or directory.stat().st_mode & 0o077:
            raise SetupBlocked("Cluster vault must be a private directory")
        lock = directory / "material.lock"
        import fcntl
        with lock.open("a+b") as stream:
            os.chmod(lock, 0o600)
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            saved = directory / "material.json"
            if saved.exists():
                info = saved.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
                    raise SetupBlocked("Stored cluster material must be a private regular file")
                value = json.loads(saved.read_text())
                if value.get("topology_digest") != canonical_digest(topology(spec)):
                    raise SetupBlocked("Cluster topology changed; use a reviewed membership operation")
                return value
            # Interrupted generation never changes an established material file.
            with tempfile.TemporaryDirectory(prefix="pki-", dir=directory) as temporary:
                work = Path(temporary)
                ca, ca_key = work / "ca.pem", work / "ca-key.pem"
                self._openssl(["req", "-x509", "-newkey", "rsa:3072", "-nodes", "-days", "3650", "-subj", "/CN=Prthak database " + spec["cluster_id"], "-keyout", str(ca_key), "-out", str(ca), "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"])
                result = {"topology_digest": canonical_digest(topology(spec)), "ca": ca.read_text(), "ca_key": ca_key.read_text(), "nodes": {},
                    "passwords": {name: secrets.token_urlsafe(48) for name in ("admin", "replication", "metadata", "traffic")}}
                for node in spec["nodes"]:
                    key, request, cert, ext = (work / (node["id"] + suffix) for suffix in ("-key.pem", ".csr", ".pem", ".ext"))
                    ext.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=IP:" + node["ip"] + ",IP:127.0.0.1,DNS:localhost\n")
                    self._openssl(["req", "-new", "-newkey", "rsa:3072", "-nodes", "-subj", "/CN=" + node["id"], "-keyout", str(key), "-out", str(request)])
                    self._openssl(["x509", "-req", "-in", str(request), "-CA", str(ca), "-CAkey", str(ca_key), "-set_serial", str(secrets.randbits(120) + 1), "-days", "825", "-extfile", str(ext), "-out", str(cert)])
                    result["nodes"][node["id"]] = {"certificate": cert.read_text(), "private_key": key.read_text()}
                result["ca_fingerprint"] = ca_fingerprint(result["ca"])
                _private_file(saved, json.dumps(result, sort_keys=True, separators=(",", ":")))
                return result


class SSHRunner:
    """Execute the repository's fixed helper through pinned OpenSSH.

    key_resolver(ref) returns an installation-controlled private regular keyfile.
    command is injectable only by trusted Python code, never by a request.
    """
    def __init__(self, key_resolver, directory, command=subprocess.run, timeout=1800):
        self.key_resolver = key_resolver
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.directory.is_symlink() or self.directory.stat().st_mode & 0o077:
            raise SetupBlocked("Pinned SSH working directory must be private")
        self.command, self.timeout = command, timeout

    def run(self, node, action, payload):
        if action not in ACTIONS:
            raise SetupBlocked("Unsupported database-node operation")
        try:
            resolved = self.key_resolver(node["ssh"]["private_key_ref"])
        except (KeyError, OSError):
            raise SetupBlocked("Private SSH key reference is unavailable") from None
        if isinstance(resolved, bytes) or isinstance(resolved, str) and resolved.startswith("-----BEGIN "):
            data = resolved.encode() if isinstance(resolved, str) else resolved
            if len(data) > 65536 or not data.startswith(b"-----BEGIN "):
                raise SetupBlocked("Vault returned an invalid private SSH key")
            descriptor, name = tempfile.mkstemp(prefix=".ssh-key-", dir=self.directory)
            os.close(descriptor)
            key = Path(name)
            try:
                _private_file(key, data)
                return self._run(node, action, payload, key)
            finally:
                key.unlink(missing_ok=True)
        if not isinstance(resolved, (str, Path)):
            raise SetupBlocked("Vault returned an invalid private SSH key reference")
        return self._run(node, action, payload, Path(resolved))

    def _run(self, node, action, payload, key):
        info = key.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > 65536 or info.st_uid != os.geteuid():
            raise SetupBlocked("SSH key must be an owned private regular file (mode 0600 or stricter)")
        pin = _host_key(node["ssh"]["host_key"])
        alias = "prthak-" + node["id"]
        known = self.directory / (canonical_digest({"alias": alias, "pin": pin}) + ".known-hosts")
        _private_file(known, alias + " " + pin + "\n")
        arguments = ["ssh", "-T", "-F", "/dev/null", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no", "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + str(known), "-o", "GlobalKnownHostsFile=/dev/null", "-o", "HostKeyAlias=" + alias, "-o", "ForwardAgent=no", "-o", "ForwardX11=no", "-o", "ClearAllForwardings=yes", "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=3", "-i", str(key), "-p", str(node["ssh"]["port"]), node["ssh"]["user"] + "@" + _ip(node["ip"])]
        arguments.append("/usr/bin/python3 -" if node["ssh"]["user"] == "root" else "sudo -n /usr/bin/python3 -")
        helper = HELPER.read_text()
        request = json.dumps({"action": action, **payload}, sort_keys=True, separators=(",", ":")).encode()
        script = helper + "\nif __name__ == '__main__':\n    import base64\n    main(json.loads(base64.b64decode(" + repr(base64.b64encode(request).decode()) + ")))\n"
        try:
            result = self.command(arguments, input=script.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=self.timeout)
        except (OSError, subprocess.TimeoutExpired):
            raise NodeUnavailable("Pinned SSH node operation timed out or could not start") from None
        if len(result.stdout) > 1024 * 1024 or result.returncode:
            # SSH stderr can contain usernames, paths or a remote exception. Do
            # not pass it to an API response or durable public job log.
            raise NodeUnavailable("Pinned SSH connection or fixed node helper failed")
        try:
            response = json.loads(result.stdout)
        except (ValueError, UnicodeError):
            raise NodeUnavailable("Node helper did not return a valid bounded response") from None
        if not isinstance(response, dict) or response.get("node_id") != node["id"]:
            raise NodeUnavailable("Node helper identity mismatch")
        return response


@dataclass(frozen=True)
class JoinAuthorization:
    """Trusted in-process result of consuming a one-time Super Admin join code.

    Never construct this directly from JSON. The platform API validates and
    consumes its code, then creates this object using the pinned stored manifest.
    """
    cluster_id: str
    node_id: str
    existing_node_ip: str
    ca_fingerprint: str
    topology_digest: str
    expires_at: str


class Provisioner:
    def __init__(self, runner, material_provider, wait_seconds=120, sleep=time.sleep):
        self.runner, self.material_provider = runner, material_provider
        self.wait_seconds, self.sleep = wait_seconds, sleep

    def _await(self, callback):
        value = callback()
        for _ in range(max(0, int(self.wait_seconds // 2))):
            if value.get("status") == "ready":
                break
            self.sleep(2)
            value = callback()
        return value

    def _request(self, spec, node, action, material=None, recovery_snapshot=None):
        payload = {"schema_version": SCHEMA_VERSION, "spec": spec, "node_id": node["id"], "topology_digest": canonical_digest(topology(spec))}
        if material is not None:
            payload["material"] = {"ca": material["ca"], "ca_fingerprint": material["ca_fingerprint"],
                **material["nodes"][node["id"]], "passwords": material["passwords"] if node["role"] == "database" else {}}
        if recovery_snapshot is not None:
            payload["expected_recovery_snapshot"] = recovery_snapshot
        response = self.runner.run(node, action, payload)
        if response.get("cluster_id") != spec["cluster_id"] or response.get("topology_digest") != payload["topology_digest"]:
            raise NodeUnavailable("Node returned a different cluster identity or topology")
        return response

    def preview(self, specification):
        spec = validate(specification)
        nodes, blockers = [], []
        for node in spec["nodes"]:
            try:
                value = self._request(spec, node, "inspect")
            except (SetupBlocked, NodeUnavailable, OSError):
                value = {"node_id": node["id"], "status": "blocked", "blockers": ["Pinned SSH inspection unavailable"]}
            nodes.append(value)
            blockers.extend(node["id"] + ": " + str(item) for item in value.get("blockers", []))
        recoveries = [{"node_id": value["node_id"], **value["configuration_recovery"]} for value in nodes if value.get("configuration_recovery", {}).get("status") == "recoverable"]
        return {"status": "blocked" if blockers else "preview", "phase": "preflight", "cluster_id": spec["cluster_id"],
            "topology_digest": canonical_digest(topology(spec)), "nodes": nodes, "blockers": blockers, "capabilities": copy.deepcopy(CAPABILITIES),
            "configuration_recovery": recoveries,
            "warnings": ["Strict synchronous replication stops commits while the only synchronous standby is unavailable.", "Installation may reboot a failed database host through its approved watchdog.", "Controller activation and L4 ingress are separate jobs; this job does not migrate application data."]}

    def apply(self, specification, progress=None, expected_recovery_snapshots=None):
        spec = validate(specification)
        preview = self.preview(spec)
        if preview["blockers"]:
            return preview
        expected = {}
        if expected_recovery_snapshots is not None:
            if not isinstance(expected_recovery_snapshots, list):
                raise SetupBlocked("Reviewed configuration recovery snapshots must be a list")
            for entry in expected_recovery_snapshots:
                if not isinstance(entry, dict) or entry.get("node_id") not in {node["id"] for node in spec["nodes"]} or not isinstance(entry.get("snapshot_digest"), str) or not re.fullmatch(r"[0-9a-f]{64}", entry["snapshot_digest"]) or entry["node_id"] in expected:
                    raise SetupBlocked("Invalid reviewed configuration recovery snapshot")
                expected[entry["node_id"]] = entry["snapshot_digest"]
        actual = {entry["node_id"]: entry["snapshot_digest"] for entry in preview["configuration_recovery"]}
        if actual != expected:
            return {**preview, "status": "blocked", "blockers": ["Interrupted configuration snapshots changed or require a fresh explicit GUI review before recovery"]}
        return self._apply_nodes(spec, spec["nodes"], progress, expected)

    def _apply_nodes(self, spec, nodes, progress, recovery_snapshots=None):
        progress = progress or (lambda value: None)
        material = self.material_provider(spec)
        if material.get("topology_digest") != canonical_digest(topology(spec)) or material.get("ca_fingerprint") != ca_fingerprint(material.get("ca")):
            raise SetupBlocked("Private cluster material does not match the reviewed topology")
        result = {"status": "running", "phase": "install", "cluster_id": spec["cluster_id"], "topology_digest": canonical_digest(topology(spec)), "ca_fingerprint": material["ca_fingerprint"], "nodes": []}
        try:
            for phase in ("install", "configure", "start_etcd"):
                result["phase"] = phase
                for node in nodes:
                    response = self._request(spec, node, phase, material, recovery_snapshot=(recovery_snapshots or {}).get(node["id"]) if phase == "configure" else None)
                    if response.get("status") == "blocked":
                        return {**result, "status": "blocked", "node_id": node["id"], "blockers": response.get("blockers", ["Node precondition failed"])}
                    progress({**result, "node_id": node["id"], "node_status": response.get("status")})
            # Do not start PostgreSQL until the complete authenticated DCS is healthy.
            result["phase"] = "quorum"
            def quorum_status():
                nodes_status = [self._request(spec, node, "status", material) for node in spec["nodes"]]
                return {"status": "ready" if all(node.get("etcd_healthy") is True for node in nodes_status) else "waiting", "nodes": nodes_status}
            quorum = self._await(quorum_status)["nodes"]
            if not all(node.get("etcd_healthy") is True for node in quorum):
                return {**result, "status": "blocked", "blockers": ["All three authenticated etcd members must be healthy before database startup"], "nodes": quorum}
            for node in nodes:
                if node["role"] == "database":
                    result["phase"] = "start_database"
                    response = self._request(spec, node, "start_database", material)
                    if response.get("status") == "blocked":
                        return {**result, "status": "blocked", "blockers": response.get("blockers", ["Required watchdog unavailable"])}
                    progress({**result, "node_id": node["id"], "node_status": response.get("status")})
            # Both DB services start before waiting for strict-sync readiness.
            result["phase"] = "verify_replication"
            state = self._await(lambda: self.status(spec, require_roles=False))
            if state["status"] != "ready":
                return {**result, "status": "blocked", "blockers": ["Database cluster is installed but not yet a healthy primary plus streaming synchronous replica"], "nodes": state["nodes"]}
            primary = next(node for node in spec["nodes"] if next(item for item in state["nodes"] if item["node_id"] == node["id"]).get("database_role") == "primary")
            result["phase"] = "create_roles"
            response = self._request(spec, primary, "create_roles", material)
            if response.get("roles_ready") is not True:
                return {**result, "status": "error", "blockers": ["Application database role verification failed"]}
            result.update(self.status(spec))
            result["phase"] = "complete" if result["status"] == "ready" else "verify"
            progress(result)
            return result
        except (SetupBlocked, NodeUnavailable, OSError):
            return {**result, "status": "error", "blockers": ["Fixed provisioning operation failed; retained node journals identify the last completed phase. No data directories were deleted."]}

    def status(self, specification, require_roles=True):
        spec = validate(specification)
        values = []
        for node in spec["nodes"]:
            try:
                value = self._request(spec, node, "status")
            except (SetupBlocked, NodeUnavailable, OSError):
                value = {"node_id": node["id"], "status": "unavailable", "etcd_healthy": False}
            values.append(value)
        database = [value for value in values if next(node for node in spec["nodes"] if node["id"] == value["node_id"])["role"] == "database"]
        primaries = [value for value in database if value.get("database_role") == "primary" and value.get("database_healthy") is True and value.get("watchdog_ready") is True]
        replicas = [value for value in database if value.get("database_role") == "replica" and value.get("database_healthy") is True]
        ready = all(value.get("etcd_healthy") is True for value in values) and len(primaries) == 1 and len(replicas) == 1 and primaries[0].get("synchronous_replica") is True and (not require_roles or primaries[0].get("roles_ready") is True)
        return {"status": "ready" if ready else "degraded", "phase": "status", "cluster_id": spec["cluster_id"], "topology_digest": canonical_digest(topology(spec)), "nodes": values, "writer_node_id": primaries[0]["node_id"] if len(primaries) == 1 else None}

    def join_dr(self, specification, node_id, authorization, progress=None):
        spec = validate(specification)
        if not isinstance(authorization, JoinAuthorization):
            raise SetupBlocked("Consume a Super Admin one-time join code before connecting a DR node")
        try:
            expiry = datetime.fromisoformat(authorization.expires_at.replace("Z", "+00:00"))
            if expiry.tzinfo is None or expiry <= datetime.now(timezone.utc):
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            raise SetupBlocked("DR join authorization expired") from None
        selected = next((node for node in spec["nodes"] if node["id"] == node_id and node["role"] == "database"), None)
        existing = next((node for node in spec["nodes"] if node["ip"] == authorization.existing_node_ip and node["role"] == "database" and node["id"] != node_id), None)
        if not selected or not existing or authorization.cluster_id != spec["cluster_id"] or authorization.node_id != node_id or authorization.topology_digest != canonical_digest(topology(spec)):
            raise SetupBlocked("Join code does not authorize this existing cluster and predeclared DR node")
        material = self.material_provider(spec)
        if authorization.ca_fingerprint != material.get("ca_fingerprint"):
            raise SetupBlocked("Existing cluster CA pin does not match the join code")
        remote = self._request(spec, existing, "status")
        if remote.get("ca_fingerprint") != authorization.ca_fingerprint or remote.get("etcd_healthy") is not True:
            raise SetupBlocked("Existing node identity or authenticated quorum could not be verified")
        inspection = self._request(spec, selected, "inspect")
        if inspection.get("blockers"):
            return {"status": "blocked", "phase": "join_preflight", "cluster_id": spec["cluster_id"], "blockers": inspection["blockers"]}
        if inspection.get("configuration_recovery"):
            raise SetupBlocked("Resume this interrupted owned configuration through a reviewed installation plan before joining")
        # No member-add/remove or force-new-cluster operation is supported here.
        return self._apply_nodes(spec, [selected], progress)

    def private_connection_fields(self, specification):
        """For the trusted activation worker only. Never serialize this to a UI."""
        spec = validate(specification)
        material = self.material_provider(spec)
        hosts = [node["ip"] for node in spec["nodes"] if node["role"] == "database"]
        return {"metadata": {"host": ",".join(hosts), "port": 5432, "dbname": spec["database"]["metadata_name"], "user": spec["database"]["metadata_user"], "password": material["passwords"]["metadata"], "sslmode": "verify-full", "target_session_attrs": "read-write", "connect_timeout": 3},
            "traffic": {"host": ",".join(hosts), "port": 5432, "dbname": spec["database"]["traffic_name"], "user": spec["database"]["traffic_user"], "password": material["passwords"]["traffic"], "sslmode": "verify-full", "target_session_attrs": "read-write", "connect_timeout": 3}, "ca": material["ca"], "ca_fingerprint": material["ca_fingerprint"]}

    def backup(self, specification):
        spec = validate(specification)
        state = self.status(spec)
        if not state.get("writer_node_id"):
            return {"status": "blocked", "phase": "backup", "cluster_id": spec["cluster_id"], "blockers": ["A single authenticated fenced writable primary is required"]}
        node = next(node for node in spec["nodes"] if node["id"] == state["writer_node_id"])
        result = self._request(spec, node, "backup")
        return {**result, "phase": "backup", "writer_node_id": node["id"]}
