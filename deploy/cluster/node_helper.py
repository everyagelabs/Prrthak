"""Fixed root helper delivered over pinned SSH by controller.ha_setup.

No command, package URL, executable path, data path or SQL is accepted from a
request. Only the operations in ACTIONS are callable. JSON is valid YAML for
etcd/Patroni, avoiding a second configuration templating language.
"""
from __future__ import annotations

import base64
import datetime
import grp
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import socket
import ssl
import stat
import subprocess
import tempfile
import time
import uuid


ACTIONS = frozenset(("inspect", "install", "configure", "start_etcd", "start_database", "status", "create_roles", "backup"))
BASE = Path("/etc/prthak-cluster")
STATE = Path("/var/lib/prthak-cluster")
JOURNAL = STATE / "setup.json"
PACKAGE_POLICY = Path("/usr/sbin/policy-rc.d")
TEMPORARY_POLICY = b"#!/bin/sh\nexit 101\n"
NAME = re.compile(r"[a-z][a-z0-9_-]{0,47}\Z")
PACKAGES = ("etcd-server", "etcd-client", "postgresql-16", "patroni", "python3-etcd", "python3-psycopg2", "openssl", "iproute2")


class Blocked(Exception):
    pass


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def topology(spec):
    return {"cluster_id": spec["cluster_id"], "name": spec["name"], "nodes": [
        {key: node[key] for key in ("id", "ip", "site", "role")} for node in sorted(spec["nodes"], key=lambda value: value["id"])],
        "database": spec["database"], "controller_cidrs": spec["controller_cidrs"], "rpo": spec["rpo"], "watchdog": spec["watchdog"]}


def validate_request(value):
    if not isinstance(value, dict) or value.get("action") not in ACTIONS or value.get("schema_version") != 1:
        raise Blocked("Unsupported fixed helper operation")
    spec = value.get("spec")
    if not isinstance(spec, dict) or str(uuid.UUID(spec.get("cluster_id", ""))) != spec.get("cluster_id") or not NAME.fullmatch(spec.get("name", "")):
        raise Blocked("Invalid cluster identity")
    nodes = spec.get("nodes")
    if not isinstance(nodes, list) or len(nodes) != 3 or sum(node.get("role") == "database" for node in nodes) != 2:
        raise Blocked("Three voters and two database nodes are required")
    for node in nodes:
        ip = ipaddress.ip_address(node.get("ip", ""))
        if ip.version != 4 or ip.is_unspecified or ip.is_loopback or ip.is_link_local or ip.is_multicast or not NAME.fullmatch(node.get("id", "")) or not NAME.fullmatch(node.get("site", "")) or node.get("role") not in ("database", "witness"):
            raise Blocked("Invalid dedicated node")
    if any(len({node[key] for node in nodes}) != 3 for key in ("id", "ip", "site")):
        raise Blocked("Voters must have independent identities and failure domains")
    for key in ("metadata_name", "traffic_name", "metadata_user", "traffic_user"):
        if not NAME.fullmatch(spec.get("database", {}).get(key, "")):
            raise Blocked("Invalid fixed application database identity")
    cidrs = spec.get("controller_cidrs")
    if not isinstance(cidrs, list) or not 1 <= len(cidrs) <= 32:
        raise Blocked("Bounded controller source networks are required")
    for value_cidr in cidrs:
        net = ipaddress.ip_network(value_cidr, strict=True)
        if net.version != 4 or net.prefixlen < 8 or net.is_loopback or net.is_multicast or net.is_unspecified:
            raise Blocked("Unsafe controller network")
    if spec.get("rpo") != "synchronous_strict" or spec.get("watchdog", {}).get("mode") != "required" or spec["watchdog"].get("approved") is not True or spec["watchdog"].get("device") not in ("/dev/watchdog", "/dev/watchdog0"):
        raise Blocked("An approved required watchdog is mandatory")
    if digest(topology(spec)) != value.get("topology_digest"):
        raise Blocked("Reviewed topology digest mismatch")
    node = next((item for item in nodes if item["id"] == value.get("node_id")), None)
    if node is None:
        raise Blocked("Node identity is outside this cluster")
    return spec, node


def command(arguments, timeout=60, input=None, environment=None, okay=(0,), combine=False):
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", **(environment or {})}
    try:
        result = subprocess.run(arguments, input=input, stdout=subprocess.PIPE, stderr=subprocess.STDOUT if combine else subprocess.PIPE, env=env, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Blocked("A fixed node operation timed out or is unavailable") from None
    if result.returncode not in okay or len(result.stdout) > 2 * 1024 * 1024:
        raise Blocked("A fixed node operation failed; no cluster data was deleted")
    return result.stdout.decode("utf-8", "replace")


def atomic(path, data, mode=0o600, user=None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or any(parent.is_symlink() for parent in path.parents if str(parent) not in ("/", "/var")):
        raise Blocked("Refusing a symlink in a managed private path")
    descriptor, temporary = tempfile.mkstemp(prefix=".pending-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            if user:
                account = pwd.getpwnam(user)
                os.fchown(stream.fileno(), account.pw_uid, account.pw_gid)
            stream.write(data.encode() if isinstance(data, str) else data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        parent = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def mkdir(path, user=None, mode=0o700):
    path = Path(path)
    if path.is_symlink():
        raise Blocked("Refusing a symlink in a managed directory")
    path.mkdir(parents=True, exist_ok=True, mode=mode)
    os.chmod(path, mode)
    if user:
        account = pwd.getpwnam(user)
        os.chown(path, account.pw_uid, account.pw_gid)


def load_journal(spec, node):
    if not JOURNAL.exists():
        return None
    if JOURNAL.is_symlink() or not stat.S_ISREG(JOURNAL.stat().st_mode) or JOURNAL.stat().st_mode & 0o077 or JOURNAL.stat().st_uid != os.geteuid():
        raise Blocked("Managed setup journal is not a private regular file")
    saved = json.loads(JOURNAL.read_text())
    if saved.get("cluster_id") != spec["cluster_id"] or saved.get("node_id") != node["id"] or saved.get("topology_digest") != digest(topology(spec)):
        raise Blocked("Node belongs to a different cluster or topology; no overwrite is allowed")
    return saved


def checkpoint(spec, node, phase, **extra):
    saved = load_journal(spec, node) or {"cluster_id": spec["cluster_id"], "node_id": node["id"], "topology_digest": digest(topology(spec)), "schema_version": 1}
    saved.update({"phase": phase, "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(), **extra})
    mkdir(STATE, mode=0o711)
    atomic(JOURNAL, json.dumps(saved, sort_keys=True, separators=(",", ":")))
    return saved


def platform_check():
    try:
        fields = {}
        for line in Path("/etc/os-release").read_text().splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                fields[key] = value.strip('"')
        if fields.get("ID") != "ubuntu" or fields.get("VERSION_ID") != "24.04":
            raise Blocked("Managed installation supports dedicated Ubuntu 24.04 nodes only")
        if os.uname().machine != "x86_64":
            raise Blocked("Managed database installation requires Ubuntu 24.04 AMD64; packaged etcd ARM64 is not supported")
        if Path("/proc/1/comm").read_text().strip() != "systemd":
            raise Blocked("A genuine systemd host is required")
    except OSError:
        raise Blocked("Linux platform identity could not be verified") from None


def device_ready(spec, node):
    if node["role"] == "witness":
        return True
    path = Path(spec["watchdog"]["device"])
    try:
        info = path.stat()
        canonical = Path("/dev/watchdog0").stat()
        if not stat.S_ISCHR(info.st_mode) or not stat.S_ISCHR(canonical.st_mode) or info.st_rdev != canonical.st_rdev:
            return False
        # This adapter and its udev rule support watchdog0 only. Never open/arm
        # a device merely to inspect it or take over a different active watchdog.
        return os.access(path, os.R_OK | os.W_OK)
    except OSError:
        return False


def inspect(spec, node):
    blockers = []
    try:
        platform_check()
        saved = load_journal(spec, node)
    except Blocked as error:
        return {"status": "blocked", "blockers": [str(error)]}
    if not device_ready(spec, node):
        blockers.append("Approved watchdog character device is unavailable; no automatic softdog installation")
    if not saved and node["role"] == "database" and device_ready(spec, node):
        try:
            if Path("/sys/class/watchdog/watchdog0/state").read_text().strip() != "inactive":
                blockers.append("Watchdog is already active or owned by another host service")
        except OSError:
            blockers.append("Watchdog inactive state cannot be verified without arming the device")
    recovery = None
    if saved:
        if saved.get("package_policy_pending"):
            try:
                read_package_policy_recovery(spec, node)
            except Blocked as error:
                blockers.append(str(error))
        if saved.get("config_pending"):
            try:
                checked = read_configuration_recovery(spec, node)
                recovery = {"status": "recoverable", "snapshot_digest": digest(checked), "warning": "An interrupted owned configuration will restore this exact private snapshot before retry"}
            except Blocked as error:
                blockers.append(str(error))
        if saved.get("etcd_ever_started") and not (STATE / "etcd/member").exists():
            blockers.append("An initialized etcd member lost its data; reviewed quorum-backed member replacement is required")
        if saved.get("database_ever_started") and (STATE / "postgres").exists() and not any((STATE / "postgres").iterdir()):
            blockers.append("An initialized database lost its data; automatic reinitialization is refused")
    else:
        # Existing services/data are never adopted or stopped by this installer.
        for path in (Path("/var/lib/postgresql"), Path("/var/lib/etcd"), STATE):
            if path.exists() and any(path.iterdir()):
                blockers.append("Unmanaged database, DCS or setup data already exists")
                break
        if BASE.exists() and any(BASE.iterdir()):
            blockers.append("Unmanaged Prthak cluster configuration already exists")
        if any(Path("/etc/systemd/system/" + unit).exists() for unit in ("prthak-etcd.service", "prthak-patroni.service")):
            blockers.append("Unmanaged Prthak cluster service already exists")
        for port in (2379, 2380, 5432, 8008):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.settimeout(0.2)
                if probe.connect_ex((node["ip"], port)) == 0 or probe.connect_ex(("127.0.0.1", port)) == 0:
                    blockers.append("A required managed service port is already occupied")
                    break
    # Bind-check a local assigned address without altering network/firewall state.
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind((node["ip"], 0))
    except OSError:
        blockers.append("Configured node IP is not assigned to this host")
    result = {"status": "blocked" if blockers else "inspected", "blockers": blockers, "platform": "ubuntu24.04-amd64", "owned": bool(saved), "watchdog_device_present": device_ready(spec, node), "phase": saved.get("phase") if saved else "empty"}
    if recovery:
        result["configuration_recovery"] = recovery
    return result


def backup_config(path):
    path = Path(path)
    if not path.exists():
        return
    if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
        raise Blocked("Existing managed configuration is not a regular file")
    target = STATE / "config-backups" / hashlib.sha256(str(path).encode()).hexdigest()
    if not target.exists():
        atomic(target, path.read_bytes())


def apt_origin_check(packages):
    output = command(["apt-get", "--print-uris", "-y", "--no-install-recommends", "-o", "APT::Get::AllowUnauthenticated=false", "install", *packages], timeout=120)
    from urllib.parse import urlsplit
    for line in output.splitlines():
        if not line.startswith("'"):
            continue
        address = line.split("'", 2)[1]
        parsed = urlsplit(address)
        hostname = parsed.hostname or ""
        if parsed.scheme not in ("http", "https") or not (hostname in ("archive.ubuntu.com", "security.ubuntu.com", "ports.ubuntu.com") or hostname.endswith(".archive.ubuntu.com")):
            raise Blocked("Package download is outside the supported official Ubuntu repositories")
    # apt itself verifies signed indexes/packages. Never enable insecure repositories.


def read_package_policy_recovery(spec, node):
    path = STATE / "package-policy.json"
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.geteuid() or info.st_size > 262144:
            raise ValueError()
        backup = json.loads(path.read_text())
        saved = load_journal(spec, node)
        if backup.get("cluster_id") != spec["cluster_id"] or backup.get("node_id") != node["id"] or backup.get("topology_digest") != digest(topology(spec)) or not saved or saved.get("package_policy_snapshot") != digest(backup):
            raise ValueError()
        original = base64.b64decode(backup["data"], validate=True) if backup["exists"] else None
        if original is not None and len(original) > 65536:
            raise ValueError()
        if PACKAGE_POLICY.is_symlink():
            raise ValueError()
        current = PACKAGE_POLICY.read_bytes() if PACKAGE_POLICY.exists() else None
        if current not in (TEMPORARY_POLICY, original):
            raise Blocked("Package service policy changed after interruption; no overwrite is allowed")
        return backup
    except Blocked:
        raise
    except (ValueError, TypeError, KeyError, OSError, UnicodeError):
        raise Blocked("Private package policy recovery record is unknown or corrupt") from None


def restore_package_policy(spec, node):
    backup = read_package_policy_recovery(spec, node)
    if backup["exists"]:
        atomic(PACKAGE_POLICY, base64.b64decode(backup["data"], validate=True), backup["mode"])
        os.chown(PACKAGE_POLICY, backup["uid"], backup["gid"])
    else:
        PACKAGE_POLICY.unlink(missing_ok=True)
    checkpoint(spec, node, "package_policy_restored", package_policy_pending=False)


def begin_package_policy(spec, node):
    if PACKAGE_POLICY.is_symlink():
        raise Blocked("Existing package service policy is not a regular file")
    exists = PACKAGE_POLICY.exists()
    backup = {"cluster_id": spec["cluster_id"], "node_id": node["id"], "topology_digest": digest(topology(spec)), "exists": exists}
    if exists:
        info = PACKAGE_POLICY.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > 65536:
            raise Blocked("Existing package service policy is not a bounded regular file")
        backup.update(mode=stat.S_IMODE(info.st_mode), uid=info.st_uid, gid=info.st_gid, data=base64.b64encode(PACKAGE_POLICY.read_bytes()).decode())
    atomic(STATE / "package-policy.json", json.dumps(backup, sort_keys=True, separators=(",", ":")))
    checkpoint(spec, node, "package_policy_staged", package_policy_pending=True, package_policy_snapshot=digest(backup))
    atomic(PACKAGE_POLICY, TEMPORARY_POLICY, 0o755)


def install(spec, node):
    inspection = inspect(spec, node)
    if inspection["blockers"]:
        return inspection
    saved = load_journal(spec, node)
    if saved and saved.get("package_policy_pending"):
        restore_package_policy(spec, node)
        saved = load_journal(spec, node)
    if saved and saved.get("installed") is True:
        return {"status": "installed"}
    checkpoint(spec, node, "installing")
    # Prevent package postinst from creating/starting an unrelated default PG cluster.
    create = Path("/etc/postgresql-common/createcluster.conf")
    backup_config(create)
    atomic(create, "# Prthak dedicated Patroni node: PostgreSQL is initialized only by Patroni.\ncreate_main_cluster = false\n", 0o644)
    try:
        begin_package_policy(spec, node)
        options = ["-o", "Acquire::AllowInsecureRepositories=false", "-o", "Acquire::AllowDowngradeToInsecureRepositories=false", "-o", "APT::Get::AllowUnauthenticated=false"]
        command(["apt-get", *options, "update"], timeout=600, environment={"DEBIAN_FRONTEND": "noninteractive"})
        packages = list(PACKAGES if node["role"] == "database" else ("etcd-server", "etcd-client", "openssl", "iproute2"))
        apt_origin_check(packages)
        command(["apt-get", *options, "-o", "Dpkg::Options::=--force-confold", "-y", "--no-install-recommends", "install", *packages], timeout=900, environment={"DEBIAN_FRONTEND": "noninteractive"})
    finally:
        if (load_journal(spec, node) or {}).get("package_policy_pending"):
            restore_package_policy(spec, node)
    # Refuse an unexpected package/daemon interface rather than weakening TLS.
    help_text = command(["/usr/bin/etcd", "--help"], okay=(0, 2), combine=True)
    if not all(flag in help_text for flag in ("--peer-client-cert-auth", "--client-cert-auth", "--tls-min-version")):
        raise Blocked("Packaged etcd lacks required authenticated TLS options")
    if node["role"] == "database":
        command(["/usr/bin/python3", "-c", "import patroni.dcs.etcd3, psycopg2, yaml"])
        command(["/usr/lib/postgresql/16/bin/postgres", "--version"])
    checkpoint(spec, node, "installed", installed=True)
    return {"status": "installed"}


def validate_material(material, database=True):
    if not isinstance(material, dict):
        raise Blocked("Private node material is required")
    for key, header in (("ca", "CERTIFICATE"), ("certificate", "CERTIFICATE"), ("private_key", "PRIVATE KEY")):
        text = material.get(key)
        if not isinstance(text, str) or len(text) > 32768 or ("-----BEGIN " + header + "-----") not in text:
            raise Blocked("Invalid private TLS material")
    actual = hashlib.sha256(ssl.PEM_cert_to_DER_cert(material["ca"])).hexdigest()
    if actual != material.get("ca_fingerprint"):
        raise Blocked("Cluster CA fingerprint mismatch")
    passwords = material.get("passwords", {})
    if database and any(not isinstance(passwords.get(key), str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", passwords[key]) for key in ("admin", "replication", "metadata", "traffic")):
        raise Blocked("Strong private database role secrets are required")


def etcd_config(spec, node):
    return {"name": node["id"], "data-dir": str(STATE / "etcd"), "listen-client-urls": "https://" + node["ip"] + ":2379", "advertise-client-urls": "https://" + node["ip"] + ":2379", "listen-peer-urls": "https://" + node["ip"] + ":2380", "initial-advertise-peer-urls": "https://" + node["ip"] + ":2380", "initial-cluster": ",".join(item["id"] + "=https://" + item["ip"] + ":2380" for item in spec["nodes"]), "initial-cluster-token": "prthak-" + spec["cluster_id"], "initial-cluster-state": "new", "enable-v2": False, "tls-min-version": "TLS1.2", "client-transport-security": {"cert-file": str(BASE / "etcd/node.pem"), "key-file": str(BASE / "etcd/node-key.pem"), "trusted-ca-file": str(BASE / "etcd/ca.pem"), "client-cert-auth": True}, "peer-transport-security": {"cert-file": str(BASE / "etcd/node.pem"), "key-file": str(BASE / "etcd/node-key.pem"), "trusted-ca-file": str(BASE / "etcd/ca.pem"), "client-cert-auth": True}}


def patroni_config(spec, node, material):
    pg = str(BASE / "patroni")
    auth = {"sslmode": "verify-full", "sslrootcert": pg + "/ca.pem"}
    hba = ["local all all peer", "hostssl all prthak_admin 127.0.0.1/32 scram-sha-256"]
    for peer in spec["nodes"]:
        if peer["role"] == "database":
            hba.extend(["hostssl replication prthak_replication " + peer["ip"] + "/32 scram-sha-256", "hostssl all prthak_admin " + peer["ip"] + "/32 scram-sha-256"])
    for cidr in spec["controller_cidrs"]:
        for scope in ("metadata", "traffic"):
            hba.append("hostssl " + spec["database"][scope + "_name"] + " " + spec["database"][scope + "_user"] + " " + cidr + " scram-sha-256")
    for scope in ("metadata", "traffic"):
        hba.append("hostssl " + spec["database"][scope + "_name"] + " " + spec["database"][scope + "_user"] + " 127.0.0.1/32 scram-sha-256")
    hba.extend(["host all all 0.0.0.0/0 reject", "host all all ::/0 reject"])
    return {"scope": spec["name"], "namespace": "/prthak/" + spec["cluster_id"] + "/", "name": node["id"],
        "restapi": {"listen": node["ip"] + ":8008", "connect_address": node["ip"] + ":8008", "certfile": pg + "/node.pem", "keyfile": pg + "/node-key.pem", "cafile": pg + "/ca.pem", "verify_client": "required"},
        "ctl": {"insecure": False, "cacert": pg + "/ca.pem", "certfile": pg + "/node.pem", "keyfile": pg + "/node-key.pem"},
        "etcd3": {"hosts": [peer["ip"] + ":2379" for peer in spec["nodes"]], "protocol": "https", "cacert": pg + "/ca.pem", "cert": pg + "/node.pem", "key": pg + "/node-key.pem"},
        "bootstrap": {"dcs": {"ttl": 60, "loop_wait": 5, "retry_timeout": 5, "maximum_lag_on_failover": 1048576, "check_timeline": True, "synchronous_mode": True, "synchronous_mode_strict": True, "synchronous_node_count": 1, "postgresql": {"use_pg_rewind": True, "parameters": {"wal_level": "replica", "hot_standby": "on", "max_wal_senders": 10, "max_replication_slots": 10, "wal_log_hints": "on", "password_encryption": "scram-sha-256", "synchronous_commit": "on"}}}, "initdb": [{"encoding": "UTF8"}, "data-checksums"], "pg_hba": hba},
        "postgresql": {"listen": node["ip"] + ",127.0.0.1:5432", "connect_address": node["ip"] + ":5432", "data_dir": str(STATE / "postgres"), "bin_dir": "/usr/lib/postgresql/16/bin", "pgpass": str(STATE / "patroni/pgpass"), "authentication": {"superuser": {"username": "prthak_admin", "password": material["passwords"]["admin"], **auth}, "replication": {"username": "prthak_replication", "password": material["passwords"]["replication"], **auth}}, "parameters": {"ssl": "on", "ssl_min_protocol_version": "TLSv1.2", "ssl_cert_file": pg + "/node.pem", "ssl_key_file": pg + "/node-key.pem", "ssl_ca_file": pg + "/ca.pem", "password_encryption": "scram-sha-256", "unix_socket_directories": str(STATE / "socket")}, "pg_hba": hba},
        "watchdog": {"mode": "required", "device": spec["watchdog"]["device"], "safety_margin": -1}, "tags": {"nofailover": False, "noloadbalance": False, "clonefrom": False, "nosync": False}}


def service(user, executable, writable):
    return "\n".join(["[Unit]", "Description=Prthak managed database cluster component", "After=network-online.target", "Wants=network-online.target", "[Service]", "Type=simple", "User=" + user, "Group=" + user, "ExecStart=" + executable, "Restart=on-failure", "RestartSec=5", "TimeoutStopSec=60", "KillMode=control-group", "UMask=0077", "NoNewPrivileges=yes", "PrivateTmp=yes", "ProtectSystem=strict", "ProtectHome=yes", "ReadWritePaths=" + writable, "[Install]", "WantedBy=multi-user.target", ""])


def _configuration_paths(node):
    paths = [BASE / "etcd" / name for name in ("ca.pem", "node.pem", "node-key.pem", "etcd.json")]
    paths.append(Path("/etc/systemd/system/prthak-etcd.service"))
    if node["role"] == "database":
        paths.extend(BASE / "patroni" / name for name in ("ca.pem", "node.pem", "node-key.pem", "patroni.json", "roles.json"))
        paths.extend([Path("/etc/systemd/system/prthak-patroni.service"), Path("/etc/udev/rules.d/70-prthak-watchdog.rules")])
    return paths


def begin_configuration(spec, node):
    entries = []
    for path in _configuration_paths(node):
        if path.is_symlink():
            raise Blocked("Refusing to back up a symlink as managed configuration")
        if path.exists():
            info = path.stat()
            if not stat.S_ISREG(info.st_mode) or info.st_size > 131072:
                raise Blocked("Existing configuration is not a bounded regular file")
            entries.append({"path": str(path), "exists": True, "mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid, "gid": info.st_gid, "data": base64.b64encode(path.read_bytes()).decode()})
        else:
            entries.append({"path": str(path), "exists": False})
    backup = {"cluster_id": spec["cluster_id"], "node_id": node["id"], "topology_digest": digest(topology(spec)), "files": entries}
    if node["role"] == "database" and device_ready(spec, node):
        info = Path(spec["watchdog"]["device"]).stat()
        backup["watchdog"] = {"uid": info.st_uid, "gid": info.st_gid, "mode": stat.S_IMODE(info.st_mode)}
    atomic(STATE / "config-transaction.json", json.dumps(backup, sort_keys=True, separators=(",", ":")))
    checkpoint(spec, node, "configuring", config_pending=True, config_snapshot_digest=digest(backup))


def read_configuration_recovery(spec, node):
    path = STATE / "config-transaction.json"
    if path.is_symlink() or not path.exists() or not stat.S_ISREG(path.stat().st_mode) or path.stat().st_mode & 0o077 or path.stat().st_uid != os.geteuid() or path.stat().st_size > 2 * 1024 * 1024:
        raise Blocked("Private configuration recovery record is unavailable")
    try:
        backup = json.loads(path.read_text())
    except (ValueError, UnicodeError, OSError):
        raise Blocked("Private configuration recovery record is corrupt") from None
    if not isinstance(backup, dict):
        raise Blocked("Private configuration recovery record is corrupt")
    allowed = {str(value) for value in _configuration_paths(node)}
    entries = backup.get("files", [])
    if not isinstance(entries, list) or any(not isinstance(entry, dict) for entry in entries):
        raise Blocked("Private configuration recovery entries are corrupt")
    saved = load_journal(spec, node)
    if backup.get("cluster_id") != spec["cluster_id"] or backup.get("node_id") != node["id"] or backup.get("topology_digest") != digest(topology(spec)) or len(entries) != len(allowed) or {entry.get("path") for entry in entries} != allowed or not saved or saved.get("config_snapshot_digest") != digest(backup):
        raise Blocked("Configuration recovery identity mismatch")
    for entry in entries:
        if not isinstance(entry.get("exists"), bool):
            raise Blocked("Invalid configuration recovery entry")
        if entry["exists"]:
            try:
                data = base64.b64decode(entry["data"], validate=True)
                if len(data) > 131072 or any(isinstance(entry.get(key), bool) or not isinstance(entry.get(key), int) or entry[key] < 0 for key in ("mode", "uid", "gid")) or entry["mode"] > 0o777:
                    raise ValueError()
            except (ValueError, TypeError, KeyError):
                raise Blocked("Invalid private configuration recovery data") from None
    return backup


def restore_configuration(spec, node):
    backup = read_configuration_recovery(spec, node)
    entries = backup["files"]
    for entry in entries:
        target = Path(entry["path"])
        if target.is_symlink():
            raise Blocked("Refusing a symlink during private configuration recovery")
        if entry["exists"]:
            atomic(target, base64.b64decode(entry["data"], validate=True), entry["mode"])
            os.chown(target, entry["uid"], entry["gid"])
        else:
            target.unlink(missing_ok=True)
    if backup.get("watchdog"):
        device = spec["watchdog"]["device"]
        info = backup["watchdog"]
        os.chown(device, info["uid"], info["gid"])
        os.chmod(device, info["mode"])
    checkpoint(spec, node, "configuration_restored", config_pending=False)


def configure(spec, node, material, expected_recovery_snapshot=None):
    saved = load_journal(spec, node)
    if not saved:
        raise Blocked("Install this dedicated node before configuration")
    validate_material(material, node["role"] == "database")
    material_hash = digest({key: material[key] for key in ("ca", "certificate", "private_key", "passwords")})
    if saved.get("material_digest") and saved["material_digest"] != material_hash:
        raise Blocked("Established node credentials cannot change during install/retry; use a reviewed credential rotation")
    if saved.get("config_pending"):
        if not isinstance(expected_recovery_snapshot, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_recovery_snapshot) or saved.get("config_snapshot_digest") != expected_recovery_snapshot:
            raise Blocked("Pending configuration snapshot requires an exact fresh recovery review")
        restore_configuration(spec, node)
    elif expected_recovery_snapshot is not None:
        raise Blocked("Reviewed recovery state changed; inspect and review again")
    begin_configuration(spec, node)
    try:
        result = _configure(spec, node, material)
        checkpoint(spec, node, "configured", config_pending=False)
        return result
    except Exception:
        restore_configuration(spec, node)
        raise


def _configure(spec, node, material):
    validate_material(material, node["role"] == "database")
    saved = load_journal(spec, node)
    if not saved:
        raise Blocked("Inspect and install this dedicated node before configuration")
    if saved.get("ca_fingerprint") and saved["ca_fingerprint"] != material["ca_fingerprint"]:
        raise Blocked("An established node CA cannot be replaced during retry")
    mkdir(BASE, mode=0o755)
    mkdir(STATE, mode=0o711)
    mkdir(BASE / "etcd", "etcd")
    mkdir(STATE / "etcd", "etcd")
    for name, value in (("ca.pem", material["ca"]), ("node.pem", material["certificate"]), ("node-key.pem", material["private_key"])):
        atomic(BASE / "etcd" / name, value, user="etcd")
    atomic(BASE / "etcd/etcd.json", json.dumps(etcd_config(spec, node), sort_keys=True), user="etcd")
    etcd_unit = Path("/etc/systemd/system/prthak-etcd.service")
    backup_config(etcd_unit)
    atomic(etcd_unit, service("etcd", "/usr/bin/etcd --config-file=/etc/prthak-cluster/etcd/etcd.json", str(STATE / "etcd")), 0o644)
    if node["role"] == "database":
        mkdir(BASE / "patroni", "postgres")
        # Parent is traversable by service accounts, private children remain 0700.
        os.chmod(STATE, 0o711)
        mkdir(STATE / "postgres", "postgres")
        mkdir(STATE / "socket", "postgres")
        mkdir(STATE / "patroni", "postgres")
        for name, value in (("ca.pem", material["ca"]), ("node.pem", material["certificate"]), ("node-key.pem", material["private_key"])):
            atomic(BASE / "patroni" / name, value, user="postgres")
        config = patroni_config(spec, node, material)
        atomic(BASE / "patroni/patroni.json", json.dumps(config, sort_keys=True), user="postgres")
        atomic(BASE / "patroni/roles.json", json.dumps({"database": spec["database"], "passwords": material["passwords"]}), user="postgres")
        unit = Path("/etc/systemd/system/prthak-patroni.service")
        backup_config(unit)
        atomic(unit, service("postgres", "/usr/bin/patroni /etc/prthak-cluster/patroni/patroni.json", str(STATE / "postgres") + " " + str(STATE / "socket") + " " + str(STATE / "patroni")), 0o644)
        # Explicit approval permits only granting postgres this existing device.
        # No module loading, soft_noboot or kernel option changes are performed.
        if not device_ready(spec, node):
            raise Blocked("Required watchdog disappeared before configuration")
        account = pwd.getpwnam("postgres")
        os.chown(spec["watchdog"]["device"], account.pw_uid, account.pw_gid)
        os.chmod(spec["watchdog"]["device"], 0o600)
        rule = 'SUBSYSTEM=="watchdog", KERNEL=="watchdog0", OWNER="postgres", GROUP="postgres", MODE="0600"\n'
        atomic(Path("/etc/udev/rules.d/70-prthak-watchdog.rules"), rule, 0o644)
    # CA/key pairing and actual IP SAN verification are checked by OpenSSL.
    for account in (("etcd",) if node["role"] == "witness" else ("etcd", "patroni")):
        directory = BASE / account
        command(["/usr/bin/openssl", "verify", "-CAfile", str(directory / "ca.pem"), "-verify_ip", node["ip"], str(directory / "node.pem")])
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(directory / "node.pem", directory / "node-key.pem")
    command(["/usr/bin/systemctl", "daemon-reload"])
    checkpoint(spec, node, "configured", ca_fingerprint=material["ca_fingerprint"], material_digest=digest({key: material[key] for key in ("ca", "certificate", "private_key", "passwords")}))
    return {"status": "configured"}


def tls_get(node, directory, port, path):
    context = ssl.create_default_context(cafile=str(directory / "ca.pem"))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(directory / "node.pem", directory / "node-key.pem")
    connection = http.client.HTTPSConnection(node["ip"], port, timeout=3, context=context)
    try:
        connection.request("GET", path, headers={"Connection": "close"})
        reply = connection.getresponse()
        body = reply.read(1024 * 1024 + 1)
        if len(body) > 1024 * 1024:
            return None
        return json.loads(body) if reply.status == 200 else None
    except (OSError, ValueError, ssl.SSLError, http.client.HTTPException):
        return None
    finally:
        connection.close()


def app_roles_ready(spec, node):
    try:
        import psycopg2
        saved = json.loads((BASE / "patroni/roles.json").read_text())
        for scope in ("metadata", "traffic"):
            connection = psycopg2.connect(host="127.0.0.1", port=5432, dbname=spec["database"][scope + "_name"], user=spec["database"][scope + "_user"], password=saved["passwords"][scope], sslmode="verify-full", sslrootcert=str(BASE / "patroni/ca.pem"), target_session_attrs="read-write", connect_timeout=3)
            try:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT current_database(),current_user,pg_is_in_recovery()")
                    if cursor.fetchone() != (spec["database"][scope + "_name"], spec["database"][scope + "_user"], False):
                        return False
            finally:
                connection.close()
        return True
    except Exception:
        return False


def status(spec, node):
    saved = load_journal(spec, node)
    if not saved:
        return {"status": "unmanaged", "etcd_healthy": False, "database_healthy": False, "watchdog_ready": False}
    value = {"status": "degraded", "phase": saved.get("phase"), "ca_fingerprint": saved.get("ca_fingerprint"), "etcd_healthy": False, "database_healthy": False, "watchdog_ready": False, "roles_ready": False}
    if saved.get("config_pending"):
        return {**value, "config_pending": True}
    etcd = tls_get(node, BASE / "etcd", 2379, "/health") if (BASE / "etcd/ca.pem").exists() else None
    value["etcd_healthy"] = isinstance(etcd, dict) and etcd.get("health") in (True, "true")
    if node["role"] == "database" and (BASE / "patroni/ca.pem").exists():
        patroni = tls_get(node, BASE / "patroni", 8008, "/patroni")
        if isinstance(patroni, dict):
            role = patroni.get("role")
            value["database_role"] = "primary" if role in ("master", "primary") else "replica" if role == "replica" else "unknown"
            value["database_healthy"] = patroni.get("state") == "running" and not patroni.get("pause") and patroni.get("patroni", {}).get("scope") == spec["name"]
            value["synchronous_replica"] = any(peer.get("state") == "streaming" and peer.get("sync_state") == "sync" for peer in patroni.get("replication", []))
            config = json.loads((BASE / "patroni/patroni.json").read_text())
            # Required-mode primary cannot be promoted without watchdog setup.
            # Also check the kernel's active state; merely having a device is insufficient.
            active = False
            try:
                active = Path("/sys/class/watchdog/watchdog0/state").read_text().strip() == "active"
            except OSError:
                pass
            value["watchdog_ready"] = config.get("watchdog", {}).get("mode") == "required" and device_ready(spec, node) and (value["database_role"] != "primary" or active)
            if value["database_role"] == "primary":
                value["roles_ready"] = app_roles_ready(spec, node)
    value["status"] = "healthy" if value["etcd_healthy"] and (node["role"] == "witness" or value["database_healthy"] and value["watchdog_ready"]) else "degraded"
    return value


def start(spec, node, database=False):
    saved = load_journal(spec, node)
    if not saved or not saved.get("ca_fingerprint") or saved.get("config_pending"):
        raise Blocked("Node must have a validated private configuration before startup")
    if database and (node["role"] != "database" or not device_ready(spec, node)):
        raise Blocked("Database promotion requires the approved watchdog")
    unit = "prthak-patroni.service" if database else "prthak-etcd.service"
    command(["/usr/bin/systemctl", "enable", "--now", unit], timeout=90)
    checkpoint(spec, node, "database_started" if database else "etcd_started", **({"database_ever_started": True} if database else {"etcd_ever_started": True}))
    return {"status": "started"}


def scram_password(password):
    import hmac
    salt = os.urandom(16)
    salted = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 4096)
    client = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    stored = hashlib.sha256(client).digest()
    server = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    encode = lambda value: base64.b64encode(value).decode()
    return "SCRAM-SHA-256$4096:" + encode(salt) + "$" + encode(stored) + ":" + encode(server)


def create_roles(spec, node):
    if node["role"] != "database" or not load_journal(spec, node):
        raise Blocked("Application roles require this managed database cluster")
    if app_roles_ready(spec, node):
        return {"status": "roles_ready", "roles_ready": True}
    import psycopg2
    from psycopg2 import sql
    private = json.loads((BASE / "patroni/roles.json").read_text())
    connection = psycopg2.connect(host="127.0.0.1", port=5432, dbname="postgres", user="prthak_admin", password=private["passwords"]["admin"], sslmode="verify-full", sslrootcert=str(BASE / "patroni/ca.pem"), target_session_attrs="read-write", connect_timeout=3)
    connection.autocommit = True
    try:
        with connection.cursor() as cursor:
            cursor.execute("SET statement_timeout='20s'")
            for scope in ("metadata", "traffic"):
                user = spec["database"][scope + "_user"]
                database = spec["database"][scope + "_name"]
                cursor.execute("SELECT 1 FROM pg_roles WHERE rolname=%s", (user,))
                verb = "ALTER" if cursor.fetchone() else "CREATE"
                cursor.execute(sql.SQL(verb + " ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD {}").format(sql.Identifier(user), sql.Literal(scram_password(private["passwords"][scope]))))
                cursor.execute("SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname=%s", (database,))
                existing = cursor.fetchone()
                if existing and existing[0] != user:
                    raise Blocked("An existing application database has a different owner")
                if not existing:
                    cursor.execute(sql.SQL("CREATE DATABASE {} OWNER {} TEMPLATE template0 ENCODING 'UTF8'").format(sql.Identifier(database), sql.Identifier(user)))
                cursor.execute(sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(sql.Identifier(database)))
    finally:
        connection.close()
    ready = app_roles_ready(spec, node)
    if ready:
        checkpoint(spec, node, "roles_ready")
    return {"status": "roles_ready" if ready else "degraded", "roles_ready": ready}


def backup(spec, node):
    """Create private local encrypted-transport-ready dumps; never return bytes.

    The platform backup worker is responsible for encrypted off-node retention.
    Two dumps are not a transactionally atomic cross-database recovery point.
    """
    state = status(spec, node)
    if state.get("database_role") != "primary" or not state.get("roles_ready"):
        raise Blocked("Backups require the authenticated writable primary")
    destination = STATE / "backups" / (datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + os.urandom(4).hex())
    mkdir(destination)
    private = json.loads((BASE / "patroni/roles.json").read_text())
    pgpass = destination / ".pgpass"
    atomic(pgpass, "127.0.0.1:5432:*:prthak_admin:" + private["passwords"]["admin"] + "\n")
    files = []
    try:
        for scope in ("metadata", "traffic"):
            target = destination / (scope + ".dump")
            env = {"PGPASSFILE": str(pgpass), "PGSSLMODE": "verify-full", "PGSSLROOTCERT": str(BASE / "patroni/ca.pem")}
            command(["/usr/lib/postgresql/16/bin/pg_dump", "--format=custom", "--host=127.0.0.1", "--port=5432", "--username=prthak_admin", "--dbname=" + spec["database"][scope + "_name"], "--file=" + str(target)], timeout=600, environment=env)
            os.chmod(target, 0o600)
            file_hash = hashlib.sha256()
            with target.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    file_hash.update(chunk)
            files.append({"name": target.name, "bytes": target.stat().st_size, "sha256": file_hash.hexdigest()})
        atomic(destination / "manifest.json", json.dumps({"cluster_id": spec["cluster_id"], "files": files, "compatible_point": False, "requires_quiesce_for_cross_database_consistency": True}, sort_keys=True))
    finally:
        pgpass.unlink(missing_ok=True)
    return {"status": "backup_created", "backup_id": destination.name, "files": files, "compatible_point": False, "off_node_retained": False}


def main(value):
    outer = value if isinstance(value, dict) else {}
    outer_spec = outer.get("spec") if isinstance(outer.get("spec"), dict) else {}
    response = {"status": "blocked", "node_id": outer.get("node_id"), "cluster_id": outer_spec.get("cluster_id"), "topology_digest": outer.get("topology_digest")}
    lock = None
    try:
        if os.geteuid() != 0:
            raise Blocked("Pinned SSH account requires root or passwordless sudo for the fixed helper")
        spec, node = validate_request(value)
        action = value["action"]
        platform_check()
        if action not in ("inspect", "status"):
            import fcntl
            lock = os.open("/run/prthak-cluster-setup.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            info = os.fstat(lock)
            if info.st_uid != 0 or info.st_mode & 0o077:
                raise Blocked("Private setup lock ownership is invalid")
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Blocked("Another fixed cluster setup operation is already running") from None
        if action == "inspect":
            result = inspect(spec, node)
        elif action == "install":
            result = install(spec, node)
        elif action == "configure":
            result = configure(spec, node, value.get("material"), value.get("expected_recovery_snapshot"))
        elif action in ("start_etcd", "start_database"):
            result = start(spec, node, action == "start_database")
        elif action == "status":
            result = status(spec, node)
        elif action == "create_roles":
            result = create_roles(spec, node)
        else:
            result = backup(spec, node)
        response.update(result)
    except Blocked as error:
        response["blockers"] = [str(error)]
    except Exception:
        # No traceback/configuration, passwords, SQL, driver diagnostics or PEM
        # data may cross this public response boundary.
        response["blockers"] = ["Fixed node operation failed; private managed data and journals were retained"]
    finally:
        if lock is not None:
            os.close(lock)
    print(json.dumps(response, sort_keys=True, separators=(",", ":")), flush=True)
