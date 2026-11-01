#!/usr/bin/env python3
"""Opt-in private daemon smoke, with no host ports or privileged containers.

Build the package image described in README.md first. This verifies actual TLS,
quorum and replication. Containers have no real watchdog: it FIRST proves the
production required-watchdog config refuses promotion, THEN explicitly switches
only private test fixtures to watchdog=off for the replication checks. It is not
hardware fencing, systemd installation or multi-site failover certification.
"""
from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid


def inside(action):
    sys.path.insert(0, "/public")
    import ha_setup
    import node_helper as helper
    if action == "diagnostics":
        import re
        material = next(Path("/vault/private").glob("*/material.json"))
        passwords = json.loads(material.read_text())["passwords"].values()
        output = []
        for log in Path("/").glob("data-*/*.log"):
            body = log.read_text(errors="replace")[-30000:]
            for password in passwords:
                body = body.replace(password, "[redacted]")
            body = re.sub(r"-----BEGIN [^-]+-----.*?-----END [^-]+-----", "[redacted PEM]", body, flags=re.S)
            output.append({"component": str(log), "tail": body})
        print(json.dumps(output))
        return
    if action == "setup":
        spec = json.loads(Path("/vault/spec.json").read_text())
        material = ha_setup.FileMaterialProvider("/vault/private")(spec)
        import pwd
        account = pwd.getpwnam("postgres")
        for node in spec["nodes"]:
            config = Path("/vault/config") / node["id"]
            data = Path("/data-" + node["id"])
            for folder in (config / "etcd", config / "patroni", data / "postgres", data / "etcd", data / "socket", data / "patroni"):
                folder.mkdir(parents=True, exist_ok=True)
            for purpose in ("etcd", "patroni"):
                for name, value in (("ca.pem", material["ca"]), ("node.pem", material["nodes"][node["id"]]["certificate"]), ("node-key.pem", material["nodes"][node["id"]]["private_key"])):
                    (config / purpose / name).write_text(value)
            (config / "etcd/etcd.json").write_text(json.dumps(helper.etcd_config(spec, node)))
            if node["role"] == "database":
                (config / "patroni/patroni.json").write_text(json.dumps(helper.patroni_config(spec, node, material)))
                (config / "patroni/roles.json").write_text(json.dumps({"database": spec["database"], "passwords": material["passwords"]}))
            (config / "spec.json").write_text(json.dumps(spec))
            (config / "node-id").write_text(node["id"])
            (data / "setup.json").write_text(json.dumps({"cluster_id": spec["cluster_id"], "node_id": node["id"], "topology_digest": ha_setup.canonical_digest(ha_setup.topology(spec)), "phase": "lab_configured", "ca_fingerprint": material["ca_fingerprint"]}))
            for root in (config, data):
                for path in [root, *root.rglob("*")]:
                    os.chown(path, account.pw_uid, account.pw_gid)
                    path.chmod(0o700 if path.is_dir() else 0o600)
        # Config ancestors must be traversable; selected node dirs stay private.
        Path("/vault/config").chmod(0o755)
        print(json.dumps({"status": "configured", "ca_fingerprint": material["ca_fingerprint"]}))
        return
    if action == "test_only_watchdog_off":
        for config in Path("/vault/config").glob("*/patroni/patroni.json"):
            value = json.loads(config.read_text())
            assert value["watchdog"]["mode"] == "required"
            value["watchdog"]["mode"] = "off"
            config.write_text(json.dumps(value))
        print(json.dumps({"status": "test_only_watchdog_off", "production_configuration_changed": False}))
        return
    spec = json.loads(Path("/etc/prthak-cluster/spec.json").read_text())
    node_id = Path("/etc/prthak-cluster/node-id").read_text()
    node = next(node for node in spec["nodes"] if node["id"] == node_id)
    if action == "node":
        children = []
        logs = []
        def stop(*args):
            for child in children:
                if child.poll() is None:
                    child.terminate()
            deadline = time.monotonic() + 8
            for child in children:
                try:
                    child.wait(max(0.1, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    child.kill()
            sys.exit(0)
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        etcd_log = open("/var/lib/prthak-cluster/etcd.log", "ab")
        logs.append(etcd_log)
        children.append(subprocess.Popen(["etcd", "--config-file=/etc/prthak-cluster/etcd/etcd.json"], stdout=etcd_log, stderr=etcd_log))
        if node["role"] == "database":
            patroni_log = open("/var/lib/prthak-cluster/patroni.log", "ab")
            logs.append(patroni_log)
            children.append(subprocess.Popen(["patroni", "/etc/prthak-cluster/patroni/patroni.json"], stdout=patroni_log, stderr=patroni_log))
        while all(child.poll() is None for child in children):
            time.sleep(0.5)
        stop()
    etcd = helper.tls_get(node, helper.BASE / "etcd", 2379, "/health")
    patroni = helper.tls_get(node, helper.BASE / "patroni", 8008, "/patroni") if node["role"] == "database" else None
    if action == "probe":
        print(json.dumps({"node_id": node_id, "etcd_healthy": bool(etcd and etcd.get("health") in (True, "true")), "role": patroni.get("role") if patroni else None, "state": patroni.get("state") if patroni else None, "sync": any(peer.get("state") == "streaming" and peer.get("sync_state") == "sync" for peer in (patroni or {}).get("replication", []))}))
        return
    if action == "watchdog_guard":
        config = json.loads((helper.BASE / "patroni/patroni.json").read_text())
        log = Path("/var/lib/prthak-cluster/patroni.log").read_text(errors="replace").lower()
        print(json.dumps({"required": config["watchdog"]["mode"] == "required", "observed": "watchdog" in log and any(text in log for text in ("no such file", "could not activate", "cannot activate", "failed to activate"))}))
        return
    if action == "security":
        import http.client, ssl
        for port, path in ((2379, "/health"), (8008, "/patroni")):
            context = ssl.create_default_context(cafile=str(helper.BASE / "etcd/ca.pem"))
            connection = http.client.HTTPSConnection(node["ip"], port, context=context, timeout=3)
            rejected = False
            try:
                connection.request("GET", path)
                connection.getresponse().read()
            except (OSError, ssl.SSLError, http.client.HTTPException):
                rejected = True
            finally:
                connection.close()
            assert rejected, "Unauthenticated TLS client unexpectedly accepted"
        print(json.dumps({"status": "client_certificate_required"}))
        return
    if action == "roles":
        print(json.dumps(helper.create_roles(spec, node)))
        return
    if action in ("write", "read"):
        import psycopg2
        private = json.loads((helper.BASE / "patroni/roles.json").read_text())
        user = spec["database"]["metadata_user"] if action == "write" else "prthak_admin"
        password = private["passwords"]["metadata" if action == "write" else "admin"]
        connection = psycopg2.connect(host="127.0.0.1", dbname=spec["database"]["metadata_name"], user=user, password=password, sslmode="verify-full", sslrootcert=str(helper.BASE / "patroni/ca.pem"), connect_timeout=3)
        try:
            with connection:
                with connection.cursor() as cursor:
                    if action == "write":
                        cursor.execute("SET statement_timeout='20s'")
                        cursor.execute("CREATE TABLE lab_replication (id INTEGER PRIMARY KEY,value TEXT NOT NULL)")
                        cursor.execute("INSERT INTO lab_replication VALUES(1,'replicated-over-tls')")
                    else:
                        cursor.execute("SELECT value FROM lab_replication WHERE id=1")
                        assert cursor.fetchone() == ("replicated-over-tls",)
                        cursor.execute("SELECT pg_is_in_recovery()")
                        assert cursor.fetchone() == (True,)
        finally:
            connection.close()
        print(json.dumps({"status": action + "_passed"}))
        return
    raise RuntimeError("Unknown private smoke action")


def host(context, image, evidence):
    label = "prthak-ha-lab-" + uuid.uuid4().hex[:8]
    network, config_volume = label, label + "-pki"
    names = ("db-a", "db-b", "witness")
    volumes, containers = [], []
    docker = ["docker", "--context", context]
    events = []
    def run(args, input=None, timeout=180):
        process = subprocess.run([*docker, *args], input=input, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=timeout)
        if process.returncode:
            raise RuntimeError("Private Docker operation failed: " + " ".join(args[:3]) + "; " + process.stderr.decode()[-1500:])
        return process.stdout.decode().strip()
    def event(text):
        events.append(text)
        print(text, flush=True)
    def execute(name, action):
        output = run(["exec", label + "-" + name, "python3", "/public/smoke_docker.py", "--inside", action], timeout=45)
        return json.loads(output)
    def await_state(predicate, seconds=90):
        latest = None
        for _ in range(seconds // 2):
            latest = [execute(name, "probe") for name in names]
            if predicate(latest):
                return latest
            time.sleep(2)
        raise RuntimeError("Private daemon readiness deadline exceeded: " + json.dumps(latest))
    source = Path(__file__).resolve().parents[2]
    staging_parent = source / ".local/ha-node-test"
    staging_parent.mkdir(parents=True, exist_ok=True)
    staging = tempfile.TemporaryDirectory(prefix="public-run-", dir=staging_parent)
    public = Path(staging.name)
    public.chmod(0o755)
    shutil.copy(source / "controller/ha_setup.py", public / "ha_setup.py")
    shutil.copy(Path(__file__).with_name("node_helper.py"), public / "node_helper.py")
    shutil.copy(__file__, public / "smoke_docker.py")
    failure = None
    try:
        run(["network", "create", "--internal", network])
        info = json.loads(run(["network", "inspect", network]))[0]
        subnet = ipaddress.ip_network(info["IPAM"]["Config"][0]["Subnet"])
        key_type = b"ssh-ed25519"
        host_key = "ssh-ed25519 " + base64.b64encode(len(key_type).to_bytes(4, "big") + key_type + (32).to_bytes(4, "big") + b"k" * 32).decode()
        import sys as _sys
        _sys.path.insert(0, str(source))
        from controller.ha_setup import validate
        spec = validate({"cluster_id": str(uuid.uuid4()), "name": "prthak_lab", "controller_origin": "https://prthak.example.internal", "nodes": [{"id": name, "ip": str(subnet.network_address + 11 + index), "site": "site-" + name, "role": "witness" if name == "witness" else "database", "ssh": {"user": "root", "host_key": host_key, "private_key_ref": "unused-lab"}} for index, name in enumerate(names)], "controller_cidrs": [str(subnet)], "watchdog": {"mode": "required", "device": "/dev/watchdog", "approved": True}})
        run(["volume", "create", config_volume])
        volumes.append(config_volume)
        mounts = ["--mount", "type=volume,source=" + config_volume + ",target=/vault", "--mount", "type=bind,source=" + str(public) + ",target=/public,readonly"]
        for name in names:
            volume = label + "-data-" + name
            run(["volume", "create", volume])
            volumes.append(volume)
            mounts.extend(["--mount", "type=volume,source=" + volume + ",target=/data-" + name])
        # Public spec only; temporary certificates/secrets are created inside Docker volumes.
        run(["run", "--rm", "-i", "--platform", "linux/amd64", "--network", network, *mounts, image, "python3", "-c", "import pathlib,sys;pathlib.Path('/vault/spec.json').write_bytes(sys.stdin.buffer.read())"], input=json.dumps(spec).encode())
        run(["run", "--rm", "--platform", "linux/amd64", "--network", network, *mounts, image, "python3", "/public/smoke_docker.py", "--inside", "setup"], timeout=120)
        for node in spec["nodes"]:
            name = label + "-" + node["id"]
            run(["create", "--name", name, "--platform", "linux/amd64", "--network", network, "--ip", node["ip"], "--user", "postgres", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--mount", "type=volume,source=" + config_volume + ",target=/etc/prthak-cluster,volume-subpath=config/" + node["id"] + ",readonly", "--mount", "type=volume,source=" + label + "-data-" + node["id"] + ",target=/var/lib/prthak-cluster", "--mount", "type=bind,source=" + str(public) + ",target=/public,readonly", image, "python3", "/public/smoke_docker.py", "--inside", "node"])
            containers.append(name)
        run(["start", *containers])
        state = await_state(lambda values: all(value["etcd_healthy"] for value in values))
        event("PASS: three actual AMD64 etcd members formed an authenticated TLS quorum")
        time.sleep(10)
        state = [execute(name, "probe") for name in names]
        guards = [execute(name, "watchdog_guard") for name in names[:2]]
        assert not any(value["role"] in ("master", "primary") for value in state)
        assert all(value["required"] and value["observed"] for value in guards)
        event("PASS: unchanged required-watchdog production configs refused database promotion without a device")
        run(["stop", "-t", "10", *containers], timeout=45)
        run(["run", "--rm", "--platform", "linux/amd64", "--network", network, *mounts, image, "python3", "/public/smoke_docker.py", "--inside", "test_only_watchdog_off"])
        event("BOUNDARY: only disposable fixture copies now use watchdog=off; hardware fencing is not certified")
        run(["start", *containers])
        state = await_state(lambda values: all(value["etcd_healthy"] for value in values) and sum(value["role"] in ("master", "primary") and value["sync"] for value in values) == 1 and sum(value["role"] == "replica" and value["state"] == "running" for value in values) == 1, seconds=120)
        primary = next(value["node_id"] for value in state if value["role"] in ("master", "primary"))
        replica = next(value["node_id"] for value in state if value["role"] == "replica")
        assert execute(primary, "roles")["roles_ready"]
        assert execute(primary, "security")["status"] == "client_certificate_required"
        assert execute(primary, "write")["status"] == "write_passed"
        assert execute(replica, "read")["status"] == "read_passed"
        event("PASS: actual Patroni strict synchronous primary/replica, mTLS APIs, SCRAM application roles and replicated SQL write/read")
        run(["stop", "-t", "10", label + "-witness"], timeout=30)
        assert execute(replica, "probe")["etcd_healthy"]
        run(["stop", "-t", "10", label + "-" + primary], timeout=30)
        time.sleep(65)
        surviving = execute(replica, "probe")
        assert not surviving["etcd_healthy"] and surviving["role"] not in ("master", "primary")
        event("PASS: a single surviving etcd voter rejected health/write quorum and its replica did not promote after the leader TTL")
    except Exception as error:
        failure = str(error)
        event("FAIL: " + failure)
        if volumes:
            try:
                diagnostic = run(["run", "--rm", "--platform", "linux/amd64", "--network", "none", *mounts, image, "python3", "/public/smoke_docker.py", "--inside", "diagnostics"], timeout=30)
                log_path = staging_parent / "last-failure.json"
                log_path.write_text(diagnostic)
                log_path.chmod(0o600)
            except Exception:
                pass
    finally:
        for container in containers:
            try:
                run(["rm", "-f", container], timeout=30)
            except Exception:
                pass
        for volume in reversed(volumes):
            try:
                run(["volume", "rm", volume], timeout=30)
            except Exception:
                pass
        try:
            run(["network", "rm", network], timeout=30)
        except Exception:
            pass
        staging.cleanup()
        if evidence:
            Path(evidence).write_text("\n".join(events) + "\n")
    if failure:
        raise SystemExit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context")
    parser.add_argument("--image", default="prthak-ha-node-test:ubuntu24-amd64")
    parser.add_argument("--evidence")
    parser.add_argument("--inside", choices=("setup", "test_only_watchdog_off", "node", "probe", "roles", "write", "read", "watchdog_guard", "security", "diagnostics"))
    args = parser.parse_args()
    if args.inside:
        inside(args.inside)
    elif args.context:
        host(args.context, args.image, args.evidence)
    else:
        parser.error("Provide an explicit disposable Docker context")
