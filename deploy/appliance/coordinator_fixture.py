#!/usr/bin/env python3
"""TEST ONLY: real shared-PG rotation coordinator over private mTLS helpers.

Run solely inside validate_cluster.py's disposable, unpublished Docker network.
No Docker socket, arbitrary command channel or production image includes this
driver. PostgreSQL, etcd, Patroni, role changes and fresh authentication are real;
the local Engine transport uses a test-only fixed-helper mTLS bridge.
"""
from __future__ import annotations

import copy
import http.client
import ipaddress
import json
import os
from pathlib import Path
import secrets
import ssl
import sys
import time
from types import SimpleNamespace

sys.path.insert(0, "/opt/prthak")
sys.path.insert(0, "/app")
import node_manager as native
from controller import cluster_bootstrap as bootstrap
from controller import replication_rotation as rotation
from controller.appliance import Appliance
from controller.platform import PlatformManager, _private_json
from controller.platform_runtime import migrate_stopped_sqlite
from controller.postgres import PostgresStore
from controller.store import Store
from psycopg.conninfo import make_conninfo


def main():
    if len(sys.argv) != 2:
        raise RuntimeError("The disposable fixture requires its three private IPv4 addresses")
    addresses = json.loads(sys.argv[1])
    if not isinstance(addresses, list) or len(addresses) != 3 or len(set(addresses)) != 3 or any(not ipaddress.ip_address(ip).is_private for ip in addresses):
        raise RuntimeError("Only a three-member private fixture network is allowed")
    root = Path("/var/lib/prthak")
    roots = [root / str(i) for i in range(3)]
    manifests = [native.load(path / "config/manifest.json") for path in roots]
    first = manifests[0]
    deployment = first["deployment_id"]
    if any(value["deployment_id"] != deployment for value in manifests) or [value["local_node"]["ip"] for value in manifests] != addresses:
        raise RuntimeError("Private manifests do not match this exact cluster")
    passwords = [native.load(path / "config/database/roles.json")["secrets"]["rotation_test"] for path in roots]
    if len(set(passwords)) != 1:
        raise RuntimeError("Private test credentials disagree")
    password = passwords[0]
    old_password = first["secrets"]["replication"]
    if password == old_password:
        raise RuntimeError("The disposable test needs a different target credential")
    mutations = []
    # Use the actual shared disposable issuing authority and one synchronization
    # seed, matching production material. The real Vault encrypts each copy;
    # neither private keys nor plaintext credentials enter shared metadata.
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    ca = first["pki"]["ca"]
    ca_key = (root / "fixture-authority/ca-key.pem").read_text()
    certificate = x509.load_pem_x509_certificate(ca.encode())
    issuing_key = serialization.load_pem_private_key(ca_key.encode(), None)
    assert certificate.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) == issuing_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert all(value["pki"]["ca"] == ca and value["secrets"] == first["secrets"] for value in manifests)
    shared_material = {"ca": ca, "ca_key": ca_key, "controller_ca": first.get("controller_ca", ca),
                       "pki_purpose": "internal-database-v1", "sync_key": secrets.token_hex(32),
                       "secrets": {kind: first["secrets"][kind] for kind in ("admin", "metadata", "traffic", "replication")}}

    def rpc(node_root, payload):
        manifest = native.load(node_root / "config/manifest.json")
        context = ssl.create_default_context(cafile=str(node_root / "config/database/ca.pem"))
        context.load_cert_chain(node_root / "config/database/node.pem", node_root / "config/database/node-key.pem")
        connection = http.client.HTTPSConnection(manifest["local_node"]["ip"], 9009, context=context, timeout=35)
        try:
            connection.request("POST", "/fixed-rotation-helper", json.dumps(payload).encode(), {"Content-Type": "application/json"})
            response = connection.getresponse()
            data = response.read(65537)
            if response.status != 200 or len(data) > 65536:
                raise native.Blocked("The private mTLS fixed helper did not acknowledge success")
            value = json.loads(data)
            if not isinstance(value, dict):
                raise native.Blocked("The private fixed helper returned an invalid result")
            if payload.get("action") == "change-role" and value.get("mutated") is True:
                mutations.append(manifest["local_node"]["id"])
            return value
        finally:
            connection.close()

    class PrivateEngine:
        def __init__(self, node_root, project):
            self.root = Path(node_root)

        def states(self):
            # The fixture launches these exact containers. Cluster readiness and
            # every barrier additionally use real authenticated peer probes.
            return {"database": "running", "etcd": "running"}

        def database_helper(self, payload):
            return rpc(self.root, payload)

    class Bridge:
        def __init__(self, manager):
            self.manager = manager

        def status(self):
            if self.manager.health_snapshot.get("checked_at", 0) < time.time() - 5:
                self.manager.refresh_health()
            return self.manager.status()

        def job(self, identifier):
            return self.manager.job(identifier)

        def submit(self, request):
            result = self.manager.submit(request)
            if result["status"] == "queued":
                if not self.manager.work_once():
                    raise RuntimeError("The real durable manager worker did not run its queued operation")
                result = self.manager.job(request["request_id"])
            return result

    private = root / "coordinator-fixture"
    private.mkdir(mode=0o700)
    source = Store(private / "stopped-source")
    os.environ.update(PRTHAK_APPLIANCE="1", PRTHAK_APPLIANCE_NODE_ID="", PRTHAK_APPLIANCE_NODE_IP="", PRTHAK_APPLIANCE_SITE="")
    apis, members = [], []
    for index, value in enumerate(manifests):
        node = value["local_node"]
        platform = PlatformManager(private / node["id"])
        platform.attach(SimpleNamespace(store=source, demo=False, controller_id=node["id"], site=node["site"]))
        manager = native.Manager(roots[index], engine_factory=PrivateEngine)
        api = Appliance(platform, client=Bridge(manager))
        _private_json(platform.root / "appliance-local.json", {"site": node["site"], "node_ip": node["ip"]})
        public = bootstrap._public_key(bootstrap._keys(api))
        runtime = api._database_runtime()
        bootstrap.require_database_runtime(runtime)
        members.append({key: node[key] for key in ("id", "site", "ip", "role")} | {"transport_public_key": public} | runtime)
        bootstrap._save_material(api, copy.deepcopy(shared_material))
        apis.append(api)
    assert all(bootstrap._material(api) == shared_material for api in apis)
    config = {"id": "appliance_cluster", "revision": 1, "deployment_id": deployment,
              "cluster_name": "Disposable coordinator acceptance", "controller_origin": first["controller_origin"],
              "bootstrap_seed_id": members[0]["id"], "members": members,
              "voters": [{key: member[key] for key in ("id", "site", "ip")} for member in members]}
    with source.meta() as db:
        source._put(db, "maintenance_settings", config)
    dsns = {kind: make_conninfo(host=",".join(addresses), port=5432, dbname=first["database"][kind + "_name"],
                               user=first["database"][kind + "_user"], password=first["secrets"][kind],
                               sslmode="verify-full", sslrootcert=str(roots[0] / "config/database/ca.pem"),
                               target_session_attrs="read-write", connect_timeout=3) for kind in ("metadata", "traffic")}
    # These exact disposable databases must be empty. The production stopped-
    # source migrator enforces this and creates real matching READY identities.
    migrated = migrate_stopped_sqlite(source.path, dsns["metadata"], dsns["traffic"], deployment, 1)
    assert migrated["verified"] is True
    for api in apis:
        api.app.store = PostgresStore(dsns["metadata"], dsns["traffic"], deployment_id=deployment, epoch=1)
    with apis[0].app.store.meta() as db:
        configuration = apis[0]._config(db)
        requested = rotation.queue(apis[0], db, configuration, password, "disposable-coordinator-acceptance")
        apis[0].app.store._put(db, "maintenance_settings", configuration)
    deadline = time.monotonic() + 100
    while time.monotonic() < deadline:
        for api in apis:
            rotation.reconcile(api)
        progress = rotation.status(apis[0])
        if progress["phase"] == "completed":
            break
        time.sleep(0.25)
    else:
        raise AssertionError("Real coordinator did not complete: " + json.dumps(rotation.status(apis[0]), sort_keys=True))
    assert len(mutations) == 1, "Expected exactly one actual SQL role mutation"
    assert progress["rotation_id"] == requested["rotation_id"] and progress["pending"] is False
    assert all(len(progress["acks"][phase]) == (1 if phase == "change-role" else 3) for phase in rotation.PHASES)
    for api, node_root in zip(apis, roots):
        rotation.sync_completed_material(api)
        assert bootstrap._material(api)["secrets"]["replication"] == password
        assert native.load(node_root / "config/manifest.json")["secrets"]["replication"] == password
        record = native.load(node_root / "manager/rotation.json")
        assert record["phase"] == "finalized"
        primary = next(node for node in api.client.status()["health"]["nodes"] if node["role"] in ("primary", "master"))["ip"]
        assert rpc(node_root, {"action": "probe", "password": password, "primary_ip": primary})["verified"] is True
    with apis[0].app.store.read_meta() as db:
        metadata = "".join(row[0] for row in db.execute("SELECT data FROM maintenance_settings").fetchall())
        audit = "".join(row[0] for row in db.execute("SELECT data FROM audit").fetchall())
    assert password not in metadata and password not in audit
    assert "recipients" not in json.dumps(progress)
    assert all(api.app.store.readiness() == {"metadata": True, "traffic": True} for api in apis)
    print("actual shared-PostgreSQL coordinator: prepare-all → primary SQL role change ONCE → reload-all → NEW replication authentication-all → finalize-all: PASS", flush=True)
    print("encrypted shared credential envelopes, exact READY identity/epoch, durable local manager jobs, and all private controller materials: PASS", flush=True)
    print("Native watchdog reset and real site partition/fencing: NOT VALIDATED", flush=True)


if __name__ == "__main__":
    main()
