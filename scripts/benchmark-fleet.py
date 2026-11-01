#!/usr/bin/env python3
"""Isolated synthetic inventory/compiler/poll benchmark; no real endpoint changes.

PostgreSQL mode refuses populated databases and requires prthak_test_scale_ names.
This measures controller storage paths, not TLS ingress or 5,000 actual agents.
"""
from concurrent.futures import ThreadPoolExecutor
import argparse
import json
import math
import os
from pathlib import Path
import platform
import sys
import tempfile
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from controller.store import Store, digest, stamp
from controller.managed import protection


def run(store, count, workers, operations):
    at = stamp()
    identifiers = [f"scale-{index:05d}" for index in range(count)]
    protected = {"management_sources": ["10.90.0.0/24"], "ssh_ports": [2022],
        "controller_url": "https://scale-controller.invalid:8787",
        "management_probe_url": "https://scale-controller.invalid:8787/api/v1/agent/enforcement/check", "zone": "public"}
    protected = protection({**protected, "digest": digest(protected), "ready": True, "blockers": []})
    started = time.monotonic()
    with store.lock, store.meta() as db:
        if store._all(db, "servers") or store._all(db, "policies"):
            raise RuntimeError("Benchmark requires a new, empty isolated test store")
        location_ids = [str(uuid.uuid5(uuid.NAMESPACE_URL, f"prthak:scale:location:{index}")) for index in range(4)]
        for index, location_id in enumerate(location_ids):
            store._put(db, "locations", {"id": location_id, "key": "location:" + location_id,
                "name": ("DC1", "DC2", "DC3", "Cloud")[index], "location": "Synthetic benchmark",
                "type": "cloud" if index == 3 else "datacenter", "synthetic": True, "aliases": [],
                "provider": "", "region": "", "created_at": at, "updated_at": at})
        for index, identifier in enumerate(identifiers):
            address = f"10.40.{index // 250}.{index % 250 + 1}"
            store._put(db, "servers", {"id": identifier, "hostname": identifier, "synthetic": True,
                "ips": [address], "tags": {"application": ("billing", "payments", "identity", "platform", "observability")[index % 5],
                    "role": "gateway" if index < 20 else "backend"}, "location_id": location_ids[index % 4],
                "status": "healthy", "created_at": at, "last_seen": at, "last_discovery_at": at,
                "discovery_interval_seconds": 900, "control_interval_seconds": 60, "expected_services": [],
                "listeners": [{"port": 2022, "protocol": "tcp", "address": "0.0.0.0", "service": "SSH", "process": "sshd"}],
                "firewalld_state": "running", "applied_version": 0, "desired_version": 0,
                "apply_status": "preview", "collector_status": "off", "protection": protected,
                "protection_digest": protected["digest"], "management_protection": protected})
    seed_seconds = time.monotonic() - started
    policy_data = {"name": "Synthetic scale access", "selector": {}, "mode": "enforce", "services": [
        {"port": 2022, "protocol": "tcp", "sources": ["10.90.0.0/24"]},
        {"port": 8443, "protocol": "tcp", "sources": [], "source_selector": {"role": "gateway"}}]}
    started = time.monotonic()
    policy = store.save_policy(policy_data, "synthetic-benchmark")
    first_compile = time.monotonic() - started
    with store.read_meta() as db:
        before = {row["id"]: row["_compiled"]["version"] for row in store._all(db, "servers")}
    started = time.monotonic()
    store.save_policy(policy_data, "synthetic-benchmark", policy["id"])
    unchanged_compile = time.monotonic() - started
    with store.read_meta() as db:
        unchanged = {row["id"]: row["_compiled"]["version"] for row in store._all(db, "servers")}
    assert before == unchanged, "Unchanged effective bundles must retain their version"
    started = time.monotonic()
    with store.lock, store.meta() as db:
        gateway = store._get(db, "servers", identifiers[0])
        gateway["ips"] = ["10.41.0.1"]
        store._put(db, "servers", gateway)
        store.compile_all(db)
    fanout_seconds = time.monotonic() - started
    with store.read_meta() as db:
        after = {row["id"]: row["_compiled"]["version"] for row in store._all(db, "servers")}
        history_count = db.execute("SELECT COUNT(*) FROM bundle_history").fetchone()[0]
    assert all(after[key] == before[key] + 1 for key in identifiers), "Source IP change must update every affected target"
    started = time.monotonic()
    rollout = store.create_managed_rollout({"name": "Synthetic benchmark approval", "server_ids": identifiers}, "synthetic-benchmark")
    first = store.confirm_managed_rollout(rollout["id"], {"confirmation_nonce": rollout["confirmation_nonce"]}, "synthetic-benchmark")
    queued = store.confirm_managed_rollout(rollout["id"], {"confirmation_nonce": first["confirmation_nonce"], "challenge": first["confirmation_phrase"]}, "synthetic-benchmark")
    assert queued["status"] == "queued"
    review_seconds = time.monotonic() - started

    def measure(name, operation):
        def one(index):
            begin = time.monotonic()
            operation(identifiers[index % count])
            return time.monotonic() - begin
        begin = time.monotonic()
        with ThreadPoolExecutor(max_workers=workers) as pool:
            samples = sorted(pool.map(one, range(operations)))
        elapsed = time.monotonic() - begin
        def percentile(percent):
            return round(1000 * samples[min(len(samples) - 1, math.ceil(len(samples) * percent) - 1)], 3)
        return {"operation": name, "requests": operations, "workers": workers, "seconds": round(elapsed, 3),
            "requests_per_second": round(operations / elapsed, 2), "p50_ms": percentile(.5), "p95_ms": percentile(.95), "p99_ms": percentile(.99)}

    def assignment(identifier):
        value, etag = store.assignment(identifier)
        assert value["server_id"] == identifier and value["enforcement"]["authorized"] and etag
    polls = measure("authorized_policy_assignment", assignment)

    # Cached heartbeat resembles the agent's ordinary poll cycle. Source address
    # is unchanged, so it must not trigger whole-fleet policy compilation.
    addresses = {identifier: (["10.41.0.1"] if index == 0 else [f"10.40.{index // 250}.{index % 250 + 1}"]) for index, identifier in enumerate(identifiers)}
    def heartbeat(identifier):
        result = store.report(identifier, {"hostname": identifier, "ips": addresses[identifier],
            "listeners": [], "discovery_performed": False, "control_interval_seconds": 60,
            "firewalld_state": "running", "apply_status": "preview", "applied_version": 0})
        assert result
    heartbeats = measure("cached_inventory_heartbeat", heartbeat)
    return {"at": stamp(), "backend": store.storage_kind, "servers": count, "source_group_size": min(20, count),
        "platform": platform.machine(), "python": platform.python_version(), "seed_seconds": round(seed_seconds, 3),
        "initial_compile_seconds": round(first_compile, 3), "unchanged_compile_seconds": round(unchanged_compile, 3),
        "source_ip_fanout_seconds": round(fanout_seconds, 3), "fanout_hosts": count,
        "immutable_bundle_history_rows": history_count, "review_all_targets_seconds": round(review_seconds, 3),
        "required_policy_checks_per_second_at_60s": round(count / 60, 2),
        "required_reports_per_second_at_60s": round(2 * count / 60, 2), "measurements": [polls, heartbeats],
        "scope": "Synthetic storage/compiler paths; excludes HTTP, mTLS, actual endpoint firewalls, traffic ingest, database failover and soak duration"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", choices=("sqlite", "postgresql"), default="sqlite")
    parser.add_argument("--servers", type=int, default=5000)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--operations", type=int, default=5000)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not 20 <= args.servers <= 20000 or not 1 <= args.workers <= 32 or not 1 <= args.operations <= 100000:
        parser.error("Use 20..20000 servers, 1..32 workers and 1..100000 operations")
    if args.backend == "postgresql":
        import psycopg
        from controller.postgres import PostgresStore
        dsns = [os.environ["SEG_TEST_DATABASE_URL"], os.environ["SEG_TEST_TRAFFIC_DATABASE_URL"]]
        for dsn in dsns:
            with psycopg.connect(dsn) as db:
                if not db.execute("SELECT current_database()").fetchone()[0].startswith("prthak_test_scale_"):
                    raise RuntimeError("Scale benchmark requires isolated prthak_test_scale_ databases")
        result = run(PostgresStore(*dsns), args.servers, args.workers, args.operations)
    else:
        with tempfile.TemporaryDirectory(prefix="prthak-scale-") as directory:
            result = run(Store(directory), args.servers, args.workers, args.operations)
    encoded = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded)
    print(encoded, end="")


if __name__ == "__main__":
    main()
