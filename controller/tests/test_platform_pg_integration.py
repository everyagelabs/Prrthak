"""Opt-in acceptance against the prepared, private local PostgreSQL cluster.

PRTHAK_PLATFORM_PG_ACCEPTANCE=1 enables actual pg_dump/pg_restore and migration.
Only fresh run-specific prthak_test_* databases may be created/reset.
No ordinary deployment, demo, or other HA-test database is touched.
"""
from contextlib import closing
from datetime import timedelta
from controller.tests import private_pg as pg_fixture

import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import subprocess
import tempfile
import unittest
import uuid
import zipfile

from controller import learning_policies, maintenance, platform_runtime as runtime
from controller.postgres import DependencyUnavailable, PostgresStore
from controller.store import Store, digest, now, stamp


ROOT = Path(__file__).resolve().parents[2]
DATABASES = pg_fixture.names("platform")


@unittest.skipUnless(os.environ.get("PRTHAK_PLATFORM_PG_ACCEPTANCE") == "1", "Opt in to private PostgreSQL platform acceptance")
class PlatformPostgresAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import make_conninfo
        cls.driver, cls.sql = psycopg, sql
        cls.parameters = pg_fixture.parameters()
        with psycopg.connect(**cls.parameters, dbname="postgres", autocommit=True) as connection:
            user, directory, version = connection.execute("SELECT current_user,current_setting('data_directory'),version()").fetchone()
            if user != "prthak_test" or Path(directory).resolve() != pg_fixture.data_directory():
                raise RuntimeError("Refusing to change a database outside the prepared private platform test cluster")
            cls.version = version
            for database in DATABASES.values():
                if connection.execute("SELECT 1 FROM pg_database WHERE datname=%s", (database,)).fetchone():
                    raise RuntimeError("Refusing to reuse a pre-existing private fixture database")
                connection.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(database)))
        cls.dsns = {namespace: make_conninfo(**cls.parameters, dbname=name) for namespace, name in DATABASES.items()}
        cls.evidence = []
        cls.addClassCleanup(cls._write_evidence)

    @classmethod
    def _write_evidence(cls):
        result = {"postgresql": cls.version, "databases": DATABASES, "evidence": cls.evidence}
        path = pg_fixture.evidence_path("platform-pg-acceptance.json")
        path.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
        path.chmod(0o600)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.deployment = str(uuid.uuid4())
        self.profile = {"metadata_dsn": self.dsns["metadata"], "traffic_dsn": self.dsns["traffic"], "deployment_id": self.deployment, "epoch": 1, "active_revision": 1}
        self._reset_targets()
        self.addCleanup(self._reset_targets)

    def _reset_targets(self):
        for namespace, dsn in self.dsns.items():
            with self.driver.connect(dsn, autocommit=True) as connection:
                self.assertEqual(connection.execute("SELECT current_database()").fetchone()[0], DATABASES[namespace])
                connection.execute("DROP SCHEMA public CASCADE")
                connection.execute("CREATE SCHEMA public")

    def _bound(self, initialize=False):
        store = PostgresStore(self.dsns["metadata"], self.dsns["traffic"], deployment_id=self.deployment, epoch=1, initialize=initialize)
        store.lab_approvals = True  # Explicit legacy, isolated migration fixture.
        return store

    def _migrate(self, source):
        return runtime.migrate_stopped_sqlite(source.path, self.dsns["metadata"], self.dsns["traffic"], self.deployment, 1)

    def _source(self, directory="source", pending=True):
        store = Store(self.directory / directory)
        self._populate_valid(store, pending)
        return store

    def _populate_valid(self, store, pending=True):
        store.lab_approvals = True  # Fixture proves persistence, not independent production approval.
        baseline = {"management_sources": ["10.99.0.0/24"], "ssh_ports": [2022], "controller_url": "https://controller.example:8787", "management_probe_url": "https://controller.example:8787/api/v1/agent/enforcement/check", "zone": "public"}
        report = {"hostname": "acceptance-app", "ips": ["10.70.0.11"], "listeners": [{"port": port, "protocol": "tcp", "address": "0.0.0.0", "process": process, "service": service} for port, process, service in ((2022, "sshd", "SSH"), (80, "nginx", "HTTP"), (443, "nginx", "HTTPS"))], "firewalld_state": "running", "discovery_performed": True, "discovered_at": stamp(), "agent_version": "0.9.0", "capabilities": ["learning_discovery_v1", "learning_auto_allow_v1","traffic_capture_v1"], "protection": {**baseline, "digest": digest(baseline), "ready": True, "blockers": []}}
        store.report("acceptance-app", report)
        policy = store.save_policy({"name": "Preserve policy history", "selector": {}, "mode": "monitor", "services": [{"port": 443, "protocol": "tcp", "sources": ["10.50.0.0/24"]}]}, "acceptance-admin")
        store.save_policy({**policy, "services": [{"port": 443, "protocol": "tcp", "sources": ["10.51.0.0/24"]}]}, "acceptance-admin", policy["id"])
        session = store.create_session({"server_ids": ["acceptance-app"], "selection_mode": "discovered", "policy_action": "auto_allow", "auto_allow_confirmed": True, "port_filter": [{"port": 443, "protocol": "tcp"}]}, "acceptance-admin")
        store.report("acceptance-app", {**report, "discovered_at": stamp(), "learning_discovery_session_ids": [session["id"]]})
        def batch(identifier, source, count):
            from controller.tests.capture_fixture import typed_event
            at = stamp()
            return {"session_id": session["id"], "batch_id": identifier, "events": [typed_event(source,443,identity=session['id']+identifier+str(index),at=at) for index in range(count)]}
        processed = batch("processed-before-migration", "10.50.0.5", 7)
        store.enqueue_flows("acceptance-app", processed)
        store.process_flows()
        overlay = store.assignment("acceptance-app")[0]["learning_allow"]
        store.report("acceptance-app", {**report, "discovery_performed": False, "learning_allow_outcome": {"generation": overlay["generation"], "digest": overlay["digest"], "binding_digest": overlay["binding_digest"], "status": "applied", "applied_generation": overlay["generation"], "applied_digest": overlay["digest"]}})
        queued = batch("pending-after-migration", "10.50.0.6", 5)
        if pending:
            store.enqueue_flows("acceptance-app", queued)
        with store.meta() as db:
            store._put(db, "auth_users", {"id": "preserved-account", "oid": "preserved-oid", "role": "super_admin", "disabled": False})
        return {"session": session, "policy": policy, "processed": processed, "queued": queued, "overlay": overlay}

    def test_every_allowlisted_table_and_specialized_column_roundtrip_exactly(self):
        source = Store(self.directory / "all-tables")
        at, expiry = stamp(), stamp(now() + timedelta(hours=1))
        for namespace, tables in (("metadata", runtime.META_TABLES), ("traffic", runtime.TRAFFIC_TABLES)):
            with (source.meta() if namespace == "metadata" else source.traffic()) as db:
                for table in tables:
                    if table == "controller_nodes":
                        db.execute("CREATE TABLE IF NOT EXISTS controller_nodes(id TEXT PRIMARY KEY,data TEXT NOT NULL)")
                    columns = runtime._columns(table)
                    key = 73 if table == "flows" else "fixture-" + table
                    payload = json.dumps({"id": key, "fixture": table, "version": 17, "revision": 11, "unicode": "पृथक्", "retained": {"source": "10.40.0.8/32", "port": 443}}, sort_keys=True)
                    values = {"id": key, "data": payload, "server_id": "preserve-endpoint", "session_id": "preserve-session", "version": 17, "revision": 11, "digest": "d" * 64, "protection_digest": "p" * 64, "created_at": at, "expires_at": expiry, "approval_id": "preserve-approval", "active": 1, "policy_id": "preserve-policy", "service_group_id": "preserve-service", "source_ip": "10.40.0.8", "event_time": at, "received_at": at, "batch_key": "preserve-batch", "processed": 0, "evidence_processed": 0, "event_index": 0, "port": 443, "protocol": "tcp", "verdict": "observed", "count": 9, "first_seen": at, "last_seen": at, "event_id": "preserve-event", "channel_id": "preserve-channel", "status": "pending", "next_attempt_at": at, "lease_until": None}
                    values.update(monitor_id="8e6b8d7b-7cb5-484f-8200-83a1f3f9a166", enabled=1,
                                  event_digest="e" * 64,capture_kind="legacy_log",capture_backend="journal",count_unit="log_records",address_family="ipv4",capture_processed=1,capture_expires_at=expiry)
                    values.update(deadline_at=expiry, deployment_id="preserve-deployment", apply_status="pending", traffic_status="awaiting_apply")
                    db.execute(f'INSERT INTO "{table}" ({",".join(columns)}) VALUES ({",".join("?" for _ in columns)})', tuple(values[column] for column in columns))
        result = self._migrate(source)
        target = self._bound()
        backup = source.path / result["backup_name"]
        for namespace, context, filename in (("metadata", target.read_meta, "inventory.sqlite3"), ("traffic", target.read_traffic, "traffic.sqlite3")):
            source_rows = runtime._source_rows(backup / filename, namespace)
            with context() as db:
                for table, original in source_rows.items():
                    columns = runtime._columns(table)
                    actual = db.execute(f'SELECT {",".join(columns)} FROM "{table}"').fetchall()
                    self.assertEqual([tuple(row[index] for index in range(len(columns))) for row in actual], original, table)
                    self.assertEqual(result["proof"][namespace]["counts"][table], 1, table)
            self.assertEqual(len(source_rows), len(runtime.META_TABLES if namespace == "metadata" else runtime.TRAFFIC_TABLES))
        with target.traffic() as db:
            identifier = db.execute("INSERT INTO flows(batch_key,event_index,server_id,session_id,source_ip,port,protocol,verdict,count,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?,?,?,?) RETURNING id", ("next-batch", 0, "preserve-endpoint", "preserve-session", "10.40.0.9", 443, "tcp", "observed", 1, at, at)).fetchone()[0]
        self.assertEqual(identifier, 74)
        self.assertEqual(target.readiness(), {"metadata": True, "traffic": True})
        self.evidence.append({"test": "all_fixed_tables", "metadata_tables": len(runtime.META_TABLES), "traffic_tables": len(runtime.TRAFFIC_TABLES), "each_table_rows": 1, "preserved_flow_id": 73, "next_flow_id": identifier, "canonical_hashes_verified": True})

    def test_real_state_policy_versions_receipts_and_pending_queue_continue_after_migration(self):
        source = Store(self.directory / "valid-state")
        fixture = self._populate_valid(source)
        before = source.assignment("acceptance-app")[0]
        result = self._migrate(source)
        target = self._bound(initialize=True)
        after = target.assignment("acceptance-app")[0]
        self.assertEqual((after["version"], after["digest"], after["learning_allow"]["generation"], after["learning_allow"]["digest"]), (before["version"], before["digest"], before["learning_allow"]["generation"], before["learning_allow"]["digest"]))
        self.assertEqual([item["revision"] for item in target.policy_revisions(fixture["policy"]["id"])], [2, 1])
        self.assertEqual(target.get("auth_users", "preserved-account")["oid"], "preserved-oid")
        self.assertTrue(target.enqueue_flows("acceptance-app", fixture["processed"])["duplicate"])
        self.assertEqual(target.process_flows(), 1)
        self.assertEqual(target.process_flows(), 0)
        rows = learning_policies.recommendations(target, fixture["session"]["id"])["rows"]
        self.assertEqual({row["source_ip"]: row["count"] for row in rows}, {"10.50.0.5": 7, "10.50.0.6": 5})
        self.assertEqual(target.assignment("acceptance-app")[0]["learning_allow"]["services"], [{"port": 443, "protocol": "tcp", "sources": ["10.50.0.5/32", "10.50.0.6/32"]}])
        with target.read_traffic() as db:
            self.assertEqual([tuple(row[index] for index in range(3)) for row in db.execute("SELECT processed,evidence_processed,COUNT(*) FROM batches GROUP BY processed,evidence_processed").fetchall()], [(1, 1, 2)])
        with target.read_meta() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM learning_evidence_receipts").fetchone()[0], 2)
        for context in (source.meta, source.traffic):
            with self.assertRaises(runtime.RuntimeSafetyError):
                with context():
                    self.fail("Retired SQLite source reopened")
        with self.assertRaises(runtime.RuntimeSafetyError):
            Store(source.path)
        self.assertEqual(json.loads((source.path / runtime.FENCE_NAME).read_text())["state"], "RETIRED")
        self.evidence.append({"test": "valid_state_continues", "bundle_version": before["version"], "policy_revisions": [2, 1], "learning_receipts": 2, "processed_batches": 2, "flow_hits": 12, "retired_sqlite_blocked": True, "table_hashes": sum(len(value["hashes"]) for value in result["proof"].values())})

    def test_postgres_backup_catalogue_validation_and_actual_isolated_restore(self):
        store = PostgresStore(self.dsns["metadata"], self.dsns["traffic"])
        fixture = self._populate_valid(store, pending=False)
        store.backup_dir = self.directory / "private-backups"
        store.pg_dump_path, store.pg_restore_path = shutil.which("pg_dump"), shutil.which("pg_restore")
        backup = maintenance.backup_create(store, "acceptance-super-admin")
        path = maintenance.backup_download(store, backup["id"])
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
        manifest = maintenance.backup_inspect(store, backup["id"])["manifest"]
        self.assertTrue(backup["verified"])
        self.assertNotIn("path", backup)
        self.assertTrue(maintenance.restore_validate(store, backup["id"], "acceptance-super-admin")["valid"])
        staging = self.directory / "offline-restore"
        staging.mkdir(mode=0o700)
        with zipfile.ZipFile(path) as archive:
            self.assertEqual(set(archive.namelist()), {"metadata.dump", "traffic.dump", "manifest.json"})
            for member in manifest["members"]:
                content = archive.read(member["name"])
                self.assertTrue(content.startswith(b"PGDMP"))
                (staging / member["name"]).write_bytes(content)
                self.assertEqual(len(member["schema_digest"]), 64)
        self._reset_targets()
        for member in manifest["members"]:
            namespace = member["kind"]
            environment = maintenance._pg_environment(self.dsns[namespace])
            try:
                result = subprocess.run([store.pg_restore_path, "--no-owner", "--no-privileges", "--exit-on-error", "--dbname", DATABASES[namespace], str(staging / member["name"])], env=environment, stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 0, "Actual isolated PostgreSQL restore failed")
            finally:
                environment.clear()
            with self.driver.connect(self.dsns[namespace]) as db:
                for table, count in member["tables"].items():
                    self.assertEqual(db.execute(self.sql.SQL("SELECT COUNT(*) FROM {}").format(self.sql.Identifier(table))).fetchone()[0], count, table)
        restored = PostgresStore(self.dsns["metadata"], self.dsns["traffic"], initialize=False)
        self.assertEqual(restored.get("auth_users", "preserved-account")["oid"], "preserved-oid")
        self.assertEqual(learning_policies.recommendations(restored, fixture["session"]["id"])["rows"][0]["count"], 7)
        self.evidence.append({"test": "actual_pg_dump_restore", "archive_mode": "0600", "directory_mode": "0700", "components": [member["name"] for member in manifest["members"]], "restored_metadata_tables": len(manifest["members"][0]["tables"]), "restored_traffic_tables": len(manifest["members"][1]["tables"]), "all_manifest_counts_match": True})

    def test_managed_markers_block_new_and_preexisting_unbound_legacy_stores(self):
        legacy = PostgresStore(self.dsns["metadata"], self.dsns["traffic"])
        self.assertEqual(legacy.readiness(), {"metadata": True, "traffic": True})
        self._migrate(self._source(pending=False))
        with self.assertRaises(DependencyUnavailable):
            PostgresStore(self.dsns["metadata"], self.dsns["traffic"], initialize=False)
        for context in (legacy.meta, legacy.traffic, legacy.read_meta, legacy.read_traffic):
            with self.assertRaises(DependencyUnavailable):
                with context():
                    self.fail("An unbound legacy store accessed managed storage")
        with self.assertRaises(DependencyUnavailable):
            legacy.run_job("health", lambda: self.fail("Unbound background job ran"))
        self.assertEqual(legacy.readiness(), {"metadata": False, "traffic": False})
        self.assertEqual(self._bound().readiness(), {"metadata": True, "traffic": True})
        self.evidence.append({"test": "legacy_bypass_closed", "constructor_transactions_reads_jobs_readiness_guarded": True})

    def test_stale_uuid_epoch_and_changed_import_fail_closed(self):
        self._migrate(self._source(pending=False))
        for deployment, epoch in ((str(uuid.uuid4()), 1), (self.deployment, 2)):
            with self.assertRaises(runtime.RuntimeSafetyError):
                PostgresStore(self.dsns["metadata"], self.dsns["traffic"], deployment_id=deployment, epoch=epoch, initialize=False)
        target = self._bound()
        with self.driver.connect(self.dsns["traffic"]) as db:
            old = json.loads(db.execute("SELECT data FROM runtime_deployment WHERE id='active'").fetchone()[0])
            db.execute("UPDATE runtime_deployment SET data=%s WHERE id='active'", (json.dumps({**old, "epoch": 2}),))
        self.assertEqual(target.readiness(), {"metadata": True, "traffic": False})
        with self.assertRaises(DependencyUnavailable):
            with target.traffic():
                self.fail("Stale epoch accepted")
        with self.driver.connect(self.dsns["traffic"]) as db:
            db.execute("UPDATE runtime_deployment SET data=%s WHERE id='active'", (json.dumps(old),))
        with self.driver.connect(self.dsns["metadata"]) as db:
            marker = json.loads(db.execute("SELECT data FROM runtime_deployment WHERE id='active'").fetchone()[0])
            db.execute("UPDATE runtime_deployment SET data=%s WHERE id='active'", (json.dumps({**marker, "import_id": "changed-import"}),))
        with self.assertRaises(DependencyUnavailable):
            with target.meta():
                self.fail("A changed import accepted")
        self.evidence.append({"test": "identity_guards", "stale_uuid_epoch_import_rejected": True})

    def test_nonempty_or_foreign_target_does_not_fence_the_original_source(self):
        target = PostgresStore(self.dsns["metadata"], self.dsns["traffic"])
        target.report("keep-target", {"hostname": "keep-target", "ips": [], "listeners": []})
        source = self._source(pending=False)
        with self.assertRaises(runtime.RuntimeSafetyError):
            self._migrate(source)
        self.assertFalse((source.path / runtime.FENCE_NAME).exists())
        self.assertEqual(source.server("acceptance-app")["id"], "acceptance-app")
        self.assertEqual(target.server("keep-target")["id"], "keep-target")
        self._reset_targets()
        with self.driver.connect(self.dsns["metadata"]) as db:
            db.execute("CREATE TABLE runtime_deployment(id TEXT PRIMARY KEY,data TEXT NOT NULL)")
            db.execute("INSERT INTO runtime_deployment VALUES('active',%s)", (json.dumps({"deployment_id": str(uuid.uuid4()), "epoch": 1, "namespace": "metadata", "state": "READY"}),))
        with self.assertRaises(runtime.RuntimeSafetyError):
            self._migrate(source)
        self.assertFalse((source.path / runtime.FENCE_NAME).exists())
        self.assertEqual(source.server("acceptance-app")["id"], "acceptance-app")
        self.evidence.append({"test": "unsafe_targets_refused", "source_unfenced_and_usable": True, "target_host_preserved": True})

    def test_join_rejects_business_data_and_preserves_blank_local_accounts_without_merging(self):
        self._migrate(self._source(pending=False))
        populated = Store(self.directory / "populated-joiner")
        populated.report("keep-local", {"hostname": "keep-local", "ips": [], "listeners": []})
        with self.assertRaises(runtime.RuntimeSafetyError):
            runtime.join_stopped_sqlite(populated.path, {**self.profile, "join_preserve_local_snapshot": True})
        self.assertFalse((populated.path / runtime.FENCE_NAME).exists())
        self.assertEqual(populated.server("keep-local")["id"], "keep-local")
        blank = Store(self.directory / "blank-joiner")
        with blank.meta() as db:
            blank._put(db, "auth_users", {"id": "local-bootstrap-only", "role": "super_admin"})
        with self.assertRaises(runtime.RuntimeSafetyError):
            runtime.join_stopped_sqlite(blank.path, self.profile)
        self.assertFalse((blank.path / runtime.FENCE_NAME).exists())
        result = runtime.join_stopped_sqlite(blank.path, {**self.profile, "join_preserve_local_snapshot": True})
        self.assertEqual(result["copied_rows"], 0)
        with closing(sqlite3.connect(blank.path / result["backup_name"] / "inventory.sqlite3")) as db:
            self.assertEqual(db.execute("SELECT id FROM auth_users").fetchall(), [("local-bootstrap-only",)])
        with self.assertRaises(KeyError):
            self._bound().get("auth_users", "local-bootstrap-only")
        with self.assertRaises(runtime.RuntimeSafetyError):
            Store(blank.path)
        self.evidence.append({"test": "join_guard", "populated_joiner_usable_after_refusal": True, "setup_account_snapshot_preserved": True, "merged_rows": 0})

    def test_finished_migration_replays_without_duplication_and_refuses_later_remote_writes(self):
        source = self._source(pending=False)
        first = self._migrate(source)
        second = self._migrate(source)
        self.assertEqual((first["import_id"], first["source_fingerprint"], first["proof"]), (second["import_id"], second["source_fingerprint"], second["proof"]))
        target = self._bound()
        target.audit("acceptance.after_activation", "acceptance-admin", {"must_survive": True})
        with self.assertRaises(runtime.RuntimeSafetyError):
            self._migrate(source)
        self.assertTrue(any(row["action"] == "acceptance.after_activation" for row in target.all("audit")))
        self.assertEqual(target.readiness(), {"metadata": True, "traffic": True})
        with self.assertRaises(runtime.RuntimeSafetyError):
            Store(source.path)
        self.evidence.append({"test": "migration_retry", "same_import_no_duplicates": True, "post_activation_writes_never_overwritten": True})


if __name__ == "__main__":
    unittest.main()
