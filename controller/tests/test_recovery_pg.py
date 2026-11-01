"""Real isolated PG restore/coordinator; fixed host/process actuators are fake.

PRTHAK_RECOVERY_PG_ACCEPTANCE=1, explicit guarded private PostgreSQL fixture only.
No main/demo database, external service or real host actuator is touched.
"""
from contextlib import closing
from datetime import timedelta
from controller.tests import private_pg as pg_fixture

import copy
import json
import os
from pathlib import Path
import secrets
import tempfile
import types
import unittest
from unittest.mock import patch
import uuid

from controller import maintenance, recovery
from controller.platform import PlatformManager
from controller.platform_runtime import migrate_stopped_sqlite
from controller.postgres import Connection, DependencyUnavailable, PostgresStore
from controller.store import Store, now, stamp
from controller.tests.test_recovery import Child, Supervisor
from controller.tests import test_recovery as recovery_fixture

ROOT = Path(__file__).resolve().parents[2]


class FixedHostFixture:
    def __init__(self, test, node):
        self.test, self.node, self.jobs, self.calls = test, node, {}, []
        self.transient_prepare_failures = 0

    def status(self):
        return {"revision": 1, "health": {"status": "observed", "checked_at": now().timestamp(), "quorum_healthy": True, "all_voters_healthy": True, "primary_count": 1, "database_ready": True, "nodes": [{**value, "etcd_healthy": True, "postgres_running": True, "role": "primary" if value["id"] == "node-a" else "replica"} for value in self.test.voters]}}

    def job(self, identifier):
        if identifier not in self.jobs:
            raise KeyError(identifier)
        return self.jobs[identifier]

    def submit(self, request):
        recovery._verify_source_fences(self.test.profile, self.test.control())
        self.calls.append(copy.deepcopy(request))
        phase, identifier = request["phase"], request["restore_id"]
        if phase == "prepare" and self.transient_prepare_failures:
            self.transient_prepare_failures -= 1
            value = {"id": request["request_id"], "status": "error", "error": "Temporary fixed-helper dependency failure fixture"}
            self.jobs[request["request_id"]] = value
            return value
        names = {kind: "prthak_restore_" + identifier + "_" + kind for kind in ("metadata", "traffic")}
        from psycopg.conninfo import conninfo_to_dict
        from controller.store import digest
        result = {"database_names": names, "binding_digest": digest({"restore_id": identifier, "deployment_id": request["deployment_id"], "archive_sha256": request["archive_sha256"], "target_epoch": request["target_epoch"], "fence_digest": request["fence_digest"], "source_databases": {kind: conninfo_to_dict(self.test.profile[kind + "_dsn"])["dbname"] for kind in names}})}
        if phase == "prepare":
            result.update(phase="prepared", prepared=True, hba_reloaded=True)
        elif phase == "create":
            if self.node != "node-a":
                result.update(phase="not_primary", not_primary=True)
            else:
                with self.test.admin() as connection:
                    for kind, name in names.items():
                        self.test.owned_candidates.add(name)
                        connection.execute(self.test.sql.SQL("CREATE DATABASE {} OWNER {} TEMPLATE template0").format(self.test.sql.Identifier(name), self.test.sql.Identifier(self.test.roles[kind])))
                result.update(phase="created", created=True, empty=True, owners_verified=True)
        elif phase in ("verify", "finalize"):
            target = recovery._candidate_profile(self.test.profile, self.test.control())
            for kind in names:
                with closing(recovery._pg_connect(target, kind)) as connection:
                    marker = recovery._raw_marker(connection)
                    if marker["state"] not in ("VERIFIED", "READY") or marker["epoch"] != 2 or marker["import_id"] != identifier:
                        raise AssertionError("real candidate marker not verified")
            if phase == "finalize":
                if request.get("all_profile_acks") is not True or not recovery._all(self.test.control(), "ready"):
                    raise AssertionError("premature profile finalization")
                result.update(phase="finalized", finalized=True, verified=True, revision=2)
            else:
                result.update(phase="verified", verified=True, marker_verified=True, new_connections=True)
        value = {"id": request["request_id"], "status": "completed", "result": result}
        self.jobs[request["request_id"]] = value
        return value


class PGSupervisor(Supervisor):
    def start_child(self, profile):
        recovery.assert_start_allowed(self.manager, profile)
        if not recovery.child_environment(self.manager).get("PRTHAK_RECOVERY_ADMISSION"):
            raise AssertionError("private candidate writer admission missing")
        store = PostgresStore(profile["metadata_dsn"], profile["traffic_dsn"], deployment_id=profile["deployment_id"], epoch=profile["epoch"])
        self.starts.append(store.get("servers", "target"))
        self.child = Child()
        return []


@unittest.skipUnless(os.environ.get("PRTHAK_RECOVERY_PG_ACCEPTANCE") == "1", "Opt in to private PostgreSQL recovery acceptance")
class PostgresRecoveryAcceptance(unittest.TestCase):
    person = recovery_fixture.SQLiteRecoveryTests.person
    plan = recovery_fixture.SQLiteRecoveryTests.plan
    submit = recovery_fixture.SQLiteRecoveryTests.submit
    approve = recovery_fixture.SQLiteRecoveryTests.approve
    queued = recovery_fixture.SQLiteRecoveryTests.queued

    @classmethod
    def setUpClass(cls):
        recovery_fixture.SQLiteRecoveryTests.setUpClass.__func__(cls)
        import psycopg
        from psycopg import sql
        cls.driver, cls.sql = psycopg, sql
        cls.parameters = pg_fixture.parameters()
        with cls.admin() as connection:
            user, directory = connection.execute("SELECT current_user,current_setting('data_directory')").fetchone()
            if user != "prthak_test" or Path(directory).resolve() != pg_fixture.data_directory():
                raise RuntimeError("Refusing recovery fixture outside the private prepared test cluster")

    @classmethod
    def admin(cls):
        return cls.driver.connect(**cls.parameters, dbname="postgres", autocommit=True)

    def setUp(self):
        from psycopg.conninfo import make_conninfo
        recovery_fixture.SQLiteRecoveryTests.setUp(self)
        suffix = secrets.token_hex(4)
        self.names = {kind: "prthak_test_recovery_" + suffix + "_" + kind for kind in ("metadata", "traffic")}
        self.roles = {kind: "prthak_test_recovery_" + suffix + "_" + kind + "_role" for kind in self.names}
        self.password = secrets.token_hex(24)
        self.owned_candidates = set()
        self.addCleanup(self.cleanup_databases)
        with self.admin() as connection:
            for kind, name in self.names.items():
                connection.execute(self.sql.SQL("CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD {}").format(self.sql.Identifier(self.roles[kind]), self.sql.Literal(self.password)))
                connection.execute(self.sql.SQL("CREATE DATABASE {} OWNER {} TEMPLATE template0").format(self.sql.Identifier(name), self.sql.Identifier(self.roles[kind])))
        self.deployment = str(uuid.uuid4())
        self.voters = [{"id": "node-" + letter, "ip": "10.90.0." + str(index + 1), "site": "site-" + letter} for index, letter in enumerate("abc")]
        with self.store.meta() as db:
            self.store._put(db, "maintenance_settings", {"id": "appliance_cluster", "deployment_id": self.deployment, "revision": 1, "voters": self.voters, "members": self.voters})
        parameters = {key: value for key, value in self.parameters.items() if key != "user"}
        dsns = {kind: make_conninfo(**parameters, dbname=name, user=self.roles[kind], password=self.password) for kind, name in self.names.items()}
        migrate_stopped_sqlite(self.directory, dsns["metadata"], dsns["traffic"], self.deployment, 1)
        self.store = PostgresStore(dsns["metadata"], dsns["traffic"], deployment_id=self.deployment, epoch=1)
        for voter in self.voters:
            self.store.register_node({"id": voter["id"], "site": voter["site"], "last_seen": stamp(), "ready": True})
        self.store.approval_tenant_id, self.store.approval_auth_fingerprint = self.config.tenant_id, self.config.fingerprint
        self.manager.app.store = self.store
        self.store.backup_dir = self.manager.root / "backups"
        self.managers, self.supervisors = [], []
        self.profile = {**{kind + "_dsn": value for kind, value in dsns.items()}, "deployment_id": self.deployment, "epoch": 1, "active_revision": 1, "controller_tls": {"cert": str(self.directory / "pki/controller.pem"), "key": str(self.directory / "pki/controller-key.pem"), "ca": str(self.directory / "pki/ca.pem"), "ca_key": str(self.directory / "pki/ca-key.pem")}}
        for index, voter in enumerate(self.voters):
            manager = self.manager if index == 0 else PlatformManager(self.directory / voter["id"])
            manager.local_controller_id(voter["id"], explicit=True)
            manager.commit_active_profile(self.profile)
            manager.recovery_client = FixedHostFixture(self, voter["id"])
            self.managers.append(manager)
            self.supervisors.append(PGSupervisor(manager))
        self.backup = maintenance.backup_create(self.store, self.maker["actor"])
        self.assertTrue(all(member.get("data_hashes") for member in self.store.get("maintenance_backups", self.backup["id"])["members"]))
        self.store.save_policy({**self.changed, "name": "After PostgreSQL backup", "services": [{"port": 8443, "sources": ["10.0.2.2/32"]}]}, self.maker["actor"], self.original["id"])
        self.highwater = self.store.assignment("target")[0]["version"]

    def cleanup_databases(self):
        with self.admin() as connection:
            for name in set(self.names.values()) | self.owned_candidates:
                connection.execute(self.sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(self.sql.Identifier(name)))
            for role in self.roles.values():
                connection.execute(self.sql.SQL("DROP ROLE IF EXISTS {}").format(self.sql.Identifier(role)))

    def control(self):
        with recovery._control(self.profile) as (_, record):
            return copy.deepcopy(record)

    def queue(self):
        identifier = self.queued()
        for manager in self.managers:
            manager.app = None  # Actual long-lived supervisor has no child App.
        return identifier

    def tick_until(self, phase, rounds=35):
        for _ in range(rounds):
            for supervisor in self.supervisors:
                recovery.supervisor_tick(supervisor)
            record = self.control()
            if record["phase"] == phase:
                return record
            if record.get("errors"):
                self.fail("Recovery blocked: " + repr(record["errors"]))
        self.fail("Recovery did not reach " + phase + ": " + repr(self.control()))

    def test_real_pg_pair_restore_and_all_controller_profile_barriers(self):
        identifier = self.queue()
        recovery.supervisor_tick(self.supervisors[0])
        self.assertEqual(self.control()["phase"], "draining")
        with self.assertRaises(DependencyUnavailable):
            with self.store.meta():
                pass
        with self.assertRaises(DependencyUnavailable):
            with self.store.traffic():
                pass
        self.assertEqual(set(self.control()["acks"]["drained"]), {"node-a"})
        result = self.tick_until("completed")
        # Deliver terminal ledger to the peers whose finalize ACK preceded it.
        for supervisor in self.supervisors:
            recovery.supervisor_tick(supervisor)
        self.assertTrue(recovery._all(result, "profile"))
        self.assertTrue(recovery._all(result, "ready"))
        self.assertTrue(recovery._all(result, "finalize", voters=True))
        for manager in self.managers:
            active = manager.active_profile()
            self.assertEqual(active["epoch"], 2)
            restored = PostgresStore(active["metadata_dsn"], active["traffic_dsn"], deployment_id=self.deployment, epoch=2)
            self.assertEqual(restored.get("policies", self.original["id"])["name"], "Current desired intent")
            assignment = restored.assignment("target")[0]
            self.assertGreater(assignment["version"], self.highwater)
            self.assertFalse(assignment["enforcement"]["authorized"])
            self.assertEqual(restored.all("auth_sessions"), [])
            self.assertFalse((manager.root / recovery.LOCAL_FENCE).exists())
        recovery._verify_source_fences(self.profile, result)
        self.assertTrue((recovery._directory(self.manager, identifier) / "original/metadata.dump").is_file())
        self.assertEqual(sum(request["phase"] == "create" for manager in self.managers for request in manager.recovery_client.calls), 1)

    def test_canonical_hashes_detect_same_count_changes_after_uncertain_import(self):
        identifier = self.queue()
        record = self.tick_until("restoring")
        target = recovery._candidate_profile(self.profile, record)
        work = recovery._directory(self.manager, identifier)
        backup = self.backup
        with recovery._control(self.profile, record) as (db, _):
            indexed = Store._get(db, "maintenance_backups", backup["id"])
        staging = work / "uncertain"
        staging.mkdir()
        maintenance._inspect_record(indexed, self.manager.root / "backups" / (backup["id"] + ".zip"), staging)
        member = next(value for value in indexed["members"] if value["kind"] == "metadata")
        recovery._restore_namespace(self.manager, target, record, "metadata", staging / member["name"], member, work)
        with closing(recovery._pg_connect(target, "metadata")) as connection:
            marker = recovery._raw_marker(connection)
            marker.pop("archive_restored")
            connection.execute("UPDATE runtime_deployment SET data=%s WHERE id='active'", (json.dumps(marker),))
            connection.commit()
        with patch("controller.recovery.maintenance._bounded_command", side_effect=AssertionError("Matching committed import must be adopted without re-running DDL")):
            recovery._restore_namespace(self.manager, target, record, "metadata", staging / member["name"], member, work)
        with closing(recovery._pg_connect(target, "metadata")) as connection:
            marker = recovery._raw_marker(connection)
            marker.pop("archive_restored")  # Crash after import COMMIT, before receipt.
            connection.execute("UPDATE runtime_deployment SET data=%s WHERE id='active'", (json.dumps(marker),))
            row = connection.execute("SELECT id,data FROM policies LIMIT 1").fetchone()
            changed = json.loads(row[1]); changed["name"] = "Same counts, different exact content"
            connection.execute("UPDATE policies SET data=%s WHERE id=%s", (json.dumps(changed), row[0]))
            connection.commit()
        with self.assertRaisesRegex(recovery.RecoveryError, "canonical data"):
            recovery._restore_namespace(self.manager, target, record, "metadata", staging / member["name"], member, work)
        recovery._verify_source_fences(self.profile, record)

    def test_more_than_five_transient_host_failures_resume_same_fenced_authority(self):
        identifier = self.queue()
        self.managers[0].recovery_client.transient_prepare_failures = 6
        clock = [now()]
        original_stamp = stamp
        with patch('controller.recovery.now', side_effect=lambda: clock[0]), patch('controller.recovery.stamp', side_effect=lambda value=None: original_stamp(value or clock[0])):
            for _ in range(40):
                for supervisor in self.supervisors:
                    recovery.supervisor_tick(supervisor)
                record = self.control()
                if record['phase'] == 'completed':
                    break
                clock[0] += timedelta(seconds=65)
            else:
                self.fail('Same-authority retries stalled: ' + repr(record))
        prepared = [request for request in self.managers[0].recovery_client.calls if request['phase'] == 'prepare']
        self.assertEqual(len(prepared), 7)
        self.assertEqual(len({request['request_id'] for request in prepared}), 7)
        for key in ('restore_id', 'archive_sha256', 'target_epoch', 'fence_digest', 'deployment_id'):
            self.assertEqual(len({request[key] for request in prepared}), 1, key)
        self.assertEqual(record['recovery_id'], identifier)
        recovery._verify_source_fences(self.profile, record)
        self.assertTrue(recovery._all(record, 'profile'))
        self.assertTrue(recovery._all(record, 'ready'))
        with closing(recovery._pg_connect(self.profile, 'metadata')) as connection:
            self.assertEqual(Store._get(Connection(connection), 'policies', self.original['id'])['name'], 'After PostgreSQL backup')


if __name__ == "__main__":
    unittest.main()
