"""Complete traffic scopes, independent of bounded overview/navigation pages."""
from contextlib import contextmanager
from datetime import timedelta
from email.message import Message
import csv
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from controller import traffic_views
from controller.app import App, handler_for
from controller.store import Store, now, parse_time, stamp
from controller.tests import private_pg


class TrafficPageChecks:
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.store = self.make_store()
        self.at = parse_time(stamp()) - timedelta(seconds=5)
        self.sequence = 0

    def make_store(self):
        return Store(self.temp.name)

    def flow(self, *, server="billing", source="192.0.2.10", port=443, protocol="tcp", count=1,
             at=None, kind="accepted_connection", backend="conntrack", unit="connections", family="ipv4", verdict="allowed", processed=1, session="learn-one"):
        self.sequence += 1
        value = ("batch-" + str(self.sequence), 0, server, session, source, port, protocol, verdict, count,
                 stamp(at or self.at), stamp(at or self.at), kind, backend, unit, family, processed)
        with self.store.traffic() as db:
            db.execute("INSERT INTO flows(batch_key,event_index,server_id,session_id,source_ip,port,protocol,verdict,count,first_seen,last_seen,capture_kind,capture_backend,count_unit,address_family,capture_processed) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", value)

    def test_matching_old_relationship_is_found_after_more_than500_newer_unrelated_rows(self):
        self.flow(source="192.0.2.99", count=3, at=self.at-timedelta(minutes=20))
        for index in range(601):
            self.flow(server="payments", source=f"198.51.{index//255}.{index%255}", port=22)
        page = traffic_views.listing(self.store, {"server_ids": ["billing"], "ports": ["443/tcp"]})
        self.assertEqual((page["total"], page["endpoint_count"], len(page["items"])), (1, 1, 1))
        self.assertEqual(page["items"][0]["source_ip"], "192.0.2.99")
        self.assertEqual(page["counts_by_unit"], {"connections": 3, "packets": 0, "log_records": 0, "sample_minutes": 0})
        self.assertTrue(page["filter_before_pagination"])

    def test_every_relationship_can_be_paged_in_stable_tie_order(self):
        for index in range(507):
            self.flow(source=f"198.51.{index//255}.{index%255}")
        ids, as_of = [], None
        for offset in range(0, 507, 100):
            query = {"limit": 100, "offset": offset, **({"as_of": as_of} if as_of else {})}
            page = traffic_views.listing(self.store, query)
            as_of = page["as_of"]
            self.assertEqual(page["total"], 507)
            self.assertEqual(page["has_more"], offset+len(page["items"]) < 507)
            ids += [item["source_ip"] for item in page["items"]]
        self.assertEqual(len(set(ids)), 507)
        self.assertEqual(ids, sorted(ids))

    def test_filters_combine_metadata_scope_ports_protocol_and_literal_search_before_counting(self):
        self.flow(source="192.0.2.44")
        self.flow(source="192.0.2.45", protocol="udp")
        self.flow(source="192.0.2.46", port=8443)
        self.flow(source="192.0.2.47", server="payments")
        query = {"server_ids": ["billing"], "ports": ["443/tcp", "8443/tcp"]}
        self.assertEqual(traffic_views.listing(self.store, query)["total"], 2)
        self.assertEqual(traffic_views.listing(self.store, {**query, "search": "192.0.2.44"})["total"], 1)
        self.assertEqual(traffic_views.listing(self.store, {**query, "search": "%_"})["total"], 0)
        self.assertEqual(traffic_views.listing(self.store, {**query, "search": "billing", "search_server_ids": ["billing"]})["total"], 2)
        self.assertEqual(traffic_views.listing(self.store, {"server_ids": []})["total"], 0)

    def test_traffic_discovery_scope_filters_totals_pages_and_csv_without_changing_global_flows(self):
        with self.store.meta() as db:
            for identifier, purpose in (("discovery", "traffic"), ("policy", "policy"), ("legacy", None)):
                session = {"id": identifier, "status": "active", "server_ids": ["billing", "payments"],
                           "starts_at": stamp(self.at-timedelta(minutes=10)),
                           "expires_at": stamp(self.at+timedelta(minutes=10))}
                if purpose is not None:
                    session["purpose"] = purpose
                self.store._put(db, "sessions", session)
        self.flow(session="policy", source="192.0.2.11", count=40)
        self.flow(session="legacy", source="192.0.2.12", count=30)
        self.flow(session="missing", source="192.0.2.13", count=20)
        self.flow(session="discovery", source="192.0.2.14", at=self.at-timedelta(seconds=10), count=3)
        self.flow(session="discovery", source="192.0.2.15", at=self.at-timedelta(seconds=20), count=4)
        self.flow(session="discovery", source="192.0.2.16", port=8443, count=8)
        self.flow(session="discovery", source="192.0.2.17", server="payments", count=9)

        scope = {"purpose": "traffic", "server_ids": ["billing"], "ports": ["443/tcp"]}
        first = traffic_views.listing(self.store, {**scope, "limit": 1})
        self.assertEqual((first["purpose"], first["total"], first["endpoint_count"], first["has_more"]), ("traffic", 2, 1, True))
        self.assertEqual(first["counts_by_unit"]["connections"], 7)
        self.assertEqual(first["items"][0]["source_ip"], "192.0.2.14")
        second = traffic_views.listing(self.store, {**scope, "limit": 1, "offset": 1, "as_of": first["as_of"]})
        self.assertEqual((second["items"][0]["source_ip"], second["has_more"]), ("192.0.2.15", False))
        with traffic_views.csv_spool(self.store, {**scope, "as_of": first["as_of"]}, max_rows=2) as (output, _):
            exported = list(csv.DictReader(io.StringIO(output.read().decode("utf-8-sig"))))
        self.assertEqual([(row["session_id"], row["source_ip"]) for row in exported],
                         [("discovery", "192.0.2.14"), ("discovery", "192.0.2.15")])
        global_page = traffic_views.listing(self.store)
        self.assertNotIn("purpose", global_page)
        self.assertEqual(global_page["total"], 7)
        self.assertEqual({row["session_id"] for row in self.store.flows()}, {"discovery", "policy", "legacy", "missing"})

    def test_typed_units_sessions_protocols_and_historical_metadata_never_collapse(self):
        self.flow(count=2)
        self.flow(count=3)
        self.flow(kind="denied_packet", backend="nflog", unit="packets", verdict="denied", count=7)
        self.flow(kind="legacy_log", backend="journal", unit="log_records", verdict="observed", count=11, family="")
        self.flow(kind="legacy_log", backend="journal", unit="log_records", verdict="observed", count=13)
        self.flow(session="learn-two")
        self.flow(protocol="udp")
        self.flow(source="2001:db8::10", family="ipv6")
        page = traffic_views.listing(self.store)
        self.assertEqual(page["total"], 6)
        self.assertEqual(page["counts_by_unit"], {"connections": 8, "packets": 7, "log_records": 24, "sample_minutes": 0})
        legacy = [item for item in page["items"] if item["count_unit"] == "log_records"]
        self.assertEqual(len(legacy), 1)
        self.assertEqual((legacy[0]["count"], legacy[0]["address_family"]), (24, "ipv4"))

    def test_window_pending_processing_and_future_rows_are_not_published(self):
        self.flow()
        self.flow(source="192.0.2.2", processed=0)
        self.flow(source="192.0.2.3", at=self.at-timedelta(hours=2))
        self.flow(source="192.0.2.4", at=now()+timedelta(seconds=20))
        page = traffic_views.listing(self.store)
        self.assertEqual((page["total"], page["items"][0]["source_ip"]), (1, "192.0.2.10"))

    def test_count_and_rows_use_one_read_snapshot_but_later_queries_can_see_late_records(self):
        self.flow()
        original = self.store.read_traffic
        owner, fired = self, [False]
        @contextmanager
        def intercepted():
            with original() as db:
                class Bridge:
                    dialect = getattr(db, "dialect", "sqlite")
                    def execute(self, sql, args=()):
                        if " ORDER BY " in sql and not fired[0]:
                            fired[0] = True
                            owner.flow(source="192.0.2.11")
                        return db.execute(sql, args)
                yield Bridge()
        with patch.object(self.store, "read_traffic", intercepted):
            page = traffic_views.listing(self.store)
        self.assertEqual((page["total"], len(page["items"])), (1, 1))
        later = traffic_views.listing(self.store, {"as_of": page["as_of"]})
        self.assertEqual(later["total"], 2)
        self.assertIn("late uploads", later["coverage"])

    def test_complete_csv_preserves_scope_pairs_units_times_and_escapes_spreadsheet_formulas(self):
        for index in range(507):
            self.flow(source=f"198.51.{index//255}.{index%255}")
        self.flow(server="payments", port=22)
        self.flow(server="=formula", kind="denied_packet", backend="nflog", unit="packets", verdict="denied")
        with traffic_views.csv_spool(self.store, {"server_ids": ["billing"], "ports": ["443/tcp"]}) as (output, size):
            self.assertEqual(os.fstat(output.fileno()).st_mode & 0o777, 0o600)
            raw = output.read()
            self.assertEqual(len(raw), size)
            records = list(csv.DictReader(io.StringIO(raw.decode("utf-8-sig"))))
        self.assertEqual(len(records), 507)
        self.assertTrue(all(row["server_id"] == "billing" and row["port"] == "443" and row["count_unit"] == "connections" and row["first_seen"] == row["last_seen"] for row in records))
        with traffic_views.csv_spool(self.store, {"server_ids": ["=formula"]}) as (output, _):
            record = next(csv.DictReader(io.StringIO(output.read().decode("utf-8-sig"))))
        self.assertEqual((record["server_id"], record["count_unit"]), ("'=formula", "packets"))

    def test_export_never_yields_silently_truncated_data_and_releases_private_spool_and_slot(self):
        self.flow(); self.flow(source="192.0.2.11")
        opened, real = [], tempfile.TemporaryFile
        def track(*args, **kwargs):
            value = real(*args, **kwargs); opened.append(value); return value
        with patch.object(traffic_views.tempfile, "TemporaryFile", side_effect=track):
            for bounds in ({"max_rows": 1}, {"max_bytes": 4}):
                with self.subTest(bounds=bounds), self.assertRaisesRegex(ValueError, "Complete traffic CSV"):
                    with traffic_views.csv_spool(self.store, **bounds):
                        self.fail("An incomplete export must never be yielded")
        self.assertTrue(all(file.closed for file in opened))
        with traffic_views.csv_spool(self.store) as (output, size):
            self.assertEqual(len(output.read()), size)
        with patch.object(traffic_views.EXPORT_SLOTS, "acquire", return_value=False), self.assertRaises(traffic_views.ExportBusy):
            with traffic_views.csv_spool(self.store):
                self.fail("Busy export must not allocate a spool")

    def test_strict_fields_bounds_and_parameters_refuse_invalid_queries(self):
        for query in ({"limit": True}, {"limit": 101}, {"offset": -1}, {"window_seconds": 1}, {"window_seconds": 1000000}, {"server_ids": "billing"}, {"server_ids": [None]}, {"ports": ["65536/tcp"]}, {"ports": ["443/sctp"]}, {"search": "x"*257}, {"search": None}, {"sql": "delete"}, {"purpose": "policy"}, {"purpose": None}, {"as_of": stamp(now()+timedelta(seconds=20))}):
            with self.subTest(query=query), self.assertRaises(ValueError):
                traffic_views.listing(self.store, query)
        with self.assertRaises(ValueError):
            with traffic_views.csv_spool(self.store, {"limit": 10}):
                self.fail("Exports must not inherit page limits")


class SQLiteTrafficPages(TrafficPageChecks, unittest.TestCase):
    def test_read_only_api_query_export_authentication_and_mutation_boundaries(self):
        self.flow()
        self.store.report("billing", {"hostname": "billing-api", "ips": ["10.1.0.7", "2001:db8::7"], "listeners": [{"port": 443, "protocol": "tcp"}, {"port": 8443, "protocol": "tcp"}]})
        self.store.report("payments", {"hostname": "payments", "ips": ["10.1.0.8"]})
        app = App(self.store, tokens={"read_only": "reader"})
        def request(method, path, body=None, token="reader"):
            handler = object.__new__(handler_for(app))
            handler.command, handler.path, handler.connection = method, path, object()
            handler.client_address = ("127.0.0.1", 12345)
            handler.headers = Message()
            if token:
                handler.headers["Authorization"] = "Bearer " + token
            handler.body = lambda: body
            handler.wfile = io.BytesIO()
            captured = {}
            handler.response = lambda status, value=None, headers=None: captured.update(status=status, value=value)
            handler.send_response = lambda status: captured.update(status=status)
            handler.send_header = lambda name, value: captured.setdefault("headers", {}).update({name: value})
            handler.end_headers = lambda: None
            handler.dispatch()
            captured["bytes"] = handler.wfile.getvalue()
            return captured
        query = request("POST", "/api/v1/flows/query", {"server_ids": ["billing"], "ports": ["443/tcp"]})
        self.assertEqual((query["status"], query["value"]["total"]), (200, 1))
        scoped = request("POST", "/api/v1/flows/query", {"purpose": "traffic"})
        self.assertEqual((scoped["status"], scoped["value"]["purpose"], scoped["value"]["total"]), (200, "traffic", 0))
        export = request("POST", "/api/v1/flows/export.csv", {"server_ids": ["billing"]})
        self.assertEqual(export["status"], 200)
        self.assertIn("text/csv", export["headers"]["Content-Type"])
        records = list(csv.DictReader(io.StringIO(export["bytes"].decode("utf-8-sig"))))
        self.assertEqual((len(records), records[0]["source_ip"]), (1, "192.0.2.10"))
        self.assertEqual(records[0]["destination_hostname"], "billing-api")
        self.assertEqual(records[0]["destination_reported_ips"], "10.1.0.7; 2001:db8::7")
        inventory = request("POST", "/api/v1/servers/export.csv", {"server_ids": ["billing"]})
        self.assertEqual(inventory["status"], 200)
        self.assertEqual(inventory["headers"]["Cache-Control"], "no-store")
        servers = list(csv.DictReader(io.StringIO(inventory["bytes"].decode("utf-8-sig"))))
        self.assertEqual({(row["hostname"], row["listening_port"], row["agent_reported_ips"]) for row in servers},
                         {("billing-api", "443", "10.1.0.7; 2001:db8::7"), ("billing-api", "8443", "10.1.0.7; 2001:db8::7")})
        self.assertEqual(request("POST", "/api/v1/servers/export.csv", {"server_ids": []}, token=None)["status"], 401)
        self.assertEqual(request("POST", "/api/v1/policies/export.csv", {"kind": "managed"})["status"], 200)
        self.assertEqual(request("POST", "/api/v1/policies/export.csv", {"kind": "managed"}, token=None)["status"], 401)
        self.assertEqual(request("POST", "/api/v1/policies/export.csv", {"kind": "managed", "limit": 10})["status"], 400)
        self.assertEqual(request("POST", "/api/v1/flows/query", {}, token=None)["status"], 401)
        self.assertEqual(request("POST", "/api/v1/flows/export.csv", {}, token=None)["status"], 401)
        self.assertEqual(request("POST", "/api/v1/flows/query", {"limit": 101})["status"], 400)
        self.assertEqual(request("POST", "/api/v1/flows/export.csv", {"limit": 10})["status"], 400)
        self.assertEqual(request("POST", "/api/v1/policies", {})["status"], 403)


PG_NAMES = private_pg.names("traffic_views")


@unittest.skipUnless(os.environ.get("PRTHAK_PLATFORM_PG_ACCEPTANCE") == "1", "Owner opt-in for private PostgreSQL traffic fixture")
class PostgreSQLTrafficPages(TrafficPageChecks, unittest.TestCase):
    @classmethod
    def verify(cls, db, expected):
        user, directory, database = db.execute("SELECT current_user,current_setting('data_directory'),current_database()").fetchone()
        if user != "prthak_test" or Path(directory).resolve() != private_pg.data_directory() or database != expected:
            raise RuntimeError("Only the prepared private PostgreSQL traffic fixture is allowed")

    @classmethod
    def setUpClass(cls):
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import make_conninfo
        cls.driver, cls.sql = psycopg, sql
        cls.parameters = private_pg.parameters()
        with psycopg.connect(**cls.parameters, dbname="postgres", autocommit=True) as db:
            cls.verify(db, "postgres")
            for name in PG_NAMES.values():
                if db.execute("SELECT 1 FROM pg_database WHERE datname=%s", (name,)).fetchone():
                    raise RuntimeError("Refusing to reuse a pre-existing private fixture database")
                db.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
        cls.dsns = {namespace: make_conninfo(**cls.parameters, dbname=name) for namespace, name in PG_NAMES.items()}

    @classmethod
    def tearDownClass(cls):
        with cls.driver.connect(**cls.parameters, dbname="postgres", autocommit=True) as db:
            cls.verify(db, "postgres")
            for name in PG_NAMES.values():
                db.execute(cls.sql.SQL("DROP DATABASE {} WITH (FORCE)").format(cls.sql.Identifier(name)))

    def reset(self):
        for namespace, dsn in self.dsns.items():
            with self.driver.connect(dsn, autocommit=True) as db:
                self.verify(db, PG_NAMES[namespace])
                db.execute("DROP SCHEMA public CASCADE"); db.execute("CREATE SCHEMA public")

    def make_store(self):
        from controller.postgres import PostgresStore
        self.reset(); self.addCleanup(self.reset)
        return PostgresStore(self.dsns["metadata"], self.dsns["traffic"])
