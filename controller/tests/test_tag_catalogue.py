import copy
from concurrent.futures import ThreadPoolExecutor
from email.message import Message
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from controller.app import handler_for
from controller.http_limits import RequestLimits
from controller.firewall import WorkflowConflict
from controller import metadata, metadata_csv, tag_catalogue
from controller.platform_runtime import META_TABLES, _columns, _source_rows
from controller.store import Store


class TagCatalogueTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = Store(self.temporary.name)

    def test_unused_definition_survives_restart_and_duplicate_keeps_original_audit(self):
        created = tag_catalogue.create(self.store, {"key": "application", "value": "billing"}, "admin-one")
        self.assertEqual(tag_catalogue.create(self.store, {"key": "application", "value": "billing"}, "admin-two"), created)
        restarted = Store(self.temporary.name)
        self.assertEqual(tag_catalogue.listing(restarted)["items"], [created])
        events = [record for record in restarted.all("audit") if record["action"] == "tag.created"]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["actor"], "admin-one")
        self.assertEqual(restarted.all("servers"), [])

    def test_two_controller_stores_create_one_shared_definition(self):
        peer = Store(self.temporary.name)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda store: tag_catalogue.create(store, {"key": "owner", "value": "finance"}, "admin"),
                                    (self.store, peer)))
        self.assertEqual(results[0], results[1])
        self.assertEqual(tag_catalogue.listing(self.store)["total"], 1)
        self.assertEqual(len([record for record in self.store.all("audit") if record["action"] == "tag.created"]), 1)

    def test_definitions_do_not_assign_servers_or_recompile_policies(self):
        self.store.report("node", {"hostname": "node", "ips": ["10.0.0.1"], "listeners": [],
                                   "firewalld_state": "running", "apply_status": "preview"})
        self.store.update_server("node", {"tags": {"application": "legacy-free-tag"}}, "admin")
        before = {table: copy.deepcopy(self.store.all(table)) for table in ("servers", "groups", "policies", "bundle_history")}
        tag_catalogue.create(self.store, {"key": "application", "value": "billing"}, "admin")
        for table, records in before.items():
            self.assertEqual(self.store.all(table), records, table)
        self.assertEqual(self.store.server("node")["tags"], {"application": "legacy-free-tag"})
        self.assertEqual(self.store.update_server("node", {"tag_updates": {"owner": "finance"}}, "admin")["tags"],
                         {"application": "legacy-free-tag", "owner": "finance"})

    def test_catalogue_preserves_exact_tag_identity_and_rejects_reserved_locations(self):
        first = tag_catalogue.create(self.store, {"key": "Application", "value": "Billing"}, "admin")
        second = tag_catalogue.create(self.store, {"key": "application", "value": "billing"}, "admin")
        self.assertNotEqual(first["id"], second["id"])
        for key in ("dc", "DC", "location", "Location_ID", "data-center", "data_centre", "datacenter", "location_type"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                tag_catalogue.create(self.store, {"key": key, "value": "Noida"}, "admin")
        for value in ({}, [], {"key": "owner"}, {"key": "owner", "value": "finance", "location_id": "other"},
                      {"key": "bad key", "value": "finance"}, {"key": 22, "value": "finance"},
                      {"key": "owner", "value": ""}, {"key": "owner", "value": ["finance"]},
                      {"key": "owner", "value": "x" * 129}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                tag_catalogue.create(self.store, value, "admin")

    def test_catalogue_search_pagination_and_capacity_are_bounded(self):
        for key, text in (("owner", "finance"), ("application", "payments"), ("application", "billing")):
            tag_catalogue.create(self.store, {"key": key, "value": text}, "admin")
        page = tag_catalogue.listing(self.store, limit=1, offset=1)
        self.assertEqual([(record["key"], record["value"]) for record in page["items"]], [("application", "payments")])
        self.assertEqual((page["total"], page["has_more"]), (3, True))
        self.assertEqual(tag_catalogue.listing(self.store, q="APPLICATION=BILL")["total"], 1)
        for options in ({"limit": 201}, {"limit": 0}, {"limit": True}, {"offset": -1}, {"offset": 10001}, {"q": "x" * 201}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                tag_catalogue.listing(self.store, **options)
        for query in ({"limit": ["1", "2"]}, {"unknown": ["field"]}, {"offset": ["-1"]}, {"limit": ["1.5"]}):
            with self.subTest(query=query), self.assertRaises(ValueError):
                tag_catalogue.options(query)
        with patch.object(tag_catalogue, "MAX_TAGS", 3):
            self.assertEqual(tag_catalogue.create(self.store, {"key": "owner", "value": "finance"}, "other")["value"], "finance")
            with self.assertRaisesRegex(ValueError, "maximum"):
                tag_catalogue.create(self.store, {"key": "owner", "value": "new"}, "admin")

    def test_schema_upgrade_and_cluster_snapshot_preserve_tag_catalogue(self):
        with self.store.meta() as db:
            db.execute("DROP TABLE tag_catalogue")
        migrated = Store(self.temporary.name)
        created = tag_catalogue.create(migrated, {"key": "owner", "value": "finance"}, "admin")
        self.assertIn("tag_catalogue", META_TABLES)
        self.assertEqual(_columns("tag_catalogue"), ("id", "data"))
        rows = _source_rows(Path(migrated.meta_path), "metadata")["tag_catalogue"]
        self.assertEqual(json.loads(rows[0][1]), created)

    def test_startup_seeds_legacy_effective_and_future_csv_tags_without_reserved_locations(self):
        self.store.report("node", {"hostname": "node", "ips": ["10.0.0.1"], "listeners": []})
        with self.store.meta() as db:
            server = self.store._get(db, "servers", "node")
            server["tags"] = {"Application": "Billing", "owner": "Finance, risk=core", "dc": "Noida"}
            server.pop("_metadata_overrides", None)
            self.store._put(db, "servers", server)
            self.store._put(db, "metadata_ip_profiles", {"id": "10.0.0.2", "ip": "10.0.0.2", "tags": {"application": "payments", "owner": "Finance, risk=core"}})
            db.execute("DROP TABLE tag_catalogue")
        restarted = Store(self.temporary.name)
        records = tag_catalogue.listing(restarted)["items"]
        self.assertEqual({(record["key"], record["value"]) for record in records},
                         {("Application", "Billing"), ("application", "payments"), ("owner", "Finance, risk=core")})
        self.assertTrue(all(record["created_by"] == "system:metadata" and record["created_from"] == "existing_metadata" for record in records))
        self.assertEqual(restarted.server("node")["tags"], {"Application": "Billing", "owner": "Finance, risk=core"})
        again = Store(self.temporary.name)
        self.assertEqual(tag_catalogue.listing(again)["items"], records)

    def test_seeding_preserves_existing_definition_assignment_sources_and_audit_without_compile(self):
        created = tag_catalogue.create(self.store, {"key": "owner", "value": "finance"}, "catalogue-admin")
        self.store.report("node", {"hostname": "node", "ips": ["10.0.0.1"], "listeners": []})
        self.store.update_server("node", {"tags": {"owner": "finance", "application": "billing"}}, "endpoint-admin")
        before = {table: copy.deepcopy(self.store.all(table)) for table in ("servers", "groups", "policies", "bundle_history", "audit")}
        with patch.object(self.store, "compile_all", side_effect=AssertionError("registration must not compile")), self.store.meta() as db:
            self.assertEqual(tag_catalogue.seed_existing(db), 0)
        for table, records in before.items():
            self.assertEqual(self.store.all(table), records, table)
        registered = {record["key"]: record for record in tag_catalogue.listing(self.store)["items"]}
        self.assertEqual(registered["owner"], created)
        self.assertEqual(registered["application"]["created_by"], "endpoint-admin")
        self.assertEqual(self.store.server("node")["tag_sources"], {"owner": {"type": "manual"}, "application": {"type": "manual"}})

    def test_manual_and_bulk_assignments_register_tags_only_after_successful_review_apply(self):
        for identifier, address in (("one", "10.0.0.1"), ("two", "10.0.0.2")):
            self.store.report(identifier, {"hostname": identifier, "ips": [address], "listeners": []})
        self.store.update_server("one", {"tag_updates": {"owner": "Finance, risk=core"}}, "single-admin")
        first = tag_catalogue.listing(self.store)["items"]
        self.assertEqual([(record["key"], record["value"], record["created_by"]) for record in first], [("owner", "Finance, risk=core", "single-admin")])
        plan = metadata.bulk_preview(self.store, {"server_ids": ["one", "two"], "tag_updates": {"application": "billing", "criticality": "high"}})
        self.assertEqual(tag_catalogue.listing(self.store)["items"], first, "preview must not register unused definitions")
        metadata.bulk_apply(self.store, plan["id"], {"confirmation_nonce": plan["confirmation_nonce"]}, "bulk-admin")
        records = {record["key"]: record for record in tag_catalogue.listing(self.store)["items"]}
        self.assertEqual(records["owner"], first[0])
        self.assertEqual(records["application"]["created_by"], "bulk-admin")
        self.assertEqual(records["criticality"]["created_from"], "central_assignment")
        self.assertEqual(self.store.server("one")["tags"], {"application": "billing", "criticality": "high", "owner": "Finance, risk=core"})
        self.assertEqual(self.store.server("two")["tags"], {"application": "billing", "criticality": "high"})
        actions = [record["action"] for record in self.store.all("audit")]
        self.assertIn("server.updated", actions)
        self.assertIn("metadata.bulk.applied", actions)
        self.assertNotIn("tag.created", actions)

    def test_csv_applied_future_profiles_register_exact_values_but_previews_and_failures_do_not(self):
        preview = metadata_csv.preview(self.store, {"csv": 'ip,application,tag.owner\n10.0.0.99,"billing, payments","Finance=risk"\n'}, "csv-admin")
        self.assertEqual(preview["status"], "draft")
        self.assertEqual(tag_catalogue.listing(self.store)["total"], 0)
        with self.assertRaises(WorkflowConflict):
            metadata_csv.apply(self.store, preview["id"], {"confirmation_nonce": "wrong"}, "csv-admin")
        self.assertEqual(tag_catalogue.listing(self.store)["total"], 0)
        metadata_csv.apply(self.store, preview["id"], {"confirmation_nonce": preview["confirmation_nonce"]}, "csv-admin")
        records = tag_catalogue.listing(self.store)["items"]
        self.assertEqual({(record["key"], record["value"]) for record in records}, {("application", "billing, payments"), ("owner", "Finance=risk")})
        self.assertTrue(all(record["created_by"] == "csv-admin" and record["created_from"] == "csv_assignment" for record in records))
        self.assertEqual(self.store.all("servers"), [])
        self.store.report("future", {"hostname": "future", "ips": ["10.0.0.99"], "listeners": [], "tags": {"owner": "untrusted-agent"}})
        self.assertEqual(self.store.server("future")["tags"], {"application": "billing, payments", "owner": "Finance=risk"})
        self.assertEqual(tag_catalogue.listing(self.store)["items"], records)

    def test_implicit_registration_capacity_never_blocks_valid_metadata_or_overwrites_definitions(self):
        created = tag_catalogue.create(self.store, {"key": "owner", "value": "finance"}, "catalogue-admin")
        self.store.report("node", {"hostname": "node", "ips": ["10.0.0.1"], "listeners": []})
        with patch.object(tag_catalogue, "MAX_TAGS", 2):
            self.store.update_server("node", {"tags": {"application": "billing", "criticality": "high", "owner": "finance"}}, "endpoint-admin")
            self.assertEqual(tag_catalogue.listing(self.store)["total"], 2)
            self.assertEqual(self.store.server("node")["tags"], {"application": "billing", "criticality": "high", "owner": "finance"})
            with self.store.meta() as db:
                self.assertEqual(tag_catalogue.seed_existing(db), 0)
            with self.assertRaisesRegex(ValueError, "maximum"):
                tag_catalogue.create(self.store, {"key": "owner", "value": "new"}, "catalogue-admin")
        records = {record["id"]: record for record in tag_catalogue.listing(self.store)["items"]}
        self.assertEqual(records[created["id"]], created)

    def test_registration_ignores_invalid_legacy_pairs_and_never_scans_inventory_on_listing(self):
        with self.store.meta() as db:
            tag_catalogue.register(db, [{"dc": "Noida", "Location_ID": "location", "valid": "kept", "bad key": "ignored", "empty": "", "long": "x" * 129}], "system:metadata", "existing_metadata")
        def bounded_read(db, table):
            self.assertEqual(table, "tag_catalogue", "picker must not scan endpoint or CSV metadata")
            return Store._all(db, table)
        with patch.object(self.store, "_all", side_effect=bounded_read):
            self.assertEqual([(row["key"], row["value"]) for row in tag_catalogue.listing(self.store)["items"]], [("valid", "kept")])

    def test_failed_metadata_transaction_rolls_back_definition_registration_too(self):
        self.store.report("node", {"hostname": "node", "ips": ["10.0.0.1"], "listeners": []})
        before = copy.deepcopy(self.store.server("node"))
        with patch.object(self.store, "compile_all", side_effect=ValueError("synthetic compile refusal")):
            with self.assertRaisesRegex(ValueError, "compile refusal"):
                self.store.update_server("node", {"tags": {"application": "uncommitted"}}, "endpoint-admin")
        self.assertEqual(tag_catalogue.listing(self.store)["total"], 0)
        self.assertEqual(self.store.server("node"), before)
        self.assertFalse(any(row["action"] == "server.updated" for row in self.store.all("audit")))

    def test_startup_seed_record_scan_is_bounded_and_idempotent(self):
        for identifier in ("a", "b", "c"):
            self.store.report(identifier, {"hostname": identifier, "ips": ["10.0.0." + str(ord(identifier) - 96)], "listeners": []})
        with self.store.meta() as db:
            for identifier in ("a", "b", "c"):
                server = self.store._get(db, "servers", identifier)
                server["tags"] = {"application": identifier}
                self.store._put(db, "servers", server)
        with patch.object(tag_catalogue, "MAX_SEED_RECORDS", 2), self.store.meta() as db:
            self.assertEqual(tag_catalogue.seed_existing(db), 2)
            self.assertEqual(tag_catalogue.seed_existing(db), 0)
        self.assertEqual({row["value"] for row in tag_catalogue.listing(self.store)["items"]}, {"a", "b"})


class TagCatalogueHTTPTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = Store(self.temporary.name)
        self.principal = {"actor": "local:admin", "role": "admin", "auth_type": "session"}

        def csrf(headers, principal):
            if headers.get("X-CSRF-Token") != "fixture-csrf":
                raise PermissionError("A valid CSRF token is required")

        self.app = SimpleNamespace(store=self.store, demo=False, limits=RequestLimits(),
                                   principal=lambda headers: self.principal,
                                   auth=SimpleNamespace(require_csrf=csrf), recovering=lambda: False)

    def request(self, method, path="/api/v1/tags", body=None, csrf=True):
        class TLS:
            pass

        handler = object.__new__(handler_for(self.app))
        handler.command, handler.path = method, path
        handler.connection, handler.client_address = TLS(), ("127.0.0.1", 0)
        handler.headers = Message()
        handler.headers["Host"], handler.headers["Origin"] = "controller.test", "https://controller.test"
        if csrf:
            handler.headers["X-CSRF-Token"] = "fixture-csrf"
        handler.body = lambda: body
        replies = []
        handler.response = lambda status, value=None, headers=None: replies.append((status, value))
        with patch("controller.app.ssl.SSLSocket", TLS):
            handler.dispatch()
        return replies[0]

    def test_admin_creation_reader_listing_and_csrf_boundaries(self):
        body = {"key": "application", "value": "billing"}
        self.assertEqual(self.request("POST", body=body, csrf=False)[0], 403)
        self.principal["role"] = "read_only"
        self.assertEqual(self.request("POST", body=body)[0], 403)
        self.principal["role"] = "admin"
        status, created = self.request("POST", body=body)
        self.assertEqual(status, 201)
        self.principal["role"] = "super_admin"
        self.assertEqual(self.request("POST", body=body), (201, created))
        self.principal["role"] = "read_only"
        self.assertEqual(self.request("GET")[1]["items"], [created])
        self.assertEqual(self.request("GET", "/api/v1/tags?q=bill&limit=1")[1]["total"], 1)
        self.assertEqual(self.request("GET", "/api/v1/tags?limit=201")[0], 400)
        self.assertEqual(self.request("DELETE")[0], 403)
        self.principal = None
        self.assertEqual(self.request("GET")[0], 401)

    def test_create_validation_and_unsupported_methods(self):
        self.assertEqual(self.request("POST", body={"key": "DC", "value": "Noida"})[0], 400)
        self.assertEqual(self.request("GET", "/api/v1/tags?limit=1&limit=2")[0], 400)
        self.assertEqual(self.request("PUT", body={})[0], 405)
        self.assertEqual(self.store.all("tag_catalogue"), [])


if __name__ == "__main__":
    unittest.main()
