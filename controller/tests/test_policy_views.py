"""Bounded source catalogues; native PG cases are owner-run and opt-in only."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from controller.tests import private_pg as pg_fixture

import copy
import csv
import io
import json
import os
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from controller import learning_policies as lp
from controller import policy_views as views
from controller import service_groups
from controller import workspace_exports
from controller.firewall import WorkflowConflict
from controller.store import Store, stamp


class PolicyViewChecks:
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="prthak-policy-view-")
        self.addCleanup(self.temporary.cleanup)
        self.store = self.make_store()
        self.store.lab_approvals = True
        self.sources = ["10.44.0.9/32", "2001:db8:44::9/128"]
        self.direct = {"id": "managed-direct", "name": "Z Billing direct", "mode": "enforce", "revision": 1, "created_at": stamp(), "updated_at": stamp(), "selector": {"application": "billing", "location_id": "dc-a"}, "group_ids": [], "services": [{"port": 8443, "protocol": "tcp", "sources": self.sources, "source_selector": {}, "source_group_ids": []}]}
        self.grouped = {**copy.deepcopy(self.direct), "id": "managed-grouped", "name": "Z Billing grouped", "selector": {}, "group_ids": ["billing-group"], "services": [{"service_group_id": "https-group", "service_group_snapshot": {"id": "https-group", "name": "Frozen application ports", "revision": 1, "ports": [{"port": 8443, "protocol": "tcp"}, {"port": 9443, "protocol": "udp"}]}, "sources": self.sources, "source_selector": {}, "source_group_ids": []}]}
        for index, identifier in enumerate(("billing-a", "billing-b", "payments-b"), 1):
            self.store.report(identifier, {"hostname": identifier, "ips": [f"10.70.0.{index}"], "listeners": [], "collector_status": "off", "applied_version": 0})
        with self.store.meta() as db:
            for identifier, name in (("dc-a", "Primary DC"), ("dc-b", "Secondary DC")):
                self.store._put(db, "locations", {"id": identifier, "key": "location:" + identifier, "name": name, "type": "datacenter", "aliases": []})
            for identifier in ("billing-a", "billing-b", "payments-b"):
                server = self.store._get(db, "servers", identifier)
                server.update(tags={"application": "billing" if identifier.startswith("billing") else "payments"}, location_id="dc-a" if identifier == "billing-a" else "dc-b", capabilities=["learning_auto_allow_v1", "signed_assignments_v1", "learning_ipsets_v1"], protection_digest="d" * 64, protection={"ready": True, "ssh_ports": [2022], "controller_url": "https://controller.example:8787"})
                self.store._put(db, "servers", server)
            self.store._put(db, "groups", {"id": "billing-group", "name": "Billing in primary DC", "type": "static", "server_ids": ["billing-a"], "selector": {}})
            self.store._put(db, "service_groups", {"id": "https-group", "name": "Current catalogue ports", "revision": 2, "description": "Current definition differs from frozen policy", "ports": [{"port": 9999, "protocol": "tcp"}]})
            for index in range(24):
                filler = {**copy.deepcopy(self.direct), "id": f"filler-{index:03d}", "name": f"000 Filler {index:03d}", "selector": {"application": "payments"}}
                self.store._put(db, "policies", filler)
            for policy in (self.direct, self.grouped): self.store._put(db, "policies", policy)
            self.learned = {"id": "learned-live", "name": "Reviewed application access", "hostname": "billing-host", "server_id": "billing-a", "session_id": "session-a", "status": "applied", "origin": "reviewed", "revision": 1, "created_at": "2026-01-04T00:00:00Z", "updated_at": stamp(), "removed": False, "removal_pending": False, "auto_updates": False, "error": "", "services": [{"port": 8443, "protocol": "tcp", "sources": self.sources}], "protection_digest": "d" * 64, "target_ips_digest": lp._bindings(self.store._get(db, "servers", "billing-a"))["target_ips_digest"]}
            for policy in (
                self.learned,
                {**self.learned, "id": "learned-other", "server_id": "payments-b", "session_id": "session-b", "hostname": "payments-host", "created_at": "2026-01-03T00:00:00Z"},
                {**self.learned, "id": "learned-removed", "removed": True, "status": "removed", "created_at": "2026-01-02T00:00:00Z"},
                {**self.learned, "id": "learned-cleanup", "removed": True, "removal_pending": True, "status": "pending", "created_at": "2026-01-01T00:00:00Z"},
            ): lp._put_policy(self.store, db, policy)

    def make_store(self):
        return Store(self.temporary.name)

    def assert_no_source_values(self, item):
        self.assertTrue(item["summary_only"])
        encoded = json.dumps(item)
        for source in self.sources: self.assertNotIn(source, encoded)
        for service in item["services"]:
            self.assertNotIn("sources", service)
            self.assertTrue(service["sources_omitted"])

    def no_catalogue_all(self, db, table):
        if table in ("policies", "learning_allow_policies"):
            raise AssertionError("Public reads cannot load whole canonical policy catalogues")
        return Store._all(db, table)

    def test_combined_billing_dc_group_scope_and_8443_filter_precede_paging(self):
        value = {"server_ids": ["billing-a"], "ports": ["8443/tcp"], "mode": "enforce", "limit": 1}
        with patch.object(self.store, "_all", self.no_catalogue_all):
            first = views.listing(self.store, "managed", value)
            second = views.listing(self.store, "managed", {**value, "offset": 1})
        self.assertEqual((first["total"], first["next_offset"], first["has_more"]), (2, 1, True))
        self.assertEqual([row["id"] for row in first["items"]], ["managed-direct"])
        self.assertEqual((second["total"], second["next_offset"], second["has_more"]), (2, 2, False))
        self.assertEqual([row["id"] for row in second["items"]], ["managed-grouped"])
        self.assertEqual(first["filters"]["server_count"], 1)

    def test_grouped_port_filter_uses_frozen_snapshot_not_current_catalogue(self):
        value = {"server_ids": ["billing-a"], "ports": ["9443/udp"]}
        result = views.listing(self.store, "managed", value)
        self.assertEqual([row["id"] for row in result["items"]], ["managed-grouped"])
        snapshot = result["items"][0]["services"][0]["service_group_snapshot"]
        self.assertEqual(snapshot["ports"], self.grouped["services"][0]["service_group_snapshot"]["ports"])
        for port in ("9999/tcp", "9443/tcp"):
            self.assertEqual(views.listing(self.store, "managed", {**value, "ports": [port]})["total"], 0)

    def test_exports_match_policy_scope_and_include_complete_exact_sources(self):
        def records(kind, **scope):
            with workspace_exports.csv_spool(self.store, "policies", {"kind": kind, **scope}) as (file, _):
                return list(csv.DictReader(io.StringIO(file.read().decode("utf-8-sig"))))

        unfiltered = records("managed", ports=["8443/tcp"])
        self.assertEqual(len(unfiltered), 52)
        self.assertEqual({row["source"] for row in unfiltered}, set(self.sources))
        self.assertEqual({row["destination_port"] for row in unfiltered}, {"8443"})

        grouped = records("managed", ports=["9443/udp"], server_ids=["billing-a"])
        self.assertEqual(len(grouped), 2)
        self.assertEqual({row["policy_id"] for row in grouped}, {"managed-grouped"})
        self.assertEqual(grouped[0]["service_group"], "Frozen application ports")
        self.assertEqual(grouped[0]["destination_group_ids"], "billing-group")

        learned = records("learned", server_ids=["billing-a"], ports=["8443/tcp"])
        self.assertNotIn("learned-other", {row["policy_id"] for row in learned})
        self.assertNotIn("learned-removed", {row["policy_id"] for row in learned})
        self.assertEqual({row["destination_reported_ips"] for row in learned}, {"10.70.0.1"})

    def test_managed_search_is_name_or_matching_target_but_never_escapes_scope(self):
        base = {"server_ids": ["billing-a"], "ports": ["8443/tcp"]}
        named = views.listing(self.store, "managed", {**base, "search": "billing direct"})
        self.assertEqual([item["id"] for item in named["items"]], ["managed-direct"])
        target = views.listing(self.store, "managed", {**base, "search": "host metadata needle", "search_server_ids": ["billing-a"]})
        self.assertEqual(target["total"], 2)
        excluded = views.listing(self.store, "managed", {**base, "server_ids": ["payments-b"], "search": "billing direct", "search_server_ids": ["billing-a"]})
        self.assertEqual(excluded["total"], 0)

    def test_learned_source_search_stays_in_database_and_all_scopes_are_applied(self):
        original = json.loads
        def no_sources(raw):
            for source in self.sources: self.assertNotIn(source, raw)
            return original(raw)
        with patch.object(views, "json", SimpleNamespace(loads=no_sources, dumps=json.dumps)), patch.object(self.store, "_all", self.no_catalogue_all):
            result = views.listing(self.store, "learned", {"search": self.sources[0], "server_ids": ["billing-a"], "session_id": "session-a", "status": "applied", "ports": ["8443/tcp"], "limit": 1})
        self.assertEqual((result["total"], len(result["items"])), (1, 1))
        self.assertEqual(result["items"][0]["id"], "learned-live")
        self.assert_no_source_values(result["items"][0])
        targeted = views.listing(self.store, "learned", {"search": "host metadata needle", "search_server_ids": ["billing-a"], "status": "applied"})
        self.assertEqual([item["id"] for item in targeted["items"]], ["learned-live"])

    def test_learned_candidate_filter_precedes_page_after_many_newer_unrelated_rows(self):
        with self.store.meta() as db:
            for index in range(24): lp._put_policy(self.store, db, {**self.learned, "id": f"unrelated-{index:03d}", "server_id": "payments-b", "created_at": "2026-02-01T00:00:00Z"})
        result = views.listing(self.store, "learned", {"server_ids": ["billing-a"], "status": "applied", "ports": ["8443/tcp"], "limit": 1})
        self.assertEqual((result["total"], result["next_offset"], result["has_more"]), (1, 1, False))
        self.assertEqual(result["items"][0]["id"], "learned-live")
        visible = views.listing(self.store, "learned", {"server_ids": ["billing-a"]})
        self.assertEqual([item["id"] for item in visible["items"]], ["learned-live", "learned-cleanup"])

    def test_source_counts_are_literal_entries_and_no_cidrs_enter_lists(self):
        for kind, value in (("managed", {"server_ids": ["billing-a"]}), ("learned", {"server_id": "billing-a"})):
            for item in views.listing(self.store, kind, value)["items"]:
                self.assert_no_source_values(item)
                self.assertEqual(item["source_count_kind"], "literal_entries")
                self.assertEqual(item["source_count"], 2)
                self.assertEqual(item["services"][0]["source_count"], 2)

    def test_overview_uses_bounded_policy_views_and_never_all_canonical_policies(self):
        with patch.object(self.store, "_all", self.no_catalogue_all): result = self.store.overview()
        self.assertEqual((result["stats"]["policy_count"], len(result["policies"])), (26, 20))
        self.assertEqual((result["policy_pagination"]["total"], result["policy_pagination"]["has_more"]), (26, True))
        self.assertEqual(result["learning_policy_pagination"]["total"], 3)
        for item in result["policies"] + result["learning_policies"]: self.assert_no_source_values(item)

    def test_service_group_references_are_capped_ids_with_exact_total_without_all_policies(self):
        with self.store.meta() as db:
            for index in range(101): self.store._put(db, "policies", {**self.grouped, "id": f"reference-{index:03d}", "name": f"Reference {index:03d}"})
        with patch.object(self.store, "_all", self.no_catalogue_all):
            group = views.service_groups(self.store, "https-group")
            groups = views.service_groups(self.store)
        self.assertEqual((len(group["policy_ids"]), group["policy_count"], group["policy_ids_has_more"]), (100, 102, True))
        self.assertEqual(group["policy_ids"], sorted(group["policy_ids"]))
        self.assertEqual(groups[0]["policy_count"], 102)

    def test_exact_details_preserve_whole_canonical_sources_and_check_size_before_decode(self):
        for kind, expected in (("managed", self.grouped), ("learned", self.learned)):
            loads = Mock(wraps=json.loads)
            with self.subTest(kind=kind), patch.object(views, "json", SimpleNamespace(loads=loads, dumps=json.dumps)):
                self.assertEqual(views.detail(self.store, kind, expected["id"]), expected)
            loads.assert_called_once()
        fail = Mock(side_effect=AssertionError("Oversized detail cannot decode"))
        with patch.object(views, "MAX_DETAIL_BYTES", 32), patch.object(views, "json", SimpleNamespace(loads=fail)):
            for kind, identifier in (("managed", self.grouped["id"]), ("learned", self.learned["id"])):
                with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, "detail limit"): views.detail(self.store, kind, identifier)
        fail.assert_not_called()

    def test_navigation_cannot_be_saved_and_invalid_query_inputs_fail_closed(self):
        summary = views.listing(self.store, "managed", {"server_ids": ["billing-a"], "limit": 1})["items"][0]
        for value in (summary, {**summary, "summary_only": False}):
            with self.assertRaisesRegex(ValueError, "navigation"): self.store.save_policy(value, "admin", self.direct["id"])
        learned = views.listing(self.store, "learned", {"server_id": "billing-a", "limit": 1})["items"][0]
        with self.assertRaisesRegex(ValueError, "omits sources"): lp._validate_services(learned["services"])
        for callback in (lp.update, lp.remove):
            with self.assertRaisesRegex(ValueError, "navigation"): callback(self.store, learned["id"], learned, "admin")
        for value in ({"limit": True}, {"limit": 0}, {"limit": 101}, {"offset": -1}, {"ports": ["8443; DROP"]}, {"server_ids": ["x' OR 1=1--"]}, {"mode": "invalid"}, {"unexpected": 1}):
            with self.subTest(value=value), self.assertRaises(ValueError): views.listing(self.store, "managed", value)
        with self.assertRaises(ValueError): views.detail(self.store, "managed", "x' OR 1=1--")
        with self.assertRaises(KeyError): views.detail(self.store, "managed", "missing-policy")

    def test_ordinary_edits_deletes_and_revision_conflicts_preserve_write_workflows(self):
        value = {"name": "Ordinary policy", "selector": {}, "mode": "monitor", "services": [{"port": 8443, "protocol": "tcp", "sources": ["10.50.0.1/32"]}]}
        created = self.store.save_policy(value, "admin")
        updated = self.store.save_policy({**value, "name": "Updated ordinary policy", "expected_revision": created["revision"]}, "admin", created["id"])
        self.assertEqual(updated["revision"], 2)
        with self.assertRaises(WorkflowConflict): self.store.save_policy({**value, "expected_revision": 1}, "admin", created["id"])
        with self.assertRaises(WorkflowConflict): self.store.delete_policy(created["id"], "admin", expected_revision=1)
        self.assertEqual(views.detail(self.store, "managed", created["id"])["revision"], 2)
        self.store.delete_policy(created["id"], "admin", expected_revision=2)
        with self.assertRaises(KeyError): views.detail(self.store, "managed", created["id"])
        changed = lp.update(self.store, self.learned["id"], {"expected_revision": 1, "services": [{"port": 8443, "protocol": "tcp", "sources": ["10.44.0.99/32"]}]}, "admin")
        self.assertEqual(changed["services"][0]["sources"], ["10.44.0.99/32"])
        with self.assertRaises(WorkflowConflict): lp.update(self.store, changed["id"], {"expected_revision": 1}, "admin")
        removed = lp.remove(self.store, changed["id"], {"expected_revision": changed["revision"]}, "admin")
        self.assertTrue(removed["removed"] and removed["removal_pending"])
        self.assertEqual(removed["services"], [])

    def test_canonical_write_byte_fence_precedes_policy_history_and_compile_changes(self):
        with self.store.read_meta() as db:
            before_counts = tuple(db.execute("SELECT COUNT(*) FROM " + table).fetchone()[0] for table in ("policies", "policy_revisions", "audit", "learning_allow_policies"))
            managed_before = self.store._get(db, "policies", self.direct["id"])
            learned_before = self.store._get(db, "learning_allow_policies", self.learned["id"])
        value = {"name": "Snapshot size fence", "selector": {}, "mode": "monitor", "services": [{"service_group_id": "https-group", "sources": self.sources}]}
        # Input fits; expansion into frozen group snapshot, normalized fields,
        # identity/revision and timestamps must be fenced before history writes.
        input_bytes = len(json.dumps(value, separators=(",", ":")).encode())
        with patch.object(views, "MAX_DETAIL_BYTES", input_bytes + 32), patch("controller.managed.record_revision", side_effect=AssertionError("History cannot change before canonical size admission")), patch.object(self.store, "compile_all", side_effect=AssertionError("Cannot compile an oversized canonical policy")):
            with self.assertRaisesRegex(ValueError, "8 MiB"): self.store.save_policy(value, "admin")
        with patch.object(views, "MAX_DETAIL_BYTES", 128):
            with self.assertRaisesRegex(ValueError, "8 MiB"): self.store.save_policy({**self.direct, "name": "漢" * 80, "expected_revision": 1}, "admin", self.direct["id"])
            for policy in ({**self.learned, "id": "learned-rejected-create"}, {**self.learned, "name": "漢" * 80}):
                with self.store.meta() as db, self.assertRaisesRegex(ValueError, "8 MiB"): lp._put_policy(self.store, db, policy)
        with self.store.read_meta() as db:
            after_counts = tuple(db.execute("SELECT COUNT(*) FROM " + table).fetchone()[0] for table in ("policies", "policy_revisions", "audit", "learning_allow_policies"))
            self.assertEqual(self.store._get(db, "policies", self.direct["id"]), managed_before)
            self.assertEqual(self.store._get(db, "learning_allow_policies", self.learned["id"]), learned_before)
        self.assertEqual(after_counts, before_counts)
        unicode_value = {"name": "漢" * 20}
        compact_utf8_bytes = len(json.dumps(unicode_value, separators=(",", ":"), ensure_ascii=False).encode())
        with patch.object(views, "MAX_DETAIL_BYTES", compact_utf8_bytes + 1):
            with self.assertRaisesRegex(ValueError, "8 MiB"): views.encoded_policy(unicode_value)

    def test_service_group_expansion_and_direct_policy_write_size_failures_roll_back_everything(self):
        with self.store.meta() as db:
            group = self.store._get(db, "service_groups", "https-group")
            group.update(created_at=stamp(), updated_at=stamp())
            self.store._put(db, "service_groups", group)
        ports = [{"port": 20000 + index, "protocol": "tcp"} for index in range(100)]
        change = {"name": group["name"], "description": group["description"], "ports": ports, "expected_revision": group["revision"]}
        expanded = copy.deepcopy(self.grouped)
        expanded["services"][0]["service_group_snapshot"] = {"id": group["id"], "name": group["name"], "revision": group["revision"] + 1, "ports": ports}
        old_bytes = len(json.dumps(self.grouped, separators=(",", ":")).encode())
        new_bytes = len(json.dumps(expanded, separators=(",", ":")).encode())
        limit = old_bytes + 32
        self.assertLess(old_bytes, limit)
        self.assertGreater(new_bytes, limit)

        def state():
            with self.store.read_meta() as db:
                return {
                    "group": self.store._get(db, "service_groups", group["id"]),
                    "policy": self.store._get(db, "policies", self.grouped["id"]),
                    "policy_count": db.execute("SELECT COUNT(*) FROM policies").fetchone()[0],
                    "group_history": [[row[0], row[1]] for row in db.execute("SELECT id,data FROM service_group_revisions WHERE service_group_id=? ORDER BY id", (group["id"],))],
                    "policy_history": [[row[0], row[1]] for row in db.execute("SELECT id,data FROM policy_revisions WHERE policy_id=? ORDER BY id", (self.grouped["id"],))],
                    "audit": [[row[0], row[1]] for row in db.execute("SELECT id,data FROM audit ORDER BY id")],
                }

        before = state()
        with patch.object(views, "MAX_DETAIL_BYTES", limit), patch.object(self.store, "compile_all", side_effect=AssertionError("Oversized refreshed policy must fail before compilation")):
            with self.assertRaisesRegex(ValueError, "8 MiB"):
                service_groups.save(self.store, change, "admin", group["id"])
            self.assertEqual(state(), before)
            for policy in (expanded, {**expanded, "id": "oversized-ordinary-create"}):
                with self.store.meta() as db, self.assertRaisesRegex(ValueError, "8 MiB"):
                    Store._put(db, "policies", policy)
                self.assertEqual(state(), before)

    def test_page_byte_budget_checks_raw_metadata_before_decode_and_never_skips_rows(self):
        with self.store.meta() as db:
            db.execute("DELETE FROM policies")
            for index in range(3):
                policy = {**copy.deepcopy(self.direct), "id": f"budget-{index}", "name": f"Budget {index}", "selector": {}}
                if index == 1: policy["selector"] = {"DO_NOT_DECODE_RAW_META": "x" * 90, **{f"key{key}": "x" * 90 for key in range(3)}}
                self.store._put(db, "policies", policy)
        first = views.listing(self.store, "managed", {"limit": 1})["items"][0]
        budget = len(json.dumps(first, separators=(",", ":"), ensure_ascii=False).encode()) + 200
        original = json.loads
        def guarded(raw):
            self.assertNotIn("DO_NOT_DECODE_RAW_META", raw)
            return original(raw)
        loads = Mock(side_effect=guarded)
        with patch.object(views, "MAX_PAGE_BYTES", budget), patch.object(views, "json", SimpleNamespace(loads=loads, dumps=json.dumps)), patch.object(views, "rows", wraps=views.rows) as stream:
            page = views.listing(self.store, "managed", {"limit": 3})
        self.assertEqual((len(page["items"]), page["next_offset"], page["total"], page["byte_limited"], page["has_more"]), (1, 1, 3, True, True))
        self.assertEqual(loads.call_count, 3)
        self.assertEqual(stream.call_args.kwargs.get("batch_size"), 1)
        rest = views.listing(self.store, "managed", {"limit": 3, "offset": page["next_offset"]})
        self.assertEqual([item["id"] for item in rest["items"]], ["budget-1", "budget-2"])
        fail = Mock(side_effect=AssertionError("Over-budget metadata cannot decode"))
        with patch.object(views, "MAX_PAGE_BYTES", 32), patch.object(views, "json", SimpleNamespace(loads=fail, dumps=json.dumps)):
            with self.assertRaisesRegex(ValueError, "page bound"): views.listing(self.store, "managed", {"limit": 1})
        fail.assert_not_called()


class PolicyViewSQLiteTests(PolicyViewChecks, unittest.TestCase):
    def test_cross_store_stale_put_and_delete_wait_before_old_read_and_preserve_history(self):
        for contender_action in ("put", "delete"):
            with self.subTest(contender=contender_action):
                value = {"name": "Concurrent original " + contender_action, "selector": {}, "mode": "monitor", "services": [{"port": 8443, "protocol": "tcp", "sources": ["10.60.0.1/32"]}]}
                created = self.store.save_policy(value, "first-writer")
                identifier = created["id"]
                contender = Store(self.temporary.name)
                first_read, release_first = threading.Event(), threading.Event()
                second_begin, second_read = threading.Event(), threading.Event()
                first_get, contender_get, contender_meta = self.store._get, contender._get, contender.meta

                def paused_get(db, table, key):
                    old = first_get(db, table, key)
                    if table == "policies" and key == identifier and not first_read.is_set():
                        first_read.set()
                        if not release_first.wait(5):
                            raise TimeoutError("Test did not release the first writer")
                    return old

                def observed_get(db, table, key):
                    if table == "policies" and key == identifier:
                        second_read.set()
                    return contender_get(db, table, key)

                class TracedConnection:
                    dialect = "sqlite"
                    def __init__(self, db): self.db = db
                    def execute(self, sql, parameters=()):
                        if sql.strip().upper() == "BEGIN IMMEDIATE": second_begin.set()
                        return self.db.execute(sql, parameters)
                    def __getattr__(self, name): return getattr(self.db, name)

                @contextmanager
                def traced_meta():
                    with contender_meta() as db: yield TracedConnection(db)

                def attempt_stale_write():
                    try:
                        if contender_action == "put":
                            contender.save_policy({**value, "name": "Stale contender", "expected_revision": 1}, "second-writer", identifier)
                        else:
                            contender.delete_policy(identifier, "second-writer", expected_revision=1)
                    except WorkflowConflict as error:
                        return error
                    raise AssertionError("Stale cross-Store write unexpectedly won")

                with patch.object(self.store, "_get", paused_get), patch.object(contender, "_get", observed_get), patch.object(contender, "meta", traced_meta), ThreadPoolExecutor(max_workers=2) as executor:
                    winner = executor.submit(self.store.save_policy, {**value, "name": "First writer won", "expected_revision": 1}, "first-writer", identifier)
                    loser = None
                    try:
                        self.assertTrue(first_read.wait(5), "First writer did not reach its old-policy read")
                        loser = executor.submit(attempt_stale_write)
                        self.assertTrue(second_begin.wait(5), "Contender did not attempt BEGIN IMMEDIATE")
                        self.assertFalse(second_read.wait(0.1), "Contender read old revision while first writer held the database writer lease")
                    finally:
                        release_first.set()
                        updated = winner.result(timeout=5)
                        if loser is not None: conflict = loser.result(timeout=5)
                self.assertIsInstance(conflict, WorkflowConflict)
                self.assertTrue(second_read.is_set(), "Contender never checked the committed newer revision")
                self.assertEqual((updated["name"], updated["revision"]), ("First writer won", 2))
                current = views.detail(self.store, "managed", identifier)
                self.assertEqual((current["name"], current["revision"]), ("First writer won", 2))
                with self.store.read_meta() as db:
                    history = [json.loads(row[0]) for row in db.execute("SELECT data FROM policy_revisions WHERE policy_id=? ORDER BY revision", (identifier,))]
                self.assertEqual([row["revision"] for row in history], [1, 2])
                self.assertEqual([row["name"] for row in history], [value["name"], "First writer won"])


ROOT = Path(__file__).resolve().parents[2]
PG_NAMES = pg_fixture.names("policy_views")


@unittest.skipUnless(os.environ.get("PRTHAK_PLATFORM_PG_ACCEPTANCE") == "1", "Owner opt-in for private policy-view PostgreSQL acceptance")
class PolicyViewPostgresTests(PolicyViewChecks, unittest.TestCase):
    @classmethod
    def verify(cls, db, expected):
        user, directory, database = db.execute("SELECT current_user,current_setting('data_directory'),current_database()").fetchone()
        if user != "prthak_test" or Path(directory).resolve() != pg_fixture.data_directory() or database != expected:
            raise RuntimeError("Only the prepared private cluster and literal policy-view fixture databases are allowed")

    @classmethod
    def setUpClass(cls):
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import make_conninfo
        cls.driver, cls.sql = psycopg, sql
        cls.parameters = pg_fixture.parameters()
        with psycopg.connect(**cls.parameters, dbname="postgres", autocommit=True) as db:
            cls.verify(db, "postgres")
            for name in PG_NAMES.values():
                if db.execute("SELECT 1 FROM pg_database WHERE datname=%s", (name,)).fetchone(): raise RuntimeError("Refusing to reuse a pre-existing private fixture database")
                db.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
        cls.dsns = {namespace: make_conninfo(**cls.parameters, dbname=name) for namespace, name in PG_NAMES.items()}

    def reset(self):
        for namespace, dsn in self.dsns.items():
            with self.driver.connect(dsn, autocommit=True) as db:
                self.verify(db, PG_NAMES[namespace]); db.execute("DROP SCHEMA public CASCADE"); db.execute("CREATE SCHEMA public")

    def make_store(self):
        from controller.postgres import PostgresStore
        self.reset(); self.addCleanup(self.reset)
        return PostgresStore(self.dsns["metadata"], self.dsns["traffic"])
