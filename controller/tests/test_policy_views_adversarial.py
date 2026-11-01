"""Independent acceptance of public policy projections and authority boundaries."""
import copy
import json
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from controller import policy_views as views
from controller.firewall import WorkflowConflict
from controller.store import Store
from controller.tests import test_policy_views as fixture


class IndependentPolicyCatalogueAcceptance(unittest.TestCase):
    def setUp(self):
        fixture.PolicyViewChecks.setUp(self)

    def make_store(self):
        return Store(self.temporary.name)

    def test_billing_dc_and_frozen_group_ports_filter_before_every_page(self):
        for port, total in (("8443/tcp", 2), ("9443/udp", 1), ("9999/tcp", 0), ("9443/tcp", 0)):
            query = {"server_ids": ["billing-a"], "ports": [port], "limit": 1}
            first = views.listing(self.store, "managed", query)
            self.assertEqual(first["total"], total)
            if total == 2:
                second = views.listing(self.store, "managed", {**query, "offset": first["next_offset"]})
                self.assertEqual([first["items"][0]["id"], second["items"][0]["id"]], ["managed-direct", "managed-grouped"])
                self.assertFalse(second["has_more"])
        self.assertEqual(views.listing(self.store, "managed", {"server_ids": ["billing-b"], "ports": ["8443/tcp"]})["total"], 0)

    def test_empty_and_disjoint_scopes_cannot_be_broadened_by_a_name_or_search_host(self):
        for query in ({"server_ids": [], "search": "Billing"}, {"server_ids": ["payments-b"], "search_server_ids": ["billing-a"], "ports": ["8443/tcp"], "search": "Billing"}, {"server_ids": ["billing-a"], "server_id": "payments-b", "search": "Billing"}):
            self.assertEqual(views.listing(self.store, "managed", query)["total"], 0)
        for query in ({"server_ids": [], "search": self.sources[0]}, {"server_ids": ["payments-b"], "server_id": "billing-a"}):
            self.assertEqual(views.listing(self.store, "learned", query)["total"], 0)

    def test_sources_never_enter_navigation_decoder_and_exact_details_remain_identical(self):
        real_loads = json.loads
        def projection_only(raw):
            for source in self.sources:
                self.assertNotIn(source, raw)
            return real_loads(raw)
        real_all = self.store._all
        def no_source_catalogue(db, table):
            if table in ("policies", "learning_allow_policies"):
                raise AssertionError("A public read traversed canonical source records")
            return real_all(db, table)
        with patch.object(views, "json", SimpleNamespace(loads=projection_only, dumps=json.dumps)), patch.object(self.store, "_all", side_effect=no_source_catalogue):
            ordinary = views.listing(self.store, "managed", {"server_ids": ["billing-a"], "ports": ["8443/tcp"], "limit": 1})
            learned = views.listing(self.store, "learned", {"server_ids": ["billing-a"], "session_id": "session-a", "search": self.sources[1]})
            self.assertEqual((ordinary["total"], learned["total"]), (2, 2))
            refs = views.service_groups(self.store, "https-group")
            self.assertEqual(refs["policy_count"], 1)
        self.assertEqual(views.detail(self.store, "managed", self.direct["id"]), self.direct)
        self.assertEqual(views.detail(self.store, "managed", self.grouped["id"]), self.grouped)
        self.assertEqual(views.detail(self.store, "learned", self.learned["id"]), self.learned)

    def test_byte_limited_navigation_advances_by_actual_items_without_loss(self):
        query = {"server_ids": ["billing-a"], "ports": ["8443/tcp"], "limit": 2}
        both = views.listing(self.store, "managed", query)
        budget = max(len(json.dumps(item, separators=(",", ":"), ensure_ascii=False).encode()) for item in both["items"]) + 32
        with patch.object(views, "MAX_PAGE_BYTES", budget):
            first = views.listing(self.store, "managed", query)
            self.assertEqual((len(first["items"]), first["total"], first["next_offset"], first["has_more"], first["byte_limited"]), (1, 2, 1, True, True))
            second = views.listing(self.store, "managed", {**query, "offset": first["next_offset"]})
        self.assertEqual([row["id"] for row in first["items"] + second["items"]], ["managed-direct", "managed-grouped"])
        self.assertFalse(second["has_more"])

    def test_summary_and_source_omission_cannot_replace_current_policy(self):
        before = copy.deepcopy(self.direct)
        summary = views.listing(self.store, "managed", {"server_ids": ["billing-a"], "ports": ["8443/tcp"], "limit": 1})["items"][0]
        for value in (summary, {**before, "services": [{**before["services"][0], "sources_omitted": True, "sources": []}]}):
            with self.assertRaises(ValueError):
                self.store.save_policy(value, "fixture", before["id"])
        self.assertEqual(views.detail(self.store, "managed", before["id"]), before)

    def test_concurrent_exact_revision_edits_have_one_winner_and_no_lost_update(self):
        def change(label):
            try:
                return self.store.save_policy({**copy.deepcopy(self.direct), "name": label, "expected_revision": 1}, "fixture", self.direct["id"])["revision"]
            except WorkflowConflict:
                return "stale"
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(change, ("Exact update A", "Exact update B")))
        self.assertEqual(sorted(results, key=str), [2, "stale"])
        current = views.detail(self.store, "managed", self.direct["id"])
        self.assertEqual(current["revision"], 2)
        self.assertEqual(current["services"], self.direct["services"])
