import tempfile
import unittest

from controller import managed, policy_impact, policy_views, service_groups
from controller.store import Store, digest


class ExactEndpointPolicyTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.store = Store(directory.name)
        for identifier, ip in (("first", "10.0.0.1"), ("second", "10.0.0.2")):
            self.report(identifier, ip)
            self.store.update_server(identifier, {"tags": {"application": "billing"}}, "test")
        self.policy = {"name": "Exact host", "mode": "enforce",
                       "services": [{"port": 8443, "protocol": "tcp", "sources": ["192.0.2.1"]}]}

    def report(self, identifier, ip):
        self.store.report(identifier, {"hostname": identifier, "ips": [ip], "listeners": [], "applied_version": 0})

    def compiled(self, policies=None):
        with self.store.read_meta() as db:
            return service_groups.effective_bundles(self.store, db, policies=policies)

    def test_compiler_and_catalogue_keep_exact_identity_when_ip_changes(self):
        saved = self.store.save_policy({**self.policy, "endpoint_ids": ["first", "first"]}, "test")
        self.report("first", "10.0.0.9")
        self.report("second", "10.0.0.1")
        self.assertEqual(saved["endpoint_ids"], ["first"])
        result = self.compiled()
        self.assertEqual(result["targets"][saved["id"]], {"first"})
        self.assertEqual(result["payloads"]["first"]["services"][0]["sources"], ["192.0.2.1/32"])
        self.assertFalse(result["payloads"]["second"]["services"])
        self.assertEqual(policy_views.listing(self.store, value={"server_ids": ["first"]})["items"][0]["endpoint_ids"], ["first"])
        self.assertEqual(policy_views.listing(self.store, value={"server_ids": ["second"]})["total"], 0)
        self.assertEqual(managed.revisions(self.store, saved["id"], 1)["endpoint_ids"], ["first"])
        self.assertEqual(policy_impact.preview(self.store, policy_id=saved["id"])["summary"]["target_servers"], 1)

    def test_invalid_scope_and_implicit_fleet_expansion_are_rejected(self):
        for fields in ({"endpoint_ids": []}, {"endpoint_ids": None}, {"endpoint_ids": ["missing"]},
                       {"endpoint_ids": ["first"], "selector": {"application": "billing"}},
                       {"endpoint_ids": ["first"], "match_all": True}):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                self.store.save_policy({**self.policy, **fields}, "test")
        saved = self.store.save_policy({**self.policy, "endpoint_ids": ["first"]}, "test")
        with self.assertRaisesRegex(ValueError, "Explicitly confirm"):
            self.store.save_policy(self.policy, "test", saved["id"])
        with self.assertRaisesRegex(ValueError, "Explicitly confirm"):
            policy_impact.preview(self.store, {"policy": self.policy, "policy_id": saved["id"], "expected_revision": 1}, proposed=True)
        widened = self.store.save_policy({**self.policy, "match_all": True}, "test", saved["id"])
        self.assertNotIn("endpoint_ids", widened)

    def test_malformed_or_missing_exact_targets_never_become_fleet_targets(self):
        saved = self.store.save_policy({**self.policy, "endpoint_ids": ["first"]}, "test")
        for invalid in (None, [], "first", ["retired"]):
            with self.subTest(invalid=invalid):
                malformed = {**saved, "endpoint_ids": invalid}
                self.assertEqual(self.compiled([malformed])["targets"][saved["id"]], set())
                with self.store.meta() as db:
                    self.store._put(db, "policies", malformed)
                self.assertEqual(policy_views.listing(self.store, value={"server_ids": ["first"]})["total"], 0)

    def test_legacy_authority_digest_does_not_change(self):
        saved = self.store.save_policy(self.policy, "test")
        legacy = {key: saved[key] for key in ("id", "name", "selector", "group_ids", "mode", "services")}
        self.assertEqual(digest(managed.policy_intent(saved)), digest(legacy))
        self.assertNotEqual(digest(managed.policy_intent({**saved, "endpoint_ids": ["first"]})), digest(legacy))
