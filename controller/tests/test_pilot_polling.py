import tempfile
import unittest
from controller import agent_settings as settings, pilot_polling
from controller.firewall import WorkflowConflict
from controller.store import Store


class PilotPollingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.store = Store(temporary.name)
        for index in range(22):
            self.store.report('host-' + str(index), {'hostname': 'host-' + str(index), 'ips': ['10.1.0.' + str(index + 1)], 'capabilities': [settings.CAPABILITY], 'listeners': []})

    def preview(self, ids, revision=0):
        return pilot_polling.preview(self.store, {'server_ids': ids, 'expected_revision': revision})

    def test_scoped_twenty_only_changes_discovery_and_preserves_global900(self):
        value = self.preview(['host-' + str(i) for i in range(20)])
        self.assertEqual(value['configuration']['defaults'], settings.DEFAULTS)
        self.assertEqual(value['effective_change_count'], 20)
        self.assertEqual(settings.get(self.store)['revision'], 0)
        settings.save(self.store, value['configuration'], 'super')
        for index in range(22):
            desired = settings.assignment(self.store, 'host-' + str(index))
            self.assertEqual(desired['control_interval_seconds'], 30)
            self.assertEqual(desired['discovery_interval_seconds'], 60 if index < 20 else 900)

    def test_invalid_scope_and_stale_revision_rejected(self):
        for identifiers in ([], ['host-0'] * 2, ['host-' + str(i) for i in range(21)], ['missing']):
            with self.assertRaises(ValueError): self.preview(identifiers)
        with self.assertRaises(WorkflowConflict): self.preview(['host-0'], 9)
        with self.store.meta() as db:
            host = self.store._get(db, 'servers', 'host-0'); host['capabilities'] = []; self.store._put(db, 'servers', host)
        with self.assertRaises(ValueError): self.preview(['host-0'])

    def test_replacement_discloses_old_scope_restored_and_keeps_operator_defaults(self):
        first = self.preview(['host-0']); first['configuration']['defaults']['discovery_interval_seconds'] = 1200
        settings.save(self.store, first['configuration'], 'super')
        second = self.preview(['host-1'], 1)
        self.assertEqual(second['pilot']['removed_server_ids'], ['host-0'])
        self.assertEqual(second['configuration']['defaults']['discovery_interval_seconds'], 1200)
        self.assertEqual({row['server_id'] for row in second['affected_servers']}, {'host-0', 'host-1'})

    def test_equal_priority_conflict_is_explicit_and_other_rules_unchanged(self):
        body = {'expected_revision': 0, 'defaults': dict(settings.DEFAULTS), 'rules': [{'id': 'a-wins', 'name': 'Existing exception', 'priority': 10000, 'enabled': True, 'server_ids': ['host-0'], 'group_ids': [], 'selector': {}, 'discovery_interval_seconds': 300}]}
        settings.save(self.store, body, 'super')
        with self.assertRaises(WorkflowConflict): self.preview(['host-0'], 1)
        value = self.preview(['host-1'], 1)
        self.assertEqual(next(row for row in value['configuration']['rules'] if row['id'] == 'a-wins'), settings.get(self.store)['rules'][0])

    def test_reserved_id_cannot_silently_replace_a_custom_broad_rule(self):
        settings.save(self.store, {'expected_revision': 0, 'defaults': dict(settings.DEFAULTS), 'rules': [{'id': pilot_polling.PRESET_ID, 'name': 'Operator broad rule', 'priority': 10000, 'enabled': True, 'server_ids': [], 'group_ids': [], 'selector': {'application': 'billing'}, 'control_interval_seconds': 30, 'discovery_interval_seconds': 60}]}, 'super')
        with self.assertRaises(WorkflowConflict): self.preview(['host-1'], 1)
        self.assertEqual(settings.get(self.store)['rules'][0]['name'], 'Operator broad rule')
