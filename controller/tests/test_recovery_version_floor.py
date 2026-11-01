import copy
import tempfile
import unittest

from controller.store import Store


class RecoveryVersionFloorTests(unittest.TestCase):
    def test_restored_intent_reissues_above_retained_history_without_authorizing_it(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            store.report('target', {'hostname': 'target', 'ips': ['10.241.7.9'], 'listeners': []})
            store.update_server('target', {'tags': {'application': 'billing'}}, 'admin')
            original = store.save_policy({'name': 'Billing', 'selector': {'application': 'billing'}, 'mode': 'enforce', 'services': [{'port': 443, 'protocol': 'tcp', 'sources': ['10.0.0.1/32']}]}, 'admin')
            old_server = copy.deepcopy(store.get('servers', 'target'))
            store.save_policy({**original, 'services': [{'port': 443, 'protocol': 'tcp', 'sources': ['10.0.0.2/32']}]}, 'admin', original['id'])
            highwater = store.assignment('target')[0]['version']
            with store.meta() as db:
                # Model a restore of the old policy + desired snapshot while
                # retaining the current immutable safety history.
                store._put(db, 'policies', original)
                store._put(db, 'servers', old_server)
                store.compile_all(db)
            assignment = store.assignment('target')[0]
            self.assertGreater(assignment['version'], highwater)
            self.assertEqual(assignment['digest'], old_server['_compiled']['digest'])
            self.assertFalse(assignment['enforcement']['authorized'])
            self.assertEqual(len(store.policy_history('target')), 4)
