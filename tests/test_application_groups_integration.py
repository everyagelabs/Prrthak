"""Application-group API acceptance; temporary inventory, no firewall changes."""
import tempfile
import unittest

from controller.app import App
from controller.store import Store
from test_integration import request, running


class ApplicationGroupAcceptance(unittest.TestCase):
    def test_applications_appear_as_reusable_groups_and_saved_policy_ids_survive(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            with running(App(store, demo=True)) as port:
                status, saved, _ = request(port, 'POST', '/api/v1/groups', {
                    'name': 'Saved Billing', 'type': 'dynamic', 'selector': {'application': 'billing'}})
                self.assertEqual(status, 201)
                for index, application in enumerate(('billing', 'payments', 'platform'), 1):
                    identifier = f'app-node-{index}'
                    status, _, _ = request(port, 'POST', '/api/v1/agent/report', {
                        'hostname': identifier, 'ips': [f'10.40.0.{index}'], 'listeners': [],
                        'firewalld_state': 'running', 'tags': {'application': 'untrusted-agent-value'}},
                        {'X-Agent-ID': identifier})
                    self.assertEqual(status, 200)
                    status, _, _ = request(port, 'PATCH', '/api/v1/servers/' + identifier,
                        {'tags': {'application': application}})
                    self.assertEqual(status, 200)
                groups = request(port, 'GET', '/api/v1/groups')[1]['items']
                application_groups = {item['application']: item for item in groups if item.get('application')}
                self.assertEqual(set(application_groups), {'billing', 'payments', 'platform'})
                self.assertEqual([application_groups[name]['member_count'] for name in sorted(application_groups)], [1, 1, 1])
                self.assertEqual(application_groups['billing']['id'], saved['id'])
                self.assertFalse(application_groups['billing'].get('managed', False))
                self.assertTrue(application_groups['payments']['managed'])
                self.assertTrue(application_groups['platform']['managed'])
                status, _, _ = request(port, 'POST', '/api/v1/policies', {
                    'name': 'Saved billing policy', 'group_ids': [saved['id']], 'mode': 'monitor',
                    'services': [{'port': 8443, 'protocol': 'tcp', 'sources': ['10.90.0.0/24']}]})
                self.assertEqual(status, 201)
                assigned = request(port, 'GET', '/api/v1/servers/app-node-1')[1]['compiled_policy']
                self.assertEqual(assigned['services'][0]['port'], 8443)
                # A saved group's definition remains editable. A replacement full
                # application group must appear without rewriting the policy ID.
                status, updated, _ = request(port, 'PUT', '/api/v1/groups/' + saved['id'], {
                    'name': 'Critical Billing', 'type': 'dynamic',
                    'selector': {'application': 'billing', 'criticality': 'high'}})
                self.assertEqual(status, 200)
                self.assertEqual(updated['id'], saved['id'])
                groups = request(port, 'GET', '/api/v1/groups')[1]['items']
                replacement = next(item for item in groups if item.get('application') == 'billing')
                self.assertNotEqual(replacement['id'], saved['id'])
                self.assertEqual(replacement['member_ids'], ['app-node-1'])
                self.assertEqual(request(port, 'GET', '/api/v1/servers/app-node-1')[1]['compiled_policy']['services'], [])
                request(port, 'PATCH', '/api/v1/servers/app-node-1', {
                    'tags': {'application': 'billing', 'criticality': 'high'}})
                self.assertEqual(request(port, 'GET', '/api/v1/servers/app-node-1')[1]['compiled_policy']['services'][0]['port'], 8443)
                overview = request(port, 'GET', '/api/v1/overview')[1]
                self.assertEqual({group.get('application') for group in overview['groups'] if group.get('application')}, {'billing', 'payments', 'platform'})


if __name__ == '__main__':
    unittest.main()
