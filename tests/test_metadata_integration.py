"""HTTP acceptance for dashboard-owned classification. No firewall mutations."""
import tempfile
import unittest
from urllib.parse import quote

from controller.app import App
from controller.store import Store
from test_integration import request, running


class CentralMetadataAcceptanceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.store = Store(temp.name)
        context = running(App(self.store, demo=True))
        self.port = context.__enter__()
        self.addCleanup(context.__exit__, None, None, None)

    def api(self, method, path, body=None, status=200):
        code, result, _ = request(self.port, method, '/api/v1/' + path, body)
        self.assertEqual(code, status, result)
        return result

    def report(self, identifier='untagged', ip='10.241.1.10', **extra):
        body = {'hostname': identifier, 'ips': [ip], 'listeners': [],
                'firewalld_state': 'running', **extra}
        code, result, _ = request(self.port, 'POST', '/api/v1/agent/report', body,
                                  {'X-Agent-ID': identifier})
        self.assertEqual(code, 200, result)
        return self.api('GET', 'servers/' + identifier)

    def location(self, name):
        return self.api('POST', 'locations',
                        {'name': name, 'type': 'datacenter', 'location': 'Test lab'}, 201)['id']

    def apply_plan(self, category, plan, status=200):
        return self.api('POST', 'metadata/' + category + '/' + plan['id'] + '/apply',
                        {'confirmation_nonce': plan.get('confirmation_nonce')}, status)

    def subnet(self, location):
        plan = self.api('POST', 'metadata/subnets/preview',
                        {'cidr': '10.241.0.0/16', 'location_id': location}, 201)
        self.apply_plan('subnets', plan)
        return plan

    def test_dashboard_owns_tags_and_subnet_applies_to_current_and_future_inventory(self):
        initial = self.report(tags={'application': 'agent-forged'}, location_id='agent-forged')
        self.assertEqual(initial['tags'], {})
        self.assertIsNone(initial['location_id'])
        noida = self.location('Noida 81 DC')
        other = self.location('Manual DC')
        plan = self.api('POST', 'metadata/subnets/preview',
                        {'cidr': '10.241.99.1/16', 'location_id': noida}, 201)
        self.assertIsNone(self.api('GET', 'servers/untagged')['location_id'])
        self.apply_plan('subnets', plan)
        current = self.api('GET', 'servers/untagged')
        self.assertEqual(current['location_id'], noida)
        self.assertEqual(current['location_source']['type'], 'subnet')
        future = self.report('future', '10.241.2.20', tags={'application': 'agent-forged'})
        self.assertEqual(future['location_id'], noida)
        self.assertEqual(future['tags'], {})
        self.api('PATCH', 'servers/untagged',
                 {'tag_updates': {'owner': 'infra'}, 'location_id': other})
        bulk = self.api('POST', 'metadata/bulk/preview',
                        {'server_ids': ['untagged', 'future'],
                         'tag_updates': {'application': 'billing', 'criticality': 'high'}}, 201)
        self.assertNotIn('application', self.api('GET', 'servers/future')['tags'])
        self.apply_plan('bulk', bulk)
        after = self.report(tags={'application': 'spoofed'}, location_id=noida)
        self.assertEqual(after['location_id'], other)
        self.assertEqual(after['location_source']['type'], 'manual')
        self.assertEqual(after['tags'], {'owner': 'infra', 'application': 'billing', 'criticality': 'high'})
        self.assertEqual(self.api('GET', 'servers/future')['tags']['application'], 'billing')
        self.api('PATCH', 'servers/untagged', {'location_mode': 'automatic'})
        self.assertEqual(self.api('GET', 'servers/untagged')['location_id'], noida)
        self.assertEqual(self.api('GET', 'metadata/subnets')['items'][0]['cidr'], '10.241.0.0/16')
        self.api('POST', 'enrollment-tokens',
                 {'name': 'forbidden defaults', 'tags': {'application': 'billing'}}, 400)

    def test_csv_exact_ip_precedence_reset_future_inventory_and_reviewed_removal(self):
        subnet_dc, csv_dc = self.location('Subnet DC'), self.location('CSV DC')
        self.report()
        self.subnet(subnet_dc)
        self.api('PATCH', 'servers/untagged', {'tag_updates': {'application': 'manual'}})
        text = 'ip,application,dc,tag.cost_center\n10.241.1.10,billing,CSV DC,42\n10.241.2.20,payments,CSV DC,88\n'
        plan = self.api('POST', 'metadata/imports/preview', {'csv': text}, 201)
        self.assertEqual(plan['summary']['future_ips'], 1)
        self.assertEqual(self.api('GET', 'metadata/imports/profiles')['total'], 0)
        self.apply_plan('imports', plan)
        server = self.api('GET', 'servers/untagged')
        self.assertEqual(server['location_id'], csv_dc)
        self.assertEqual(server['location_source']['type'], 'csv')
        self.assertEqual(server['tags'], {'application': 'manual', 'cost_center': '42'})
        self.api('PATCH', 'servers/untagged', {'reset_tag_keys': ['application']})
        self.assertEqual(self.api('GET', 'servers/untagged')['tags']['application'], 'billing')
        self.api('PATCH', 'servers/untagged', {'tag_updates': {'application': None}})
        self.assertNotIn('application', self.report()['tags'])
        future = self.report('future', '10.241.2.20', tags={'application': 'forged'})
        self.assertEqual(future['tags']['application'], 'payments')
        self.assertEqual(future['location_id'], csv_dc)
        listed = self.api('GET', 'metadata/imports/profiles?limit=1&offset=1')
        self.assertEqual((listed['total'], listed['limit'], listed['offset']), (2, 1, 1))
        remove = self.api('POST', 'metadata/imports/profiles/' + quote('10.241.1.10', safe='') + '/delete-preview', {}, 201)
        self.assertEqual(self.api('GET', 'servers/untagged')['location_id'], csv_dc)
        self.apply_plan('imports', remove)
        after = self.api('GET', 'servers/untagged')
        self.assertEqual(after['location_id'], subnet_dc)
        self.assertEqual(after['tags'], {})
        self.assertIn('application', after['metadata_removed_tag_keys'])
        self.assertEqual(self.api('GET', 'metadata/imports/profiles')['total'], 1)
        self.apply_plan('imports', remove, 409)

    def test_preview_survives_heartbeat_but_metadata_change_and_ip_change_reject_stale_apply(self):
        self.report()
        payload = {'server_ids': ['untagged'], 'tag_updates': {'application': 'billing'}}
        plan = self.api('POST', 'metadata/bulk/preview', payload, 201)
        self.report()
        self.apply_plan('bulk', plan)
        stale = self.api('POST', 'metadata/bulk/preview',
                         {**payload, 'tag_updates': {'application': 'payments'}}, 201)
        self.api('PATCH', 'servers/untagged', {'tag_updates': {'owner': 'admin'}})
        self.apply_plan('bulk', stale, 409)
        ip_stale = self.api('POST', 'metadata/bulk/preview', payload, 201)
        self.report(ip='10.242.1.10')
        self.apply_plan('bulk', ip_stale, 409)
        self.assertEqual(self.api('GET', 'servers/untagged')['tags'],
                         {'application': 'billing', 'owner': 'admin'})

    def test_invalid_csv_and_bulk_are_atomic_and_no_firewall_mutation_is_authorized(self):
        self.report()
        before = self.api('GET', 'servers/untagged')
        invalid = self.api('POST', 'metadata/imports/preview',
                           {'csv': 'ip,application,dc\n10.241.1.10,billing,Unknown DC\n10.241.2.20,payments,Unknown DC\n'}, 201)
        self.assertEqual(invalid['status'], 'invalid')
        self.apply_plan('imports', invalid, 409)
        self.api('POST', 'metadata/bulk/preview',
                 {'server_ids': ['untagged', 'missing'], 'tag_updates': {'application': 'billing'}}, 400)
        after = self.api('GET', 'servers/untagged')
        self.assertEqual(after['tags'], before['tags'])
        self.assertEqual(after['location_id'], before['location_id'])
        self.assertEqual(self.api('GET', 'metadata/imports/profiles')['total'], 0)
        self.assertFalse(after['compiled_policy'].get('enforcement', {}).get('authorized', False))

    def test_new_metadata_operations_enforce_admin_role(self):
        self.report()
        tokens = {'admin': 'admin-secret', 'operator': 'operator-secret', 'viewer': 'viewer-secret'}
        with running(App(self.store, tokens=tokens)) as port:
            for role in ('operator', 'viewer'):
                headers = {'Authorization': 'Bearer ' + tokens[role]}
                for body in ({'tag_updates': {'application': 'billing'}},
                             {'reset_tag_keys': ['application']}, {'location_mode': 'automatic'},
                             {'location_id': None}, {'tags': {}}):
                    self.assertEqual(request(port, 'PATCH', '/api/v1/servers/untagged', body, headers)[0], 403)
                self.assertEqual(request(port, 'POST', '/api/v1/metadata/bulk/preview',
                                         {'server_ids': ['untagged'], 'tag_updates': {'application': 'billing'}}, headers)[0], 403)
                self.assertEqual(request(port, 'POST', '/api/v1/metadata/imports/preview',
                                         {'csv': 'ip,application\n10.241.1.10,billing\n'}, headers)[0], 403)
                self.assertEqual(request(port, 'GET', '/api/v1/metadata/imports/profiles', headers=headers)[0], 403)
                self.assertEqual(request(port, 'GET', '/api/v1/metadata/subnets', headers=headers)[0], 200)
            operator = {'Authorization': 'Bearer ' + tokens['operator']}
            self.assertEqual(request(port, 'PATCH', '/api/v1/servers/untagged',
                                     {'expected_services': [{'port': 2022, 'protocol': 'tcp'}]}, operator)[0], 403)


if __name__ == '__main__':
    unittest.main()
