"""HTTP acceptance for reusable port groups and fresh per-server learning."""
from datetime import timedelta
import tempfile
import unittest

from controller.app import App
from controller.store import Store, now, stamp
from controller.tests.capture_fixture import typed_event
from test_integration import request, running


class ServiceLearningAcceptanceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.store = Store(temp.name)
        context = running(App(self.store, demo=True))
        self.port = context.__enter__()
        self.addCleanup(context.__exit__, None, None, None)

    def api(self, method, path, body=None, status=200, headers=None):
        code, value, _ = request(self.port, method, '/api/v1/' + path, body, headers)
        self.assertEqual(code, status, value)
        return value

    def report(self, identifier, ports, ip=None, **extra):
        report = {'hostname': identifier, 'ips': [ip or '10.70.0.11'],
                  'listeners': [{'port': port, 'protocol': 'tcp', 'address': '0.0.0.0'} for port in ports],
                  'discovery_performed': True, 'discovered_at': stamp(), 'firewalld_state': 'running',
                  'agent_version': '0.9.0', 'capabilities': ['learning_discovery_v1','traffic_capture_v1'], **extra}
        self.api('POST', 'agent/report', report, headers={'X-Agent-ID': identifier})
        return report

    def assignment(self, identifier):
        return self.api('GET', 'agent/policy', headers={'X-Agent-ID': identifier})

    def test_reusable_port_group_and_multiple_source_groups_stay_aligned_per_row(self):
        self.report('billing', [2022, 8080])
        self.api('PATCH', 'servers/billing', {'tag_updates': {'application': 'billing'}})
        self.report('lb', [], '10.20.0.1')
        self.report('monitor', [], '10.20.0.2')
        self.api('PATCH', 'servers/monitor', {'tag_updates': {'role': 'monitoring'}})
        lb = self.api('POST', 'groups', {'name': 'Load balancers', 'type': 'static', 'server_ids': ['lb']}, 201)
        monitors = self.api('POST', 'groups', {'name': 'Monitoring', 'type': 'dynamic', 'selector': {'role': 'monitoring'}}, 201)
        web = self.api('POST', 'service-groups', {'name': 'Web', 'ports': [{'port': 80, 'protocol': 'tcp'}, {'port': 443, 'protocol': 'tcp'}]}, 201)
        policy = self.api('POST', 'policies', {'name': 'Billing service mappings', 'selector': {'application': 'billing'}, 'mode': 'enforce',
                          'services': [{'service_group_id': web['id'], 'sources': ['10.99.0.0/24'], 'source_group_ids': [lb['id'], monitors['id']]},
                                       {'port': 2022, 'protocol': 'tcp', 'sources': ['10.88.0.0/24']}]}, 201)
        bundle = self.assignment('billing')
        by_port = {row['port']: row for row in bundle['services']}
        for port in (80, 443):
            self.assertEqual(by_port[port]['sources'], ['10.20.0.1/32', '10.20.0.2/32', '10.99.0.0/24'])
        self.assertEqual(by_port[2022]['sources'], ['10.88.0.0/24'])
        self.assertFalse(bundle['enforcement']['authorized'])
        self.api('DELETE', 'service-groups/' + web['id'], status=400)
        self.api('DELETE', 'groups/' + lb['id'], status=400)
        proposed = {**web, 'expected_revision': web['revision'], 'ports': web['ports'] + [{'port': 8443, 'protocol': 'tcp'}]}
        preview = self.api('POST', 'service-groups/preview', proposed)
        self.assertEqual(preview['affected_server_ids'], ['billing'])
        self.assertEqual(self.assignment('billing')['version'], bundle['version'])
        edited = self.api('PUT', 'service-groups/' + web['id'], proposed)
        self.assertEqual(edited['revision'], 2)
        self.assertGreater(self.assignment('billing')['version'], bundle['version'])
        self.assertEqual(self.assignment('billing')['services'][-1]['port'], 8443)
        self.assertFalse(self.assignment('billing')['enforcement']['authorized'])
        self.api('PUT', 'service-groups/' + web['id'], proposed, 409)
        historical = self.api('GET', 'policies/' + policy['id'] + '/revisions/1')
        self.assertEqual(historical['services'][0]['service_group_snapshot']['ports'], web['ports'])
        self.assertEqual(len(self.api('GET', 'service-groups/' + web['id'] + '/revisions')['items']), 2)

    def test_auto_learning_uses_fresh_per_endpoint_ports_and_freezes_the_snapshot(self):
        self.report('host-a', [2022, 8080])
        self.report('host-b', [5432], '10.70.0.12')
        preview = self.api('POST', 'learning/preview', {'server_ids': ['host-a', 'host-b']})
        self.assertEqual(preview['freshness'], 'cached_preview')
        session = self.api('POST', 'learning', {'server_ids': ['host-a', 'host-b'], 'selection_mode': 'discovered', 'duration_seconds': 3600}, 201)
        version = self.assignment('host-a')['version']
        pending = self.assignment('host-a')['learning_sessions'][0]
        self.assertTrue(pending['discovery_pending'])
        self.assertEqual(pending['ports'], [])
        stale = {'hostname': 'host-a', 'ips': ['10.70.0.11'], 'listeners': [], 'discovery_performed': True,
                 'discovered_at': stamp(now() - timedelta(minutes=1)), 'capabilities': ['learning_discovery_v1','traffic_capture_v1'],
                 'learning_discovery_session_ids': [session['id']]}
        self.api('POST', 'agent/report', stale, 400, {'X-Agent-ID': 'host-a'})
        self.report('host-a', [2022, 9090], learning_discovery_session_ids=[session['id']])
        self.report('host-b', [], '10.70.0.12', learning_discovery_session_ids=[session['id']],
                    listeners=[{'port': 5432, 'protocol': 'tcp', 'address': '0.0.0.0'},
                               {'port': 53, 'protocol': 'udp', 'address': '::'},
                               {'port': 11211, 'protocol': 'tcp', 'address': '127.0.0.1'}])
        a = self.assignment('host-a')['learning_sessions'][0]
        b = self.assignment('host-b')['learning_sessions'][0]
        self.assertEqual(a['ports'], [{'port': 2022, 'protocol': 'tcp'}, {'port': 9090, 'protocol': 'tcp'}])
        self.assertEqual(b['ports'], [{'port': 5432, 'protocol': 'tcp'}, {'port': 53, 'protocol': 'udp'}])
        self.assertNotIn('server_ports', a)
        self.assertFalse(a['discovery_pending'])
        self.assertEqual(self.assignment('host-a')['version'], version)
        def upload(host, port, status):
            event = typed_event('10.50.0.1',port,identity=session['id']+host+str(port))
            self.api('POST', 'agent/flows', {'batch_id': host + '-' + str(port), 'session_id': session['id'], 'events': [event]}, status, {'X-Agent-ID': host})
        upload('host-a', 9090, 202)
        upload('host-a', 5432, 400)
        upload('host-b', 9090, 400)
        upload('host-b', 5432, 202)
        self.report('host-a', [9999])
        self.assertEqual(self.assignment('host-a')['learning_sessions'][0]['ports'], a['ports'])
        upload('host-a', 9999, 400)
        self.api('POST', 'learning/' + session['id'] + '/stop', {})
        tombstone = self.assignment('host-a')['learning_tombstones'][0]
        self.assertEqual(tombstone['ports'], a['ports'])
        self.assertEqual(self.assignment('host-a')['version'], version)

    def test_unsupported_agents_no_listeners_and_role_guards_do_not_start_collection(self):
        self.report('legacy', [22], agent_version='0.2.0', capabilities=[])
        self.api('POST', 'learning', {'server_ids': ['legacy'], 'selection_mode': 'discovered'}, 400)
        self.api('POST', 'learning', {'server_ids': ['legacy'], 'ports': [{'port': 22, 'protocol': 'tcp'}]}, 400)
        # Stored pre-feature manual scope stays readable; current API cannot
        # create a journal-only downgrade for this old endpoint.
        manual={'id':'legacy-manual','server_ids':['legacy'],'selection_mode':'manual','ports':[{'port':22,'protocol':'tcp'}],
                'starts_at':stamp(),'expires_at':stamp(now()+timedelta(hours=1)),'status':'active','policy_action':'observe'}
        with self.store.meta() as db:self.store._put(db,'sessions',manual)
        self.assertEqual(self.assignment('legacy')['learning_sessions'][0]['ports'], manual['ports'])
        self.report('empty', [], '10.70.0.12')
        auto = self.api('POST', 'learning', {'server_ids': ['empty'], 'selection_mode': 'discovered'}, 201)
        self.report('empty', [], '10.70.0.12', learning_discovery_session_ids=[auto['id']])
        host = self.api('GET', 'servers/empty')
        self.assertEqual(host['learning_discovery_status'], 'no_listeners')
        self.assertEqual(host['collector_desired_status'], 'off')
        self.assertEqual(host['collector_status'], 'off')
        with running(App(self.store, tokens={'read_only': 'ro', 'admin': 'admin'})) as port:
            ro = {'Authorization': 'Bearer ro'}
            for path, body in [('service-groups', {'name': 'No', 'ports': [{'port': 80}]}),
                               ('service-groups/preview', {'name': 'No', 'ports': [{'port': 80}]}),
                               ('learning', {'server_ids': ['empty'], 'selection_mode': 'discovered'})]:
                self.assertEqual(request(port, 'POST', '/api/v1/' + path, body, ro)[0], 403)
            self.assertEqual(request(port, 'GET', '/api/v1/service-groups', headers=ro)[0], 200)


if __name__ == '__main__':
    unittest.main()
