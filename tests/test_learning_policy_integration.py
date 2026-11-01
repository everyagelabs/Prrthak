"""Loopback-only acceptance for exact observed access and additive learning grants."""
import csv
import http.client
import io
import ipaddress
import tempfile
import unittest
from datetime import timedelta
from unittest.mock import patch

from controller.app import App
from controller.store import Store, digest, now, stamp
from test_integration import request, running


class LearningPolicyAcceptanceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.store = Store(temp.name)
        context = running(App(self.store, demo=True))
        self.port = context.__enter__()
        self.addCleanup(context.__exit__, None, None, None)
        self.batch_number = 0
        self.report('learn-a', '10.70.0.11')
        self.report('target-b', '10.70.0.12')

    def api(self, method, path, value=None, status=200, headers=None):
        code, body, _ = request(self.port, method, '/api/v1/' + path, value, headers)
        self.assertEqual(code, status, body)
        return body

    def report(self, identifier, address, **extra):
        protected = {'management_sources': ['10.90.0.0/24'], 'ssh_ports': [2022],
                     'controller_url': 'https://controller.example',
                     'management_probe_url': 'https://controller.example/api/v1/agent/enforcement/check', 'zone': 'public'}
        payload = {'hostname': identifier, 'ips': [address], 'firewalld_state': 'running',
                   'listeners': [{'port': port, 'protocol': 'tcp', 'address': '0.0.0.0',
                                  'process': 'sshd' if port == 2022 else 'api-service',
                                  'service': 'SSH' if port == 2022 else 'Billing API'} for port in (2022, 80, 443, 8443, 9090)],
                   'discovery_performed': True, 'discovered_at': stamp(),
                   'capabilities': ['learning_discovery_v1', 'learning_auto_allow_v1'], 'agent_version': '0.4.0',
                   'protection': {**protected, 'digest': digest(protected), 'ready': True, 'blockers': []}, **extra}
        return self.api('POST', 'agent/report', payload, headers={'X-Agent-ID': identifier})

    def start(self, action='observe', selected=None):
        payload = {'server_ids': ['learn-a'], 'selection_mode': 'discovered', 'policy_action': action,
                   'duration_seconds': 3600}
        if action == 'auto_allow':
            payload['auto_allow_confirmed'] = True
        if selected:
            payload['port_filter'] = selected
        session = self.api('POST', 'learning', payload, 201)
        self.report('learn-a', '10.70.0.11', learning_discovery_session_ids=[session['id']])
        return session

    def upload(self, session, tuples, at=None):
        self.batch_number += 1
        events = [{'source_ip': source, 'port': port, 'protocol': protocol, 'verdict': verdict,
                   'count': count, 'first_seen': at or stamp(), 'last_seen': at or stamp()}
                  for source, port, protocol, verdict, count in tuples]
        payload = {'batch_id': 'accepted-' + str(self.batch_number), 'session_id': session['id'], 'events': events}
        self.api('POST', 'agent/flows', payload, 202, {'X-Agent-ID': 'learn-a'})
        self.store.process_flows()
        return payload

    def assignment(self, identifier='learn-a'):
        return self.api('GET', 'agent/policy', headers={'X-Agent-ID': identifier})

    def evidence(self, session):
        return self.api('GET', 'learning/' + session['id'] + '/recommendations')

    def test_443_auto_mode_does_not_change_22_80_or_authorize_other_managed_policy(self):
        before = self.assignment()
        session = self.start('auto_allow', [{'port': 443, 'protocol': 'tcp'}])
        self.upload(session, [('10.50.0.5', 443, 'tcp', 'observed', 3), ('10.50.0.6', 443, 'tcp', 'denied', 1)])
        navigation = self.api('GET', 'learning-policies')
        self.assertTrue(navigation['summary_only'])
        self.assertNotIn('sources', navigation['items'][0]['services'][0])
        generated = [self.api('GET', 'learning-policies/' + item['id']) for item in navigation['items']]
        self.assertEqual(len(generated), 1)
        self.assertEqual(generated[0]['services'], [{'port': 443, 'protocol': 'tcp', 'sources': ['10.50.0.5/32', '10.50.0.6/32']}])
        current = self.assignment()
        self.assertEqual(current['learning_sessions'][0]['ports'], [{'port': 443, 'protocol': 'tcp'}])
        self.assertTrue(current['learning_allow']['authorized'])
        self.assertFalse(current['enforcement']['authorized'])
        self.assertEqual((current['version'], current['digest'], current['services']), (before['version'], before['digest'], before['services']))
        self.assertEqual({row['port'] for row in self.api('GET', 'servers/learn-a')['listeners']}, {2022, 80, 443, 8443, 9090})
        for port in (80, 2022):
            event = {'source_ip': '10.50.0.9', 'port': port, 'protocol': 'tcp', 'first_seen': stamp(), 'last_seen': stamp()}
            self.api('POST', 'agent/flows', {'batch_id': 'outside-' + str(port), 'session_id': session['id'], 'events': [event]}, 400, {'X-Agent-ID': 'learn-a'})
        self.assertNotEqual(generated[0]['status'], 'applied')
        self.assertEqual(self.api('GET', 'overview')['learning_policies'][0]['id'], generated[0]['id'])

    def test_observe_review_applies_only_selected_pairs_to_frozen_group_members(self):
        session = self.start()
        self.upload(session, [('10.50.0.5', 8443, 'tcp', 'observed', 3), ('10.50.0.6', 9090, 'tcp', 'observed', 7)])
        evidence = self.evidence(session)
        self.assertEqual(len(evidence['rows']), 2)
        self.assertEqual(self.api('GET', 'learning-policies')['items'], [])
        chosen = next(row for row in evidence['rows'] if row['port'] == 8443)
        group = self.api('POST', 'groups', {'name': 'Selected Billing servers', 'type': 'static', 'server_ids': ['learn-a', 'target-b']}, 201)
        base = 'learning/' + session['id'] + '/recommendations/'
        body = {'row_ids': [chosen['id']], 'group_ids': [group['id']], 'name': 'Reviewed Billing 8443', 'expected_evidence_revision': evidence['evidence_revision']}
        plan = self.api('POST', base + 'preview', body, 201)
        self.assertEqual(plan['target_server_ids'], ['learn-a', 'target-b'])
        self.api('PUT', 'groups/' + group['id'], {'name': group['name'], 'type': 'static', 'server_ids': ['learn-a']})
        self.api('POST', base + 'apply', {'preview_id': plan['id'], 'digest': plan['digest'], 'confirm': True}, 409)
        plan = self.api('POST', base + 'preview', body, 201)
        applied = self.api('POST', base + 'apply', {'preview_id': plan['id'], 'digest': plan['digest'], 'confirm': True}, 201)
        self.assertEqual(applied['target_server_ids'], ['learn-a'])
        self.assertEqual(applied['policies'][0]['services'], [{'port': 8443, 'protocol': 'tcp', 'sources': ['10.50.0.5/32']}])
        self.assertEqual(self.assignment('target-b')['learning_allow']['generation'], 0)
        again = self.api('POST', base + 'apply', {'preview_id': plan['id'], 'digest': plan['digest'], 'confirm': True}, 201)
        self.assertTrue(again['duplicate'])

    def test_stop_prevents_new_automatic_sources_but_keeps_evidence_for_review(self):
        session = self.start('auto_allow', [{'port': 8443, 'protocol': 'tcp'}])
        payload = self.upload(session, [('10.50.0.5', 8443, 'tcp', 'observed', 2)])
        navigation = self.api('GET', 'learning-policies')['items'][0]
        policy = self.api('GET', 'learning-policies/' + navigation['id'])
        self.api('POST', 'learning/' + session['id'] + '/stop', {})
        self.upload(session, [('10.50.0.6', 8443, 'tcp', 'observed', 4)], payload['events'][0]['last_seen'])
        self.assertEqual(self.api('GET', 'learning-policies/' + policy['id'])['services'], policy['services'])
        self.assertEqual(len(self.evidence(session)['rows']), 2)
        self.assertFalse(self.assignment()['learning_allow']['authorized'])

    def test_export_contains_all_pairs_beyond_dashboard_limit_and_survives_retention(self):
        session = self.start(selected=[{'port': 8443, 'protocol': 'tcp'}])
        source = int(ipaddress.ip_address('10.50.1.1'))
        batch = self.upload(session, [(str(ipaddress.ip_address(source + i)), 8443, 'tcp', 'observed', 2) for i in range(601)])
        self.api('POST', 'agent/flows', batch, 202, {'X-Agent-ID': 'learn-a'})
        self.store.process_flows()
        evidence = self.evidence(session)
        self.assertEqual(evidence['total_rows'], 601)
        self.assertEqual(len(evidence['rows']), 200)
        self.assertTrue(evidence['has_more'])
        with patch('controller.store.now', return_value=now() + timedelta(hours=25)):
            self.store.prune()
        self.assertEqual(self.store.flows(), [])
        with running(App(self.store, tokens={'read_only': 'fixture-ro'})) as ro_port:
            connection = http.client.HTTPConnection('127.0.0.1', ro_port, timeout=10)
            connection.request('GET', '/api/v1/learning/' + session['id'] + '/export.csv', headers={'Authorization': 'Bearer fixture-ro'})
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            self.assertIn('text/csv', response.getheader('Content-Type'))
            exported = list(csv.DictReader(io.StringIO(response.read().decode('utf-8-sig'))))
            connection.close()
        self.assertEqual(len(exported), 601)
        self.assertTrue(all(int(row['count']) == 2 and row['port'] == '8443' for row in exported))

    def test_role_guards_and_exact_generation_protect_mutations_and_health_witness(self):
        session = self.start('auto_allow', [{'port': 8443, 'protocol': 'tcp'}])
        self.upload(session, [('10.50.0.5', 8443, 'tcp', 'observed', 1)])
        navigation = self.api('GET', 'learning-policies')['items'][0]
        policy = self.api('GET', 'learning-policies/' + navigation['id'])
        with running(App(self.store, tokens={'read_only': 'fixture-ro'})) as ro_port:
            read_only = {'Authorization': 'Bearer fixture-ro'}
            for method, path, body in [
                ('PATCH', 'learning-policies/' + policy['id'], {'expected_revision': policy['revision'], 'services': []}),
                ('DELETE', 'learning-policies/' + policy['id'], {'expected_revision': policy['revision']}),
                ('POST', 'learning/' + session['id'] + '/recommendations/preview', {})]:
                self.assertEqual(request(ro_port, method, '/api/v1/' + path, body, read_only)[0], 403)
        grant = self.assignment()['learning_allow']
        bad = {'hostname': 'learn-a', 'ips': ['10.70.0.11'], 'discovery_performed': False,
               'learning_allow_outcome': {'status': 'applied', 'generation': grant['generation'] + 99,
                                          'digest': grant['digest'], 'binding_digest': grant['binding_digest']}}
        self.api('POST', 'agent/report', bad, 403, {'X-Agent-ID': 'learn-a'})
        self.api('POST', 'agent/learning-allow/check', {'nonce': 'x' * 32, 'ssh_ports': [2022]}, 403, {'X-Agent-ID': 'learn-a'})
