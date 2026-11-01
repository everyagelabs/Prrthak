"""Controller HTTP acceptance for imported rules; no firewall access is changed."""
import tempfile
import unittest

from controller.app import App
from controller.firewall import fingerprints
from controller.store import Store, stamp
from test_integration import request, running


BROAD_ALLOW = 'rule family="ipv4" source address="0.0.0.0/0" accept'


def snapshot(include_broad=True):
    rules = []
    for scope in ('runtime', 'permanent'):
        for kind, value in [('service', 'ssh'), ('port', '8080/tcp')] + ([('rich_rule', BROAD_ALLOW)] if include_broad else []):
            rules.append({'scope': scope, 'zone': 'public', 'kind': kind, 'value': value, 'editable': True})
    return {'collected_at': stamp(), 'status': 'ok', 'rules': rules, 'capabilities': ['runtime', 'permanent']}


class FirewallHTTPAcceptance(unittest.TestCase):
    def test_one_reviewed_removal_is_delivered_to_twenty_hosts_only_after_two_confirmations(self):
        with tempfile.TemporaryDirectory() as temp:
            store = Store(temp)
            with running(App(store, demo=True)) as port:
                ids = [f'billing-{number:02}' for number in range(1, 21)]
                reports = {}
                for number, identifier in enumerate(ids, 1):
                    reports[identifier] = {'hostname': identifier, 'ips': [f'10.44.0.{number}'], 'firewalld_state': 'running',
                        'listeners': [{'port': 22, 'protocol': 'tcp', 'process': 'sshd'}], 'firewall_snapshot': snapshot()}
                    self.assertEqual(request(port, 'POST', '/api/v1/agent/report', reports[identifier], {'X-Agent-ID': identifier})[0], 200)
                status, inventory, _ = request(port, 'GET', '/api/v1/firewall')
                self.assertEqual(status, 200)
                common = next(rule for rule in inventory['common_rules'] if rule['value'] == BROAD_ALLOW)
                self.assertEqual(common['host_count'], 20)
                self.assertEqual(common['risk'], 'high')
                self.assertEqual(common['scope_host_counts'], {'runtime': 20, 'permanent': 20})
                self.assertTrue(all(item['snapshot']['summary_only'] and 'rules' not in item['snapshot'] for item in inventory['servers']))
                canonical = request(port, 'GET', '/api/v1/firewall?server_ids='+ids[0])[1]
                self.assertEqual(len(canonical['servers'][0]['snapshot']['rules']),6)
                status, draft, _ = request(port, 'POST', '/api/v1/firewall/changes', {'name': 'Remove broad billing access',
                    'server_ids': ids, 'rule_key': common['rule_key'], 'operation': 'remove', 'scopes': ['runtime', 'permanent']})
                self.assertEqual(status, 201)
                self.assertEqual(draft['preview']['matched_host_count'], 20)
                self.assertTrue(draft['requires_double_confirmation'])
                for identifier in ids:
                    self.assertFalse(request(port, 'GET', '/api/v1/agent/policy', headers={'X-Agent-ID': identifier})[1]['firewall_changes'])
                path = f"/api/v1/firewall/changes/{draft['id']}/confirm"
                status, first, _ = request(port, 'POST', path, {'confirmation_nonce': draft['confirmation_nonce']})
                self.assertEqual(status, 200)
                self.assertEqual(first['status'], 'awaiting_second_confirmation')
                self.assertEqual(request(port, 'POST', path, {'confirmation_nonce': draft['confirmation_nonce']})[0], 409)
                self.assertEqual(request(port, 'POST', path, {'confirmation_nonce': first['confirmation_nonce'], 'challenge': 'WRONG'})[0], 409)
                self.assertFalse(request(port, 'GET', '/api/v1/agent/policy', headers={'X-Agent-ID': ids[0]})[1]['firewall_changes'])
                status, queued, _ = request(port, 'POST', path, {'confirmation_nonce': first['confirmation_nonce'], 'challenge': first['confirmation_phrase']})
                self.assertEqual(status, 200)
                self.assertEqual(queued['status'], 'queued')
                for identifier in ids:
                    assignment = request(port, 'GET', '/api/v1/agent/policy', headers={'X-Agent-ID': identifier})[1]['firewall_changes']
                    self.assertEqual(len(assignment), 1)
                    self.assertEqual(assignment[0]['confirmation_count'], 2)
                    self.assertEqual(len(assignment[0]['operations']), 2)
                # Simulated agent read-back acknowledgements exercise delivery tracking;
                # actual firewalld execution is covered by the Go adapter tests/lab smoke.
                for identifier in ids:
                    report = {**reports[identifier], 'firewall_snapshot': snapshot(False), 'firewall_change_results': [{
                        'id': queued['id'], 'plan_digest': queued['plan_digest'], 'status': 'applied', 'message': 'Read-back verified in acceptance fixture'}]}
                    self.assertEqual(request(port, 'POST', '/api/v1/agent/report', report, {'X-Agent-ID': identifier})[0], 200)
                inventory = request(port, 'GET', '/api/v1/firewall')[1]
                self.assertFalse(any(rule['value'] == BROAD_ALLOW for rule in inventory['common_rules']))
                plan = next(plan for plan in inventory['changes'] if plan['id'] == queued['id'])
                self.assertEqual(plan['result_counts']['applied'],20)
                self.assertTrue(plan['summary_only'])
                status,plan,_=request(port,'GET','/api/v1/firewall/changes/'+queued['id'])
                self.assertEqual(status,200)
                self.assertEqual(len(plan['results']),20)
                self.assertEqual(plan['status'], 'applied')

    def test_security_observations_replay_once_and_multiport_hits_raise_possible_probe(self):
        with tempfile.TemporaryDirectory() as temp:
            store = Store(temp)
            with running(App(store, demo=True)) as port:
                stamp_now = stamp()
                events = [{'event_id': f'observation-{number}', 'kind': 'unexpected_port_hit', 'source_ip': '10.90.0.5',
                    'destination_ip': '10.44.0.1', 'port': number, 'protocol': 'tcp', 'count': 3,
                    'first_seen': stamp_now, 'last_seen': stamp_now, 'inventory_checked_at': stamp_now,
                    'listening': False, 'observed_while_monitoring': True} for number in range(9000, 9005)]
                report = {'hostname': 'probe-target', 'ips': ['10.44.0.1'], 'firewalld_state': 'running',
                    'listeners': [{'port': 22, 'protocol': 'tcp'}], 'security_monitor': {'enabled': True, 'status': 'active', 'rate_limited': True},
                    'security_events': events}
                headers = {'X-Agent-ID': 'probe-target'}
                status, receipt, _ = request(port, 'POST', '/api/v1/agent/report', report, headers)
                self.assertEqual(status, 200)
                self.assertEqual(set(receipt['ack_security_event_ids']), {event['event_id'] for event in events})
                self.assertEqual(request(port, 'POST', '/api/v1/agent/report', report, headers)[0], 200)
                alerts = request(port, 'GET', '/api/v1/alerts')[1]['items']
                hits = [alert for alert in alerts if alert['kind'] == 'unexpected_port_hit']
                scans = [alert for alert in alerts if alert['kind'] == 'possible_scan']
                self.assertEqual(len(hits), 5)
                self.assertEqual(sum(alert['details']['count'] for alert in hits), 15)
                self.assertEqual(len(scans), 1)
                self.assertEqual(scans[0]['details']['port_count'], 5)
                self.assertIn('does not establish lateral movement', scans[0]['details']['assessment'])

