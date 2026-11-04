from datetime import timedelta
import tempfile
import unittest
from unittest.mock import patch

from controller import learning, learning_policies, session_views
from controller.store import Store, now, parse_time, stamp
from controller.tests.capture_fixture import typed_event


class DiscoverTrafficTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.store = Store(directory.name)
        self.start_at = parse_time(stamp(now() - timedelta(seconds=4)))
        self.capabilities = ['learning_discovery_v1', 'traffic_capture_v1']
        self.report()

    def report(self, **extra):
        self.store.report('web-1', {
            'hostname': 'web-1', 'ips': ['192.0.2.1'], 'firewalld_state': 'running',
            'listeners': [{'address': '0.0.0.0', 'port': 443, 'protocol': 'tcp', 'service': 'HTTPS'}],
            'discovery_performed': True, 'discovered_at': stamp(), 'capabilities': self.capabilities,
            **extra,
        })

    def start(self, **overrides):
        with patch('controller.learning.now', return_value=self.start_at):
            return self.store.create_session({
                'purpose': 'traffic', 'selection_mode': 'discovered', 'policy_action': 'observe',
                'server_ids': ['web-1'], 'duration_seconds': 60, **overrides,
            }, 'admin')

    def upload(self, session, batch, events):
        self.store.enqueue_flows('web-1', {'session_id': session['id'], 'batch_id': batch, 'events': events})
        self.store.process_flows()

    def event(self, identity, second, kind='accepted_connection', source='192.0.2.2'):
        return typed_event(source, 443, identity=identity, at=self.start_at + timedelta(seconds=second), kind=kind)

    def test_long_duration_requires_capability_and_only_traffic_can_exceed_week(self):
        self.assertFalse(learning.preview(self.store, {'server_ids': ['web-1'], 'purpose': 'traffic'})['servers'][0]['long_capture_supported'])
        with self.assertRaisesRegex(ValueError, 'upgraded agents'):
            self.start(duration_seconds=2592000)
        with self.assertRaisesRegex(ValueError, 'observe-only'):
            self.start(policy_action='auto_allow', auto_allow_confirmed=True)
        with self.assertRaisesRegex(ValueError, '604800'):
            self.start(purpose='policy', duration_seconds=604801)
        with self.assertRaisesRegex(ValueError, '2592000'):
            self.start(duration_seconds=2592001)
        self.capabilities.append(learning.TRAFFIC_DISCOVERY_CAPABILITY)
        self.report()
        session = self.start(duration_seconds=2592000)
        assignment, _ = self.store.assignment('web-1')
        self.assertEqual(assignment['learning_sessions'][0]['purpose'], 'traffic')
        self.assertNotIn('evidence_expires_at', assignment['learning_sessions'][0])
        self.capabilities.remove(learning.TRAFFIC_DISCOVERY_CAPABILITY)
        self.report()
        self.assertEqual(self.store.assignment('web-1')[0]['learning_sessions'], [])
        self.assertEqual(session_views.listing(self.store, purpose='traffic')['items'][0]['id'], session['id'])
        self.assertEqual(session_views.listing(self.store, purpose='policy')['total'], 0)

    def test_traffic_peaks_dedupe_across_batches_and_never_produce_access(self):
        session = self.start()
        self.report(learning_discovery_session_ids=[session['id']])
        signed_generation = self.store.assignment('web-1')[0]['assignment_generation']
        first = self.event('first', 1)
        self.upload(session, 'first', [first, self.event('denied', 1, 'denied_packet')])
        self.upload(session, 'second', [first, self.event('second', 1), self.event('later', 2)])
        with self.store.traffic() as db:
            db.execute('UPDATE batches SET evidence_processed=0')
        self.store.process_flows()
        result = learning_policies.recommendations(self.store, session['id'])
        observed = {row['count_unit']: row for row in result['rows']}
        self.assertEqual(result['purpose'], 'traffic')
        self.assertEqual(observed['connections']['count'], 3)
        self.assertEqual(observed['connections']['peak_observed_per_second'], 2)
        self.assertEqual(observed['connections']['peak_observed_at'], first['first_seen'])
        self.assertEqual(observed['connections']['rate_window_seconds'], 1)
        self.assertTrue(observed['connections']['rate_is_lower_bound'])
        self.assertFalse(observed['connections']['eligible_for_auto'])
        self.assertEqual(observed['packets']['peak_observed_per_second'], 1)
        self.assertEqual(result['generated_policies'], [])
        self.assertIn('peak_observed_per_second,rate_window_seconds,peak_observed_at,rate_is_lower_bound', learning_policies.export_csv(self.store, session['id']))
        self.assertEqual(self.store.assignment('web-1')[0]['assignment_generation'], signed_generation)
        with self.assertRaisesRegex(PermissionError, 'cannot create firewall policy'):
            learning_policies.preview(self.store, session['id'], {'row_ids': [observed['connections']['id']]}, 'admin')

    def test_traffic_burst_counts_connections_and_denied_packets_separately(self):
        session = self.start()
        self.report(learning_discovery_session_ids=[session["id"]])
        connections = [self.event(f"connection-{i}", 1) for i in range(99)]
        self.upload(session, "mixed", [*connections, self.event("denied-1", 1, "denied_packet")])
        self.assertFalse(any(alert["kind"] == "traffic_burst" for alert in self.store.all("alerts")))
        self.upload(session, "trigger", [self.event("connection-99", 1)])
        bursts = [alert for alert in self.store.all("alerts") if alert["kind"] == "traffic_burst"]
        self.assertEqual(len(bursts), 1)
        self.assertEqual(bursts[0]["details"]["count"], 100)
        self.assertEqual(bursts[0]["details"]["count_unit"], "connections")

    def test_scoped_evidence_expires_after_stop_and_legacy_retention_is_unchanged(self):
        session = self.start(duration_seconds=3600)
        self.report(learning_discovery_session_ids=[session['id']])
        self.upload(session, 'traffic', [self.event('traffic', 1)])
        stopped = self.store.stop_session(session['id'], 'admin')
        stopped_at = parse_time(stopped['stopped_at'])
        self.assertEqual(session_views.listing(self.store, purpose='traffic')['items'][0]['stopped_at'], stopped['stopped_at'])
        self.assertEqual(parse_time(stopped['evidence_expires_at']), stopped_at + timedelta(days=30))
        with patch('controller.learning.now', return_value=stopped_at):
            legacy = self.store.create_session({'selection_mode': 'manual', 'server_ids': ['web-1'], 'ports': [{'port': 443}]}, 'admin')
        self.upload(legacy, 'legacy', [typed_event('192.0.2.3', 443, identity='legacy', at=stopped_at)])
        with patch('controller.store.now', return_value=stopped_at + timedelta(days=2)):
            self.store.prune()
            self.assertEqual(self.store.flows(), [])
            self.assertEqual(learning_policies.recommendations(self.store, session['id'])['rows'][0]['count'], 1)
        with patch('controller.store.now', return_value=stopped_at + timedelta(days=30)):
            self.assertTrue(learning_policies.recommendations(self.store, session['id'])['evidence_expired'])
            self.assertNotIn('192.0.2.2', learning_policies.export_csv(self.store, session['id']))
            self.store.prune()
            with self.store.read_meta() as db:
                self.assertEqual(db.execute('SELECT session_id FROM learning_evidence').fetchall(), [(legacy['id'],)])
                self.assertEqual(db.execute('SELECT COUNT(*) FROM learning_evidence_receipts').fetchone()[0], 1)
            self.assertEqual(learning_policies.recommendations(self.store, legacy['id'])['rows'][0]['count'], 1)
