from datetime import timedelta
import tempfile
import unittest
from unittest.mock import patch

from controller import approvals, learning, learning_policies, session_views, traffic_views
from controller.store import Store, now, parse_time, stamp
from controller.tests.capture_fixture import typed_event


class DiscoverTrafficTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.store = Store(directory.name)
        self.start_at = parse_time(stamp(now() - timedelta(seconds=4)))
        self.capabilities = ['learning_discovery_v1', 'traffic_capture_v1', learning.TRAFFIC_SAMPLING_CAPABILITY]
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
        receipt = self.store.enqueue_flows('web-1', {'session_id': session['id'], 'batch_id': batch, 'events': events})
        self.store.process_flows()
        return receipt

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
        session = self.start(traffic_collection_mode='hits')
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

    def test_discovery_preview_and_start_reject_automatic_access_options_for_traffic(self):
        base = {'server_ids': ['web-1'], 'purpose': 'traffic'}
        for options in ({'policy_action': 'auto_allow'}, {'policy_action': 'observe', 'auto_allow_confirmed': True}):
            with self.subTest(options=options):
                with self.assertRaisesRegex(ValueError, 'observe-only'):
                    learning.preview(self.store, {**base, **options})
                with self.assertRaisesRegex(ValueError, 'observe-only'):
                    self.start(**options)
        with self.assertRaisesRegex(ValueError, 'only available in Discover traffic'):
            learning.preview(self.store, {**base, 'purpose': 'policy', 'traffic_collection_mode': 'hits'})
        self.assertEqual(learning.preview(self.store, {**base, 'purpose': 'policy', 'policy_action': 'auto_allow'})['purpose'], 'policy')
        self.assertEqual(self.store.all('sessions'), [])

    def test_traffic_receipts_have_trusted_purpose_and_only_appear_on_their_exact_session(self):
        session = self.start()
        self.report(learning_coverage={'session_id': session['id'], 'purpose': 'policy'})
        receipt = self.store.overview()['servers'][0]['learning_coverage']
        self.assertEqual(receipt['purpose'], 'traffic')
        result = learning_policies.recommendations(self.store, session['id'])
        self.assertEqual(result['coverage']['servers'][0]['learning_coverage'], receipt)
        self.store.stop_session(session['id'], 'admin')
        policy = self.store.create_session({'server_ids': ['web-1'], 'ports': [{'port': 443}]}, 'admin')
        with self.assertRaisesRegex(ValueError, 'does not belong'):
            self.store.report('different-endpoint', {'hostname': 'different-endpoint', 'ips': ['192.0.2.6'],
                              'learning_coverage': {'session_id': session['id'], 'purpose': 'traffic'}})
        self.report(learning_coverage={'session_id': policy['id'], 'purpose': 'traffic'})
        self.assertEqual(self.store.overview()['servers'][0]['learning_coverage']['purpose'], 'policy')
        result = learning_policies.recommendations(self.store, session['id'])
        self.assertIsNone(result['coverage']['servers'][0]['learning_coverage'])

    def test_restored_traffic_metadata_cannot_show_or_use_policy_authority(self):
        session = self.start()
        self.report(learning_discovery_session_ids=[session['id']])
        self.upload(session, 'observation', [self.event('observed', 1)])
        self.store.lab_approvals = True
        with self.store.meta() as db:
            saved = self.store._get(db, 'sessions', session['id'])
            saved.update(policy_action='auto_allow', auto_allow_confirmed=True, initial_approval_mode='lab_only',
                         initial_approval_state='awaiting_review', initial_approval_plan={
                             'id': 'old-initial-review', 'status': 'draft', 'expires_at': stamp(now() + timedelta(minutes=1))})
            self.store._put(db, 'sessions', saved)
            self.store._put(db, 'learning_policy_previews', {'id': 'old-review', 'session_id': session['id'],
                            'digest': 'a' * 64, 'status': 'reviewed', 'expires_at': stamp(now() + timedelta(minutes=1))})
            learning_policies._put_policy(self.store, db, {'id': 'historical-allow', 'session_id': session['id'],
                                          'server_id': 'web-1', 'name': 'Historical entry', 'status': 'pending'})
            self.assertFalse(approvals.learning_authorized(self.store, db, saved))
        public = session_views.listing(self.store, purpose='traffic')['items'][0]
        self.assertNotIn('initial_approval_plan', public)
        self.assertEqual(public['policy_action'], 'observe')
        assigned = self.store.assignment('web-1')[0]['learning_sessions'][0]
        self.assertEqual(assigned['policy_action'], 'observe')
        result = learning_policies.recommendations(self.store, session['id'])
        self.assertEqual((result['generated_policies'], result['pending_approvals'], result['total_rows']), ([], [], 1))
        self.assertEqual((result['generated_policy_total'], result['pending_approval_total']), (0, 0))
        self.assertIn('sample_minutes', learning_policies.export_csv(self.store, session['id']))
        self.assertEqual(learning_policies.get(self.store, 'historical-allow')['name'], 'Historical entry')
        with self.assertRaisesRegex(PermissionError, 'cannot create firewall policy'):
            approvals.learning_preview(self.store, session['id'], {}, 'admin')
        with self.assertRaisesRegex(PermissionError, 'cannot create firewall policy'):
            approvals.learning_confirm(self.store, session['id'], {'preview_id': 'old-initial-review'}, 'admin')
        with self.assertRaisesRegex(PermissionError, 'cannot create firewall policy'):
            learning_policies.apply(self.store, session['id'], {'confirm': True, 'preview_id': 'old-review', 'digest': 'a' * 64}, 'admin')

    def test_traffic_burst_counts_connections_and_denied_packets_separately(self):
        session = self.start(traffic_collection_mode='hits')
        self.report(learning_discovery_session_ids=[session["id"]])
        connections = [self.event(f"connection-{i}", 1) for i in range(99)]
        self.upload(session, "mixed", [*connections, self.event("denied-1", 1, "denied_packet")])
        self.assertFalse(any(alert["kind"] == "traffic_burst" for alert in self.store.all("alerts")))
        self.upload(session, "trigger", [self.event("connection-99", 1)])
        bursts = [alert for alert in self.store.all("alerts") if alert["kind"] == "traffic_burst"]
        self.assertEqual(len(bursts), 1)
        self.assertEqual(bursts[0]["details"]["count"], 100)
        self.assertEqual(bursts[0]["details"]["count_unit"], "connections")

    def test_default_sampling_caps_each_relationship_per_utc_minute_across_kinds_and_retries(self):
        self.start_at = now().replace(second=0, microsecond=0) - timedelta(minutes=1)
        session = self.start(duration_seconds=180)
        self.assertEqual(session['traffic_collection_mode'], 'sampled')
        self.report(learning_discovery_session_ids=[session['id']])
        assignment = self.store.assignment('web-1')[0]['learning_sessions'][0]
        self.assertEqual(assignment['traffic_collection_mode'], 'sampled')
        self.assertEqual(session_views.listing(self.store, purpose='traffic')['items'][0]['traffic_collection_mode'], 'sampled')

        first = self.event('one', 1)
        same_minute = [self.event(f'connection-{i}', 1) for i in range(100)]
        receipt = self.upload(session, 'first', [first, *same_minute, self.event('denied', 2, 'denied_packet')])
        self.assertEqual(receipt['duplicate_events'], 101)
        self.assertTrue(self.upload(session, 'first', [first, *same_minute, self.event('denied', 2, 'denied_packet')])['duplicate'])
        self.assertEqual(self.upload(session, 'agent-restarted', [self.event('after-restart', 5, 'denied_packet')])['duplicate_events'], 1)
        self.upload(session, 'new-minute', [self.event('next-minute', 60), self.event('another-source', 10, source='192.0.2.3')])

        result = learning_policies.recommendations(self.store, session['id'])
        self.assertEqual(result['traffic_collection_mode'], 'sampled')
        rows = {row['source_ip']: row for row in result['rows']}
        self.assertEqual({source: (row['count_unit'], row['count']) for source, row in rows.items()},
                         {'192.0.2.2': ('sample_minutes', 2), '192.0.2.3': ('sample_minutes', 1)})
        self.assertEqual(rows['192.0.2.2']['capture_kind'], 'accepted_connection')
        self.assertNotIn('peak_observed_per_second', rows['192.0.2.2'])
        self.assertFalse(any(alert['kind'] == 'traffic_burst' for alert in self.store.all('alerts')))
        self.assertIn('sample_minutes', learning_policies.export_csv(self.store, session['id']))
        expected = {'connections': 0, 'packets': 0, 'log_records': 0, 'sample_minutes': 3}
        self.assertEqual(traffic_views.listing(self.store)['counts_by_unit'], expected)
        self.assertEqual(self.store.overview()['stats']['capture_counts'], expected)

    def test_old_agents_can_count_hits_but_never_receive_a_sampled_lease(self):
        self.capabilities.remove(learning.TRAFFIC_SAMPLING_CAPABILITY)
        self.report()
        with self.assertRaisesRegex(ValueError, 'minute sampling'):
            self.start()
        with self.assertRaisesRegex(ValueError, 'sampled or hits'):
            self.start(traffic_collection_mode='unknown')
        with self.assertRaisesRegex(ValueError, 'only available in Discover traffic'):
            self.start(purpose='policy', traffic_collection_mode='sampled')
        session = self.start(traffic_collection_mode='hits')
        self.assertEqual(session['traffic_collection_mode'], 'hits')
        self.assertNotIn('traffic_collection_mode', self.store.assignment('web-1')[0]['learning_sessions'][0])
        with self.store.meta() as db:
            session.pop('traffic_collection_mode')
            self.store._put(db, 'sessions', session)
        self.report(learning_discovery_session_ids=[session['id']])
        self.upload(session, 'historical-session', [self.event('first', 1), self.event('second', 1)])
        result = learning_policies.recommendations(self.store, session['id'])
        self.assertNotIn('traffic_collection_mode', result)
        self.assertEqual(result['rows'][0]['peak_observed_per_second'], 2)

    def test_agent_without_sampling_capability_cannot_continue_sampled_collection(self):
        session = self.start()
        self.report(learning_discovery_session_ids=[session['id']])
        self.capabilities.remove(learning.TRAFFIC_SAMPLING_CAPABILITY)
        self.report()
        self.assertEqual(self.store.assignment('web-1')[0]['learning_sessions'], [])
        with self.assertRaisesRegex(ValueError, 'no longer advertises'):
            self.upload(session, 'stale-agent', [self.event('first', 1)])

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
