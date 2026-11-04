"""SIEM delivery tests use mocked destinations/transports; no external sends."""
from datetime import timedelta
import json
from pathlib import Path
import socket
import ssl
import tempfile
import types
import unittest
from unittest.mock import patch

from controller import notifications as net, siem
from controller.firewall import WorkflowConflict
from controller.platform import PlatformManager
from controller.store import Store, now, stamp


class SIEMTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.store = Store(Path(temporary.name)/'db')
        with self.store.meta() as db: siem.initialize(db)
        self.manager = PlatformManager(Path(temporary.name)/'private')
        self.manager.app = types.SimpleNamespace(store=self.store, demo=False)
        self.manager.shared_secret_key = lambda purpose: b'siem-fixture-private-key-32-bytes!'[:32]
        self.resolver = lambda host, port, **kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', port))]
        self.secret = 'never-publish-this-token'

    def body(self, **extra):
        return {'expected_revision': siem.get(self.manager)['revision'], 'enabled': True,
                'url': 'https://siem.example.test/private?secret=private-url-token', 'auth_token': self.secret,
                'audit_enabled': True, 'alerts_enabled': True, **extra}

    def review(self, body=None, actor='super-admin'):
        return siem.preview(self.manager, body or self.body(), actor, resolver=self.resolver)

    def confirmation(self, plan):
        return {'preview_id': plan['id'], **{key: plan[key] for key in ('digest', 'confirmation_nonce', 'confirmation_phrase')}}

    def configure(self, body=None):
        plan = self.review(body)
        return siem.apply(self.manager, self.confirmation(plan), 'super-admin', resolver=self.resolver)

    def event(self, identifier='event-one', category='audit', previous=None, **extra):
        value = {'id': identifier, 'action': 'policies.saved', 'actor': 'admin', 'kind': 'port_scan', 'severity': 'warning', 'status': 'open', 'server_id': 'server-one', 'created_at': stamp(), **extra}
        with self.store.lock, self.store.meta() as db:
            result = siem.record(db, category, value, previous)
        return result, value

    def send(self, **kwargs):
        return siem.run_once(self.manager, transport=lambda *_: {'status_code': 204}, **kwargs)

    def rows(self):
        return siem.deliveries(self.store)['items']

    def test_disabled_default_performs_no_capture_or_network(self):
        self.assertEqual(siem.get(self.manager)['health'], 'disabled')
        self.assertFalse(self.event()[0])
        with self.store.read_meta() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM siem_cursor').fetchone()[0],0)
        with patch.object(siem, 'dispatch', side_effect=AssertionError('No sends')):
            self.assertEqual(siem.run_once(self.manager), {'processed': 0})

    def test_disabled_capture_is_only_an_indexed_settings_lookup(self):
        statements = []
        with self.store.meta() as db:
            db.set_trace_callback(statements.append)
            self.assertFalse(siem.record(db, 'audit', {'id': 'disabled', 'action': 'policy.saved'}))
            db.set_trace_callback(None)
        self.assertEqual(len(statements), 1)
        self.assertIn('FROM siem_settings WHERE id=', statements[0])
        self.assertNotIn('siem_cursor', statements[0])

    def test_exact_review_encrypts_secrets_and_binds_same_actor(self):
        plan = self.review()
        self.assertNotIn(self.secret, json.dumps(plan))
        with self.assertRaises(WorkflowConflict): siem.apply(self.manager, self.confirmation(plan), 'other-admin', resolver=self.resolver)
        siem.apply(self.manager, self.confirmation(plan), 'super-admin', resolver=self.resolver)
        for table in ('siem_settings', 'siem_reviews', 'audit'):
            text = json.dumps(self.store.all(table))
            self.assertNotIn(self.secret, text); self.assertNotIn('private-url-token', text)
        self.assertNotIn('sealed', json.dumps(siem.get(self.manager)))
        with self.assertRaises(WorkflowConflict): siem.apply(self.manager, self.confirmation(plan), 'super-admin', resolver=self.resolver)

    def test_stale_wrong_nonce_wrong_phrase_and_expired_reviews_fail_closed(self):
        for change in ({'confirmation_nonce': 'wrong'}, {'confirmation_phrase': 'yes'}, {'digest': 'wrong'}):
            plan = self.review()
            with self.assertRaises(WorkflowConflict): siem.apply(self.manager, {**self.confirmation(plan), **change}, 'super-admin', resolver=self.resolver)
        plan = self.review()
        with patch.object(siem, 'now', return_value=now()+timedelta(minutes=11)), self.assertRaises(WorkflowConflict):
            siem.apply(self.manager, self.confirmation(plan), 'super-admin', resolver=self.resolver)
        self.assertFalse(siem.get(self.manager)['enabled'])

    def test_ssrf_and_unencrypted_or_credential_urls_are_rejected(self):
        for address in ('127.0.0.1', '169.254.169.254', '100.100.100.200', '0.0.0.0', '::1', 'fe80::1', '224.0.0.1'):
            resolver = lambda host, port, **kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (address, port))]
            with self.subTest(address=address), self.assertRaises(ValueError):
                siem.preview(self.manager, self.body(allow_private_network=True), 'super-admin', resolver=resolver)
        for url in ('http://siem.example.test', 'https://user:pass@siem.example.test', 'https://siem.example.test/#fragment', 'https://siem.example.test:0', 'https://siem.example.test/a\nb'):
            with self.subTest(url=url), self.assertRaises(ValueError): self.review(self.body(url=url))

    def test_private_addresses_require_review_and_dns_rebinding_blocks_apply_and_send(self):
        private = lambda host, port, **kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.1.2.3', port))]
        with self.assertRaises(ValueError): siem.preview(self.manager, self.body(), 'super-admin', resolver=private)
        plan = siem.preview(self.manager, self.body(allow_private_network=True), 'super-admin', resolver=private)
        self.assertEqual(plan['summary']['destination']['addresses'], ['10.1.2.3'])
        with self.assertRaises(WorkflowConflict): siem.apply(self.manager, self.confirmation(plan), 'super-admin', resolver=self.resolver)
        self.configure(); self.event()
        with patch.object(net, '_addresses', return_value=['8.8.4.4']), patch.object(net, 'PinnedHTTPS', side_effect=AssertionError('No connection to changed IP')):
            siem.run_once(self.manager)
        self.assertEqual(self.rows()[0]['status'], 'held')

    def test_fixed_schema_excludes_details_credentials_and_duplicate_alert_updates(self):
        self.configure()
        added, alert = self.event(category='alerts', details={'token': self.secret}, message=self.secret)
        self.assertTrue(added)
        self.assertFalse(self.event(category='alerts', previous=alert, details={'other': 'ignored'}, created_at=alert['created_at'])[0])
        self.assertTrue(self.event(category='alerts', previous=alert, status='resolved', created_at=alert['created_at'])[0])
        captured = []
        siem.run_once(self.manager, transport=lambda _, batch: captured.extend(batch['events']) or {'status_code': 202})
        self.assertEqual([event['sequence'] for event in captured], [1, 2])
        self.assertTrue(all(event['schema'] == siem.SCHEMA and event['category'] == 'security_alert' for event in captured))
        self.assertNotIn(self.secret, json.dumps(captured)); self.assertNotIn('details', json.dumps(captured))

    def test_valid_structured_security_context_exports_canonical_native_ip_port_protocol(self):
        self.configure()
        self.event('ipv4-alert', category='alerts', details={'source_ip': '192.0.2.11', 'port': 2022, 'protocol': 'tcp', 'address_family': 'ipv4', 'credential': self.secret, 'message': self.secret})
        self.event('ipv6-alert', category='alerts', source_ip='2001:0db8:0:0::22', port=8443, protocol='udp', address_family='ipv6', details={'password': self.secret})
        captured = []
        siem.run_once(self.manager, transport=lambda _, batch: captured.extend(batch['events']) or {'status_code': 204})
        self.assertEqual([(row['source_ip'], row['address_family'], row['port'], row['protocol']) for row in captured], [('192.0.2.11', 'ipv4', 2022, 'tcp'), ('2001:db8::22', 'ipv6', 8443, 'udp')])
        self.assertNotIn(self.secret, json.dumps(captured)); self.assertTrue(all('details' not in row and 'message' not in row for row in captured))

    def test_malformed_scoped_mapped_or_mismatched_security_context_is_never_exported(self):
        bad_sources = ('not-an-ip', self.secret, '::ffff:192.0.2.8', 'fe80::1%eth0', '192.0.2.8/32', '192.0.2.8\n')
        for source in bad_sources:
            with self.subTest(source=source):
                row = siem._summary('alerts', {'id': 'bad', 'source_ip': source, 'details': {'source_ip': '192.0.2.22', 'password': self.secret}})
                self.assertNotIn('source_ip', row); self.assertNotIn('address_family', row); self.assertNotIn(self.secret, json.dumps(row))
        row = siem._summary('alerts', {'id': 'mismatch', 'details': {'source_ip': '192.0.2.8', 'address_family': 'ipv6'}})
        self.assertNotIn('source_ip', row); self.assertNotIn('address_family', row)
        for port, protocol in ((True, 'tcp'), ('22', 'tcp'), (0, 'tcp'), (65536, 'udp'), (22, 'TCP'), (22, self.secret), (22, ['tcp'])):
            with self.subTest(port=port, protocol=protocol):
                row = siem._summary('alerts', {'id': 'bad-port', 'details': {'port': port, 'protocol': protocol}})
                self.assertNotIn('port', row); self.assertNotIn('protocol', row)

    def test_filters_self_export_recursion_and_prior_events_are_not_broadcast(self):
        self.event('before-enable')
        self.configure(self.body(audit_enabled=False))
        self.assertFalse(self.event()[0]); self.assertTrue(self.event(category='alerts')[0])
        self.configure()
        self.assertFalse(self.event('internal', action='siem.delivery_outcome')[0])
        self.assertEqual(siem.get(self.manager)['queued_events'], 1)

    def test_500_events_batch_with_bounded_work_and_monotonic_durable_sequences(self):
        self.configure()
        for index in range(501): self.event('event-'+str(index))
        self.assertEqual(self.send()['processed'], 5)
        self.assertEqual(siem.get(self.manager)['queued_events'], 1)
        self.assertEqual(siem.get(self.manager)['last_acknowledged_sequence'], 500)
        self.send()
        state = siem.get(self.manager)
        self.assertEqual(state['queued_events'], 0); self.assertEqual(state['last_acknowledged_sequence'], 501)
        self.assertEqual(sorted(row['event_count'] for row in self.rows()), [1, 100, 100, 100, 100, 100])

    def test_queue_overflow_is_visible_and_does_not_block_primary_operation(self):
        self.configure()
        with patch.object(siem, 'MAX_QUEUED', 2):
            for index in range(4): self.event('bounded-'+str(index))
        state = siem.get(self.manager)
        self.assertEqual(state['queued_events'], 2); self.assertEqual(state['overflow_events'], 2)
        self.assertEqual(state['last_dropped_sequence'], 4); self.assertEqual(state['health'], 'degraded')
        self.send(); self.event('after-space')
        self.assertEqual(siem.get(self.manager)['last_sequence'], 5)

    def test_pending_retry_retains_stable_batch_and_event_ids(self):
        self.configure(); self.event(); at = now(); captured = []
        def rejected(_, batch):
            captured.append((batch['id'], batch['events'][0]['event_id']))
            raise net.DeliveryFailure('retry', 'provider_temporary', 503)
        siem.run_once(self.manager, transport=rejected, at=at)
        self.assertEqual(self.rows()[0]['status'], 'retry')
        self.assertEqual(siem.run_once(self.manager, transport=rejected, at=at)['processed'], 0)
        def accepted(_, batch):
            captured.append((batch['id'], batch['events'][0]['event_id'])); return {'status_code': 200, 'secret': self.secret}
        siem.run_once(self.manager, transport=accepted, at=at+timedelta(seconds=31))
        self.assertEqual(captured[0], captured[1]); self.assertEqual(self.rows()[0]['status'], 'delivered')
        self.assertNotIn(self.secret, json.dumps(self.rows())); self.assertEqual(siem.get(self.manager)['queued_events'], 0)

    def test_unknown_acknowledgement_is_held_until_explicit_retry(self):
        self.configure(); self.event()
        siem.run_once(self.manager, transport=lambda *_: (_ for _ in ()).throw(RuntimeError(self.secret)))
        row = self.rows()[0]; self.assertEqual(row['status'], 'uncertain'); self.assertNotIn(self.secret, json.dumps(row))
        self.assertEqual(self.send()['processed'], 0)
        body = {'delivery_id': row['id'], 'expected_revision': 1, 'expected_attempts': 1, 'confirm_possible_duplicate': True}
        with self.assertRaises(WorkflowConflict): siem.retry(self.manager, {**body, 'confirm_possible_duplicate': False}, 'super-admin')
        siem.retry(self.manager, body, 'super-admin'); self.send()
        self.assertEqual(self.rows()[0]['status'], 'delivered')

    def test_configuration_change_holds_old_batch_until_reviewed_rebind(self):
        self.configure(); self.event()
        self.configure(self.body(url='https://other.example.test/new'))
        self.assertEqual(self.send()['processed'], 0)
        row = self.rows()[0]; self.assertEqual(row['status'], 'held')
        siem.retry(self.manager, {'delivery_id': row['id'], 'expected_revision': 2, 'expected_attempts': 0, 'confirm_possible_duplicate': True}, 'super-admin')
        sent = []
        siem.run_once(self.manager, transport=lambda destination, _: sent.append(destination['host']) or {'status_code': 200})
        self.assertEqual(sent, ['other.example.test'])

    def test_worker_lease_prevents_reentrant_duplicate_and_handles_expiry(self):
        self.configure(); self.event(); received = []
        def outer(_, batch):
            received.append(batch['id'])
            self.assertEqual(self.send()['processed'], 0)
            return {'status_code': 204}
        siem.run_once(self.manager, transport=outer)
        self.assertEqual(len(received), 1)
        self.event('next')
        def abandoned(_, batch):
            with self.store.meta() as db:
                row = json.loads(db.execute('SELECT data FROM siem_deliveries WHERE id=?', (batch['id'],)).fetchone()[0])
                row['lease_token'] = 'lost-worker'; row['lease_until'] = stamp(now()-timedelta(seconds=1)); siem._put_delivery(db, row)
            return {'status_code': 204}
        siem.run_once(self.manager, transport=abandoned)
        self.assertEqual(siem.get(self.manager)['queued_events'], 1)
        self.send(); self.assertTrue(any(row['status'] == 'uncertain' for row in self.rows()))

    def test_retries_are_bounded_and_receiver_non_ack_is_never_success(self):
        self.configure(); self.event(); at = now()
        def fail(*_): raise net.DeliveryFailure('retry', 'connection')
        for index in range(siem.MAX_ATTEMPTS): siem.run_once(self.manager, transport=fail, at=at+timedelta(hours=index))
        self.assertEqual(self.rows()[0]['status'], 'failed'); self.assertEqual(self.rows()[0]['attempts'], siem.MAX_ATTEMPTS)
        self.assertEqual(self.send(at=at+timedelta(days=1))['processed'], 0)

    def test_blank_credentials_preserve_and_foreign_key_fails_closed(self):
        self.configure(); self.configure({'expected_revision': 1, 'enabled': True}); self.event()
        captured = []
        siem.run_once(self.manager, transport=lambda destination, _: captured.append(destination['auth_token']) or {'status_code': 204})
        self.assertEqual(captured, [self.secret])
        self.manager.shared_secret_key = lambda purpose: b'x'*32
        with self.assertRaises(ValueError): self.send()

    def test_acknowledged_history_prunes_only_terminal_rows(self):
        self.configure()
        with patch.object(siem, 'HISTORY_LIMIT', 2):
            for index in range(4): self.event('prune-'+str(index)); self.send()
        self.assertEqual(len(self.rows()), 2); self.assertEqual(siem.get(self.manager)['queued_events'], 0)

    def test_https_transport_uses_pinned_address_verified_hostname_and_structured_batch(self):
        self.configure(); self.event()
        with patch.object(net, '_addresses', return_value=['8.8.8.8']), patch.object(net, 'PinnedHTTPS') as constructor:
            connection = constructor.return_value
            connection.getresponse.return_value.status = 202
            connection.getresponse.return_value.read.return_value = b'accepted'
            self.assertEqual(siem.run_once(self.manager)['processed'], 1)
            host, port, address, context = constructor.call_args.args
            self.assertEqual((host, port, address), ('siem.example.test', 443, '8.8.8.8'))
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED); self.assertTrue(context.check_hostname)
            self.assertGreaterEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
            method, path, payload, headers = connection.request.call_args.args
            batch = json.loads(payload)
            self.assertEqual(method, 'POST'); self.assertEqual(batch['schema'], siem.SCHEMA)
            self.assertEqual(batch['events'][0]['sequence'], 1)
            self.assertEqual(headers['Idempotency-Key'], batch['batch_id'])
            self.assertEqual(headers['Authorization'], 'Bearer '+self.secret)
            self.assertEqual(path, '/private?secret=private-url-token')
            connection.close.assert_called_once()

    def test_https_never_follows_redirect_or_accepts_oversized_ack(self):
        self.configure()
        for index, (status, response) in enumerate(((302, b''), (200, b'x'*65537))):
            self.event('transport-'+str(index))
            with patch.object(net, '_addresses', return_value=['8.8.8.8']), patch.object(net, 'PinnedHTTPS') as constructor:
                connection = constructor.return_value
                connection.getresponse.return_value.status = status
                connection.getresponse.return_value.read.return_value = response
                siem.run_once(self.manager)
                self.assertEqual(constructor.call_count, 1); self.assertEqual(connection.request.call_count, 1)
        self.assertTrue(all(row['status'] == 'failed' for row in self.rows()))

    def test_tls_failure_retries_but_ambiguous_post_needs_receiver_deduplication(self):
        self.configure(); self.event('tls')
        with patch.object(net, '_addresses', return_value=['8.8.8.8']), patch.object(net, 'PinnedHTTPS') as constructor:
            constructor.return_value.connect.side_effect = ssl.SSLCertVerificationError('private certificate detail')
            siem.run_once(self.manager)
            self.assertEqual(self.rows()[0]['status'], 'retry')
            constructor.return_value.request.assert_not_called()
        self.event('ambiguous')
        with patch.object(net, '_addresses', return_value=['8.8.8.8']), patch.object(net, 'PinnedHTTPS') as constructor:
            constructor.return_value.request.side_effect = OSError(self.secret)
            siem.run_once(self.manager)
        self.assertTrue(any(row['status'] == 'uncertain' for row in self.rows()))
        self.assertNotIn(self.secret, json.dumps(self.rows()))

    def test_demo_never_sends_and_validation_is_strict(self):
        self.configure(); self.event(); self.manager.app.demo = True
        self.assertEqual(self.send(), {'processed': 0, 'demo_blocked': True})
        for extra in ({'enabled': 'true'}, {'audit_enabled': 1}, {'unknown': 'field'}, {'audit_enabled': False, 'alerts_enabled': False}, {'custom_ca_pem': 'not a certificate'}):
            with self.subTest(extra=extra), self.assertRaises(ValueError): self.review(self.body(**extra))
        for arguments in ({'limit': True}, {'offset': -1}, {'limit': 201}):
            with self.assertRaises(ValueError): siem.deliveries(self.store, **arguments)
