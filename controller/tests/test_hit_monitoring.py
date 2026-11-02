"""Real isolated SQLite stores: optional capture never grants access."""
import copy
from datetime import timedelta
import hashlib
import json
import tempfile
import unittest
from unittest.mock import patch

from controller import hit_monitoring as hm, recovery
from controller.firewall import WorkflowConflict
from controller.store import Store, now, stamp
from controller.tests.capture_fixture import typed_event


class HitMonitorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(self.temp.name)
        self.at = now().replace(microsecond=0)
        self.report('one', application='Billing')
        self.report('two', application='Payments')

    def report(self, identifier, application='Billing', **extra):
        body = dict(hostname=identifier, ips=['10.0.0.' + ('1' if identifier == 'one' else '2')], listeners=[{'port': 22, 'protocol': 'tcp', 'service': 'SSH', 'process': 'sshd'}, {'port': 443, 'protocol': 'tcp', 'service': 'HTTPS', 'process': '=untrusted'}], capabilities=['signed_assignments_v1', hm.CAPABILITY,'traffic_capture_v1'], agent_version='0.9.0', firewalld_state='running')
        body.update(extra)
        self.store.report(identifier, body)
        with self.store.meta() as db:
            server = self.store._get(db, 'servers', identifier)
            server['tags'] = {'application': application}
            server['_metadata_overrides'] = {'tags': {'application': application}}
            self.store._put(db, 'servers', server)

    def make(self, ports=None, selection=None, retention=24):
        plan = hm.preview(self.store, {'name': 'TLS hits', 'selection': selection or {'server_ids': ['one']}, 'ports': ports or [{'port': 443, 'protocol': 'tcp'}], 'retention_hours': retention}, 'maker')
        return hm.apply(self.store, self.confirm(plan), 'maker')

    @staticmethod
    def confirm(plan):
        return {'preview_id': plan['id'], **{key: plan[key] for key in ('digest', 'confirmation_nonce', 'confirmation_phrase')}}

    def lease(self, monitor, server='one', at=None):
        with self.store.read_meta() as db:
            return hm.assignments(self.store, db, self.store._get(db, 'servers', server), at or now())[0]

    def batch(self, monitor, server='one', source='2001:db8::12', port=443, identity='a', at=None):
        lease = self.lease(monitor, server)
        point = at or now()
        event = typed_event(source,port,identity=identity,at=point)
        return {'batch_id': identity, 'monitor_id': monitor['id'], 'lease_starts_at': lease['starts_at'], 'lease_expires_at': lease['expires_at'], 'events': [event]}

    def stop(self, monitor):
        plan = hm.stop_preview(self.store, monitor['id'], {'expected_revision': monitor['revision']}, 'maker')
        return hm.apply(self.store, self.confirm(plan), 'maker')

    def test_disabled_default_legacy_unchanged_and_signed_lease_replay_floor(self):
        self.assertEqual(hm.listing(self.store)['items'], [])
        self.assertEqual(self.store.assignment('one')[0]['hit_monitors'], [])
        self.report('two', capabilities=[])
        self.assertNotIn('hit_monitors', self.store.assignment('two')[0])
        before = self.store.assignment('one')[0]
        monitor = self.make()
        after = self.store.assignment('one')[0]
        self.assertGreater(after['assignment_generation'], before['assignment_generation'])
        lease = after['hit_monitors'][0]
        self.assertEqual(lease['server_id'], 'one')
        self.assertEqual((hm.parse_time(lease['expires_at']) - hm.parse_time(lease['starts_at'])).total_seconds(), 120)
        self.assertEqual(lease['ports'], [{'port': 443, 'protocol': 'tcp'}])
        self.stop(monitor)
        stopped = self.store.assignment('one')[0]
        self.assertEqual(stopped['hit_monitors'], [])
        self.assertGreater(stopped['assignment_generation'], after['assignment_generation'])

    def test_ipv6_queue_identity_dedup_exact_scope_and_no_learning(self):
        monitor = self.make()
        body = self.batch(monitor)
        self.assertEqual(hm.enqueue(self.store, 'one', body)['accepted'], 1)
        self.assertTrue(hm.enqueue(self.store, 'one', body)['duplicate'])
        retry = copy.deepcopy(body); retry['batch_id'] = 'new-batch'
        self.assertEqual(hm.enqueue(self.store, 'one', retry)['accepted'], 0)
        changed = copy.deepcopy(body); changed['batch_id'] = 'changed'; changed['events'][0]['source_ip'] = '10.2.3.4'
        with self.assertRaises(ValueError): hm.enqueue(self.store, 'one', changed)
        with self.assertRaises(PermissionError): hm.enqueue(self.store, 'two', body)
        wrong = self.batch(monitor, port=22, identity='ssh-not-approved')
        with self.assertRaises(PermissionError): hm.enqueue(self.store, 'one', wrong)
        self.assertEqual(hm.hits(self.store, monitor['id'])['total'], 0)
        self.store.process_flows()
        rows = hm.hits(self.store, monitor['id'])['items']
        self.assertEqual(len(rows), 1); self.assertEqual(rows[0]['source_ip'], '2001:db8::12'); self.assertEqual(rows[0]['count'], 1)
        with self.store.read_meta() as db:
            for table in ('sessions', 'learning_evidence', 'learning_allow_policies'):
                self.assertEqual(db.execute('SELECT COUNT(*) FROM ' + table).fetchone()[0], 0)
        with hm.csv_spool(self.store, monitor['id']) as (source, size):
            data = source.read().decode('utf-8-sig')
            self.assertIn('2001:db8::12', data); self.assertIn("'=untrusted", data); self.assertGreater(size, 0)

    def test_observing_ssh_allowed_but_stop_ack_not_central_desired(self):
        monitor = self.make(ports=[{'port': 22, 'protocol': 'tcp'}])
        stopped = self.stop(monitor)
        with self.store.meta() as db:
            server = self.store._get(db, 'servers', 'one')
            self.assertTrue(hm.retirement_blockers(self.store, db, server))
            hm.report_status(self.store, db, server, {'hit_monitoring': [{'id': monitor['id'], 'status': 'off', 'checked_at': stamp(now())}]})
            self.assertEqual(hm.retirement_blockers(self.store, db, server), [])
        self.assertFalse(stopped['enabled'])
        self.assertEqual(hm.target_page(self.store, monitor['id'])['items'][0]['last_outcome']['status'], 'off')

    def test_frozen_group_and_metadata_change_reject_review(self):
        with self.store.meta() as db:
            self.store._put(db, 'groups', {'id': 'billing', 'name': 'Billing', 'type': 'dynamic', 'selector': {'application': 'Billing'}})
        plan = hm.preview(self.store, {'name': 'Scope', 'selection': {'group_ids': ['billing']}, 'ports': [{'port': 443, 'protocol': 'tcp'}], 'retention_hours': 1}, 'maker')
        self.assertEqual(plan['server_ids'], ['one'])
        with self.store.meta() as db:
            server = self.store._get(db, 'servers', 'two'); server['tags']['application'] = 'Billing'; self.store._put(db, 'servers', server)
        with self.assertRaises(WorkflowConflict): hm.apply(self.store, self.confirm(plan), 'maker')
        with self.assertRaises(PermissionError): hm.apply(self.store, self.confirm(plan), 'checker')

    def test_lease_upload_grace_and_post_stop_new_window_rejected(self):
        monitor = self.make()
        body = self.batch(monitor)
        stopped = self.stop(monitor)
        self.assertEqual(hm.enqueue(self.store, 'one', body)['accepted'], 1)  # already-issued, bounded residual
        future = hm.parse_time(body['lease_expires_at']) + timedelta(seconds=301)
        with patch.object(hm, 'now', return_value=future):
            with self.assertRaises(hm.MonitoringExpired): hm.enqueue(self.store, 'one', body)
        bad = copy.deepcopy(body)
        bad['lease_starts_at'] = body['lease_expires_at']; bad['lease_expires_at'] = stamp(hm.parse_time(body['lease_expires_at']) + timedelta(seconds=120))
        with patch.object(hm, 'now', return_value=hm.parse_time(bad['lease_starts_at'])):
            with self.assertRaises(hm.MonitoringExpired): hm.enqueue(self.store, 'one', bad)

    def test_storage_budget_backpressure_atomic_and_retention_prunes_counter(self):
        monitor = self.make(retention=1)
        body = self.batch(monitor)
        with patch.object(hm, 'MAX_STORED_EVENTS', 0):
            with self.assertRaises(RuntimeError): hm.enqueue(self.store, 'one', body)
        self.assertEqual(hm.listing(self.store)['storage_budget']['event_count'], 0)
        hm.enqueue(self.store, 'one', body); hm.process(self.store)
        with patch.object(hm, 'now', return_value=now() + timedelta(hours=2)):
            hm.prune(self.store)
        self.assertEqual(hm.listing(self.store)['storage_budget']['event_count'], 0)
        self.assertEqual(hm.listing(self.store)['storage_budget']['batch_count'], 0)

    def test_capacity_and_unsupported_extra_scope_keys_rejected(self):
        for index in range(8): self.make()
        with self.assertRaises(ValueError): self.make()
        with self.assertRaises(ValueError): hm._ports([{'port': 443, 'protocol': 'tcp', 'sources': ['0.0.0.0/0']}])
        self.report('two', capabilities=['signed_assignments_v1'])
        with self.assertRaises(ValueError): self.make(selection={'server_ids': ['two']})

    def test_large_historical_group_ids_are_projected_before_python_decoding(self):
        monitor = self.make()
        groups = ['unrequested-group-' + str(index) + '-' + 'x' * 80 for index in range(10000)]
        with self.store.meta() as db:
            canonical = self.store._get(db, 'hit_monitors', monitor['id'])
            canonical['selection_summary']['group_ids'] = groups
            self.store._put(db, 'hit_monitors', canonical)
        original = json.loads
        def bounded_load(value, *args, **kwargs):
            if isinstance(value, str) and 'unrequested-group-' in value:
                raise AssertionError('Historical membership reached Python JSON decoding')
            return original(value, *args, **kwargs)
        with patch.object(hm.json, 'loads', side_effect=bounded_load):
            self.assertNotIn('group_ids', hm.listing(self.store)['items'][0]['selection_summary'])
            self.assertNotIn('group_ids', hm.hits(self.store, monitor['id'])['monitor']['selection_summary'])
            self.assertEqual(self.lease(monitor)['ports'], monitor['ports'])
        self.assertEqual(self.store.get('hit_monitors', monitor['id'])['selection_summary']['group_ids'], groups)
        self.assertEqual(hm.target_page(self.store, monitor['id'])['total'], 1)

    def test_current_stopped_monitor_cannot_be_reactivated_by_archive(self):
        monitor = self.make()
        with self.store.read_meta() as db:
            archive_monitors = recovery._rows(db, 'hit_monitors')
        self.stop(monitor)
        with self.store.read_meta() as db:
            safety = {table: recovery._rows(db, table) for table in recovery.SAFETY_TABLES}
        with self.store.meta() as db:
            recovery._replace(db, 'hit_monitors', archive_monitors)
            recovery._overlay_safety(db, safety, 'a' * 32)
            value = self.store._get(db, 'hit_monitors', monitor['id'])
            self.assertFalse(value['enabled']); self.assertTrue(value['requires_review'])
            self.assertEqual(db.execute('SELECT COUNT(*) FROM hit_monitor_targets WHERE enabled=1').fetchone()[0], 0)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM hit_monitor_reviews').fetchone()[0], 0)


class HitMonitorEmptyBaseline(unittest.TestCase):
    def test_default_off_does_not_make_new_join_source_or_migration_target_populated(self):
        from types import SimpleNamespace
        from controller.platform import PlatformManager
        from controller.platform_runtime import TRAFFIC_TABLES
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            with store.read_traffic() as db:
                for table in TRAFFIC_TABLES:
                    self.assertEqual(db.execute('SELECT COUNT(*) FROM ' + table).fetchone()[0], 0, table)
            manager = PlatformManager(directory)
            manager.app = SimpleNamespace(store=store)
            manager._join_source_preflight()
            # Normalize the exact unreleased empty singleton without weakening
            # refusal of actual rows or a nonzero/corrupt quota ledger.
            with store.traffic() as db:
                store._put(db, 'hit_limits', {'id':'usage','events':0,'batches':0})
            store = Store(directory); manager.app.store = store
            manager._join_source_preflight()
            hm.prune(store)
            manager._join_source_preflight()
            with store.traffic() as db:
                store._put(db, 'hit_limits', {'id':'usage','events':1,'batches':0})
            store = Store(directory); manager.app.store = store
            with self.assertRaises(ValueError): manager._join_source_preflight()
