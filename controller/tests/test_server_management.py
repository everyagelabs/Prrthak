import json
import tempfile
import unittest
from datetime import timedelta
from unittest.mock import patch

from controller import server_management as lifecycle
from controller.firewall import WorkflowConflict
from controller.store import Store, digest, now, stamp


class ServerLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(self.temp.name)
        self.store.lab_approvals = True  # Explicit isolated single-actor lab fixture.
        with self.store.meta() as db:
            lifecycle.initialize(db)

    def host(self, identifier='node1', address='10.241.1.1'):
        self.store.report(identifier, {'hostname': identifier, 'ips': [address], 'listeners': [],
                                      'firewalld_state': 'running'})
        return self.store.server(identifier)

    def retire(self, identifier, plan=None):
        plan = plan or lifecycle.delete_preview(self.store, identifier, 'named-admin')
        return lifecycle.delete_confirm(self.store, identifier,
                    {'plan_id': plan['id'], 'confirmation_nonce': plan.get('confirmation_nonce')}, 'named-admin')

    def mutate(self, identifier, **fields):
        with self.store.meta() as db:
            server = self.store._get(db, 'servers', identifier)
            server.update(fields)
            self.store._put(db, 'servers', server)

    def test_manual_reservation_is_unverified_and_never_a_policy_source(self):
        self.host('consumer')
        policy = self.store.save_policy({'name': 'Empty source', 'selector': {}, 'mode': 'monitor',
                 'services': [{'port': 8443, 'sources': [], 'source_selector': {'application': 'billing'}}]}, 'named-admin')
        before = self.store.assignment('consumer')[0]
        reservation = lifecycle.create(self.store, {'hostname': 'pending-node', 'ips': ['2001:0db8::1', '10.241.1.2']}, 'named-admin')
        self.assertEqual(reservation['ips'], [])
        self.assertEqual(reservation['planned_ips'], ['10.241.1.2', '2001:db8::1'])
        self.assertEqual(reservation['address_status'], 'planned_unverified')
        self.assertEqual(reservation['status'], 'waiting_enrollment')
        self.assertIsNone(reservation['last_seen'])
        self.assertEqual(lifecycle.reservation_listing(self.store)[0]['id'], reservation['id'])
        self.assertEqual(len(self.store.servers()), 1)
        self.assertEqual(self.store.assignment('consumer')[0]['digest'], before['digest'])
        self.assertEqual(self.store.assignment('consumer')[0]['services'][0]['sources'], [])
        with self.assertRaises(ValueError):
            lifecycle.create(self.store, {'hostname': 'pending-node', 'ips': []}, 'named-admin')
        for value in ({'hostname': 'bad/name'}, {'hostname': 'node', 'ips': ['10.1.0.0/16']},
                      {'hostname': 'node', 'ips': ['fe80::1%eth0']}, {'hostname': 'node', 'tags': {'application': 'billing'}}):
            with self.assertRaises(ValueError):
                lifecycle.create(self.store, value, 'named-admin')

    def test_unknown_recovery_baseline_blocks_retirement_without_blocking_monitor_only_hosts(self):
        self.host()
        self.mutate('node1', recovery_reconciliation_required=True)
        self.assertTrue(lifecycle.delete_preview(self.store, 'node1', 'named-admin')['can_delete'])
        self.mutate('node1', recovery_unverified_outcome={'status': 'unverified', 'version': 100, 'evidence_only': True})
        blocked = lifecycle.delete_preview(self.store, 'node1', 'named-admin')
        self.assertFalse(blocked['can_delete'])
        self.assertTrue(any('unverified endpoint firewall baseline' in reason for reason in blocked['blockers']))
        self.assertNotIn('confirmation_nonce', blocked)
        self.mutate('node1', recovery_reconciliation_required=False)
        self.assertTrue(lifecycle.delete_preview(self.store, 'node1', 'named-admin')['can_delete'])

    def test_bound_token_requires_exact_pending_hostname_and_consumes_after_enrollment(self):
        reservation = lifecycle.create(self.store, {'hostname': 'pending-node'}, 'named-admin')
        with self.store.meta() as db:
            record = {'server_id': reservation['id']}
            self.assertEqual(lifecycle.validate_binding(self.store, db, record)['id'], reservation['id'])
            with self.assertRaises(PermissionError):
                lifecycle.validate_binding(self.store, db, record, 'other-node')
            with self.assertRaises(PermissionError):
                lifecycle.assert_report_allowed(self.store, db, reservation['id'])
            with self.assertRaises(ValueError):
                lifecycle.consume_reservation(self.store, db, reservation['id'])
            self.store._put(db, 'servers', {'id': reservation['id'], 'hostname': 'pending-node', 'ips': [], 'last_seen': stamp()})
            lifecycle.consume_reservation(self.store, db, reservation['id'])
            with self.assertRaises(PermissionError):
                lifecycle.validate_binding(self.store, db, record, 'pending-node')
        self.assertEqual(lifecycle.reservation_listing(self.store), [])

    def test_retire_unmanaged_preserves_history_and_removes_static_and_source_membership(self):
        self.host()
        self.host('consumer', '10.241.2.2')
        self.store.update_server('node1', {'tag_updates': {'application': 'billing'}}, 'named-admin')
        group = self.store.save_group({'name': 'Static', 'type': 'static', 'server_ids': ['node1', 'consumer']}, 'named-admin')
        self.store.save_policy({'name': 'Source policy', 'selector': {}, 'mode': 'monitor',
            'services': [{'port': 8443, 'sources': [], 'source_selector': {'application': 'billing'}}]}, 'named-admin')
        before = self.store.assignment('consumer')[0]
        self.assertEqual(before['services'][0]['sources'], ['10.241.1.1/32'])
        self.store.audit('historical.fixture', 'named-admin', {'server_id': 'node1'})
        histories = self.store.policy_history('node1')
        with self.store.meta() as db:
            self.store._put(db, 'alerts', {'id': 'open-alert', 'server_id': 'node1', 'status': 'open', 'message': 'Old alert'})
            self.store._put(db, 'metadata_ip_profiles', {'id': '10.241.1.1', 'ip': '10.241.1.1', 'tags': {'owner': 'finance'}})
        preview = lifecycle.delete_preview(self.store, 'node1', 'named-admin')
        self.assertTrue(preview['can_delete'])
        self.assertEqual(preview['impact']['static_group_ids'], [group['id']])
        self.assertEqual(preview['impact']['retained_ip_profile_ids'], ['10.241.1.1'])
        self.assertEqual(self.store.server('node1')['hostname'], 'node1')
        with patch.object(self.store, 'compile_all', wraps=self.store.compile_all) as compile_all:
            self.assertEqual(self.retire('node1', preview)['status'], 'applied')
            self.assertEqual(compile_all.call_count, 1)
        with self.assertRaises(KeyError):
            self.store.server('node1')
        self.assertEqual(self.store.get('retired_endpoints', 'node1')['server']['hostname'], 'node1')
        self.assertEqual(self.store.get('groups', group['id'])['server_ids'], ['consumer'])
        self.assertEqual(self.store.assignment('consumer')[0]['services'][0]['sources'], [])
        self.assertGreater(self.store.assignment('consumer')[0]['version'], before['version'])
        self.assertEqual(self.store.policy_history('node1'), histories)
        self.assertEqual(self.store.get('alerts', 'open-alert')['resolution_reason'], 'Endpoint retired; monitoring is no longer active')
        with self.store.meta() as db:
            with self.assertRaises(PermissionError):
                lifecycle.assert_report_allowed(self.store, db, 'node1')
        with self.assertRaises(WorkflowConflict):
            self.retire('node1', preview)

    def test_pending_reservation_cancel_revokes_bound_tokens_without_compiling(self):
        reservation = lifecycle.create(self.store, {'hostname': 'pending-node'}, 'named-admin')
        with self.store.meta() as db:
            self.store._put(db, 'tokens', {'id': 'tokenhash', 'server_id': reservation['id'], 'used': False})
        with patch.object(self.store, 'compile_all', wraps=self.store.compile_all) as compile_all:
            result = self.retire(reservation['id'])
            self.assertEqual(compile_all.call_count, 0)
        self.assertEqual(result['kind'], 'reservation_retirement')
        self.assertEqual(lifecycle.reservation_listing(self.store), [])
        self.assertTrue(self.store.get('tokens', 'tokenhash')['revoked'])
        with self.store.meta() as db:
            with self.assertRaises(PermissionError):
                lifecycle.validate_binding(self.store, db, {'server_id': reservation['id']}, 'pending-node')

    def test_active_managed_history_firewall_work_and_collectors_block_retirement(self):
        self.host()
        for fields in ({'_managed_rules_active': True},
                       {'_managed_rules_active': False, '_last_managed_applied_version': 4},
                       {'_last_managed_applied_version': 0, 'managed_enforcement': {'status': 'committing'}},
                       {'managed_enforcement': {}, 'collector_status': 'learning'},
                       {'collector_status': 'off', 'security_monitor': {'enabled': True, 'status': 'active'}}):
            self.mutate('node1', **fields)
            preview = lifecycle.delete_preview(self.store, 'node1', 'named-admin')
            self.assertFalse(preview['can_delete'])
            self.assertNotIn('confirmation_nonce', preview)
            with self.assertRaises(WorkflowConflict):
                self.retire('node1', preview)
        self.mutate('node1', security_monitor={}, managed_enforcement={})
        with self.store.meta() as db:
            self.store._put(db, 'firewall_changes', {'id': 'queued-change', 'status': 'queued', 'server_ids': ['node1'],
                                                  'operations_by_server': {'node1': []}, 'results': {}})
        self.assertFalse(lifecycle.delete_preview(self.store, 'node1', 'named-admin')['can_delete'])

    def test_review_ignores_heartbeat_but_rejects_changed_metadata_nonce_expiry_and_wrong_host(self):
        self.host()
        preview = lifecycle.delete_preview(self.store, 'node1', 'named-admin')
        self.host()
        with self.assertRaises(WorkflowConflict):
            lifecycle.delete_confirm(self.store, 'wrong-host', {'plan_id': preview['id'], 'confirmation_nonce': preview['confirmation_nonce']}, 'named-admin')
        with self.assertRaises(WorkflowConflict):
            lifecycle.delete_confirm(self.store, 'node1', {'plan_id': preview['id'], 'confirmation_nonce': 'wrong'}, 'named-admin')
        self.store.update_server('node1', {'tag_updates': {'application': 'billing'}}, 'named-admin')
        with self.assertRaises(WorkflowConflict):
            self.retire('node1', preview)
        expired = lifecycle.delete_preview(self.store, 'node1', 'named-admin')
        with self.store.meta() as db:
            raw = self.store._get(db, 'server_lifecycle_plans', expired['id'])
            raw['expires_at'] = stamp(now() - timedelta(seconds=1))
            self.store._put(db, 'server_lifecycle_plans', raw)
        with self.assertRaises(WorkflowConflict):
            self.retire('node1', expired)
        fresh = lifecycle.delete_preview(self.store, 'node1', 'named-admin')
        self.host()
        self.assertEqual(self.retire('node1', fresh)['status'], 'applied')

    def test_failed_recompile_rolls_back_archiving_membership_and_plan_consumption(self):
        self.host()
        preview = lifecycle.delete_preview(self.store, 'node1', 'named-admin')
        with patch.object(self.store, 'compile_all', side_effect=RuntimeError('fixture compiler failure')):
            with self.assertRaises(RuntimeError):
                self.retire('node1', preview)
        self.assertEqual(self.store.server('node1')['hostname'], 'node1')
        with self.assertRaises(KeyError):
            self.store.get('retired_endpoints', 'node1')
        self.assertEqual(self.store.get('server_lifecycle_plans', preview['id'])['status'], 'draft')
        self.assertEqual(self.retire('node1', preview)['status'], 'applied')

    def test_historical_approved_cleanup_is_required_and_all_related_plans_are_invalidated(self):
        baseline = {'management_sources': ['10.99.0.0/24'], 'ssh_ports': [2022],
                    'controller_url': 'https://controller.example',
                    'management_probe_url': 'https://controller.example/api/v1/agent/enforcement/check', 'zone': 'public'}
        protection = {**baseline, 'digest': digest(baseline), 'ready': True, 'blockers': []}
        report = {'hostname': 'node1', 'ips': ['10.241.1.1'], 'listeners': [{'port': 2022, 'protocol': 'tcp', 'process': 'sshd', 'service': 'SSH'}],
                  'firewalld_state': 'running', 'protection': protection, 'apply_status': 'preview', 'applied_version': 0}
        self.store.report('node1', report)
        policy = self.store.save_policy({'name': 'Managed SSH', 'selector': {}, 'mode': 'enforce',
                    'services': [{'port': 2022, 'sources': ['10.99.0.0/24']}]}, 'named-admin')

        def approve_and_report():
            plan = self.store.create_managed_rollout({'name': 'Exact test review', 'server_ids': ['node1']}, 'named-admin')
            first = self.store.confirm_managed_rollout(plan['id'], {'confirmation_nonce': plan['confirmation_nonce']}, 'named-admin')
            approved = self.store.confirm_managed_rollout(plan['id'], {'confirmation_nonce': first['confirmation_nonce'],
                         'challenge': first['confirmation_phrase']}, 'named-admin')
            bundle = self.store.assignment('node1')[0]
            outcome = {'status': 'enforced', 'version': bundle['version'], 'digest': bundle['digest'],
                       'approval_id': approved['id'], 'updated_at': stamp()}
            self.store.report('node1', {**report, 'managed_enforcement': outcome,
                              'applied_version': bundle['version'], 'apply_status': 'synced'})
            return approved

        enforcement = approve_and_report()
        self.assertFalse(lifecycle.delete_preview(self.store, 'node1', 'named-admin')['can_delete'])
        self.store.save_policy({**policy, 'mode': 'monitor'}, 'named-admin', policy['id'])
        self.assertFalse(lifecycle.delete_preview(self.store, 'node1', 'named-admin')['can_delete'])
        cleanup = approve_and_report()
        self.assertEqual(self.store.server('node1')['managed_enforcement']['intent'], 'remove_managed_rules')
        safe = lifecycle.delete_preview(self.store, 'node1', 'named-admin')
        self.assertTrue(safe['can_delete'], safe['blockers'])
        self.retire('node1', safe)
        for identifier in (enforcement['id'], cleanup['id']):
            self.assertEqual(self.store.get('managed_rollouts', identifier)['status'], 'invalidated')
        self.assertEqual(len(self.store.managed_rollouts()), 2)
        with self.store.meta() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM managed_approvals WHERE active=1').fetchone()[0], 0)

    def test_draft_imported_changes_are_invalidated_without_changing_their_exact_targets(self):
        self.host()
        with self.store.meta() as db:
            self.store._put(db, 'firewall_changes', {'id': 'draft-change', 'status': 'draft', 'confirmation_nonce': 'draft-nonce',
                         'server_ids': ['node1'], 'operations_by_server': {'node1': [{'operation': 'remove'}]}, 'results': {}})
        preview = lifecycle.delete_preview(self.store, 'node1', 'named-admin')
        self.assertEqual(preview['impact']['invalidated_firewall_change_ids'], ['draft-change'])
        self.retire('node1', preview)
        change = self.store.get('firewall_changes', 'draft-change')
        self.assertEqual(change['server_ids'], ['node1'])
        self.assertEqual(change['operations_by_server'], {'node1': [{'operation': 'remove'}]})
        self.assertEqual(change['status'], 'invalidated')
        self.assertEqual(change['confirmation_nonce'], '')


if __name__ == '__main__':
    unittest.main()
