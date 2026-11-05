import copy
import tempfile
import unittest
from unittest.mock import patch

from controller import metadata
from controller.firewall import WorkflowConflict
from controller.store import Store


class CentralMetadataTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(self.temp.name)
        self.noida = self.store.save_location({'name': 'Noida81', 'location': 'Noida', 'type': 'datacenter'}, 'admin')
        self.dr = self.store.save_location({'name': 'Recovery', 'location': 'Mumbai', 'type': 'datacenter'}, 'admin')

    def host(self, identifier='node1', ips=None, **extra):
        return self.store.report(identifier, {'hostname': identifier, 'ips': ips or ['10.241.1.1'],
            'listeners': [], 'firewalld_state': 'running', **extra})

    def subnet(self, cidr='10.241.0.0/16', location=None, **extra):
        preview = metadata.subnet_preview(self.store, {'cidr': cidr, 'location_id': (location or self.noida)['id'], **extra})
        metadata.subnet_apply(self.store, preview['id'], {'confirmation_nonce': preview['confirmation_nonce']}, 'admin')
        return preview['payload']['rule']

    def profile(self, ip='10.241.1.1', tags=None, location=None):
        value = {'id': ip, 'ip': ip, 'tags': tags or {}}
        if location is not None:
            value['location_id'] = location['id']
        with self.store.meta() as db:
            self.store._put(db, 'metadata_ip_profiles', value)
            metadata.reconcile_all(self.store, db)
            self.store.compile_all(db)

    def test_bulk_preview_freezes_reported_ips_for_five_and_two_unchanged_hosts(self):
        expected = {}
        for index in range(5):
            identifier = 'node' + str(index)
            addresses = ['172.31.3.' + str(index + 1), '100.66.222.' + str(index + 1), '2001:db8::' + str(index + 1)]
            self.host(identifier, ips=addresses, transport_ip='198.51.100.99')
            self.store.update_server(identifier, {'tags': {'application': 'billing'}}, 'admin')
            expected[identifier] = sorted(addresses)
        before = {table: copy.deepcopy(self.store.all(table)) for table in ('servers', 'policies', 'audit')}
        for selected in (list(expected), ['node1', 'node3']):
            preview = metadata.bulk_preview(self.store, {'server_ids': selected,
                'tag_updates': {'application': 'billing'}})
            self.assertEqual(preview['summary']['matched_servers'], len(selected))
            self.assertEqual(preview['summary']['changed_servers'], 0)
            self.assertEqual({row['server_id']: row['ips'] for row in preview['items']},
                             {identifier: expected[identifier] for identifier in selected})
            self.assertNotIn('198.51.100.99', str(preview))
            for table, rows in before.items():
                self.assertEqual(self.store.all(table), rows, table)
        self.host('node1', ips=['172.31.9.1'])
        with self.assertRaises(WorkflowConflict):
            metadata.bulk_apply(self.store, preview['id'],
                {'confirmation_nonce': preview['confirmation_nonce']}, 'admin')

    def test_current_and_future_hosts_follow_saved_subnet_without_enrollment_tags(self):
        self.host()
        self.assertIsNone(self.store.server('node1')['location_id'])
        rule = self.subnet()
        current = self.store.server('node1')
        self.assertEqual(current['location_id'], self.noida['id'])
        self.assertEqual(current['location_source'], {'type': 'subnet', 'rule_id': rule['id'], 'cidr': '10.241.0.0/16', 'ip': '10.241.1.1'})
        self.host('node2', ['10.241.9.2'])
        self.assertEqual(self.store.server('node2')['location_id'], self.noida['id'])
        self.assertEqual(self.store.server('node2')['tags'], {})

    def test_manual_overrides_csv_and_subnet_until_explicit_reset(self):
        self.subnet()
        self.profile(tags={'application': 'billing', 'owner': 'finance'}, location=self.dr)
        self.host()
        csv = self.store.server('node1')
        self.assertEqual(csv['location_id'], self.dr['id'])
        self.assertEqual(csv['tag_sources']['application']['type'], 'csv')
        self.store.update_server('node1', {'location_id': self.noida['id'], 'tag_updates': {'application': 'payments'}}, 'admin')
        self.profile(tags={'application': 'platform', 'owner': 'ops'}, location=self.dr)
        manual = self.store.server('node1')
        self.assertEqual(manual['tags'], {'application': 'payments', 'owner': 'ops'})
        self.assertEqual(manual['location_id'], self.noida['id'])
        self.assertEqual(manual['location_source']['type'], 'manual')
        self.store.update_server('node1', {'location_mode': 'automatic', 'reset_tag_keys': ['application']}, 'admin')
        reset = self.store.server('node1')
        self.assertEqual(reset['tags']['application'], 'platform')
        self.assertEqual(reset['location_id'], self.dr['id'])

    def test_manual_clear_tombstones_are_visible_and_survive_future_reports(self):
        self.profile(tags={'application': 'billing'}, location=self.noida)
        self.host()
        self.store.update_server('node1', {'tags': {}, 'location_id': None}, 'admin')
        self.host(tags={'application': 'agent-invention'}, location_id=self.dr['id'])
        current = self.store.server('node1')
        self.assertEqual(current['tags'], {})
        self.assertIsNone(current['location_id'])
        self.assertEqual(current['tag_sources']['application'], {'type': 'manual', 'removed': True})
        self.assertEqual(current['metadata_removed_tag_keys'], ['application'])
        self.store.update_server('node1', {'reset_tag_keys': ['application'], 'location_mode': 'automatic'}, 'admin')
        self.assertEqual(self.store.server('node1')['tags']['application'], 'billing')
        self.assertEqual(self.store.server('node1')['location_id'], self.noida['id'])

    def test_full_tag_editor_does_not_pin_untouched_automatic_values(self):
        self.profile(tags={'application': 'billing', 'owner': 'finance'})
        self.host()
        self.store.update_server('node1', {'tags': {'application': 'billing', 'owner': 'audit'}}, 'admin')
        self.profile(tags={'application': 'platform', 'owner': 'ops'})
        current = self.store.server('node1')
        self.assertEqual(current['tags'], {'application': 'platform', 'owner': 'audit'})
        self.assertEqual(current['tag_sources']['application']['type'], 'csv')
        self.assertEqual(current['tag_sources']['owner']['type'], 'manual')

    def test_bulk_preview_counts_source_only_changes_and_failed_apply_is_atomic(self):
        self.profile(tags={'application': 'billing'})
        self.host()
        self.host('node2', ['10.241.1.2'])
        preview = metadata.bulk_preview(self.store, {'server_ids': ['node1'],
            'tag_updates': {'application': 'billing'}})
        self.assertEqual(preview['summary']['changed_servers'], 1)
        self.assertEqual(preview['items'][0]['before'], preview['items'][0]['after'])
        self.assertEqual(preview['items'][0]['tag_sources']['application']['type'], 'manual')
        metadata.bulk_apply(self.store, preview['id'], {'confirmation_nonce': preview['confirmation_nonce']}, 'admin')
        preview = metadata.bulk_preview(self.store, {'server_ids': ['node1', 'node2'],
            'tag_updates': {'owner': 'finance'}, 'location_id': self.noida['id']})
        before = {identifier: self.store.server(identifier) for identifier in ['node1', 'node2']}
        with patch.object(self.store, 'compile_all', side_effect=RuntimeError('compilation unavailable')):
            with self.assertRaises(RuntimeError):
                metadata.bulk_apply(self.store, preview['id'], {'confirmation_nonce': preview['confirmation_nonce']}, 'admin')
        self.assertEqual({identifier: self.store.server(identifier) for identifier in before}, before)
        self.assertEqual(self.store.get('metadata_plans', preview['id'])['status'], 'draft')
        metadata.bulk_apply(self.store, preview['id'], {'confirmation_nonce': preview['confirmation_nonce']}, 'admin')
        self.assertEqual(self.store.server('node2')['tags']['owner'], 'finance')

    def test_prefix_precedence_and_multi_interface_conflicts_do_not_guess(self):
        self.subnet()
        self.subnet('10.241.1.0/24', self.dr)
        self.host()
        self.assertEqual(self.store.server('node1')['location_id'], self.dr['id'])
        self.host(ips=['10.241.1.1', '10.241.2.1'])
        conflict = self.store.server('node1')
        self.assertIsNone(conflict['location_id'])
        self.assertEqual(conflict['location_source']['type'], 'conflict')
        self.assertTrue(conflict['metadata_conflicts'])
        self.assertTrue(any(row['kind'] == 'metadata_location_conflict' and not row.get('resolved') for row in self.store.all('alerts')))
        self.store.update_server('node1', {'location_id': self.noida['id']}, 'admin')
        self.assertEqual(self.store.server('node1')['location_id'], self.noida['id'])
        self.assertFalse(self.store.server('node1')['metadata_conflicts'])

    def test_nested_dc_networks_reassign_current_future_and_moved_hosts(self):
        pune = self.store.save_location({'name': 'Pune', 'location': 'Pune', 'type': 'datacenter'}, 'admin')
        broad = self.subnet('10.0.0.0/8', self.noida)
        self.subnet('10.241.0.0/16', self.dr)
        self.host('wide', ['10.20.1.2'])
        self.host('nested', ['10.241.7.9'])
        narrow = self.subnet('10.241.7.0/24', pune)
        self.assertEqual(self.store.server('wide')['location_id'], self.noida['id'])
        self.assertEqual(self.store.server('nested')['location_id'], pune['id'])
        self.assertEqual(self.store.server('nested')['location_source']['rule_id'], narrow['id'])
        self.host('future', ['10.241.7.10'])
        self.assertEqual(self.store.server('future')['location_id'], pune['id'])
        self.host('nested', ['10.241.8.9'])
        self.assertEqual(self.store.server('nested')['location_id'], self.dr['id'])
        removal = metadata.subnet_preview(self.store, {}, remove_id=narrow['id'])
        metadata.subnet_apply(self.store, removal['id'], {'confirmation_nonce': removal['confirmation_nonce']}, 'admin')
        self.assertEqual(self.store.server('future')['location_id'], self.dr['id'])
        self.assertEqual(self.store.server('wide')['location_source']['rule_id'], broad['id'])

    def test_ipv6_specific_network_and_manual_override_take_precedence(self):
        self.subnet('2001:db8::/32', self.noida)
        self.subnet('2001:db8:81::/48', self.dr)
        self.host('v6', ['2001:db8:81:7::5'])
        self.assertEqual(self.store.server('v6')['location_id'], self.dr['id'])
        self.store.update_server('v6', {'location_id': self.noida['id']}, 'admin')
        self.host('v6', ['2001:db8:81:7::6'])
        self.assertEqual(self.store.server('v6')['location_source']['type'], 'manual')
        self.assertEqual(self.store.server('v6')['location_id'], self.noida['id'])
        self.store.update_server('v6', {'location_mode': 'automatic'}, 'admin')
        self.assertEqual(self.store.server('v6')['location_id'], self.dr['id'])

    def test_one_ip_cannot_be_assigned_to_two_dcs_and_same_dc_vip_is_allowed(self):
        self.subnet()
        self.host('node1')
        self.host('node2')
        self.assertEqual(self.store.server('node1')['location_id'], self.noida['id'])
        self.assertEqual(self.store.server('node2')['location_id'], self.noida['id'])
        with self.assertRaisesRegex(ValueError, 'another DC'):
            self.store.update_server('node2', {'location_id': self.dr['id']}, 'admin')
        self.assertEqual(self.store.server('node2')['location_id'], self.noida['id'])
        plan = metadata.bulk_preview(self.store, {'server_ids': ['node1', 'node2'], 'location_id': self.dr['id']})
        metadata.bulk_apply(self.store, plan['id'], {'confirmation_nonce': plan['confirmation_nonce']}, 'admin')
        self.assertEqual({self.store.server(value)['location_id'] for value in ('node1', 'node2')}, {self.dr['id']})

    def test_later_duplicate_ip_with_conflicting_manual_dc_is_withheld(self):
        self.host('node1', ['10.241.1.1'])
        self.host('node2', ['10.242.1.1'])
        self.store.update_server('node1', {'location_id': self.noida['id']}, 'admin')
        self.store.update_server('node2', {'location_id': self.dr['id']}, 'admin')
        self.host('node2', ['10.241.1.1'])
        for value in ('node1', 'node2'):
            current = self.store.server(value)
            self.assertIsNone(current['location_id'])
            self.assertEqual(current['location_source']['type'], 'conflict')
            self.assertTrue(any('same IP' in row['reason'] for row in current['metadata_conflicts']))

    def test_duplicate_cidr_invalid_ids_and_missing_location_rejected(self):
        self.subnet()
        for value in ({'cidr': '10.241.0.1/16', 'location_id': self.dr['id']},
                      {'cidr': '10.242.0.0/16', 'location_id': 'missing'},
                      {'cidr': '0.0.0.0/0', 'location_id': self.noida['id']},
                      {'cidr': True, 'location_id': self.noida['id']},
                      {'cidr': '10.242.0.0/16', 'location_id': self.noida['id'], 'id': 42}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                metadata.subnet_preview(self.store, value)

    def test_subnet_delete_restores_automatic_fallback_without_touching_manual(self):
        rule = self.subnet()
        self.host()
        self.host('node2', ['10.241.2.1'])
        self.store.update_server('node2', {'location_id': self.noida['id']}, 'admin')
        plan = metadata.subnet_preview(self.store, {}, remove_id=rule['id'])
        self.assertEqual(plan['payload']['rule'], rule)
        self.assertEqual(plan['payload']['rule_id'], rule['id'])
        metadata.subnet_apply(self.store, plan['id'], {'confirmation_nonce': plan['confirmation_nonce']}, 'admin')
        self.assertIsNone(self.store.server('node1')['location_id'])
        self.assertEqual(self.store.server('node2')['location_id'], self.noida['id'])

    def test_bulk_preview_is_atomic_binds_metadata_not_heartbeats_and_compiles_once(self):
        self.host()
        self.host('node2', ['10.241.2.1'])
        plan = metadata.bulk_preview(self.store, {'server_ids': ['node1', 'node2'],
            'tag_updates': {'application': 'billing', 'criticality': 'high'}, 'location_id': self.noida['id']})
        self.assertEqual(self.store.server('node1')['tags'], {})
        self.host()
        with patch.object(self.store, 'compile_all', wraps=self.store.compile_all) as compile_all:
            metadata.bulk_apply(self.store, plan['id'], {'confirmation_nonce': plan['confirmation_nonce']}, 'admin')
            self.assertEqual(compile_all.call_count, 1)
        self.assertEqual(self.store.server('node2')['tags']['application'], 'billing')
        with self.assertRaises(WorkflowConflict):
            metadata.bulk_apply(self.store, plan['id'], {'confirmation_nonce': 'replayed'}, 'admin')

    def test_bulk_stale_metadata_and_ip_changes_require_new_preview(self):
        self.host()
        plan = metadata.bulk_preview(self.store, {'server_ids': ['node1'], 'tag_updates': {'application': 'billing'}})
        self.host(ips=['10.241.2.1'])
        with self.assertRaises(WorkflowConflict):
            metadata.bulk_apply(self.store, plan['id'], {'confirmation_nonce': plan['confirmation_nonce']}, 'admin')
        self.assertEqual(self.store.server('node1')['tags'], {})

    def test_legacy_manual_state_migrates_and_legacy_enrollment_defaults_never_apply(self):
        self.host()
        with self.store.meta() as db:
            server = self.store._get(db, 'servers', 'node1')
            server.pop('_metadata_overrides')
            server.update({'tags': {'application': 'billing'}, 'location_id': self.noida['id']})
            self.store._put(db, 'servers', server)
        restarted = Store(self.temp.name)
        self.assertEqual(restarted.server('node1')['location_source']['type'], 'manual')
        self.assertEqual(restarted.server('node1')['tag_sources']['application']['type'], 'manual')
        for invalid in ({'tags': {'application': 'payments'}}, {'location_id': self.noida['id']}):
            with self.assertRaises(ValueError):
                restarted.create_token('identity only', 'admin', **invalid)
        token = restarted.create_token('legacy', 'admin')
        with restarted.meta() as db:
            record = next(row for row in restarted._all(db, 'tokens') if row['name'] == 'legacy')
            record.update({'tags': {'application': 'legacy-default'}, 'location_id': self.noida['id']})
            restarted._put(db, 'tokens', record)
        enrolled = restarted.enroll(token['token'], 'new-host', '-----BEGIN CERTIFICATE REQUEST-----\nrequest', lambda *args: ('certificate', 'ca'))
        self.assertEqual(restarted.server(enrolled['server_id'])['tags'], {})
        self.assertIsNone(restarted.server(enrolled['server_id'])['location_id'])

    def test_duplicate_claimed_ip_and_conflicting_profiles_require_resolution(self):
        self.profile(tags={'application': 'billing'})
        self.host()
        self.host('node2')
        self.assertEqual(self.store.server('node1')['tags'], {})
        self.assertTrue(self.store.server('node2')['metadata_conflicts'])
        self.store.update_server('node1', {'tag_updates': {'application': 'payments'}}, 'admin')
        self.assertEqual(self.store.server('node1')['tags']['application'], 'payments')
        self.host('node2', ['10.250.0.2'])
        self.profile('10.241.2.1', {'application': 'platform'})
        self.host('node3', ['10.241.1.1', '10.241.2.1'])
        # The first address remains ambiguous, so the unique second profile wins.
        self.assertEqual(self.store.server('node3')['tags']['application'], 'platform')

    def test_manual_override_resolves_csv_field_conflict_and_location_references_guard_delete(self):
        self.profile('10.241.1.1', {'application': 'billing'})
        self.profile('10.241.2.1', {'application': 'payments'})
        self.host(ips=['10.241.1.1', '10.241.2.1'])
        self.assertTrue(self.store.server('node1')['metadata_conflicts'])
        self.store.update_server('node1', {'tag_updates': {'application': None}}, 'admin')
        self.assertFalse(self.store.server('node1')['metadata_conflicts'])
        self.subnet()
        with self.assertRaises(ValueError):
            self.store.delete_location(self.noida['id'], 'admin')
        self.profile('10.250.0.9', location=self.dr)
        with self.assertRaises(ValueError):
            self.store.delete_location(self.dr['id'], 'admin')

    def test_valid_future_profile_cannot_block_reports_when_combined_tags_overflow(self):
        self.host(ips=['10.250.0.1'])
        manual = {f'key{index}': f'value{index}' for index in range(32)}
        self.store.update_server('node1', {'tags': manual}, 'admin')
        self.profile('10.241.1.1', {'application': 'billing'})
        self.host(ips=['10.241.1.1'])
        current = self.store.server('node1')
        self.assertEqual(current['ips'], ['10.241.1.1'])
        self.assertEqual(current['tags'], manual)
        self.assertTrue(any(conflict['field'] == 'tags' for conflict in current['metadata_conflicts']))
        with self.assertRaises(ValueError):
            self.store.update_server('node1', {'tag_updates': {'extra': 'value'}}, 'admin')
        self.assertEqual(self.store.server('node1')['tags'], manual)


class LocationOwnershipBoundsTests(unittest.TestCase):
    def test_collision_on_one_address_cannot_hide_a_second_dc_collision(self):
        servers = [{'id': 'a', 'ips': ['10.1.0.1'], 'location_id': 'noida'},
                   {'id': 'b', 'ips': ['10.1.0.1', '10.2.0.1'], 'location_id': 'pune'},
                   {'id': 'c', 'ips': ['10.2.0.1'], 'location_id': 'cloud'}]
        metadata.enforce_location_ownership(servers)
        self.assertTrue(all(server['location_id'] is None for server in servers))
        self.assertEqual({row['ip'] for row in servers[1]['metadata_conflicts']}, {'10.1.0.1', '10.2.0.1'})

    def test_large_shared_address_keeps_all_hosts_withheld_and_evidence_bounded(self):
        servers = [{'id': 'host-' + str(index), 'ips': ['10.1.0.1'], 'location_id': 'noida' if index else 'pune'} for index in range(5000)]
        metadata.enforce_location_ownership(servers)
        self.assertTrue(all(server['location_id'] is None for server in servers))
        for server in servers:
            conflict = server['metadata_conflicts'][0]
            self.assertEqual(conflict['server_count'], 5000)
            self.assertEqual(len(conflict['server_ids']), 50)
            self.assertTrue(conflict['details_truncated'])


if __name__ == '__main__':
    unittest.main()
