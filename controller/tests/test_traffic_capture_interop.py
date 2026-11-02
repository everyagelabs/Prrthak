"""Current backend generation plus checked-in public Python -> Go contracts."""
from collections import Counter
import importlib.util
import json
from pathlib import Path
import unittest

from controller import traffic_capture
from controller.tests.fixtures.generate_traffic_capture_interop import generate


@unittest.skipUnless(importlib.util.find_spec('cryptography'), 'Signed interop needs controller cryptography requirements')
class CaptureInteropTests(unittest.TestCase):
    def assert_contract(self, vector):
        self.assertEqual(vector['schema_version'],1)
        self.assertFalse(vector['provenance']['private_material_exported'])
        self.assertFalse(vector['provenance']['native_firewall_or_live_Entra'])
        encoded=json.dumps(vector)
        for marker in ('BEGIN PRIVATE KEY','BEGIN RSA PRIVATE KEY','BEGIN EC PRIVATE KEY'):
            self.assertNotIn(marker,encoded)
        self.assertEqual({case['name'] for case in vector['cases']}, {'both','accepted-only','denied-only','legacy'})
        for case in vector['cases']:
            policy=case['policy']
            self.assertEqual(policy['server_id'],'target')
            self.assertEqual(policy['signature']['algorithm'],'Ed25519')
            self.assertEqual(policy['hit_monitors'][0]['server_id'],'target')
            self.assertIn('2001:db8:10::1',case['endpoint_ips'])
            self.assertEqual(case['receipts']['monitor_retry']['accepted'],0)
            self.assertTrue(all(row['address_family'] in ('ipv4','ipv6') for row in case['flow_rows']))
            if case['legacy']:
                self.assertNotIn('observation_kinds',policy['learning_sessions'][0])
                self.assertNotIn('observation_kinds',policy['hit_monitors'][0])
                self.assertEqual({row['count_unit'] for row in case['flow_rows']},{'log_records'})
                self.assertEqual({row['capture_kind'] for row in case['flow_rows']},{'legacy_log'})
                # Metadata-free legacy batches have no stable event identity:
                # two distinct batch IDs retain their historical log counts.
                self.assertEqual(sum(row['count'] for row in case['flow_rows']),56)
                self.assertEqual(sum(row['count'] for row in case['recommendations']),56)
                continue
            count=len(case['learning_events'])
            self.assertEqual(case['receipts']['learning_retry']['duplicate_events'],count)
            self.assertEqual(len(case['flow_rows']),count)
            self.assertTrue(all(row['count']==1 for row in case['flow_rows']))
            self.assertTrue(all(row['count']==1 for row in case['monitor_rows']))
            kinds=policy['learning_sessions'][0]['observation_kinds']
            self.assertEqual(policy['hit_monitors'][0]['observation_kinds'],kinds)
            self.assertEqual(policy['learning_allow']['authorities'][0]['observation_kinds'],kinds)
            self.assertEqual(policy['learning_allow']['authorities'][0]['approval_proof']['mode'],'single_admin')
            units={traffic_capture.TYPED[kind][1] for kind in kinds}
            for rows in (case['flow_rows'],case['monitor_rows'],case['recommendations']):
                self.assertEqual(set(row['count_unit'] for row in rows),units)
                totals=Counter()
                for row in rows:totals[row['count_unit']]+=row['count']
                self.assertEqual(dict(totals),{unit:2 for unit in units})
            self.assertEqual(policy['learning_allow']['services'],[{
                'port':443,'protocol':'tcp','sources':['10.50.0.8/32','2001:db8:20::44/128']}])
            self.assertIsNone(case['coverage']['capture_backends'][0]['lost_events'])
            self.assertEqual(case['coverage']['capture_backends'][1]['status'],'unsupported')

    def test_checked_in_fixture_keeps_units_identity_and_legacy_provenance(self):
        path=Path(__file__).with_name('fixtures')/'traffic-capture-v1.json'
        self.assert_contract(json.loads(path.read_text()))

    def test_real_store_apis_still_generate_native_compatible_scopes(self):
        self.assert_contract(generate())
