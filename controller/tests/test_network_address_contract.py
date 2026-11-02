"""Controller input parity with the endpoint's native netip address contract."""
import tempfile
import unittest

from controller import endpoint_configuration, managed, network_addresses
from controller.store import Store


INVALID=('::ffff:192.0.2.1/128','::ffff:192.0.2.1/64','2001:db8::1%eth0/128','2001:db8::1%eth0/64')


class NativeAddressContractTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.store=Store(self.temp.name);self.store.lab_approvals=True
        self.store.report('client',{'hostname':'client','ips':['2001:db8:10::1'],'listeners':[]})
        self.store.report('target',{'hostname':'target','ips':['2001:db8:10::2'],'listeners':[]})
        self.store.update_server('client',{'tag_updates':{'role':'client'}},'admin')
        self.store.update_server('target',{'tag_updates':{'application':'billing'}},'admin')
        self.policy={'name':'Native sources','selector':{'application':'billing'},'mode':'monitor','services':[{'port':8443,'protocol':'tcp','sources':['2001:db8:20::/64']}]}
        self.settings={'controller_url':'https://controller.example','control_url':'','discovery_url':'','management_sources':[],'protected_ssh_ports':[],'zone':'',**{key:False for key in endpoint_configuration.FLAGS}}
        self.protected={'management_sources':['2001:db8:20::/64'],'ssh_ports':[2022],'controller_url':'https://controller.example','management_probe_url':'https://controller.example/api/v1/agent/enforcement/check','zone':'public','ready':True,'blockers':[]}

    def test_policy_mapped_and_scoped_sources_cannot_be_published_or_silently_widened(self):
        original=self.store.save_policy(self.policy,'admin')
        before=self.store.assignment('target')[0]
        for address in INVALID:
            candidate={**original,'expected_revision':original['revision'],'services':[{'port':8443,'sources':[address]}]}
            with self.subTest(address=address),self.assertRaises(ValueError):self.store.save_policy(candidate,'admin',original['id'])
        after=self.store.assignment('target')[0]
        self.assertEqual((before['digest'],before['version']),(after['digest'],after['version']))
        self.assertEqual(self.store.get('policies',original['id'])['revision'],original['revision'])
        self.assertEqual(len(self.store.policy_revisions(original['id'])),1)

    def test_management_settings_and_reported_baseline_reject_same_unsupported_families(self):
        for address in INVALID:
            with self.subTest(address=address):
                with self.assertRaises(ValueError):endpoint_configuration.normalize({**self.settings,'management_sources':[address]})
                with self.assertRaises(ValueError):managed.protection({**self.protected,'management_sources':[address],'digest':'a'*64})

    def test_inventory_claims_cannot_inject_scoped_or_mapped_source_group_addresses(self):
        before=self.store.get('servers','client')
        for address in ('::ffff:192.0.2.1','2001:db8::1%eth0'):
            with self.subTest(address=address),self.assertRaises(ValueError):self.store.report('client',{'hostname':'client','ips':[address],'listeners':[]})
        self.assertEqual(self.store.get('servers','client')['ips'],before['ips'])

    def test_legacy_invalid_source_membership_fails_whole_compilation_without_partial_grant(self):
        group=self.store.save_group({'name':'Clients','type':'dynamic','selector':{'role':'client'},'server_ids':[]},'admin')
        original=self.store.save_policy({**self.policy,'services':[{'port':8443,'sources':[],'source_group_ids':[group['id']]}]},'admin')
        before=self.store.assignment('target')[0]
        with self.store.meta() as db:
            legacy=self.store._get(db,'servers','client');legacy['ips']=['2001:db8::1%eth0'];self.store._put(db,'servers',legacy)
        with self.assertRaises(ValueError):self.store.save_policy({**original,'name':'No partial scope'},'admin',original['id'])
        self.assertEqual(self.store.get('policies',original['id'])['revision'],original['revision'])
        with self.store.read_meta() as db:
            current=self.store._get(db,'servers','target')['_compiled']
        self.assertEqual((current['digest'],current['version']),(before['digest'],before['version']))

    def test_valid_ipv4_and_global_ipv6_keep_canonical_bytes_and_source_group_alignment(self):
        expected={'2001:DB8:0:0::/64':'2001:db8::/64','2001:db8:20::7/128':'2001:db8:20::7/128','192.0.2.129/24':'192.0.2.0/24','192.0.2.7':'192.0.2.7/32'}
        for value,canonical in expected.items():self.assertEqual(str(network_addresses.network(value)),canonical)
        policy=self.store.save_policy({**self.policy,'services':[{'port':8443,'sources':list(expected)}]},'admin')
        self.assertEqual(policy['services'][0]['sources'],sorted(expected.values()))
        normalized=endpoint_configuration.normalize({**self.settings,'management_sources':list(expected)})
        self.assertEqual(normalized['management_sources'],sorted(expected.values()))
        source=self.store.save_policy({**self.policy,'name':'Tag expansion','services':[{'port':9443,'sources':[],'source_selector':{'role':'client'}}]},'admin')
        by_port={row['port']:row['sources'] for row in self.store.assignment('target')[0]['services']}
        self.assertEqual(by_port[9443],['2001:db8:10::1/128'])


if __name__=='__main__':unittest.main()
