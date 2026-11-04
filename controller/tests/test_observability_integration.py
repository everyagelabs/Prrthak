"""Real store/manager/HTTP seams; no network providers or endpoint mutations."""
from datetime import timedelta
from email.message import Message
import json
from pathlib import Path
import socket
import tempfile
import types
import unittest
from unittest.mock import patch

from controller.app import App, handler_for
from controller import siem
from controller.platform import PlatformManager
from controller.platform_runtime import META_TABLES, _columns
from controller.store import Store, now, stamp
from controller.tests.test_firewall_counters import sample, rule


class ObservabilityIntegrationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='prthak-observability-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.store = Store(self.root/'store')
        self.manager = PlatformManager(self.root/'private')
        self.app = App(self.store, tokens={'read_only': 'reader', 'admin': 'operator', 'super_admin': 'super'})
        self.manager.app = self.app
        self.app.platform = self.manager
        self.material = patch('controller.cluster_bootstrap._material', return_value={'sync_key': 'test-only-sync-material', 'ca': 'test-only-authority-material'})
        self.material.start(); self.addCleanup(self.material.stop)
        (self.manager.root/'appliance-material.json').write_text('{}')
        (self.manager.root/'appliance-material.json').chmod(0o600)
        _ = self.manager.vault
        self.resolver = lambda host, port, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', port))]

    def request(self, path, body=None, token='reader', method='GET'):
        handler = object.__new__(handler_for(self.app))
        handler.command, handler.path, handler.connection = method, '/api/v1'+path, object()
        handler.client_address, handler.headers = ('127.0.0.1',12345), Message()
        if token: handler.headers['Authorization'] = 'Bearer '+token
        handler.body = lambda: {} if body is None else body
        result = {}; handler.response = lambda status, value=None, headers=None: result.update(status=status,value=value)
        handler.dispatch(); return result

    def configure_siem(self):
        # Resolver injection is the test seam; no DNS/network calls.
        plan=siem.preview(self.manager, {'enabled': True,'expected_revision':0,'url':'https://siem.example.test/receive','auth_token':'private-test-token'}, 'super', resolver=self.resolver)
        return siem.apply(self.manager, {'preview_id':plan['id'], **{key:plan[key] for key in ('digest','confirmation_nonce','confirmation_phrase')}}, 'super', resolver=self.resolver)

    def test_real_manager_derives_separate_siem_key_and_store_hook_captures_once(self):
        self.assertNotEqual(self.manager.shared_secret_key('siem-export-v1'),self.manager.shared_secret_key('policy-signing-v1'))
        self.configure_siem()
        self.store.audit('policy.saved','operator',{'secret':'never-export'})
        alert={'id':'alert','kind':'port_scan','server_id':'node','severity':'warning','status':'open','created_at':stamp(),'details':{'source_ip':'192.0.2.44','port':443,'protocol':'tcp','private':'never-export'}}
        with self.store.meta() as db:
            self.store._put(db,'alerts',alert)
            self.store._put(db,'alerts',alert)
            queued=db.execute('SELECT sequence,queued FROM siem_cursor WHERE id=?',('stream',)).fetchone()
            data=[json.loads(row[0]) for row in db.execute('SELECT data FROM siem_events ORDER BY sequence')]
        self.assertEqual((queued[0],queued[1]),(2,2))
        self.assertNotIn('never-export',json.dumps(data));self.assertNotIn('private-test-token',json.dumps(data))
        self.assertEqual(data[1]['source_ip'],'192.0.2.44')
        self.assertEqual(siem.get(self.manager)['health'],'queued')

    def test_counter_report_lives_outside_server_and_fleet_policy_payloads(self):
        at=now(); payload={'hostname':'node','ips':['192.0.2.10'],'listeners':[],'firewall_counters':sample(collected_at=stamp(at))}
        self.store.report('node',payload)
        server=self.store.get('servers','node')
        self.assertNotIn('firewall_counters',server)
        self.assertEqual(self.store.get('firewall_counter_samples','node')['firewall_counters']['rules'][0]['packets'],'9007199254740993')

        result=self.request('/servers/node/firewall-counters?limit=1')
        self.assertEqual(result['status'],200);self.assertEqual(result['value']['count_unit'],'packets')
        self.assertEqual(len(result['value']['items']),1)
        self.assertNotIn('firewall_counters',json.dumps(self.store.overview()))
        self.assertNotIn('firewall_counters',json.dumps(self.store.assignment('node')))
        self.store.report('node',{'hostname':'node','ips':['192.0.2.10'],'listeners':[],'discovery_performed':False})
        self.assertEqual(self.request('/servers/node/firewall-counters')['value']['items'][0]['delta_status'],'baseline')
        invalid={**payload,'firewall_counters':sample([rule(packets='0',bytes='0')],collected_at=stamp(at))}
        with self.assertRaisesRegex(ValueError,'cached'): self.store.report('node',invalid)
        self.assertEqual(self.store.get('firewall_counter_samples','node')['firewall_counters']['rules'][0]['packets'],'9007199254740993')

    def test_fleet_projection_hides_maintenance_payloads_and_marks_uncertain_quarantine(self):
        self.store.report('node',{'hostname':'node','ips':['192.0.2.10'],'listeners':[]})
        with self.store.meta() as db:
            server=self.store._get(db,'servers','node')
            server['_firewall_activation_job']={'approval_proof':{'private':'PRIVATE_JOB'},'assessment':'X'*120000}
            server['firewall_activation']={'id':'job','operation':'assess','target_operation':'migrate_ufw','status':'assessed','checked_at':stamp(),
                'assessment':{'can_apply':False,'firewalld_active':False,'ufw_active':True,'blockers':['Unsupported routed rule'],
                    'translated_rules':[{'source':'PRIVATE_RULE'}]*1000}}
            server['network_control']={'checked_at':stamp(),'protected_egress':[{'destination':'PRIVATE_CONTEXT'}],
                'egress':{'status':'enforced'},'quarantine':{'status':'quarantined','expires_at':stamp(now()-timedelta(seconds=1))}}
            self.store._put(db,'servers',server)
        for public in (self.store.servers()[0],self.store.server('node')):
            encoded=json.dumps(public)
            for private in ('PRIVATE_JOB','PRIVATE_RULE','PRIVATE_CONTEXT','translated_rules','_firewall_activation_job'):
                self.assertNotIn(private,encoded)
            facts=public['firewall_activation']['assessment']
            self.assertIs(facts['can_apply'],False);self.assertIs(facts['ufw_active'],True)
            self.assertEqual(public['network_control']['quarantine']['status'],'expiry_unconfirmed')
            self.assertTrue(public['network_control']['quarantine']['expiry_unconfirmed'])

    def test_network_and_maintenance_routes_keep_read_only_queries_and_admin_mutations_separate(self):
        self.assertEqual(self.request('/network-control')['status'],200)
        self.assertEqual(self.request('/firewall-activation/query',{},method='POST')['status'],200)
        for path in ('/network-control/assess','/network-control/preview','/network-control/job/confirm',
                     '/firewall-activation/assess','/firewall-activation/preview','/firewall-activation/job/confirm'):
            self.assertEqual(self.request(path,{},method='POST')['status'],403,path)

    def test_siem_and_signing_http_boundaries_preserve_roles_and_do_not_accept_private_keys(self):
        for token in ('reader','operator'):
            self.assertEqual(self.request('/platform/siem',token=token)['status'],200)
            self.assertEqual(self.request('/platform/signing',token=token)['status'],200)
            for path in ('/platform/siem/preview','/platform/signing/check','/platform/signing/checkpoints'):
                self.assertEqual(self.request(path,{},token=token,method='POST')['status'],403)
        self.assertEqual(self.request('/platform/signing/check',{},token='super',method='POST')['value']['status'],'passed')
        self.assertEqual(self.request('/platform/signing/check',{'private_key':'not-accepted'},token='super',method='POST')['status'],400)
        self.assertEqual(self.request('/platform/siem',token=None)['status'],401)

    def test_all_new_metadata_tables_have_backup_column_contracts(self):
        with self.store.read_meta() as db:
            for table in ('network_control_plans','network_control_assignments','firewall_counter_samples','siem_settings','siem_reviews','siem_cursor','siem_events','siem_deliveries'):
                self.assertIn(table,META_TABLES)
                if getattr(db,'dialect','sqlite')=='postgresql':
                    actual=tuple(row[0] for row in db.execute("SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND table_name=? ORDER BY ordinal_position",(table,)))
                else:
                    actual=tuple(row[1] for row in db.execute('PRAGMA table_info('+table+')'))
                self.assertEqual(actual,_columns(table))
