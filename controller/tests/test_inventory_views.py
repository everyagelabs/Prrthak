import json
import http.client
import tempfile
import threading
import unittest
from unittest.mock import patch

from controller.firewall import fingerprints
from controller.store import Store,stamp


class InventoryPayloadTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.store=Store(self.temp.name)
        rules=[]
        for number in range(100):
            for scope in ('runtime','permanent'):
                value='rule family="ipv4" source address="10.210.0.0/16" port port="'+str(10000+number)+'" protocol="tcp" accept'
                fingerprint,logical=fingerprints(scope,'public','rich_rule',value)
                rules.append(dict(fingerprint=fingerprint,logical_key=logical,scope=scope,zone='public',kind='rich_rule',value=value,action='accept',risk='medium',editable=True,ports=[{'port':str(10000+number),'protocol':'tcp'}]))
        self.template={'id':'fixture','hostname':'fixture','ips':['10.230.0.1'],'tags':{'application':'billing'},'listeners':[{'port':8443,'protocol':'tcp','service':'HTTPS'}],'status':'healthy','last_seen':stamp(),'expected_services':[],'firewall_snapshot':{'status':'ok','collected_at':stamp(),'digest':'a'*64,'rules':rules,'error':''}}
        # A virtual SQL view materializes five thousand representative snapshots
        # without writing a hundreds-of-megabytes fixture into the repository.
        with self.store.meta() as db:
            db.execute('CREATE TABLE fixture_template(data TEXT NOT NULL)')
            db.execute('INSERT INTO fixture_template VALUES(?)',(json.dumps(self.template),))
            db.execute('CREATE TABLE fixture_numbers(n INTEGER PRIMARY KEY)')
            db.executemany('INSERT INTO fixture_numbers VALUES(?)',((number,) for number in range(5000)))
            db.execute('DROP TABLE servers')
            db.execute("CREATE VIEW servers AS SELECT 'fixture-'||n AS id,json_set(data,'$.id','fixture-'||n,'$.hostname',printf('fixture-%05d',n)) AS data FROM fixture_numbers CROSS JOIN fixture_template")

    def test_5000_snapshot_overview_payload_is_compact_and_detail_is_canonical(self):
        with patch.object(self.store,'meta',side_effect=AssertionError('Read view acquired metadata writer')):
            overview=self.store.overview()
        encoded=json.dumps(overview).encode()
        raw_estimate=len(json.dumps(self.template).encode())*5000
        self.assertGreater(raw_estimate,300*1024*1024)
        self.assertLess(len(encoded),10*1024*1024)
        self.assertEqual(len(overview['servers']),5000)
        self.assertEqual(overview['stats']['total_servers'],5000)
        self.assertTrue(all(server['firewall_snapshot']['summary_only'] for server in overview['servers']))
        self.assertTrue(all('rules' not in server['firewall_snapshot'] for server in overview['servers']))
        detail=self.store.server('fixture-17')
        self.assertEqual(len(detail['firewall_snapshot']['rules']),200)
        self.assertEqual(detail['firewall_snapshot']['digest'],'a'*64)

    def test_5000_snapshot_common_page_bounds_payload_without_writer(self):
        with patch.object(self.store,'meta',side_effect=AssertionError('Inventory rendering acquired metadata writer')):
            page=self.store.firewall_inventory(limit=7)
        self.assertEqual(len(page['common_rules']),7)
        self.assertEqual(page['summary']['reported_snapshots'],5000)
        self.assertEqual(page['summary']['matching_endpoint_count'],5000)
        self.assertLess(len(json.dumps(page).encode()),5*1024*1024)
        self.assertTrue(page['pagination']['has_more'])
        self.assertTrue(all(row['host_count']==5000 for row in page['common_rules']))
        self.assertTrue(all('rules' not in row['snapshot'] for row in page['servers']))

    def test_keyset_pages_are_complete_disjoint_and_single_snapshot_is_lazy(self):
        cursor='';seen=[]
        while True:
            page=self.store.firewall_inventory({'fixture-1','fixture-2'},after=cursor,limit=13)
            keys=[row['rule_key'] for row in page['common_rules']]
            self.assertEqual(keys,sorted(keys));self.assertFalse(set(seen)&set(keys));seen.extend(keys)
            if not page['pagination']['has_more']: break
            cursor=page['pagination']['next_cursor']
        self.assertEqual(len(seen),100)
        lazy=self.store.firewall_inventory({'fixture-1'})
        self.assertEqual(len(lazy['servers'][0]['snapshot']['rules']),200)
        self.assertEqual(self.store.firewall_inventory(set())['common_rules'],[])
        with self.assertRaises(ValueError): self.store.firewall_inventory(after='untrusted')
        with self.assertRaises(ValueError): self.store.firewall_inventory(limit=1000)


class InventoryPortScopeTests(unittest.TestCase):
    def test_port_and_search_scope_preserves_exact_host_and_configuration_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            store=Store(directory)
            for identity,ports in (('a',(('runtime','22'),)),('b',(('runtime','2022'),)),('c',(('runtime','2022'),('permanent','22')))):
                store.report(identity,{'hostname':'billing-'+identity,'ips':['10.1.0.'+str(ord(identity)-96)],'listeners':[],'firewall_snapshot':{'status':'ok','collected_at':stamp(),'rules':[{'scope':scope,'zone':'public','kind':'service','value':'ssh','editable':True,'ports':[{'port':port,'protocol':'tcp'}]} for scope,port in ports]}})
            page=store.firewall_inventory({'a','b'},ports=['2022/tcp'],include_snapshots=False)
            self.assertEqual(page['common_rules'][0]['server_ids'],['b'])
            self.assertTrue(page['common_rules'][0]['editable'])
            page=store.firewall_inventory({'a','b','c'},ports=['2022/tcp'],include_snapshots=False)
            self.assertEqual(page['common_rules'][0]['server_ids'],['b','c'])
            self.assertFalse(page['common_rules'][0]['editable'])
            self.assertIn('configuration scopes',page['common_rules'][0]['reason'])
            self.assertEqual(store.firewall_inventory({'a','b'},search='missing',search_server_ids={'b'})['common_rules'][0]['server_ids'],['b'])
            self.assertEqual(store.firewall_inventory({'a','b'},search='ssh',search_server_ids=set())['common_rules'][0]['server_ids'],['a','b'])


class InventoryReadOnlyAPITests(unittest.TestCase):
    def test_read_only_query_and_lazy_canonical_plan_do_not_grant_mutation_access(self):
        from controller.app import App,Server
        with tempfile.TemporaryDirectory() as directory:
            store=Store(directory)
            store.lab_approvals=True  # Explicit disposable fixture; no enforcement is executed.
            store.report('server-a',{'hostname':'server-a','ips':['10.99.0.1'],'listeners':[],'capabilities':['signed_assignments_v1'],'firewall_snapshot':{'status':'ok','collected_at':stamp(),'rules':[{'scope':'runtime','zone':'public','kind':'port','value':'80/tcp','editable':True}]}})
            plan=store.create_firewall_change({'name':'Review fixture','server_ids':['server-a'],'rule_key':fingerprints('runtime','public','port','80/tcp')[1],'operation':'remove','scopes':['runtime']},'fixture-admin')
            app=App(store,tokens={'read_only':'private-inventory-read-token'})
            server=Server(('127.0.0.1',0),app)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            connection=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=5)
            def request(method,path,body=None):
                connection.request(method,path,json.dumps(body).encode() if body is not None else None,{'Authorization':'Bearer private-inventory-read-token','Content-Type':'application/json'})
                response=connection.getresponse();return response.status,json.loads(response.read())
            try:
                status,page=request('POST','/api/v1/firewall/query',{'server_ids':['server-a'],'ports':['80/tcp'],'limit':1})
                self.assertEqual(status,200);self.assertEqual(page['common_rules'][0]['host_count'],1)
                self.assertTrue(page['servers'][0]['snapshot']['summary_only'])
                self.assertNotIn('preview',page['changes'][0])
                status,detail=request('GET','/api/v1/firewall/changes/'+plan['id'])
                self.assertEqual(status,200);self.assertEqual(detail['preview']['before'][0]['value'],'80/tcp')
                status,evidence=request('GET','/api/v1/firewall?server_ids=server-a')
                self.assertEqual(status,200);self.assertEqual(evidence['servers'][0]['snapshot']['rules'][0]['value'],'80/tcp')
                self.assertEqual(request('POST','/api/v1/servers',{'hostname':'forbidden'})[0],403)
                self.assertEqual(request('POST','/api/v1/firewall/changes',{})[0],403)
            finally:
                connection.close();server.shutdown();server.server_close();thread.join(timeout=5)


if __name__=='__main__':unittest.main()
