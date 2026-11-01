"""Large read-only views stay paged; complete exports fail before delivery."""
import csv
import io
import ipaddress
import json
import tempfile
import tracemalloc
import unittest
from datetime import timedelta
from unittest.mock import patch

from controller import evidence_views as views
from controller import learning_policies as lp
from controller.store import Store, now, stamp


class EvidenceViewTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='prthak-evidence-view-')
        self.addCleanup(self.temp.cleanup)
        self.store=self.make_store()
        self.session={'id':'audit-session','server_ids':['a','b'],'status':'active','policy_action':'observe'}
        with self.store.meta() as db:
            self.store._put(db,'sessions',self.session)
            for identifier in self.session['server_ids']:
                # Real-sized inventory fields must not be repeatedly decoded for
                # evidence rows: the evidence projection excludes this data.
                self.store._put(db,'servers',{'id':identifier,'hostname':' =unsafe()' if identifier=='a' else 'billing-b','ips':['10.1.0.1'],'listeners':[{'port':2022,'service':'OpenSSH','process':'sshd'}],'protection':{'ssh_ports':[22],'controller_url':'https://controller.example'},'firewall_snapshot':{'large':'x'*512000}})

    def make_store(self):
        return Store(self.temp.name)

    def seed(self,count=8):
        at=stamp()
        with self.store.meta() as db:
            def values():
                for index in range(count):
                    identifier='a' if index<count//2 else 'b'
                    source=str(ipaddress.IPv4Address('10.20.0.1')+index)
                    row={'id':f'row-{index:06d}','session_id':self.session['id'],'server_id':identifier,'source_ip':source,'source_cidr':source+'/32','source_error':'','port':443,'protocol':'tcp','service':'service-'+'s'*500,'process':'@'+'p'*511,'count':1,'verdicts':['observed'],'first_seen':at,'last_seen':at}
                    yield(row['id'],row['session_id'],identifier,json.dumps(row))
            db.executemany('INSERT INTO learning_evidence(id,session_id,server_id,data) VALUES(?,?,?,?)',values())

    def test_pages_count_and_server_filter_do_not_load_full_evidence(self):
        self.seed(20000)
        with patch.object(lp,'_evidence',side_effect=AssertionError('Public reads must not materialize canonical evidence')):
            result=lp.recommendations(self.store,self.session['id'],limit=7,offset=5)
            self.assertEqual((len(result['rows']),result['total_rows'],result['has_more']),(7,20000,True))
            self.assertEqual(result['rows'][0]['id'],'row-000005')
            filtered=lp.recommendations(self.store,self.session['id'],limit=7,offset=9997,server_id='b')
            self.assertEqual((len(filtered['rows']),filtered['total_rows'],filtered['has_more']),(3,10000,False))
            self.assertTrue(all(row['server_id']=='b' for row in filtered['rows']))
        for identifier in ('unknown','a\' OR 1=1--',''):
            with self.assertRaisesRegex(ValueError,'member'):
                lp.recommendations(self.store,self.session['id'],server_id=identifier)

    def test_count_and_page_share_snapshot_under_concurrent_ingest(self):
        self.seed(8)
        original=views.evidence_rows
        def concurrent(db,*args,**kwargs):
            with self.store.meta() as writer:
                row=next(original(writer,self.session['id']))
                lp._put_evidence(writer,{**row,'id':'new-row'})
            yield from original(db,*args,**kwargs)
        with patch.object(views,'evidence_rows',concurrent):
            result=lp.recommendations(self.store,self.session['id'],limit=20)
        self.assertEqual((result['total_rows'],len(result['rows'])),(8,8))
        self.assertEqual(lp.recommendations(self.store,self.session['id'])['total_rows'],9)

    def test_complete_twenty_thousand_row_export_has_bounded_memory(self):
        self.seed(20000)
        tracemalloc.start()
        try:
            with patch.object(lp,'_evidence',side_effect=AssertionError('Export must stream SQL rows')):
                with views.csv_spool(self.store,self.session['id']) as (source,size):
                    self.assertGreater(size,20*1024*1024)
                    self.assertEqual(source.read(3),b'\xef\xbb\xbf')
                    reader=csv.DictReader(io.TextIOWrapper(source,encoding='utf-8',newline=''))
                    count=0
                    for row in reader:
                        self.assertTrue(row['process'].startswith("'@"))
                        if row['server_id']=='a':self.assertEqual(row['hostname'],"' =unsafe()")
                        count+=1
                    self.assertEqual(count,20000)
            _,peak=tracemalloc.get_traced_memory()
        finally:tracemalloc.stop()
        self.assertLess(peak,3*1024*1024,f'Export-only peak {peak} must not scale with the complete CSV')

    def test_private_spool_closes_and_slot_releases_on_size_error_read_error_and_disconnect(self):
        self.seed()
        actual=views.tempfile.TemporaryFile
        opened=[]
        def tracked(*args,**kwargs):
            output=actual(*args,**kwargs);opened.append(output);return output
        with patch.object(views.tempfile,'TemporaryFile',tracked):
            with self.assertRaisesRegex(ValueError,'Complete CSV exceeds'):
                with views.csv_spool(self.store,self.session['id'],max_bytes=1024):self.fail('Oversized export must never yield a response')
            with patch.object(views,'evidence_rows',side_effect=RuntimeError('fixture database read failed')):
                with self.assertRaisesRegex(RuntimeError,'database read failed'):
                    with views.csv_spool(self.store,self.session['id']):self.fail('Failed export must never yield')
            with self.assertRaises(BrokenPipeError):
                with views.csv_spool(self.store,self.session['id']):raise BrokenPipeError('fixture consumer disconnected')
        self.assertEqual(len(opened),3)
        self.assertTrue(all(output.closed for output in opened))
        with views.csv_spool(self.store,self.session['id']) as (source,size):self.assertEqual(len(source.read()),size)

    def test_only_two_spools_may_be_live_and_third_does_not_wait(self):
        self.seed()
        with views.csv_spool(self.store,self.session['id']),views.csv_spool(self.store,self.session['id']):
            with self.assertRaisesRegex(views.ExportBusy,'retry'):
                with views.csv_spool(self.store,self.session['id']):self.fail('Third spool should be rejected')
        with views.csv_spool(self.store,self.session['id']):pass

    def test_export_bound_counts_bom_and_rejects_nonmember_filter(self):
        self.seed()
        with views.csv_spool(self.store,self.session['id'],server_id='b') as (source,size):
            raw=source.read();self.assertEqual(size,len(raw))
        rows=list(csv.DictReader(io.StringIO(raw.decode('utf-8-sig'))))
        self.assertEqual(len(rows),4)
        self.assertEqual({row['server_id'] for row in rows},{'b'})
        with views.csv_spool(self.store,self.session['id'],server_id='b',max_bytes=size) as (source,measured):self.assertEqual(measured,size)
        with self.assertRaises(ValueError):
            with views.csv_spool(self.store,self.session['id'],server_id='b',max_bytes=size-1):pass
        with self.assertRaisesRegex(ValueError,'member'):
            with views.csv_spool(self.store,self.session['id'],server_id='unknown'):pass

    def test_compact_projection_retains_custom_ssh_port_and_generated_policy_counts(self):
        self.seed()
        with self.store.meta() as db:
            row=json.loads(db.execute('SELECT data FROM learning_evidence LIMIT 1').fetchone()[0]);row['port']=2022;lp._put_evidence(db,row)
            for index in range(120):
                lp._put_policy(self.store,db,{'id':f'generated-{index:03d}','name':'Learned billing','server_id':'a','session_id':self.session['id'],'status':'pending','services':[{'port':443,'protocol':'tcp','sources':['10.20.0.1/32']}], 'error':'x'*2000})
        result=lp.recommendations(self.store,self.session['id'])
        self.assertFalse(next(row for row in result['rows'] if row['port']==2022)['eligible_for_auto'])
        self.assertEqual((result['generated_policy_total'],len(result['generated_policies'])),(120,100))
        self.assertTrue(all('services' not in policy and len(policy['error'])==512 for policy in result['generated_policies']))

    def test_pending_navigation_is_bounded_and_does_not_load_global_review_matrices(self):
        with self.store.meta() as db:
            for index in range(122):
                plan={'id':f'review-{index:03d}','session_id':self.session['id'] if index<120 else 'another-session','status':'reviewed','created_at':stamp(),'expires_at':stamp(now()+timedelta(minutes=10)),'targets':[{'services':['canonical authority remains detail-only']}],'digest':'f'*64}
                self.store._put(db,'learning_policy_previews',plan)
        original=self.store._all
        def no_global_previews(db,table):
            if table=='learning_policy_previews':raise AssertionError('Evidence navigation must not load global canonical plans')
            return original(db,table)
        with patch.object(self.store,'_all',no_global_previews):result=lp.recommendations(self.store,self.session['id'])
        self.assertEqual((result['pending_approval_total'],len(result['pending_approvals'])),(120,100))
        self.assertTrue(all(plan['summary_only'] and 'targets' not in plan for plan in result['pending_approvals']))
