"""The read-only CSV route sends complete exact bytes or a bounded error."""
import csv
import http.client
import io
import json
from pathlib import Path
import ssl
import tempfile
import unittest
from unittest.mock import patch

from controller.app import App
from controller import evidence_views as views
from controller.pki import init_ca
from controller.store import Store, stamp
from test_integration import running


class LearningExportHTTPS(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='prthak-export-https-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.store=Store(self.root/'state');self.session='export-session'
        at=stamp()
        with self.store.meta() as db:
            self.store._put(db,'sessions',{'id':self.session,'server_ids':['a'],'status':'stopped','policy_action':'observe'})
            self.store._put(db,'servers',{'id':'a','hostname':'=formula()','ips':['10.1.0.1'],'listeners':[],'protection':{}})
            for index in range(4):
                row={'id':f'row-{index}','session_id':self.session,'server_id':'a','source_ip':f'10.20.0.{index+1}','source_cidr':f'10.20.0.{index+1}/32','port':443,'protocol':'tcp','service':'@service','process':'nginx','count':1,'verdicts':['observed'],'first_seen':at,'last_seen':at}
                db.execute('INSERT INTO learning_evidence(id,session_id,server_id,data) VALUES(?,?,?,?)',(row['id'],self.session,'a',json.dumps(row)))
        pki=init_ca(self.root)
        tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls.load_cert_chain(pki/'controller.pem',pki/'controller-key.pem')
        self.tls=ssl.create_default_context(cafile=str(pki/'ca.pem'))
        # Background jobs are unnecessary for this private frozen evidence view.
        app=App(self.store,tokens={'read_only':'fixture-read-only'});app.start_jobs=lambda:None
        manager=running(app,tls);self.port=manager.__enter__();self.addCleanup(manager.__exit__,None,None,None)

    def get(self,path):
        connection=http.client.HTTPSConnection('localhost',self.port,context=self.tls,timeout=10)
        try:
            connection.request('GET','/api/v1/'+path,headers={'Authorization':'Bearer fixture-read-only'})
            response=connection.getresponse();return response.status,response.read(),dict(response.getheaders())
        finally:connection.close()

    def test_read_only_export_complete_exact_bytes_and_member_filter(self):
        with views.csv_spool(self.store,self.session) as (source,size):expected=source.read()
        code,body,headers=self.get(f'learning/{self.session}/export.csv?server_id=a')
        self.assertEqual(code,200,body);self.assertEqual(body,expected);self.assertEqual(int(headers['Content-Length']),size)
        self.assertEqual(headers['Cache-Control'],'no-store')
        data=list(csv.DictReader(io.StringIO(body.decode('utf-8-sig'))));self.assertEqual(len(data),4)
        self.assertTrue(all(row['hostname']=="'=formula()" and row['service']=="'@service" for row in data))
        code,body,_=self.get(f'learning/{self.session}/recommendations?limit=2&offset=2&server_id=a')
        result=json.loads(body);self.assertEqual((code,result['total_rows'],len(result['rows']),result['has_more']),(200,4,2,False))
        self.assertEqual(self.get(f'learning/{self.session}/export.csv?server_id=other')[0],400)

    def test_oversize_is_json_error_before_success_and_busy_is_retryable(self):
        with patch.object(views,'MAX_EXPORT_BYTES',300):
            code,body,headers=self.get(f'learning/{self.session}/export.csv')
        self.assertEqual(code,400,body);self.assertIn('application/json',headers['Content-Type']);self.assertIn('Complete CSV exceeds',json.loads(body)['error'])
        with views.csv_spool(self.store,self.session),views.csv_spool(self.store,self.session):
            code,body,headers=self.get(f'learning/{self.session}/export.csv')
        self.assertEqual(code,503,body);self.assertEqual(headers['Retry-After'],'2')
        self.assertEqual(self.get(f'learning/{self.session}/export.csv')[0],200)
