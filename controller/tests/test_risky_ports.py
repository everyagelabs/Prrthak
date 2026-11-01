import copy
import json
import tempfile
import threading
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request
from datetime import timedelta
from http.server import ThreadingHTTPServer
from controller import risky_ports as risk
from controller.app import App,handler_for
from controller.store import Store,now,stamp


class RiskyPortTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.store=Store(self.temp.name)
 def report(self,listeners):
  self.store.report('host',{'hostname':'billing-host','ips':['10.0.0.1'],'listeners':listeners,'firewalld_state':'running'})
  self.store.evaluate_health()
 def test_exact_protocol_range_bindings_and_reasons(self):
  self.report([{'port':23,'protocol':'tcp','address':'0.0.0.0','service':'Telnet'}, {'port':5905,'protocol':'tcp','address':'::','service':'VNC'}, {'port':514,'protocol':'udp','address':'10.0.0.1'}, {'port':6379,'protocol':'tcp','address':'::ffff:127.0.0.1'}])
  server=self.store.server('host');rows=server['risky_ports']
  self.assertEqual({r['port'] for r in rows},{23,5905,6379});self.assertEqual(next(r for r in rows if r['port']==6379)['exposure'],'loopback')
  for row in rows:self.assertTrue(row['reason']);self.assertTrue(row['recommendation']);self.assertTrue(row['source_ids'])
  alerts=[a for a in self.store.all('alerts') if a['kind']=='risky_port_in_use'];self.assertEqual(len(alerts),2)
  self.assertTrue(all(a['details']['reason'] for a in alerts))
 def test_secure_service_port_is_not_automatically_called_vulnerable(self):
  self.report([{'port':443,'protocol':'tcp','address':'0.0.0.0'}, {'port':8443,'protocol':'tcp','address':'0.0.0.0'}])
  self.assertEqual(self.store.server('host')['risky_ports'],[])
 def test_stale_scan_keeps_last_evidence_without_new_alerts_or_false_resolution(self):
  self.report([{'port':23,'protocol':'tcp','address':'10.0.0.1'}])
  alert=next(a for a in self.store.all('alerts') if a['kind']=='risky_port_in_use')
  with self.store.meta() as db:
   server=self.store._get(db,'servers','host');server['last_seen']=stamp(now()-timedelta(hours=1));self.store._put(db,'servers',server)
  self.store.evaluate_health();self.assertEqual(self.store.get('alerts',alert['id'])['status'],'open')
  self.assertEqual(len(self.store.server('host')['risky_ports']),1)
 def test_listener_absence_and_catalog_withdrawal_resolve_without_recovery_claim(self):
  self.report([{'port':23,'protocol':'tcp','address':'10.0.0.1'}]);self.report([])
  alerts=[a for a in self.store.all('alerts') if a['kind']=='risky_port_in_use'];self.assertEqual(alerts[0]['status'],'resolved')
  self.assertEqual(alerts[0]['resolution_reason'],'listener_or_catalog_changed')
 def test_catalog_cas_custom_rule_and_changed_reasons_are_central(self):
  self.report([{'port':8443,'protocol':'tcp','address':'10.0.0.1'}])
  rule=risk._rule('private-api','Private API',8443,'tcp','medium','Organization-defined management API.','Limit administration clients.')
  saved=risk.save(self.store,{'expected_revision':0,'rules':[rule]},'admin')
  self.assertEqual(saved['revision'],1);self.assertEqual(self.store.server('host')['risky_ports'][0]['reason'],rule['reason'])
  with self.assertRaises(ValueError):risk.save(self.store,{'expected_revision':0,'rules':[]},'admin')
  rule['reason']='Changed review reason.';rule['severity']='high'
  risk.save(self.store,{'expected_revision':1,'rules':[rule]},'admin')
  alert=next(a for a in self.store.all('alerts') if a['kind']=='risky_port_in_use' and a['status']=='open')
  self.assertEqual((alert['severity'],alert['details']['reason']),('high','Changed review reason.'))
 def test_validation_and_bounded_results(self):
  catalog=risk.public_catalog(self.store);rule=catalog['rules'][0]
  for patch in ({'port_start':True},{'port_end':0},{'source_ids':['invented']},{'reason':''},{'protocol':'sctp'},{'enabled':'true'}):
   with self.assertRaises(ValueError):risk.validate_rules([{**rule,**patch}])
  many=[{'port':5900+i%10,'protocol':'tcp','address':'10.0.'+str(i//250)+'.'+str(i%250+1)} for i in range(300)]
  self.report(many);server=self.store.server('host');self.assertTrue(server['risk_summary']['truncated']);self.assertEqual(len(server['risky_ports']),256)
  result=risk.findings(self.store,{'limit':'10','offset':'10','severity':'high'});self.assertEqual(len(result['items']),10)
 def test_regulatory_mapping_does_not_pretend_24h_traffic_meets_180days(self):
  rows=risk.regulatory(self.store)['controls'];logs=next(r for r in rows if r['id']=='CERT-IV')
  self.assertIn('180',logs['requirement']);self.assertEqual(logs['status'],'operator_evidence_required');self.assertIn('shorter',logs['support'])
  self.assertTrue(all(row['source_id'] in risk.SOURCES for row in rows));self.assertFalse(any(row['status']=='compliant' for row in rows))
 def test_fleet_projection_keeps_counts_without_repeating_full_rationales(self):
  self.report([{'port':23,'protocol':'tcp','address':'10.0.0.1'}])
  brief=self.store.servers()[0]
  self.assertNotIn('risky_ports',brief);self.assertEqual(brief['risk_summary']['total'],1)
  self.assertEqual(self.store.server('host')['risky_ports'][0]['port'],23)
  self.assertEqual(risk.findings(self.store,{})['items'][0]['port'],23)
  self.assertNotIn('_risk_matches',brief)
 def test_cached_finding_query_never_reclassifies_fleet_and_filters_beyond_display_cap(self):
  low=risk._rule('wide','Custom review',1000,'tcp','low','Review this service.','Verify approved clients.',end=1400)
  high=risk._rule('high','Sensitive review',23,'tcp','high','Sensitive remote login.','Use approved encrypted access.')
  risk.save(self.store,{'expected_revision':0,'rules':[low,high]},'admin')
  self.report([{'port':port,'protocol':'tcp','address':'10.0.0.1'} for port in range(1000,1300)]+[{'port':23,'protocol':'tcp','address':'10.0.0.1'}])
  with patch.object(risk,'_matches',side_effect=AssertionError('Read path reclassified inventory')):
   last=risk.findings(self.store,{'port':'1299'});self.assertEqual((last['total'],last['items'][0]['port']),(1,1299))
   highs=risk.findings(self.store,{'severity':'high'});self.assertEqual(highs['total'],1)
  self.assertEqual(self.store.server('host')['risk_summary']['total'],301)
 def test_unknown_catalog_change_cannot_orphan_old_open_alert(self):
  self.report([{'port':23,'protocol':'tcp','address':'10.0.0.1'}])
  with self.store.meta() as db:
   host=self.store._get(db,'servers','host');host['last_seen']=stamp(now()-timedelta(hours=1));self.store._put(db,'servers',host)
  self.store.evaluate_health();risk.save(self.store,{'expected_revision':0,'rules':[]},'admin')
  self.assertTrue(any(a['kind']=='risky_port_in_use' and a['status']=='open' for a in self.store.all('alerts')))
  self.report([{'port':23,'protocol':'tcp','address':'10.0.0.1'}])
  self.assertFalse(any(a['kind']=='risky_port_in_use' and a['status']=='open' for a in self.store.all('alerts')))
 def test_http_readonly_cannot_change_catalog_admin_can_and_references_are_not_fetched(self):
  app=App(self.store,tokens={'read_only':'read-token','admin':'admin-token'})
  server=ThreadingHTTPServer(('127.0.0.1',0),handler_for(app));thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
  self.addCleanup(server.server_close);self.addCleanup(server.shutdown)
  url='http://127.0.0.1:'+str(server.server_port)+'/api/v1/risk/catalog'
  payload=json.dumps({'expected_revision':0,'rules':[]}).encode()
  with self.assertRaises(urllib.error.HTTPError) as error:urllib.request.urlopen(urllib.request.Request(url,payload,{'Authorization':'Bearer read-token','Content-Type':'application/json'},method='PUT'))
  self.assertEqual(error.exception.code,403)
  with urllib.request.urlopen(urllib.request.Request(url,payload,{'Authorization':'Bearer admin-token','Content-Type':'application/json'},method='PUT')) as response:self.assertEqual(json.load(response)['revision'],1)
  with urllib.request.urlopen(urllib.request.Request(url,headers={'Authorization':'Bearer read-token'})) as response:self.assertIn('sources',json.load(response))
