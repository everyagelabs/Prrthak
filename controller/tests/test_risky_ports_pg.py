"""Actual private PostgreSQL projection/cache/lifecycle acceptance."""
import json
import os
import unittest
from datetime import timedelta
from unittest.mock import patch
from controller import risky_ports as risk
from controller.store import now,stamp

@unittest.skipUnless(os.environ.get('PRTHAK_PLATFORM_PG_ACCEPTANCE')=='1','Private PostgreSQL opt-in required')
class RiskPostgresTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  import psycopg
  from psycopg import sql
  from psycopg.conninfo import make_conninfo
  from controller.postgres import PostgresStore
  from controller.tests import private_pg
  parameters,expected=private_pg.configuration();cls.psycopg=psycopg;cls.sql=sql
  cls.admin=make_conninfo(**parameters,dbname='postgres');cls.names=private_pg.names('risk');cls.created=[]
  try:
   with psycopg.connect(cls.admin,autocommit=True) as db:
    from pathlib import Path
    if Path(db.execute('SHOW data_directory').fetchone()[0]).resolve()!=expected:raise RuntimeError('Wrong private PostgreSQL fixture')
    for name in cls.names.values():db.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(name)));cls.created.append(name)
   cls.store=PostgresStore(*(make_conninfo(**parameters,dbname=cls.names[key]) for key in ('metadata','traffic')))
  except BaseException:cls.tearDownClass();raise
 @classmethod
 def tearDownClass(cls):
  with cls.psycopg.connect(cls.admin,autocommit=True) as db:
   for name in cls.created:db.execute(cls.sql.SQL('DROP DATABASE {} WITH (FORCE)').format(cls.sql.Identifier(name)))
 def test_cache_projection_excludes_large_evidence_before_json_decode(self):
  self.store.report('risk-projection',{'hostname':'risk-projection','ips':['192.0.2.1'],'listeners':[{'port':23,'protocol':'tcp','address':'0.0.0.0'}],'firewalld_state':'running'})
  self.store.evaluate_health()
  sentinel='PRIVATE_LARGE_RISK_SNAPSHOT'
  with self.store.meta() as db:
   server=self.store._get(db,'servers','risk-projection');server['firewall_snapshot']={'rules':[{'value':sentinel+'x'*2000000}]};self.store._put(db,'servers',server)
  real=json.loads
  def decode(value,*args,**kwargs):
   self.assertNotIn(sentinel,value);return real(value,*args,**kwargs)
  with patch.object(risk.json,'loads',side_effect=decode),patch.object(risk,'_matches',side_effect=AssertionError('Read path reclassified fleet')):
   result=risk.findings(self.store,{'server_id':'risk-projection','port':'23'})
  self.assertEqual((result['total'],result['items'][0]['port']),(1,23))
 def test_pg_stale_catalog_change_then_fresh_scan_resolves_durable_alert(self):
  catalog=risk.public_catalog(self.store);risk.save(self.store,{'expected_revision':catalog['revision'],'rules':risk.DEFAULT_RULES},'fixture-admin')
  body={'hostname':'risk-life','ips':['192.0.2.2'],'listeners':[{'port':23,'protocol':'tcp','address':'0.0.0.0'}],'firewalld_state':'running'}
  self.store.report('risk-life',body);self.store.evaluate_health()
  with self.store.meta() as db:
   server=self.store._get(db,'servers','risk-life');server['last_seen']=stamp(now()-timedelta(hours=1));self.store._put(db,'servers',server)
  self.store.evaluate_health();catalog=risk.public_catalog(self.store)
  risk.save(self.store,{'expected_revision':catalog['revision'],'rules':[]},'fixture-admin')
  self.store.report('risk-life',body);self.store.evaluate_health()
  self.assertFalse(any(a['kind']=='risky_port_in_use' and a['server_id']=='risk-life' and a['status']=='open' for a in self.store.all('alerts')))
