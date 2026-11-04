"""Isolated real SQLite evidence/authority regressions for typed capture."""
import copy
import hashlib
import json
import os
from pathlib import Path
import unittest
from datetime import timedelta
from unittest.mock import patch

from controller import approvals, hit_monitoring as hm, learning_policies as lp, traffic_capture as capture, traffic_views
from controller.store import Store, now, stamp
from controller.tests import test_hit_monitoring as hm_fixture
from controller.tests import test_learning_policies as lp_fixture
from controller.tests import test_approvals as approval_fixture
from controller.tests import private_pg as pg_fixture


class TrafficCaptureTests(unittest.TestCase):
    def setUp(self):
        self.fixture=lp_fixture.LearningPolicyTests('test_auto_preserves_exact_source_service_pairs_and_normal_policy_authority')
        self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.store=self.fixture.store

    def upgraded(self, **extra):
        return self.fixture.report('a','10.1.0.1',capabilities=['learning_discovery_v1','learning_auto_allow_v1',capture.CAPABILITY],**extra)

    def session(self, auto=False, kinds=None):
        self.upgraded()
        if kinds is None:session=self.fixture.session(auto)
        else:
            session=self.store.create_session({'server_ids':['a'],'selection_mode':'discovered','policy_action':'auto_allow' if auto else 'observe','auto_allow_confirmed':auto,'observation_kinds':kinds},'admin')
            self.fixture.report('a','10.1.0.1',learning_discovery_session_ids=[session['id']])
        self.upgraded()
        return session

    def event(self, kind='accepted_connection', identity='one', source='2001:db8::44', port=80):
        backend,unit,verdict=capture.TYPED[kind];point=stamp()
        return dict(event_id=hashlib.sha256(identity.encode()).hexdigest(),source_ip=source,port=port,protocol='tcp',count=1,verdict=verdict,first_seen=point,last_seen=point,capture_kind=kind,capture_backend=backend,count_unit=unit,address_family='ipv6' if ':' in source else 'ipv4')

    def upload(self, session, events, batch='one', process=True):
        result=self.store.enqueue_flows('a',{'batch_id':batch,'session_id':session['id'],'events':events})
        if process:self.store.process_flows()
        return result

    def test_units_and_legacy_claims_stay_separate_in_flows_recommendations_and_csv(self):
        session=self.session()
        events=[self.event(),self.event('denied_packet','two')]
        legacy={key:value for key,value in self.event(identity='old').items() if key not in (*capture.FIELDS,'event_id')}
        legacy['count']=7  # An old allowed string is not conntrack evidence.
        self.upload(session,events)
        # Deliberate pre-0.9 retained fixture: an omitted-kind historical scope,
        # not a new API request that silently downgrades typed capture.
        historical={**self.store.get('sessions',session['id']),'id':session['id']+'-historic','status':'stopped','stopped_at':stamp()}
        historical.pop('observation_kinds')
        with self.store.meta() as db:self.store._put(db,'sessions',historical)
        self.upload(historical,[legacy],batch='legacy')
        rows=self.store.flows()
        self.assertEqual({(r['capture_kind'],r['count_unit'],r['count']) for r in rows},{('accepted_connection','connections',1),('denied_packet','packets',1),('legacy_log','log_records',7)})
        stats=self.store.overview()['stats']
        self.assertEqual(stats['capture_counts'],{'connections':1,'packets':1,'log_records':7,'sample_minutes':0})
        self.assertEqual((stats['observed_events'],stats['observed_events_unit']),(7,'legacy_log_records'))
        recommendations=lp.recommendations(self.store,session['id'])
        self.assertEqual(recommendations['total_rows'],2)
        self.assertEqual({r['count_unit'] for r in recommendations['rows']},{'connections','packets'})
        exported=lp.export_csv(self.store,session['id'])
        self.assertIn('count_unit,capture_kind,capture_backend,address_family',exported)
        self.assertIn('legacy_log,journal,ipv6',lp.export_csv(self.store,historical['id']))

    def test_typed_event_replay_across_batches_and_restart_is_counted_once(self):
        session=self.session();event=self.event()
        self.upload(session,[event],process=False)
        self.assertEqual(self.store.flows(),[],'Queued evidence must not appear processed before the worker')
        duplicate=self.upload(session,[event],batch='retry-other-batch',process=False)
        self.assertEqual(duplicate['duplicate_events'],1)
        self.store=Store(self.fixture.temp.name);self.fixture.store=self.store
        self.store.process_flows()
        self.assertEqual([r['count'] for r in self.store.flows()],[1])
        self.assertEqual([r['count'] for r in lp.recommendations(self.store,session['id'])['rows']],[1])
        with self.store.traffic() as db:db.execute('UPDATE batches SET evidence_processed=0')
        self.store.process_flows()
        self.assertEqual(lp.recommendations(self.store,session['id'])['rows'][0]['count'],1)

    def test_event_identity_conflict_rolls_back_batch_and_reserved_rows(self):
        session=self.session();original=self.event()
        self.upload(session,[original])
        changed={**original,'source_ip':'2001:db8::45'}
        with self.assertRaises(ValueError):self.upload(session,[self.event(identity='new'),changed],batch='conflict')
        with self.store.read_traffic() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM batches').fetchone()[0],1)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM flows').fetchone()[0],1)

    def test_long_session_replay_after_raw_pruning_uses_redacted_nonpublishing_tombstone(self):
        session=self.store.create_session({'server_ids':['a'],'selection_mode':'manual','ports':[{'port':80,'protocol':'tcp'}],'duration_seconds':604800},'admin')
        self.upgraded();event=self.event();self.upload(session,[event])
        later=now()+timedelta(days=2)
        with patch('controller.store.now',return_value=later):
            self.store.prune()
            with self.store.read_traffic() as db:
                row=db.execute('SELECT source_ip,count,capture_processed FROM flows WHERE event_id=?',(event['event_id'],)).fetchone()
                self.assertEqual(tuple(row[index] for index in range(3)),('',0,2))
            self.assertEqual(self.upload(session,[event],batch='after-prune')['duplicate_events'],1)
            # Even reuse of the original pruned batch ID cannot resurrect data.
            self.assertEqual(self.upload(session,[event],batch='one')['duplicate_events'],1)
        self.assertEqual(self.store.flows(),[])
        self.assertEqual(lp.recommendations(self.store,session['id'])['rows'][0]['count'],1)

    def test_typed_wrong_family_backend_unit_count_capability_and_scope_are_refused(self):
        session=self.session(kinds=['accepted_connection']);base=self.event()
        for change in ({'address_family':'ipv4'},{'capture_backend':'journal'},{'count_unit':'packets'},{'count':2},{'verdict':'observed'},{'event_id':'x'},{'source_ip':'::ffff:192.0.2.1'},{'source_ip':'fe80::1%eth0'}):
            with self.subTest(change=change),self.assertRaises(ValueError):self.upload(session,[{**base,**change}])
        with self.assertRaises(ValueError):self.upload(session,[self.event('denied_packet')])
        with self.assertRaises(ValueError):self.upload(session,[{k:v for k,v in base.items() if k!='count_unit'}])
        self.fixture.report('a','10.1.0.1',capabilities=['learning_discovery_v1','learning_auto_allow_v1'])
        with self.assertRaises(ValueError):self.upload(session,[base])
        self.assertEqual(self.store.flows(),[])

    def test_new_scope_refuses_metadata_free_downgrade_before_any_queue_or_auto_grant(self):
        session=self.session(auto=True,kinds=['accepted_connection'])
        legacy={key:value for key,value in self.event().items() if key not in (*capture.FIELDS,'event_id')}
        with self.assertRaises(ValueError):self.upload(session,[legacy])
        with self.store.read_traffic() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM batches').fetchone()[0],0)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM flows').fetchone()[0],0)
        self.assertEqual(lp.listing(self.store),[])
        self.assertEqual(lp.recommendations(self.store,session['id'])['rows'],[])

    def test_explicit_any_hit_auto_allow_keeps_denied_first_hits_exact_and_protected(self):
        session=self.session(auto=True)
        self.assertEqual(session['observation_kinds'],list(capture.KINDS))
        self.upload(session,[self.event('denied_packet','blocked-first','2001:db8::55'),self.event('accepted_connection','accepted','10.40.0.9',5432),self.event('denied_packet','ssh','10.40.0.8',2022)])
        assigned=self.fixture.assignment()
        self.assertEqual(assigned['services'],[{'port':80,'protocol':'tcp','sources':['2001:db8::55/128']},{'port':5432,'protocol':'tcp','sources':['10.40.0.9/32']}])
        self.assertTrue(assigned['authorized'])
        self.assertEqual(assigned['authorities'][0]['observation_kinds'],list(capture.KINDS))
        self.assertFalse(self.store.assignment('a')[0]['enforcement']['authorized'])

    def test_capture_support_and_unknown_losses_are_preserved_not_filled_with_zero(self):
        session=self.session()
        facts={'capture_backends':[{'backend':'conntrack','status':'active','ipv4':True,'ipv6':True,'lost_events':None},{'backend':'nflog','status':'unsupported','ipv4':False,'ipv6':False,'lost_events':None,'error':'terminal path unavailable'}],'capture_gaps':['netlink queue overflow; loss unknown']}
        self.upgraded(learning_coverage={'session_id':session['id'],**facts})
        coverage=self.store.get('servers','a')['learning_coverage']
        self.assertIsNone(coverage['capture_backends'][0]['lost_events'])
        self.assertEqual(coverage['capture_gaps'],facts['capture_gaps'])
        with self.assertRaises(ValueError):self.upgraded(learning_coverage={'session_id':session['id'],'capture_backends':[{'backend':'conntrack','status':'active','ipv4':True,'ipv6':True,'lost_events':-1}]})

    def test_ipv6_discovery_tag_group_sources_and_exact_recommendation_preview(self):
        self.fixture.report('a','2001:db8:10::1',listeners=[{'port':80,'protocol':'tcp','address':'::','service':'HTTP'}])
        self.fixture.report('b','2001:db8:10::2')
        self.store.update_server('a',{'tag_updates':{'role':'client'}},'admin')
        self.store.update_server('b',{'tag_updates':{'application':'billing'}},'admin')
        group=self.store.save_group({'name':'Billing v6','type':'dynamic','selector':{'application':'billing'},'server_ids':[]},'admin')
        self.store.save_policy({'name':'IPv6 clients','selector':{'application':'billing'},'mode':'enforce','services':[{'port':80,'protocol':'tcp','sources':[],'source_selector':{'role':'client'}}]},'admin')
        self.assertEqual(self.store.assignment('b')[0]['services'][0]['sources'],['2001:db8:10::1/128'])
        session=self.store.create_session({'server_ids':['a'],'selection_mode':'discovered'},'admin')
        self.fixture.report('a','2001:db8:10::1',listeners=[{'port':80,'protocol':'tcp','address':'::','service':'HTTP'}],learning_discovery_session_ids=[session['id']],capabilities=['learning_discovery_v1','learning_auto_allow_v1',capture.CAPABILITY])
        self.upload(session,[self.event(source='2001:db8:20::99')])
        row=lp.recommendations(self.store,session['id'])['rows'][0]
        plan=lp.preview(self.store,session['id'],{'row_ids':[row['id']],'group_ids':[group['id']],'expected_evidence_revision':self.store.get('sessions',session['id'])['evidence_revision']},'admin')
        self.assertEqual(plan['target_server_ids'],['b'])
        self.assertEqual(plan['services'],[{'port':80,'protocol':'tcp','sources':['2001:db8:20::99/128']}])


class HitTypedCaptureTests(unittest.TestCase):
    def setUp(self):
        self.fixture=hm_fixture.HitMonitorTests('test_ipv6_queue_identity_dedup_exact_scope_and_no_learning')
        self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.store=self.fixture.store
        self.fixture.report('one',capabilities=['signed_assignments_v1',hm.CAPABILITY,capture.CAPABILITY])

    def test_monitor_preserves_each_unit_ipv6_receipts_export_and_no_policy(self):
        monitor=self.fixture.make();body=self.fixture.batch(monitor)
        point=body['events'][0]['first_seen'];base=body['events'][0]
        body['events']=[]
        for index,(kind,(backend,unit,verdict)) in enumerate(capture.TYPED.items()):
            body['events'].append({**base,'event_id':str(index+1)*64,'capture_kind':kind,'capture_backend':backend,'count_unit':unit,'verdict':verdict,'address_family':'ipv6'})
        hm.enqueue(self.store,'one',body);self.store.process_flows()
        rows=hm.hits(self.store,monitor['id'])['items']
        self.assertEqual({(r['count_unit'],r['count']) for r in rows},{('connections',1),('packets',1)})
        with hm.csv_spool(self.store,monitor['id']) as (source,size):
            csv=source.read().decode('utf-8-sig');self.assertIn('denied_packet,nflog,ipv6',csv);self.assertIn('accepted_connection,conntrack,ipv6',csv)
        receipt={'id':monitor['id'],'status':'observing','checked_at':point,'capture_backends':[{'backend':'nflog','status':'active','ipv4':True,'ipv6':True,'lost_events':None}],'capture_gaps':['loss unknown']}
        with self.store.meta() as db:
            server=self.store._get(db,'servers','one');hm.report_status(self.store,db,server,{'hit_monitoring':[receipt]})
        self.assertIsNone(hm.target_page(self.store,monitor['id'])['items'][0]['last_outcome']['capture_backends'][0]['lost_events'])
        self.assertEqual(lp.listing(self.store),[])
        self.assertEqual(self.store.all('sessions'),[])

    def test_monitor_review_freezes_selected_kind_and_legacy_batch_retry_bytes(self):
        plan=hm.preview(self.store,{'name':'Accepted only','selection':{'server_ids':['one']},'ports':[{'port':443,'protocol':'tcp'}],'retention_hours':1,'observation_kinds':['accepted_connection']},'maker')
        monitor=hm.apply(self.store,self.fixture.confirm(plan),'maker')
        self.assertEqual(self.fixture.lease(monitor)['observation_kinds'],['accepted_connection'])
        body=self.fixture.batch(monitor);event=body['events'][0]
        body['events'][0]={**event,'capture_kind':'denied_packet','capture_backend':'nflog','count_unit':'packets','address_family':'ipv6','verdict':'denied'}
        with self.assertRaises(ValueError):hm.enqueue(self.store,'one',body)
        for address in ('::ffff:192.0.2.1','fe80::1%eth0'):
            bad=copy.deepcopy(body);bad['events'][0].update(source_ip=address,capture_kind='accepted_connection',capture_backend='conntrack',count_unit='connections',verdict='allowed')
            with self.subTest(address=address),self.assertRaises(ValueError):hm.enqueue(self.store,'one',bad)
        legacy=self.fixture.batch(monitor,identity='legacy')
        for event in legacy['events']:
            for key in capture.FIELDS:event.pop(key,None)
            event['verdict']='observed'
        with self.assertRaises(ValueError):hm.enqueue(self.store,'one',legacy)
        with self.store.read_traffic() as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM hit_batches').fetchone()[0],0)
        # Explicit retained pre-0.9 monitor record; preserve its old canonical
        # journal retry bytes rather than creating a new implicit legacy scope.
        with self.store.meta() as db:
            historic=self.store._get(db,'hit_monitors',monitor['id']);historic.pop('observation_kinds');self.store._put(db,'hit_monitors',historic)
        hm.enqueue(self.store,'one',legacy)
        self.assertTrue(hm.enqueue(self.store,'one',copy.deepcopy(legacy))['duplicate'])


class CaptureScopeAuthorityTests(unittest.TestCase):
    def test_current_single_admin_scope_binds_capture_kinds_without_invalidating_history(self):
        fixture=approval_fixture.IndependentApprovalTests('test_start_learning_enables_frozen_port_auto_allow_without_more_approval')
        fixture.setUp();self.addCleanup(fixture.doCleanups)
        session=fixture.learned_session(auto=True);fixture.discover_and_hit(session)
        with fixture.store.meta() as db:
            stored=fixture.store._get(db,'sessions',session['id']);server=fixture.store._get(db,'servers','target')
            self.assertEqual(stored['initial_approval_scope']['observation_kinds'],list(capture.KINDS))
            self.assertTrue(approvals.learning_authorized(fixture.store,db,stored,server))
            stored['observation_kinds']=['accepted_connection']
            self.assertFalse(approvals.learning_authorized(fixture.store,db,stored,server),'Changing capture authority cannot reuse the original exact Admin scope')
            fixture.store._put(db,'sessions',stored)
        held=fixture.store.assignment('target')[0]['learning_allow']
        self.assertFalse(held['authorized'])
        self.assertEqual(held['services'],[{'port':443,'protocol':'tcp','sources':['10.50.0.1/32']}])

    def test_demo_new_capture_scope_is_explicitly_synthetic_and_has_no_kernel_provenance(self):
        import tempfile
        from controller import learning, seed
        with tempfile.TemporaryDirectory() as directory:
            store=Store(directory);seed.seed(store)
            legacy_before=store.flows()
            session=store.create_session({'server_ids':['srv-dev-01'],'selection_mode':'discovered'},'demo')
            self.assertTrue(session['synthetic'])
            seed.tick_synthetic_hosts(store)
            server=store.get('servers','srv-dev-01')
            self.assertIn('synthetic',server['agent_version'])
            self.assertEqual(server['capabilities'], ['learning_discovery_v1', 'traffic_capture_v1', learning.TRAFFIC_SAMPLING_CAPABILITY])
            self.assertTrue(all(row['status']=='unsupported' and row['lost_events'] is None for row in server['learning_coverage']['capture_backends']))
            self.assertTrue(server['learning_coverage']['capture_gaps'])
            self.assertTrue(all(row['capture_kind']=='legacy_log' for row in legacy_before))
            self.assertFalse(store.assignment('srv-dev-01')[0]['enforcement']['authorized'])
            self.assertEqual(lp.listing(store),[])


@unittest.skipUnless(os.environ.get('PRTHAK_PLATFORM_PG_ACCEPTANCE')=='1','Opt in to isolated PostgreSQL capture acceptance')
class TrafficCapturePostgresTests(unittest.TestCase):
    """Fresh UUID databases only; the prepared admin role is never altered."""
    upgraded=TrafficCaptureTests.upgraded
    session=TrafficCaptureTests.session
    event=TrafficCaptureTests.event
    upload=TrafficCaptureTests.upload
    test_units_and_legacy_claims_stay_separate_in_flows_recommendations_and_csv=TrafficCaptureTests.test_units_and_legacy_claims_stay_separate_in_flows_recommendations_and_csv
    test_event_identity_conflict_rolls_back_batch_and_reserved_rows=TrafficCaptureTests.test_event_identity_conflict_rolls_back_batch_and_reserved_rows
    test_typed_wrong_family_backend_unit_count_capability_and_scope_are_refused=TrafficCaptureTests.test_typed_wrong_family_backend_unit_count_capability_and_scope_are_refused
    test_explicit_any_hit_auto_allow_keeps_denied_first_hits_exact_and_protected=TrafficCaptureTests.test_explicit_any_hit_auto_allow_keeps_denied_first_hits_exact_and_protected
    test_ipv6_discovery_tag_group_sources_and_exact_recommendation_preview=TrafficCaptureTests.test_ipv6_discovery_tag_group_sources_and_exact_recommendation_preview
    test_long_session_replay_after_raw_pruning_uses_redacted_nonpublishing_tombstone=TrafficCaptureTests.test_long_session_replay_after_raw_pruning_uses_redacted_nonpublishing_tombstone

    def setUp(self):
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import make_conninfo
        from controller.postgres import PostgresStore
        self.driver,self.sql=psycopg,sql
        self.parameters=pg_fixture.parameters();self.databases=pg_fixture.names('capture')
        self.created=[];self.addCleanup(self._drop)
        with psycopg.connect(**self.parameters,dbname='postgres',autocommit=True) as db:
            user,directory=db.execute("SELECT current_user,current_setting('data_directory')").fetchone()
            if user!='prthak_test' or Path(directory).resolve()!=pg_fixture.data_directory():raise RuntimeError('Refusing nonfixture PostgreSQL')
            for database in self.databases.values():
                if db.execute('SELECT 1 FROM pg_database WHERE datname=%s',(database,)).fetchone():raise RuntimeError('Fixture name already exists')
                db.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(database)));self.created.append(database)
        self.fixture=lp_fixture.LearningPolicyTests('test_auto_preserves_exact_source_service_pairs_and_normal_policy_authority')
        self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.store=PostgresStore(*(make_conninfo(**self.parameters,dbname=self.databases[name]) for name in ('metadata','traffic')))
        self.store.lab_approvals=True;self.fixture.store=self.store
        self.fixture.report('a','10.1.0.1');self.fixture.report('b','10.1.0.2')

    def _drop(self):
        if not self.created:return
        with self.driver.connect(**self.parameters,dbname='postgres',autocommit=True) as db:
            for database in self.created:
                db.execute('SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=%s AND pid<>pg_backend_pid()',(database,))
                db.execute(self.sql.SQL('DROP DATABASE {}').format(self.sql.Identifier(database)))

    def test_additive_postgres_migration_labels_existing_rows_and_preserves_new_replay_receipts(self):
        with self.store.traffic() as db:
            for table,columns in (('flows',capture.FLOW_COLUMNS),('hit_events',capture.HIT_COLUMNS)):
                for column,_ in columns:db.execute('ALTER TABLE '+table+' DROP COLUMN '+column+' CASCADE')
            point=stamp()
            db.execute('INSERT INTO flows(batch_key,event_index,server_id,session_id,source_ip,port,protocol,verdict,count,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?,?,?,?)',('old',0,'a','old-session','2001:db8::8',80,'tcp','allowed',9,point,point))
        self.store.initialize_schema()
        historical=self.store.flows()[0]
        self.assertEqual((historical['capture_kind'],historical['count_unit'],historical['count']),('legacy_log','log_records',9))
        session=self.session();event=self.event()
        self.upload(session,[event],process=False)
        self.assertEqual(self.upload(session,[event],batch='replayed',process=False)['duplicate_events'],1)
        self.store.process_flows()
        self.assertEqual(lp.recommendations(self.store,session['id'])['rows'][0]['count'],1)
        self.assertEqual({row['count_unit'] for row in self.store.flows()},{'connections','log_records'})

    def test_observe_only_peak_and_scoped_evidence_prune_in_postgres(self):
        from controller import learning
        self.fixture.report('a','10.1.0.1',capabilities=['learning_discovery_v1', capture.CAPABILITY, learning.TRAFFIC_DISCOVERY_CAPABILITY])
        session = self.store.create_session({'purpose':'traffic','traffic_collection_mode':'hits','server_ids':['a'],'selection_mode':'manual',
            'ports':[{'port':80}],'duration_seconds':2592000}, 'admin')
        first = self.event(identity='peak-one')
        second = {**self.event(identity='peak-two'), 'first_seen':first['first_seen'], 'last_seen':first['last_seen']}
        self.upload(session, [first], batch='peak-one')
        self.upload(session, [first, second], batch='peak-two')
        row = lp.recommendations(self.store, session['id'])['rows'][0]
        self.assertEqual((row['count'], row['peak_observed_per_second']), (2, 2))
        self.store.stop_session(session['id'], 'admin')
        with patch('controller.store.now', return_value=now()+timedelta(days=31)):
            self.store.prune()
            self.assertTrue(lp.recommendations(self.store, session['id'])['evidence_expired'])
        with self.store.read_meta() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM learning_evidence').fetchone()[0], 0)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM learning_evidence_receipts').fetchone()[0], 0)

    def test_sampled_discovery_deduplicates_mixed_evidence_and_reports_separate_units(self):
        from controller import learning
        self.fixture.report('a', '10.1.0.1', capabilities=['learning_discovery_v1', capture.CAPABILITY, learning.TRAFFIC_SAMPLING_CAPABILITY])
        session = self.store.create_session({'purpose': 'traffic', 'server_ids': ['a'], 'selection_mode': 'manual',
            'ports': [{'port': 80}]}, 'admin')
        first = self.event(identity='sample-first')
        duplicate = {**self.event('denied_packet', 'denied'), 'first_seen': first['first_seen'], 'last_seen': first['last_seen']}
        self.assertEqual(self.upload(session, [first, duplicate], batch='sample-first')['duplicate_events'], 1)
        self.assertEqual(self.upload(session, [duplicate], batch='sample-replayed')['duplicate_events'], 1)
        row = lp.recommendations(self.store, session['id'])['rows'][0]
        self.assertEqual((row['count_unit'], row['count']), (capture.SAMPLE_UNIT, 1))
        self.assertNotIn('peak_observed_per_second', row)
        self.assertEqual(traffic_views.listing(self.store)['counts_by_unit'],
            {'connections': 0, 'packets': 0, 'log_records': 0, capture.SAMPLE_UNIT: 1})

    def test_hit_monitor_typed_ipv6_units_cross_batch_dedup_and_csv_do_not_create_learning(self):
        self.fixture.report('a','10.1.0.1',capabilities=['signed_assignments_v1',hm.CAPABILITY,capture.CAPABILITY])
        plan=hm.preview(self.store,{'name':'PG IPv6 capture','selection':{'server_ids':['a']},'ports':[{'port':80,'protocol':'tcp'}],'retention_hours':1},'admin')
        monitor=hm.apply(self.store,{'preview_id':plan['id'],**{key:plan[key] for key in ('digest','confirmation_nonce','confirmation_phrase')}},'admin')
        with self.store.read_meta() as db:lease=hm.assignments(self.store,db,self.store._get(db,'servers','a'))[0]
        body={'batch_id':'pg-hit','monitor_id':monitor['id'],'lease_starts_at':lease['starts_at'],'lease_expires_at':lease['expires_at'],'events':[self.event(),self.event('denied_packet','denied')]}
        self.assertEqual(hm.enqueue(self.store,'a',body)['accepted'],2)
        self.assertEqual(hm.enqueue(self.store,'a',{**body,'batch_id':'pg-hit-retry'})['accepted'],0)
        self.store.process_flows()
        rows=hm.hits(self.store,monitor['id'])['items']
        self.assertEqual({(row['count_unit'],row['count'],row['address_family']) for row in rows},{('connections',1,'ipv6'),('packets',1,'ipv6')})
        with hm.csv_spool(self.store,monitor['id']) as (source,size):
            self.assertIn('denied_packet,nflog,ipv6',source.read().decode('utf-8-sig'))
        self.assertEqual(self.store.all('sessions'),[])
        self.assertEqual(lp.listing(self.store),[])


if __name__=='__main__':unittest.main()
