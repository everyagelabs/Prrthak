"""Real PostgreSQL acceptance tests; never connect to ordinary deployment databases.

Set SEG_TEST_DATABASE_URL and SEG_TEST_TRAFFIC_DATABASE_URL to isolated databases
whose names start with prthak_test_. This suite truncates only those test tables.
"""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import timedelta
import multiprocessing
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
import time
import unittest

from controller.app import App
from controller.pki import Signer, init_ca
from controller.postgres import PostgresStore
from controller.store import now, stamp
from test_integration import request, running


METADATA = os.environ.get('SEG_TEST_DATABASE_URL')
TRAFFIC = os.environ.get('SEG_TEST_TRAFFIC_DATABASE_URL')


def hold_job_until_terminated(metadata, traffic, signal):
    store = PostgresStore(metadata, traffic, initialize=False)
    def callback():
        signal.put('held')
        time.sleep(30)
    store.run_job('health', callback)


@unittest.skipUnless(METADATA and TRAFFIC, 'Set both SEG_TEST_* database URLs for real HA acceptance tests')
class HAIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import psycopg
        cls.driver = psycopg
        for dsn in (METADATA, TRAFFIC):
            with psycopg.connect(dsn) as connection:
                database = connection.execute('SELECT current_database()').fetchone()[0]
                if not database.startswith('prthak_test_'):
                    raise RuntimeError('HA integration tests require prthak_test_ database names')
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.pki = init_ca(cls.temp.name)

    def setUp(self):
        self.a = PostgresStore(METADATA, TRAFFIC)
        self.b = PostgresStore(METADATA, TRAFFIC)
        # These legacy wire fixtures exercise transaction/HA behavior with
        # synthetic actors. Production approval identity is tested separately.
        self.a.lab_approvals = self.b.lab_approvals = True
        for dsn, tables in ((METADATA, 'servers,policies,groups,sessions,alerts,audit,tokens,controller_nodes,firewall_changes,security_event_receipts,security_alert_windows,policy_revisions,bundle_history,managed_rollouts,managed_approvals,managed_outcomes,locations,metadata_ip_profiles,metadata_subnets,metadata_plans,auth_users,auth_sessions,auth_states,server_reservations,retired_endpoints,server_lifecycle_plans,service_groups,service_group_revisions'),
                            (TRAFFIC, 'flows,batches')):
            if dsn == METADATA:
                tables += ',learning_evidence,learning_evidence_receipts,learning_allow_policies,learning_allow_hosts,learning_allow_history,learning_policy_previews'
                tables += ',maintenance_backups,maintenance_plans,maintenance_settings,runtime_deployment'
                tables += ',agent_polling_settings,agent_polling_revisions'
                tables += ',notification_settings,notification_revisions,notification_reviews,notification_deliveries'
            with self.driver.connect(dsn) as connection:
                connection.execute('TRUNCATE ' + tables)

    def test_learning_evidence_and_443_only_overlay_survive_cross_node_stop_and_cleanup(self):
        from controller import learning_policies
        from controller.store import digest
        protected = {'management_sources': ['10.90.0.0/24'], 'ssh_ports': [2022],
                     'controller_url': 'https://controller.example',
                     'management_probe_url': 'https://controller.example/api/v1/agent/enforcement/check', 'zone': 'public'}
        body = {'hostname': 'learn-443', 'ips': ['10.70.0.11'], 'firewalld_state': 'running',
                'listeners': [{'port': port, 'protocol': 'tcp', 'address': '0.0.0.0', 'process': 'sshd' if port == 2022 else 'nginx'} for port in (2022, 80, 443)],
                'discovery_performed': True, 'discovered_at': stamp(), 'agent_version': '0.4.0',
                'capabilities': ['learning_discovery_v1', 'learning_auto_allow_v1'],
                'protection': {**protected, 'digest': digest(protected), 'ready': True, 'blockers': []}}
        self.a.report('learn-443', body)
        session = self.b.create_session({'server_ids': ['learn-443'], 'selection_mode': 'discovered',
            'policy_action': 'auto_allow', 'auto_allow_confirmed': True,
            'port_filter': [{'port': 443, 'protocol': 'tcp'}]}, 'admin')
        self.a.report('learn-443', {**body, 'discovered_at': stamp(), 'learning_discovery_session_ids': [session['id']]})
        at = stamp()
        batch = {'session_id': session['id'], 'batch_id': 'ha-learned-443', 'events': [
            {'source_ip': '10.50.0.5', 'port': 443, 'protocol': 'tcp', 'count': 3, 'first_seen': at, 'last_seen': at}]}
        self.b.enqueue_flows('learn-443', batch)
        self.a.process_flows()
        self.assertTrue(self.a.enqueue_flows('learn-443', batch)['duplicate'])
        self.b.process_flows()
        evidence = learning_policies.recommendations(self.b, session['id'])
        self.assertEqual(evidence['rows'][0]['count'], 3)
        grant = self.a.assignment('learn-443')[0]['learning_allow']
        self.assertEqual(grant['services'], [{'port': 443, 'protocol': 'tcp', 'sources': ['10.50.0.5/32']}])
        self.assertTrue(grant['authorized'])
        self.assertFalse(self.b.assignment('learn-443')[0]['enforcement']['authorized'])
        def receipt(store, authority):
            store.report('learn-443', {**body, 'discovery_performed': False, 'learning_allow_outcome': {
                'status': 'applied', 'generation': authority['generation'], 'digest': authority['digest'],
                'binding_digest': authority['binding_digest'], 'applied_generation': authority['generation'],
                'applied_digest': authority['digest']}})
        receipt(self.b, grant)
        policy = learning_policies.listing(self.a)[0]
        self.assertEqual(policy['status'], 'applied')
        self.b.stop_session(session['id'], 'admin')
        self.assertFalse(self.a.assignment('learn-443')[0]['learning_allow']['authorized'])
        learning_policies.remove(self.a, policy['id'], {'expected_revision': policy['revision']}, 'admin')
        removal = self.b.assignment('learn-443')[0]['learning_allow']
        self.assertTrue(removal['authorized'])
        self.assertEqual(removal['services'], [])
        receipt(self.a, removal)
        self.assertEqual(learning_policies.get(self.b, policy['id'])['status'], 'removed')
        self.assertIn('10.50.0.5', learning_policies.export_csv(self.a, session['id']))

    def test_service_catalogue_versions_and_per_host_learning_are_shared_between_nodes(self):
        from controller import service_groups
        def report(store, identifier, port, address, **extra):
            return store.report(identifier, {'hostname': identifier, 'ips': [address],
                'listeners': [{'port': port, 'protocol': 'tcp', 'address': '0.0.0.0'}],
                'discovered_at': stamp(), 'discovery_performed': True,
                'capabilities': ['learning_discovery_v1'], 'agent_version': '0.3.0', **extra})
        report(self.a, 'learn-a', 2022, '10.70.0.11')
        report(self.b, 'learn-b', 5432, '10.70.0.12')
        source = self.a.save_group({'name': 'Approved clients', 'type': 'static', 'server_ids': ['learn-b']}, 'admin')
        web = service_groups.save(self.a, {'name': 'Web', 'ports': [{'port': 80, 'protocol': 'tcp'}, {'port': 443, 'protocol': 'tcp'}]}, 'admin')
        policy = self.b.save_policy({'name': 'Shared grouped ports', 'selector': {}, 'mode': 'enforce',
            'services': [{'service_group_id': web['id'], 'source_group_ids': [source['id']]}]}, 'admin')
        original = self.a.assignment('learn-a')[0]
        proposal = {**web, 'expected_revision': web['revision'], 'ports': web['ports'] + [{'port': 8443, 'protocol': 'tcp'}]}
        self.assertEqual(service_groups.preview(self.b, proposal)['effective_change_count'], 2)
        service_groups.save(self.b, proposal, 'admin', web['id'])
        compiled = self.a.assignment('learn-a')[0]
        self.assertGreater(compiled['version'], original['version'])
        self.assertEqual([rule['port'] for rule in compiled['services']], [80, 443, 8443])
        self.assertTrue(all(rule['sources'] == ['10.70.0.12/32'] for rule in compiled['services']))
        self.assertFalse(compiled['enforcement']['authorized'])
        self.assertEqual(self.a.policy_revisions(policy['id'], 1)['services'][0]['service_group_snapshot']['ports'], web['ports'])
        session = self.a.create_session({'server_ids': ['learn-a', 'learn-b'], 'selection_mode': 'discovered'}, 'admin')
        self.assertTrue(self.b.assignment('learn-a')[0]['learning_sessions'][0]['discovery_pending'])
        report(self.b, 'learn-a', 2022, '10.70.0.11', learning_discovery_session_ids=[session['id']])
        report(self.a, 'learn-b', 5432, '10.70.0.12', learning_discovery_session_ids=[session['id']])
        self.assertEqual(self.a.assignment('learn-a')[0]['learning_sessions'][0]['ports'], [{'port': 2022, 'protocol': 'tcp'}])
        self.assertEqual(self.b.assignment('learn-b')[0]['learning_sessions'][0]['ports'], [{'port': 5432, 'protocol': 'tcp'}])
        at = stamp()
        with self.assertRaises(ValueError):
            self.b.enqueue_flows('learn-a', {'batch_id': 'wrong-host-port', 'session_id': session['id'],
                'events': [{'port': 5432, 'protocol': 'tcp', 'source_ip': '10.90.0.1', 'first_seen': at, 'last_seen': at}]})
        self.b.stop_session(session['id'], 'admin')
        self.assertEqual(self.a.assignment('learn-a')[0]['learning_tombstones'][0]['ports'], [{'port': 2022, 'protocol': 'tcp'}])

    def test_entra_state_sessions_roles_and_revocation_are_shared_across_tls_nodes(self):
        from controller.auth import EntraAuth, EntraConfig, SESSION_COOKIE
        from controller.tests import test_auth as fixture
        from urllib.parse import quote, urlencode
        import http.client
        import json
        if not fixture.HAS_CRYPTO:
            self.skipTest('Install controller auth requirements for Entra HA acceptance')
        from cryptography.hazmat.primitives.asymmetric import rsa
        config = EntraConfig(fixture.TENANT, fixture.CLIENT,
                             'https://localhost/api/v1/auth/callback', 'fixture-secret', fixture.SUPER)
        provider = fixture.LocalMicrosoft(config, rsa.generate_private_key(public_exponent=65537, key_size=2048))
        auth_a, auth_b = EntraAuth(self.a, config, provider), EntraAuth(self.b, config, provider)
        server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_tls.load_cert_chain(self.pki / 'controller.pem', self.pki / 'controller-key.pem')
        client_tls = ssl.create_default_context(cafile=str(self.pki / 'ca.pem'))
        with running(App(self.a, auth=auth_a), server_tls) as pa, running(App(self.b, auth=auth_b), server_tls) as pb:
            def api(port, method, path, body=None, headers=None, expected=200):
                conn = http.client.HTTPSConnection('localhost', port, context=client_tls, timeout=15)
                # Model two TLS backends behind the same reviewed LB origin.
                # The network sockets have ephemeral ports; browser Host and
                # Origin remain canonical for OIDC and session CSRF checks.
                outgoing = {'Host': 'localhost', 'Origin': config.origin, **(headers or {})}
                if body is not None:
                    outgoing['Content-Type'] = 'application/json'
                conn.request(method, '/api/v1/' + path, json.dumps(body) if body is not None else None, outgoing)
                response = conn.getresponse()
                data, pairs = response.read(), response.getheaders()
                result = json.loads(data) if data else None
                self.assertEqual(response.status, expected, result)
                conn.close()
                return result, dict(pairs), [value for key, value in pairs if key.lower() == 'set-cookie']
            # An old node alias must redirect before creating OIDC state. The
            # canonical LB Host below then receives the normal nonce/cookie.
            _, alias_redirect, alias_cookies = api(pa, 'GET', 'auth/login',
                headers={'Host': 'localhost:' + str(pa)}, expected=302)
            self.assertEqual(alias_redirect['Location'], config.origin + '/api/v1/auth/login')
            self.assertEqual(alias_cookies, [])
            def signin(oid):
                _, redirect, cookies = api(pa, 'GET', 'auth/login', expected=302)
                query = provider.issue(redirect['Location'], oid)
                _, _, cookies = api(pb, 'GET', 'auth/callback?' + urlencode(query, doseq=True),
                                     headers={'Cookie': cookies[0].split(';', 1)[0]}, expected=303)
                session = next(cookie.split(';', 1)[0] for cookie in cookies if cookie.startswith(SESSION_COOKIE + '='))
                identity, _, _ = api(pa, 'GET', 'auth', headers={'Cookie': session})
                return {'Cookie': session, 'X-CSRF-Token': identity['csrf_token']}
            super_headers = signin(fixture.SUPER)
            user, _, _ = api(pa, 'POST', 'access/users', {'object_id': fixture.ADMIN, 'role': 'admin'}, super_headers, 201)
            admin_headers = signin(fixture.ADMIN)
            reservation, _, _ = api(pb, 'POST', 'servers', {'hostname': 'cross-node-reservation'}, admin_headers, 201)
            pending, _, _ = api(pa, 'GET', 'server-reservations', headers=admin_headers)
            self.assertEqual(pending['items'][0]['id'], reservation['id'])
            api(pa, 'POST', 'access/users/' + quote(user['id'], safe='') + '/revoke-sessions', {}, super_headers)
            api(pb, 'GET', 'overview', headers=admin_headers, expected=401)
            admin_headers = signin(fixture.ADMIN)
            api(pb, 'PATCH', 'access/users/' + quote(user['id'], safe=''), {'role': 'read_only'}, super_headers)
            api(pa, 'POST', 'servers', {'hostname': 'revoked-authority'}, admin_headers, 401)
            downgraded = signin(fixture.ADMIN)
            api(pb, 'POST', 'servers', {'hostname': 'readonly-denied'}, downgraded, 403)

    def test_central_metadata_review_and_future_ip_profiles_apply_across_controllers(self):
        tokens = {'admin': 'shared-ha-admin'}
        headers = {'Authorization': 'Bearer shared-ha-admin'}
        self.a.report('metadata-ha', {'hostname': 'metadata-ha', 'ips': ['10.241.1.10'], 'listeners': []})
        with running(App(self.a, tokens=tokens, controller_id='metadata-a')) as pa, \
             running(App(self.b, tokens=tokens, controller_id='metadata-b')) as pb:
            def api(port, method, path, body=None, expected=200):
                status, value, _ = request(port, method, '/api/v1/' + path, body, headers)
                self.assertEqual(status, expected, value)
                return value
            location = api(pa, 'POST', 'locations',
                           {'name': 'Noida 81 DC', 'type': 'datacenter', 'location': 'Noida'}, 201)
            rule = api(pa, 'POST', 'metadata/subnets/preview',
                       {'cidr': '10.241.0.0/16', 'location_id': location['id']}, 201)
            api(pb, 'POST', 'metadata/subnets/' + rule['id'] + '/apply',
                {'confirmation_nonce': rule['confirmation_nonce']})
            self.assertEqual(api(pa, 'GET', 'servers/metadata-ha')['location_id'], location['id'])
            plan = api(pa, 'POST', 'metadata/bulk/preview',
                       {'server_ids': ['metadata-ha'], 'tag_updates': {'application': 'billing'}}, 201)
            self.b.report('metadata-ha', {'hostname': 'metadata-ha', 'ips': ['10.241.1.10'],
                                          'listeners': [], 'tags': {'application': 'forged'}})
            api(pb, 'POST', 'metadata/bulk/' + plan['id'] + '/apply',
                {'confirmation_nonce': plan['confirmation_nonce']})
            imported = api(pa, 'POST', 'metadata/imports/preview',
                           {'csv': 'ip,application,dc,owner\n10.241.1.10,payments,Noida 81 DC,operations\n2001:db8::1,platform,Noida 81 DC,cloud\n'}, 201)
            api(pb, 'POST', 'metadata/imports/' + imported['id'] + '/apply',
                {'confirmation_nonce': imported['confirmation_nonce']})
            current = api(pa, 'GET', 'servers/metadata-ha')
            self.assertEqual(current['tags'], {'application': 'billing', 'owner': 'operations'})
            self.assertEqual(current['tag_sources']['application']['type'], 'manual')
            self.b.report('metadata-future', {'hostname': 'metadata-future', 'ips': ['2001:db8::1'], 'listeners': []})
            future = api(pa, 'GET', 'servers/metadata-future')
            self.assertEqual(future['tags']['application'], 'platform')
            self.assertEqual(future['location_id'], location['id'])
            self.assertEqual(api(pb, 'GET', 'metadata/imports/profiles')['total'], 2)
            removal = api(pa, 'POST', 'metadata/imports/profiles/2001%3Adb8%3A%3A1/delete-preview', {}, 201)
            api(pb, 'POST', 'metadata/imports/' + removal['id'] + '/apply',
                {'confirmation_nonce': removal['confirmation_nonce']})
            self.assertIsNone(api(pa, 'GET', 'servers/metadata-future')['location_id'])
            api(pa, 'POST', 'metadata/imports/' + removal['id'] + '/apply',
                {'confirmation_nonce': removal['confirmation_nonce']}, 409)
            api(pb, 'PATCH', 'servers/metadata-ha', {'reset_tag_keys': ['application']})
            self.assertEqual(api(pa, 'GET', 'servers/metadata-ha')['tags']['application'], 'payments')

    def test_firewall_confirmations_and_security_receipts_are_shared_between_controllers(self):
        from controller.firewall import inventory, create_change, confirm_change
        from test_firewall_integration import snapshot, BROAD_ALLOW
        report={'hostname':'ha-firewall','ips':['10.1.2.3'],'firewalld_state':'running','listeners':[], 'firewall_snapshot':snapshot()}
        self.a.report('ha-endpoint',report)
        rule=next(rule for rule in inventory(self.b)['common_rules'] if rule['value']==BROAD_ALLOW)
        plan=create_change(self.a,{'name':'Cross-node removal','server_ids':['ha-endpoint'],'rule_key':rule['rule_key'],'operation':'remove','scopes':['runtime','permanent']},'admin')
        first=confirm_change(self.b,plan['id'],{'confirmation_nonce':plan['confirmation_nonce']},'admin')
        self.assertEqual(first['status'],'awaiting_second_confirmation')
        self.assertEqual(self.a.assignment('ha-endpoint')[0]['firewall_changes'],[])
        queued=confirm_change(self.a,plan['id'],{'confirmation_nonce':first['confirmation_nonce'],'challenge':first['confirmation_phrase']},'admin')
        self.assertEqual(len(self.b.assignment('ha-endpoint')[0]['firewall_changes']),1)
        self.b.report('ha-endpoint',{**report,'firewall_snapshot':snapshot(False),'firewall_change_results':[{'id':queued['id'],'plan_digest':queued['plan_digest'],'status':'applied','message':'fixture read-back'}]})
        self.assertEqual(inventory(self.a)['changes'][0]['status'],'applied')
        at=stamp()
        event={'event_id':'ha-security-event','kind':'unexpected_port_hit','source_ip':'10.90.0.1','destination_ip':'10.1.2.3','port':9999,'protocol':'tcp','count':4,'first_seen':at,'last_seen':at,'inventory_checked_at':at,'listening':False,'observed_while_monitoring':True}
        observation={**report,'firewall_snapshot':snapshot(False),'security_monitor':{'enabled':True,'status':'active'},'security_events':[event]}
        self.assertEqual(self.a.report('ha-endpoint',observation)['ack_security_event_ids'],['ha-security-event'])
        self.assertEqual(self.b.report('ha-endpoint',observation)['ack_security_event_ids'],['ha-security-event'])
        alerts=[alert for alert in self.a.all('alerts') if alert['kind']=='unexpected_port_hit']
        self.assertEqual(len(alerts),1)
        self.assertEqual(alerts[0]['details']['count'],4)

    def report(self, store=None):
        (store or self.a).report('ha-endpoint', {'hostname': 'ha-endpoint', 'ips': ['10.1.2.3'],
            'firewalld_state': 'running', 'listeners': [{'port': 2022, 'protocol': 'tcp',
            'process': 'sshd', 'service': 'ssh', 'application': 'OpenSSH'}]})

    def test_managed_history_approval_restore_and_outcomes_survive_controller_changes(self):
        from controller.store import digest
        protected = {'management_sources': ['10.99.0.0/24'], 'ssh_ports': [2022],
            'controller_url': 'https://controller.example',
            'management_probe_url': 'https://controller.example/api/v1/agent/enforcement/check', 'zone': 'public'}
        protected = {**protected, 'digest': digest(protected), 'ready': True, 'blockers': []}
        report = {'hostname': 'ha-managed', 'ips': ['10.1.2.7'], 'firewalld_state': 'running',
            'listeners': [{'port': 2022, 'protocol': 'tcp', 'process': 'sshd', 'service': 'SSH'}],
            'protection': protected, 'apply_status': 'preview', 'applied_version': 0}
        self.a.report('ha-managed', report)
        policy = self.a.save_policy({'name': 'HA managed SSH', 'selector': {}, 'mode': 'enforce',
            'services': [{'port': 2022, 'protocol': 'tcp', 'sources': ['10.99.0.0/24']}]}, 'admin')
        original = self.b.assignment('ha-managed')[0]
        self.assertEqual(self.b.policy_revisions(policy['id'], 1)['services'], policy['services'])
        plan = self.a.create_managed_rollout({'name': 'Cross-node exact approval', 'server_ids': ['ha-managed']}, 'admin')
        first = self.b.confirm_managed_rollout(plan['id'], {'confirmation_nonce': plan['confirmation_nonce']}, 'admin')
        self.assertFalse(self.a.assignment('ha-managed')[0]['enforcement']['authorized'])
        second = self.a.confirm_managed_rollout(plan['id'], {'confirmation_nonce': first['confirmation_nonce'], 'challenge': first['confirmation_phrase']}, 'admin')
        authorized = self.b.assignment('ha-managed')[0]
        self.assertEqual(authorized['enforcement']['approval_id'], second['id'])
        self.assertTrue(authorized['enforcement']['authorized'])
        outcome = {'status': 'enforced', 'version': authorized['version'], 'digest': authorized['digest'],
            'approval_id': second['id'], 'updated_at': stamp()}
        self.b.report('ha-managed', {**report, 'managed_enforcement': outcome,
            'applied_version': authorized['version'], 'apply_status': 'synced'})
        self.assertEqual(self.a.policy_history('ha-managed', original['version'])['outcomes'][0]['status'], 'enforced')
        changed = {**policy, 'services': [{'port': 2022, 'protocol': 'tcp', 'sources': ['10.98.0.0/24']}]}
        self.b.save_policy(changed, 'admin', policy['id'])
        self.assertFalse(self.a.assignment('ha-managed')[0]['enforcement']['authorized'])
        self.a.rollback_policy(policy['id'], 1, 'HA test restore former config', 'admin')
        restored = self.b.assignment('ha-managed')[0]
        self.assertGreater(restored['version'], original['version'])
        self.assertEqual(restored['digest'], original['digest'])
        self.assertFalse(restored['enforcement']['authorized'])
        self.assertEqual(len(self.a.policy_revisions(policy['id'])), 3)
        self.assertEqual(self.b.policy_history('ha-managed', original['version'])['digest'], original['digest'])

    def test_policy_mvcc_read_remains_available_while_peer_holds_write_lock(self):
        self.report()
        published = self.b.assignment('ha-endpoint')
        with self.a.meta() as connection:
            server = self.a._get(connection, 'servers', 'ha-endpoint')
            server['pending_test_metadata'] = True
            self.a._put(connection, 'servers', server)
            with ThreadPoolExecutor(max_workers=1) as pool:
                value = pool.submit(self.b.assignment, 'ha-endpoint').result(timeout=3)
            self.assertEqual(value[0]['server_id'], 'ha-endpoint')
            self.assertEqual(value[1], published[1])
            self.assertEqual(value[0]['assignment_generation'], published[0]['assignment_generation'])

    def test_application_groups_have_shared_stable_identity_and_live_membership(self):
        for index in (1, 2):
            identifier = f'ha-billing-{index}'
            self.a.report(identifier, {'hostname': identifier, 'ips': [f'10.40.0.{index}'],
                'listeners': [], 'firewalld_state': 'running'})
            self.b.update_server(identifier, {'tags': {'application': 'billing'}}, 'admin')
        billing = next(group for group in self.a.groups() if group.get('application') == 'billing')
        self.assertEqual(billing['member_ids'], ['ha-billing-1', 'ha-billing-2'])
        self.a.save_policy({'name': 'Shared automatic billing group', 'mode': 'monitor',
            'group_ids': [billing['id']], 'services': [{'port': 8443, 'protocol': 'tcp',
            'sources': ['10.90.0.0/24']}]}, 'admin')
        self.assertEqual(self.b.assignment('ha-billing-1')[0]['services'][0]['port'], 8443)
        self.b.update_server('ha-billing-1', {'tags': {'application': 'payments'}}, 'admin')
        self.assertEqual(self.a.assignment('ha-billing-1')[0]['services'], [])
        remaining = next(group for group in self.a.groups() if group.get('application') == 'billing')
        self.assertEqual(remaining['id'], billing['id'])
        self.assertEqual(remaining['member_ids'], ['ha-billing-2'])
        self.assertEqual(next(group for group in self.a.groups() if group.get('application') == 'payments')['member_ids'], ['ha-billing-1'])
        restarted = PostgresStore(METADATA, TRAFFIC)
        self.assertEqual(next(group for group in restarted.groups() if group.get('application') == 'billing')['id'], billing['id'])

    def test_manual_location_catalogue_assignment_and_rename_are_shared(self):
        self.report()
        location = self.a.save_location({'name': 'DR Mumbai', 'location': 'Mumbai, India', 'type': 'datacenter'}, 'admin')
        self.b.update_server('ha-endpoint', {'location_id': location['id'], 'tags': {'application': 'billing', 'owner': 'payments'}}, 'admin')
        group = self.a.save_group({'name': 'DR billing', 'type': 'dynamic', 'selector': {'location_id': location['id'], 'application': 'billing'}}, 'admin')
        self.assertEqual(group['member_ids'], ['ha-endpoint'])
        self.b.save_location({**location, 'name': 'Mumbai Recovery', 'location': 'Mumbai West'}, 'admin', location['id'])
        self.assertEqual(self.a.servers()[0]['location']['name'], 'Mumbai Recovery')
        self.assertEqual(self.b.groups()[0]['member_ids'], ['ha-endpoint'])
        self.assertEqual(self.a.locations()[0]['server_count'], 1)
        with self.assertRaises(ValueError):
            self.a.delete_location(location['id'], 'admin')
        with self.assertRaises(ValueError):
            self.b.update_server('ha-endpoint', {'location_id': 'unknown-location'}, 'admin')

    def test_shared_groups_policy_versions_and_inventory_across_nodes(self):
        self.report()
        self.a.update_server('ha-endpoint', {'tags': {'application': 'billing'}}, 'admin')
        group = self.b.save_group({'name': 'Billing', 'type': 'dynamic', 'selector': {'application': 'billing'}}, 'admin')
        policy = self.a.save_policy({'name': 'Billing SSH', 'group_ids': [group['id']], 'mode': 'monitor',
            'services': [{'port': 2022, 'protocol': 'tcp', 'sources': ['10.90.0.0/24']}]}, 'admin')
        assignment, etag = self.b.assignment('ha-endpoint')
        self.assertEqual(assignment['services'][0]['sources'], ['10.90.0.0/24'])
        policy['services'][0]['sources'] = ['10.91.0.0/24']
        self.b.save_policy(policy, 'admin', policy['id'])
        updated, new_etag = self.a.assignment('ha-endpoint')
        self.assertGreater(updated['version'], assignment['version'])
        self.assertNotEqual(new_etag, etag)
        self.assertEqual(updated['services'][0]['sources'], ['10.91.0.0/24'])
        self.assertEqual(self.b.servers()[0]['listeners'][0]['application'], 'OpenSSH')

    def test_cross_node_read_modify_write_transactions_do_not_lose_updates(self):
        self.report()
        stores = [PostgresStore(METADATA, TRAFFIC, initialize=False) for _ in range(4)]
        def increment(store):
            for _ in range(10):
                with store.lock, store.meta() as connection:
                    server = store._get(connection, 'servers', 'ha-endpoint')
                    count = server.get('acceptance_counter', 0)
                    time.sleep(0.002)
                    server['acceptance_counter'] = count + 1
                    store._put(connection, 'servers', server)
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(increment, stores))
        self.assertEqual(self.a.get('servers', 'ha-endpoint')['acceptance_counter'], 40)

    def test_shared_traffic_queue_is_durable_and_idempotent_across_workers(self):
        self.report()
        session = self.a.create_session({'server_ids': ['ha-endpoint'], 'ports': [{'port': 2022, 'protocol': 'tcp'}], 'duration_seconds': 120}, 'admin')
        batch = {'batch_id': 'shared-batch', 'session_id': session['id'], 'events': [{
            'source_ip': '192.0.2.10', 'port': 2022, 'protocol': 'tcp', 'verdict': 'observed',
            'count': 7, 'first_seen': session['starts_at'], 'last_seen': session['starts_at']}]}
        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(lambda store: store.enqueue_flows('ha-endpoint', batch), [self.a, self.b]))
        restarted = PostgresStore(METADATA, TRAFFIC, initialize=False)
        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(lambda store: store.process_flows(), [self.b, restarted]))
        self.assertEqual(sum(flow['count'] for flow in self.a.flows()), 7)
        restarted.enqueue_flows('ha-endpoint', batch)
        restarted.process_flows()
        self.assertEqual(sum(flow['count'] for flow in self.b.flows()), 7)

    def test_distributed_background_job_excludes_peers_and_releases_after_error(self):
        entered, release = threading.Event(), threading.Event()
        def callback():
            entered.set()
            if not release.wait(5):
                raise RuntimeError('acceptance callback timed out')
            return 'first'
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(self.a.run_job, 'health', callback)
            try:
                self.assertTrue(entered.wait(5))
                self.assertIsNone(self.b.run_job('health', lambda: 'duplicate'))
            finally:
                release.set()
            self.assertEqual(pending.result(timeout=5), 'first')
        def failing():
            raise ValueError('test failure')
        with self.assertRaises(ValueError):
            self.a.run_job('health', failing)
        self.assertEqual(self.b.run_job('health', lambda: 'recovered'), 'recovered')

    def test_background_leadership_recovers_after_controller_process_dies(self):
        context = multiprocessing.get_context('spawn')
        signal = context.Queue()
        process = context.Process(target=hold_job_until_terminated, args=(METADATA, TRAFFIC, signal))
        process.start()
        try:
            self.assertEqual(signal.get(timeout=10), 'held')
            self.assertIsNone(self.b.run_job('health', lambda: 'duplicate'))
            process.terminate()
            process.join(5)
            self.assertFalse(process.is_alive())
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                result = self.b.run_job('health', lambda: 'failover')
                if result == 'failover':
                    break
                time.sleep(0.05)
            self.assertEqual(result, 'failover')
        finally:
            if process.is_alive():
                process.terminate()
                process.join(5)
            signal.close()

    def test_readiness_checks_both_shared_databases_and_redacts_connection_details(self):
        self.assertEqual(self.a.readiness(), {'metadata': True, 'traffic': True})
        settings = self.driver.conninfo.conninfo_to_dict(TRAFFIC)
        settings['dbname'] = 'prthak_test_missing_database'
        invalid = self.driver.conninfo.make_conninfo(**settings)
        from controller.postgres import DependencyUnavailable
        with self.assertRaises(DependencyUnavailable):
            PostgresStore(METADATA, invalid, initialize=False)
        # Existing nodes must become unready if a dependency disappears after
        # their initially verified connection, without leaking its details.
        degraded = PostgresStore(METADATA, TRAFFIC, initialize=False)
        degraded._traffic_dsn = invalid
        with running(App(degraded, tokens={'admin': 'a' * 48}, controller_id='degraded', site='DR')) as port:
            status, readiness, _ = request(port, 'GET', '/readyz')
            self.assertEqual(status, 503)
            self.assertEqual(readiness['checks'], {'metadata': True, 'traffic': False, 'provider_authority': True})
            self.assertNotIn('prthak_test_missing_database', str(readiness))
            self.assertEqual(request(port, 'GET', '/healthz')[0], 200)

    def tls(self):
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(self.pki / 'controller.pem', self.pki / 'controller-key.pem')
        tls.load_verify_locations(self.pki / 'ca.pem')
        tls.verify_mode = ssl.CERT_OPTIONAL
        return tls

    def test_two_tls_controllers_share_enrollment_and_keep_policy_after_node_failure(self):
        signer = Signer(self.pki / 'ca.pem', self.pki / 'ca-key.pem')
        token = 'a' * 48
        app_a = App(self.a, signer=signer, tokens={'admin': token}, controller_id='dc1-controller', site='DC1')
        app_b = App(self.b, signer=signer, tokens={'admin': token}, controller_id='dr-controller', site='DR')
        client = ssl.create_default_context(cafile=str(self.pki / 'ca.pem'))
        headers = {'Authorization': 'Bearer ' + token}
        with running(app_b, self.tls()) as port_b:
            with running(app_a, self.tls()) as port_a:
                _, bootstrap, _ = request(port_a, 'POST', '/api/v1/enrollment-tokens', {'name': 'HA endpoint'}, headers, client)
                with tempfile.TemporaryDirectory() as temp:
                    key, csr, cert = (Path(temp) / name for name in ('key.pem', 'request.pem', 'cert.pem'))
                    subprocess.run(['openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(csr), '-subj', '/CN=untrusted-request'], check=True, capture_output=True)
                    payload = {'token': bootstrap['token'], 'hostname': 'ha-host', 'csr': csr.read_text()}
                    status, enrollment, _ = request(port_b, 'POST', '/api/v1/agent/enroll', payload, context=client)
                    self.assertEqual(status, 201)
                    self.assertEqual(request(port_a, 'POST', '/api/v1/agent/enroll', payload, context=client)[1], enrollment)
                    cert.write_text(enrollment['certificate'])
                    endpoint = ssl.create_default_context(cafile=str(self.pki / 'ca.pem'))
                    endpoint.load_cert_chain(cert, key)
                    report = {'hostname': 'ha-host', 'ips': ['10.1.2.5'], 'listeners': [{'port': 2022, 'protocol': 'tcp', 'process': 'sshd', 'service': 'ssh'}], 'firewalld_state': 'running'}
                    self.assertEqual(request(port_a, 'POST', '/api/v1/agent/report', report, context=endpoint)[0], 200)
                    self.assertEqual(request(port_b, 'POST', '/api/v1/agent/report', report, context=endpoint)[0], 200)
                    proof = {'nonce': 'a' * 32, 'ssh_ports': [2022]}
                    self.assertEqual(request(port_a, 'POST', '/api/v1/agent/enforcement/check', proof, context=endpoint)[0], 403)
                    self.assertEqual(request(port_b, 'POST', '/api/v1/agent/enforcement/check', proof, headers, client)[0], 403)
                    first_policy = request(port_a, 'GET', '/api/v1/agent/policy', context=endpoint)[1]
                    app_a.heartbeat()
                    app_b.heartbeat()
                    status, cluster, _ = request(port_b, 'GET', '/api/v1/cluster', headers=headers, context=client)
                    self.assertEqual(status, 200)
                    self.assertEqual({node['id'] for node in cluster['nodes']}, {'dc1-controller', 'dr-controller'})
                    self.assertTrue(all(node['ready'] for node in cluster['nodes']))
            # The first server socket and all its jobs are now stopped. Node B serves the same endpoint identity.
            status, next_policy, _ = request(port_b, 'GET', '/api/v1/agent/policy', context=endpoint)
            self.assertEqual(status, 200)
            self.assertEqual(next_policy, first_policy)
            self.assertEqual(len(self.b.servers()), 1)
            with self.b.lock, self.b.meta() as connection:
                node = self.b._get(connection, 'controller_nodes', 'dc1-controller')
                node['last_seen'] = stamp(now() - timedelta(seconds=31))
                self.b._put(connection, 'controller_nodes', node)
            cluster = request(port_b, 'GET', '/api/v1/cluster', headers=headers, context=client)[1]
            self.assertEqual(next(node for node in cluster['nodes'] if node['id'] == 'dc1-controller')['status'], 'offline')

