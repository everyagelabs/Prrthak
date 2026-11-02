"""Cross-component acceptance tests. Requires openssl; optional SEG_AGENT_BINARY.

These tests bind loopback only and use temporary databases and development CAs.
The optional real Go enrollment test performs read-only discovery. No firewall
rules are changed by this suite.
"""
from contextlib import contextmanager
from datetime import timedelta
import hashlib
import http.client
import json
import os
import secrets
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
import unittest

from controller.app import App, Server
from controller.pki import Signer, init_ca
from controller.store import Store, now, stamp
from controller.tests.capture_fixture import typed_event


def stored_entra_admin(app, origin):
    """Private persisted session fixture; never a live Microsoft sign-in."""
    from controller.auth import EntraAuth, EntraConfig, SESSION_COOKIE
    config = EntraConfig("11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222",
                         origin + "/api/v1/auth/callback", "isolated-session-fixture")
    app.auth = EntraAuth(app.store, config, provider=object())
    app.store.approval_tenant_id = config.tenant_id
    app.store.approval_auth_fingerprint = config.fingerprint
    raw = secrets.token_urlsafe(32)
    user = app.auth._user({"object_id": "33333333-3333-3333-3333-333333333333", "role": "admin"})
    with app.store.meta() as db:
        app.store._put(db, "auth_users", user)
        app.store._put(db, "auth_sessions", {"id": hashlib.sha256(raw.encode()).hexdigest(), "user_id": user["id"],
            "expires_at": stamp(now() + timedelta(hours=1)), "config": config.fingerprint})
    cookie = {"Cookie": SESSION_COOKIE + "=" + raw}
    principal = app.auth.authenticate(cookie)
    return {**cookie, "X-CSRF-Token": principal["csrf_token"], "Origin": origin}


@contextmanager
def running(app, tls=None):
    server = Server(('127.0.0.1', 0), app)
    if tls:
        server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    app.start_jobs()
    try:
        yield server.server_address[1]
    finally:
        app.stop.set()
        server.shutdown()
        server.server_close()
        thread.join(3)
        for job in app.threads:
            job.join(3)


def request(port, method, path, payload=None, headers=None, context=None):
    conn = (http.client.HTTPSConnection('localhost', port, context=context, timeout=15)
            if context else http.client.HTTPConnection('127.0.0.1', port, timeout=15))
    encoded = json.dumps(payload).encode() if payload is not None else None
    outgoing = dict(headers or {})
    if encoded is not None:
        outgoing['Content-Type'] = 'application/json'
    conn.request(method, path, body=encoded, headers=outgoing)
    response = conn.getresponse()
    data = response.read()
    result = (response.status, json.loads(data) if data else None, dict(response.getheaders()))
    conn.close()
    return result


class EndToEndTests(unittest.TestCase):
    def test_custom_port_inventory_and_later_service_discovery_reach_dashboard_api(self):
        with tempfile.TemporaryDirectory() as temp:
            store = Store(temp)
            with running(App(store, demo=True)) as port:
                headers = {'X-Agent-ID': 'discovery-acceptance'}
                first_scan = stamp(now() - timedelta(minutes=15))
                ssh = {'port': 2022, 'protocol': 'tcp', 'address': '0.0.0.0', 'process': 'sshd',
                       'service': 'ssh', 'application': 'OpenSSH', 'systemd_unit': 'ssh.service', 'pid': 123}
                nginx = {'port': 8080, 'protocol': 'tcp', 'address': '0.0.0.0', 'process': 'nginx',
                         'service': 'nginx', 'application': 'Nginx', 'systemd_unit': 'nginx.service', 'pid': 456}
                report = {'hostname': 'auto-discovered-host', 'ips': ['10.60.20.11'],
                          'firewalld_state': 'running', 'listeners': [ssh], 'discovery_performed': True,
                          'discovered_at': first_scan, 'discovery_interval_seconds': 900}
                self.assertEqual(request(port, 'POST', '/api/v1/agent/report', report, headers)[0], 200)
                # A heartbeat cannot publish invented/new listeners or refresh the scan time.
                cached = {**report, 'discovery_performed': False, 'listeners': [ssh, nginx]}
                self.assertEqual(request(port, 'POST', '/api/v1/agent/report', cached, headers)[0], 200)
                _, inventory, _ = request(port, 'GET', '/api/v1/servers')
                server = inventory['items'][0]
                self.assertEqual(server['last_discovery_at'], first_scan)
                self.assertEqual([(item['service'], item['port']) for item in server['listeners']], [('ssh', 2022)])
                second_scan = stamp()
                self.assertEqual(request(port, 'POST', '/api/v1/agent/report',
                    {**report, 'discovered_at': second_scan, 'listeners': [ssh, nginx]}, headers)[0], 200)
                for _ in range(2):
                    self.assertEqual(request(port, 'POST', '/api/v1/agent/report', cached, headers)[0], 200)
                _, overview, _ = request(port, 'GET', '/api/v1/overview')
                server = overview['servers'][0]
                discovered = next(item for item in server['listeners'] if item['port'] == 8080)
                self.assertEqual(discovered['application'], 'Nginx')
                self.assertTrue(discovered['is_new'])
                self.assertEqual(server['last_discovery_at'], second_scan)
                alerts = [item for item in overview['alerts'] if item['kind'] == 'service_discovered'
                          and item.get('details', {}).get('port') == 8080]
                self.assertEqual(len(alerts), 1)
                self.assertEqual(alerts[0]['severity'], 'warning')
                self.assertEqual(request(port, 'POST', f"/api/v1/alerts/{alerts[0]['id']}/ack")[0], 200)
                _, inventory, _ = request(port, 'GET', '/api/v1/servers')
                self.assertFalse(next(item for item in inventory['items'][0]['listeners'] if item['port'] == 8080)['is_new'])
                for section in ('overview', 'servers', 'policies', 'traffic', 'alerts', 'activity'):
                    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=10)
                    conn.request('GET', '/' + section)
                    response = conn.getresponse()
                    self.assertEqual(response.status, 200)
                    page = response.read().decode()
                    self.assertIn('Prṛthak', page)
                    self.assertIn('पृथक्', page)
                    self.assertIn('Airtel Payments Bank. All rights reserved.', page)
                    conn.close()

    def test_one_billing_policy_covers_twenty_servers_and_new_members(self):
        with tempfile.TemporaryDirectory() as temp:
            store = Store(temp)
            with running(App(store, demo=True)) as port:
                status, group, _ = request(port, 'POST', '/api/v1/groups',
                    {'name': 'Billing fleet', 'type': 'dynamic', 'selector': {'application': 'billing'}})
                self.assertEqual(status, 201)
                status, policy, _ = request(port, 'POST', '/api/v1/policies',
                    {'name': 'Billing shared access', 'selector': {}, 'group_ids': [group['id']], 'mode': 'monitor',
                     'services': [{'port': 8443, 'protocol': 'tcp', 'sources': ['10.90.0.0/24']}]})
                self.assertEqual(status, 201)
                for number in range(1, 22):
                    identifier = f'billing-{number:02}'
                    self.assertEqual(request(port, 'POST', '/api/v1/agent/report',
                        {'hostname': identifier, 'ips': [f'10.44.0.{number}'], 'firewalld_state': 'running',
                         'listeners': [{'port': 8443, 'protocol': 'tcp'}]}, {'X-Agent-ID': identifier})[0], 200)
                    self.assertEqual(request(port, 'PATCH', f'/api/v1/servers/{identifier}',
                        {'tags': {'application': 'billing', 'owner': 'finance'}})[0], 200)
                    if number == 20:
                        _, groups, _ = request(port, 'GET', '/api/v1/groups')
                        self.assertEqual(groups['items'][0]['member_count'], 20)
                _, overview, _ = request(port, 'GET', '/api/v1/overview')
                self.assertEqual(len(overview['policies']), 1)
                self.assertEqual(overview['groups'][0]['member_count'], 21)
                for server in overview['servers']:
                    self.assertIn(policy['id'], server['matched_policy_ids'])
                    compiled, _ = store.assignment(server['id'])
                    self.assertEqual(compiled['services'][0]['sources'], ['10.90.0.0/24'])
                status, _, _ = request(port, 'DELETE', f"/api/v1/groups/{group['id']}")
                self.assertEqual(status, 400)

    def test_learning_does_not_change_access_version_and_ingestion_is_idempotent(self):
        with tempfile.TemporaryDirectory() as temp:
            store = Store(temp)
            app = App(store, demo=True)
            with running(app) as port:
                headers = {'X-Agent-ID': 'integration-endpoint'}
                report = {'hostname': 'integration-rhel', 'ips': ['10.20.1.5'], 'os': 'rhel',
                          'firewalld_state': 'running', 'listeners': [{'port': 80, 'protocol': 'tcp'}],
                          'applied_version': 0, 'apply_status': 'preview','capabilities':['traffic_capture_v1']}
                self.assertEqual(request(port, 'POST', '/api/v1/agent/report', report, headers)[0], 200)
                store.update_server('integration-endpoint', {'tags': {'application': 'test'}}, 'test')
                status, policy, original_headers = request(port, 'GET', '/api/v1/agent/policy', headers=headers)
                self.assertEqual(status, 200)
                version = policy['version']
                self.assertEqual(request(port, 'GET', '/api/v1/agent/policy', headers={**headers, 'If-None-Match': original_headers['ETag']})[0], 304)
                status, session, _ = request(port, 'POST', '/api/v1/learning', {
                    'server_ids': ['integration-endpoint'], 'ports': [{'port': 80, 'protocol': 'tcp'}], 'duration_seconds': 120})
                self.assertEqual(status, 201)
                _, learning_policy, learning_headers = request(port, 'GET', '/api/v1/agent/policy', headers=headers)
                self.assertEqual(learning_policy['version'], version)
                self.assertNotEqual(learning_headers['ETag'], original_headers['ETag'])
                events = [typed_event('192.0.2.8',80,identity=session['id']+str(index),at=session['starts_at']) for index in range(3)]
                batch = {'batch_id': 'acceptance-batch', 'session_id': session['id'], 'events': events}
                self.assertEqual(request(port, 'POST', '/api/v1/agent/flows', batch, headers)[0], 202)
                self.assertEqual(request(port, 'POST', '/api/v1/agent/flows', batch, headers)[0], 202)
                store.process_flows()
                self.assertEqual(sum(row['count'] for row in store.flows()), 3)
                # Use a known enrolled fixture identity so this asserts the
                # session's endpoint boundary, independently of unknown-ID404.
                self.assertEqual(request(port,'POST','/api/v1/agent/report',report,{'X-Agent-ID':'someone-else'})[0],200)
                self.assertEqual(request(port, 'POST', '/api/v1/agent/flows', batch, {'X-Agent-ID': 'someone-else'})[0], 403)
                self.assertEqual(request(port, 'POST', f"/api/v1/learning/{session['id']}/stop")[0], 200)
                _, stopped, stopped_headers = request(port, 'GET', '/api/v1/agent/policy', headers=headers)
                self.assertEqual(stopped['version'], version)
                self.assertEqual(stopped['learning_sessions'], [])
                self.assertEqual(stopped['learning_tombstones'][0]['id'], session['id'])
                self.assertIn('stopped_at', stopped['learning_tombstones'][0])
                self.assertNotEqual(stopped_headers['ETag'], learning_headers['ETag'])
                status, overview, _ = request(port, 'GET', '/api/v1/overview')
                self.assertEqual(status, 200)
                self.assertTrue(overview['meta']['demo'])
                self.assertEqual(overview['servers'][0]['apply_status'], 'pending')
                self.assertEqual(overview['servers'][0]['applied_version'], 0)

    def test_tls_enrollment_role_boundaries_and_certificate_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            pki = init_ca(root)
            store = Store(root / 'data')
            admin, operator, viewer = ('a' * 48, 'o' * 48, 'v' * 48)
            app = App(store, signer=Signer(pki / 'ca.pem', pki / 'ca-key.pem'),
                      tokens={'admin': admin, 'operator': operator, 'viewer': viewer})
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.load_cert_chain(pki / 'controller.pem', pki / 'controller-key.pem')
            tls.load_verify_locations(pki / 'ca.pem')
            tls.verify_mode = ssl.CERT_OPTIONAL
            client_context = ssl.create_default_context(cafile=str(pki / 'ca.pem'))
            with running(app, tls) as port:
                self.assertEqual(request(port, 'GET', '/api/v1/overview', context=client_context)[0], 401)
                self.assertEqual(request(port, 'POST', '/api/v1/enrollment-tokens', {'name': 'bad'}, {'Authorization': f'Bearer {viewer}'}, client_context)[0], 403)
                self.assertEqual(request(port, 'POST', '/api/v1/enrollment-tokens', {'name': 'bad'}, {'Authorization': f'Bearer {operator}'}, client_context)[0], 403)
                self.assertEqual(request(port, 'GET', '/api/v1/agent/policy', headers={'X-Agent-ID': 'forged'}, context=client_context)[0], 403)
                status, token_data, _ = request(port, 'POST', '/api/v1/enrollment-tokens', {'name': 'acceptance'}, {'Authorization': f'Bearer {admin}'}, client_context)
                self.assertEqual(status, 201)
                key, csr = root / 'endpoint.key', root / 'endpoint.csr'
                subprocess.run(['openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(csr), '-subj', '/CN=forged-controller-subject'], check=True, capture_output=True)
                payload = {'token': token_data['token'], 'hostname': 'tls-endpoint', 'csr': csr.read_text()}
                status, enrollment, _ = request(port, 'POST', '/api/v1/agent/enroll', payload, context=client_context)
                self.assertEqual(status, 201)
                self.assertNotEqual(enrollment['server_id'], 'forged-controller-subject')
                replay_status, replay, _ = request(port, 'POST', '/api/v1/agent/enroll', payload, context=client_context)
                self.assertEqual(replay_status, 201)
                self.assertEqual(replay, enrollment)
                self.assertEqual(request(port, 'POST', '/api/v1/agent/enroll', {**payload, 'hostname': 'different-host'}, context=client_context)[0], 403)
                cert = root / 'endpoint.crt'
                cert.write_text(enrollment['certificate'])
                client_context.load_cert_chain(cert, key)
                status, policy, _ = request(port, 'GET', '/api/v1/agent/policy', headers={'X-Agent-ID': 'forged'}, context=client_context)
                self.assertEqual(status, 200)
                self.assertEqual(policy['server_id'], enrollment['server_id'])
                for table in ('servers', 'tokens', 'audit'):
                    serialized = json.dumps(store.all(table))
                    self.assertNotIn(token_data['token'], serialized)
                if os.environ.get('SEG_AGENT_BINARY'):
                    # Enrollment-token RBAC above exercises legacy bootstrap;
                    # policy CRUD uses a real, current Entra session record.
                    admin_headers = stored_entra_admin(app, f'https://localhost:{port}')
                    self.assertEqual(request(port, 'GET', '/api/v1/overview',
                        headers={'Authorization': f'Bearer {admin}'}, context=client_context)[0], 401)
                    group_status, billing_group, _ = request(port, 'POST', '/api/v1/groups',
                        {'name': 'Billing', 'type': 'dynamic', 'selector': {'application': 'billing'}}, admin_headers, client_context)
                    self.assertEqual(group_status, 201)
                    self.assertEqual(billing_group['member_count'], 0)
                    policy_status, _, _ = request(port, 'POST', '/api/v1/policies',
                        {'name': 'Billing service', 'group_ids': [billing_group['id']], 'selector': {}, 'mode': 'monitor',
                         'services': [{'port': 8443, 'protocol': 'tcp', 'sources': ['10.24.5.0/24']}]}, admin_headers, client_context)
                    self.assertEqual(policy_status, 201)
                    location_status, location, _ = request(port, 'POST', '/api/v1/locations',
                        {'name': 'Hyderabad DC', 'location': 'Hyderabad, India', 'type': 'datacenter'}, admin_headers, client_context)
                    self.assertEqual(location_status, 201)
                    self.assertEqual(request(port, 'POST', '/api/v1/enrollment-tokens',
                        {'name': 'invalid-metadata', 'tags': {'application': 'billing'}}, admin_headers, client_context)[0], 400)
                    _, bootstrap, _ = request(port, 'POST', '/api/v1/enrollment-tokens',
                        {'name': 'real-go-client'}, admin_headers, client_context)
                    token_file = root / 'bootstrap.token'
                    token_file.write_text(bootstrap['token'])
                    token_file.chmod(0o600)
                    agent_state = root / 'go-enrolled'
                    config = root / 'go-enrollment.json'
                    config.write_text(json.dumps({'controller_url': f'https://localhost:{port}',
                        'state_dir': str(agent_state), 'ca_cert': str(pki / 'ca.pem'),
                        'enrollment_token_file': str(token_file)}))
                    environment = dict(os.environ)
                    environment.pop('SEG_ENROLLMENT_TOKEN', None)
                    process = subprocess.run([os.environ['SEG_AGENT_BINARY'], '--config', str(config), '--once'],
                        capture_output=True, text=True, timeout=30, env=environment)
                    self.assertEqual(process.returncode, 0, process.stderr)
                    self.assertTrue((agent_state / 'agent.crt').is_file())
                    self.assertEqual(len(store.servers()), 2)
                    go_server = next(server for server in store.servers() if server['id'] != enrollment['server_id'])
                    self.assertEqual(go_server['apply_status'], 'preview')
                    self.assertEqual(go_server['applied_version'], 0)
                    self.assertEqual(go_server['tags'], {})
                    self.assertIsNone(go_server['location_id'])
                    status, go_server, _ = request(port, 'PATCH', '/api/v1/servers/' + go_server['id'],
                        {'tag_updates': {'application': 'billing'}, 'location_id': location['id']}, admin_headers, client_context)
                    self.assertEqual(status, 200)
                    self.assertEqual(go_server['tags']['application'], 'billing')
                    self.assertEqual(go_server['location_id'], location['id'])
                    self.assertEqual(go_server['location']['name'], 'Hyderabad DC')
                    _, groups, _ = request(port, 'GET', '/api/v1/groups', headers=admin_headers, context=client_context)
                    self.assertEqual(groups['items'][0]['member_ids'], [go_server['id']])
                    self.assertEqual(groups['items'][0]['member_count'], 1)
                    # A restart reuses its certificate instead of creating another inventory record.
                    again = subprocess.run([os.environ['SEG_AGENT_BINARY'], '--config', str(config), '--once'],
                        capture_output=True, text=True, timeout=30, env=environment)
                    self.assertEqual(again.returncode, 0, again.stderr)
                    self.assertEqual(len(store.servers()), 2)
                    plan = json.loads((agent_state / 'policy-plan.json').read_text())
                    self.assertEqual(plan['services'][0]['port'], 8443)
                    self.assertEqual(plan['services'][0]['sources'], ['10.24.5.0/24'])
                    self.assertEqual(store.server(go_server['id'])['tags']['application'], 'billing')
                    self.assertEqual(store.server(go_server['id'])['location_id'], location['id'])

    @unittest.skipUnless(os.environ.get('SEG_AGENT_BINARY'), 'Set SEG_AGENT_BINARY to test the built Go executable')
    def test_real_go_agent_simulated_sync_and_cached_preview(self):
        binary = str(Path(os.environ.get('SEG_AGENT_BINARY')).resolve())
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            store = Store(root / 'controller')
            with running(App(store, demo=True)) as port:
                config = root / 'agent.json'
                state = root / 'endpoint'
                config.write_text(json.dumps({'controller_url': f'http://127.0.0.1:{port}', 'state_dir': str(state),
                                              'demo_agent_id': 'go-acceptance-endpoint', 'interval_seconds': 5}))
                process = subprocess.run([binary, '--config', str(config), '--simulate', '--once'], capture_output=True, text=True, timeout=30)
                self.assertEqual(process.returncode, 0, process.stderr)
                server = store.get('servers', 'go-acceptance-endpoint')
                self.assertEqual(server['apply_status'], 'preview')
                self.assertEqual(server['applied_version'], 0)
                plan = json.loads((state / 'policy-plan.json').read_text())
                self.assertEqual(plan['capability'], 'preview-only')
                self.assertEqual((state / 'state.json').stat().st_mode & 0o777, 0o600)
                from controller import __version__
                self.assertEqual(server['agent_version'], __version__)
                self.assertIn('agent_polling_config_v1', server['capabilities'])
                self.assertIn('learning_discovery_v1', server['capabilities'])
                session = store.create_session({'server_ids': [server['id']], 'selection_mode': 'discovered'}, 'admin')
                version = store.assignment(server['id'])[0]['version']
                second = subprocess.run([binary, '--config', str(config), '--simulate', '--once'], capture_output=True, text=True, timeout=30)
                self.assertEqual(second.returncode, 0, second.stderr)
                learned = store.get('sessions', session['id'])
                self.assertEqual(learned['discovery_pending_server_ids'], [])
                self.assertEqual(learned['discovery_results'][server['id']]['status'], 'ready')
                self.assertTrue(learned['server_ports'][server['id']])
                assignment = store.assignment(server['id'])[0]
                self.assertEqual(assignment['version'], version)
                self.assertFalse(assignment['learning_sessions'][0]['discovery_pending'])
                self.assertEqual(assignment['learning_sessions'][0]['ports'], learned['server_ports'][server['id']])


if __name__ == '__main__':
    unittest.main(verbosity=2)
