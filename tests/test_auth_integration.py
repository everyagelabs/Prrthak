"""Real HTTPS and RSA verification with a local Microsoft fixture, never a tenant."""
import http.client
import json
from pathlib import Path
import ssl
import tempfile
import unittest
from urllib.parse import quote, urlencode

from controller.app import App
from controller.auth import EntraAuth, EntraConfig, SESSION_COOKIE, STATE_COOKIE
from controller.pki import Signer, init_ca, run
from controller.store import Store
from controller.tests import test_auth as fixture
from test_integration import running


@unittest.skipUnless(fixture.HAS_CRYPTO, 'Install controller requirements for Entra acceptance')
class EntraHTTPSAcceptanceTests(unittest.TestCase):
    def setUp(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(self.temp.name)
        self.pki = init_ca(self.temp.name)
        server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_tls.load_cert_chain(self.pki / 'controller.pem', self.pki / 'controller-key.pem')
        server_tls.load_verify_locations(self.pki / 'ca.pem')
        server_tls.verify_mode = ssl.CERT_OPTIONAL
        self.client_tls = ssl.create_default_context(cafile=str(self.pki / 'ca.pem'))
        self.app = App(self.store, signer=Signer(self.pki / 'ca.pem', self.pki / 'ca-key.pem'),
                       tokens={'super_admin': 'ignored-legacy-super'})
        context = running(self.app, server_tls)
        self.port = context.__enter__()
        self.addCleanup(context.__exit__, None, None, None)
        self.origin = 'https://localhost:' + str(self.port)
        config = EntraConfig(fixture.TENANT, fixture.CLIENT, self.origin + '/api/v1/auth/callback',
                             'fixture-secret', fixture.SUPER)
        self.provider = fixture.LocalMicrosoft(config, rsa.generate_private_key(public_exponent=65537, key_size=2048))
        self.app.auth = EntraAuth(self.store, config, self.provider)

    def http(self, method, path, body=None, headers=None, tls=None):
        conn = http.client.HTTPSConnection('localhost', self.port, context=tls or self.client_tls, timeout=15)
        outgoing = dict(headers or {})
        encoded = json.dumps(body).encode() if body is not None else None
        if encoded is not None:
            outgoing['Content-Type'] = 'application/json'
        conn.request(method, '/api/v1/' + path, encoded, outgoing)
        response = conn.getresponse()
        data, pairs = response.read(), response.getheaders()
        result = (response.status, json.loads(data) if data else None, dict(pairs),
                  [value for key, value in pairs if key.lower() == 'set-cookie'])
        conn.close()
        return result

    def api(self, method, path, body=None, headers=None, expected=200):
        code, result, _, _ = self.http(method, path, body, headers)
        self.assertEqual(code, expected, result)
        return result

    def signin(self, oid=fixture.SUPER, expected=303, **claims):
        code, _, headers, cookies = self.http('GET', 'auth/login')
        self.assertEqual(code, 302)
        binding = next(cookie.split(';', 1)[0] for cookie in cookies if cookie.startswith(STATE_COOKIE + '='))
        query = self.provider.issue(headers['Location'], oid, **claims)
        status, result, _, returned = self.http('GET', 'auth/callback?' + urlencode(query, doseq=True),
                                               headers={'Cookie': binding})
        self.assertEqual(status, expected, result)
        if expected != 303:
            return None
        self.assertEqual(len(returned), 2)
        for cookie in returned:
            for flag in ('Secure', 'HttpOnly', 'SameSite=Lax', 'Path=/'):
                self.assertIn(flag, cookie)
        session = next(cookie.split(';', 1)[0] for cookie in returned if cookie.startswith(SESSION_COOKIE + '='))
        auth = self.api('GET', 'auth', headers={'Cookie': session})
        self.assertNotIn('_session_id', auth)
        return {'Cookie': session, 'X-CSRF-Token': auth['csrf_token'], 'Origin': self.origin}

    def provision(self, super_headers, oid, role):
        return self.api('POST', 'access/users', {'object_id': oid, 'role': role,
                        'display_name': role + ' user', 'email': role + '@example.internal'},
                        super_headers, 201)

    def test_preprovisioning_three_roles_and_all_user_management_are_super_admin_only(self):
        self.signin(fixture.OTHER, 403, roles=['super_admin'], email='admin@example.internal')
        super_headers = self.signin()
        admin = self.provision(super_headers, fixture.ADMIN, 'admin')
        self.provision(super_headers, fixture.READ, 'read_only')
        admin_headers, read_headers = self.signin(fixture.ADMIN), self.signin(fixture.READ)
        for headers in (admin_headers, read_headers):
            self.api('GET', 'access/users', headers=headers, expected=403)
            for role in ('read_only', 'admin', 'super_admin'):
                self.api('POST', 'access/users', {'object_id': fixture.OTHER, 'role': role}, headers, 403)
            self.api('PATCH', 'access/users/' + quote(admin['id'], safe=''), {'role': 'super_admin'}, headers, 403)
            self.api('POST', 'access/users/' + quote(admin['id'], safe='') + '/revoke-sessions', {}, headers, 403)
        self.api('GET', 'overview', headers=read_headers)
        for path in ('servers', 'policies', 'groups', 'locations', 'metadata/bulk/preview', 'enrollment-tokens'):
            self.api('POST', path, {}, read_headers, 403)
        policy = self.api('POST', 'policies', {'name': 'Named admin policy', 'selector': {}, 'mode': 'monitor',
                         'services': [{'port': 80, 'protocol': 'tcp', 'sources': ['10.90.0.0/24']}]}, admin_headers, 201)
        removed = self.api('DELETE', 'policies/' + policy['id'], headers=admin_headers, expected=200)
        self.assertTrue(removed['deleted'])
        self.assertIn('deployment', removed)
        self.assertEqual(len(self.api('GET', 'access/users', headers=super_headers)['items']), 3)
        audits = self.api('GET', 'audit', headers=super_headers)['items']
        self.assertTrue(any(row['action'] == 'policy.created' and row['actor'] == 'entra:' + admin['id'] for row in audits))

    def test_csrf_logout_disabled_users_and_role_changes_revoke_authority(self):
        super_headers = self.signin()
        admin = self.provision(super_headers, fixture.ADMIN, 'admin')
        admin_headers = self.signin(fixture.ADMIN)
        self.api('POST', 'servers', {'hostname': 'csrf-host'}, {'Cookie': admin_headers['Cookie']}, 403)
        self.api('POST', 'servers', {'hostname': 'csrf-host'}, {**admin_headers, 'Origin': 'https://evil.example'}, 403)
        self.api('PATCH', 'access/users/' + quote(admin['id'], safe=''), {'role': 'read_only'}, super_headers)
        self.api('GET', 'overview', headers=admin_headers, expected=401)
        downgraded = self.signin(fixture.ADMIN)
        self.api('POST', 'servers', {'hostname': 'denied-host'}, downgraded, 403)
        self.api('POST', 'auth/logout', {}, downgraded)
        self.api('GET', 'overview', headers=downgraded, expected=401)
        self.api('PATCH', 'access/users/' + quote(admin['id'], safe=''), {'enabled': False}, super_headers)
        self.signin(fixture.ADMIN, 403)
        self.api('PATCH', 'access/users/' + quote(fixture.TENANT + ':' + fixture.SUPER, safe=''),
                 {'enabled': False}, super_headers, 409)
        self.api('GET', 'auth', headers={'Authorization': 'Bearer ignored-legacy-super'}, expected=401)

    def test_admin_reserved_enrollment_and_retirement_revoke_agent_certificate_identity(self):
        super_headers = self.signin()
        self.provision(super_headers, fixture.ADMIN, 'admin')
        admin_headers = self.signin(fixture.ADMIN)
        reservation = self.api('POST', 'servers', {'hostname': 'reserved-linux', 'ips': ['10.241.1.20']}, admin_headers, 201)
        self.assertEqual(self.api('GET', 'servers', headers=admin_headers)['items'], [])
        token = self.api('POST', 'enrollment-tokens', {'name': 'Bound Linux', 'server_id': reservation['id']}, admin_headers, 201)
        key = Path(self.temp.name) / 'endpoint.key'
        csr = run('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-subj', '/CN=untrusted')
        enrolled = self.api('POST', 'agent/enroll', {'token': token['token'], 'hostname': 'reserved-linux', 'csr': csr}, expected=201)
        self.assertEqual(enrolled['server_id'], reservation['id'])
        self.assertEqual(self.api('GET', 'server-reservations', headers=admin_headers)['items'], [])
        cert = Path(self.temp.name) / 'endpoint.crt'
        cert.write_text(enrolled['certificate'])
        agent_tls = ssl.create_default_context(cafile=str(self.pki / 'ca.pem'))
        agent_tls.load_cert_chain(cert, key)
        self.assertEqual(self.http('GET', 'agent/policy', tls=agent_tls)[0], 200)
        # Human role sessions never grant endpoint reporting/policy identity.
        self.api('GET', 'agent/policy', headers=admin_headers, expected=403)
        plan = self.api('POST', 'servers/' + reservation['id'] + '/delete-preview', {}, admin_headers, 201)
        self.assertTrue(plan['can_delete'])
        self.api('POST', 'servers/' + reservation['id'] + '/delete-confirm',
                 {'plan_id': plan['id'], 'confirmation_nonce': plan['confirmation_nonce']}, admin_headers)
        self.assertEqual(self.http('GET', 'agent/policy', tls=agent_tls)[0], 403)
        self.api('POST', 'agent/enroll', {'token': token['token'], 'hostname': 'reserved-linux', 'csr': csr}, expected=403)

    def test_duplicate_blank_callback_parameters_and_plain_http_signin_are_rejected(self):
        code, _, headers, cookies = self.http('GET', 'auth/login')
        self.assertEqual(code, 302)
        query = self.provider.issue(headers['Location'])
        binding = cookies[0].split(';', 1)[0]
        self.http('GET', 'auth/callback?' + urlencode(query, doseq=True) + '&state=', headers={'Cookie': binding})
        self.assertEqual(self.store.all('auth_users'), [])
        with running(App(self.store, auth=self.app.auth)) as port:
            conn = http.client.HTTPConnection('127.0.0.1', port)
            conn.request('GET', '/api/v1/auth/login')
            response = conn.getresponse()
            self.assertEqual(response.status, 403)
            response.read()
            conn.close()


if __name__ == '__main__':
    unittest.main()
