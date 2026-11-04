"""Real HTTPS local-password and signed SAML paths; no directory or OS writes."""
import base64
import http.client
import json
import ssl
import tempfile
import unittest
from urllib.parse import parse_qs, quote, urlencode, urlsplit
import zlib

from controller.app import App
from controller.auth import EntraAuth, EntraConfig, SESSION_COOKIE
from controller.authentication import Authentication
from controller.pki import init_ca
from controller.store import Store, digest
from controller.tests import test_saml_auth as saml_fixture
from test_integration import running


class LocalHTTPSAuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(self.temp.name)
        pki = init_ca(self.temp.name)
        server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server.load_cert_chain(pki / 'controller.pem', pki / 'controller-key.pem')
        self.tls = ssl.create_default_context(cafile=str(pki / 'ca.pem'))
        auth = Authentication(self.store, entra=EntraAuth(self.store, EntraConfig()))
        self.app = App(self.store, auth=auth)
        context = running(self.app, server)
        self.port = context.__enter__()
        self.addCleanup(context.__exit__, None, None, None)
        self.origin = 'https://localhost:' + str(self.port)
        self.app.auth.local.origin = self.origin

    def http(self, method, path, body=None, headers=None, *, form=False):
        outgoing = dict(headers or {})
        raw = None
        if body is not None:
            raw = (urlencode(body, doseq=True) if form else json.dumps(body)).encode()
            outgoing['Content-Type'] = 'application/x-www-form-urlencoded' if form else 'application/json'
        conn = http.client.HTTPSConnection('localhost', self.port, context=self.tls, timeout=20)
        conn.request(method, '/api/v1/' + path, raw, outgoing)
        response = conn.getresponse()
        contents = response.read()
        pairs = response.getheaders()
        content_type = response.getheader('Content-Type', '')
        value = json.loads(contents) if contents and 'json' in content_type else contents
        result = response.status, value, dict(pairs), [v for k, v in pairs if k.lower() == 'set-cookie']
        conn.close()
        return result

    def api(self, method, path, body=None, headers=None, expected=200):
        code, value, _, _ = self.http(method, path, body, headers)
        self.assertEqual(code, expected, value)
        return value

    def login(self, username='admin', password='admin'):
        code, auth, _, cookies = self.http('POST', 'auth/local', {'username': username, 'password': password}, {'Origin': self.origin})
        self.assertEqual(code, 200, auth)
        cookie = next(value.split(';', 1)[0] for value in cookies if value.startswith(SESSION_COOKIE + '='))
        return auth, {'Cookie': cookie, 'X-CSRF-Token': auth['csrf_token'], 'Origin': self.origin}, cookies

    def change(self, headers, current, new='Individual-password-014!'):
        code, auth, _, cookies = self.http('POST', 'auth/password',
            {'current_password': current, 'new_password': new, 'confirm_password': new}, headers)
        self.assertEqual(code, 200, auth)
        cookie = next(value.split(';', 1)[0] for value in cookies if value.startswith(SESSION_COOKIE + '='))
        return auth, {'Cookie': cookie, 'X-CSRF-Token': auth['csrf_token'], 'Origin': self.origin}

    def bootstrap(self):
        auth, headers, _ = self.login()
        self.assertTrue(auth['password_change_required'])
        return self.change(headers, 'admin')[1]

    def local_user(self, super_headers, username, role):
        temporary = 'Temporary-for-' + username + '-014!'
        user = self.api('POST', 'access/users', {'provider': 'local', 'username': username,
            'password': temporary, 'role': role, 'display_name': username}, super_headers, 201)
        auth, limited, _ = self.login(username, temporary)
        self.assertTrue(auth['password_change_required'])
        auth, headers = self.change(limited, temporary)
        self.assertFalse(auth['password_change_required'])
        return user, headers

    def report_target(self):
        protection = {'management_sources': ['192.0.2.0/24'], 'ssh_ports': [2022],
            'controller_url': self.origin, 'management_probe_url': self.origin + '/api/v1/agent/enforcement/check', 'zone': 'public'}
        self.store.report('local-auth-target', {'hostname': 'private-target', 'ips': ['192.0.2.10'], 'listeners': [],
            'firewalld_state': 'running', 'capabilities': ['signed_assignments_v1', 'policy_verification_v1'],
            'protection': {**protection, 'digest': digest(protection), 'ready': True, 'blockers': []}})

    def policy(self, headers, port=8443):
        return self.api('POST', 'policies', {'name': 'Authenticated port ' + str(port), 'selector': {}, 'mode': 'enforce',
            'services': [{'protocol': 'tcp', 'port': port, 'sources': ['198.51.100.0/24']}]}, headers, 201)

    def test_bootstrap_is_change_only_and_rotation_replaces_cookie(self):
        config = self.api('GET', 'auth/config')
        self.assertEqual(config['mode'], 'local')
        self.assertTrue(config['local_enabled'])
        auth, limited, cookies = self.login()
        self.assertEqual(auth['role'], 'super_admin')
        self.assertEqual(auth['auth_provider'], 'local')
        self.assertNotIn('_session_id', auth)
        self.assertNotIn('password_hash', json.dumps(auth))
        for flag in ('Secure', 'HttpOnly', 'SameSite=Lax', 'Path=/'):
            self.assertIn(flag, cookies[0])
        for method, path, body in [('GET', 'overview', None), ('GET', 'auth/providers', None),
                                  ('POST', 'enrollment-tokens', {}), ('POST', 'policies', {})]:
            value = self.api(method, path, body, limited, 403)
            self.assertEqual(value['code'], 'password_change_required')
        self.api('POST', 'auth/password', {'current_password': 'admin', 'new_password': 'A-new-password-014!'},
                 {'Cookie': limited['Cookie'], 'Origin': self.origin}, 403)
        auth, full = self.change(limited, 'admin')
        self.assertFalse(auth['password_change_required'])
        self.assertNotEqual(full['Cookie'], limited['Cookie'])
        self.api('GET', 'auth', headers=limited, expected=401)
        self.api('GET', 'overview', headers=full)
        self.api('POST', 'auth/local', {'username': 'admin', 'password': 'admin'}, {'Origin': self.origin}, 403)

    def test_local_roles_super_only_management_reset_and_own_password_for_read_only(self):
        super_headers = self.bootstrap()
        admin, admin_headers = self.local_user(super_headers, 'policy-admin', 'admin')
        reader, read_headers = self.local_user(super_headers, 'observer', 'read_only')
        self.api('GET', 'overview', headers=read_headers)
        for headers in (read_headers, admin_headers):
            self.api('GET', 'access/users', headers=headers, expected=403)
            self.api('POST', 'access/users', {'provider': 'local', 'username': 'forbidden', 'password': 'A-temporary-014!', 'role': 'super_admin'}, headers, 403)
            self.api('POST', 'access/users/' + quote(reader['id'], safe='') + '/reset-password',
                     {'password': 'Reset-temporary-014!'}, headers, 403)
            self.api('PUT', 'auth/providers/saml', {'enabled': False}, headers, 403)
        self.api('POST', 'policies', {}, read_headers, 403)
        self.report_target()
        policy = self.policy(admin_headers)
        self.assertEqual(policy['direct_authorization']['requester']['auth_provider'], 'local')
        self.assertTrue(self.store.assignment('local-auth-target')[0]['enforcement']['authorized'])
        reset = 'Reset-temporary-014!'
        self.api('POST', 'access/users/' + quote(admin['id'], safe='') + '/reset-password',
                 {'password': reset, 'confirm_password': reset}, super_headers)
        self.api('GET', 'auth', headers=admin_headers, expected=401)
        self.assertFalse(self.store.assignment('local-auth-target')[0]['enforcement']['authorized'])
        _, limited, _ = self.login('policy-admin', reset)
        self.api('GET', 'overview', headers=limited, expected=403)
        _, fresh = self.change(limited, reset)
        # A credential reset cannot silently revive the former saved intent.
        self.assertFalse(self.store.assignment('local-auth-target')[0]['enforcement']['authorized'])
        self.api('GET', 'overview', headers=fresh)
        self.api('DELETE', 'policies/' + policy['id'], headers=super_headers)

    def test_builtin_admin_cannot_be_deleted_or_changed_by_another_super_admin(self):
        original = self.bootstrap()
        admin = self.api('GET', 'auth', headers=original)['user']
        self.assertTrue(admin['protected_account'])
        _, other = self.local_user(original, 'second-super', 'super_admin')
        path = 'access/users/' + quote(admin['id'], safe='')
        before = self.store.get('auth_users', admin['id'])
        for changes in ({'enabled': False}, {'role': 'admin'}):
            with self.subTest(changes=changes):
                error = self.api('PATCH', path, changes, other, 409)
                self.assertIn('The built-in admin account is protected', error['error'])
        for changes in ({'display_name': 'Replacement'}, {'email': 'other@example.test'}):
            with self.subTest(changes=changes):
                error = self.api('PATCH', path, changes, other, 403)
                self.assertIn('Sign in as the built-in admin to edit its profile', error['error'])
        # Identity fields are immutable for all users, including the built-in.
        for changes in ({'username': 'replacement'}, {'provider': 'saml'}, {'protected_account': False}):
            with self.subTest(changes=changes):
                self.api('PATCH', path, changes, other, 400)
        # User deletion is intentionally not an API operation: even a direct
        # authenticated DELETE cannot remove the retained protected identity.
        self.api('DELETE', path, headers=other, expected=405)
        self.assertEqual(self.store.get('auth_users', admin['id']), before)
        self.api('GET', 'overview', headers=original)
        temporary = 'Protected-admin-recovery-015!'
        reset = self.api('POST', path + '/reset-password', {'password': temporary, 'confirm_password': temporary}, other)
        self.assertTrue(reset['protected_account'])
        self.api('GET', 'auth', headers=original, expected=401)
        limited, headers, _ = self.login('admin', temporary)
        self.assertTrue(limited['password_change_required'])
        changed, _ = self.change(headers, temporary)
        self.assertTrue(changed['user']['protected_account'])
        self.assertEqual(changed['role'], 'super_admin')

    def test_login_origin_json_and_session_csrf_are_enforced(self):
        self.api('POST', 'auth/local', {'username': 'admin', 'password': 'admin'}, {'Origin': 'https://outside.example'}, 403)
        status, _, _, _ = self.http('POST', 'auth/local', {'username': 'admin', 'password': 'admin'}, form=True)
        self.assertEqual(status, 400)
        headers = self.bootstrap()
        self.api('POST', 'auth/logout', {}, {'Cookie': headers['Cookie'], 'Origin': self.origin}, 403)
        self.api('POST', 'auth/logout', {}, {**headers, 'Origin': 'https://outside.example'}, 403)
        self.api('POST', 'auth/logout', {}, headers)
        self.api('GET', 'overview', headers=headers, expected=401)

    def test_installed_production_accepts_user_sessions_without_legacy_role_token_fallback(self):
        local = self.bootstrap()
        self.store.approval_production = False
        self.app.tokens.update({'super_admin': 'old-super-lab-token', 'admin': 'old-admin-lab-token', 'read_only': 'old-reader-lab-token'})
        self.api('GET', 'auth', headers={'Authorization': 'Bearer old-admin-lab-token'})
        self.store.approval_production = True
        for token in self.app.tokens.values():
            self.api('GET', 'auth', headers={'Authorization': 'Bearer ' + token}, expected=401)
            self.api('GET', 'overview', headers={'Authorization': 'Bearer ' + token}, expected=401)
        self.api('GET', 'auth', headers=local)
        self.api('GET', 'overview', headers=local)

    def test_local_password_repair_remains_available_during_provider_quarantine(self):
        headers = self.bootstrap()
        with self.store.meta() as db:
            self.store._put(db, 'maintenance_settings', {'id': 'controller_provider_authority',
                            'fingerprint': 'a' * 64, 'epoch': 'b' * 32})
        self.api('GET', 'auth', headers=headers)
        self.assertFalse(self.app.readiness()['checks']['provider_authority'])
        self.api('GET', 'overview', headers=headers, expected=403)
        self.api('GET', 'auth/providers', headers=headers)
        _, current = self.change(headers, 'Individual-password-014!', 'Repair-individual-015!')
        self.api('GET', 'auth', headers=current)
        self.api('GET', 'overview', headers=current, expected=403)
        self.api('PUT', 'auth/providers/saml', {'enabled': False, 'expected_revision': 0}, current)

    def test_reviewed_initial_entra_identity_can_bootstrap_alongside_local_users(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from controller.tests import test_auth as fixture
        local = self.bootstrap()
        # The real GUI activation validates this exact candidate before writing
        # its Entra environment. Simulate that installed, reviewed configuration.
        config = EntraConfig(fixture.TENANT, fixture.CLIENT, self.origin + '/api/v1/auth/callback',
                             'private-integration-secret', fixture.SUPER)
        provider = fixture.LocalMicrosoft(config, rsa.generate_private_key(public_exponent=65537, key_size=2048))
        self.app.auth.entra = EntraAuth(self.store, config, provider)
        self.store.approval_auth_fingerprint = config.fingerprint
        self.store.approval_tenant_id = config.tenant_id
        status, _, response, cookies = self.http('GET', 'auth/login')
        self.assertEqual(status, 302)
        callback = provider.issue(response['Location'], fixture.SUPER)
        binding = '; '.join(value.split(';', 1)[0] for value in cookies)
        status, value, _, cookies = self.http('GET', 'auth/callback?' + urlencode(callback, doseq=True), headers={'Cookie': binding})
        self.assertEqual(status, 303, value)
        cookie = next(value.split(';', 1)[0] for value in cookies if value.startswith(SESSION_COOKIE + '='))
        entra = self.api('GET', 'auth', headers={'Cookie': cookie})
        self.assertEqual(entra['auth_provider'], 'entra')
        self.assertEqual(entra['role'], 'super_admin')
        self.api('GET', 'overview', headers=local)
        users = self.api('GET', 'access/users', headers=local)['items']
        self.assertEqual(sorted(user['provider'] for user in users), ['entra', 'local'])


@unittest.skipUnless(saml_fixture.HAS_SAML, 'Install controller SAML dependencies')
class SAMLHTTPSAuthenticationTests(LocalHTTPSAuthenticationTests):
    # Inherit real local transport cases as well as exercising the combined mode.
    def configure(self, headers, enabled=True):
        if not hasattr(self, 'idp_key'):
            self.idp_key, self.idp_cert = saml_fixture.fixture_key()
        body = {'enabled': enabled, 'sp_entity_id': self.origin + '/saml', 'origin': self.origin,
                'idp_metadata_xml': saml_fixture.fixture_metadata(self.idp_cert), 'display_name': 'Test directory SAML',
                'expected_revision': self.api('GET', 'auth/providers', headers=headers)['saml']['revision']}
        result = self.api('PUT', 'auth/providers/saml', body, headers)
        return body, result

    def saml_signin(self, role='read_only', *, headers=None, subject=saml_fixture.SUBJECT):
        if headers:
            self.api('POST', 'access/users', {'provider': 'saml', 'subject': subject, 'role': role}, headers, 201)
        status, _, response, cookies = self.http('GET', 'auth/saml/login')
        self.assertEqual(status, 302)
        params = parse_qs(urlsplit(response['Location']).query)
        from lxml import etree
        request = etree.fromstring(zlib.decompress(base64.b64decode(params['SAMLRequest'][0]), -15))
        xml = saml_fixture.response_xml(request.get('ID'), self.idp_key, self.idp_cert,
            subject=subject, audience=self.origin + '/saml', destination=self.origin + '/api/v1/auth/saml/callback')
        form = {'SAMLResponse': base64.b64encode(xml).decode(), 'RelayState': params['RelayState'][0]}
        binding = '; '.join(cookie.split(';', 1)[0] for cookie in cookies)
        status, value, _, returned = self.http('POST', 'auth/saml/callback', form,
            {'Cookie': binding, 'Origin': saml_fixture.IDP}, form=True)
        self.assertEqual(status, 303, value)
        session = next(cookie.split(';', 1)[0] for cookie in returned if cookie.startswith(SESSION_COOKIE + '='))
        auth = self.api('GET', 'auth', headers={'Cookie': session})
        return auth, {'Cookie': session, 'X-CSRF-Token': auth['csrf_token'], 'Origin': self.origin}, (form, binding)

    def test_saml_and_local_coexist_with_app_roles_and_one_use_post_binding(self):
        local = self.bootstrap()
        body, result = self.configure(local)
        self.assertTrue(result['local']['enabled'])
        self.assertEqual(self.api('GET', 'auth/config')['mode'], 'hybrid')
        status, xml, response, _ = self.http('GET', 'auth/saml/metadata')
        self.assertEqual(status, 200)
        self.assertIn(b'EntityDescriptor', xml)
        self.assertIn('samlmetadata+xml', response['Content-Type'])
        auth, sso, (form, binding) = self.saml_signin(headers=local)
        self.assertEqual(auth['role'], 'read_only')  # Signed directory role says super_admin.
        self.assertEqual(auth['auth_provider'], 'saml')
        self.api('GET', 'overview', headers=sso)
        self.api('POST', 'servers', {}, sso, 403)
        status, _, _, _ = self.http('POST', 'auth/saml/callback', form, {'Cookie': binding}, form=True)
        self.assertEqual(status, 403)
        self.api('GET', 'overview', headers=local)
        self.configure(local, False)
        self.api('GET', 'auth', headers=sso, expected=401)
        self.configure(local)
        self.api('GET', 'auth', headers=sso, expected=401)
        # Restart/facade creation and SSO changes cannot recreate admin/admin.
        self.app.auth = Authentication(self.store, entra=EntraAuth(self.store, EntraConfig()), origin=self.origin)
        self.api('GET', 'overview', headers=local)
        self.api('POST', 'auth/local', {'username': 'admin', 'password': 'admin'}, {'Origin': self.origin}, 403)

    def test_mixed_policy_authors_and_saml_epoch_remain_bound_to_current_provider(self):
        local = self.bootstrap()
        self.configure(local)
        _, sso, _ = self.saml_signin('admin', headers=local)
        self.report_target()
        self.policy(local)
        other = self.policy(sso, 9443)
        self.assertTrue(self.store.assignment('local-auth-target')[0]['enforcement']['authorized'])
        self.configure(local, False)
        self.assertFalse(self.store.assignment('local-auth-target')[0]['enforcement']['authorized'])
        self.configure(local)
        self.assertFalse(self.store.assignment('local-auth-target')[0]['enforcement']['authorized'])
        self.api('DELETE', 'policies/' + other['id'], headers=local)
        self.assertTrue(self.store.assignment('local-auth-target')[0]['enforcement']['authorized'])

    def test_invalid_persisted_saml_configuration_does_not_lock_out_local_repair(self):
        local = self.bootstrap()
        self.configure(local)
        self.app.tokens['admin'] = 'explicit-old-lab-token'
        for invalid in ({'enabled': True, 'idp_metadata_xml': '<invalid>'}, None, [], 'invalid'):
            with self.subTest(invalid=invalid):
                with self.store.meta() as db:
                    value = self.store._get(db, 'maintenance_settings', 'saml_configuration')
                    value['config'] = invalid
                    value['revision'] += 1
                    self.store._put(db, 'maintenance_settings', value)
                providers = self.api('GET', 'auth/providers', headers=local)
                self.assertTrue(providers['local']['enabled'])
                self.assertFalse(providers['saml']['enabled'])
                self.assertTrue(providers['saml']['error'])
                self.api('GET', 'overview', headers=local)
                self.api('GET', 'overview', headers={'Authorization': 'Bearer explicit-old-lab-token'}, expected=401)
        self.api('PUT', 'auth/providers/saml', {'enabled': False,
                 'expected_revision': providers['saml']['revision']}, local)

    def test_stale_provider_revision_is_rejected_without_changing_current_trust(self):
        local = self.bootstrap()
        body, first = self.configure(local)
        with self.store.read_meta() as db:
            before = self.store._get(db, 'maintenance_settings', 'saml_configuration')
        self.api('PUT', 'auth/providers/saml', {**body, 'enabled': False}, local, 409)
        with self.store.read_meta() as db:
            self.assertEqual(self.store._get(db, 'maintenance_settings', 'saml_configuration'), before)
        for bad in (None, True, -1, '1'):
            self.api('PUT', 'auth/providers/saml', {**body, 'expected_revision': bad}, local, 400)
        retained = self.api('PUT', 'auth/providers/saml', {**body, 'idp_metadata_xml': '',
                            'expected_revision': first['saml']['revision']}, local)
        self.assertTrue(retained['saml']['enabled'])

    def test_saml_super_admin_configuration_change_signs_out_only_saml_sessions(self):
        local = self.bootstrap()
        body, _ = self.configure(local)
        _, sso, _ = self.saml_signin('super_admin', headers=local)
        current = self.api('GET', 'auth/providers', headers=sso)['saml']['revision']
        result = self.api('PUT', 'auth/providers/saml', {**body, 'expected_revision': current}, sso)
        self.assertTrue(result['signed_out'])
        self.api('GET', 'auth', headers=sso, expected=401)
        self.api('GET', 'overview', headers=local)
