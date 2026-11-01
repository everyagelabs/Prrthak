"""Entra/RBAC tests use locally signed RSA ID tokens; no Microsoft traffic."""
from datetime import timedelta
import hashlib
import importlib.util
import json
from pathlib import Path
import secrets
import tempfile
import time
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from controller.auth import (AuthConflict, AuthDenied, AuthUnavailable, EntraAuth, EntraConfig,
    MicrosoftProvider, ROLES, SESSION_COOKIE, SESSION_SECONDS, STATE_COOKIE, STATE_SECONDS,
    _b64, initialize)
from controller.store import Store, now, stamp


TENANT = '11111111-1111-1111-1111-111111111111'
CLIENT = '22222222-2222-2222-2222-222222222222'
SUPER = '33333333-3333-3333-3333-333333333333'
ADMIN = '44444444-4444-4444-4444-444444444444'
READ = '55555555-5555-5555-5555-555555555555'
OTHER = '66666666-6666-6666-6666-666666666666'
LEGACY_SUPER = {'role': 'super_admin', 'actor': 'bootstrap-token', 'auth_type': 'token', 'user': None}
HAS_CRYPTO = bool(importlib.util.find_spec('jwt') and importlib.util.find_spec('cryptography'))


class EntraConfigTests(unittest.TestCase):
    def test_unconfigured_mode_needs_no_oidc_runtime_and_status_exposes_no_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            with store.meta() as db:
                initialize(db)
            auth = EntraAuth(store, EntraConfig())
            self.assertFalse(auth.enabled)
            self.assertEqual(auth.status()['mode'], 'tokens')
            self.assertIsNone(auth.authenticate({'Cookie': SESSION_COOKIE + '=' + secrets.token_urlsafe(32)}))
            with self.assertRaises(AuthUnavailable):
                auth.begin_login({})

    def test_partial_wildcard_tenant_and_noncanonical_redirect_configuration_fail(self):
        with self.assertRaises(ValueError):
            EntraConfig.from_env({'SEG_ENTRA_TENANT_ID': TENANT})
        for tenant in ('common', 'organizations', 'consumers', 'tenant.invalid'):
            with self.subTest(tenant=tenant), self.assertRaises(ValueError):
                EntraConfig(tenant, CLIENT, 'https://prthak.example/api/v1/auth/callback', 'private-secret')
        for uri in ('http://prthak.example/api/v1/auth/callback',
                    'https://user:pass@prthak.example/api/v1/auth/callback',
                    'https://prthak.example/other',
                    'https://prthak.example/api/v1/auth/callback?return=https://outside.example',
                    'https://prthak.example/api/v1/auth/callback#fragment',
                    'https://prthak.example:invalid/api/v1/auth/callback'):
            with self.subTest(uri=uri), self.assertRaises(ValueError):
                EntraConfig(TENANT, CLIENT, uri, 'private-secret')

    def test_secret_file_is_private_and_secret_is_not_in_repr_or_public_status(self):
        with tempfile.TemporaryDirectory() as directory:
            secret_file = Path(directory) / 'secret'
            secret_file.write_text('private-client-secret\n')
            secret_file.chmod(0o644)
            env = {'SEG_ENTRA_TENANT_ID': TENANT, 'SEG_ENTRA_CLIENT_ID': CLIENT,
                   'SEG_ENTRA_REDIRECT_URI': 'https://prthak.example/api/v1/auth/callback',
                   'SEG_ENTRA_CLIENT_SECRET_FILE': str(secret_file), 'SEG_BOOTSTRAP_SUPER_ADMIN_OID': SUPER}
            with self.assertRaises(ValueError):
                EntraConfig.from_env(env)
            secret_file.chmod(0o600)
            config = EntraConfig.from_env(env)
            self.assertEqual(config.client_secret, 'private-client-secret')
            self.assertNotIn(config.client_secret, repr(config))
            self.assertNotIn(config.bootstrap_oid, json.dumps(EntraAuth(Store(directory), config, provider=object()).status()))
            self.assertNotIn(config.client_secret, json.dumps(EntraAuth(Store(directory), config, provider=object()).status()))
            with self.assertRaises(ValueError):
                EntraConfig.from_env({**env, 'SEG_ENTRA_CLIENT_SECRET': 'another-secret'})


if HAS_CRYPTO:
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa

    class LocalMicrosoft(MicrosoftProvider):
        """Actual verification, fake bounded HTTPS responses and one-use codes."""
        def __init__(self, config, private_key):
            self.private_key = private_key
            self.codes = {}
            self.requested_urls = []
            self.exchanges = 0
            self.kid = 'fixture-key'
            self.token_transform = lambda token: token
            self.discovery_overrides = {}
            super().__init__(config)

        def issue(self, authorization, object_id=SUPER, **changes):
            params = parse_qs(urlsplit(authorization).query)
            code = secrets.token_urlsafe(24)
            issued = int(time.time())
            claims = {'iss': self.config.issuer, 'aud': self.config.client_id, 'sub': 'pairwise-' + object_id,
                      'tid': self.config.tenant_id, 'oid': object_id, 'nonce': params['nonce'][0],
                      'iat': issued, 'nbf': issued, 'exp': issued + 3600,
                      'name': 'Directory test user', 'preferred_username': 'directory@example.internal', **changes}
            token = jwt.encode(claims, self.private_key, algorithm='RS256', headers={'kid': self.kid})
            self.codes[code] = {'token': self.token_transform(token), 'challenge': params['code_challenge'][0]}
            return {'state': params['state'], 'code': [code]}

        def _json(self, url, data=None, maximum=1024 * 1024):
            self.requested_urls.append(url)
            base = 'https://login.microsoftonline.com/' + self.config.tenant_id
            if url.endswith('/.well-known/openid-configuration'):
                return {'issuer': self.config.issuer, 'authorization_endpoint': base + '/oauth2/v2.0/authorize',
                        'token_endpoint': base + '/oauth2/v2.0/token',
                        'jwks_uri': base + '/discovery/v2.0/keys', **self.discovery_overrides}
            if url.endswith('/keys'):
                jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.private_key.public_key()))
                return {'keys': [{**jwk, 'kid': self.kid, 'alg': 'RS256', 'use': 'sig'}]}
            if url.endswith('/token'):
                self.exchanges += 1
                params = parse_qs(data.decode())
                if params.get('client_secret') != [self.config.client_secret] or params.get('redirect_uri') != [self.config.redirect_uri]:
                    raise AssertionError('Wrong confidential-client or redirect binding')
                fixture = self.codes.pop(params['code'][0])
                if _b64(hashlib.sha256(params['code_verifier'][0].encode()).digest()) != fixture['challenge']:
                    raise AuthDenied('PKCE did not match')
                return {'id_token': fixture['token'], 'access_token': 'unused-access-token'}
            raise AssertionError('Unexpected provider endpoint')


@unittest.skipUnless(HAS_CRYPTO, 'Install controller/requirements.txt for signed Entra ID-token tests')
class EntraAuthenticationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(self.temp.name)
        with self.store.meta() as db:
            initialize(db)
        self.config = EntraConfig(TENANT, CLIENT, 'https://prthak.example/api/v1/auth/callback',
                                  'private-client-secret', SUPER)
        self.provider = LocalMicrosoft(self.config, self.private_key)
        self.auth = EntraAuth(self.store, self.config, self.provider)

    def begin(self):
        start = self.auth.begin_login({})
        binding = {'Cookie': start['cookies'][0].split(';', 1)[0]}
        return start, binding

    def login(self, object_id=SUPER, **claims):
        start, binding = self.begin()
        result = self.auth.callback(self.provider.issue(start['location'], object_id, **claims), binding)
        session_cookie = next(cookie.split(';', 1)[0] for cookie in result['cookies'] if cookie.startswith(SESSION_COOKIE + '='))
        return {**result, 'headers': {'Cookie': session_cookie}}

    def add(self, object_id, role, **extra):
        return self.auth.create_user({'object_id': object_id, 'role': role, **extra}, LEGACY_SUPER)

    def test_authorization_code_pkce_nonce_browser_binding_and_hashed_durable_session(self):
        start, binding = self.begin()
        params = parse_qs(urlsplit(start['location']).query)
        self.assertEqual(params['response_type'], ['code'])
        self.assertEqual(params['code_challenge_method'], ['S256'])
        self.assertEqual(params['scope'], ['openid profile email'])
        self.assertIn('Secure; HttpOnly; SameSite=Lax', start['cookies'][0])
        result = self.auth.callback(self.provider.issue(start['location']), binding)
        self.assertEqual(result['principal']['role'], 'super_admin')
        self.assertEqual(result['principal']['actor'], 'entra:' + TENANT + ':' + SUPER)
        self.assertEqual(result['location'], '/overview')
        self.assertEqual(len(self.store.all('auth_users')), 1)
        state = self.store.all('auth_states')[0]
        self.assertTrue(state['consumed'])
        self.assertNotIn('verifier', state)
        self.assertNotIn(params['state'][0], json.dumps(state))
        self.assertNotIn(params['nonce'][0], json.dumps(state))
        session_raw = result['cookies'][1].split(';', 1)[0].split('=', 1)[1]
        self.assertNotIn(session_raw, json.dumps(self.store.all('auth_sessions')))
        self.assertEqual(self.auth.status()['roles'], list(ROLES))
        self.assertEqual(self.auth.status()['session_seconds'], 28800)
        actions = [item['action'] for item in self.store.all('audit')]
        self.assertIn('access.user.bootstrapped', actions)
        self.assertIn('auth.login.succeeded', actions)

    def test_new_directory_user_and_role_claims_cannot_self_provision(self):
        for role in ('Prthak.SuperAdmin', 'admin', 'super_admin'):
            start, binding = self.begin()
            with self.subTest(role=role), self.assertRaises(AuthDenied):
                self.auth.callback(self.provider.issue(start['location'], OTHER, roles=[role], groups=[SUPER]), binding)
        self.assertEqual(self.store.all('auth_users'), [])
        self.assertEqual(self.store.all('auth_sessions'), [])
        self.assertEqual(len([event for event in self.store.all('audit') if event['action'] == 'auth.login.denied']), 3)

    def test_bootstrap_requires_exact_oid_and_empty_table(self):
        self.add(OTHER, 'read_only')
        start, binding = self.begin()
        with self.assertRaises(AuthDenied):
            self.auth.callback(self.provider.issue(start['location'], SUPER), binding)
        self.assertEqual([user['object_id'] for user in self.store.all('auth_users')], [OTHER])

    def test_state_is_browser_bound_single_use_expiring_and_retained_across_restart(self):
        start, binding = self.begin()
        query = self.provider.issue(start['location'])
        with self.assertRaises(AuthDenied):
            self.auth.callback(query, {'Cookie': STATE_COOKIE + '=' + secrets.token_urlsafe(32)})
        self.assertEqual(self.provider.exchanges, 0)
        second = EntraAuth(Store(self.temp.name), self.config, self.provider)
        second.callback(query, binding)
        with self.assertRaises(AuthDenied):
            self.auth.callback(query, binding)
        self.assertEqual(self.provider.exchanges, 1)
        start, binding = self.begin()
        with patch('controller.auth.now', return_value=now() + timedelta(seconds=STATE_SECONDS + 1)):
            with self.assertRaises(AuthDenied):
                self.auth.callback(self.provider.issue(start['location']), binding)

    def test_duplicate_callback_parameters_missing_state_error_and_nonce_fail_closed(self):
        start, binding = self.begin()
        query = self.provider.issue(start['location'])
        with self.assertRaises(AuthDenied):
            self.auth.callback({**query, 'code': query['code'] * 2}, binding)
        with self.assertRaises(AuthDenied):
            self.auth.callback({'code': query['code']}, binding)
        with self.assertRaises(AuthDenied):
            self.auth.callback({**query, 'error': ['access_denied']}, binding)
        self.assertEqual(self.provider.exchanges, 0)
        start, binding = self.begin()
        with self.assertRaises(AuthDenied):
            self.auth.callback(self.provider.issue(start['location'], nonce='wrong-nonce'), binding)
        self.assertEqual(self.store.all('auth_sessions'), [])

    def test_signed_wrong_issuer_audience_tenant_expiry_iat_and_missing_claims_reject(self):
        overrides = [{'iss': 'https://login.microsoftonline.com/common/v2.0'}, {'aud': OTHER},
                     {'aud': [CLIENT]}, {'tid': OTHER}, {'oid': 'not-an-object-id'},
                     {'exp': int(time.time()) - 120}, {'iat': int(time.time()) + 120}, {'sub': None}]
        for changed in overrides:
            start, binding = self.begin()
            with self.subTest(changed=changed), self.assertRaises(AuthDenied):
                self.auth.callback(self.provider.issue(start['location'], **changed), binding)
        self.assertEqual(self.store.all('auth_users'), [])
        self.assertEqual(self.store.all('auth_sessions'), [])

    def test_signed_id_tokens_require_finite_numeric_dates_and_valid_not_before(self):
        cases = [{'iat': True}, {'iat': str(int(time.time()))},
                 {'exp': str(int(time.time()) + 3600)}, {'nbf': True},
                 {'nbf': int(time.time()) + 120}, {'exp': None}, {'nonce': None}, {'oid': None}]
        for claims in cases:
            start, binding = self.begin()
            with self.subTest(claims=claims), self.assertRaises(AuthDenied):
                self.auth.callback(self.provider.issue(start['location'], **claims), binding)
        self.assertEqual(self.store.all('auth_users'), [])
        self.assertEqual(self.store.all('auth_sessions'), [])

    def test_hmac_algorithm_confusion_cannot_replace_microsoft_rsa_signature(self):
        self.provider.token_transform = lambda token: jwt.encode(
            jwt.decode(token, options={'verify_signature': False}), key='attacker-selected-HMAC-secret-long-enough',
            algorithm='HS256', headers={'kid': self.provider.kid})
        start, binding = self.begin()
        with self.assertRaises(AuthDenied):
            self.auth.callback(self.provider.issue(start['location']), binding)
        self.assertEqual(self.store.all('auth_users'), [])
        self.assertEqual(self.store.all('auth_sessions'), [])

    def test_signature_tampering_untrusted_jwks_url_and_unsigned_token_reject(self):
        start, binding = self.begin()
        query = self.provider.issue(start['location'])
        fixture = self.provider.codes[query['code'][0]]
        parts = fixture['token'].split('.')
        claims = jwt.decode(fixture['token'], options={'verify_signature': False})
        claims['oid'] = OTHER
        parts[1] = _b64(json.dumps(claims).encode())
        fixture['token'] = '.'.join(parts)
        with self.assertRaises(AuthDenied):
            self.auth.callback(query, binding)
        self.provider.token_transform = lambda token: jwt.encode(
            jwt.decode(token, options={'verify_signature': False}), key='', algorithm='none')
        start, binding = self.begin()
        with self.assertRaises(AuthDenied):
            self.auth.callback(self.provider.issue(start['location']), binding)
        poisoned = LocalMicrosoft(self.config, self.private_key)
        poisoned.discovery_overrides = {'jwks_uri': 'https://attacker.invalid/keys'}
        with self.assertRaises(AuthUnavailable):
            EntraAuth(self.store, self.config, poisoned).begin_login({})
        self.assertFalse(any('attacker.invalid' in url for url in poisoned.requested_urls))

    def test_signing_key_rotation_refreshes_trusted_keys_and_endpoint_poisoning_never_sends_secret(self):
        self.login()
        old_key_reads = sum(url.endswith('/keys') for url in self.provider.requested_urls)
        self.provider.kid = 'rotated-fixture-key'
        rotated = self.login()
        self.assertEqual(rotated['principal']['role'], 'super_admin')
        self.assertGreater(sum(url.endswith('/keys') for url in self.provider.requested_urls), old_key_reads)
        poisoned = LocalMicrosoft(self.config, self.private_key)
        poisoned.discovery_overrides = {'token_endpoint': 'https://attacker.invalid/token'}
        with self.assertRaises(AuthUnavailable):
            EntraAuth(self.store, self.config, poisoned).begin_login({})
        self.assertEqual(poisoned.requested_urls,
                         ['https://login.microsoftonline.com/' + TENANT + '/v2.0/.well-known/openid-configuration'])

    def test_old_tenant_superadmins_cannot_satisfy_last_current_tenant_guard(self):
        logged = self.login()
        other_tenant = '77777777-7777-7777-7777-777777777777'
        foreign = {**self.store.all('auth_users')[0], 'id': other_tenant + ':' + OTHER,
                   'tenant_id': other_tenant, 'object_id': OTHER}
        with self.store.meta() as db:
            self.store._put(db, 'auth_users', foreign)
        with self.assertRaises(AuthConflict):
            self.auth.update_user(TENANT + ':' + SUPER, {'enabled': False}, LEGACY_SUPER)
        with self.assertRaises(AuthDenied):
            self.auth.update_user(foreign['id'], {'role': 'admin'}, logged['principal'])

    def test_session_expiry_disabled_role_changes_and_revoke_take_effect_immediately(self):
        self.add(ADMIN, 'admin')
        logged = self.login(ADMIN)
        headers = logged['headers']
        principal = self.auth.authenticate(headers)
        self.assertEqual(principal['role'], 'admin')
        with patch('controller.auth.now', return_value=now() + timedelta(seconds=SESSION_SECONDS + 1)):
            self.assertIsNone(self.auth.authenticate(headers))
        changed = self.auth.update_user(TENANT + ':' + ADMIN, {'role': 'read_only'}, LEGACY_SUPER)
        self.assertEqual(changed['revoked_sessions'], 1)
        self.assertIsNone(self.auth.authenticate(headers))
        logged = self.login(ADMIN)
        self.assertEqual(logged['principal']['role'], 'read_only')
        self.auth.update_user(TENANT + ':' + ADMIN, {'enabled': False}, LEGACY_SUPER)
        self.assertIsNone(self.auth.authenticate(logged['headers']))
        with self.assertRaises(AuthDenied):
            self.login(ADMIN)
        self.auth.update_user(TENANT + ':' + ADMIN, {'enabled': True}, LEGACY_SUPER)
        logged = self.login(ADMIN)
        result = self.auth.revoke_sessions(TENANT + ':' + ADMIN, LEGACY_SUPER)
        self.assertEqual(result['revoked_sessions'], 1)
        self.assertIsNone(self.auth.authenticate(logged['headers']))

    def test_cookie_mutation_and_logout_require_session_csrf_and_same_origin(self):
        logged = self.login()
        headers, principal = logged['headers'], logged['principal']
        with self.assertRaises(AuthDenied):
            self.auth.require_csrf(headers, principal)
        with self.assertRaises(AuthDenied):
            self.auth.logout(headers)
        good = {**headers, 'X-CSRF-Token': principal['csrf_token'], 'Origin': self.config.origin}
        self.auth.require_csrf(good, principal)
        with self.assertRaises(AuthDenied):
            self.auth.require_csrf({**good, 'Origin': 'https://outside.example'}, principal)
        cleared = self.auth.logout(good)
        self.assertTrue(all('Max-Age=0' in cookie for cookie in cleared['cookies']))
        self.assertIsNone(self.auth.authenticate(headers))

    def test_only_superadmin_can_create_any_role_list_update_or_revoke(self):
        self.add(ADMIN, 'admin')
        for role in ('read_only', 'admin'):
            principal = {'role': role, 'actor': 'unprivileged', 'auth_type': 'token'}
            for requested in ROLES:
                with self.subTest(role=role, requested=requested), self.assertRaises(AuthDenied):
                    self.auth.create_user({'object_id': OTHER, 'role': requested}, principal)
            for operation in (lambda: self.auth.list_users(principal),
                              lambda: self.auth.update_user(TENANT + ':' + ADMIN, {'role': 'super_admin'}, principal),
                              lambda: self.auth.revoke_sessions(TENANT + ':' + ADMIN, principal)):
                with self.assertRaises(AuthDenied):
                    operation()
        super_login = self.login(ADMIN)
        with self.assertRaises(AuthDenied):
            self.auth.create_user({'object_id': OTHER, 'role': 'super_admin'}, super_login['principal'])
        self.assertEqual(len(self.store.all('auth_users')), 1)

    def test_last_superadmin_self_role_tenant_mutation_and_duplicate_user_are_guarded(self):
        logged = self.login()
        identifier = TENANT + ':' + SUPER
        with self.assertRaises(AuthConflict):
            self.auth.update_user(identifier, {'role': 'admin'}, logged['principal'])
        with self.assertRaises(AuthConflict):
            self.auth.update_user(identifier, {'enabled': False}, LEGACY_SUPER)
        with self.assertRaises(AuthConflict):
            self.add(SUPER, 'read_only')
        with self.assertRaises(ValueError):
            self.auth.update_user(identifier, {'object_id': OTHER}, logged['principal'])
        with self.assertRaises(ValueError):
            self.auth.create_user({'object_id': OTHER, 'role': 'operator'}, logged['principal'])
        self.add(OTHER, 'super_admin')
        changed = self.auth.update_user(identifier, {'role': 'admin'}, LEGACY_SUPER)
        self.assertEqual(changed['role'], 'admin')
        with self.assertRaises(AuthDenied):
            self.auth.create_user({'object_id': READ, 'role': 'admin'}, logged['principal'])

    def test_rejected_last_superadmin_and_self_demotion_leave_all_authority_rows_unchanged(self):
        logged = self.login()
        before = {table: self.store.all(table) for table in ('auth_users', 'auth_sessions')}
        identifier = TENANT + ':' + SUPER
        for changes, principal in [({'enabled': False}, LEGACY_SUPER),
                                   ({'role': 'read_only'}, LEGACY_SUPER),
                                   ({'role': 'admin'}, logged['principal']),
                                   ({'enabled': False}, logged['principal'])]:
            with self.subTest(changes=changes), self.assertRaises(AuthConflict):
                self.auth.update_user(identifier, changes, principal)
            self.assertEqual({table: self.store.all(table) for table in before}, before)
            self.assertEqual(self.auth.authenticate(logged['headers'])['role'], 'super_admin')

    def test_audit_has_named_before_after_without_passwords_tokens_or_identity_by_email(self):
        logged = self.login()
        user = self.auth.create_user({'object_id': ADMIN, 'role': 'read_only',
                                     'display_name': 'Administrator', 'email': 'directory@example.internal'}, logged['principal'])
        self.auth.update_user(user['id'], {'role': 'admin'}, logged['principal'])
        events = self.store.all('audit')
        changed = next(event for event in events if event['action'] == 'access.user.updated')
        self.assertEqual(changed['actor'], 'entra:' + TENANT + ':' + SUPER)
        self.assertEqual(changed['details']['before']['role'], 'read_only')
        self.assertEqual(changed['details']['after']['role'], 'admin')
        # An identical email or claimed app role cannot select a different object.
        with self.assertRaises(AuthDenied):
            self.login(OTHER, email='directory@example.internal', roles=['super_admin'])
        for secret in (self.config.client_secret, logged['headers']['Cookie'].split('=', 1)[1], 'unused-access-token'):
            self.assertNotIn(secret, json.dumps(events))

    def test_configuration_change_duplicate_cookie_and_unknown_session_fail_closed(self):
        logged = self.login()
        self.assertIsNone(self.auth.authenticate({'Cookie': logged['headers']['Cookie'] + '; ' + logged['headers']['Cookie']}))
        self.assertIsNone(self.auth.authenticate({'Cookie': SESSION_COOKIE + '=' + secrets.token_urlsafe(32)}))
        changed = EntraConfig(TENANT, CLIENT, 'https://other.example/api/v1/auth/callback', 'private-client-secret')
        other_auth = EntraAuth(self.store, changed, self.provider)
        self.assertIsNone(other_auth.authenticate(logged['headers']))


if __name__ == '__main__':
    unittest.main()
