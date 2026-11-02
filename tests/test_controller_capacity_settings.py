"""Capacity settings cannot bypass appliance validation or protected reinstall."""
import importlib.util
import copy
from contextlib import redirect_stderr, redirect_stdout
from datetime import timedelta
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


manager = load('capacity_appliance_manager', 'deploy/appliance/node_manager.py')
entrypoint = load('capacity_appliance_entrypoint', 'deploy/appliance/controller_entrypoint.py')
fixture = load('capacity_mtls_fixture', 'scripts/benchmark-mtls-fleet.py')


class CapacityConfigurationTests(unittest.TestCase):
    def test_installer_and_runtime_admit_only_bounded_public_pool_settings(self):
        values = {'SEG_HTTP_WORKERS': '2', 'SEG_HTTP_THREADS': '32',
                  'SEG_DB_POOL_META_MAX': '16', 'SEG_DB_POOL_TRAFFIC_MAX': '4', 'SEG_DB_POOL_WAIT_SECONDS': '5'}
        prepared = manager.initial_environment(values)
        self.assertEqual(entrypoint.validate_initial_environment(prepared)['environment'], values)
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'basic.env'
            source.write_text('\n'.join(key + '=' + value for key, value in values.items()))
            source.chmod(0o600)
            parsed = manager.read_env(source)
            self.assertEqual({key: parsed[key] for key in values}, values)

    def test_out_of_bounds_or_noninteger_pools_are_rejected_on_both_sides(self):
        for key, bad_values in [('SEG_DB_POOL_META_MAX', ('0', '65', 'many')),
                                ('SEG_DB_POOL_TRAFFIC_MAX', ('0', '17', '2.5')),
                                ('SEG_DB_POOL_WAIT_SECONDS', ('0', '16', 'infinite'))]:
            for value in bad_values:
                with self.subTest(key=key, value=value):
                    with self.assertRaises(manager.Blocked): manager.initial_environment({key: value})
                    with self.assertRaises(ValueError): entrypoint.validate_initial_environment({key: value})

    def test_reinstall_preserves_pool_settings_and_refuses_silent_replacement(self):
        environment = {'SEG_DB_POOL_META_MAX': '12', 'SEG_DB_POOL_TRAFFIC_MAX': '3', 'SEG_DB_POOL_WAIT_SECONDS': '4'}
        class Engine:
            @staticmethod
            def validate_initial_environment(value): return entrypoint.validate_initial_environment(value)
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(manager.stage_initial_environment(Engine(), directory, {}, {'environment': environment}), environment)
            with self.assertRaisesRegex(manager.Blocked, 'preserves'):
                manager.stage_initial_environment(Engine(), directory, {'SEG_DB_POOL_META_MAX': '13'}, {'environment': environment})
            self.assertFalse(any(Path(directory).iterdir()))


class ChangedPolicyFixtureAssertions(unittest.TestCase):
    def setUp(self):
        self.services = [{'port': 8443, 'protocol': 'tcp', 'sources': ['192.0.2.1/32', '2001:db8::1/128']}]
        self.before = (1, 'old-digest', 'monitor')
        self.policy = {'version': 2, 'digest': 'new-digest', 'services': self.services}

    def test_actual_new_revision_preserves_complete_sources_independent_of_order(self):
        policy = json.loads(json.dumps(self.policy))
        policy['services'][0]['sources'].reverse()
        fixture.verify_changed_policy(policy, self.before, self.services)

    def test_signature_refresh_or_nonadvancing_version_cannot_pass_as_edit(self):
        for changed in ({'version': 1}, {'digest': 'old-digest'}):
            with self.subTest(changed=changed), self.assertRaises(RuntimeError):
                fixture.verify_changed_policy({**self.policy, **changed}, self.before, self.services)

    def test_missing_extra_or_wrong_port_source_matrix_is_rejected(self):
        for services in ([], [{'port': 8443, 'protocol': 'tcp', 'sources': ['192.0.2.1/32']}],
                         [{'port': 8443, 'protocol': 'tcp', 'sources': [*self.services[0]['sources'], '0.0.0.0/0']}],
                         [{'port': 443, 'protocol': 'tcp', 'sources': self.services[0]['sources']}],
                         [self.services[0], self.services[0]]):
            with self.subTest(services=services), self.assertRaises(RuntimeError):
                fixture.verify_changed_policy({**self.policy, 'services': services}, self.before, self.services)


class RetainedHistoryFixtureAssertions(unittest.TestCase):
    def test_expired_history_is_retained_without_becoming_current_agent_authority(self):
        from controller.store import Store
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            store.report('current-host', {'hostname': 'current-host', 'ips': ['192.0.2.10'], 'listeners': []})
            result = fixture.seed_retained_history(store, ['current-host', 'other-host'], 3)
            self.assertEqual(result['expired_sessions'], 3)
            self.assertEqual(result['endpoint_memberships'], 6)
            retained = store.all('sessions')
            self.assertEqual(len(retained), 3)
            self.assertTrue(all(row['status'] == 'expired' and row['server_ids'] == ['current-host', 'other-host'] for row in retained))
            assignment = store.assignment('current-host')[0]
            self.assertEqual(assignment['learning_sessions'], [])
            self.assertEqual(assignment.get('learning_tombstones', []), [])

    def test_history_fixture_refuses_unbounded_preparation(self):
        for count in (-1, 101):
            with self.subTest(count=count), self.assertRaises(ValueError):
                fixture.seed_retained_history(None, [], count)


class PassiveLeaseFixtureAssertions(unittest.TestCase):
    def setUp(self):
        start = fixture.now()
        self.policy = {"server_id": "host-1", "version": 7, "digest": "a" * 64, "mode": "enforce", "services": [{"port": 443, "protocol": "tcp", "mode": "enforce", "sources": ["192.0.2.1/32"]}],
                       "enforcement": {"approval_id": "approval-1", "protection_digest": "b" * 64},
                       "policy_verification": {"schema_version": 1, "id": "lease-1", "deployment_id": "run-1", "server_id": "host-1", "version": 7, "digest": "a" * 64, "approval_id": "approval-1", "protection_digest": "b" * 64, "target_ips_digest": fixture.digest(["198.51.100.2"]), "ports": [{"port": 443, "protocol": "tcp"}], "starts_at": fixture.stamp(start), "expires_at": fixture.stamp(start + timedelta(seconds=600)), "window_seconds": 600}}

    def test_only_exact_current_endpoint_policy_and_ports_qualify_as_lease_delivery(self):
        fixture.verify_observation_lease(self.policy, "host-1", ["198.51.100.2"])
        fixture.verify_observation_lease(self.policy, "host-1", ["198.51.100.2"], "run-1")
        with self.assertRaises(RuntimeError):
            fixture.verify_observation_lease(self.policy, "host-1", ["198.51.100.2"], "previous-bulk-run")
        for change in ({"server_id": "other"}, {"version": 6}, {"digest": "c" * 64}, {"approval_id": "old"}, {"target_ips_digest": "d" * 64}, {"ports": []}, {"ports": [{"port": 22, "protocol": "tcp"}]}, {"ports": [{"port": 443, "protocol": "tcp"}] * 2}, {"window_seconds": 3600}):
            policy = copy.deepcopy(self.policy)
            policy["policy_verification"].update(change)
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                fixture.verify_observation_lease(policy, "host-1", ["198.51.100.2"])

    def test_absent_or_extended_lease_is_not_counted_and_no_witness_is_fabricated(self):
        for lease in ({}, {**self.policy["policy_verification"], "expires_at": fixture.stamp(fixture.now() + timedelta(hours=1))}):
            with self.assertRaises(RuntimeError):
                fixture.verify_observation_lease({**self.policy, "policy_verification": lease}, "host-1", ["198.51.100.2"])
        self.assertNotIn("evidence", self.policy["policy_verification"])


class DirectAuthorityFixtureAssertions(unittest.TestCase):
    def setUp(self):
        self.identity='5000-capacity-host';self.fingerprint='a'*64;self.epoch='b'*64
        actor={'role':'admin','auth_config':self.fingerprint,'user_id':'local-fixture'}
        proof={'scheme':'prthak-maker-checker-v1','mode':'single_admin','stage':'approved',
               'requester':actor,'submitted_by':actor,'approved_by':actor,
               'scope':{'kind':'managed_policy','server_ids':[self.identity]},
               'provider_authority':{'fingerprint':self.fingerprint,'epoch':self.epoch}}
        proof['binding_digest']=fixture.digest(proof)
        self.policy={'version':2,'digest':'changed-policy','enforcement':{'authorized':True,'confirmation_count':1,
            'approved_version':2,'approved_digest':'changed-policy','approval_proof':proof}}

    def test_compact_current_single_admin_scope_is_required(self):
        fixture.verify_direct_authority(self.policy,self.identity,self.fingerprint,self.epoch)
        for changes in ({'authorized':False},{'confirmation_count':2},{'approved_version':1},{'approved_digest':'old'}):
            with self.subTest(changes=changes),self.assertRaises(RuntimeError):
                fixture.verify_direct_authority({**self.policy,'enforcement':{**self.policy['enforcement'],**changes}},self.identity,self.fingerprint,self.epoch)

    def test_wrong_host_epoch_retired_mode_and_tampered_evidence_fail(self):
        base=self.policy['enforcement']['approval_proof']
        for changes in ({'mode':'single_admin_pilot'},{'scope':{'kind':'managed_policy','server_ids':['other']}},
                        {'provider_authority':{'fingerprint':self.fingerprint,'epoch':'old'}},{'binding_digest':'f'*64}):
            with self.subTest(changes=changes),self.assertRaises(RuntimeError):
                fixture.verify_direct_authority({**self.policy,'enforcement':{**self.policy['enforcement'],'approval_proof':{**base,**changes}}},self.identity,self.fingerprint,self.epoch)


class AuthenticationProviderFixtureAssertions(unittest.TestCase):
    def prepare(self, provider):
        from controller.store import Store
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        store = Store(directory.name)
        prepared = fixture.seed_administrative_fixture(store, 'https://127.0.0.1:18443', provider)
        return store, prepared

    def proof_policy(self, prepared):
        subject = copy.deepcopy(prepared['subject'])
        proof = {'scheme':'prthak-maker-checker-v1','mode':'single_admin','stage':'approved',
                 'requester':subject,'submitted_by':subject,'approved_by':subject,
                 'scope':{'kind':'managed_policy','server_ids':['host']},
                 'provider_authority':{'fingerprint':prepared['fingerprint'],'epoch':prepared['epoch']}}
        proof['binding_digest'] = fixture.digest(proof)
        return {'version':2,'digest':'current-policy','enforcement':{'authorized':True,'confirmation_count':1,
                'approved_version':2,'approved_digest':'current-policy','approval_proof':proof}}

    def test_local_fixture_uses_completed_real_credentials_and_exact_version_bound_session(self):
        from controller.authentication import validate_current_principal
        from controller.local_auth import SCRYPT_ALGORITHM
        store, prepared = self.prepare('local')
        principal = prepared['auth'].authenticate(prepared['admin_headers'])
        self.assertEqual(principal['auth_provider'], 'local')
        self.assertEqual(principal['role'], 'admin')
        self.assertFalse(principal['password_change_required'])
        self.assertEqual(prepared['auth'].authenticate(prepared['setup_headers'])['role'], 'super_admin')
        self.assertEqual(prepared['environment'], {})
        self.assertEqual(prepared['epoch'], '')
        self.assertNotIn('Authorization', prepared['admin_headers'])
        self.assertEqual(len(store.all('auth_users')), 2)
        self.assertNotIn('admin', {user['username'] for user in store.all('auth_users')})
        with store.read_meta() as db:
            current = validate_current_principal(store, db, principal)
        self.assertEqual(current['password_hash']['algorithm'], SCRYPT_ALGORITHM)
        self.assertEqual(prepared['subject']['credential_version'], current['credential_version'])
        fixture.verify_direct_authority(self.proof_policy(prepared), 'host', prepared['fingerprint'],
                                        provider='local', expected_subject=prepared['subject'])

    def test_entra_default_fixture_retains_its_original_actor_and_epoch(self):
        store, prepared = self.prepare('entra')
        self.assertTrue(prepared['principal']['actor'].startswith('entra:'))
        self.assertEqual(prepared['subject'].get('auth_provider', 'entra'), 'entra')
        self.assertEqual(prepared['epoch'], prepared['environment']['PRTHAK_PROVIDER_EPOCH'])
        with patch.dict(os.environ, prepared['environment']):
            self.assertEqual(prepared['auth'].authenticate(prepared['admin_headers'])['role'], 'admin')
        fixture.verify_direct_authority(self.proof_policy(prepared), 'host', prepared['fingerprint'], prepared['epoch'],
                                        provider='entra', expected_subject=prepared['subject'])

    @unittest.skipUnless(all(importlib.util.find_spec(name) for name in ('cryptography', 'onelogin', 'xmlsec', 'lxml')),
                         'Install controller/requirements.txt for canonical SAML fixture validation')
    def test_saml_fixture_uses_current_canonical_metadata_epoch_and_individual_subject(self):
        from controller.authentication import provider_fingerprint, validate_current_principal
        store, prepared = self.prepare('saml')
        principal = prepared['auth'].authenticate(prepared['admin_headers'])
        self.assertEqual(principal['auth_provider'], 'saml')
        self.assertEqual(principal['role'], 'admin')
        self.assertEqual(principal['actor'], 'saml:'+principal['user']['id'])
        self.assertEqual(principal['user']['subject'], 'private-capacity-admin')
        self.assertEqual(prepared['environment'], {})
        config = store.get('maintenance_settings', 'saml_configuration')
        self.assertEqual(config['config_digest'], fixture.digest(config['config']))
        self.assertEqual(prepared['fingerprint'], fixture.digest({'configuration_fingerprint': config['configuration_fingerprint'],
                                                                 'epoch': config['epoch']}))
        with store.read_meta() as db:
            self.assertEqual(provider_fingerprint(store, db, 'saml'), prepared['fingerprint'])
            validate_current_principal(store, db, principal)
        fixture.verify_direct_authority(self.proof_policy(prepared), 'host', prepared['fingerprint'],
                                        provider='saml', expected_subject=prepared['subject'])

    def test_provider_substitution_cannot_pass_even_with_a_fresh_binding_digest(self):
        _, prepared = self.prepare('local')
        policy = self.proof_policy(prepared)
        proof = policy['enforcement']['approval_proof']
        subject = {**proof['requester'], 'auth_provider':'entra', 'actor':'entra:'+proof['requester']['user_id']}
        proof.update(requester=subject, submitted_by=subject, approved_by=subject)
        proof['binding_digest'] = fixture.digest({key:value for key,value in proof.items() if key!='binding_digest'})
        with self.assertRaises(RuntimeError):
            fixture.verify_direct_authority(policy, 'host', prepared['fingerprint'], provider='local', expected_subject=prepared['subject'])

    def test_missing_local_credential_version_cannot_be_counted_as_provider_authority(self):
        _, prepared = self.prepare('local')
        policy = self.proof_policy(prepared)
        proof = policy['enforcement']['approval_proof']
        subject = {key:value for key,value in proof['requester'].items() if key!='credential_version'}
        proof.update(requester=subject, submitted_by=subject, approved_by=subject)
        proof['binding_digest'] = fixture.digest({key:value for key,value in proof.items() if key!='binding_digest'})
        with self.assertRaises(RuntimeError):
            fixture.verify_direct_authority(policy, 'host', prepared['fingerprint'], provider='local', expected_subject=subject)

    def test_noncanonical_subject_cannot_pass_an_otherwise_exact_provider_assertion(self):
        _, prepared = self.prepare('local')
        policy = self.proof_policy(prepared)
        proof = policy['enforcement']['approval_proof']
        subject = {**proof['requester'], 'tenant_id':'not-a-canonical-realm'}
        subject['user_id'] = subject['tenant_id']+':'+subject['object_id']
        subject['actor'] = 'local:'+subject['user_id']
        proof.update(requester=subject, submitted_by=subject, approved_by=subject)
        proof['binding_digest'] = fixture.digest({key:value for key,value in proof.items() if key!='binding_digest'})
        with self.assertRaises(RuntimeError):
            fixture.verify_direct_authority(policy, 'host', prepared['fingerprint'], provider='local', expected_subject=subject)


class AuthenticationProviderArgumentAssertions(unittest.TestCase):
    def invoke(self, extra):
        with tempfile.TemporaryDirectory() as directory:
            args = ['benchmark-mtls-fleet.py', '--output', str(Path(directory)/'result.json'), *extra]
            with patch('sys.argv', args), patch.object(fixture, 'run', return_value={
                    'all_http_cycles_succeeded': True, 'all_cycle_targets_met': True}) as run, redirect_stdout(io.StringIO()):
                fixture.main()
            return run.call_args.args[0]

    def test_entra_remains_the_default_single_admin_provider(self):
        self.assertEqual(self.invoke(['--authorization-mode','single-admin']).authentication_provider, 'entra')

    def test_local_and_saml_provider_choices_are_explicit_single_admin_fixtures(self):
        for provider in ('local', 'saml'):
            with self.subTest(provider=provider):
                self.assertEqual(self.invoke(['--authorization-mode','single-admin','--authentication-provider',provider]).authentication_provider, provider)

    def test_unknown_provider_and_selector_without_direct_authority_fail_before_preparation(self):
        for extra in (['--authentication-provider','unknown'], ['--authentication-provider','local'], ['--authentication-provider','saml']):
            with self.subTest(extra=extra), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                self.invoke(extra)
            self.assertEqual(error.exception.code, 2)


if __name__ == '__main__': unittest.main()
