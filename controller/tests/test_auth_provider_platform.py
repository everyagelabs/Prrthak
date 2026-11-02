"""Platform settings distinguish local sessions from directory configuration."""
import tempfile
import types
import unittest
from unittest.mock import patch

from controller import application_port as port, gui_setup
from controller.auth import EntraAuth, EntraConfig
from controller.authentication import Authentication
from controller.firewall import WorkflowConflict
from controller.pki import init_ca
from controller.platform import PlatformManager
from controller.store import Store
from controller.tests import test_application_port as port_fixture
from controller.tests import test_gui_setup as setup_fixture


class AuthenticationPlatformTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.store = Store(temporary.name)
        pki = init_ca(temporary.name)
        self.old, self.new = port_fixture.free_port(), port_fixture.free_port()
        self.origin = 'https://localhost:' + str(self.old)
        self.environment = patch.dict('os.environ', {'CONTROLLER_ORIGIN': self.origin,
                                                   'PRTHAK_APPLIANCE': '0'})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.auth = Authentication(self.store, entra=EntraAuth(self.store, EntraConfig()),
                                   origin=self.origin)
        login = self.auth.local_login({'username': 'admin', 'password': 'admin'},
                                     {'Host': 'localhost:' + str(self.old), 'Origin': self.origin})
        limited = login['principal']
        headers = {'Cookie': login['cookies'][0].split(';', 1)[0], 'Origin': self.origin,
                   'X-CSRF-Token': limited['csrf_token']}
        self.principal = self.auth.change_password({'current_password': 'admin',
                        'new_password': 'Platform-auth-fixture-2026!',
                        'confirm_password': 'Platform-auth-fixture-2026!'}, limited, headers)['principal']
        self.app = types.SimpleNamespace(store=self.store, demo=False,
            controller_id='auth-platform-fixture', site='isolated',
            application_listen='127.0.0.1:' + str(self.old), auth=self.auth, tokens={},
            controller_certificate=pki/'controller.pem', controller_private_key=pki/'controller-key.pem',
            signer=types.SimpleNamespace(ca=pki/'ca.pem', ca_key=pki/'ca-key.pem'))
        self.manager = PlatformManager(temporary.name)
        self.manager.attach(self.app)
        self.manager.local_controller_id(self.app.controller_id, explicit=True)
        port.record_context(self.manager, ['--listen', self.app.application_listen])
        self.client = setup_fixture.ManagerClient()

    def saml_origin(self, origin='https://sso-controller.example.internal:9443'):
        # This is the public origin projection used by the port supervisor, not
        # a login trust fixture. Signature/metadata validation is tested by the
        # independent real-SAML and HTTP configuration suites.
        with self.store.meta() as db:
            self.store._put(db, 'maintenance_settings', {'id': 'saml_configuration',
                'config': {'enabled': True, 'origin': origin}})
        return origin

    def test_local_session_facade_keeps_port_status_and_review_available_without_sso(self):
        self.assertTrue(self.auth.enabled)
        self.assertFalse(self.auth.config.enabled)
        status = port.status(self.manager)
        self.assertTrue(status['can_apply'], status)
        self.assertEqual(status['applied_port'], self.old)
        self.assertIsNone(status['sso_origin'])
        plan = port.preview(self.manager, {'expected_revision': status['revision'], 'port': self.new},
                            self.principal['actor'])
        self.assertTrue(plan['can_apply'], plan)
        self.assertEqual(plan['controller_origin'], self.origin)

    def test_local_facade_saml_origin_is_preserved_in_port_status_and_review(self):
        saml = self.saml_origin()
        status = port.status(self.manager)
        self.assertTrue(status['can_apply'], status)
        self.assertEqual(status['sso_origin'], saml)
        plan = port.preview(self.manager, {'expected_revision': status['revision'], 'port': self.new},
                            self.principal['actor'])
        self.assertEqual(plan['sso_origin'], saml)
        self.assertEqual(plan['origin_mode'], 'preserve')
        self.assertEqual(plan['controller_origin'], self.origin)

    def test_supervisor_without_app_reads_saml_origin_from_the_shared_store(self):
        saml = self.saml_origin()
        self.manager.app = None
        status = port.status(self.manager)
        self.assertTrue(status['can_apply'], status)
        self.assertEqual(status['applied_port'], self.old)
        self.assertEqual(status['sso_origin'], saml)

    def test_changed_saml_origin_invalidates_an_existing_port_review(self):
        self.saml_origin()
        plan = port.preview(self.manager, {'expected_revision': port.status(self.manager)['revision'],
                            'port': self.new}, self.principal['actor'])
        self.saml_origin('https://replacement-sso.example.internal:9443')
        body = {key: plan[key] for key in ('preview_id', 'digest', 'expected_revision',
                                          'confirmation_nonce', 'confirmation_phrase')}
        with self.assertRaises(WorkflowConflict):
            port.apply(self.manager, {**body, 'acknowledge_dependencies': True}, self.principal['actor'])
        self.assertFalse(list((self.manager.root/'jobs').glob('*.json')))

    def test_gui_setup_reports_no_entra_for_local_only_then_actual_entra_configuration(self):
        status = gui_setup.status(self.manager, self.principal, self.client)
        self.assertFalse(status['entra_configured'])
        self.assertFalse(status['convergence_required'])
        self.assertTrue(status['capabilities']['configuration'])
        directory = EntraConfig('11111111-1111-1111-1111-111111111111',
                                '22222222-2222-2222-2222-222222222222',
                                'https://directory-controller.example/api/v1/auth/callback',
                                'private-unit-only-client-secret')
        self.app.auth = Authentication(self.store, entra=EntraAuth(self.store, directory, provider=object()),
                                       origin=self.origin, bootstrap=False)
        status = gui_setup.status(self.manager, self.principal, self.client)
        self.assertTrue(status['entra_configured'])
        self.assertTrue(status['convergence_required'])

    def test_installed_entra_pending_restart_keeps_configuration_guard_with_local_facade(self):
        self.client.state['controller_configuration']['entra_configured'] = True
        status = gui_setup.status(self.manager, self.principal, self.client)
        self.assertTrue(status['entra_configured'])
        self.assertFalse(status['capabilities']['configuration'])
        self.assertTrue(status['blockers'])


if __name__ == '__main__':
    unittest.main()
