import unittest
from unittest.mock import patch
from controller.auth import MicrosoftProvider,EntraConfig,AuthUnavailable


class AuthLibraryVersionTests(unittest.TestCase):
    def test_old_or_unknown_jwt_version_is_rejected_before_oidc_networking(self):
        try:import jwt
        except ImportError:self.skipTest('PyJWT required')
        config=EntraConfig('11111111-1111-4111-8111-111111111111','22222222-2222-4222-8222-222222222222','https://controller.example/api/v1/auth/callback','fixture-secret')
        for version in ('2.3.0','2.9.9','1.7.1','3.0.0','unknown','2.10.0rc1'):
            with self.subTest(version=version),patch.object(jwt,'__version__',version),patch('controller.auth.build_opener') as transport:
                with self.assertRaisesRegex(AuthUnavailable,'PyJWT >=2.10'):
                    MicrosoftProvider(config)
                transport.assert_not_called()
        with patch.object(jwt,'__version__','2.10.0'):
            self.assertIsNotNone(MicrosoftProvider(config))
