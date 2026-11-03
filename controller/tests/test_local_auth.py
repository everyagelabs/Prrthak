"""Local credentials, forced change and cross-provider application authority."""
from datetime import timedelta
import copy
import json
import secrets
import tempfile
import threading
import unittest
from unittest.mock import patch

from controller.auth import (AuthConflict, AuthDenied, AuthUnavailable, EntraAuth, EntraConfig,
                             SESSION_COOKIE)
from controller.authentication import Authentication, validate_current_principal
from controller.local_auth import (ATTEMPT_SECONDS, LOGIN_ERROR, REALM_ID, SCRYPT_ALGORITHM,
                                   hash_password, verify_password)
from controller.store import Store, now, stamp


ORIGIN = "https://prthak.example.internal"
PASSWORD = "Pilot passphrase alpha 2026"
SECOND_PASSWORD = "Pilot passphrase beta 2026"
TEMP_PASSWORD = "Temporary password for pilot"


def cookie(result):
    return {"Cookie": result["cookies"][0].split(";", 1)[0]}


class LocalAuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(self.temp.name)
        self.auth = Authentication(self.store, entra=EntraAuth(self.store, EntraConfig()), origin=ORIGIN)
        self.headers = {"Host": "prthak.example.internal", "Origin": ORIGIN}

    def login(self, name="admin", password="admin"):
        return self.auth.local_login({"username": name, "password": password}, self.headers)

    def complete(self, result, old="admin", new=PASSWORD):
        return self.auth.change_password({"current_password": old, "new_password": new, "confirm_password": new},
                                         result["principal"], {**self.headers, "X-CSRF-Token": result["principal"]["csrf_token"]})

    def super(self):
        return self.complete(self.login())["principal"]

    def create(self, principal, username="operator", role="admin"):
        return self.auth.create_user({"provider": "local", "username": username,
                                      "password": TEMP_PASSWORD, "role": role, "display_name": "Pilot operator"}, principal)

    def test_bootstrap_is_a_limited_super_admin_until_own_password_changes(self):
        first = self.login()
        principal = first["principal"]
        self.assertEqual(principal["role"], "super_admin")
        self.assertTrue(principal["password_change_required"])
        self.assertEqual(principal["auth_provider"], "local")
        self.assertTrue(principal["actor"].startswith("local:"))
        self.assertIn("Secure; HttpOnly; SameSite=Lax", first["cookies"][0])
        self.assertIn("Max-Age=600", first["cookies"][0])
        with self.store.read_meta() as db, self.assertRaises(AuthDenied):
            validate_current_principal(self.store, db, principal)
        with self.assertRaises(AuthDenied):
            self.auth.list_users(principal)
        with self.assertRaises(AuthDenied):
            self.create(principal)
        self.assertEqual(self.auth.authenticate(cookie(first))["user"]["username"], "admin")
        second = self.complete(first)
        self.assertFalse(second["principal"]["password_change_required"])
        self.assertIsNone(self.auth.authenticate(cookie(first)))
        self.assertIn("Max-Age=28800", second["cookies"][0])
        with self.store.read_meta() as db:
            self.assertEqual(validate_current_principal(self.store, db, second["principal"])["role"], "super_admin")
        with self.assertRaisesRegex(AuthDenied, LOGIN_ERROR):
            self.login()

    def test_credentials_are_salted_hashes_and_never_public_or_audited(self):
        principal = self.super()
        account = self.create(principal)
        record = self.store.get("auth_users", account["id"])
        self.assertEqual(record["password_hash"]["algorithm"], SCRYPT_ALGORITHM)
        self.assertTrue(verify_password(TEMP_PASSWORD, record["password_hash"]))
        self.assertFalse(verify_password(PASSWORD, record["password_hash"]))
        self.assertNotIn("password_hash", account)
        self.assertNotIn("credential_version", account)
        exposed = json.dumps(self.auth.list_users(principal)) + json.dumps(self.store.all("audit")) + json.dumps(self.auth.status())
        self.assertNotIn(PASSWORD, exposed)
        self.assertNotIn(TEMP_PASSWORD, exposed)
        self.assertNotIn(record["password_hash"]["digest"], exposed)
        self.assertNotIn(record["password_hash"]["salt"], exposed)
        self.assertNotEqual(hash_password(PASSWORD), hash_password(PASSWORD))

    def test_builtin_admin_has_durable_protected_identity_and_only_password_changes(self):
        principal = self.super()
        admin_id = principal["user"]["id"]
        self.assertTrue(principal["user"]["protected_account"])
        self.assertEqual(self.store.get("maintenance_settings", REALM_ID)["bootstrap_user_id"], admin_id)
        other = self.create(principal, "second-super", "super_admin")
        second = self.complete(self.login(other["username"], TEMP_PASSWORD), TEMP_PASSWORD, SECOND_PASSWORD)["principal"]
        before = self.store.get("auth_users", admin_id)
        for changes in ({"enabled": False}, {"role": "read_only"}, {"role": "admin"},
                        {"display_name": "Replacement"}, {"email": "replacement@example.test"},
                        {"role": "super_admin", "enabled": True}):
            with self.subTest(changes=changes), self.assertRaisesRegex(AuthConflict, "built-in admin account is protected"):
                self.auth.update_user(admin_id, changes, second)
        for changes in ({"username": "replacement"}, {"provider": "saml"}, {"protected_account": False}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.auth.update_user(admin_id, changes, second)
        self.assertEqual(self.store.get("auth_users", admin_id), before)
        self.assertTrue(next(user for user in self.auth.list_users(second)["items"] if user["id"] == admin_id)["protected_account"])
        # The protection is specific to the seeded account, not every Super Admin.
        self.auth.update_user(other["id"], {"display_name": "Second administrator"}, principal)
        self.assertEqual(self.store.get("auth_users", other["id"])["display_name"], "Second administrator")

    def test_prior_seeded_install_backfills_protection_without_changing_credentials(self):
        principal = self.super()
        identifier = principal["user"]["id"]
        original = self.store.get("auth_users", identifier)
        with self.store.meta() as db:
            realm = self.store._get(db, "maintenance_settings", REALM_ID)
            realm.pop("bootstrap_user_id")
            self.store._put(db, "maintenance_settings", realm)
            user = self.store._get(db, "auth_users", identifier)
            user.pop("protected_account")
            self.store._put(db, "auth_users", user)
        restarted = Authentication(self.store, entra=EntraAuth(self.store, EntraConfig()), origin=ORIGIN)
        migrated = self.store.get("auth_users", identifier)
        self.assertEqual(migrated, {**original, "protected_account": True})
        self.assertEqual(self.store.get("maintenance_settings", REALM_ID)["bootstrap_user_id"], identifier)
        self.assertTrue(restarted.local_login({"username": "admin", "password": PASSWORD}, self.headers)["principal"]["user"]["protected_account"])
        with self.assertRaises(AuthDenied):
            restarted.local_login({"username": "admin", "password": "admin"}, self.headers)

    def test_builtin_protection_uses_durable_identity_not_public_annotation_or_legacy_seed_flag(self):
        principal = self.super()
        other = self.create(principal, "independent-super", "super_admin")
        second = self.complete(self.login(other["username"], TEMP_PASSWORD), TEMP_PASSWORD, SECOND_PASSWORD)["principal"]
        identifier = principal["user"]["id"]
        with self.store.meta() as db:
            user = self.store._get(db, "auth_users", identifier)
            user.pop("protected_account")
            self.store._put(db, "auth_users", user)
            realm = self.store._get(db, "maintenance_settings", REALM_ID)
            realm["seeded"] = False
            self.store._put(db, "maintenance_settings", realm)
        with self.assertRaisesRegex(AuthConflict, "built-in admin account is protected"):
            self.auth.update_user(identifier, {"role": "read_only", "enabled": False}, second)
        retained = self.store.get("auth_users", identifier)
        self.assertEqual(retained["role"], "super_admin")
        self.assertTrue(retained["enabled"])

    def test_builtin_password_reset_remains_available_and_keeps_protection(self):
        principal = self.super()
        other = self.create(principal, "recovery-super", "super_admin")
        second = self.complete(self.login(other["username"], TEMP_PASSWORD), TEMP_PASSWORD, SECOND_PASSWORD)["principal"]
        result = self.auth.reset_password(principal["user"]["id"],
                                          {"password": TEMP_PASSWORD, "confirm_password": TEMP_PASSWORD}, second)
        self.assertTrue(result["protected_account"])
        self.assertTrue(result["password_change_required"])
        changed = self.complete(self.login("admin", TEMP_PASSWORD), TEMP_PASSWORD, PASSWORD)
        self.assertTrue(changed["principal"]["user"]["protected_account"])
        self.assertEqual(changed["principal"]["role"], "super_admin")
        self.assertFalse(changed["principal"]["password_change_required"])
        with self.store.read_meta() as db, self.assertRaises(AuthDenied):
            validate_current_principal(self.store, db, principal)

    def test_unseeded_same_named_local_account_is_not_treated_as_builtin(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            auth = Authentication(store, entra=EntraAuth(store, EntraConfig()), origin=ORIGIN, bootstrap=False)
            # An existing directory estate may explicitly provision an ordinary
            # local user named admin. No seeded identity exists in this realm.
            record = auth.local.prepare_user({"provider": "local", "username": "admin", "password": TEMP_PASSWORD,
                                               "role": "super_admin"})
            with store.meta() as db:
                store._put(db, "auth_users", record)
            auth = Authentication(store, entra=EntraAuth(store, EntraConfig()), origin=ORIGIN)
            initial = auth.local_login({"username": "admin", "password": TEMP_PASSWORD}, self.headers)
            signed = auth.change_password({"current_password": TEMP_PASSWORD, "new_password": PASSWORD}, initial["principal"],
                                          {**self.headers, "X-CSRF-Token": initial["principal"]["csrf_token"]})
            self.assertFalse(signed["principal"]["user"]["protected_account"])
            result = auth.update_user(record["id"], {"display_name": "Directory fallback"}, signed["principal"])
            self.assertEqual(result["display_name"], "Directory fallback")
            self.assertNotIn("bootstrap_user_id", store.get("maintenance_settings", REALM_ID))

    def test_missing_builtin_is_not_recreated_or_replaced_with_new_default_credentials(self):
        principal = self.super()
        other = self.create(principal, "remaining-super", "super_admin")
        second = self.complete(self.login(other["username"], TEMP_PASSWORD), TEMP_PASSWORD, SECOND_PASSWORD)["principal"]
        # Simulate an out-of-band deletion in an old snapshot. A new controller
        # must preserve the bootstrap decision, never restore admin/admin.
        with self.store.meta() as db:
            db.execute("DELETE FROM auth_users WHERE id=?", (principal["user"]["id"],))
        restarted = Authentication(self.store, entra=EntraAuth(self.store, EntraConfig()), origin=ORIGIN)
        with self.assertRaises(KeyError):
            self.store.get("auth_users", principal["user"]["id"])
        with self.assertRaises(AuthDenied):
            restarted.local_login({"username": "admin", "password": "admin"}, self.headers)
        with self.assertRaisesRegex(AuthConflict, "built-in admin identity is reserved"):
            restarted.create_user({"provider": "local", "username": "admin", "password": TEMP_PASSWORD, "role": "admin"}, second)
        with self.assertRaises(KeyError):
            self.store.get("auth_users", principal["user"]["id"])

    def test_bootstrap_is_not_recreated_after_password_change_restart_or_disabled_account(self):
        principal = self.super()
        original = self.store.get("auth_users", principal["user"]["id"])
        restarted = Authentication(self.store, entra=EntraAuth(self.store, EntraConfig()), origin=ORIGIN)
        self.assertEqual(self.store.get("auth_users", original["id"])["password_hash"], original["password_hash"])
        with self.assertRaises(AuthDenied):
            restarted.local_login({"username": "admin", "password": "admin"}, self.headers)
        with self.store.meta() as db:
            record = self.store._get(db, "auth_users", original["id"])
            record["enabled"] = False
            self.store._put(db, "auth_users", record)
        Authentication(self.store, entra=EntraAuth(self.store, EntraConfig()), origin=ORIGIN)
        self.assertEqual(len(self.store.all("auth_users")), 1)
        with self.assertRaises(AuthDenied):
            self.login(password=PASSWORD)

    def test_existing_directory_estate_never_gets_a_new_default_password(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            with store.meta() as db:
                store._put(db, "auth_users", {"id": "retained-directory-account", "enabled": False, "role": "super_admin"})
            auth = Authentication(store, entra=EntraAuth(store, EntraConfig()), origin=ORIGIN)
            self.assertEqual(len(store.all("auth_users")), 1)
            self.assertFalse(store.get("maintenance_settings", REALM_ID)["seeded"])
            with self.assertRaises(AuthDenied):
                auth.local_login({"username": "admin", "password": "admin"}, self.headers)
            with store.meta() as db:
                db.execute("DELETE FROM auth_users")
            Authentication(store, entra=EntraAuth(store, EntraConfig()), origin=ORIGIN)
            self.assertEqual(store.all("auth_users"), [])

    def test_bootstrap_false_marks_the_decision_once_without_an_account(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            Authentication(store, entra=EntraAuth(store, EntraConfig()), origin=ORIGIN, bootstrap=False)
            self.assertEqual(store.all("auth_users"), [])
            Authentication(store, entra=EntraAuth(store, EntraConfig()), origin=ORIGIN)
            self.assertEqual(store.all("auth_users"), [])

    def test_username_case_is_normalized_and_duplicate_creation_does_not_overwrite(self):
        principal = self.super()
        account = self.create(principal, "Billing.Admin")
        self.assertEqual(account["username"], "billing.admin")
        self.assertTrue(self.login("BILLING.ADMIN", TEMP_PASSWORD)["principal"]["password_change_required"])
        before = self.store.get("auth_users", account["id"])
        with self.assertRaises(AuthConflict):
            self.create(principal, "billing.admin", "read_only")
        self.assertEqual(self.store.get("auth_users", account["id"]), before)

    def test_local_accounts_receive_all_three_roles_and_only_super_manages_them(self):
        principal = self.super()
        for role in ("read_only", "admin", "super_admin"):
            account = self.create(principal, "pilot-" + role, role)
            signed = self.complete(self.login(account["username"], TEMP_PASSWORD), TEMP_PASSWORD, SECOND_PASSWORD)
            current = signed["principal"]
            self.assertEqual(current["role"], role)
            if role != "super_admin":
                for action in (lambda: self.auth.list_users(current),
                               lambda: self.create(current, "not-authorized"),
                               lambda: self.auth.update_user(principal["user"]["id"], {"display_name": "No"}, current),
                               lambda: self.auth.reset_password(principal["user"]["id"], {"password": TEMP_PASSWORD}, current),
                               lambda: self.auth.revoke_sessions(principal["user"]["id"], current)):
                    with self.assertRaises(AuthDenied):
                        action()
            else:
                self.assertGreaterEqual(len(self.auth.list_users(current)["items"]), 2)

    def test_password_change_requires_current_password_csrf_and_same_origin(self):
        first = self.login()
        change = {"current_password": "admin", "new_password": PASSWORD}
        with self.assertRaises(AuthDenied):
            self.auth.change_password(change, first["principal"], self.headers)
        headers = {**self.headers, "X-CSRF-Token": first["principal"]["csrf_token"]}
        with self.assertRaises(AuthDenied):
            self.auth.change_password(change, first["principal"], {**headers, "Origin": "https://other.example"})
        with self.assertRaises(AuthDenied):
            self.auth.change_password({**change, "current_password": "wrong"}, first["principal"], headers)
        with self.assertRaises(ValueError):
            self.auth.change_password({**change, "confirm_password": "not-the-password"}, first["principal"], headers)
        self.assertTrue(self.auth.authenticate(cookie(first))["password_change_required"])
        self.complete(first)

    def test_new_password_policy_is_bounded_and_never_trims_secrets(self):
        principal = self.super()
        for password in ("short", "x" * 257, "hello\nthere long password", "\ud800" * 12, None):
            with self.subTest(password_length=len(password) if isinstance(password, str) else None), self.assertRaises(ValueError):
                self.auth.create_user({"provider": "local", "username": "bounds", "password": password, "role": "admin"}, principal)
        account = self.auth.create_user({"provider": "local", "username": "spaces", "password": "  long exact password  ", "role": "admin"}, principal)
        self.assertEqual(account["username"], "spaces")
        with self.assertRaises(AuthDenied):
            self.login("spaces", "long exact password")
        self.assertTrue(self.login("spaces", "  long exact password  ")["principal"]["password_change_required"])

    def test_shared_account_throttle_survives_new_instance_and_has_generic_errors(self):
        for _ in range(5):
            with self.assertRaisesRegex(AuthDenied, LOGIN_ERROR):
                self.login(password="incorrect")
        fresh = Authentication(self.store, entra=EntraAuth(self.store, EntraConfig()), origin=ORIGIN)
        with patch("controller.local_auth.verify_password", side_effect=AssertionError("Rate-limited request reached KDF")):
            with self.assertRaisesRegex(AuthDenied, LOGIN_ERROR):
                fresh.local_login({"username": "ADMIN", "password": "admin"}, self.headers)
        attempt = self.store.all("auth_local_attempts")[0]
        self.assertNotIn("admin", json.dumps(attempt))
        with self.store.meta() as db:
            attempt["expires_at"] = stamp(now() - timedelta(seconds=1))
            self.store._put(db, "auth_local_attempts", attempt)
        self.assertTrue(fresh.local_login({"username": "admin", "password": "admin"}, self.headers)["principal"]["password_change_required"])
        self.assertEqual(self.store.all("auth_local_attempts"), [])

    def test_unknown_disabled_and_wrong_password_errors_do_not_reveal_account_state(self):
        principal = self.super()
        disabled = self.create(principal, "disabled")
        self.auth.update_user(disabled["id"], {"enabled": False}, principal)
        for name, password in (("no-such-user", TEMP_PASSWORD), ("disabled", TEMP_PASSWORD), ("admin", "bad")):
            with self.assertRaises(AuthDenied) as caught:
                self.login(name, password)
            self.assertEqual(str(caught.exception), LOGIN_ERROR)

    def test_password_reset_revokes_all_sessions_and_forces_change_again(self):
        principal = self.super()
        account = self.create(principal)
        first = self.complete(self.login("operator", TEMP_PASSWORD), TEMP_PASSWORD, SECOND_PASSWORD)
        second = self.login("operator", SECOND_PASSWORD)
        old = self.store.get("auth_users", account["id"])["credential_version"]
        result = self.auth.reset_password(account["id"], {"password": TEMP_PASSWORD}, principal)
        self.assertEqual(result["revoked_sessions"], 2)
        self.assertTrue(result["password_change_required"])
        self.assertNotEqual(old, self.store.get("auth_users", account["id"])["credential_version"])
        self.assertIsNone(self.auth.authenticate(cookie(first)))
        self.assertIsNone(self.auth.authenticate(cookie(second)))
        with self.store.read_meta() as db, self.assertRaises(AuthDenied):
            validate_current_principal(self.store, db, second["principal"])
        self.assertTrue(self.login("operator", TEMP_PASSWORD)["principal"]["password_change_required"])
        with self.assertRaises(AuthConflict):
            self.auth.reset_password(principal["user"]["id"], {"password": TEMP_PASSWORD}, principal)

    def test_role_or_disable_change_revokes_current_sessions_without_password_leak(self):
        principal = self.super()
        account = self.create(principal)
        session = self.complete(self.login("operator", TEMP_PASSWORD), TEMP_PASSWORD, SECOND_PASSWORD)
        updated = self.auth.update_user(account["id"], {"role": "read_only"}, principal)
        self.assertEqual(updated["revoked_sessions"], 1)
        self.assertIsNone(self.auth.authenticate(cookie(session)))
        current = self.login("operator", SECOND_PASSWORD)
        self.assertEqual(current["principal"]["role"], "read_only")
        self.auth.update_user(account["id"], {"enabled": False}, principal)
        self.assertIsNone(self.auth.authenticate(cookie(current)))
        with self.assertRaises(AuthConflict):
            self.auth.update_user(principal["user"]["id"], {"enabled": False}, principal)

    def test_sessions_expire_and_logout_requires_csrf(self):
        result = self.complete(self.login())
        with self.assertRaises(AuthDenied):
            self.auth.logout({**self.headers, **cookie(result)})
        headers = {**self.headers, **cookie(result), "X-CSRF-Token": result["principal"]["csrf_token"]}
        cleared = self.auth.logout(headers)
        self.assertIn("Max-Age=0", cleared["cookies"][0])
        self.assertIsNone(self.auth.authenticate(cookie(result)))
        signed = self.login(password=PASSWORD)
        with self.store.meta() as db:
            row = self.store._get(db, "auth_sessions", signed["principal"]["_session_id"])
            row["expires_at"] = stamp(now() - timedelta(seconds=1))
            self.store._put(db, "auth_sessions", row)
        self.assertIsNone(self.auth.authenticate(cookie(signed)))

    def test_role_tokens_and_forged_provider_or_subject_cannot_manage_users(self):
        principal = self.super()
        for changes in ({"auth_type": "token"}, {"auth_provider": "entra"}, {"actor": "entra:" + principal["user"]["id"]},
                        {"_session_id": secrets.token_hex(32)}, {"role": "read_only"},
                        {"user": {**principal["user"], "object_id": "11111111-1111-1111-1111-111111111111"}}):
            forged = {**principal, **changes}
            with self.assertRaises(AuthDenied):
                self.auth.list_users(forged)

    def test_invalid_realm_marker_fails_closed_without_recreating_default(self):
        first = self.login()
        with self.store.meta() as db:
            row = self.store._get(db, "maintenance_settings", REALM_ID)
            row["fingerprint"] = "altered"
            self.store._put(db, "maintenance_settings", row)
        with self.assertRaises(AuthDenied):
            self.auth.authenticate(cookie(first))
        with self.assertRaises(AuthDenied):
            Authentication(self.store, entra=EntraAuth(self.store, EntraConfig()), origin=ORIGIN)
        self.assertEqual(len(self.store.all("auth_users")), 1)

    def test_cross_origin_login_rejected_and_password_kdf_is_resource_bounded(self):
        with self.assertRaises(AuthDenied):
            self.auth.local_login({"username": "admin", "password": "admin"}, {**self.headers, "Origin": "https://evil.example"})
        with patch("controller.local_auth._KDF_SLOTS.acquire", return_value=False):
            with self.assertRaises(AuthUnavailable):
                hash_password(PASSWORD)
        self.assertFalse(verify_password(PASSWORD, {"algorithm": SCRYPT_ALGORITHM, "salt": "x" * 10000, "digest": "wrong"}))
        self.assertFalse(verify_password(PASSWORD, {"algorithm": "scrypt", "n": 2**40, "salt": "", "digest": ""}))

    def test_login_rechecks_version_after_hash_when_an_admin_reset_races_it(self):
        principal = self.super()
        account = self.create(principal)
        initial = self.complete(self.login("operator", TEMP_PASSWORD), TEMP_PASSWORD, SECOND_PASSWORD)
        reached, release = threading.Event(), threading.Event()
        original = verify_password
        outcome = []

        def blocked(secret, encoded):
            valid = original(secret, encoded)
            reached.set()
            self.assertTrue(release.wait(5))
            return valid

        def login():
            try:
                self.login("operator", SECOND_PASSWORD)
                outcome.append("unexpected-login")
            except AuthDenied:
                outcome.append("denied")

        with patch("controller.local_auth.verify_password", side_effect=blocked):
            worker = threading.Thread(target=login)
            worker.start()
            self.assertTrue(reached.wait(5))
            # The expensive password work owns no database/global write lock.
            self.auth.reset_password(account["id"], {"password": TEMP_PASSWORD}, principal)
            release.set()
            worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertEqual(outcome, ["denied"])
        self.assertIsNone(self.auth.authenticate(cookie(initial)))

    def test_super_admin_reset_clears_a_locked_account_without_restoring_default_credentials(self):
        principal = self.super()
        account = self.create(principal)
        for _ in range(5):
            with self.assertRaises(AuthDenied):
                self.login("operator", "wrong")
        with self.assertRaises(AuthDenied):
            self.login("operator", TEMP_PASSWORD)
        self.auth.reset_password(account["id"], {"password": SECOND_PASSWORD}, principal)
        self.assertTrue(self.login("operator", SECOND_PASSWORD)["principal"]["password_change_required"])


from controller.tests.test_saml_auth import HAS_SAML


@unittest.skipUnless(HAS_SAML, "Install controller/requirements.txt for SAML/local cross-provider validation")
class MixedProviderAuthenticationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from controller.tests.test_saml_auth import fixture_key
        cls.key, cls.cert = fixture_key()

    def setUp(self):
        from controller.saml_auth import SAMLAuth, SAMLConfig
        from controller.tests.test_saml_auth import ENTITY, ORIGIN as SAML_ORIGIN, fixture_metadata
        from controller.store import digest
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(self.temp.name)
        self.auth = Authentication(self.store, entra=EntraAuth(self.store, EntraConfig()), origin=ORIGIN)
        self.headers = {"Host": "prthak.example.internal", "Origin": ORIGIN}
        first = self.auth.local_login({"username": "admin", "password": "admin"}, self.headers)
        self.local = self.auth.change_password({"current_password": "admin", "new_password": PASSWORD},
                                               first["principal"], {**self.headers, "X-CSRF-Token": first["principal"]["csrf_token"]})
        self.value = {"enabled": True, "sp_entity_id": ENTITY, "origin": SAML_ORIGIN,
                      "idp_metadata_xml": fixture_metadata(self.cert), "display_name": "Pilot SSO"}
        self.config = SAMLConfig.from_value(self.value)
        epoch = secrets.token_hex(32)
        self.row = {"id": "saml_configuration", "config": self.value, "config_digest": digest(self.value),
                    "realm_id": self.config.realm_id, "configuration_fingerprint": self.config.fingerprint, "epoch": epoch,
                    "fingerprint": digest({"configuration_fingerprint": self.config.fingerprint, "epoch": epoch})}
        with self.store.meta() as db:
            self.store._put(db, "maintenance_settings", self.row)
        self.auth.saml = SAMLAuth(self.store, self.config)

    def saml_login(self, role="read_only"):
        import base64
        from urllib.parse import parse_qs, urlsplit
        import zlib
        from lxml import etree
        from controller.tests.test_saml_auth import ORIGIN as SAML_ORIGIN, SUBJECT, response_xml
        account = self.auth.create_user({"provider": "saml", "subject": SUBJECT, "role": role}, self.local["principal"])
        begin = self.auth.saml.begin_login({"Host": urlsplit(SAML_ORIGIN).netloc})
        params = parse_qs(urlsplit(begin["location"]).query)
        request = etree.fromstring(zlib.decompress(base64.b64decode(params["SAMLRequest"][0]), -15))
        form = {"RelayState": params["RelayState"][0], "SAMLResponse": base64.b64encode(response_xml(request.get("ID"), self.key, self.cert)).decode()}
        result = self.auth.saml.callback(form, {"Host": urlsplit(SAML_ORIGIN).netloc,
                                               "Cookie": begin["cookies"][0].split(";", 1)[0]})
        session_cookie = next(value.split(";", 1)[0] for value in result["cookies"] if value.startswith(SESSION_COOKIE + "="))
        return account, result, {"Cookie": session_cookie}

    def test_local_super_admin_provisions_saml_without_claim_based_role_escalation(self):
        account, result, headers = self.saml_login()
        principal = self.auth.authenticate(headers)
        self.assertEqual(principal["role"], "read_only")
        self.assertEqual(principal["auth_provider"], "saml")
        self.assertEqual(account["id"], principal["user"]["id"])
        with self.store.read_meta() as db:
            self.assertEqual(validate_current_principal(self.store, db, principal)["provider"], "saml")
        with self.assertRaises(AuthDenied):
            self.auth.create_user({"provider": "local", "username": "no-access", "password": TEMP_PASSWORD, "role": "admin"}, principal)
        self.assertEqual(self.auth.authenticate(cookie(self.local))["user"]["username"], "admin")
        self.assertEqual(self.auth.status()["mode"], "hybrid")
        self.assertEqual({provider["provider"] for provider in self.auth.status()["providers"]}, {"local", "saml"})

    def test_saml_super_admin_can_manage_local_accounts_and_uses_its_own_csrf_origin(self):
        from controller.tests.test_saml_auth import ORIGIN as SAML_ORIGIN
        _, result, headers = self.saml_login("super_admin")
        principal = self.auth.authenticate(headers)
        created = self.auth.create_user({"provider": "local", "username": "sso-created", "password": TEMP_PASSWORD, "role": "admin"}, principal)
        self.assertEqual(created["provider"], "local")
        self.assertTrue(created["password_change_required"])
        self.auth.require_csrf({**headers, "Origin": SAML_ORIGIN, "X-CSRF-Token": principal["csrf_token"]}, principal)
        with self.assertRaises(AuthDenied):
            self.auth.require_csrf({**headers, "Origin": ORIGIN, "X-CSRF-Token": principal["csrf_token"]}, principal)
        with self.assertRaises(AuthDenied):
            self.auth.reset_password(principal["user"]["id"], {"password": TEMP_PASSWORD}, self.local["principal"])

    def test_saml_header_and_epoch_are_bound_without_reparsing_xml_on_each_policy_check(self):
        from controller.authentication import provider_fingerprint
        from controller.saml_auth import SAMLAuth, SAMLConfig
        from controller.store import digest
        _, result, headers = self.saml_login()
        principal = self.auth.authenticate(headers)
        with self.store.read_meta() as db, patch.object(SAMLConfig, "from_value", side_effect=AssertionError("Hot path reparsed metadata")):
            self.assertEqual(provider_fingerprint(self.store, db, "saml"), self.row["fingerprint"])
            self.assertEqual(validate_current_principal(self.store, db, principal)["provider"], "saml")
        changed = {**self.row, "epoch": secrets.token_hex(32)}
        changed["fingerprint"] = digest({"configuration_fingerprint": self.config.fingerprint, "epoch": changed["epoch"]})
        with self.store.meta() as db:
            self.store._put(db, "maintenance_settings", changed)
        self.auth.saml = SAMLAuth(self.store, self.config)
        self.assertIsNone(self.auth.authenticate(headers))
        with self.store.read_meta() as db, self.assertRaises(AuthDenied):
            validate_current_principal(self.store, db, principal)
        self.assertEqual(self.auth.authenticate(cookie(self.local))["auth_provider"], "local")

    def test_disabling_saml_keeps_local_repair_access_and_rejects_its_old_session(self):
        from controller.saml_auth import SAMLAuth, SAMLConfig
        _, result, headers = self.saml_login("super_admin")
        changed = {**self.row, "config": {**self.value, "enabled": False}}
        with self.store.meta() as db:
            self.store._put(db, "maintenance_settings", changed)
        self.auth.saml = SAMLAuth(self.store, SAMLConfig())
        self.assertIsNone(self.auth.authenticate(headers))
        self.assertEqual(self.auth.authenticate(cookie(self.local))["role"], "super_admin")
        self.assertEqual(self.auth.status()["mode"], "local")
        with self.store.read_meta() as db, self.assertRaises(AuthDenied):
            validate_current_principal(self.store, db, result["principal"])


if __name__ == "__main__":
    unittest.main()
