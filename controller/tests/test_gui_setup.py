"""Real OIDC signature/PKCE/nonce checks and private GUI proposal boundaries."""
import copy
import hashlib
from datetime import timedelta
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

from controller import gui_setup as setup
from controller.auth import EntraAuth, EntraConfig, AuthDenied, STATE_COOKIE, SESSION_COOKIE, initialize
from controller.firewall import WorkflowConflict
from controller.platform import PlatformManager, _private_json
from controller.store import Store, stamp, now
from controller.tests import test_auth as auth_fixture


class ManagerClient:
    def __init__(self):
        self.state = {"controller_configuration": {"expected_revision": 7, "digest": "f" * 64,
            "entra_configured": False, "bootstrap_available": True, "environment": {}}}

    def status(self):
        return copy.deepcopy(self.state)


class GUISetupTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name)
        self.store = Store(self.directory / "db")
        with self.store.meta() as db:
            initialize(db)
        self.manager = PlatformManager(self.directory / "db")
        self.app = types.SimpleNamespace(store=self.store, demo=False, controller_id="pilot", site="local",
            tokens={"super_admin": "initial-private-super-token-value"}, auth=EntraAuth(self.store, EntraConfig()))
        self.manager.attach(self.app)
        self.client = ManagerClient()
        self.principal = {"role": "super_admin", "actor": "legacy-token:super_admin", "auth_type": "token"}

    def request(self, entra=False):
        environment = {"SEG_HTTP_WORKERS": "", "SEG_HTTP_THREADS": "32", "SEG_DB_POOL_META_MAX": "8",
                       "SEG_DB_POOL_TRAFFIC_MAX": "2", "SEG_DB_POOL_WAIT_SECONDS": "5"}
        value = {"expected_revision": 7, "expected_config_digest": "f" * 64, "environment": environment}
        if entra:
            environment.update(SEG_ENTRA_TENANT_ID=auth_fixture.TENANT, SEG_ENTRA_CLIENT_ID=auth_fixture.CLIENT,
                SEG_ENTRA_REDIRECT_URI="https://prthak.example/api/v1/auth/callback", SEG_BOOTSTRAP_SUPER_ADMIN_OID=auth_fixture.SUPER)
            value["client_secret"] = "private-gui-candidate-secret"
        return value

    @staticmethod
    def confirmation(plan):
        return {"preview_id": plan["id"], **{key: plan[key] for key in ("digest", "confirmation_nonce", "confirmation_phrase")}}

    def test_runtime_review_and_idempotent_queue_keep_exact_private_request(self):
        plan = setup.preview(self.manager, self.request(), self.principal, self.client)
        self.assertFalse(plan["candidate_login_required"])
        job = setup.apply(self.manager, self.confirmation(plan), self.principal, self.client)
        self.assertEqual(job["status"], "queued")
        again = setup.apply(self.manager, self.confirmation(plan), self.principal, self.client)
        self.assertEqual(job["id"], again["id"])
        request = json.loads(self.manager.vault.get(self.manager._job(job["id"])["private"]["request_ref"]))
        self.assertEqual(request["action"], "controller-config")
        self.assertEqual(request["environment"]["SEG_DB_POOL_META_MAX"], "8")

    def test_first_status_has_no_pending_plan_and_needs_no_configuration_file(self):
        value = setup.status(self.manager, self.principal, self.client)
        self.assertTrue(value["installed"])
        self.assertIsNone(value["setup_pending"])

    def test_typed_fields_roles_revisions_and_expiry_reject_without_work(self):
        for changes in ({"environment": {"SHELL": "anything"}}, {"environment": {"SEG_HTTP_WORKERS": "99"}},
                        {"environment": {"SEG_HTTP_THREADS": True}}, {"environment": {"SEG_HTTP_THREADS": "32\nBAD=1"}}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                setup.preview(self.manager, {**self.request(), **changes}, self.principal, self.client)
        with self.assertRaises(PermissionError):
            setup.preview(self.manager, self.request(), {**self.principal, "role": "admin"}, self.client)
        with self.assertRaises(WorkflowConflict):
            setup.preview(self.manager, {**self.request(), "expected_revision": True}, self.principal, self.client)
        plan = setup.preview(self.manager, self.request(), self.principal, self.client)
        self.client.state["controller_configuration"]["expected_revision"] = 8
        with self.assertRaises(WorkflowConflict):
            setup.apply(self.manager, self.confirmation(plan), self.principal, self.client)

    def test_entra_candidate_secret_never_in_public_plan_or_plaintext_state(self):
        plan = setup.preview(self.manager, self.request(True), self.principal, self.client)
        self.assertTrue(plan["candidate_login_required"])
        public = json.dumps(setup.status(self.manager, self.principal, self.client)) + json.dumps(plan)
        self.assertNotIn("private-gui-candidate-secret", public)
        for path in self.directory.rglob("*.json"):
            self.assertNotIn(b"private-gui-candidate-secret", path.read_bytes(), str(path))
        with self.assertRaisesRegex(ValueError, "sign-in"):
            setup.apply(self.manager, self.confirmation(plan), self.principal, self.client)

    def test_changed_bootstrap_credential_invalidates_pending_plan(self):
        plan = setup.preview(self.manager, self.request(True), self.principal, self.client)
        self.app.tokens["super_admin"] = "replacement-private-super-token"
        with self.assertRaises(WorkflowConflict):
            setup.apply(self.manager, self.confirmation(plan), self.principal, self.client)

    def test_active_provider_review_requires_a_live_super_session(self):
        self.client.state["controller_configuration"]["entra_configured"] = True
        self.client.state["controller_configuration"]["environment"] = dict(self.request(True)["environment"])
        self.app.auth = EntraAuth(self.store, EntraConfig(auth_fixture.TENANT, auth_fixture.CLIENT,
            "https://prthak.example/api/v1/auth/callback", "existing-private-secret", auth_fixture.SUPER), provider=object())
        principal = {"role": "super_admin", "actor": "entra:" + auth_fixture.TENANT + ":" + auth_fixture.SUPER, "auth_type": "session"}
        with self.assertRaises(AuthDenied):
            setup.preview(self.manager, self.request(True), principal, self.client)

    def active_super(self, oid=auth_fixture.SUPER):
        if not self.app.auth.enabled:
            self.app.auth = EntraAuth(self.store, EntraConfig(auth_fixture.TENANT, auth_fixture.CLIENT,
                "https://prthak.example/api/v1/auth/callback", "existing-private-secret", auth_fixture.SUPER), provider=object())
        config = self.app.auth.config
        self.store.approval_tenant_id = config.tenant_id
        self.store.approval_auth_fingerprint = config.fingerprint
        raw = "private-live-session-" + oid
        with self.store.meta() as db:
            user = self.app.auth._user({"object_id": oid, "role": "super_admin"})
            self.store._put(db, "auth_users", user)
            self.store._put(db, "auth_sessions", {"id": hashlib.sha256(raw.encode()).hexdigest(), "user_id": user["id"], "config": config.fingerprint, "created_at": stamp(), "expires_at": stamp(now()+timedelta(hours=1))})
        return self.app.auth.authenticate({"Cookie": SESSION_COOKIE + "=" + raw})

    def verified_plan(self, body, principal):
        from cryptography.hazmat.primitives.asymmetric import rsa
        plan = setup.preview(self.manager, body, principal, self.client)
        private = setup._load(self.manager, plan["id"])
        config = setup._candidate(self.manager, private, object()).config
        provider = auth_fixture.LocalMicrosoft(config, rsa.generate_private_key(public_exponent=65537, key_size=2048))
        started = setup.begin_login(self.manager, {"preview_id": plan["id"]}, principal, {"Host": "prthak.example"}, provider)
        setup.finish_login(self.manager, plan["id"], provider.issue(started["location"], config.bootstrap_oid), {"Cookie": started["cookies"][0].split(";",1)[0]}, provider)
        return setup._load(self.manager, plan["id"])

    def test_joined_profile_convergence_uses_effective_provider_after_candidate_login(self):
        principal = self.active_super()
        value = setup.status(self.manager, principal, self.client)
        self.assertTrue(value["capabilities"]["configuration"])
        self.assertTrue(value["convergence_required"])
        self.assertEqual(value["environment"]["SEG_ENTRA_CLIENT_ID"], auth_fixture.CLIENT)
        plan = self.verified_plan(self.request(), principal)
        self.assertFalse(plan["requires_independent"])
        job = setup.apply(self.manager, self.confirmation(plan), principal, self.client)
        request = json.loads(self.manager.vault.get(self.manager._job(job["id"])["private"]["request_ref"]))
        self.assertTrue(request["profile_convergence"])
        self.assertTrue(request["candidate_login_verified"])
        self.assertEqual(request["client_secret"], "existing-private-secret")

    def test_secret_rotation_one_live_super_verifies_candidate_and_revokes_sessions_at_commit(self):
        from controller import provider_lifecycle as lifecycle
        first = self.active_super();second = self.active_super(auth_fixture.ADMIN)
        plan = self.verified_plan(self.request(True), first)
        self.assertFalse(plan["requires_independent"])
        queued = setup.apply(self.manager, self.confirmation(plan), first, self.client)
        self.assertNotIn("pending_approval", queued)
        self.assertEqual(setup.apply(self.manager, self.confirmation(plan), first, self.client)["provider_transition"]["phase"], "prepare")
        self.assertEqual(queued["provider_transition"]["phase"], "prepare")
        class FixedClient(ManagerClient):
            def submit(inner, body):
                inner.body=body
                return {"id": body["request_id"]}
            def job(inner, identifier):
                return {"status":"completed", "result":{"verified":True,"applied":True,"binding_digest":setup.binding(inner.body)}}
        fixed = FixedClient()
        lifecycle.reconcile(self.manager, fixed)
        self.assertEqual(lifecycle.get(self.manager)["phase"], "apply")
        lifecycle.reconcile(self.manager, fixed)
        self.assertEqual(lifecycle.get(self.manager)["phase"], "completed")
        self.assertEqual(self.store.all("auth_sessions"), [])
        self.assertNotIn("private-gui-candidate-secret", json.dumps(lifecycle.get(self.manager)))
        with self.assertRaises(AuthDenied):lifecycle.assert_current(self.app)

    def test_cross_origin_candidate_code_is_exact_host_one_use_and_does_not_grant(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        principal = self.active_super()
        body = self.request(True);body["environment"]["SEG_ENTRA_REDIRECT_URI"]="https://new.example/api/v1/auth/callback";body["retain_old_origin"]=True
        plan = setup.preview(self.manager, body, principal, self.client)
        provider = auth_fixture.LocalMicrosoft(setup._candidate(self.manager, setup._load(self.manager,plan["id"]),object()).config, rsa.generate_private_key(public_exponent=65537,key_size=2048))
        started=setup.begin_login(self.manager,{"preview_id":plan["id"]},principal,{"Host":"prthak.example"},provider)
        self.assertEqual(started["verification_url"],"https://new.example/provider-verification.html")
        self.assertNotIn(started["verification_code"],json.dumps(setup.status(self.manager,principal,self.client)))
        with self.assertRaises(AuthDenied):setup.bridge_login(self.manager,{"verification_code":started["verification_code"]},{"Host":"evil.example","Origin":"https://evil.example"},provider)
        headers={"Host":"new.example","Origin":"https://new.example"}
        login=setup.bridge_login(self.manager,{"verification_code":started["verification_code"]},headers,provider)
        with self.assertRaises(AuthDenied):setup.bridge_login(self.manager,{"verification_code":started["verification_code"]},headers,provider)
        before=len(self.store.all("auth_sessions"))
        setup.finish_login(self.manager,plan["id"],provider.issue(login["location"],auth_fixture.SUPER),{"Cookie":login["cookies"][0].split(";",1)[0]},provider)
        self.assertEqual(len(self.store.all("auth_sessions")),before)

    def test_readiness_refuses_superseded_epoch_without_changing_liveness(self):
        from controller.app import App
        from controller import provider_lifecycle as lifecycle
        principal = self.active_super()
        self.app.recovering = lambda: False
        self.assertEqual(App.readiness(self.app)["status"], "ready")
        with self.store.meta() as db:
            self.store._put(db,"maintenance_settings",{"id":lifecycle.AUTHORITY,"fingerprint":self.app.auth.config.fingerprint,"epoch":"e"*32})
        self.assertFalse(App.readiness(self.app)["checks"]["provider_authority"])
        with patch.dict("os.environ", {"PRTHAK_PROVIDER_EPOCH":"e"*32}):
            self.assertEqual(App.readiness(self.app)["status"],"ready")

    def test_current_super_downgrade_before_cutover_forces_rollback_without_revoking_sessions(self):
        from controller import provider_lifecycle as lifecycle
        first=self.active_super();second=self.active_super(auth_fixture.ADMIN)
        plan=self.verified_plan(self.request(True),first)
        setup.apply(self.manager,self.confirmation(plan),first,self.client)
        with self.store.meta() as db:
            user=self.store._get(db,"auth_users",first["user"]["id"]);user["role"]="admin";self.store._put(db,"auth_users",user)
        class FixedClient(ManagerClient):
            def submit(inner,body):inner.body=body;return {"id":body["request_id"]}
            def job(inner,identifier):return {"status":"completed","result":{"verified":True,"applied":not inner.body.get("rollback_operation"),"rolled_back":bool(inner.body.get("rollback_operation")),"binding_digest":setup.binding(inner.body)}}
        fixed=FixedClient()
        lifecycle.reconcile(self.manager,fixed);lifecycle.reconcile(self.manager,fixed)
        self.assertEqual(lifecycle.get(self.manager)["phase"],"rollback")
        lifecycle.reconcile(self.manager,fixed)
        self.assertEqual(lifecycle.get(self.manager)["phase"],"rolled_back")
        self.assertEqual(len(self.store.all("auth_sessions")),2)
        lifecycle.assert_current(self.app)

    def test_old_alias_login_moves_to_reviewed_callback_origin_before_setting_state_cookie(self):
        self.active_super()
        before=len(self.store.all("auth_states"))
        result=self.app.auth.begin_login({"Host":"old.example"})
        self.assertEqual(result,{"location":"https://prthak.example/api/v1/auth/login","cookies":[]})
        self.assertEqual(len(self.store.all("auth_states")),before)

    def test_three_controller_recipient_sealed_barrier_preserves_local_ports_and_waits_for_every_member(self):
        from controller import provider_lifecycle as lifecycle
        from controller.cluster_bootstrap import _public_key
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        first=self.active_super();second=self.active_super(auth_fixture.ADMIN)
        managers=[self.manager];targets=[];clients=[]
        class FixedClient(ManagerClient):
            def submit(inner,body):inner.body=body;return {"id":body["request_id"]}
            def job(inner,identifier):return {"status":"completed","result":{"verified":True,"applied":True,"binding_digest":setup.binding(inner.body)}}
        for index,node in enumerate(('pilot','peer-b','peer-c')):
            manager=self.manager if index==0 else PlatformManager(self.directory/node)
            if index:
                manager.attach(types.SimpleNamespace(store=self.store,demo=False,controller_id=node,site=node,auth=self.app.auth,tokens=self.app.tokens))
                managers.append(manager)
            key=rsa.generate_private_key(public_exponent=65537,key_size=3072)
            private=key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
            _private_json(manager.root/'appliance-node-key.json',{'key_ref':manager.vault.put(private)})
            targets.append({'id':node,'ip':'10.0.0.'+str(index+1),'site':node,'transport_public_key':_public_key(key)})
            client=FixedClient();client.state['controller_configuration']['environment']={'SEG_CONTROL_PORT':str(8788+index*1000),'SEG_DISCOVERY_PORT':str(8789+index*1000)};clients.append(client)
        with patch.object(self.store,'ha',True),patch.object(lifecycle,'members',return_value=targets):
            plan=self.verified_plan(self.request(True),first)
            setup.apply(self.manager,self.confirmation(plan),first,self.client)
            # The same Super Admin can read the durable result on a peer.
            setup.apply(managers[1],self.confirmation(plan),first,clients[1])
            for manager,client in zip(managers,clients):lifecycle.reconcile(manager,client)
            self.assertEqual(lifecycle.get(self.manager)['phase'],'apply')
            lifecycle.reconcile(managers[0],clients[0]);lifecycle.reconcile(managers[1],clients[1])
            self.assertEqual(lifecycle.get(self.manager)['phase'],'apply')
            self.assertEqual(clients[1].body['environment']['SEG_CONTROL_PORT'],'9788')
            self.assertEqual(clients[1].body['environment']['SEG_DISCOVERY_PORT'],'9789')
            lifecycle.reconcile(managers[2],clients[2])
            self.assertEqual(lifecycle.get(self.manager)['phase'],'completed')
            self.assertNotIn('private-gui-candidate-secret',json.dumps(self.store.all('maintenance_settings')))
            self.assertEqual(self.store.all('auth_sessions'),[])

    def test_existing_fleet_port_change_requires_typed_external_alias_ack_in_exact_review(self):
        with self.store.meta() as db:self.store._put(db,"servers",{"id":"endpoint-one","hostname":"endpoint-one"})
        body=self.request();body["environment"].update(SEG_CONTROL_PORT="9448",SEG_DISCOVERY_PORT="9449")
        with self.assertRaisesRegex(ValueError,"Retain both old and new"):
            setup.preview(self.manager,body,self.principal,self.client)
        with self.assertRaisesRegex(ValueError,"booleans"):
            setup.preview(self.manager,{**body,"acknowledge_agent_aliases":"true"},self.principal,self.client)
        plan=setup.preview(self.manager,{**body,"acknowledge_agent_aliases":True},self.principal,self.client)
        self.assertEqual(plan["summary"]["agent_ports"]["enrolled_endpoints"],1)
        self.assertTrue(plan["summary"]["agent_ports"]["external_aliases_acknowledged"])
        request=json.loads(self.manager.vault.get(setup._load(self.manager,plan["id"])["request_ref"]))
        self.assertTrue(request["acknowledge_agent_aliases"])
        changed={**request,"acknowledge_agent_aliases":False}
        self.assertNotEqual(setup.binding(changed),setup.binding(request))

    def test_tenant_migration_grants_only_verified_target_after_old_supers_approve_and_retires_old_accounts(self):
        from controller import provider_lifecycle as lifecycle
        first=self.active_super();second=self.active_super(auth_fixture.ADMIN)
        target_tenant="88888888-8888-4888-8888-888888888888";target_oid="77777777-7777-4777-8777-777777777777"
        body=self.request(True);body["environment"]["SEG_ENTRA_TENANT_ID"]=target_tenant;body["candidate_object_id"]=target_oid
        plan=self.verified_plan(body,first)
        self.assertEqual(len(self.store.all("auth_users")),2)
        setup.apply(self.manager,self.confirmation(plan),first,self.client)
        class FixedClient(ManagerClient):
            def submit(inner,body):inner.body=body;return {"id":body["request_id"]}
            def job(inner,identifier):return {"status":"completed","result":{"verified":True,"applied":True,"binding_digest":setup.binding(inner.body)}}
        fixed=FixedClient();lifecycle.reconcile(self.manager,fixed);lifecycle.reconcile(self.manager,fixed)
        enabled=[user for user in self.store.all("auth_users") if user["enabled"]]
        self.assertEqual([user["id"] for user in enabled],[target_tenant+":"+target_oid])
        self.assertEqual(enabled[0]["role"],"super_admin")
        self.assertEqual(self.store.all("auth_sessions"),[])

    def test_two_reviews_with_same_clock_always_show_latest_and_prune_expired_secret(self):
        instant = now()
        with patch("controller.gui_setup.now", return_value=instant):
            first = setup.preview(self.manager, self.request(True), self.principal, self.client)
            second = setup.preview(self.manager, self.request(), self.principal, self.client)
            self.assertNotEqual(first["id"], second["id"])
            self.assertEqual(setup.status(self.manager, self.principal, self.client)["setup_pending"]["id"], second["id"])
        private = setup._load(self.manager, first["id"])
        secret_path = self.manager.vault.root / (private["request_ref"][7:] + ".json")
        self.assertTrue(secret_path.exists())
        with patch("controller.gui_setup.now", return_value=instant + timedelta(minutes=11)):
            self.assertIsNone(setup.status(self.manager, self.principal, self.client)["setup_pending"])
        self.assertFalse(secret_path.exists())

    def test_sqlite_rejects_multiple_workers_before_queueing_restart(self):
        body = self.request()
        body["environment"]["SEG_HTTP_WORKERS"] = "2"
        with self.assertRaisesRegex(ValueError, "Standalone SQLite"):
            setup.preview(self.manager, body, self.principal, self.client)

    def test_configuration_receipts_require_exact_binding_and_consistent_verified_outcome(self):
        from controller.appliance import execute_job
        for phase, applied, rolled_back, matching, expected in (
            ("controller_config_applied", True, False, True, "applied"),
            ("controller_config_rolled_back", False, True, True, "rolled_back"),
            ("controller_config_applied", True, False, False, "failed"),
            ("controller_config_applied", False, True, True, "failed"),
        ):
            with self.subTest(phase=phase, matching=matching, applied=applied):
                plan = setup.preview(self.manager, self.request(), self.principal, self.client)
                queued = setup.apply(self.manager, self.confirmation(plan), self.principal, self.client)
                job = self.manager._job(queued["id"])
                request = json.loads(self.manager.vault.get(job["private"]["request_ref"]))
                result = {"id": queued["id"], "status": "completed", "result": {
                    "verified": True, "phase": phase, "applied": applied, "rolled_back": rolled_back,
                    "binding_digest": setup.binding(request) if matching else "0" * 64}}
                with patch("controller.appliance.NodeClient") as client:
                    client.return_value.submit.return_value = result
                    execute_job(self.manager, job)
                self.assertEqual(self.manager.job(queued["id"])["status"], expected)

    @unittest.skipUnless(auth_fixture.HAS_CRYPTO, "OIDC candidate test requires installed auth dependencies")
    def test_signed_candidate_login_verifies_exact_oid_without_granting_access(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        plan = setup.preview(self.manager, self.request(True), self.principal, self.client)
        config = EntraConfig(auth_fixture.TENANT, auth_fixture.CLIENT, "https://prthak.example/api/v1/auth/callback",
                             "private-gui-candidate-secret", auth_fixture.SUPER)
        provider = auth_fixture.LocalMicrosoft(config, rsa.generate_private_key(public_exponent=65537, key_size=2048))
        with self.assertRaisesRegex(ValueError, "exact configured"):
            setup.begin_login(self.manager, {"preview_id": plan["id"]}, self.principal, {"Host": "other.example"}, provider)
        start = setup.begin_login(self.manager, {"preview_id": plan["id"]}, self.principal, {"Host": "prthak.example"}, provider)
        cookies = {"Cookie": start["cookies"][0].split(";", 1)[0]}
        query = provider.issue(start["location"], auth_fixture.SUPER)
        self.assertEqual(setup.callback_plan(self.manager, query), plan["id"])
        with self.assertRaises(AuthDenied):
            EntraAuth(self.store, config, provider).verify_callback_identity(query, cookies)
        result = setup.finish_login(self.manager, plan["id"], query, cookies, provider)
        self.assertEqual(result["location"], "/settings?setup=verified")
        self.assertFalse(self.app.auth.enabled)
        self.assertEqual(self.store.all("auth_users"), [])
        self.assertEqual(self.store.all("auth_sessions"), [])
        self.assertTrue(setup.status(self.manager, self.principal, self.client)["setup_pending"]["candidate_login_verified"])
        with self.assertRaises(AuthDenied):
            setup.finish_login(self.manager, plan["id"], query, cookies, provider)
        job = setup.apply(self.manager, self.confirmation(plan), self.principal, self.client)
        request = json.loads(self.manager.vault.get(self.manager._job(job["id"])["private"]["request_ref"]))
        self.assertTrue(request["candidate_login_verified"])
        self.assertEqual(request["candidate_binding_digest"], setup.binding(request))

    @unittest.skipUnless(auth_fixture.HAS_CRYPTO, "OIDC candidate test requires installed auth dependencies")
    def test_other_directory_user_cannot_verify_initial_super_admin(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        plan = setup.preview(self.manager, self.request(True), self.principal, self.client)
        config = EntraConfig(auth_fixture.TENANT, auth_fixture.CLIENT, "https://prthak.example/api/v1/auth/callback", "private-gui-candidate-secret", auth_fixture.SUPER)
        provider = auth_fixture.LocalMicrosoft(config, rsa.generate_private_key(public_exponent=65537, key_size=2048))
        start = setup.begin_login(self.manager, {"preview_id": plan["id"]}, self.principal, {"Host": "prthak.example"}, provider)
        with self.assertRaisesRegex(AuthDenied, "exact reviewed"):
            setup.finish_login(self.manager, plan["id"], provider.issue(start["location"], auth_fixture.ADMIN),
                               {"Cookie": start["cookies"][0].split(";", 1)[0]}, provider)
        self.assertFalse(setup.status(self.manager, self.principal, self.client)["setup_pending"]["candidate_login_verified"])


if __name__ == "__main__":
    unittest.main()
