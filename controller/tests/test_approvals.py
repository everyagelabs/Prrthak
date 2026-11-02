import copy
from datetime import timedelta
import hashlib
import secrets
import tempfile
import unittest
from unittest.mock import patch

from controller import approvals, firewall, managed
from controller.auth import EntraAuth, EntraConfig, SESSION_COOKIE
from controller.firewall import WorkflowConflict
from controller.store import Store, digest, now, stamp
from controller.tests.capture_fixture import typed_event


class IndependentApprovalTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.store = Store(temp.name)
        self.config = EntraConfig(tenant_id="11111111-1111-1111-1111-111111111111", client_id="22222222-2222-2222-2222-222222222222", redirect_uri="https://controller.example/api/v1/auth/callback", client_secret="isolated-identity-fixture")
        self.auth = EntraAuth(self.store, self.config, provider=object())
        self.store.approval_tenant_id = self.config.tenant_id
        self.store.approval_auth_fingerprint = self.config.fingerprint
        self.maker = self.person("33333333-3333-3333-3333-333333333333")
        self.checker = self.person("44444444-4444-4444-4444-444444444444")
        baseline = {"management_sources": ["10.90.0.0/24"], "ssh_ports": [2022], "controller_url": "https://controller.example", "management_probe_url": "https://controller.example/api/v1/agent/enforcement/check", "zone": "public"}
        self.store.report("target", {"hostname": "target", "ips": ["10.70.0.1"], "listeners": [], "firewalld_state": "running", "capabilities": ["signed_assignments_v1"], "protection": {**baseline, "digest": digest(baseline), "ready": True, "blockers": []}, "firewall_snapshot": {"collected_at": stamp(), "status": "ok", "rules": [{"scope": "runtime", "zone": "public", "kind": "port", "value": "8080/tcp", "editable": True}]}})
        self.store.save_policy({"name": "Exact protected app", "selector": {}, "mode": "enforce", "services": [{"port": 8443, "sources": ["10.50.0.0/24"]}]}, self.maker["actor"])

    def person(self, oid, role="admin"):
        identifier = self.config.tenant_id + ":" + oid
        raw = secrets.token_urlsafe(32)
        with self.store.meta() as db:
            self.store._put(db, "auth_users", {"id": identifier, "tenant_id": self.config.tenant_id, "object_id": oid, "role": role, "enabled": True, "display_name": "Same display name", "email": "same@example.test"})
            self.store._put(db, "auth_sessions", {"id": hashlib.sha256(raw.encode()).hexdigest(), "user_id": identifier, "expires_at": stamp(now() + timedelta(hours=8)), "config": self.config.fingerprint})
        principal = self.auth.authenticate({"Cookie": SESSION_COOKIE + "=" + raw})
        self.assertIsNotNone(principal)
        return principal

    def draft(self, principal=None):
        principal = principal or self.maker
        return managed.rollout(self.store, {"name":"Direct current action","server_ids":["target"]}, principal["actor"], principal=principal)

    def test_direct_admin_action_publishes_exact_signed_audit_proof_once(self):
        plan = self.draft()
        self.assertEqual(plan["status"],"queued")
        self.assertEqual(plan["confirmation_count"],1)
        assigned = self.store.assignment("target")[0]
        self.assertTrue(assigned["enforcement"]["authorized"])
        proof = assigned["enforcement"]["approval_proof"]
        self.assertEqual(proof["mode"],"single_admin")
        self.assertEqual(proof["requester"],proof["approved_by"])
        self.assertEqual(proof["submitted_by"],proof["approved_by"])
        self.assertNotIn("pilot",proof)
        self.assertNotIn(self.maker["_session_id"],str(proof))
        self.assertEqual(proof["provider_authority"]["fingerprint"],self.config.fingerprint)
        with self.assertRaises(WorkflowConflict):
            managed.confirm(self.store,plan["id"],{"confirmation_nonce":""},self.maker["actor"],principal=self.maker)

    def test_live_session_and_current_admin_role_are_required(self):
        for field,value in (("expires_at",stamp(now()-timedelta(seconds=1))),("config","different")):
            with self.store.meta() as db:
                old=self.store._get(db,"auth_sessions",self.maker["_session_id"])
                self.store._put(db,"auth_sessions",{**old,field:value})
            with self.assertRaises(PermissionError):self.draft()
            with self.store.meta() as db:self.store._put(db,"auth_sessions",old)
        with self.assertRaises(PermissionError):self.draft({**self.maker,"auth_type":"token"})
        with self.assertRaises(PermissionError):managed.rollout(self.store,{"name":"forged","server_ids":["target"]},self.checker["actor"],principal=self.maker)
        readonly=self.person("66666666-6666-6666-6666-666666666666","read_only")
        with self.assertRaises(PermissionError):self.draft(readonly)

    def test_revoked_actor_and_provider_epoch_revoke_new_delivery(self):
        self.draft();assigned=self.store.assignment("target")[0]
        with self.store.meta() as db:
            user=self.store._get(db,"auth_users",self.maker["user"]["id"])
            self.store._put(db,"auth_users",{**user,"enabled":False})
        self.assertFalse(self.store.assignment("target")[0]["enforcement"]["authorized"])
        with self.store.meta() as db:
            self.store._put(db,"auth_users",user)
            self.store._put(db,"maintenance_settings",{"id":"controller_provider_authority","fingerprint":self.config.fingerprint,"epoch":"a"*64})
        self.assertFalse(self.store.assignment("target")[0]["enforcement"]["authorized"])
        self.assertEqual(assigned["enforcement"]["approval_proof"]["mode"],"single_admin")

    def test_saved_symbolic_policy_directly_authorizes_future_members_and_source_changes(self):
        policy=self.store.all("policies")[0]
        saved=self.store.save_policy({**policy,"selector":{"application":"billing"},"services":[{"port":8443,"sources":[],"source_selector":{"application":"client"}}]},self.maker["actor"],policy["id"],principal=self.maker)
        self.store.update_server("target",{"tags":{"application":"billing"}},self.maker["actor"])
        first=self.store.assignment("target")[0]
        self.assertTrue(first["enforcement"]["authorized"])
        target=self.store.get("servers","target")
        self.store.report("source",{"hostname":"source","ips":["10.60.0.1"],"listeners":[]})
        self.store.update_server("source",{"tags":{"application":"client"}},self.maker["actor"])
        changed=self.store.assignment("target")[0]
        self.assertGreater(changed["version"],first["version"])
        self.assertEqual(changed["services"][0]["sources"],["10.60.0.1/32"])
        self.assertTrue(changed["enforcement"]["authorized"])
        self.store.report("future",{"hostname":"future","ips":["10.70.0.2"],"listeners":[],"capabilities":target["capabilities"],"protection":target["protection"]})
        self.store.update_server("future",{"tags":{"application":"billing"}},self.maker["actor"])
        self.assertTrue(self.store.assignment("future")[0]["enforcement"]["authorized"])
        self.assertEqual(self.store.get("policies",saved["id"])["revision"],saved["revision"])

    def test_policy_save_publishes_without_a_separate_rollout(self):
        old=self.store.all("policies")[0]
        self.store.save_policy(old,self.maker["actor"],old["id"],principal=self.maker)
        self.assertTrue(self.store.assignment("target")[0]["enforcement"]["authorized"])
        self.assertEqual(self.store.all("managed_rollouts"),[])

    def test_legacy_monitor_rows_do_not_block_an_authorized_enforce_intent(self):
        self.store.save_policy({"name":"Observe only","selector":{},"mode":"monitor","services":[{"port":9090,"sources":["0.0.0.0/0"]}]},"legacy-monitor")
        old=next(item for item in self.store.all("policies") if item["mode"]=="enforce")
        self.store.save_policy(old,self.maker["actor"],old["id"],principal=self.maker)
        assigned=self.store.assignment("target")[0]
        self.assertTrue(assigned["enforcement"]["authorized"])
        self.assertEqual(next(row for row in assigned["services"] if row["port"]==9090)["mode"],"monitor")

    def test_policy_delete_directly_resolves_cleanup_and_does_not_reissue_it_each_report(self):
        old=self.store.all("policies")[0]
        self.store.save_policy(old,self.maker["actor"],old["id"],principal=self.maker)
        with self.store.meta() as db:
            server=self.store._get(db,"servers","target");server["_managed_rules_active"]=True;self.store._put(db,"servers",server)
        self.store.delete_policy(old["id"],self.maker["actor"])
        cleanup=self.store.assignment("target")[0]["enforcement"]
        self.assertTrue(cleanup["authorized"])
        self.assertEqual(cleanup["intent"],"remove_managed_rules")
        for _ in range(2):
            self.store.report("target",{"hostname":"target","ips":["10.70.0.1"],"listeners":[],"capabilities":["signed_assignments_v1"]})
            self.assertEqual(self.store.assignment("target")[0]["enforcement"]["approval_id"],cleanup["approval_id"])

    def test_service_group_changes_resolve_the_saved_reference_without_another_review(self):
        from controller import service_groups
        catalogue=service_groups.save(self.store,{"name":"Web","ports":[{"port":443,"protocol":"tcp"}]},self.maker["actor"])
        old=self.store.all("policies")[0]
        self.store.save_policy({**old,"services":[{"service_group_id":catalogue["id"],"sources":["10.50.0.0/24"]}]},self.maker["actor"],old["id"],principal=self.maker)
        first=self.store.assignment("target")[0]
        service_groups.save(self.store,{**catalogue,"expected_revision":catalogue["revision"],"ports":[{"port":443,"protocol":"tcp"},{"port":8443,"protocol":"tcp"}]},self.maker["actor"],catalogue["id"])
        resolved=self.store.assignment("target")[0]
        self.assertGreater(resolved["version"],first["version"])
        self.assertTrue(resolved["enforcement"]["authorized"])
        self.assertEqual([row["port"] for row in resolved["services"]],[443,8443])

    def test_normal_import_also_rechecks_its_actor_on_delivery(self):
        rule='rule port port="8080" protocol="tcp" log prefix="OBS: "'
        self.store.report("target",{"hostname":"target","ips":["10.70.0.1"],"listeners":[],"capabilities":["signed_assignments_v1"],"firewall_snapshot":{"collected_at":stamp(),"status":"ok","rules":[{"scope":"runtime","zone":"public","kind":"rich_rule","value":rule,"editable":True}]}})
        plan=firewall.create_change(self.store,{"name":"Remove observation","server_ids":["target"],"rule_key":firewall.fingerprints("runtime","public","rich_rule",rule)[1],"operation":"remove","scopes":["runtime"]},self.maker["actor"],principal=self.maker)
        self.assertFalse(plan["requires_double_confirmation"])
        firewall.confirm_change(self.store,plan["id"],{"confirmation_nonce":plan["confirmation_nonce"]},self.maker["actor"],principal=self.maker)
        self.assertEqual(len(self.store.assignment("target")[0]["firewall_changes"]),1)
        with self.store.meta() as db:
            user=self.store._get(db,"auth_users",self.maker["user"]["id"]);user["enabled"]=False;self.store._put(db,"auth_users",user)
        self.assertEqual(self.store.assignment("target")[0]["firewall_changes"],[])

    def test_stale_legacy_pending_review_cannot_be_promoted(self):
        plan={"id":"old-pending","plan_digest":"d"*64}
        with self.store.meta() as db:
            approvals.request(self.store,db,plan,self.maker["actor"],self.maker)
            plan["approval"]["mode"]="independent_entra"
            with self.assertRaises(PermissionError):approvals.confirm(self.store,db,plan,self.maker["actor"],self.maker)

    def test_deny_destructive_import_requires_two_same_actor_current_nonces(self):
        body={"name":"Remove old opening","server_ids":["target"],"rule_key":firewall.fingerprints("runtime","public","port","8080/tcp")[1],"operation":"remove","scopes":["runtime"]}
        plan=firewall.create_change(self.store,body,self.maker["actor"],principal=self.maker)
        first=firewall.confirm_change(self.store,plan["id"],{"confirmation_nonce":plan["confirmation_nonce"]},self.maker["actor"],principal=self.maker)
        self.assertEqual(self.store.assignment("target")[0]["firewall_changes"],[])
        with self.assertRaises(WorkflowConflict):firewall.confirm_change(self.store,plan["id"],{"confirmation_nonce":plan["confirmation_nonce"]},self.maker["actor"],principal=self.maker)
        final={"confirmation_nonce":first["confirmation_nonce"],"challenge":first["confirmation_phrase"]}
        with self.assertRaises(PermissionError):firewall.confirm_change(self.store,plan["id"],final,self.checker["actor"],principal=self.checker)
        firewall.confirm_change(self.store,plan["id"],final,self.maker["actor"],principal=self.maker)
        self.assertEqual(len(self.store.assignment("target")[0]["firewall_changes"]),1)

    def test_unready_target_never_gains_direct_enforcement(self):
        with self.store.meta() as db:
            server=self.store._get(db,"servers","target");server["protection"]["ready"]=False;self.store._put(db,"servers",server)
        with self.assertRaises(ValueError):self.draft()
        self.assertFalse(self.store.assignment("target")[0]["enforcement"]["authorized"])

    def learned_session(self, auto=False):
        from controller import learning
        self.learning_body = {"hostname": "target", "ips": ["10.70.0.1"], "listeners": [{"port": port, "protocol": "tcp", "address": "0.0.0.0", "process": "nginx"} for port in (80, 443)], "firewalld_state": "running", "capabilities": ["signed_assignments_v1", "learning_discovery_v1", "learning_auto_allow_v1", "traffic_capture_v1"], "discovery_performed": True, "discovered_at": stamp()}
        self.store.report("target", self.learning_body)
        session = learning.create_session(self.store, {"server_ids": ["target"], "selection_mode": "discovered", "port_filter": [{"port": 443, "protocol": "tcp"}], "policy_action": "auto_allow" if auto else "observe", "auto_allow_confirmed": auto}, self.maker["actor"], principal=self.maker)
        return session

    def discover_and_hit(self, session, batch="hit-1", source="10.50.0.1"):
        self.store.report("target", {**self.learning_body, "discovered_at": stamp(), "learning_discovery_session_ids": [session["id"]]})
        self.store.enqueue_flows("target", {"session_id": session["id"], "batch_id": batch, "events": [typed_event(source,443,identity=session['id']+':'+batch)]})
        self.store.process_flows()

    def test_start_learning_enables_frozen_port_auto_allow_without_more_approval(self):
        from controller import learning_policies as lp
        session=self.learned_session(auto=True)
        self.assertEqual(session["initial_approval_state"],"waiting_for_discovery")
        self.discover_and_hit(session)
        saved=self.store.get("sessions",session["id"])
        self.assertEqual(saved["initial_approval_state"],"approved")
        self.assertEqual(saved["initial_approval_proof"]["mode"],"single_admin")
        self.assertEqual(lp.listing(self.store)[0]["services"],[{"port":443,"protocol":"tcp","sources":["10.50.0.1/32"]}])
        self.discover_and_hit(session,"hit-2","10.50.0.2")
        self.assertEqual(lp.listing(self.store)[0]["services"][0]["sources"],["10.50.0.1/32","10.50.0.2/32"])
        self.assertTrue(self.store.assignment("target")[0]["learning_allow"]["authorized"])
        self.assertEqual(lp.approval_reviews(self.store)["total"],0)

    def reviewed_learning_policy(self):
        from controller import learning_policies as lp
        session=self.learned_session();self.discover_and_hit(session)
        evidence=lp.recommendations(self.store,session["id"])
        plan=lp.preview(self.store,session["id"],{"row_ids":[evidence["rows"][0]["id"]],"server_ids":["target"],"expected_evidence_revision":evidence["evidence_revision"]},self.maker["actor"],principal=self.maker)
        result=lp.apply(self.store,session["id"],{"preview_id":plan["id"],"digest":plan["digest"],"confirm":True,"confirmation_nonce":plan["confirmation_nonce"]},self.maker["actor"],principal=self.maker)
        self.assertFalse(result["pending_approval"])
        return result["policies"][0]

    def test_manual_suggestion_applies_once_and_only_removal_needs_two_steps(self):
        from controller import learning_policies as lp
        policy=self.reviewed_learning_policy()
        self.assertEqual(policy["approval_proof"]["mode"],"single_admin")
        change={"expected_revision":policy["revision"],"services":[{"port":443,"protocol":"tcp","sources":["10.50.0.1/32","10.50.0.3/32"]}]}
        policy=lp.update(self.store,policy["id"],change,self.maker["actor"],principal=self.maker)
        plan=lp.change_preview(self.store,policy["id"],{"expected_revision":policy["revision"],"remove":True},self.maker["actor"],principal=self.maker)
        body={"preview_id":plan["id"],"digest":plan["digest"],"confirm":True,"confirmation_nonce":plan["confirmation_nonce"]}
        first=lp.change_confirm(self.store,policy["id"],body,self.maker["actor"],principal=self.maker)
        self.assertTrue(first["pending_approval"])
        body.update(confirmation_nonce=first["preview"]["confirmation_nonce"],challenge=first["preview"]["confirmation_phrase"])
        result=lp.change_confirm(self.store,policy["id"],body,self.maker["actor"],principal=self.maker)
        self.assertTrue(result["policy"]["removed"])
