"""Actual HTTPS direct Admin changes; retired pilot UI cannot gate authority."""
import unittest
from controller import firewall
from controller.store import digest, stamp
from controller.tests import test_auth as identities
import test_auth_integration as fixture


@unittest.skipUnless(identities.HAS_CRYPTO, "Controller cryptography requirements needed")
class DirectAdminHTTPS(unittest.TestCase):
    http = fixture.EntraHTTPSAcceptanceTests.http
    api = fixture.EntraHTTPSAcceptanceTests.api
    signin = fixture.EntraHTTPSAcceptanceTests.signin
    provision = fixture.EntraHTTPSAcceptanceTests.provision

    def setUp(self):
        fixture.EntraHTTPSAcceptanceTests.setUp(self)
        self.store.approval_auth_fingerprint = self.app.auth.config.fingerprint
        self.store.approval_tenant_id = self.app.auth.config.tenant_id
        baseline = {"management_sources":["10.90.0.0/24"],"ssh_ports":[2022],"controller_url":self.origin,
            "management_probe_url":self.origin+"/api/v1/agent/enforcement/check","zone":"public"}
        self.store.report("target", {"hostname":"direct-target","ips":["10.70.0.1"],"listeners":[],
            "capabilities":["approval_mode_proof_v1","signed_assignments_v1"],"firewalld_state":"running",
            "protection":{**baseline,"digest":digest(baseline),"ready":True,"blockers":[]},
            "firewall_snapshot":{"collected_at":stamp(),"status":"ok","rules":[{"scope":"runtime","zone":"public","kind":"port","value":"8080/tcp","editable":True}]}})

    def accounts(self):
        super_headers=self.signin()
        self.provision(super_headers,identities.ADMIN,"admin")
        self.provision(super_headers,identities.READ,"read_only")
        return super_headers,self.signin(identities.ADMIN),self.signin(identities.READ)

    def test_admin_save_immediately_publishes_without_pilot_mode_or_another_person(self):
        super_headers,admin,readonly=self.accounts()
        policy={"name":"Direct443","selector":{},"mode":"enforce","services":[{"port":443,"sources":["10.60.0.0/24"]}]}
        self.api("POST","policies",policy,readonly,403)
        self.api("POST","policies",policy,{k:v for k,v in admin.items() if k!='X-CSRF-Token'},403)
        self.api("POST","policies",policy,{"Authorization":"Bearer ignored-legacy-super"},401)
        self.api("POST","policies",policy,admin,201)
        enforcement=self.store.assignment("target")[0]["enforcement"]
        self.assertTrue(enforcement["authorized"])
        self.assertEqual(enforcement["confirmation_count"],1)
        self.assertEqual(enforcement["approval_proof"]["mode"],"single_admin")
        self.assertEqual(enforcement["approval_proof"]["requester"]["user_id"],identities.TENANT+":"+identities.ADMIN)
        self.assertEqual(self.store.all("managed_rollouts"),[])
        self.assertFalse(self.api("GET","platform/approval-settings",headers=admin)["selectable"])
        self.api("POST","platform/approval-settings/preview",{},super_headers,410)
        self.api("POST","access/users",{"object_id":identities.OTHER,"role":"admin"},admin,403)

    def test_destructive_firewall_change_keeps_two_same_admin_explicit_steps(self):
        _,admin,_=self.accounts()
        body={"name":"Remove old opening","server_ids":["target"],"rule_key":firewall.fingerprints("runtime","public","port","8080/tcp")[1],"operation":"remove","scopes":["runtime"]}
        plan=self.api("POST","firewall/changes",body,admin,201)
        path="firewall/changes/"+plan["id"]+"/confirm"
        first=self.api("POST",path,{"confirmation_nonce":plan["confirmation_nonce"]},admin)
        self.assertEqual(first["status"],"awaiting_second_confirmation")
        self.api("POST",path,{"confirmation_nonce":plan["confirmation_nonce"]},admin,409)
        final=self.api("POST",path,{"confirmation_nonce":first["confirmation_nonce"],"challenge":first["confirmation_phrase"]},admin)
        self.assertEqual(final["status"],"queued")
        self.assertEqual(final["approval"]["requester"],final["approval"]["approved_by"])
