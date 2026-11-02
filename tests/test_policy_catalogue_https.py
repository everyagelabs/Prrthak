"""Small real HTTPS checks for bounded source navigation and exact writes."""
from datetime import timedelta
import hashlib
import json
import unittest
from unittest.mock import patch

from controller import policy_views, service_groups
from controller.auth import EntraAuth, EntraConfig, SESSION_COOKIE
from controller.learning_policies import _put_policy
from controller.store import now, stamp
import test_learning_approval_views_https as fixture
from test_integration import stored_entra_admin


class PolicyCatalogueHTTPS(unittest.TestCase):
    request=fixture.LearningApprovalViewHTTPS.request

    def setUp(self):
        fixture.LearningApprovalViewHTTPS.setUp(self)
        self.store.update_server("host-one",{"tags":{"application":"billing"}},"fixture")
        self.group=service_groups.save(self.store,{"name":"Web group","ports":[{"port":443,"protocol":"tcp"},{"port":8443,"protocol":"tcp"}]},"fixture")
        self.policy=self.store.save_policy({"name":"Billing grouped API","selector":{"application":"billing"},"services":[{"service_group_id":self.group["id"],"sources":["10.23.45.67/32","10.23.45.68/32"]}]},"fixture")
        self.policy=self.store.get("policies",self.policy["id"])
        self.learned={"id":"learned-one","name":"Exact billing","server_id":"host-one","hostname":"host-one","session_id":"session-one","status":"pending","revision":1,"created_at":stamp(),"origin":"reviewed","auto_updates":False,"services":[{"port":8443,"protocol":"tcp","sources":["10.23.45.67/32","10.23.45.68/32"]}]}
        with self.store.meta() as db:_put_policy(self.store,db,self.learned)

    def test_read_only_navigation_is_compact_and_exact_details_preserve_every_source(self):
        original=self.store._all
        def no_catalogue(db,table):
            if table in ("policies","learning_allow_policies"):raise AssertionError("Public catalogue decoded canonical source history")
            return original(db,table)
        with patch.object(self.store,"_all",side_effect=no_catalogue):
            for path in ("policies?limit=1","learning-policies?limit=1","overview","service-groups","service-groups/"+self.group["id"]):
                code,value,_=self.request(path)
                self.assertEqual(code,200,(path,value))
                self.assertNotIn("10.23.45.67/32",json.dumps(value))
            code,page,_=self.request("policies?limit=1")
            self.assertEqual((page["total"],page["items"][0]["source_count"]),(1,2))
            self.assertTrue(page["items"][0]["summary_only"])
            self.assertNotIn("sources",page["items"][0]["services"][0])
        self.assertEqual(self.request("policies/"+self.policy["id"])[1],self.policy)
        self.assertEqual(self.request("learning-policies/learned-one")[1],self.learned)
        with patch.object(policy_views,"MAX_DETAIL_BYTES",128):
            code,value,_=self.request("learning-policies/learned-one")
            self.assertEqual(code,400)
            self.assertNotIn("10.23.45.67",json.dumps(value))

    def test_combined_query_is_read_only_and_cookie_csrf_origin_checks_are_retained(self):
        origin="https://localhost:"+str(self.port)
        config=EntraConfig("11111111-1111-1111-1111-111111111111","22222222-2222-2222-2222-222222222222",origin+"/api/v1/auth/callback","isolated-secret")
        self.app.auth=EntraAuth(self.store,config,provider=object())
        raw="isolated-real-cookie-session-"+"x"*32
        with self.store.meta() as db:
            self.store._put(db,"auth_users",{"id":"readonly","tenant_id":config.tenant_id,"object_id":"33333333-3333-3333-3333-333333333333","role":"read_only","enabled":True})
            self.store._put(db,"auth_sessions",{"id":hashlib.sha256(raw.encode()).hexdigest(),"user_id":"readonly","expires_at":stamp(now()+timedelta(hours=1)),"config":config.fingerprint})
        cookie={"Cookie":SESSION_COOKIE+"="+raw}
        csrf=self.request("auth",authenticated=False,extra_headers=cookie)[1]["csrf_token"]
        valid={**cookie,"X-CSRF-Token":csrf,"Origin":origin}
        scope={"server_ids":["host-one"],"search_server_ids":["host-one"],"ports":["8443/tcp"],"search":"billing","limit":1,"offset":0}
        for path in ("policies/query","learning-policies/query"):
            self.assertEqual(self.request(path,"POST",False,scope,extra_headers=cookie)[0],403)
            self.assertEqual(self.request(path,"POST",False,scope,extra_headers={**valid,"Origin":"https://wrong.invalid"})[0],403)
            code,page,_=self.request(path,"POST",False,scope,extra_headers=valid)
            self.assertEqual((code,page["total"],len(page["items"])),(200,1,1))
        self.assertEqual(self.request("policies","POST",False,self.policy,extra_headers=valid)[0],403)
        self.assertEqual(self.request("policies/query","POST",False,{"server_ids":["x' OR 1=1--"]},extra_headers=valid)[0],400)

    def test_summary_writes_and_stale_exact_revision_cannot_change_policy(self):
        path="policies/"+self.policy["id"]
        summary=self.request("policies")[1]["items"][0]
        admin=stored_entra_admin(self.app,"https://localhost:"+str(self.port))
        self.assertEqual(self.request(path,"PUT",False,summary,extra_headers=admin)[0],400)
        self.assertEqual(self.request(path,"DELETE",False,summary,extra_headers=admin)[0],400)
        current=self.store.save_policy({**self.policy,"name":"A newer exact edit"},"fixture",self.policy["id"])
        current=self.store.get("policies",current["id"])
        self.assertEqual(self.request(path,"PUT",False,{**self.policy,"expected_revision":1},extra_headers=admin)[0],409)
        self.assertEqual(self.request(path,"DELETE",False,{"expected_revision":1},extra_headers=admin)[0],409)
        self.assertEqual(self.store.get("policies",self.policy["id"]),current)
        body={**current,"expected_revision":current["revision"],"name":"Current exact edit"}
        code,saved,_=self.request(path,"PUT",False,body,extra_headers=admin)
        self.assertEqual(code,200,saved)
        self.assertEqual(saved["services"][0]["sources"],self.policy["services"][0]["sources"])
