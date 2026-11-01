"""Retired pilot rows cannot influence the direct role-authorized workflow."""
import unittest
from controller import approvals
from controller.tests import test_approvals as fixture

class DirectApprovalModeTests(unittest.TestCase):
    person=fixture.IndependentApprovalTests.person
    def setUp(self):fixture.IndependentApprovalTests.setUp(self)
    def test_old_pilot_limit_and_expiry_are_ignored_for_new_actions(self):
        with self.store.meta() as db:
            self.store._put(db,"maintenance_settings",{"id":"approval_settings","revision":99,"mode":"single_admin_pilot","server_ids":[],"expires_at":"2000-01-01T00:00:00Z"})
            plan={"id":"current","plan_digest":"a"*64}
            approvals.request(self.store,db,plan,self.maker["actor"],self.maker,endpoint_ids=["target"]*5000)
            proof=approvals.decide(self.store,db,plan,self.maker["actor"],self.maker)
            self.assertEqual(proof["mode"],"single_admin")
            self.assertNotIn("pilot",proof)
            self.assertTrue(approvals.authorized(self.store,db,proof,server_id="target"))
