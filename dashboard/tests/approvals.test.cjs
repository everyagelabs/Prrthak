const test=require('node:test');
const assert=require('node:assert/strict');
const A=require('../approvals-page.js');
const plan=()=>({id:'p1',digest:'d1',status:'reviewed',confirmation_count:0,confirmation_nonce:'n1',confirmation_phrase:'CONFIRM p1',expires_at:new Date(Date.now()+300000).toISOString(),approval:{mode:'single_admin',requester:{user_id:'t:admin',tenant_id:'t'}}});
const admin={role:'admin',authType:'session',userId:'t:admin',tenantId:'t'};
test('one current Admin applies an exact normal change without another person or pilot mode',()=>{
 const p=plan();assert.equal(A.canAct(p,admin),true);
 assert.deepEqual(A.confirmationBody(p,{confirm:true}),{confirm:true,preview_id:'p1',digest:'d1',confirmation_nonce:'n1'});
 assert.match(A.phaseLabel(p),/Ready to apply/);assert.doesNotMatch(A.explain(p),/different|pilot|seven|20 endpoint/i);
 assert.equal(A.canAct(p,{...admin,userId:'t:other'}),false);assert.equal(A.canAct(p,{...admin,role:'read_only'}),false);
});
test('restrictive final confirmation uses same Admin and rotated nonce plus exact typed phrase',()=>{
 const p={...plan(),requires_double_confirmation:true,status:'awaiting_second_confirmation',confirmation_count:1,confirmation_nonce:'second'};
 assert.equal(A.canAct(p,admin),true);assert.equal(A.canAct(p,{...admin,userId:'t:other'}),false);
 assert.throws(()=>A.confirmationBody(p,{},'wrong'),/exact displayed/);
 assert.equal(A.confirmationBody(p,{},'CONFIRM p1').challenge,'CONFIRM p1');assert.match(A.explain(p),/same Admin/);
});
test('missing authority, summaries, expiry and foreign or token identities stay nonactionable',()=>{
 const p=plan();assert.equal(A.canAct({...p,summary_only:true},admin),false);assert.equal(A.canAct({...p,expires_at:'invalid'},admin),false);
 assert.equal(A.canAct({...p,approval:null},admin),false);assert.equal(A.canAct(p,{...admin,authType:'token'}),false);
 assert.equal(A.canAct(p,{...admin,tenantId:'foreign'}),false);assert.equal(A.canAct({...p,status:'queued'},admin),false);
});
test('historical mode proofs remain readable without a second-reviewer call to action',()=>{
 const p={...plan(),approval:{mode:'independent_entra',requester:{user_id:'t:admin'}}};assert.equal(A.canAct(p,admin),false);
 assert.match(A.explain(p),/Historical change/);assert.doesNotMatch(A.explain(p),/different.*Admin|pilot/i);
 const lab={...plan(),approval:{mode:'lab_only',requester:{actor:'lab:admin'}}};assert.equal(A.canAct(lab,{role:'admin',authType:'token',userId:'lab:admin'}),true);
});
