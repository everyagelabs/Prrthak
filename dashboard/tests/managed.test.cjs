const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const M=require('../managed.js'),F=require('../filters.js');
const digest='a'.repeat(64),protectionDigest='b'.repeat(64);
function draft(){return {id:'rollout-1',name:'Lab billing review',status:'draft',server_ids:['host-1'],bindings:{'host-1':{version:2,digest,protection_digest:protectionDigest}},preview:{targets:[{server_id:'host-1',hostname:'billing-01',protection_status:'ready',blockers:[]}]},requires_double_confirmation:true,confirmation_count:0,confirmation_nonce:'nonce-1',confirmation_phrase:'CONFIRM abc123',plan_digest:'c'.repeat(64),expires_at:new Date(Date.now()+600000).toISOString(),results:{}};}
const policy={id:'policy-1',revision:2,name:'Billing',mode:'enforce',selector:{application:'billing'},group_ids:[],services:[{port:8443,protocol:'tcp',sources:['10.20.0.0/24'],source_selector:{role:'gateway'}}]};
test('revision comparison excludes metadata and order while retaining access and mode changes',()=>{
 const before={...policy,services:[{...policy.services[0],sources:['10.20.0.0/24','10.21.0.0/24']}]},after=structuredClone(before);after.revision=9;after.actor='operator';after.services[0].sources.reverse();assert.equal(M.compare(before,after).length,0);
 after.mode='monitor';after.services[0].sources=['10.20.0.0/24'];assert.deepEqual(M.compare(before,after).map(change=>change.field),['mode','services']);assert.equal(before.services[0].sources.length,2);
});
test('authorization requires complete frozen host/version/access/protection bindings, readiness and a fresh review',()=>{
 const plan=draft();assert.equal(M.canConfirm(plan,'admin'),true);assert.equal(M.canConfirm(plan,'super_admin'),true);for(const role of ['read_only','operator','viewer'])assert.equal(M.canConfirm(plan,role),false);
 delete plan.bindings['host-1'].protection_digest;assert.equal(M.canConfirm(plan,'admin'),false);plan.bindings['host-1'].protection_digest=protectionDigest;
 plan.preview.targets[0].blockers=['Management vantage is not configured'];assert.equal(M.canConfirm(plan,'admin'),false);plan.preview.targets[0].blockers=[];
 plan.expires_at=new Date(Date.now()-1).toISOString();assert.equal(M.canConfirm(plan,'admin'),false);plan.expires_at=new Date(Date.now()+60000).toISOString();plan.status='invalidated';assert.equal(M.canConfirm(plan,'admin'),false);
});
test('second confirmation uses a rotated nonce and requires an exact typed phrase without mutating the plan',()=>{
 const plan=draft();assert.deepEqual(M.confirmationBody(plan),{confirmation_nonce:'nonce-1'});assert.equal(plan.confirmation_count,0);
 Object.assign(plan,{status:'awaiting_second_confirmation',confirmation_nonce:'nonce-2',confirmation_count:1});
 assert.throws(()=>M.confirmationBody(plan,''),/exact displayed/);assert.throws(()=>M.confirmationBody(plan,'CONFIRM abc123 '),/exact displayed/);assert.deepEqual(M.confirmationBody(plan,'CONFIRM abc123'),{confirmation_nonce:'nonce-2',challenge:'CONFIRM abc123'});
});
test('a previous enforced bundle cannot make a new desired version look current',()=>{
 const server={desired_version:3,applied_version:2,apply_status:'synced',managed_enforcement:{status:'enforced',version:2,digest}};
 assert.equal(M.serverState(server),'pending_approval');assert.equal(F.policyStatus(server),'pending_approval');
 server.desired_version=2;assert.equal(F.policyStatus(server),'current');server.managed_enforcement.status='rolled_back';assert.equal(F.policyStatus(server),'rolled_back');
 for(const status of ['preview','pending_approval','staging','runtime_healthchecking','committing']){server.managed_enforcement.status=status;assert.equal(F.policyStatus(server),status);assert.notEqual(F.policyStatus(server),'current');}
});
function environment(){
 const calls=[],shown=[],errors=[],messages=[];let typed='';let form={};
 const plan={...draft(),approval:{mode:'single_admin',requester:{user_id:'tenant:maker',tenant_id:'tenant',actor:'entra:tenant:maker'}}},servers=[{id:'host-1',hostname:'billing-01',desired_version:2,applied_version:0,tags:{application:'billing'},protection:{digest:protectionDigest,ready:true,management_sources:['10.0.0.0/24'],ssh_ports:[2022]}}];
 const state={role:'admin',authType:'session',user:{id:'tenant:maker',tenant_id:'tenant'},view:'policies',policyTab:'rollouts',filters:F.empty(),data:{servers,policies:[policy],groups:[]},managedRollouts:[plan],activeManagedRollout:null};
 const serverPlans=new Map([[plan.id,plan]]),page=(items,limit=20,offset=0,total=items.length)=>({items,total,limit,offset,has_more:offset+limit<total,summary_only:true});
 const h=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
 const context={PrthakApprovals:require('../approvals-page.js'),Date,Map,Set,JSON,Array,String,Number,Error,M,F,state,h,num:value=>Number(value)||0,format:value=>String(value),timestamp:value=>String(value||'Not reported'),humanize:value=>String(value||'').replaceAll('_',' '),icon:()=>'',badge:(label,tone)=>`<span class="${tone||''}">${h(label)}</span>`,serverName:id=>servers.find(server=>server.id===id)?.hostname||id,filteredServers:()=>servers,canWrite:()=>['admin','super_admin'].includes(state.role),filterBarHTML:()=>'',policyCardsHTML:()=>'',errorSlot:'',modalFooter:label=>`<button type="submit">${label}</button>`,showModal:(title,html)=>shown.push({title,html}),formError:error=>errors.push(error.message),toast:message=>messages.push(message),load:async()=>{},render:()=>{},renderServerDrawer:()=>{},document:{activeElement:null},sessionStorage:{setItem:()=>{}},$:(selector)=>selector==='#managed-confirmation-challenge'?{value:typed}:selector==='button[type="submit"]'?{disabled:false}:selector==='#modal'?{open:true}:selector==='#policy-compare-from'?{value:'1'}:selector==='#policy-compare-to'?{value:'2'}:{},$$:()=>[],FormData:class{constructor(){this.values=form;}get(key){return this.values[key]}getAll(key){return this.values[key]||[]}},api:async(path,options={})=>{
  calls.push({path,options});
  if(path==='/policy-rollouts')return options.method==='POST'?plan:{items:state.managedRollouts};
  if(path==='/policy-rollouts/query')return page([...serverPlans.values()].map(value=>({...value,summary_only:true,target_count:value.server_ids.length,server_ids:undefined,bindings:undefined,preview:undefined,confirmation_nonce:undefined})),20,options.body.offset);
  if(path===`/policy-rollouts/${plan.id}`)return serverPlans.get(plan.id);
  if(path.endsWith('/confirm')){const result={...serverPlans.get(plan.id),status:options.body.challenge?'queued':'awaiting_second_confirmation',confirmation_count:options.body.challenge?2:1,confirmation_nonce:options.body.challenge?'nonce-3':'nonce-2'};serverPlans.set(plan.id,result);return result;}
  if(path.endsWith('/rollback'))return {...policy,revision:3};
  if(path.includes('/revisions?')){const url=new URL('http://fixture'+path),limit=Number(url.searchParams.get('limit'));return page([policy,{...policy,revision:1,mode:'monitor'}].slice(0,limit).map(value=>({...value,summary_only:true,services:undefined})),limit,Number(url.searchParams.get('offset')),2);}
  if(path.includes('/revisions/')){const revision=Number(path.split('/').at(-1));return {...policy,revision,mode:revision===1?'monitor':'enforce'};}
  return plan;
 }};
 vm.createContext(context);vm.runInContext(fs.readFileSync(require.resolve('../managed-page.js'),'utf8'),context);
 return {context,calls,shown,errors,messages,state,plan,setTyped:value=>{typed=value},setForm:value=>{form=value}};
}
test('opening history, restore review or a new rollout never authorizes or applies rules',async()=>{
 const env=environment();await env.context.managedPolicyHistory(policy.id);await env.context.managedRestoreReview(policy.id,1);env.context.managedNewRollout();
 assert.equal(env.calls.filter(call=>call.options.method==='POST').length,0);assert.match(env.shown.at(-1).html,/No endpoint is selected automatically/);assert.doesNotMatch(env.shown.at(-1).html,/name="server_ids"[^>]*checked/);
 assert.match(env.shown.at(-2).html,/new revision/);assert.match(env.shown.at(-2).html,/published to eligible endpoints/);
});
test('restrictive managed cleanup uses two explicit same-Admin confirmations with a rotated nonce',async()=>{
 const env=environment();env.context.managedShowRollout(env.plan);const click=()=>env.context.managedAction({dataset:{action:'managed-confirm-rollout'},disabled:false});
 await click();let requests=env.calls.filter(call=>call.path.endsWith('/confirm'));assert.equal(requests.length,1);assert.equal(requests[0].options.body.confirmation_nonce,'nonce-1');assert.equal(env.state.activeManagedRollout.status,'awaiting_second_confirmation');assert.match(env.shown.at(-1).html,/Final confirmation/);assert.doesNotMatch(env.shown.at(-1).html,/value="CONFIRM abc123"/);
 await click();assert.equal(env.calls.filter(call=>call.path.endsWith('/confirm')).length,1);assert.match(env.errors.at(-1),/exact displayed/);
 env.state.user.id='tenant:checker';await click();assert.equal(env.calls.filter(call=>call.path.endsWith('/confirm')).length,1);assert.match(env.errors.at(-1),/Admin identity/);env.state.user.id='tenant:maker';
 env.setTyped('CONFIRM abc123');await click();requests=env.calls.filter(call=>call.path.endsWith('/confirm'));assert.equal(requests.length,2);assert.equal(requests[1].options.body.confirmation_nonce,'nonce-2');assert.equal(env.state.activeManagedRollout.status,'queued');assert.match(env.shown.at(-1).html,/approval or download is not proof of enforcement/);
});
test('restoring uses an explicit reason and creates a revision without drafting or confirming a rollout',async()=>{
 const env=environment();await env.context.managedRestoreReview(policy.id,1);env.setForm({reason:'Restore the approved application dependency baseline'});
 await env.context.managedSubmit({preventDefault:()=>{},target:{id:'managed-restore-form',dataset:{id:policy.id,revision:'1'}}});
 const mutations=env.calls.filter(call=>call.options.method==='POST');assert.equal(mutations.length,1);assert.equal(mutations[0].path,'/policies/policy-1/rollback');assert.equal(mutations[0].options.body.revision,1);assert.match(mutations[0].options.body.reason,/approved/);assert.match(env.messages[0],/new revision 3/);
});
test('invalidated or expired plans cannot be confirmed and server invalidation is displayed without another approval control',async()=>{
 const env=environment();env.plan.status='invalidated';env.context.managedShowRollout(env.plan);await env.context.managedAction({dataset:{action:'managed-confirm-rollout'},disabled:false});assert.equal(env.calls.filter(call=>call.path.endsWith('/confirm')).length,0);assert.doesNotMatch(env.shown.at(-1).html,/data-action="managed-confirm-rollout"/);
 env.plan.status='draft';env.plan.expires_at=new Date(Date.now()-1).toISOString();env.context.managedShowRollout(env.plan);assert.match(env.shown.at(-1).html,/authorization has expired/);assert.match(env.shown.at(-1).html,/data-action="managed-confirm-rollout" disabled/);
});
test('protection evidence, rollback reasons and readback states are escaped and unknown coverage stays explicit',()=>{
 const env=environment(),server={...env.state.data.servers[0],managed_enforcement:{status:'rolled_back',version:2,rollback_reason:'<img src=x onerror=alert(1)>'},protection:{ready:false,blockers:['Missing management vantage'],ssh_ports:[2022],management_sources:['10.0.0.0/24']}};
 const html=env.context.managedEndpointHTML(server);assert.match(html,/Rolled back/);assert.match(html,/Missing management vantage/);assert.match(html,/Configuration incomplete/);assert.match(html,/2022\/tcp/);assert.doesNotMatch(html,/<img/);assert.match(html,/&lt;img/);assert.doesNotMatch(html,/Enforced · agent verified/);
});
test('verified cleanup is distinct from active managed enforcement and queued targets do not falsely request approval',()=>{
 const env=environment();env.plan.status='queued';env.plan.confirmation_count=2;env.context.managedShowRollout(env.plan);assert.match(env.shown.at(-1).html,/Pending agent/);assert.doesNotMatch(env.shown.at(-1).html,/Approval required/);
 const report={status:'enforced',intent:'remove_managed_rules',version:2};assert.equal(M.outcomeState(report),'removed');assert.equal(F.policyStatus({desired_version:2,applied_version:2,managed_enforcement:report}),'removed');
 env.plan.preview.targets[0].intent='remove_managed_rules';env.plan.results={'host-1':report};env.context.managedShowRollout(env.plan);assert.match(env.shown.at(-1).html,/Remove Prṛthak-managed rules/);assert.match(env.shown.at(-1).html,/Existing legacy firewall policy resumes/);assert.match(env.shown.at(-1).html,/Managed rules removed · verified/);assert.doesNotMatch(env.shown.at(-1).html,/Enforced · agent verified/);
});
test('Read Only roles cannot mutate while a normal Admin change supports one apply action',async()=>{
 const env=environment();env.state.role='operator';await env.context.managedPolicyHistory(policy.id);const before=env.shown.length;await env.context.managedRestoreReview(policy.id,1);assert.equal(env.shown.length,before);assert.match(env.shown.at(-1).html,/disabled>Review restore/);assert.equal(M.canConfirm(draft(),'operator'),false);
 const plan=draft();plan.requires_double_confirmation=false;assert.equal(M.canConfirm(plan,'admin'),true);plan.requires_double_confirmation=true;plan.confirmation_count=2;assert.equal(M.canConfirm(plan,'admin'),false);
});
test('catalogue summaries cannot supply editor configuration or confirmation authority even with copied bindings',()=>{
 const summary={...draft(),summary_only:true};assert.equal(M.canConfirm(summary,'admin'),false);assert.throws(()=>M.confirmationBody(summary),/exact frozen/);
 assert.throws(()=>M.policyConfiguration({...policy,summary_only:true}),/exact immutable/);assert.throws(()=>M.compare({...policy,summary_only:true},policy),/exact immutable/);
 assert.throws(()=>M.exactPolicy({...policy,sources_omitted:true},policy.id,2),/identity or configuration/);
 assert.throws(()=>M.exactPolicy({...policy,services:[{port:8443,sources_omitted:true}]},policy.id,2),/identity or configuration/);
 assert.throws(()=>M.exactBundle({server_id:'host-2',version:2,services:[]},'host-1',2),/bundle identity/);
 assert.deepEqual(M.resultCounts({summary_only:true,result_counts:{enforced:20,rolled_back:1}}),{enforced:20,rolled_back:1});
});
test('revision view fetches the exact selected revision and restore refuses a summary or mismatched identity',async()=>{
 const env=environment();env.state.policyHistories={[policy.id]:[{id:policy.id,revision:1,summary_only:true,marker:'cached navigation summary'}]};
 await env.context.managedAction({dataset:{action:'managed-view-revision',id:policy.id,revision:'1'}});
 assert.ok(env.calls.some(call=>call.path==='/policies/policy-1/revisions/1'));assert.match(env.shown.at(-1).html,/10.20.0.0\/24/);assert.doesNotMatch(env.shown.at(-1).html,/cached navigation/);
 const original=env.context.api;env.context.api=async(path,options)=>path.includes('/revisions/')?{...policy,id:'other-policy',revision:1}:original(path,options);
 await env.context.managedRestoreReview(policy.id,1);assert.equal(env.state.activeManagedRestore,null);assert.match(env.errors.at(-1),/identity/);
 env.setForm({reason:'Try a copied summary'});await env.context.managedSubmit({preventDefault(){},target:{id:'managed-restore-form',dataset:{id:policy.id,revision:'1'}}});assert.equal(env.calls.filter(call=>call.path.endsWith('/rollback')).length,0);
});
test('rollout detail mismatch or a changed fresh nonce blocks confirmation without advancing authorization',async()=>{
 const env=environment();env.context.managedShowRollout(env.plan);const original=env.context.api;
 env.context.api=async(path,options)=>path===`/policy-rollouts/${env.plan.id}`?{...env.plan,summary_only:true}:original(path,options);
 await env.context.managedAction({dataset:{action:'managed-confirm-rollout'},disabled:false});assert.match(env.errors.at(-1),/exact frozen/);assert.equal(env.calls.filter(call=>call.path.endsWith('/confirm')).length,0);
 env.context.api=async(path,options)=>path===`/policy-rollouts/${env.plan.id}`?{...env.plan,confirmation_nonce:'fresh-server-nonce'}:original(path,options);
 await env.context.managedAction({dataset:{action:'managed-confirm-rollout'},disabled:false});assert.match(env.errors.at(-1),/exact review changed/);assert.equal(env.state.activeManagedRollout.confirmation_nonce,'fresh-server-nonce');assert.equal(env.calls.filter(call=>call.path.endsWith('/confirm')).length,0);
 env.context.api=async()=>({...env.plan,id:'other-review'});await assert.rejects(env.context.managedLoadRollout(env.plan.id),/exact frozen/);
});
test('overlapping rollout scopes discard late pages and an empty endpoint filter stays explicitly empty',async()=>{
 const env=environment(),pending=[];env.context.api=(path,options)=>new Promise(resolve=>pending.push({path,options,resolve}));
 env.state.filters.application=['billing'];env.context.filteredServers=()=>[{id:'billing-host'}];const first=env.context.refreshManagedRollouts();
 env.state.filters.application=['payments'];env.context.filteredServers=()=>[{id:'payment-host'}];const second=env.context.refreshManagedRollouts();
 pending[1].resolve({items:[{id:'payment-review',summary_only:true}],total:1,limit:20,offset:0,has_more:false});await second;
 pending[0].resolve({items:[{id:'billing-review',summary_only:true}],total:1,limit:20,offset:0,has_more:false});await first;
 assert.equal(env.state.managedRollouts[0].id,'payment-review');assert.deepEqual(Array.from(pending[0].options.body.server_ids),['billing-host']);assert.deepEqual(Array.from(pending[1].options.body.server_ids),['payment-host']);
 env.context.filteredServers=()=>[];const empty=env.context.refreshManagedRollouts();assert.deepEqual(Array.from(pending[2].options.body.server_ids),[]);pending[2].resolve({items:[],total:0,limit:20,offset:0,has_more:false});await empty;assert.equal(env.state.managedRollouts.length,0);
});
test('async rollout redraw preserves typed port/tag values, focus and caret while replacing visible results',()=>{
 const env=environment(),position=[];let inputs={'service-filter-input':{id:'service-filter-input',value:'8443/tcp',selectionStart:3,selectionEnd:5,focus(){position.push('focus')},setSelectionRange(a,b){position.push([a,b])}},'custom-tag-filter-input':{value:'owner=finance'}};
 env.context.document.activeElement=inputs['service-filter-input'];env.context.document.getElementById=id=>inputs[id];env.context.$=selector=>inputs[selector.slice(1)];env.context.render=()=>{inputs={'service-filter-input':{value:'',focus(){position.push('focus')},setSelectionRange(a,b){position.push([a,b])}},'custom-tag-filter-input':{value:''}}};
 env.context.managedRedraw();assert.equal(inputs['service-filter-input'].value,'8443/tcp');assert.equal(inputs['custom-tag-filter-input'].value,'owner=finance');assert.deepEqual(position,['focus',[3,5]]);
});
test('rollout and immutable revision pagination request bounded pages and retain complete-scope labels',async()=>{
 const env=environment();await env.context.refreshManagedRollouts({offset:20});const query=env.calls.find(call=>call.path==='/policy-rollouts/query');assert.equal(query.options.method,'POST');assert.equal(query.options.body.limit,20);assert.equal(query.options.body.offset,20);
 env.state.managedPagination={...env.state.managedPagination,total:81,offset:20,has_more:true};env.state.managedRollouts=[{id:'summary',name:'Large reviewed scope',summary_only:true,target_count:5000,matching_target_count:1,status:'completed',result_counts:{enforced:4999,rolled_back:1}}];
 const html=env.context.managedRolloutsHTML();assert.match(html,/5000 endpoints/);assert.match(html,/4999 Enforced/);assert.match(html,/of 81 matching records/);assert.match(html,/data-action="managed-rollouts-page"/);assert.doesNotMatch(html,/confirmation_nonce/);
 const original=env.context.api;env.context.api=async(path,options)=>path.includes('/revisions?')?{items:[{...policy,revision:21,summary_only:true,services:undefined}],total:61,limit:20,offset:20,has_more:true}:original(path,options);
 await env.context.managedPolicyHistory(policy.id,20);assert.match(env.shown.at(-1).html,/21–21 of 61/);assert.match(env.shown.at(-1).html,/data-action="managed-history-page"/);
});
test('managed navigation cache retains only eight recent histories',()=>{
 const env=environment(),cache={};for(let index=0;index<30;index++)env.context.managedRememberHistory(cache,'host-'+index,[{version:index}]);assert.equal(Object.keys(cache).length,8);assert.equal(cache['host-0'],undefined);assert.equal(cache['host-29'][0].version,29);
});
