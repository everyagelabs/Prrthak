const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');

const hash='a'.repeat(64),protectionHash='b'.repeat(64);
function review(overrides={}){
 return {id:'review-1',revision:3,digest:hash,confirmation_nonce:'private-fixture-nonce',action:'enable',server_ids:['host-1'],group_ids:[],status:'draft',can_apply:true,blockers:[],expires_at:new Date(Date.now()+600000).toISOString(),preview:{targets:[{server_id:'host-1',hostname:'Billing API',revision:0,base_version:7,version:8,digest:hash,services:[{port:8443,protocol:'tcp',sources:['192.0.2.8/32','2001:db8::8/128']}],protection:{digest:protectionHash,ssh_ports:[2022],management_sources:['192.0.2.9/32'],host_default_deny_control_profile:'host-inbound-control-v1'},ips:['192.0.2.50'],blockers:[]}]},...overrides};
}
function workspace(role='admin',demo=false){
 const fields=new Map(),requests=[],errors=[],notices=[];
 const element=selector=>{if(!fields.has(selector))fields.set(selector,{value:'',checked:false,disabled:false,hidden:false,open:false,textContent:'',dataset:{}});return fields.get(selector);};
 const c={console,URLSearchParams,Date,JSON,Map,Set,Number,String,Array,state:{view:'policies',policyTab:'default-deny',role,data:{meta:{demo},servers:[{id:'host-1',hostname:'Billing API',desired_version:7,ips:['192.0.2.50']}],groups:[]}},canWrite:()=>['admin','super_admin'].includes(c.state.role),h:value=>String(value??'').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;'),num:value=>Number(value)||0,badge:(label,tone)=>`<span data-tone="${tone}">${label}</span>`,timestamp:value=>String(value??'Not reported'),filterBarHTML:()=>'',errorSlot:'<p id="form-error"></p>',F:{groupMembers:(group,servers)=>servers.filter(server=>group.server_ids?.includes(server.id))},managedRolloutScope:()=>({key:c.scopeKey||'all',ids:c.scopeIds??null}),managedRedraw:()=>{},filteredServers:()=>c.state.data.servers,$:element,showModal:(title,html)=>{element('#modal').open=true;element('#modal-title').textContent=title;c.html=html;},closeModal:()=>{element('#modal').open=false;c.defaultDenyClose();},formError:error=>errors.push(error.message),toast:message=>notices.push(message),openServer:id=>notices.push('open '+id),FormData:class{constructor(form){this.values=form.values||{};}get(key){return this.values[key]??null;}getAll(key){const value=this.values[key];return Array.isArray(value)?value:value==null?[]:[value];}},api:async(path,options={})=>{requests.push({path,options});return path==='/host-default-deny/query'?{items:[],total:0,offset:options.body.offset,limit:20,has_more:false}:{status:'queued'};}};
 vm.createContext(c);vm.runInContext(fs.readFileSync(require.resolve('../default-deny-page.js'),'utf8'),c);
 return {c,element,requests,errors,notices,run:script=>vm.runInContext(script,c)};
}
function form(plan,ack='on'){return {id:'default-deny-review-form',dataset:{id:plan.id,digest:plan.digest,revision:String(plan.revision)},values:{acknowledge_downtime:ack}};}
function submit(env,target){return env.c.defaultDenySubmit({preventDefault(){},target});}

test('target selection is explicit and a current group does not authorize future members',()=>{
 const env=workspace();env.c.state.data.groups=[{id:'billing',name:'Billing',type:'static'}];env.c.defaultDenyShowSelection();
 assert.match(env.c.html,/No endpoint is selected automatically/);assert.match(env.c.html,/never opts future members in automatically/);assert.match(env.c.html,/name="server_ids"/);assert.match(env.c.html,/name="group_ids"/);assert.doesNotMatch(env.c.html,/\schecked(?:\s|>)/);
 const readonly=workspace('read_only');readonly.c.defaultDenyShowSelection();assert.equal(readonly.c.html,undefined);
});
test('each new or reloaded preview starts with an unchecked disabled push control',()=>{
 const env=workspace(),plan=review();env.element('#default-deny-ack').checked=true;env.c.defaultDenyShowReview(plan);
 assert.equal(env.element('#default-deny-ack').checked,false);assert.equal(env.element('button[type="submit"]').disabled,true);
 assert.match(env.c.html,/I understand unapproved inbound connections will be blocked and this can cause downtime\./);assert.doesNotMatch(env.c.html,/id="default-deny-ack"[^>]*\schecked/);
 env.element('#default-deny-ack').checked=true;env.c.defaultDenyChange({target:{id:'default-deny-ack',checked:true}});assert.equal(env.element('button[type="submit"]').disabled,false);
 env.c.defaultDenyShowReview(review({confirmation_nonce:'new-nonce'}));assert.equal(env.element('#default-deny-ack').checked,false);assert.equal(env.element('button[type="submit"]').disabled,true);
});
test('one actual Admin acknowledgement sends only the exact immutable confirmation body',async()=>{
 const env=workspace(),plan=review();env.c.defaultDenyShowReview(plan);env.element('#default-deny-ack').checked=true;await submit(env,form(plan));
 const pushes=env.requests.filter(request=>request.path.endsWith('/confirm'));assert.equal(pushes.length,1);assert.equal(pushes[0].path,'/host-default-deny/review-1/confirm');assert.deepEqual(JSON.parse(JSON.stringify(pushes[0].options.body)),{digest:hash,expected_revision:3,confirmation_nonce:'private-fixture-nonce',acknowledge_downtime:true});
 assert.equal(env.run('defaultDenyState.review'),null);assert.equal(env.element('#default-deny-ack').checked,false);assert.match(env.notices.join(' '),/queued does not mean applied/);assert.equal(pushes.some(request=>/approval|checker/.test(request.path)),false);
});
test('unchecked, string-false and stale form bindings cannot send a push',async()=>{
 for(const variant of ['unchecked','string','revision']){
  const env=workspace(),plan=review();env.c.defaultDenyShowReview(plan);env.element('#default-deny-ack').checked=variant!=='unchecked';const target=form(plan,variant==='string'?'false':'on');if(variant==='revision')target.dataset.revision='2';await submit(env,target);assert.equal(env.requests.length,0,variant);assert.ok(env.errors.length,variant);
 }
});
test('summary, omitted source, expired, duplicate and blocked reviews fail closed',()=>{
 const env=workspace();
 for(const mutate of [p=>p.summary_only=true,p=>p.preview.targets[0].sources_omitted=true,p=>delete p.preview.targets[0].services[0].sources,p=>p.expires_at='invalid',p=>p.expires_at=new Date(Date.now()-1000).toISOString(),p=>p.server_ids=['host-1','host-1'],p=>p.can_apply='true',p=>p.blockers=['Upgrade host_default_deny_v1 and explicitly configure allow_host_default_deny'],p=>delete p.preview.targets[0].protection.digest]){const plan=review();mutate(plan);env.c.defaultDenyShowReview(plan);assert.notEqual(env.c.defaultDenyReviewProblem(plan),'');assert.equal(env.element('#default-deny-ack').disabled,true);}
 const demo=workspace('admin',true),readonly=workspace('read_only');assert.match(demo.c.defaultDenyReviewProblem(review()),/Demo/);assert.match(readonly.c.defaultDenyReviewProblem(review()),/Admin/);
});
test('version, opt-in configuration and group membership changes clear a prior acknowledgement',()=>{
 for(const change of ['version','configuration','group']){
  const env=workspace(),plan=review({group_ids:['billing']});env.c.state.data.groups=[{id:'billing',revision:1,server_ids:['host-1']}];env.c.defaultDenyShowReview(plan);env.element('#default-deny-ack').checked=true;
  if(change==='version')env.c.state.data.servers[0].desired_version=8;
  if(change==='configuration')env.c.state.data.servers[0].configuration_state={digest:'new-digest'};
  if(change==='group')env.c.state.data.groups[0].server_ids=[];
  env.c.defaultDenyInvalidateReview();assert.equal(env.element('#default-deny-ack').checked,false,change);assert.equal(env.element('button[type="submit"]').disabled,true,change);assert.match(env.c.defaultDenyReviewProblem(plan),/changed/);
 }
});
test('changing action or scope discards the old review rather than reusing its acknowledgement',()=>{
 const env=workspace(),plan=review();env.c.defaultDenyShowReview(plan);env.element('#default-deny-ack').checked=true;env.c.defaultDenyShowSelection();assert.equal(env.run('defaultDenyState.review'),null);env.c.defaultDenyShowReview(review({id:'disable-2',action:'disable',digest:'d'.repeat(64)}));assert.equal(env.element('#default-deny-ack').checked,false);assert.match(env.c.html,/last applied allowed matrix/);
});
test('a failed or ambiguous request consumes the local acknowledgement and cannot auto-retry',async()=>{
 const env=workspace(),plan=review();env.c.api=async(path,options)=>{env.requests.push({path,options});throw new Error('Connection closed before receipt');};env.c.defaultDenyShowReview(plan);env.element('#default-deny-ack').checked=true;await submit(env,form(plan));assert.equal(env.requests.length,1);assert.equal(env.run('defaultDenyState.review'),null);assert.equal(env.element('#default-deny-ack').checked,false);
 env.element('#default-deny-ack').checked=true;await submit(env,form(plan));assert.equal(env.requests.length,1);assert.match(env.element('#default-deny-review-warning').textContent,/unverified/);
});
test('concurrent submit events publish at most once',async()=>{
 const env=workspace(),plan=review();let release;env.c.api=(path,options)=>{env.requests.push({path,options});return path.endsWith('/confirm')?new Promise(resolve=>release=resolve):Promise.resolve({items:[],total:0,offset:0,limit:20,has_more:false});};env.c.defaultDenyShowReview(plan);env.element('#default-deny-ack').checked=true;const first=submit(env,form(plan));await submit(env,form(plan));assert.equal(env.requests.length,1);release({status:'queued'});await first;assert.equal(env.requests.filter(request=>request.path.endsWith('/confirm')).length,1);
});
test('preview completion cannot replace a newer or unrelated dialog',async()=>{
 const env=workspace();let release;env.c.api=(path,options)=>{env.requests.push({path,options});return new Promise(resolve=>release=resolve);};env.c.defaultDenyShowSelection();const pending=submit(env,{id:'default-deny-selection-form',values:{operation:'enable',server_ids:['host-1']}});env.c.showModal('Unrelated dialog','Keep this draft');release(review());await pending;assert.equal(env.c.html,'Keep this draft');assert.equal(env.run('defaultDenyState.review'),null);
});
test('status queries filter before paging and stale responses cannot replace a newer scope',async()=>{
 const env=workspace(),pending=[];env.c.api=(path,options)=>{env.requests.push({path,options});return new Promise(resolve=>pending.push(resolve));};const first=env.c.loadDefaultDeny();env.c.scopeKey='billing';env.c.scopeIds=['host-1'];const next=env.c.loadDefaultDeny({force:true});pending[1]({items:[{server_id:'host-1',status:'review_required'}],total:1,offset:0,limit:20,has_more:false});await next;pending[0]({items:[],total:99,offset:0,limit:20,has_more:true});await first;assert.equal(env.run('defaultDenyState.page.total'),1);assert.deepEqual(JSON.parse(JSON.stringify(env.requests[1].options.body)),{limit:20,offset:0,server_ids:['host-1'],search:''});assert.match(env.c.defaultDenyHTML(),/Fresh downtime review required/);
});
test('matrix review escapes data, retains both address families and explains the fixed exceptions',()=>{
 const env=workspace(),plan=review();plan.preview.targets[0].hostname='<img src=x onerror=bad()>';plan.preview.targets[0].protection.note='<script>bad()</script>';env.c.defaultDenyShowReview(plan);assert.match(env.c.html,/192\.0\.2\.8\/32/);assert.match(env.c.html,/2001:db8::8\/128/);assert.match(env.c.html,/2022/);assert.match(env.c.html,/ICMP\/ICMPv6/);assert.match(env.c.html,/UDP 68\/546/);assert.match(env.c.html,/Monitor-only rows do not permit inbound access/);assert.match(env.c.html,/&lt;img/);assert.doesNotMatch(env.c.html,/<img|<script>/);
});
test('pending disable and stale-policy rows never claim the requested state was applied',()=>{
 const env=workspace();env.run("defaultDenyState.scope='all';defaultDenyState.page={items:[{server_id:'host-1',hostname:'Billing',desired_enabled:false,removal_pending:true,status:'applied',desired_version:9,applied_version:7}],total:1,offset:0,limit:20,has_more:false}");const html=env.c.defaultDenyHTML();assert.match(html,/Disable requested/);assert.match(html,/Removal pending/);assert.match(html,/Reported applied 7/);assert.doesNotMatch(html,/Disabled · endpoint verified|Applied · endpoint verified/);
});

test('reloading an unchanged stale review cannot clear its observed membership invalidation',()=>{
 const env=workspace(),plan=review({group_ids:['billing']});env.c.state.data.groups=[{id:'billing',revision:1,server_ids:['host-1']}];env.c.defaultDenyShowReview(plan);env.c.state.data.groups[0].revision=2;env.c.defaultDenyInvalidateReview();env.c.defaultDenyShowReview(structuredClone(plan));assert.match(env.c.defaultDenyReviewProblem(env.run('defaultDenyState.review')),/changed/);assert.equal(env.element('#default-deny-ack').disabled,true);
});
test('future proposed version is accepted only while its frozen base version still matches inventory',()=>{
 const env=workspace(),plan=review();assert.equal(plan.preview.targets[0].version,8);env.c.defaultDenyShowReview(plan);assert.equal(env.c.defaultDenyReviewProblem(plan),'');env.c.state.data.servers[0].desired_version=8;assert.match(env.c.defaultDenyReviewProblem(plan),/base policy version changed/);
});

test('never-enabled, previous receipts and current failed pushes stay distinct from live applied state',()=>{
 const env=workspace();let html=env.c.defaultDenyRowHTML({server_id:'host-1',desired_enabled:false,status:'not_enabled',active:false,active_verified:false});assert.match(html,/Not enabled/);assert.doesNotMatch(html,/Disabled ·|Last authenticated receipt reported an active/);
 html=env.c.defaultDenyRowHTML({server_id:'host-1',desired_enabled:true,status:'review_required',active:true,active_verified:true,last_good_version:7,last_outcome:{status:'enforced',is_current:false,version:7,rollout_id:'old-push',updated_at:'2026-11-01T00:00:00Z'}});assert.match(html,/Fresh downtime review required/);assert.match(html,/Previous push receipt · does not verify this push/);assert.match(html,/not a live kernel probe/);
 html=env.c.defaultDenyRowHTML({server_id:'host-1',desired_enabled:false,removal_pending:true,status:'rolled_back',active:true,last_outcome:{status:'rolled_back',is_current:true,version:9,last_good_version:7,error:'<rollback error>'}});assert.match(html,/Rolled back/);assert.match(html,/cleanup is still pending/);assert.match(html,/Current push receipt/);assert.match(html,/&lt;rollback error&gt;/);assert.doesNotMatch(html,/<rollback error>/);
});
