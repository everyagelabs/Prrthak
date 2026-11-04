const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const source=fs.readFileSync(path.join(__dirname,'..','firewall-activation-page.js'),'utf8');
const facts=()=>({firewalld_active:false,ufw_active:true,version:'2.3.1',backend:'nftables',ips:['10.0.0.8'],ssh_ports:[2022],management_sources:['10.20.0.0/24'],discovered_ports:[{port:8443,protocol:'tcp'}],translated_rules:[{family:'ipv4',source:'10.30.0.0/24',port:8443,protocol:'tcp',action:'accept',priority:-29000}],can_apply:true,blockers:[],notes:['Private backup required']});
const plan=()=>({id:'review-one',operation:'migrate_ufw',status:'preview',can_apply:true,blockers:[],challenge:'APPLY FIREWALL MAINTENANCE',digest:'exact-digest',confirmation_nonce:'exact-nonce',expires_at:new Date(Date.now()+60000).toISOString(),targets:[{server_id:'host-one',hostname:'billing-one',baseline_digest:'native-baseline',assessment:facts(),blockers:[]}]});
const page=()=>({items:[{server_id:'host-one',hostname:'billing-one',ips:['10.0.0.8'],firewalld_state:'not-running',job:{id:'job-one',plan_digest:'plan-digest',target_operation:'migrate_ufw',status:'assigned'},receipt:{id:'prior-job',plan_digest:'prior-digest',status:'completed',assessment:facts()}}],total:1,offset:0});
function fixture(handler){
 const requests=[],elements=new Map(),modals=[],messages=[];const element=(selector,parent)=>{if(parent?.fields)return parent.fields[selector];if(!elements.has(selector))elements.set(selector,{open:selector==='#modal',disabled:false,checked:false,value:''});return elements.get(selector);};
 const c={console,JSON,Object,Array,String,Number,Date,Promise,FormData:class{constructor(form){this.values=form.values||{};}get(key){return this.values[key]??null;}},state:{authType:'session',role:'admin',user:{id:'admin-one'},data:{servers:[{id:'host-one',hostname:'billing-one',ips:['10.0.0.8']}],groups:[{id:'billing',name:'Billing'}]}},$:element,$$:(selector,form)=>selector.includes('server_ids')?(form.selectedServers||[]).map(value=>({value})):(form.selectedGroups||[]).map(value=>({value})),badge:value=>'<span>'+value+'</span>',h:value=>String(value??'').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;'),num:value=>Number(value)||0,timestamp:value=>value||'',errorSlot:'<div class="form-error"></div>',canWrite:()=>['admin','super_admin'].includes(c.state.role),render(){},closeModal(){element('#modal').open=false;},showModal:(title,html)=>{element('#modal').open=true;modals.push({title,html});},toast:message=>messages.push(message),formError:error=>messages.push(error.message),api:async(url,options)=>{requests.push({url,options});return handler?handler(url,options):url.endsWith('/query')?page():url.endsWith('/confirm')?{status:'assigned'}:plan();}};
 vm.createContext(c);vm.runInContext(source,c);c.state.firewallActivationOwner=c.firewallActivationIdentity();c.state.firewallActivationPage=page();return {c,requests,elements,element,modals,messages};
}
const form=()=>({id:'firewall-activation-form',selectedServers:['host-one'],values:{operation:'migrate_ufw'}}),submit=form=>({target:form,preventDefault(){}});
const deferred=()=>{let resolve;const promise=new Promise(done=>{resolve=done;});return {promise,resolve};};

test('maintenance panel distinguishes live maintenance from monitor policies and preserves unsupported UFW',()=>{
 const f=fixture(),html=f.c.firewallActivationHTML();assert.match(html,/even when ordinary policy enforcement is monitor-only/);assert.match(html,/Start firewalld/);assert.match(html,/Stopped/);assert.match(html,/UFW is preserved/);assert.match(html,/Previous job/);assert.match(html,/Does not confirm the current request/);assert.match(html,/independent endpoint rollback watchdog/);
 f.c.state.firewallActivationPage.items[0].receipt.error='<script>alert(1)</script>';assert.match(f.c.firewallActivationHTML(),/&lt;script&gt;/);
});
test('selection stays explicit, no downtime is pre-acknowledged, and readonly cannot mutate',async()=>{
 const f=fixture();f.c.showFirewallActivationForm();assert.doesNotMatch(f.modals[0].html,/name="server_ids"[^>]*checked/);assert.doesNotMatch(f.modals[0].html,/acknowledge_downtime/);assert.match(f.modals[0].html,/Request fresh assessment/);assert.throws(()=>f.c.firewallActivationSelection({values:{operation:'migrate_ufw'}}),/Select at least one/);f.c.state.role='read_only';await f.c.firewallActivationSubmit(submit(form()));await f.c.firewallActivationAction({dataset:{action:'firewall-activation-open'}});assert.equal(f.requests.length,0);assert.equal(f.modals.length,1);
});
test('fresh assessment uses selected exact operation and never submits approval or service change',async()=>{
 const f=fixture(),selection=f.element('#firewall-activation-form');Object.assign(selection,form());await f.c.firewallActivationAction({dataset:{action:'firewall-activation-assess'}});assert.equal(f.requests[0].url,'/firewall-activation/assess');assert.equal(f.requests[0].options.body.operation,'migrate_ufw');assert.equal(f.requests[0].options.body.server_ids[0],'host-one');assert.equal('acknowledge_downtime' in f.requests[0].options.body,false);assert.match(f.messages[0],/Read-only endpoint assessment requested/);
});
test('starting firewalld waits for the exact assessment and a blocked review has no confirmation fields',async()=>{
 const job={id:'fresh',server_id:'host-one',plan_digest:'fresh-digest'};
 const f=fixture(url=>url.endsWith('/assess')?{items:[job]}:url.endsWith('/query')?{
   items:[{server_id:'host-one',hostname:'billing-one',job,receipt:{
    id:'old',plan_digest:'old-digest',status:'assessed',checked_at:new Date().toISOString()}}]
 }:plan());
 const selection=f.element('#firewall-activation-form');
 Object.assign(selection,form(),{fields:{'button[type="submit"]':{disabled:false}}});
 await f.c.firewallActivationAction({dataset:{action:'firewall-activation-assess'}});
 assert.match(f.element('#firewall-assessment-status').innerHTML,/Waiting for the agent/);
 assert.equal(selection.fields['button[type="submit"]'].disabled,true);
 assert.equal(f.requests.some(item=>item.url.endsWith('/preview')),false);
 f.c.showFirewallActivationReview({...plan(),can_apply:false,blockers:['Assessment blocked']});
 assert.doesNotMatch(f.modals.at(-1).html,/name="confirmation_phrase"|name="acknowledge_downtime"/);
});
test('exact review displays translated source/port/action and both fresh confirmation controls',()=>{
 const f=fixture(),review=plan();f.c.showFirewallActivationReview(review);const html=f.modals[0].html;assert.match(html,/10.30.0.0\/24/);assert.match(html,/8443\/tcp/);assert.match(html,/2022/);assert.match(html,/native-baseline/);assert.match(html,/No second administrator is required/);assert.match(html,/<input id="firewall-activation-ack" name="acknowledge_downtime" type="checkbox">/);assert.equal(f.c.firewallActivationReviewUsable(review,review.challenge,false),false);assert.equal(f.c.firewallActivationReviewUsable(review,'yes',true),false);assert.equal(f.c.firewallActivationReviewUsable(review,review.challenge,true),true);review.can_apply=false;assert.equal(f.c.firewallActivationReviewUsable(review,review.challenge,true),false);
});
test('push resets manual acknowledgement and sends exact frozen identity; assigned is not applied',async()=>{
 const f=fixture(),review=plan();f.c.showFirewallActivationReview(review);f.element('#firewall-activation-ack').checked=true;await f.c.firewallActivationSubmit(submit({id:'firewall-activation-review-form',values:{confirmation_phrase:review.challenge}}));assert.equal(f.requests[0].url,'/firewall-activation/review-one/confirm');assert.equal(f.requests[0].options.body.confirmation_nonce,'exact-nonce');assert.equal(f.requests[0].options.body.digest,'exact-digest');assert.equal(f.requests[0].options.body.acknowledge_downtime,true);assert.equal(f.element('#firewall-activation-ack').checked,false);assert.match(f.messages[0],/queued is not applied/);
});
test('full assessments load only for explicit single-endpoint inspection',async()=>{
 const f=fixture();await f.c.firewallActivationAction({dataset:{action:'firewall-activation-inspect',id:'host-one'}});assert.equal(f.requests[0].url,'/firewall-activation/query');assert.equal(f.requests[0].options.body.details,true);assert.equal(f.requests[0].options.body.limit,1);assert.equal(f.requests[0].options.body.server_ids.length,1);await f.c.loadFirewallActivation(false);assert.equal('details' in f.requests[1].options.body,false);
});
test('identity changes and closed dialogs discard stale history and preview responses',async()=>{
 const pending=deferred(),f=fixture(()=>pending.promise),loading=f.c.loadFirewallActivation(false);f.c.state.user={id:'different-admin'};pending.resolve(page());await loading;assert.equal(f.c.firewallActivationPage().items,undefined);
 const request=deferred(),g=fixture(()=>request.promise),saving=g.c.firewallActivationSubmit(submit(form()));g.element('#modal').open=false;request.resolve(plan());await saving;assert.equal(g.modals.length,0);
 const old=fixture();old.c.showFirewallActivationReview(plan());old.c.state.user={id:'other-admin'};assert.equal(old.c.firewallActivationReviewUsable(plan(),'APPLY FIREWALL MAINTENANCE',true),false);
});
