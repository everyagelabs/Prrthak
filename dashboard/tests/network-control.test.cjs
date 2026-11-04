const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const source=fs.readFileSync(path.join(__dirname,'..','network-control-page.js'),'utf8');
const descriptor=()=>({id:'child-one',generation:2,plan_digest:'child-digest',operation:'apply',default_deny:true,services:[{port:443,protocol:'tcp',destinations:['10.20.0.0/16']}],expires_at:new Date(Date.now()+900000).toISOString()});
const plan=()=>({id:'plan-one',kind:'egress',operation:'apply',status:'draft',assessment:false,server_ids:['host-one'],group_ids:[],can_apply:true,blockers:[],digest:'exact-digest',confirmation_nonce:'exact-nonce',confirmation_phrase:'APPLY OUTBOUND CHANGE TO 1 SERVERS',expires_at:new Date(Date.now()+60000).toISOString(),preview:{targets:[{server_id:'host-one',hostname:'billing-one',ips:['10.0.0.8'],descriptor:descriptor(),management:{ssh_ports:[2022]},protected_egress:[],blockers:[]}]}});
function fixture(handler){
 const requests=[],elements=new Map(),modals=[],messages=[];
 const element=(selector,parent)=>{if(parent?.fields)return parent.fields[selector];if(!elements.has(selector))elements.set(selector,{open:false,disabled:false,checked:false,value:''});return elements.get(selector);};
 const c={console,JSON,Object,Array,String,Number,Date,Promise,FormData:class{constructor(form){this.values=form.values||{};}get(key){return this.values[key]??null;}},state:{authType:'session',role:'admin',user:{id:'admin-one'},view:'network-control',data:{servers:[{id:'host-one',hostname:'billing-one',ips:['10.0.0.8']}],groups:[{id:'billing',name:'Billing'}]},networkControlPage:{items:[plan()],total:1,offset:0,has_more:false}},$:element,$$:(selector,form)=>selector.includes('server_ids')?(form.selectedServers||[]).map(value=>({value})):selector.includes('group_ids')?(form.selectedGroups||[]).map(value=>({value})):selector==='.network-service-row'?form.rows||[]:[],h:value=>String(value??'').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;'),num:value=>Number(value)||0,badge:(text,tone)=>`<span class="${tone}">${text}</span>`,timestamp:value=>value||'',errorSlot:'<div class="form-error"></div>',canWrite:()=>['admin','super_admin'].includes(c.state.role),render(){},closeModal(){},showModal:(title,html)=>modals.push({title,html}),toast:message=>messages.push(message),formError:error=>messages.push(error.message),api:async(url,options)=>{requests.push({url,options});return handler?handler(url,options):url.endsWith('/confirm')?{status:'queued'}:url.endsWith('/assess')?{...plan(),assessment:true,operation:'assess',status:'queued'}:url.includes('?')?{items:[plan()],total:1,offset:0,has_more:false}:plan();}};
 vm.createContext(c);vm.runInContext(source,c);c.state.networkControlOwner=c.networkControlIdentity();return {c,requests,modals,messages,element};
}
const submit=form=>({target:form,preventDefault(){}});
const row=(destinations='',denied=false)=>({fields:{'[name="egress_port"]':{value:'443'},'[name="egress_protocol"]':{value:'tcp'},'[name="egress_deny_port"]':{checked:denied},'[name="egress_destinations"]':{value:destinations}}});
const deferred=()=>{let resolve;const promise=new Promise(done=>{resolve=done;});return {promise,resolve};};

test('separate outbound/quarantine GUI distinguishes intent, established-traffic isolation and expiry receipts',()=>{
 const f=fixture(),html=f.c.networkControlHTML();assert.match(html,/Outbound & quarantine/);assert.match(html,/Queued intent|Ready for exact review/);assert.match(html,/covers established application traffic/);assert.match(html,/waits for an authenticated receipt before claiming release/);assert.match(html,/future members are not automatically enabled/);assert.match(html,/ordinary inbound policy save/);
 f.c.state.networkControlPage.items[0].blockers=['<script>unsafe</script>'];assert.match(f.c.networkControlHTML(),/&lt;script&gt;unsafe&lt;\/script&gt;/);
});
test('new forms select no servers or default deny automatically and readonly cannot open mutation flow',async()=>{
 const f=fixture();f.c.showNetworkControlForm('egress');let html=f.modals[0].html;assert.doesNotMatch(html,/<input name="server_ids"[^>]*checked/);assert.match(html,/<input name="default_deny" type="checkbox">/);assert.match(html,/Request fresh native assessment/);assert.match(html,/Deny this port/);
 f.c.state.role='read_only';await f.c.networkControlAction({dataset:{action:'network-control-new-quarantine'}});await f.c.networkControlSubmit(submit({id:'network-control-form'}));assert.equal(f.modals.length,1);assert.equal(f.requests.length,0);f.c.showNetworkControlReview(plan());assert.doesNotMatch(f.modals[1].html,/id="network-control-ack"/);
});
test('empty destinations require explicit selected-port deny; removal ignores the application matrix',()=>{
 const f=fixture(),form={dataset:{kind:'egress'},selectedServers:['host-one'],values:{operation:'apply'},rows:[row()]};assert.throws(()=>f.c.networkControlPayload(form),/Provide destination CIDRs/);form.rows=[row('',true)];let body=f.c.networkControlPayload(form);assert.equal(body.default_deny,false);assert.equal(body.services[0].destinations.length,0);form.rows=[row('10.20.0.0/16,2001:db8::/64')];body=f.c.networkControlPayload(form);assert.equal(body.services[0].destinations.length,2);form.values.operation='remove';form.values.default_deny='on';body=f.c.networkControlPayload(form);assert.equal(body.default_deny,false);assert.equal(body.services.length,0);
 assert.throws(()=>f.c.networkControlSelection({dataset:{kind:'egress'}}),/Select at least one/);
});
test('current exact phrase plus manual downtime acknowledgement are both mandatory and reset each review',()=>{
 const f=fixture(),review=plan();f.c.showNetworkControlReview(review);assert.match(f.modals[0].html,/<input id="network-control-ack" name="acknowledge_downtime" type="checkbox">/);assert.equal(f.c.networkControlReviewUsable(review,review.confirmation_phrase,false),false);assert.equal(f.c.networkControlReviewUsable(review,'yes',true),false);assert.equal(f.c.networkControlReviewUsable(review,review.confirmation_phrase,true),true);f.c.state.user={id:'different-admin'};assert.equal(f.c.networkControlReviewUsable(review,review.confirmation_phrase,true),false);
});
test('push carries exact frozen nonce/digest and reports queued intent separately from endpoint application',async()=>{
 const f=fixture(),review=plan();f.c.showNetworkControlReview(review);f.element('#network-control-ack').checked=true;await f.c.networkControlSubmit(submit({id:'network-control-review-form',values:{confirmation_phrase:review.confirmation_phrase}}));const request=f.requests[0];assert.equal(request.url,'/network-control/plan-one/confirm');assert.equal(request.options.body.confirmation_nonce,'exact-nonce');assert.equal(request.options.body.digest,'exact-digest');assert.equal(request.options.body.acknowledge_downtime,true);assert.equal(f.element('#network-control-ack').checked,false);assert.match(f.messages[0],/Wait for authenticated endpoint receipts/);
});
test('fresh assessment is a separate signed read-only operation and cannot be mistaken for applying policy',async()=>{
 const f=fixture(),form=f.element('#network-control-form');Object.assign(form,{dataset:{kind:'quarantine'},selectedServers:['host-one'],selectedGroups:[],values:{operation:'enable'}});await f.c.networkControlAction({dataset:{action:'network-control-assess-form'}});assert.equal(f.requests[0].url,'/network-control/assess');assert.equal(f.requests[0].options.body.kind,'quarantine');assert.equal('operation' in f.requests[0].options.body,false);assert.match(f.messages[0],/read-only assessment requested/);assert.doesNotMatch(f.modals[0].html,/id="network-control-ack"/);
});
test('previous receipts never confirm a new operation and malicious target text is escaped',()=>{
 const f=fixture(),target=plan().preview.targets[0];target.last_report={...descriptor(),id:'older-child',status:'enforced',error:'<img src=x>'};let html=f.c.networkControlTargetHTML(target);assert.match(html,/Previous operation receipt · does not confirm this push/);assert.match(html,/&lt;img src=x&gt;/);target.last_report.id=target.descriptor.id;html=f.c.networkControlTargetHTML(target);assert.match(html,/This operation receipt/);
});
test('rolled-back replacement still shows independently reported old active control and original lease',()=>{
 const f=fixture(),target=plan().preview.targets[0];target.last_report={...descriptor(),status:'rolled_back',active:true,active_generation:1,active_expires_at:'2026-11-04T12:30:00Z'};const html=f.c.networkControlReceiptHTML(target);assert.match(html,/This operation receipt: rolled_back/);assert.match(html,/separately records an active existing control/);assert.match(html,/2026-11-04T12:30:00Z/);assert.match(html,/does not mean the previous control was removed/);
});
test('late history loads and preview responses cannot cross identity changes',async()=>{
 const pending=deferred(),f=fixture(()=>pending.promise),loading=f.c.loadNetworkControl(false);f.c.state.user={id:'replacement'};pending.resolve({items:[plan()]});await loading;assert.equal(f.c.networkControlPage().items,undefined);
 const request=deferred(),g=fixture(()=>request.promise),saving=g.c.networkControlSubmit(submit({id:'network-control-form',dataset:{kind:'egress'},selectedServers:['host-one'],values:{operation:'apply'},rows:[row('10.20.0.0/16')]}));g.c.state.role='read_only';request.resolve(plan());await saving;assert.equal(g.modals.length,0);
});
