const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const app=fs.readFileSync(path.join(__dirname,'..','app.js'),'utf8');
const source=fs.readFileSync(path.join(__dirname,'..','policy-catalogue-page.js'),'utf8');
const deferred=()=>{let resolve;const promise=new Promise(done=>{resolve=done;});return {promise,resolve};};
function result({id='policy-1',draft=false,items,offset=0,total=1,...rest}={}){
 const rows=items || [{server_id:'host-1',hostname:'Billing host',source_ip:'192.0.2.10',port:443,protocol:'tcp',origin:'learning',capture_scope_id:'session-a',capture_kind:'accepted_connection',capture_backend:'conntrack',count_unit:'connections',count:3,first_seen:'2026-11-04T01:00:00Z',last_seen:'2026-11-04T01:01:00Z',current_decision:'would_allow',proposed_decision:'would_block',reason:'Outside the compiled source allowlist',coverage:{complete_window:false,receipt_available:false,endpoint_stale:false,dropped_events:null}}];
 return {read_only:true,model:'compiled_ingress_intent',context_digest:'a'.repeat(64),policy:{id,name:'Billing',revision:3,proposed:draft},as_of:'2026-11-04T01:02:00Z',from_time:'2026-11-04T00:02:00Z',window_seconds:3600,summary:{target_servers:5000,effective_changed_servers:5000,relationships:1,by_outcome:{would_allow:0,would_block:1,unverified:0},servers_with_observations:1,servers_without_observations:4999},items:rows,total,offset,limit:50,next_offset:offset+rows.length,has_more:offset+rows.length<total,total_is_lower_bound:false,targets:{items:[{server_id:'host-1',hostname:'Billing host',has_observations:true,observation_status:'observed'}],total:5000,has_more:true},coverage:{complete_window:false,evaluation_limit_reached:false},limitations:['Existing connections and application success are unverified.'],...rest};
}
function fixture({role='admin',request}={}){
 const elements=new Map(),requests=[],listeners={},children=[];
 const element=selector=>{if(!elements.has(selector))elements.set(selector,{id:selector.startsWith('#')?selector.slice(1):'',innerHTML:'',textContent:'',hidden:false,open:false,value:'',dataset:{},append(child){children.push(child);},querySelector(selector){return selector==='.modal-body'?element('#editor-body'):null;}});return elements.get(selector);};
 const c={console,JSON,Array,String,Number,Object,Set,Map,Date,Promise,Error,AbortController,FormData:class{constructor(form){this.values=form.values || {};}get(name){return this.values[name] ?? null;}getAll(name){const value=this.values[name];return Array.isArray(value)?value:value===undefined?[]:[value];}},setTimeout,clearTimeout,state:{authType:'session',role,user:{id:'admin',tenant_id:'tenant'},csrfToken:'csrf',filters:{ports:[]},flowServer:'all',search:'',data:{servers:[{id:'host-1'}],meta:{traffic_retention_hours:24}}},document:{addEventListener(name,handler){(listeners[name] ||= []).push(handler);},createElement(){return {innerHTML:'',id:''};}},$:element,F:{matchServer:()=>true,count:()=>0},L:{withLocation:(tags,id)=>id?{...tags,location_id:id}:tags},parseTags:text=>Object.fromEntries(text?text.split(',').map(pair=>pair.trim().split('=')):[]),collectPolicyServices:form=>form.rules,format:String,num:value=>Number(value)||0,timestamp:value=>String(value || 'Not reported'),h:value=>String(value ?? '').replace(/[&<>"']/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char])),showModal(title,html){element('#modal').open=true;element('#modal-title').textContent=title;element('#modal-content').innerHTML=html;},fetch:async(url,options)=>{requests.push({url,options});const body=JSON.parse(options.body),value=request?await request(url,body,c):result({id:body.policy_id || 'policy-1',draft:url.endsWith('/policies/impact')});return {ok:true,status:200,json:async()=>value};}};
 vm.createContext(c);
 vm.runInContext(app.slice(app.indexOf('async function api('),app.indexOf('\nfunction toast(')),c);
 vm.runInContext(app.match(/function canWrite\(\)\{[^\n]+/)[0],c);
 vm.runInContext(app.slice(app.indexOf('function policyEditorTarget('),app.indexOf('function updatePolicyTargets(')),c);
 vm.runInContext(source,c);
 const run=code=>vm.runInContext(code,c);
 const action=(action,extra={})=>c.policyCatalogueAction({dataset:{action,...extra}});
 function draft(id='policy-1'){
  const form=element('#policy-form');form.dataset={id};form.values={name:'Edited billing',mode:'enforce',target_type:'tags',selector:'application=billing',target_location_id:'dc-a'};form.rules=[{port:443,protocol:'tcp',sources:['192.0.2.20/32'],source_selector:{}}];
  c.state.activePolicyEditor={kind:'managed',id,policy:{id,revision:3,services:form.rules}};element('#modal').open=true;element('#modal-title').textContent='Edit access policy';return form;
 }
 return {c,element,requests,listeners,children,run,action,draft};
}
test('Read Only previews saved policy with CSRF and never calls a publishing route',async()=>{
 const f=fixture({role:'read_only'});await f.action('policy-catalogue-impact',{id:'policy-1'});
 assert.equal(f.requests.length,1);assert.equal(f.requests[0].url,'/api/v1/policies/policy-1/impact');assert.equal(f.requests[0].options.headers['X-CSRF-Token'],'csrf');
 const html=f.element('#policy-impact-results').innerHTML;assert.match(html,/5000/);assert.match(html,/4999/);assert.match(html,/Would block new ingress/);assert.match(html,/live enforcement is unverified/);assert.match(html,/Loss count unknown/);assert.doesNotMatch(html,/Traffic verified|successfully applied|Safe to apply/);
 await assert.rejects(()=>f.c.api('/policies/impact',{method:'POST',body:{policy:{}}}),/Read Only/);await f.action('policy-catalogue-impact-draft');assert.equal(f.requests.length,1);
});
test('draft preview preserves unsaved fields and sends exact form intent and revision only to analysis',async()=>{
 const f=fixture(),form=f.draft();f.c.policyImpactAttachEditor();assert.equal(f.children.length,1);assert.match(f.children[0].innerHTML,/Preview the current unsaved form/);assert.match(f.children[0].innerHTML,/type="button"[^>]*policy-catalogue-impact-draft/);
 const original=JSON.stringify(form.values);await f.action('policy-catalogue-impact-draft');assert.equal(JSON.stringify(form.values),original);assert.equal(f.element('#modal-title').textContent,'Edit access policy');assert.equal(f.c.state.activePolicyEditor.id,'policy-1');
 const request=f.requests[0],body=JSON.parse(request.options.body);assert.equal(request.url,'/api/v1/policies/impact');assert.equal(body.policy_id,'policy-1');assert.equal(body.expected_revision,3);assert.equal(body.policy.name,'Edited billing');assert.deepEqual(body.policy.selector,{application:'billing',location_id:'dc-a'});assert.deepEqual(body.policy.services,form.rules);assert.equal(body.policy.mode,'enforce');assert.equal(body.policy.confirmation_nonce,undefined);
});
test('source port outcome and time filters precede paging with stable analysis context',async()=>{
 const f=fixture({request:(url,body)=>result({offset:body.offset,total:60})});await f.action('policy-catalogue-impact',{id:'policy-1'});
 f.element('#policy-impact-source').value='2001:db8::/64';f.element('#policy-impact-ports').value='443/tcp, 53/udp';f.element('#policy-impact-outcome').value='would_block';f.element('#policy-impact-window').value='300';await f.action('policy-catalogue-impact-run');
 await f.action('policy-catalogue-impact-page',{offset:'50'});const body=JSON.parse(f.requests.at(-1).options.body);assert.equal(body.source_ip,'2001:db8::/64');assert.deepEqual(body.ports,['443/tcp','53/udp']);assert.equal(body.outcome,'would_block');assert.equal(body.window_seconds,300);assert.equal(body.offset,50);assert.equal(body.context_digest,'a'.repeat(64));assert.equal(body.as_of,'2026-11-04T01:02:00Z');
 f.element('#policy-impact-ports').value='8443/tcp';const count=f.requests.length;await f.action('policy-catalogue-impact-page',{offset:'0'});assert.equal(f.requests.length,count);assert.match(f.element('#policy-impact-error').textContent,/filters changed/);
});
test('invalid ports and stale draft identities never trigger a preview or implicit save',async()=>{
 const f=fixture(),form=f.draft();f.element('#policy-impact-ports').value='65536/tcp';await f.action('policy-catalogue-impact-draft');assert.equal(f.requests.length,0);assert.match(f.element('#policy-impact-error').textContent,/exact ports/);
 f.element('#policy-impact-ports').value='';f.c.state.activePolicyEditor.id='another-policy';await f.action('policy-catalogue-impact-draft');assert.equal(f.requests.length,0);
 let prevented=false;f.listeners.keydown.find(fn=>fn.name==='policyImpactKeydown')({key:'Enter',target:{closest:()=>form},preventDefault(){prevented=true;}});assert.equal(prevented,true);
});
test('no observations and bounded evaluation display unknown dependencies without inventing safety',async()=>{
 const f=fixture({request:()=>result({items:[],total:0,total_is_lower_bound:true,summary:{target_servers:20,effective_changed_servers:20,relationships:0,by_outcome:{},servers_with_observations:0,servers_without_observations:null},coverage:{complete_window:false,evaluation_limit_reached:true}})});await f.action('policy-catalogue-impact',{id:'policy-1'});const html=f.element('#policy-impact-results').innerHTML;assert.match(html,/No retained observations match/);assert.match(html,/does not mean it is safe to block/);assert.match(html,/Totals are lower bounds/);assert.match(html,/Unknown · evaluation bounded/);assert.doesNotMatch(html,/Safe to apply|All endpoints passed/);
});
test('connection packet and legacy units and escaped coverage remain distinct',async()=>{
 const base=result().items[0],rows=[{...base,source_ip:'<img src=x>',hostname:'<script>host</script>',reason:'<svg onload=x>',capture_scope_id:'<b>scope</b>',coverage:{receipt_available:true,dropped_events:2,rate_limited:true,capture_gaps:['<bad>'],error:'<offline>'}},{...base,capture_kind:'denied_packet',count_unit:'packets',count:7,proposed_decision:'unverified'},{...base,capture_kind:'legacy_log',count_unit:'log_records',count:9,coverage:{legacy_sampled_logs:true}}];
 const f=fixture({request:()=>result({items:rows,total:3})});await f.action('policy-catalogue-impact',{id:'policy-1'});const html=f.element('#policy-impact-results').innerHTML;for(const label of ['3 connections','7 packets','9 log_records','sampled legacy logs','rate limited'])assert.ok(html.includes(label));assert.doesNotMatch(html,/<img src|<script>host|<svg onload|<bad>|<offline>/);assert.match(html,/&lt;offline&gt;/);
});
test('late responses cannot overwrite a closed modal different user or newer request',async()=>{
 for(const mode of ['closed','identity','replaced']){const pending=deferred(),f=fixture({request:()=>pending.promise});const call=f.action('policy-catalogue-impact',{id:'policy-1'});if(mode==='closed')f.element('#modal').open=false;if(mode==='identity')f.c.state.user={id:'other'};if(mode==='replaced'){f.element('#modal-title').textContent='Different form';f.element('#policy-impact-results').innerHTML='other draft';}pending.resolve(result());await call;assert.doesNotMatch(f.element('#policy-impact-results').innerHTML,/Billing host/);}
 const pending=[],f=fixture({request:()=>new Promise(resolve=>pending.push(resolve))});const first=f.action('policy-catalogue-impact',{id:'policy-1'}),second=f.action('policy-catalogue-impact-run');pending[1](result({items:[{...result().items[0],hostname:'Newer result'}]}));await second;pending[0](result({items:[{...result().items[0],hostname:'Stale result'}]}));await first;assert.match(f.element('#policy-impact-results').innerHTML,/Newer result/);assert.doesNotMatch(f.element('#policy-impact-results').innerHTML,/Stale result/);
});
test('malformed foreign oversized or falsely complete results fail closed',async()=>{
 for(const value of [result({id:'another-policy'}),result({items:Array(101).fill(result().items[0])}),result({coverage:{complete_window:true}}),result({items:[{...result().items[0],proposed_decision:'verified'}]}),result({items:[{...result().items[0],count_unit:'requests'}]})]){const f=fixture({request:()=>value});await f.action('policy-catalogue-impact',{id:'policy-1'});assert.equal(f.element('#policy-impact-error').hidden,false);assert.match(f.element('#policy-impact-results').innerHTML,/No safe\/allow\/block conclusion/);assert.doesNotMatch(f.element('#policy-impact-results').innerHTML,/Billing host/);}
});

test('draft preview submits exact endpoint IDs and requires acknowledgement to expand to the fleet',async()=>{
 const f=fixture(),form=f.draft();f.c.state.activePolicyEditor.policy.endpoint_ids=['host-1'];
 form.values.target_type='endpoints';form.values.target_endpoints=['host-1','host-1'];
 await f.action('policy-catalogue-impact-draft');
 assert.deepEqual(JSON.parse(f.requests.at(-1).options.body).policy.endpoint_ids,['host-1']);
 form.values.target_type='all';const count=f.requests.length;
 await f.action('policy-catalogue-impact-draft');assert.equal(f.requests.length,count);assert.match(f.element('#policy-impact-error').textContent,/fleet-wide expansion/);
 form.values.confirm_match_all='on';await f.action('policy-catalogue-impact-draft');
 const request=JSON.parse(f.requests.at(-1).options.body);assert.equal(request.policy.match_all,true);assert.equal(request.policy.endpoint_ids,undefined);
});
