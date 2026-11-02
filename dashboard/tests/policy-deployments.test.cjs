const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const app=fs.readFileSync(path.join(__dirname,'..','app.js'),'utf8');
const moduleSource=fs.readFileSync(path.join(__dirname,'..','policy-deployments-page.js'),'utf8');
const deferred=()=>{let resolve;const promise=new Promise(done=>{resolve=done;});return {promise,resolve};};
function summary(id='change-1',updates={}){return {id,label:'Billing source change',origin:'policy',policy_id:'billing',created_at:'2026-11-02T12:00:00Z',created_by:'Admin',deadline_at:'2026-11-02T12:10:00Z',target_count:20,applied_count:12,traffic_verified_count:0,active_count:20,failed_count:0,awaiting_count:12,unverified_count:0,unavailable_count:0,rolled_back_count:0,superseded_count:0,state:'active',...updates};}
function target(id='server-1',updates={}){return {server_id:id,hostname:id+'-billing',version:42,digest:'a'.repeat(64),approval_id:'approval-'+id,apply_status:'applied',traffic_status:'awaiting',readback_at:'2026-11-02T12:01:00Z',armed_at:'2026-11-02T12:01:00Z',last_seen:'2026-11-02T12:01:01Z',reason:'Waiting for matching observed traffic',port_count:2,verified_port_count:0,checked_at:'2026-11-02T12:01:01Z',deadline_at:'2026-11-02T12:10:00Z',...updates};}
function evidence(updates={}){return {source_ip:'192.0.2.10',destination_ip:'198.51.100.20',address_family:'ipv4',capture_kind:'conntrack',expected_action:'allow',observed_at:'2026-11-02T12:01:03Z',...updates};}
function ports(updates={}){return {...target(),ports:[{port:443,protocol:'tcp',status:'awaiting',allow:{status:'verified',evidence:evidence()},deny:{status:'awaiting',reason:'No denied packet observed'}},{port:2022,protocol:'tcp',status:'awaiting',allow:{status:'awaiting'},deny:{status:'not_applicable',reason:'No denied check is required'}}],...updates};}
function page(items,total=items.length,limit=10,offset=0,extra={}){return {items,total,limit,offset,has_more:offset+items.length<total,...extra};}
function fixture({role='admin',request}={}){
 const elements=new Map(),listeners={},requests=[],timers=new Map();let nextTimer=1;
 const element=selector=>{if(!elements.has(selector))elements.set(selector,{selector,innerHTML:'',textContent:'',disabled:false,hidden:false,open:false,dataset:{},attributes:{},setAttribute(name,value){this.attributes[name]=String(value);},focus(){c.document.activeElement=this;},closest(value){return value===selector?this:null;},querySelector(value){const id=value.startsWith('#')?value.slice(1):'';return id&&this.innerHTML.includes(`id="${id}"`)?element(value):null;},querySelectorAll(){return [];}});return elements.get(selector);};
 const c={console,JSON,Array,String,Number,Object,Set,Map,Date,Promise,URL,Error,AbortController,state:{authType:'session',authConfig:{mode:'entra'},role,user:{id:'admin',tenant_id:'tenant'},token:'',csrfToken:'csrf'},document:{hidden:false,activeElement:null,addEventListener:(name,handler)=>{(listeners[name]||=[]).push(handler);}},$:element,h:value=>String(value??'').replace(/[&<>"']/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char])),num:value=>Number(value)||0,format:String,timestamp:value=>String(value||'Not reported'),icon:name=>`<svg data-icon="${name}"></svg>`,setTimeout:handler=>{const id=nextTimer++;timers.set(id,handler);return id;},clearTimeout:id=>timers.delete(id),closeAccountMenu(){},showModal:(title,html)=>{element('#modal').open=true;element('#modal-title').textContent=title;element('#modal-content').innerHTML=html;},fetch:async(url,options)=>{
  requests.push({url,options});let value=request?await request(url,options,c):undefined;
  if(value===undefined){
   const parsed=new URL('http://fixture'+url),offset=Number(parsed.searchParams.get('offset')||0);
   if(parsed.pathname==='/api/v1/policy-deployments')value=page(offset?[]:[summary()],1,10,offset,{active_total:1});
   else if(parsed.pathname==='/api/v1/policy-deployments/change-1')value=summary();
   else if(parsed.pathname==='/api/v1/policy-deployments/change-1/targets')value=page([target(),target('server-2',{apply_status:'applying',traffic_status:'awaiting_apply'})],20,50,offset);
   else if(parsed.pathname.startsWith('/api/v1/policy-deployments/change-1/targets/')){const id=decodeURIComponent(parsed.pathname.split('/').at(-1));value=ports({server_id:id});}
   else throw new Error('Unexpected request '+url);
  }
  return {ok:true,status:200,json:async()=>value};
 }};
 c.closeModal=()=>{c.policyDeploymentsModalClosed();element('#modal').open=false;element('#modal-content').innerHTML='';};
 vm.createContext(c);const start=app.indexOf('async function api('),end=app.indexOf('\nfunction toast(',start);vm.runInContext(app.slice(start,end),c);vm.runInContext(app.match(/function canWrite\(\)\{[^\n]+/)[0],c);vm.runInContext(moduleSource,c);
 const state=()=>vm.runInContext('policyDeploymentsState',c),dispatch=(type,event)=>listeners[type]?.forEach(handler=>handler(event));
 return {c,state,element,requests,timers,dispatch};
}
test('top-right status uses bounded server summaries and exact counts for a 5000-server publication',async()=>{
 const f=fixture({request:url=>url.startsWith('/api/v1/policy-deployments?')?page([summary('change-1',{target_count:5000,applied_count:4998,traffic_verified_count:4200,active_count:800,awaiting_count:798})],600,10,0,{active_total:40}):undefined});
 f.c.renderPolicyDeploymentsChrome();await f.c.refreshPolicyDeployments();
 assert.equal(f.requests.length,1);assert.equal(f.requests[0].url,'/api/v1/policy-deployments?limit=10&offset=0');assert.equal(f.element('#policy-deployments-count').textContent,'40');assert.equal(f.element('#policy-deployments-count').hidden,false);
 const html=f.element('#policy-deployments-list').innerHTML;assert.match(html,/4998 \/ 5000/);assert.match(html,/4200 \/ 5000/);assert.match(html,/of 600/);assert.match(html,/No verification traffic probes are generated/);assert.doesNotMatch(html,/Traffic verified[^<]*5000/);
});
test('Read Only can query target receipts and evidence through the production API wrapper and cannot mutate',async()=>{
 const f=fixture({role:'read_only'});await f.c.policyDeploymentsOpen('change-1');await f.c.policyDeploymentsAction({dataset:{action:'policy-deployment-target',id:'server-1'}});
 assert.equal(f.requests.length,3);assert.ok(f.requests.every(row=>!row.options.method||row.options.method==='GET'));assert.match(f.element('#policy-deployment-detail').innerHTML,/192\.0\.2\.10/);assert.match(f.element('#policy-deployment-detail').innerHTML,/2022\/tcp/);
 await assert.rejects(()=>f.c.api('/policies',{method:'POST',body:{}}),/Read Only access/);assert.equal(f.requests.length,3);
});
test('Applied and Traffic verified remain independent and absent traffic never becomes a fake pass',async()=>{
 const f=fixture();await f.c.policyDeploymentsOpen('change-1');let html=f.element('#policy-deployment-detail').innerHTML;
 assert.match(html,/deployment-status-badge verified">Applied/);assert.match(html,/Awaiting traffic/);assert.doesNotMatch(html,/deployment-status-badge verified">Traffic verified/);assert.match(html,/No matching traffic stays Awaiting until the deadline, then Unverified/);
 f.state().targets.items[0].traffic_status='unverified';f.state().targets.items[0].apply_status='rolled_back';f.c.renderPolicyDeploymentsDetail();html=f.element('#policy-deployment-detail').innerHTML;assert.match(html,/Rolled back/);assert.match(html,/Unverified/);assert.doesNotMatch(html,/deployment-status-badge verified">Traffic verified/);
 assert.doesNotMatch(f.c.policyDeploymentsBadge('enforced','apply'),/verified/);assert.match(f.c.policyDeploymentsBadge('unsupported_new_state'),/Status unknown/);
});
test('per-port allow and deny witnesses are separate and malformed verification cannot appear green',async()=>{
 const f=fixture();await f.c.policyDeploymentsOpen('change-1');await f.c.policyDeploymentsAction({dataset:{action:'policy-deployment-target',id:'server-1'}});let html=f.element('#policy-deployment-detail').innerHTML;
 assert.match(html,/443\/tcp/);assert.match(html,/Allowed traffic/);assert.match(html,/Denied traffic/);assert.match(html,/No denied packet observed/);assert.match(html,/192\.0\.2\.10/);assert.match(html,/conntrack/);assert.match(html,/2026-11-02T12:01:03Z/);assert.match(html,/not an application health check/);
 f.state().targetDetail.ports[0]={port:443,protocol:'udp',status:'verified',allow:{status:'verified',evidence:{source_ip:'',observed_at:'bad'}},deny:{status:'not_applicable'}};f.c.renderPolicyDeploymentsDetail();html=f.element('#policy-deployment-detail').innerHTML;
 assert.match(html,/443\/udp/);assert.match(html,/Verification evidence unavailable/);assert.doesNotMatch(html,/deployment-port-heading[^]*?deployment-status-badge verified">Traffic verified/);
 f.state().targetDetail.ports[0]={port:443,protocol:'tcp',status:'verified'};f.c.renderPolicyDeploymentsDetail();assert.doesNotMatch(f.element('#policy-deployment-detail').innerHTML,/deployment-port-heading[^]*?deployment-status-badge verified">Traffic verified/);
});
test('late summaries cannot cross logout, identity changes or overlapping history pages',async()=>{
 for(const mode of ['logout','identity']){const pending=deferred(),f=fixture({request:()=>pending.promise});const call=f.c.refreshPolicyDeployments();if(mode==='logout'){f.c.clearPolicyDeployments();f.c.state.authType=null;}else f.c.state.user={id:'other',tenant_id:'tenant'};pending.resolve(page([summary()],1,10,0,{active_total:1}));await call;assert.equal(f.state().page,null);assert.doesNotMatch(f.element('#policy-deployments-list').innerHTML,/Billing source change/);}
 const pending=[],f=fixture({request:url=>new Promise(resolve=>pending.push({url,resolve}))}),first=f.c.refreshPolicyDeployments(),second=f.c.refreshPolicyDeployments({offset:10});pending[1].resolve(page([summary('newer-page')],11,10,10,{active_total:1}));await second;pending[0].resolve(page([summary()],11,10,0,{active_total:1}));await first;assert.equal(f.state().page.items[0].id,'newer-page');assert.equal(f.state().offset,10);
});
test('closed or replaced dialogs reject delayed target pages',async()=>{
 for(const mode of ['close','replace','identity']){const pending=deferred(),f=fixture({request:url=>url.includes('/targets?')?pending.promise:undefined});const call=f.c.policyDeploymentsOpen('change-1');if(mode==='close'){f.c.policyDeploymentsModalClosed();f.element('#modal').open=false;}else if(mode==='replace'){f.element('#modal-title').textContent='Another settings form';f.element('#modal-content').innerHTML='<input value="draft">';}else f.c.state.role='read_only';pending.resolve(page([target()],20,50,0));await call;assert.equal(f.state().targets,null);if(mode==='replace')assert.equal(f.element('#modal-content').innerHTML,'<input value="draft">');}
});
test('target and page races keep only the latest exact selection and native witness',async()=>{
 const pending=[],f=fixture({request:url=>/\/targets\/server-/.test(url)?new Promise(resolve=>pending.push({url,resolve})):undefined});await f.c.policyDeploymentsOpen('change-1');
 const action=id=>f.c.policyDeploymentsAction({dataset:{action:'policy-deployment-target',id}}),first=action('server-1'),second=action('server-2'),third=action('server-1');
 pending[2].resolve(ports({server_id:'server-1',ports:[{port:8443,protocol:'tcp',status:'awaiting',allow:{status:'verified',evidence:evidence({source_ip:'203.0.113.99'})},deny:{status:'awaiting'}}]}));await third;pending[0].resolve(ports({server_id:'server-1'}));await first;pending[1].resolve(ports({server_id:'server-2'}));await second;
 assert.equal(f.state().expandedId,'server-1');assert.equal(f.state().targetDetail.ports[0].port,8443);assert.match(f.element('#policy-deployment-detail').innerHTML,/203\.0\.113\.99/);
});
test('controller errors preserve and visibly qualify last known facts instead of inventing success',async()=>{
 let fail=false;const f=fixture({request:()=>{if(fail)throw new Error('<offline>');}});await f.c.refreshPolicyDeployments();const stamp=f.state().refreshedAt;fail=true;await f.c.refreshPolicyDeployments();
 assert.equal(f.state().refreshedAt,stamp);assert.equal(f.state().page.items[0].applied_count,12);const html=f.element('#policy-deployments-list').innerHTML;assert.match(html,/Status unavailable: &lt;offline&gt;/);assert.match(html,/Showing last reported status/);assert.match(html,/12 \/ 20/);assert.doesNotMatch(html,/<offline>/);
});
test('status content and native evidence are escaped, and oversized or foreign responses fail closed',async()=>{
 const f=fixture();await f.c.policyDeploymentsOpen('change-1');f.state().detail.label='<img src=x>';f.state().targets.items[0].reason='<script>reason</script>';f.state().expandedId='server-1';f.state().targetDetail=ports();f.state().targetDetail.ports[0].allow.evidence.source_ip='<svg onload=x>';f.c.renderPolicyDeploymentsDetail();const html=f.element('#policy-deployment-detail').innerHTML;assert.doesNotMatch(html,/<img|<script|<svg/);assert.match(html,/&lt;svg/);
 for(const response of [summary('wrong-run'),{...summary(),applied_count:21}]){const bad=fixture({request:url=>url==='/api/v1/policy-deployments/change-1'?response:undefined});await bad.c.policyDeploymentsOpen('change-1');assert.equal(bad.state().detail,null);assert.match(bad.state().detailError,/exact deployment/);}
 const bad=fixture({request:url=>url.endsWith('/targets/server-1')?ports({ports:Array.from({length:65},()=>({port:443,protocol:'tcp'}))}):undefined});await bad.c.policyDeploymentsOpen('change-1');await bad.c.policyDeploymentsAction({dataset:{action:'policy-deployment-target',id:'server-1'}});assert.equal(bad.state().targetDetail,null);assert.match(bad.state().targetError,/bounded port evidence/);
});
test('keyboard, outside click, visibility and logout stop bounded live polling and restore focus',async()=>{
 const f=fixture();f.c.renderPolicyDeploymentsChrome();await f.c.policyDeploymentsAction({dataset:{action:'policy-deployment-toggle'}});assert.equal(f.state().open,true);assert.equal(f.timers.size,1);assert.equal(f.element('#policy-deployments-toggle').attributes['aria-expanded'],'true');
 let prevented=false;f.dispatch('keydown',{key:'Escape',preventDefault(){prevented=true;},stopImmediatePropagation(){}});assert.equal(prevented,true);assert.equal(f.state().open,false);assert.equal(f.timers.size,0);assert.equal(f.c.document.activeElement,f.element('#policy-deployments-toggle'));
 await f.c.policyDeploymentsAction({dataset:{action:'policy-deployment-toggle'}});f.c.document.hidden=true;f.dispatch('visibilitychange',{});assert.equal(f.timers.size,0);f.c.document.hidden=false;f.dispatch('click',{target:{closest:()=>null}});assert.equal(f.state().open,false);f.c.clearPolicyDeployments();assert.equal(f.timers.size,0);assert.equal(f.element('#policy-deployments-list').innerHTML,'');
});
test('published change shows durable status without issuing any additional authorization or traffic writes',async()=>{
 const f=fixture();await f.c.policyDeploymentsPublished({deployment:summary()});assert.equal(f.state().open,true);assert.equal(f.requests.length,1);assert.equal(f.requests[0].url,'/api/v1/policy-deployments?limit=10&offset=0');assert.equal(f.element('#modal').open,false);assert.ok(f.requests.every(row=>!row.options.method||row.options.method==='GET'));
 const before=f.requests.length;await f.c.policyDeploymentsPublished({id:'policy-without-deployment'});assert.equal(f.requests.length,before);
});
test('lazy target paging stays bounded and exact totals are independent of the visible fifty rows',async()=>{
 const f=fixture({request:url=>{if(url==='/api/v1/policy-deployments/change-1')return summary('change-1',{target_count:5000});if(url.includes('/targets?')){const offset=Number(new URL('http://fixture'+url).searchParams.get('offset'));return page(Array.from({length:50},(_,index)=>target('server-'+(offset+index))),5000,50,offset);}}});await f.c.policyDeploymentsOpen('change-1');assert.equal(f.requests.length,2);assert.match(f.element('#policy-deployment-detail').innerHTML,/1–50 of 5000 frozen targets/);assert.equal(f.requests.filter(row=>/\/targets\/server-/.test(row.url)).length,0);
 await f.c.policyDeploymentsAction({dataset:{action:'policy-deployment-target-page',offset:'500'}});assert.match(f.requests.at(-1).url,/limit=50&offset=500/);assert.match(f.element('#policy-deployment-detail').innerHTML,/501–550 of 5000/);assert.equal(f.state().targets.items.length,50);
});
test('Admin passive recheck sends one CSRF-protected request and opens a new durable run without editing firewall intent',async()=>{
 for(const authType of ['session','token']){
  const f=fixture({request:url=>url.endsWith('/recheck')?{deployment:summary('observe-again',{target_count:1,applied_count:0,traffic_verified_count:0,active_count:1,awaiting_count:0})}:undefined});
  f.c.state.authType=authType;if(authType==='token'){f.c.state.authConfig.mode='tokens';f.c.state.token='lab-role-token';}
  await f.c.policyDeploymentsOpen('change-1');assert.match(f.element('#policy-deployment-detail').innerHTML,/Observe again/);await f.c.policyDeploymentsAction({dataset:{action:'policy-deployment-recheck',id:'server-1'}});
  const writes=f.requests.filter(row=>row.options.method==='POST');assert.equal(writes.length,1);assert.equal(writes[0].url,'/api/v1/policy-deployments/change-1/targets/server-1/recheck');assert.equal(writes[0].options.body,'{}');if(authType==='session')assert.equal(writes[0].options.headers['X-CSRF-Token'],'csrf');else assert.equal(writes[0].options.headers.Authorization,'Bearer lab-role-token');
  assert.equal(f.state().detailOpen,false);assert.equal(f.state().open,true);assert.equal(f.requests.some(row=>/\/policies|\/learning|\/hit-monitors/.test(row.url)),false);
 }
});
test('Read Only, demo, closed or changed identities cannot recheck and late recheck replies do not reopen private status',async()=>{
 for(const mode of ['readonly','demo','closed','identity']){const f=fixture({role:mode==='readonly'?'read_only':'admin'});if(mode==='demo')f.c.state.authType='demo';await f.c.policyDeploymentsOpen('change-1');if(mode==='readonly'||mode==='demo')assert.doesNotMatch(f.element('#policy-deployment-detail').innerHTML,/data-action="policy-deployment-recheck"/);if(mode==='closed')f.c.closeModal();if(mode==='identity')f.c.state.user={id:'other'};const before=f.requests.length;await f.c.policyDeploymentsRecheck('server-1');assert.equal(f.requests.length,before);}
 const pending=deferred(),f=fixture({request:url=>url.endsWith('/recheck')?pending.promise:undefined});await f.c.policyDeploymentsOpen('change-1');const call=f.c.policyDeploymentsRecheck('server-1');assert.equal(f.state().recheckBusy,'server-1');await f.c.policyDeploymentsRecheck('server-1');assert.equal(f.requests.filter(row=>row.url.endsWith('/recheck')).length,1);f.c.closeModal();pending.resolve({deployment:summary('late-window')});await call;assert.equal(f.state().open,false);assert.equal(f.state().detailOpen,false);
 const changed=fixture({request:url=>{if(url.endsWith('/recheck'))throw new Error('Policy changed; publish or reopen its current deployment.');}});await changed.c.policyDeploymentsOpen('change-1');await changed.c.policyDeploymentsRecheck('server-1');assert.match(changed.state().detailError,/Policy changed/);assert.equal(changed.state().recheckBusy,'');assert.equal(changed.state().open,false);
});
test('a policy beyond the64-port evidence limit remains visible as unavailable and unchanged intent is not installation proof',async()=>{
 const f=fixture({request:url=>url.includes('/targets?')?page([target('server-1',{port_count:100,apply_status:'pending',traffic_status:'unavailable',unchanged_intent:true,reason:'Traffic verification supports at most64 enforced pairs'})],20,50,0):undefined});await f.c.policyDeploymentsOpen('change-1');const html=f.element('#policy-deployment-detail').innerHTML;assert.equal(f.state().detailError,'');assert.match(html,/0 \/ 100 ports verified/);assert.match(html,/Unavailable/);assert.match(html,/Unchanged intent; awaiting actual agent readback/);assert.doesNotMatch(html,/deployment-status-badge verified">Applied/);
});
test('Already present requires the exact boolean from an accepted Applied agent receipt and never follows intent',async()=>{
 const f=fixture();await f.c.policyDeploymentsOpen('change-1');
 for(const values of [{already_present:true,apply_status:'applied'},{already_present:true,apply_status:'pending'},{already_present:'true',apply_status:'applied'},{already_present:false,apply_status:'applied'},{unchanged_intent:true,apply_status:'applied'}]){
  const row=target('server-1',values);f.state().targets.items=[row];f.c.renderPolicyDeploymentsDetail();const html=f.element('#policy-deployment-detail').innerHTML;
  assert.equal(html.includes('Already present · verified by agent'),values.already_present===true&&values.apply_status==='applied');
  assert.doesNotMatch(html,/deployment-status-badge verified">Traffic verified/);
 }
});
test('superseded or recovered historical witnesses stay readable without appearing as current green passes',async()=>{
 const f=fixture();await f.c.policyDeploymentsOpen('change-1');f.state().expandedId='server-1';
 for(const status of ['superseded','failed','verified']){
  f.state().targetDetail=ports({historical_only:true,traffic_status:'superseded',ports:[{port:443,protocol:'tcp',status,allow:{status:'verified',evidence:evidence()},deny:{status:'verified',evidence:evidence({source_ip:'203.0.113.20',expected_action:'denied',capture_kind:'denied_packet',capture_backend:'nflog',count_unit:'packets'})}}]});
  const html=f.c.policyDeploymentPortsHTML();assert.match(html,/Historical evidence only/);assert.match(html,/do not verify the current rules/);assert.match(html,/deployment-status-badge muted">Previously observed/);assert.match(html,/192\.0\.2\.10/);assert.match(html,/203\.0\.113\.20/);assert.doesNotMatch(html,/deployment-status-badge verified/);
 }
});
