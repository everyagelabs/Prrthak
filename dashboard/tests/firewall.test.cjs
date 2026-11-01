const test=require('node:test');const assert=require('node:assert/strict');const fs=require('node:fs');const vm=require('node:vm');
const F=require('../filters.js'),W=require('../firewall.js');
const servers=[{id:'billing-1',hostname:'billing-api-01',tags:{application:'billing',dc:'Mumbai'},listeners:[{port:8443,protocol:'tcp'}]},{id:'billing-2',hostname:'billing-api-02',tags:{application:'billing',dc:'Hyderabad'},listeners:[]},{id:'web',hostname:'web-01',tags:{application:'payments',dc:'Mumbai'},listeners:[{port:80,protocol:'tcp'}]}];
const common={rule_key:'common-http',zone:'public',kind:'port',value:'80/tcp',action:'accept',risk:'medium',editable:true,scopes:['runtime','permanent'],server_ids:servers.map(server=>server.id),host_count:3};

test('firewall port scope follows imported rules rather than currently listening sockets',()=>{
 const filters=F.empty();filters.application=['billing'];filters.ports=['80/tcp'];
 const rules=W.scopedRules([common],servers,[],filters);
 assert.deepEqual(rules[0].matching_server_ids,['billing-1','billing-2']);assert.equal(rules[0].matching_host_count,2);
 assert.equal(W.scopedRules([common],servers,[],{...filters,ports:['8443/tcp']}).length,0);
});
test('named service ports require actual definitions and can use nonstandard SSH ports',()=>{
 const ssh={kind:'service',value:'ssh'};assert.equal(W.matchesPorts(ssh,['22/tcp']),false);
 const snapshot={service_definitions:{ssh:{ports:[{port:2022,protocol:'tcp'}]}}};
 assert.equal(W.matchesPorts(ssh,['2022/tcp'],snapshot),true);assert.equal(W.matchesPorts(ssh,['22/tcp'],snapshot),false);
 assert.equal(W.matchesPorts({kind:'port',value:'1000-2000/tcp'},['1500/tcp']),true);assert.equal(W.matchesPorts({kind:'port',value:'1000-2000/tcp'},['1500/udp']),false);
});
test('any-zone, deny and unsupported inventory types are labelled without parsing log messages as actions',()=>{
 const target={kind:'target',value:'ACCEPT',action:'accept',risk:'high',editable:false};assert.equal(W.highRisk(target),true);assert.equal(W.anySource(target),true);assert.equal(W.editable(target),false);assert.equal(W.matchesPorts(target,['8443/tcp']),true);
 assert.equal(W.action({kind:'rich_rule',value:'rule port port="80" protocol="tcp" log prefix="drop packet" accept'}),'accept');
 assert.equal(W.action({kind:'rich_rule',value:'rule port port="80" protocol="tcp" reject'}),'reject');assert.equal(W.resultLabel({status:'preview'}),'Preview only');
});
function uiEnvironment(){
 const calls=[],shown=[],errors=[];let typed='';
 const plan={id:'plan-1',name:'Remove shared HTTP',operation:'remove',scopes:['runtime','permanent'],server_ids:['billing-1','billing-2'],status:'draft',requires_double_confirmation:true,confirmation_count:0,confirmation_nonce:'nonce-1',confirmation_phrase:'CONFIRM abc123',plan_digest:'abc123',expires_at:new Date(Date.now()+600000).toISOString(),preview:{matched_host_count:2,unmatched_host_count:0,unmatched_server_ids:[],before:[{server_id:'billing-1',value:'80/tcp'}],after:[],impact:'Removal restricts access'},results:{}};
 const state={role:'admin',data:{servers},firewallData:{common_rules:[common],servers:[],changes:[plan]},filters:F.empty(),search:'',flowServer:'all',firewallLoading:false};
 const context={console,Date,Map,Set,JSON,Array,String,Number,Error,F,W,state,num:value=>Number(value)||0,format:value=>String(value),h:value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])),humanize:value=>String(value||'').replaceAll('_',' '),icon:()=>'',badge:(label,kind)=>`<span class="badge ${kind||''}">${label}</span>`,date:value=>value?new Date(value):null,timestamp:value=>String(value||''),serverName:id=>servers.find(server=>server.id===id)?.hostname||id,filteredServers:()=>servers,errorSlot:'',modalFooter:label=>label,showModal:(title,html)=>shown.push({title,html}),toast:()=>{},render:()=>{},formError:error=>errors.push(error.message),$:(selector)=>selector==='#firewall-confirmation-challenge'?{value:typed}:{open:true},$$:()=>[],api:async(path,options={})=>{calls.push({path,options});if(path==='/firewall')return state.firewallData;if(path.endsWith('/confirm')){const confirmation=options.body.challenge?{...plan,status:'queued',confirmation_count:2,confirmation_nonce:'nonce-3'}:{...plan,status:'awaiting_second_confirmation',confirmation_count:1,confirmation_nonce:'nonce-2'};state.firewallData.changes=[confirmation];return confirmation;}return {};}};
 vm.createContext(context);vm.runInContext(fs.readFileSync(require.resolve('../firewall-page.js'),'utf8'),context);
 return {context,calls,shown,errors,plan,setTyped:value=>{typed=value}};
}
test('initial Edit or Remove only opens draft preparation and never mutates an endpoint',()=>{
 const env=uiEnvironment();env.context.firewallEditRule(common.rule_key,'remove');assert.equal(env.calls.length,0);assert.match(env.shown.at(-1).html,/Create review plan/);assert.match(env.shown.at(-1).html,/billing-api-01/);
 env.context.state.role='viewer';const before=env.shown.length;env.context.firewallEditRule(common.rule_key,'replace');assert.equal(env.shown.length,before);assert.equal(env.calls.length,0);
});
test('restrictive change requires a new nonce and a separately typed second confirmation',async()=>{
 const env=uiEnvironment();env.context.firewallShowPlan(env.plan);
 await env.context.firewallAction({dataset:{action:'firewall-confirm-plan'},disabled:false});
 const confirmations=()=>env.calls.filter(call=>call.path.endsWith('/confirm'));
 assert.equal(confirmations().length,1);assert.equal(confirmations()[0].options.body.confirmation_nonce,'nonce-1');assert.equal(confirmations()[0].options.body.challenge,undefined);
 assert.equal(env.context.state.activeFirewallPlan.status,'awaiting_second_confirmation');assert.match(env.shown.at(-1).html,/Type the exact confirmation phrase/);assert.doesNotMatch(env.shown.at(-1).html,/value="CONFIRM abc123"/);
 await env.context.firewallAction({dataset:{action:'firewall-confirm-plan'},disabled:false});assert.equal(confirmations().length,1);assert.match(env.errors.at(-1),/exact displayed confirmation/);
 env.setTyped('CONFIRM abc123');await env.context.firewallAction({dataset:{action:'firewall-confirm-plan'},disabled:false});assert.equal(confirmations().length,2);assert.equal(confirmations()[1].options.body.confirmation_nonce,'nonce-2');assert.equal(confirmations()[1].options.body.challenge,'CONFIRM abc123');assert.equal(env.context.state.activeFirewallPlan.status,'queued');assert.match(env.shown.at(-1).html,/Queued/);assert.match(env.shown.at(-1).html,/Preview is not applied enforcement/);
});
test('change plans remain visible by their imported before/after service even when no listener exists',()=>{
 const filters=F.empty();filters.application=['billing'];filters.ports=['80/tcp'];const plan={id:'removed-rule',server_ids:['billing-2'],preview:{before:[{server_id:'billing-2',kind:'port',value:'80/tcp'}],after:[]}};const list=W.scopedPlans([plan],servers,[],filters);assert.equal(list.length,1);assert.deepEqual(list[0].matching_server_ids,['billing-2']);assert.equal(W.scopedPlans([plan],servers,[],{...filters,ports:['8443/tcp']}).length,0);
});
test('mixed named-service definitions narrow hosts by actual per-host ports and block cross-scope ambiguity',()=>{
 const rule={...common,rule_key:'ssh',kind:'service',value:'ssh',ports:[],port_resolution:'mixed'},filters=F.empty();filters.ports=['2022/tcp'];
 const snapshots=[{server_id:'billing-1',snapshot:{status:'ok',rules:[{logical_key:'ssh',scope:'runtime',zone:'public',kind:'service',value:'ssh',ports:[{port:'22',protocol:'tcp'}],editable:true}]}},{server_id:'billing-2',snapshot:{status:'ok',rules:[{logical_key:'ssh',scope:'runtime',zone:'public',kind:'service',value:'ssh',ports:[{port:'2022',protocol:'tcp'}],editable:true}]}}];
 let filtered=W.scopedRules([rule],servers,snapshots,filters);assert.deepEqual(filtered[0].matching_server_ids,['billing-2']);assert.equal(filtered[0].editable,true);
 snapshots[1].snapshot.rules.push({logical_key:'ssh',scope:'permanent',zone:'public',kind:'service',value:'ssh',ports:[{port:'22',protocol:'tcp'}],editable:true});filtered=W.scopedRules([rule],servers,snapshots,filters);assert.equal(filtered[0].editable,false);assert.match(filtered[0].reason,/Different service ports/);
});

test('large common-rule target review pages100checkboxes without dropping the full explicit selection',async()=>{
 const env=uiEnvironment(),fleet=Array.from({length:5000},(_,i)=>({id:'host-'+i,hostname:'host-'+i,tags:{},listeners:[]}));
 env.context.state.data.servers=fleet;env.context.state.firewallData.common_rules=[{...common,server_ids:fleet.map(row=>row.id),host_count:5000}];
 env.context.firewallEditRule(common.rule_key,'remove');
 assert.equal((env.shown.at(-1).html.match(/data-firewall-target=/g)||[]).length,100);
 assert.equal(env.context.state.firewallEditSelection.selected.size,5000);
 env.context.firewallChange({target:{dataset:{firewallTarget:'host-1'},checked:false}});
 await env.context.firewallAction({dataset:{action:'firewall-target-page',offset:'100'}});
 assert.equal(env.context.state.firewallEditSelection.offset,100);
 assert.equal(env.context.state.firewallEditSelection.selected.size,4999);
 assert.equal(env.context.state.firewallEditSelection.selected.has('host-1'),false);
 assert.equal(env.calls.length,0);
});
test('opening a compact plan summary fetches full canonical review evidence lazily',async()=>{
 const env=uiEnvironment();env.context.api=async(path,options={})=>{env.calls.push({path,options});return env.plan;};
 await env.context.firewallAction({dataset:{action:'firewall-plan',id:env.plan.id},disabled:false});
 assert.equal(env.calls[0].path,'/firewall/changes/plan-1');assert.equal(env.calls[0].options.method,undefined);
 assert.match(env.shown.at(-1).html,/80\/tcp/);assert.equal(env.context.state.activeFirewallPlan.preview.before.length,1);
});
test('five thousand server rows render in200row pages while retaining full filter totals',()=>{
 const fleet=Array.from({length:5000},(_,i)=>({id:'host-'+i,hostname:'host-'+i,tags:{},listeners:[]}));
 const source=fs.readFileSync(require.resolve('../app.js'),'utf8');const fn=source.slice(source.indexOf('function serverRows('),source.indexOf('\nfunction inventoryHTML'));
 const context={state:{view:'servers',filters:{},search:'',flowServer:'all'},filteredServers:()=>fleet,JSON,Math,h:String,icon:()=>'',num:Number,metadataSelectionCell:()=>'',listenerChip:()=>'',serverLocationHTML:()=>'',tagsHTML:()=>'',serverHealth:()=>'',policyBadge:()=>'',L:{customTags:()=>({})}};
 vm.createContext(context);vm.runInContext(fs.readFileSync(require.resolve('../risk-page.js'),'utf8'),context);vm.runInContext(fn,context);
 let page=context.serverRows();assert.equal(page.list.length,5000);assert.equal((page.html.match(/<tr /g)||[]).length,200);assert.equal(page.offset,0);
 context.state.inventoryOffset=200;page=context.serverRows();assert.equal(page.offset,200);assert.match(page.html,/data-id="host-200"/);assert.doesNotMatch(page.html,/data-id="host-0"/);
 context.state.search='changed';page=context.serverRows();assert.equal(page.offset,0);
});

function asyncFirewallEnvironment(inputValue=''){
 const env=uiEnvironment(),input={id:'service-filter-input',value:inputValue,selectionStart:2,selectionEnd:5},results={innerHTML:'old result'},count={textContent:''},timers=new Map();let sequence=0;
 env.context.state.view='firewall';env.context.state.firewallData={scoped_query:true,common_rules:[],servers:[],changes:[]};
 env.context.state.firewallScopeKey=env.context.firewallScopeKey();
 env.context.document={activeElement:input};
 env.context.$=selector=>selector==='#modal'?{open:false}:selector==='#firewall-results'?results:selector==='#filter-result-count'?count:selector==='#service-filter-input'?input:null;
 env.context.emptyHTML=title=>title;
 env.context.render=()=>assert.fail('Async results must not rebuild the filter DOM');
 env.context.setTimeout=fn=>{const id=++sequence;timers.set(id,fn);return id;};
 env.context.clearTimeout=id=>timers.delete(id);
 return {...env,input,results,count,timers,flushQuery(){assert.equal(timers.size,1);const [id,fn]=[...timers][0];timers.delete(id);fn();}};
}
function deferred(){let resolve,reject;const promise=new Promise((yes,no)=>{resolve=yes;reject=no;});return {promise,resolve,reject};}
function billing8443Page(){return {scoped_query:true,common_rules:[{...common,value:'8443/tcp',server_ids:['billing-1','billing-2'],host_count:2}],servers:[{server_id:'billing-1',snapshot:{summary_only:true}},{server_id:'billing-2',snapshot:{summary_only:true}}],changes:[],pagination:{has_more:false},summary:{matching_endpoint_count:2}};}

test('billing plus8443 async results update despite a focused empty or partially typed port input',async()=>{
 for(const draft of ['', '9443/tcp']){
  const env=asyncFirewallEnvironment(draft),reply=deferred();env.context.state.filters.application=['billing'];env.context.state.filters.ports=['8443/tcp'];
  env.context.api=async(path,options)=>{env.calls.push({path,options});return reply.promise;};
  const pending=env.context.refreshFirewallData();reply.resolve(billing8443Page());await pending;
  assert.deepEqual(Array.from(env.calls[0].options.body.server_ids),['billing-1','billing-2']);assert.deepEqual(Array.from(env.calls[0].options.body.ports),['8443/tcp']);
  assert.match(env.results.innerHTML,/8443\/tcp/);assert.match(env.results.innerHTML,/2 matching/);assert.equal(env.count.textContent,'1 common rules in selected scope');
  assert.equal(env.context.document.activeElement,env.input);assert.equal(env.input.value,draft);assert.equal(env.input.selectionStart,2);assert.equal(env.input.selectionEnd,5);
 }
});
test('a scope changed while fetching discards stale results and explicitly fetches the latest combined scope',async()=>{
 const env=asyncFirewallEnvironment('9443/tcp'),first=deferred(),second=deferred(),initial=env.context.state.firewallData;
 env.context.api=async(path,options)=>{env.calls.push({path,options});return env.calls.length===1?first.promise:second.promise;};
 const pending=env.context.refreshFirewallData();
 env.context.state.filters.application=['billing'];env.context.state.filters.ports=['8443/tcp'];
 await env.context.refreshFirewallData();first.resolve({scoped_query:true,common_rules:[{...common,value:'stale80/tcp'}],servers:[],changes:[]});await pending;
 assert.equal(env.context.state.firewallData,initial);assert.doesNotMatch(env.results.innerHTML,/stale80/);env.flushQuery();
 assert.equal(env.calls.length,2);assert.deepEqual(Array.from(env.calls[1].options.body.server_ids),['billing-1','billing-2']);assert.deepEqual(Array.from(env.calls[1].options.body.ports),['8443/tcp']);
 second.resolve(billing8443Page());await new Promise(setImmediate);
 assert.match(env.results.innerHTML,/8443\/tcp/);assert.equal(env.context.state.firewallScopeKey,env.context.firewallScopeKey());assert.equal(env.timers.size,0);assert.equal(env.input.value,'9443/tcp');
});
test('Refresh during an in-flight cursor page discards that page and loads the requested first page',async()=>{
 const env=asyncFirewallEnvironment(),first=deferred(),second=deferred();env.context.state.firewallCursor='old-cursor';
 env.context.api=async(path,options)=>{env.calls.push({path,options});return env.calls.length===1?first.promise:second.promise;};
 const pending=env.context.refreshFirewallData();await env.context.firewallAction({dataset:{action:'firewall-refresh'}});
 first.resolve({scoped_query:true,common_rules:[{...common,value:'stale-page80/tcp'}],servers:[],changes:[]});await pending;
 assert.doesNotMatch(env.results.innerHTML,/stale-page/);env.flushQuery();assert.equal(env.calls[1].options.body.after,'');second.resolve(billing8443Page());await new Promise(setImmediate);
 assert.match(env.results.innerHTML,/8443\/tcp/);assert.equal(env.context.state.firewallCursor,'');
});

test('extended imported editing stays typed and zone targets expose permanent replacement only',()=>{
 for(const kind of ['direct','forward_port'])assert.equal(W.editable({kind,editable:true}),true);
 assert.equal(W.editable({kind:'masquerade',editable:true}),false);
 const target={...common,kind:'target',value:'ACCEPT',rule_key:'target-key',ports:[]};
 const snapshot={status:'ok',stale:false,rules:[{kind:'target',value:'ACCEPT',logical_key:'target-key',scope:'runtime',editable:false},{kind:'target',value:'ACCEPT',logical_key:'target-key',scope:'permanent',editable:true}]};
 const row=W.scopedRules([{...target,server_ids:['billing-1']}],servers,[{server_id:'billing-1',snapshot}],F.empty())[0];
 assert.equal(row.editable,true);assert.deepEqual(row.editable_scopes,['permanent']);assert.equal(W.removable(row),false);assert.match(W.editHint(row),/runtime remains unchanged/);
 assert.equal(W.matchesPorts({kind:'direct',value:'ipv4 filter INPUT 0 -p tcp --dport 8443 -j ACCEPT'},['8443/tcp']),true);
 assert.equal(W.matchesPorts({kind:'forward_port',value:'port=8080:proto=tcp:toport=8443:toaddr='},['8080/tcp']),true);
});

test('target editor disables runtime and remove rather than silently converting a live change',()=>{
 const env=uiEnvironment(),target={...common,kind:'target',value:'ACCEPT',rule_key:'target-key',editable_scopes:['permanent']};
 env.context.state.firewallData.common_rules=[target];env.context.firewallEditRule('target-key','replace');
 const html=env.shown.at(-1).html;assert.match(html,/value="runtime" disabled/);assert.match(html,/value="permanent" checked/);assert.match(html,/No global reload is performed/);
 const count=env.shown.length;env.context.firewallEditRule('target-key','remove');assert.equal(env.shown.length,count);assert.equal(env.calls.length,0);
});

test('cross-host probe evidence renders bounded destinations safely and never claims malicious success',()=>{
 const env=uiEnvironment();
 const html=env.context.securityAlertDetailsHTML({kind:'possible_lateral_movement',details:{source_ip:'<img src=x onerror=alert(1)>',port:8443,protocol:'tcp',destination_count:3,window_seconds:300,coverage_limited:true,shared_destination_address:true,destinations:[{server_id:'host" onclick="bad',hostname:'<script>bad</script>',destination_ip:'10.0.0.1'}]}});
 assert.match(html,/Possible cross-host probe/);assert.match(html,/Connection success is unknown/);assert.match(html,/No automatic block/);assert.match(html,/partial observation/);assert.match(html,/VIP\/address ownership/);assert.doesNotMatch(html,/<img|<script|data-id="host" onclick/);assert.match(html,/&lt;script&gt;/);
});

test('policy missing-listener detail reports expectation rather than kernel or application proof',()=>{
 const env=uiEnvironment(),html=env.context.securityAlertDetailsHTML({kind:'service_down',details:{basis:'effective_policy_intent',last_discovery_at:'2026-11-01T01:00:00Z',policy_version:3}});
 assert.match(html,/Policy-derived listener expectation/);assert.match(html,/application responses and kernel policy application are not verified/);
 const withdrawn=env.context.securityAlertDetailsHTML({kind:'service_down',resolution_reason:'expectation_withdrawn',details:{basis:'effective_policy_intent'}});assert.match(withdrawn,/does not verify service recovery/);
});

test('missing and closed port alert filters use observed alert ports while ordinary server filters require listeners',()=>{
 const host={id:'closed',hostname:'billing-closed',tags:{application:'billing'},listeners:[{port:2022,protocol:'tcp'}]},filters=F.empty();filters.application=['billing'];filters.ports=['8443/tcp'];
 assert.equal(F.matchServer(host,filters),false);
 assert.equal(F.matchAlert({details:{port:8443,protocol:'tcp'}},host,filters),true);
 assert.equal(F.matchAlert({details:{port:8443,protocol:'udp'}},host,filters),false);
 assert.equal(F.matchAlert({kind:'agent_offline'},host,filters),false);
 assert.equal(F.matchAlert({details:{port:8443,protocol:'tcp',source_ip:'192.0.2.99'}},host,filters,'192.0.2.99'),true);
});

test('the actual alert scope function finds every affected host without broadening endpoint or tag scope',()=>{
 const source=fs.readFileSync(require.resolve('../app.js'),'utf8').match(/^function scopedAlerts\([^\n]+/m)[0],context={F,state:{data:{servers,alerts:[{id:'fanout',kind:'possible_lateral_movement',status:'open',server_id:'web',details:{target_server_ids:['web','billing-1'],port:8443,protocol:'tcp'}}]},filters:F.empty(),search:'',flowServer:'billing-1'}};
 context.state.filters.application=['billing'];context.state.filters.ports=['8443/tcp'];vm.createContext(context);vm.runInContext(source,context);assert.equal(context.scopedAlerts().length,1);
 context.state.flowServer='billing-2';assert.equal(context.scopedAlerts().length,0);context.state.flowServer='web';assert.equal(context.scopedAlerts().length,0);
});
