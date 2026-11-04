const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');

function ui(flows=[]){
 const h=value=>String(value??'').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'",'&#39;');
 const context={console,Date,URL,Number,String,Map,Set,JSON,Array,Error,h,num:value=>Number(value)||0,format:value=>String(value),compact:value=>String(value),date:value=>new Date(value),state:{window:3600,data:{servers:[],service_groups:[]}},visibleFlows:()=>flows,activeFilterCount:()=>0,canWrite:()=>true,filteredServers:()=>[],errorSlot:'',modalFooter:()=>'',savedLocationOptions:()=>'',showModal:(title,html)=>{context.modal=html;},parsePorts:text=>text?text.split(',').map(value=>({port:Number(value.split('/')[0]),protocol:value.split('/')[1]||'tcp'})):[]};
 vm.createContext(context);vm.runInContext(fs.readFileSync(path.join(__dirname,'..','learning-page.js'),'utf8'),context);
 const recommendations=fs.readFileSync(path.join(__dirname,'..','recommendations-page.js'),'utf8');vm.runInContext(recommendations.slice(recommendations.indexOf('function trafficDiscoveryRateHTML'),recommendations.indexOf('async function loadLearningRecommendations')),context);
 const app=fs.readFileSync(path.join(__dirname,'..','app.js'),'utf8');vm.runInContext(app.slice(app.indexOf('function chartHTML(){'),app.indexOf('\nfunction postureHTML()')),context);
 return {context,run:source=>vm.runInContext(source,context)};
}
const values=data=>({get:key=>data[key]??null,getAll:key=>Array.isArray(data[key])?data[key]:data[key]==null?[]:[data[key]]});

test('reviewed capture choices default both and never introduce another consent or approver',()=>{
 const env=ui();env.run('showLearning()');
 assert.match(env.context.modal,/name="observation_kinds" value="accepted_connection" checked/);
 assert.match(env.context.modal,/name="observation_kinds" value="denied_packet" checked/);
 assert.match(env.context.modal,/Denied first-hits and scanners can become allowed sources/);
 assert.doesNotMatch(env.context.modal,/auto_allow_denied_confirmed|second administrator|checker account/);
 env.context.values=values({server_ids:['server-a'],selection_mode:'discovered',duration:'1',unit:'3600',policy_action:'auto_allow',auto_allow_confirmed:'on',capture_scope_version:'1',observation_kinds:['denied_packet']});
 assert.deepEqual(JSON.parse(env.run('JSON.stringify(learningPayload(values))')).observation_kinds,['denied_packet']);
 assert.equal(env.run('learningPayload(values).auto_allow_confirmed'),true);
});
test('empty or unknown capture selections fail before a learning request; legacy callers remain compatible',()=>{
 const env=ui();env.context.values=values({capture_scope_version:'1'});
 assert.throws(()=>env.run('captureKindsPayload(values)'),/Select accepted connections/);
 env.context.values=values({capture_scope_version:'1',observation_kinds:['arbitrary']});
 assert.throws(()=>env.run('captureKindsPayload(values)'),/Select accepted connections/);
 env.context.values=values({});assert.equal(env.run('captureKindsPayload(values)'),undefined);
});
test('historical allowed strings remain legacy logs and backend errors cannot inject HTML',()=>{
 const env=ui();env.context.row={verdict:'allowed',source_ip:'2001:db8::1',count:8};
 assert.match(env.run('captureEvidenceHTML(row)'),/Legacy sampled log/);
 assert.match(env.run('captureCountHTML(row)'),/legacy log records/);
 env.context.coverage={capture_backends:[{backend:'nflog',status:'error',ipv4:false,ipv6:false,lost_events:null,error:'<img src=x onerror=alert(1)>'}],capture_gaps:['<script>bad()</script>']};
 const html=env.run('captureCoverageHTML(coverage)');
 assert.match(html,/lost events unknown/);assert.match(html,/IPv6 unavailable/);assert.match(html,/&lt;img/);assert.doesNotMatch(html,/<img|<script>/);
});
test('the production traffic chart selects a count unit instead of summing connections and packets',()=>{
 const at=new Date().toISOString(),env=ui([{source_ip:'192.0.2.1',last_seen:at,count:2,capture_kind:'accepted_connection',verdict:'allowed'},{source_ip:'192.0.2.1',last_seen:at,count:500,capture_kind:'denied_packet',verdict:'denied'},{source_ip:'2001:db8::1',last_seen:at,count:7,verdict:'allowed'}]);
 let html=env.run('chartHTML()');assert.match(html,/<strong>2<\/strong><span>connections/);assert.doesNotMatch(html,/<strong>509<\/strong>/);
 env.run("state.captureUnit='packets'");html=env.run('chartHTML()');assert.match(html,/<strong>500<\/strong><span>denied packets/);
 env.run("state.captureUnit='log_records'");html=env.run('chartHTML()');assert.match(html,/<strong>7<\/strong><span>legacy log records/);assert.match(html,/Legacy reported allowed/);
 env.run("state.view='traffic';state.captureUnit='packets'");html=env.run('chartHTML()');assert.match(html,/id="traffic-chart-unit"/);assert.match(html,/<strong>500<\/strong><span>denied packets/);assert.doesNotMatch(html,/Legacy observed|aria-label="Traffic window"/);
});

test('traffic shows a short coverage summary with technical receipts collapsed by default',()=>{
 const env=ui();
 assert.match(env.run('trafficCaptureStatusHTML()'),/<summary>Capture coverage <strong>No reports yet<\/strong><\/summary>/);
 env.context.filteredServers=()=>[{hostname:'db-1',learning_coverage:{session_id:'receipt-1',capture_backends:[{backend:'nflog',status:'active',ipv4:true,ipv6:false,lost_events:null}]}}];
 const html=env.run('trafficCaptureStatusHTML()');
 assert.match(html,/<details class="traffic-coverage limited" >\s*<summary>Capture coverage <strong>Limited<\/strong><\/summary>/);
 assert.match(html,/<div class="traffic-coverage-details">.*receipt-1.*IPv6 unavailable/);
 assert.match(env.run('state.trafficCoverageOpen=true;trafficCaptureStatusHTML()'),/<details class="traffic-coverage limited" open>/);
});

test('Discover traffic is metadata-only for up to 30 days and Discover policy uses the protected auto-allow flow',()=>{
 const env=ui();env.run("showLearning(undefined,{purpose:'traffic'})");
 assert.match(env.context.modal,/name="purpose" value="traffic"/);
 assert.match(env.context.modal,/name="policy_action" value="observe"/);
 assert.match(env.context.modal,/1 minute to 30 days/);
 assert.doesNotMatch(env.context.modal,/value="auto_allow"|name="policy_action"[^>]+auto_allow/);
 const input={server_ids:['a','b'],purpose:'traffic',selection_mode:'discovered',duration:'30',unit:'86400',policy_action:'observe'};
 env.context.values=values(input);
 assert.deepEqual(JSON.parse(env.run('JSON.stringify(learningPayload(values))')),{server_ids:['a','b'],selection_mode:'discovered',duration_seconds:2592000,policy_action:'observe',purpose:'traffic'});
 env.context.values=values({...input,duration:'31'});assert.throws(()=>env.run('learningPayload(values)'),/30 days/);
 env.context.values=values({...input,policy_action:'auto_allow'});assert.throws(()=>env.run('learningPayload(values)'),/only observes/);
 env.run("showLearning(undefined,{purpose:'automatic'})");
 assert.match(env.context.modal,/name="policy_action" value="auto_allow"/);
 assert.match(env.context.modal,/name="auto_allow_confirmed" required/);
 assert.match(env.context.modal,/1 minute to 7 days/);
 assert.doesNotMatch(env.context.modal,/name="purpose" value="traffic"/);
});
test('scope search uses exact agent addresses and tags, with separate location filtering',()=>{
 const env=ui();
 env.context.servers=[{id:'a',hostname:'api-one',ips:['10.0.0.1','2001:db8::1'],tags:{app:'billing'},location_id:'dc-one'},{id:'b',hostname:'api-two',ips:['10.0.0.10'],tags:{app:'billing-v2'},location_id:'dc-two'}];
 for(const query of ['10.0.0.1','2001:0db8::1','app=billing','api-one']){
  env.context.query=query;
  assert.equal(env.run('endpointPickerMatches(servers,query).map(item=>item.id).join()'),'a');
 }
 assert.equal(env.run("endpointPickerMatches(servers,'api','dc-two').map(item=>item.id).join()"),'b');
 assert.match(env.run("endpointPickerRows('server_ids',servers.slice(0,1),['a','b'])"),/type="hidden" name="server_ids" value="b"/);
});
test('observed peaks retain their count unit and absent or invalid rates stay unavailable',()=>{
 const env=ui();
 for(const [unit,label] of [['connections','connections/s'],['packets','denied packets/s']]){
  env.context.row={count_unit:unit,peak_observed_per_second:120,rate_window_seconds:1,rate_is_lower_bound:true};
  const html=env.run('trafficDiscoveryRateHTML(row)');assert.ok(html.includes('120 '+label));assert.match(html,/Observed lower bound · 1-second interval/);
 }
 for(const row of [{count_unit:'connections',peak_observed_per_second:null},{count_unit:'connections',peak_observed_per_second:2,rate_window_seconds:0},{count_unit:'unknown',peak_observed_per_second:2,rate_window_seconds:1}]){
  env.context.row=row;assert.match(env.run('trafficDiscoveryRateHTML(row)'),/Unavailable/);
 }
});
