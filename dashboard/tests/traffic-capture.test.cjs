const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');

function ui(flows=[]){
 const h=value=>String(value??'').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'",'&#39;');
 const context={console,Date,Number,String,Map,Set,JSON,Array,Error,h,num:value=>Number(value)||0,format:value=>String(value),compact:value=>String(value),date:value=>new Date(value),state:{window:3600,data:{servers:[],service_groups:[]}},visibleFlows:()=>flows,activeFilterCount:()=>0,canWrite:()=>true,filteredServers:()=>[],errorSlot:'',modalFooter:()=>'',showModal:(title,html)=>{context.modal=html;},parsePorts:text=>text?text.split(',').map(value=>({port:Number(value.split('/')[0]),protocol:value.split('/')[1]||'tcp'})):[]};
 vm.createContext(context);vm.runInContext(fs.readFileSync(path.join(__dirname,'..','learning-page.js'),'utf8'),context);
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
});
