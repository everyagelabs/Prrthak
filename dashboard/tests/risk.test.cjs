const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
function workspace(write=false){const calls=[],c={state:{view:'risk'},URLSearchParams,canWrite:()=>write,num:v=>Number(v)||0,h:v=>String(v??'').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;'),badge:(v)=>String(v),$:()=>null,$$:()=>[],showModal:(...args)=>calls.push(args)};vm.createContext(c);vm.runInContext(fs.readFileSync(require.resolve('../risk-page.js'),'utf8'),c);return {c,calls};}
test('reasons and service metadata are escaped in findings and discovered-port highlights',()=>{const {c}=workspace();vm.runInContext(`riskState.findings={items:[{server_id:'x',hostname:'<host>',ips:[],port:23,protocol:'tcp',name:'Telnet',reason:'<img src=x onerror=bad()>',recommendation:'<next>',severity:'high',source_ids:[]}],total:1,server_count:1};riskState.findingsScope=riskScope();`,c);const html=c.riskHTML();assert.match(html,/Why marked risky/);assert.match(html,/&lt;img/);assert.doesNotMatch(html,/<img/);const badge=c.riskyPortBadge({risky_ports:[{port:23,protocol:'tcp',reason:'<reason>',severity:'high'}]},{port:23,protocol:'tcp'});assert.match(badge,/Risky port/);assert.match(badge,/risk-port-reason/);assert.doesNotMatch(badge,/<reason>/);});
test('Read Only cannot open the catalogue editor and empty pages never claim item1',async()=>{const {c,calls}=workspace();vm.runInContext("riskState.tab='catalog';riskState.catalog={revision:3,rules:[]};",c);assert.doesNotMatch(c.riskHTML(),/Edit catalogue/);await c.riskAction({dataset:{action:'risk-catalog-edit'}});assert.equal(calls.length,0);vm.runInContext("riskState.tab='findings';riskState.findings={items:[],total:0};riskState.findingsScope=riskScope();",c);assert.match(c.riskHTML(),/0–0 of 0/);});
test('catalogue editor freezes revision at opening rather than using a later refresh',async()=>{const {c,calls}=workspace(true);vm.runInContext("riskState.catalog={revision:7,rules:[]};",c);await c.riskAction({dataset:{action:'risk-catalog-edit'}});assert.match(calls[0][1],/data-revision="7"/);});
test('newer filtered requests supersede stale in-flight responses',async()=>{const {c}=workspace();const pending=[];c.api=url=>new Promise(resolve=>pending.push({url,resolve}));const older=c.riskLoad(true);vm.runInContext("riskState.severity='high';",c);const newer=c.riskLoad(true);assert.equal(pending.length,6);pending[3].resolve({revision:2,rules:[]});pending[4].resolve({items:[],total:2});pending[5].resolve({controls:[]});await newer;pending[0].resolve({revision:1,rules:[]});pending[1].resolve({items:[],total:99});pending[2].resolve({controls:[]});await older;assert.equal(vm.runInContext('riskState.findings.total',c),2);});

test('ordinary refresh reloads findings while caching reference data and coalescing concurrent loads',async()=>{
 const {c}=workspace();const calls=[];let total=1,release;
 c.api=async url=>{calls.push(url);if(url==='/risk/catalog')return {revision:1,rules:[]};if(url==='/risk/regulatory')return {controls:[]};return {items:[],total,server_count:1,classification_pending_servers:0};};
 await c.riskLoad();assert.equal(calls.length,3);
 total=2;await c.riskLoad();assert.equal(calls.length,4);assert.equal(vm.runInContext('riskState.findings.total',c),2);
 assert.match(calls[3],/^\/risk\/findings\?/);assert.match(c.riskHTML(),/Risk results last refreshed:/);
 c.api=url=>{calls.push(url);return new Promise(resolve=>release=resolve);};
 const first=c.riskLoad(),duplicate=c.riskLoad();assert.equal(first,duplicate);assert.equal(calls.length,5);
 release({items:[],total:3,classification_pending_servers:0});await first;assert.equal(vm.runInContext('riskState.findings.total',c),3);
});
test('pending and host-detail coverage limits are explicit even when no matches are available',()=>{
 const {c}=workspace();vm.runInContext('riskState.findings={items:[],total:0,server_count:0,classification_pending_servers:2,truncated_server_count:3,stored_reason_limit:256};riskState.findingsScope=riskScope();',c);
 const html=c.riskHTML();assert.match(html,/Partial coverage/);assert.match(html,/2 servers await classification/);assert.match(html,/zero matches is not an all-clear/);assert.match(html,/3 servers have stored detailed reasons limited to 256/);assert.match(html,/host-detail limit/);assert.doesNotMatch(html,/No matching risky-port indicators in the available listener classification/);
 vm.runInContext('delete riskState.findings.classification_pending_servers;delete riskState.findings.stored_reason_limit;',c);assert.match(c.riskHTML(),/coverage is not reported/);assert.match(c.riskHTML(),/Matching counts may omit indicators/);
});
test('a failed changed-filter refresh never presents the previous scope as matching results',async()=>{
 const {c}=workspace();vm.runInContext("riskState.catalog={revision:1,rules:[]};riskState.regulatory={controls:[]};riskState.findings={items:[{hostname:'old-scope-host',port:23,protocol:'tcp',ips:[],source_ids:[]}],total:1,classification_pending_servers:0};riskState.findingsScope=riskScope();riskState.severity='high';",c);
 let reject;c.api=()=>new Promise((resolve,fail)=>reject=fail);const loading=c.riskLoad();let html=c.riskHTML();assert.doesNotMatch(html,/old-scope-host/);assert.match(html,/Results not loaded/);assert.doesNotMatch(html,/0 indicators/);
 reject(new Error('Temporary unavailable <retry>'));await loading;html=c.riskHTML();assert.match(html,/Temporary unavailable &lt;retry&gt;/);assert.match(html,/Findings are unavailable for the selected filters/);assert.doesNotMatch(html,/old-scope-host/);
});
test('risk refresh preserves unsaved filter text and focused caret without adding fetches from render',async()=>{
 const {c}=workspace();const fields={};let focusCalls=0,selection;
 for(const [id,value]of [['risk-search','unfinished name'],['risk-severity','high'],['risk-port','8443']])fields['#'+id]={id,value};
 const search=fields['#risk-search'];search.selectionStart=4;search.selectionEnd=8;search.focus=()=>focusCalls++;search.setSelectionRange=(...args)=>selection=args;
 const target={set innerHTML(value){for(const field of Object.values(fields))field.value='';},get innerHTML(){return '';}};
 c.$=selector=>selector==='#view-content'?target:fields[selector]||null;c.document={activeElement:search};let calls=0;
 c.api=async url=>{calls++;return url==='/risk/catalog'?{revision:1,rules:[]}:url==='/risk/regulatory'?{controls:[]}:{items:[],total:0,classification_pending_servers:0};};
 await c.riskLoad();assert.equal(calls,3);assert.equal(search.value,'unfinished name');assert.equal(fields['#risk-port'].value,'8443');assert.equal(fields['#risk-severity'].value,'high');assert.deepEqual(selection,[4,8]);assert.equal(focusCalls,2);
});
