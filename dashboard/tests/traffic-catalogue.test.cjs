const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const F=require('../filters.js');
const L=require('../locations.js');
const source=fs.readFileSync(path.join(__dirname,'..','app.js'),'utf8');
const deferred=()=>{let resolve;const promise=new Promise(done=>{resolve=done;});return {promise,resolve};};
const flow=(source='192.0.2.44')=>({server_id:'billing',session_id:'learn-one',source_ip:source,port:443,protocol:'tcp',verdict:'allowed',capture_kind:'accepted_connection',capture_backend:'conntrack',count_unit:'connections',address_family:'ipv4',count:3,first_seen:'2026-11-02T00:00:00Z',last_seen:'2026-11-02T00:00:00Z'});
function page(items=[flow()],overrides={}){return {items,total:507,endpoint_count:1,counts_by_unit:{connections:1521,packets:7,log_records:0},limit:50,offset:0,has_more:true,window_seconds:3600,as_of:'2026-11-02T00:01:00Z',from_time:'2026-11-01T23:01:00Z',coverage:'Full retained scope; each page is a read snapshot. Late processing can change later pages.',filter_before_pagination:true,...overrides};}
function fixture(request=async()=>page()){
 const elements=new Map(),requests=[],downloads=[],toasts=[],blobs=[],revoked=[],context={console,JSON,Array,String,Number,Set,Map,Date,Promise,F,URLSearchParams,AbortController,Blob};
 const element=selector=>{if(!elements.has(selector))elements.set(selector,{innerHTML:'',open:false});return elements.get(selector);};
 L.setCatalog([{id:'dc-1',name:'Noida',type:'datacenter',location:'Facility81'}]);F.setGroups([{id:'bill-group',type:'static',server_ids:['billing']}]);
 Object.assign(context,{state:{authType:'session',role:'read_only',user:{id:'viewer',tenant_id:'tenant'},token:'',csrfToken:'csrf-fixture',view:'traffic',window:3600,filters:F.empty(),search:'',flowServer:'all',authConfig:{mode:'entra'},data:{meta:{traffic_query_v1:true},servers:[{id:'billing',hostname:'billing-app',os:'rhel',status:'healthy',location_id:'dc-1',tags:{application:'billing',owner:'finance'},listeners:[{port:22,protocol:'tcp'}]},{id:'payments',hostname:'payments-app',os:'ubuntu',status:'healthy',tags:{application:'payments'},listeners:[{port:443,protocol:'tcp'}]}]}},$:element,document:{createElement:()=>({click(){downloads.push({href:this.href,name:this.download});}})},URL:{createObjectURL:blob=>{blobs.push(blob);return 'blob:traffic-'+blobs.length;},revokeObjectURL:value=>revoked.push(value)},setTimeout:()=>1,clearTimeout(){},canWrite:()=>false,canManagePlatform:()=>false,canManageUsers:()=>false,format:value=>String(value),num:value=>Number(value)||0,h:value=>String(value??'').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('"','&quot;'),timestamp:value=>value,age:value=>value,serverName:id=>id,filterBarHTML:()=>'',trafficCaptureStatusHTML:()=>'',flowGraphHTML:()=>'<div>graph of loaded page</div>',chartHTML:()=>'<div>chart of loaded page</div>',captureEvidenceHTML:()=>'',captureCountHTML:row=>String(row.count),learningHTML:()=>'',hitMonitoringHTML:()=>'',renderPreservingFilterFocus:()=>{},toast:(message,error)=>toasts.push({message,error}),fetch:async(url,options={})=>{requests.push({url,options});const result=await request(url,options);if(result?.ok!==undefined)return result;return {ok:true,status:200,json:async()=>result};}});
 vm.createContext(context);
 const api=source.slice(source.indexOf('async function api('),source.indexOf('\nfunction toast',source.indexOf('async function api(')));
 assert.ok(api.includes('readOnlyQuery'),'Test uses the real production api permission wrapper');vm.runInContext(api,context);
 vm.runInContext(fs.readFileSync(path.join(__dirname,'..','traffic-catalogue-page.js'),'utf8'),context);
 return {c:context,element,requests,downloads,toasts,blobs,revoked};
}
test('Read Only traffic pagination passes the real shared API guard and sends cookie CSRF',async()=>{
 const f=fixture(async(url,options)=>page(Array.from({length:7},(_,index)=>flow('192.0.2.'+(index+1))),{offset:500,has_more:false}));
 await f.c.loadTrafficCatalogue(500);
 assert.equal(f.requests.length,1);assert.equal(f.requests[0].url,'/api/v1/flows/query');assert.equal(f.requests[0].options.method,'POST');assert.equal(f.requests[0].options.credentials,'same-origin');assert.equal(f.requests[0].options.headers['X-CSRF-Token'],'csrf-fixture');
 const html=f.c.trafficCatalogueHTML();assert.match(html,/501–507 of 507 matching relationships/);assert.match(html,/data-offset="450"/);assert.match(html,/data-offset="507" disabled/);assert.match(html,/Charts show the current page\./);assert.match(html,/Export matching CSV/);assert.doesNotMatch(html,/Showing up to500|Showing up to 500/);assert.equal(f.c.trafficCatalogueResultText(),'507 matching relationships · 1 endpoints');
 await assert.rejects(()=>f.c.api('/policies',{method:'POST',body:{}}),/Read Only/);
});
test('combined application location group custom tag port and endpoint filters build one pre-pagination scope',()=>{
 const f=fixture();f.c.state.filters.application=['billing'];f.c.state.filters.locations=['location:dc-1'];f.c.state.filters.groups=['bill-group'];f.c.state.filters.custom.owner=['finance'];f.c.state.filters.ports=['443/tcp'];f.c.state.search='billing';
 const query=JSON.parse(JSON.stringify(f.c.trafficCatalogueQuery(100)));
 assert.deepEqual(query,{limit:50,offset:100,window_seconds:3600,server_ids:['billing'],search_server_ids:['billing'],ports:['443/tcp'],search:'billing'});
 assert.equal(f.c.state.data.servers[0].listeners[0].port,22,'Historical traffic port does not have to be a currently listening port');
 f.c.state.flowServer='payments';assert.deepEqual(Array.from(f.c.trafficCatalogueQuery(0).server_ids),[]);
});
test('traffic scope changes clear previous rows and delayed query responses cannot cross scope identity or signout',async()=>{
 for(const change of [c=>{c.state.filters.application=['payments'];},c=>{c.state.user={id:'another-viewer'};},c=>{c.state.authType=null;}]){
  const pending=deferred(),f=fixture(()=>pending.promise),operation=f.c.loadTrafficCatalogue(50);change(f.c);pending.resolve(page([flow('late-row')],{offset:50}));await operation;assert.equal(f.c.state.trafficCatalogue.items.some(row=>row.source_ip==='late-row'),false);
 }
 const f=fixture();await f.c.loadTrafficCatalogue(0);f.c.state.filters.application=['payments'];const current=f.c.trafficCataloguePage();assert.equal(current.items.length,0);assert.equal(current.total,null);await new Promise(setImmediate);assert.equal(f.requests.at(-1).options.body.includes('payments'),true);
 const pending=deferred(),metadata=fixture(()=>pending.promise);metadata.c.state.filters.application=['billing'];const operation=metadata.c.loadTrafficCatalogue(0);metadata.c.state.data.servers[0].tags.application='payments';pending.resolve(page([flow('old-membership-row')]));await operation;assert.equal(metadata.c.state.trafficCatalogue.items.length,0,'A pending response cannot retain a host after its matching business tags change');
});
test('navigation reuses the selected time bound while explicit refresh requests newer observations',async()=>{
 const f=fixture(async(url,options)=>{const query=JSON.parse(options.body);return page([flow()],{offset:query.offset});});
 await f.c.loadTrafficCatalogue(0);await f.c.loadTrafficCatalogue(50);assert.equal(JSON.parse(f.requests.at(-1).options.body).as_of,'2026-11-02T00:01:00Z');
 await f.c.loadTrafficCatalogue(0,{fresh:true});assert.equal(Object.hasOwn(JSON.parse(f.requests.at(-1).options.body),'as_of'),false);
});
test('complete filtered CSV downloads are Read Only safe scoped CSRF-bound and reject stale identities',async()=>{
 const f=fixture(async(url,options)=>url.endsWith('export.csv')?{ok:true,blob:async()=>new Blob(['server_id,source_ip,port,protocol,count_unit\r\nbilling,192.0.2.44,443,tcp,connections\r\n'])}:page());
 f.c.state.filters.application=['billing'];f.c.state.filters.ports=['443/tcp'];await f.c.loadTrafficCatalogue(0);await f.c.downloadTrafficCatalogueCSV();
 assert.equal(f.downloads.length,1);assert.equal(f.downloads[0].name,'prthak-filtered-traffic.csv');const request=f.requests.at(-1);assert.equal(request.url,'/api/v1/flows/export.csv');assert.equal(request.options.headers['X-CSRF-Token'],'csrf-fixture');assert.deepEqual(JSON.parse(request.options.body).server_ids,['billing']);assert.equal(Object.hasOwn(JSON.parse(request.options.body),'limit'),false);assert.equal(Object.hasOwn(JSON.parse(request.options.body),'offset'),false);
 for(const change of [c=>{c.state.search='changed';},c=>{c.state.user={id:'different'};},c=>{c.state.authType=null;}]){
  const pending=deferred(),g=fixture(()=>pending.promise),operation=g.c.downloadTrafficCatalogueCSV();change(g.c);pending.resolve({ok:true,blob:async()=>new Blob(['late private data'])});await operation;assert.equal(g.downloads.length,0);assert.equal(g.blobs.length,0);
 }
});
test('oversized exports and malformed response totals fail visibly without creating a partial download',async()=>{
 const f=fixture(async()=>({ok:false,json:async()=>({error:'Complete traffic CSV exceeds its row bound; narrow the endpoint/time scope'})}));await f.c.downloadTrafficCatalogueCSV();assert.equal(f.downloads.length,0);assert.match(f.toasts[0].message,/Complete traffic CSV exceeds/);
 const g=fixture(async()=>page(Array.from({length:101},()=>flow()),{limit:100}));await g.c.loadTrafficCatalogue(0);assert.match(g.c.trafficCatalogueHTML(),/bounded, completely filtered traffic page/);assert.equal(g.c.state.trafficCatalogue.total,null);
 assert.throws(()=>g.c.trafficCatalogueRecord(page([],{counts_by_unit:{connections:1,packets:'2',log_records:0}}),'scope'),/separate traffic count units/);
 assert.throws(()=>g.c.trafficCatalogueRecord(page([],{filter_before_pagination:false}),'scope'),/completely filtered/);
});
