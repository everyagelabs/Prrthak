const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const F=require('../filters.js');
const source=fs.readFileSync(path.join(__dirname,'..','app.js'),'utf8');
const deferred=()=>{let resolve;const promise=new Promise(done=>{resolve=done;});return {promise,resolve};};
const alert=(id='offline-one')=>({id,kind:'agent_offline',severity:'critical',server_id:'billing',status:'open',created_at:'2026-11-02T00:00:00Z',message:'Agent heartbeat missing: billing',details:{}});
function page(items=[alert()],overrides={}){return {items,total:507,all_count:1108,unresolved_count:507,critical_count:507,unacknowledged_count:506,open_count:506,limit:50,offset:0,has_more:true,include_resolved:false,...overrides};}
function fixture(request=async()=>page()){
 const elements=new Map(),requests=[],context={console,JSON,Array,String,Number,Set,Map,Date,Promise,F};
 const element=selector=>{if(!elements.has(selector))elements.set(selector,{innerHTML:'',open:false});return elements.get(selector);};
 Object.assign(context,{state:{authType:'session',role:'read_only',user:{id:'viewer',tenant_id:'tenant'},token:'',view:'alerts',filters:F.empty(),search:'',flowServer:'all',alertIncludeResolved:false,data:{servers:[{id:'billing',hostname:'billing',os:'rhel',status:'offline',tags:{application:'billing'},listeners:[{port:443,protocol:'tcp'}]},{id:'payments',hostname:'payments',os:'ubuntu',status:'healthy',tags:{application:'payments'},listeners:[{port:22,protocol:'tcp'}]}],alerts:[alert()]}},$:element,canWrite:()=>false,format:value=>String(value),num:value=>Number(value)||0,h:value=>String(value??'').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('"','&quot;'),date:value=>new Date(value),timestamp:value=>value,icon:()=>'',humanize:value=>String(value).replaceAll('_',' '),acknowledged:row=>row.status==='acknowledged',serverName:id=>id,alertServiceDetailsHTML:()=>'',securityAlertDetailsHTML:()=>'',filterBarHTML:()=>'',emptyHTML:(title,body)=>`<p>${title}: ${body}</p>`,filteredAlerts:()=>context.state.data.alerts.filter(F.unresolved),activeFilterCount:()=>0,scopedSummary:()=>({servers:context.state.data.servers,current:[],collecting:[],assigned:[],alerts:context.state.data.alerts.filter(F.unresolved)}),api:async(url,options)=>{requests.push({url,options});return request(url,options);}});
 vm.createContext(context);vm.runInContext(fs.readFileSync(path.join(__dirname,'..','alerts-catalogue-page.js'),'utf8'),context);
 for(const [first,last] of [['function alertsHTML(){','\nfunction activityHTML'],['function statsHTML(){','\nfunction chartHTML']]){const start=source.indexOf(first),end=source.indexOf(last,start);assert.ok(start>=0&&end>start,first+' production function remains discoverable');vm.runInContext(source.slice(start,end),context);}
 context.render=()=>{element('#view-content').innerHTML=context.alertsHTML();};
 context.alertsReceiveOverview({alerts:[alert()],alert_pagination:page().items&&Object.fromEntries(Object.entries(page()).filter(([key])=>key!=='items'))});
 return {c:context,element,requests};
}
test('bounded alert pages keep older live outages visible, exact counts and endpoint links beyond500',async()=>{
 const f=fixture(async(url,options)=>page(Array.from({length:7},(_,i)=>alert('offline-'+(500+i))),{offset:500,has_more:false}));
 let html=f.c.alertsHTML();assert.match(html,/507 results in selected scope/);assert.match(html,/0–1 of 507|1–1 of 507/);assert.match(html,/Agent heartbeat missing: billing/);assert.match(html,/data-action="server" data-id="billing"/);assert.match(html,/data-action="ack-alert"[^>]*disabled/);
 await f.c.loadAlertCatalogue(500);html=f.c.alertsHTML();assert.match(html,/501–507 of 507 matching alerts/);assert.match(html,/data-offset="450"/);assert.match(html,/data-offset="507" disabled/);assert.equal(f.requests[0].url,'/alerts/query');assert.equal(f.requests[0].options.body.limit,50);assert.equal(f.c.alertCatalogueCounts().total,507);assert.match(f.c.statsHTML(),/>507<\/div>/);
});
test('recovered history can be paged without inflating unresolved overview numbers',async()=>{
 const f=fixture(async()=>page([{...alert('recovered'),status:'resolved',kind:'recovered'}],{total:1108,include_resolved:true}));f.c.state.alertIncludeResolved=true;
 f.c.alertCataloguePage();await new Promise(setImmediate);assert.equal(f.requests[0].options.body.include_resolved,true);
 const html=f.c.alertsHTML();assert.match(html,/1108 results in selected scope/);assert.match(html,/includes recovered \/ resolved/);assert.match(html,/>Recovered</);assert.doesNotMatch(html,/data-action="ack-alert"/);assert.equal(f.c.alertCatalogueCounts().matchedTotal,1108);assert.equal(f.c.alertCatalogueCounts().total,507);assert.match(f.c.statsHTML(),/>507<\/div>/);assert.doesNotMatch(f.c.statsHTML(),/>1108<\/div>/);
});
test('metadata, listener ports and literal text search produce one bounded matching alert scope',async()=>{
 const f=fixture();f.c.state.filters.application=['billing'];f.c.state.filters.ports=['443/tcp'];f.c.state.search='billing';const query=f.c.alertCatalogueQuery(100);
 assert.deepEqual(JSON.parse(JSON.stringify(query)),{limit:50,offset:100,include_resolved:false,server_ids:['billing'],listener_server_ids:['billing'],search_server_ids:['billing'],ports:['443/tcp'],search:'billing'});
 f.c.state.search='anything';assert.deepEqual(Array.from(f.c.alertCatalogueQuery(0).search_server_ids),[]);f.c.state.flowServer='payments';assert.deepEqual(Array.from(f.c.alertCatalogueQuery(0).server_ids),[]);
});
test('pending alert responses cannot cross filter scopes, identities or signout',async()=>{
 for(const change of [c=>{c.state.filters.application=['payments'];},c=>{c.state.user={id:'other-viewer'};},c=>{c.state.authType=null;}]){
  const pending=deferred(),f=fixture(()=>pending.promise),request=f.c.loadAlertCatalogue(50);change(f.c);pending.resolve(page([alert('late-private-row')],{offset:50}));await request;assert.equal(f.c.state.alertCatalogue.items.some(row=>row.id==='late-private-row'),false);
 }
 const f=fixture();f.c.state.user={id:'other-viewer'};const current=f.c.alertCataloguePage();assert.equal(current.items.length,0);assert.equal(current.total,null);await new Promise(setImmediate);
});
test('malformed count metadata and oversized pages fail visibly without treating partial pages as fleet totals',async()=>{
 const f=fixture(async()=>page(Array.from({length:101},()=>alert()),{limit:100}));await f.c.loadAlertCatalogue(0);assert.match(f.c.alertsHTML(),/bounded alert page/);assert.match(f.c.alertsHTML(),/Retry/);assert.equal(f.c.alertCatalogueCounts().total,507);
 assert.throws(()=>f.c.alertCatalogueRecord(page([],{critical_count:508}),'scope'),/inconsistent/);assert.throws(()=>f.c.alertCatalogueRecord(page([],{total:'507'}),'scope'),/exact alert counts/);
});

function bulkFixture(request){
 const f=fixture(request),messages=[],errors=[];let loads=0,closes=0;
 f.c.canWrite=()=>f.c.state.role==='admin';f.c.state.role='admin';f.c.errorSlot='<div id="form-error"></div>';
 f.c.showModal=(title,html)=>{f.element('#modal').open=true;f.element('#modal-title').textContent=title;f.element('#modal-content').innerHTML=html;};
 f.c.closeModal=()=>{closes++;f.element('#modal').open=false;f.element('#modal-content').innerHTML='';};
 f.c.toast=message=>messages.push(message);f.c.formError=error=>errors.push(error.message);f.c.load=async()=>{loads++;};
 const action=(name,scope)=>f.c.alertBulkAcknowledgementAction({disabled:false,dataset:{action:name,scope}});
 return {...f,action,messages,errors,loads:()=>loads,closes:()=>closes};
}
test('bulk filtered acknowledgement uses the whole exact query scope and refreshes counts after confirmation',async()=>{
 const f=bulkFixture(async(url,options)=>url==='/alerts/ack'?{scope:'filtered',acknowledged_count:506}:page([],{total:0,all_count:0,unresolved_count:0,critical_count:0,unacknowledged_count:0,open_count:0,has_more:false}));
 f.c.state.filters.application=['billing'];f.c.state.filters.ports=['443/tcp'];f.c.state.search='billing';
 // Mark this page as the current remote scope rather than allowing a background query.
 f.c.state.alertCatalogue=f.c.alertCatalogueRecord(page(),f.c.alertCatalogueScopeKey());
 assert.match(f.c.alertsHTML(),/Acknowledge filtered \(506\)/);
 await f.action('alert-bulk-ack-review','filtered');assert.equal(f.requests.length,0);assert.match(f.element('#modal-content').innerHTML,/across all result pages/);
 await f.action('alert-bulk-ack-confirm');
 const mutation=f.requests.find(({url})=>url==='/alerts/ack');assert.equal(mutation.options.method,'POST');
 assert.deepEqual(JSON.parse(JSON.stringify(mutation.options.body)),{scope:'filtered',query:{limit:50,offset:0,include_resolved:false,server_ids:['billing'],listener_server_ids:['billing'],search_server_ids:['billing'],ports:['443/tcp'],search:'billing'}});
 assert.deepEqual(f.messages,['506 alerts acknowledged.']);assert.equal(f.closes(),1);assert.equal(f.loads(),1);assert.equal(f.c.state.alertCatalogue.unacknowledged_count,0);
});
test('acknowledge all explicitly ignores current endpoint filters and reports the actual count',async()=>{
 const f=bulkFixture(async url=>url==='/alerts/ack'?{scope:'all',acknowledged_count:812}:page());f.c.state.filters.application=['billing'];
 await f.action('alert-bulk-ack-review','all');assert.match(f.element('#modal-content').innerHTML,/Current filters do not restrict/);
 await f.action('alert-bulk-ack-confirm');
 assert.deepEqual(JSON.parse(JSON.stringify(f.requests.find(row=>row.url==='/alerts/ack').options.body)),{scope:'all'});assert.deepEqual(f.messages,['812 alerts acknowledged.']);
});
test('read only and changed filtered scopes cannot perform a bulk acknowledgement',async()=>{
 const f=bulkFixture(async()=>page());f.c.state.role='read_only';assert.match(f.c.alertsHTML(),/data-scope="all" disabled/);
 await f.action('alert-bulk-ack-review','all');await f.action('alert-bulk-ack-confirm');assert.equal(f.requests.length,0);
 f.c.state.role='admin';f.c.state.alertCatalogue=f.c.alertCatalogueRecord(page(),f.c.alertCatalogueScopeKey());await f.action('alert-bulk-ack-review','filtered');assert.match(f.element('#modal-content').innerHTML,/data-alert-ack-generation/);f.c.state.filters.ports=['22/tcp'];await f.action('alert-bulk-ack-confirm');assert.equal(f.requests.filter(row=>row.url==='/alerts/ack').length,0);
});
test('a pending acknowledgement cannot close another dialog or cross an identity change',async()=>{
 for(const mode of ['new-dialog','identity']){
  const pending=deferred(),f=bulkFixture(async url=>url==='/alerts/ack'?pending.promise:page());await f.action('alert-bulk-ack-review','all');const operation=f.action('alert-bulk-ack-confirm');
  if(mode==='new-dialog')f.c.showModal('Keep my new draft','<input value="new draft">');else f.c.state.user={id:'different-admin'};
  pending.resolve({scope:'all',acknowledged_count:7});await operation;
  assert.equal(f.closes(),0);
  if(mode==='new-dialog')assert.match(f.element('#modal-content').innerHTML,/new draft/);else {assert.equal(f.messages.length,0);assert.equal(f.loads(),0);}
 }
});
test('bulk acknowledgement refuses duplicate clicks while busy and exposes failures for retry',async()=>{
 const pending=deferred(),f=bulkFixture(async url=>{if(url==='/alerts/ack')return pending.promise;return page();});await f.action('alert-bulk-ack-review','all');const first=f.action('alert-bulk-ack-confirm');await f.action('alert-bulk-ack-confirm');assert.equal(f.requests.filter(row=>row.url==='/alerts/ack').length,1);
 pending.resolve({scope:'all',acknowledged_count:-1});await first;assert.match(f.errors[0],/did not confirm/);assert.equal(f.closes(),0);assert.equal(f.loads(),0);
});
