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
