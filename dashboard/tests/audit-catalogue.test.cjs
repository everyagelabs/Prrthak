const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const app=fs.readFileSync(path.join(__dirname,'..','app.js'),'utf8');
const empty={search:'',action:'',actor:'',from_at:'',to_at:''};
const event=(id='old-policy')=>({id,action:'policy.updated',actor:'admin-one',created_at:'2026-11-02T00:00:00Z',details:{policy_id:'billing'}});
const page=(items=[event()],updates={})=>({items,total:608,limit:50,offset:0,has_more:true,filters:{...empty},summary_only:true,...updates});
const deferred=()=>{let resolve;const promise=new Promise(done=>{resolve=done;});return {promise,resolve};};
function fixture(request=async()=>page()){
 const elements=new Map(),requests=[],downloads=[],listeners={};
 const element=selector=>{if(!elements.has(selector))elements.set(selector,{innerHTML:'',open:false,click(){downloads.push({href:this.href,name:this.download});}});return elements.get(selector);};
 const c={console,JSON,Array,String,Number,Object,Date,Promise,Blob,AbortController,FormData:class{constructor(form){this.values=form.values;}get(key){return this.values[key];}},state:{authType:'session',authConfig:{mode:'entra'},role:'read_only',user:{id:'viewer',tenant_id:'tenant'},token:'',csrfToken:'csrf-reader',view:'activity',data:{servers:[]}},document:{activeElement:null,createElement:()=>element('download'),addEventListener:(kind,handler)=>{listeners[kind]=handler;}},$:element,h:value=>String(value??'').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;'),format:value=>String(value),icon:()=>'',humanize:value=>value,timestamp:value=>value,age:value=>value,emptyHTML:(title,body)=>`<p>${title}: ${body}</p>`,setTimeout:()=>1,clearTimeout(){},URL:{createObjectURL:()=> 'blob:audit-export',revokeObjectURL(){}},fetch:async(url,options)=>{requests.push({url,options});const value=await request(url,options);if(value?.blobResponse)return value;return {ok:true,status:200,json:async()=>value};}};
 vm.createContext(c);
 const start=app.indexOf('async function api('),end=app.indexOf('\nfunction toast(',start);assert.ok(start>=0&&end>start);vm.runInContext(app.slice(start,end),c);
 vm.runInContext(app.match(/function canWrite\(\)\{[^\n]+/)[0],c);
 vm.runInContext(fs.readFileSync(path.join(__dirname,'..','audit-catalogue-page.js'),'utf8'),c);
 c.render=()=>{element('#view-content').innerHTML=c.auditCatalogueHTML();};
 return {c,requests,downloads,element,listeners};
}
test('Read Only pages complete audit history through the production permission wrapper with CSRF',async()=>{
 const f=fixture(async()=>page(Array.from({length:8},(_,i)=>event('event-'+(600+i))),{offset:600,has_more:false}));
 await f.c.loadAuditCatalogue(600);const html=f.c.auditCatalogueHTML();
 assert.match(html,/601–608 of 608 matching audit events/);assert.match(html,/data-offset="550"/);assert.match(html,/data-offset="608" disabled/);assert.equal(f.requests.length,1);assert.equal(f.requests[0].url,'/api/v1/audit/query');assert.equal(f.requests[0].options.method,'POST');assert.equal(f.requests[0].options.credentials,'same-origin');assert.equal(f.requests[0].options.headers['X-CSRF-Token'],'csrf-reader');assert.equal(JSON.parse(f.requests[0].options.body).offset,600);assert.match(html,/Export filtered history CSV/);
 await assert.rejects(()=>f.c.api('/policies',{method:'POST',body:{}}),/Read Only access/);assert.equal(f.requests.length,1);
});
test('action actor search and local date filters are applied before navigation and clear resets page',async()=>{
 const f=fixture(async(url,options)=>{const query=JSON.parse(options.body);return page([event()],{total:1,has_more:false,filters:Object.fromEntries(Object.keys(empty).map(key=>[key,query[key]]))});});
 const form={values:{search:' billing%_ ',action:'policy.updated',actor:'admin-one',from_at:'2026-11-02T05:30:00',to_at:'2026-11-02T06:30:00'}};
 await f.c.auditCatalogueSubmit(form);const body=JSON.parse(f.requests[0].options.body);
 assert.equal(body.search,'billing%_');assert.equal(body.action,'policy.updated');assert.equal(body.actor,'admin-one');assert.equal(body.from_at,new Date(form.values.from_at).toISOString().replace('.000Z','Z'));assert.equal(body.offset,0);assert.equal(f.c.auditCataloguePage().total,1);
 await f.c.auditCatalogueAction({dataset:{action:'audit-clear'}});assert.equal(JSON.parse(f.requests[1].options.body).search,'');assert.equal(f.c.state.auditDraft,null);
 const before=f.requests.length;await f.c.auditCatalogueSubmit({values:{...form.values,from_at:'2026-11-03T00:00:00',to_at:'2026-11-02T00:00:00'}});assert.equal(f.requests.length,before);assert.match(f.c.auditCatalogueHTML(),/start time must not follow/);
});
test('pending pages never cross search filters identities or signout',async()=>{
 for(const change of [c=>{c.state.auditFilters={search:'payments'};},c=>{c.state.user={id:'different-viewer'};},c=>{c.state.authType=null;}]){
  const pending=deferred(),f=fixture(()=>pending.promise),request=f.c.loadAuditCatalogue(50);change(f.c);pending.resolve(page([event('late-private')],{offset:50}));await request;
  assert.equal(f.c.auditCataloguePage().items.some(row=>row.id==='late-private'),false);assert.doesNotMatch(f.c.auditCatalogueHTML(),/late-private/);
 }
});
test('audit events and errors are escaped and inconsistent scope/count pages fail visibly',async()=>{
 const f=fixture(async()=>page([{...event(),actor:'<img src=x>',details:{reason:'<script>unsafe</script>'}}]));await f.c.loadAuditCatalogue(0);
 let html=f.c.auditCatalogueHTML();assert.match(html,/&lt;img src=x&gt;/);assert.match(html,/&lt;script&gt;unsafe&lt;\/script&gt;/);assert.doesNotMatch(html,/<img src=x>|<script>/);
 for(const response of [page([],{total:'608'}),page(Array.from({length:51},()=>event())),page([],{filters:{...empty,search:'other'}})]){
  const g=fixture(async()=>response);await g.c.loadAuditCatalogue(0);assert.match(g.c.auditCatalogueHTML(),/Audit history unavailable/);assert.equal(g.c.auditCataloguePage().total,null);
 }
});
test('CSV export uses complete applied scope with CSRF and suppresses stale downloads',async()=>{
 const csv=()=>({blobResponse:true,ok:true,blob:async()=>new Blob(['id,action\r\nold,policy.updated\r\n'])});
 const f=fixture(async(url)=>url.endsWith('.csv')?csv():page());await f.c.loadAuditCatalogue(0);await f.c.downloadAuditCSV();
 assert.equal(f.requests[1].url,'/api/v1/audit/export.csv');assert.equal(f.requests[1].options.credentials,'same-origin');assert.equal(f.requests[1].options.headers['X-CSRF-Token'],'csrf-reader');assert.deepEqual(JSON.parse(f.requests[1].options.body),empty);assert.equal(f.downloads.length,1);assert.equal(f.downloads[0].name,'prthak-audit-history.csv');
 const pending=deferred(),g=fixture(()=>pending.promise),request=g.c.downloadAuditCSV();g.c.state.user={id:'replacement'};pending.resolve(csv());await request;assert.equal(g.downloads.length,0);assert.equal(g.c.auditExportBusy(),false);
 const pendingBlob=deferred(),k=fixture(async()=>({blobResponse:true,ok:true,blob:()=>pendingBlob.promise})),download=k.c.downloadAuditCSV();await new Promise(setImmediate);k.c.state.auditFilters={search:'different'};pendingBlob.resolve(new Blob(['private data']));await download;assert.equal(k.downloads.length,0);
});
test('unapplied audit filter drafts survive rendering and cannot ambiguously export',async()=>{
 const f=fixture();await f.c.loadAuditCatalogue(0);const form={values:{...empty,search:'unapplied billing'}};f.listeners.input({target:{closest:()=>form}});
 assert.match(f.c.auditCatalogueHTML(),/value="unapplied billing"/);const before=f.requests.length;await f.c.downloadAuditCSV();assert.equal(f.requests.length,before);assert.match(f.c.auditCatalogueHTML(),/Apply or clear filter edits/);assert.match(f.c.auditCatalogueHTML(),/Unapplied filter edits are preserved/);
});
