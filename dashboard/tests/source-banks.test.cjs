const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const app=fs.readFileSync(path.join(__dirname,'..','app.js'),'utf8');
const digest=letter=>letter.repeat(64),nonce='n'.repeat(43);
const deferred=()=>{let resolve;const promise=new Promise(done=>{resolve=done;});return {promise,resolve};};
const stamp=()=>new Date(Date.now()-1000).toISOString();
const server=(id='billing')=>({id,hostname:id+'-server',ips:['192.0.2.'+(id==='billing'?10:11)],capabilities:['source_bank_preparation_v1','signed_assignments_v1'],desired_version:1,configuration_state:{digest:digest('b')},protection_digest:digest('c')});
function receipt(id='billing',updates={}){return {schema_version:1,id:'assess-'+id,operation:'assess',plan_digest:digest('d'),status:'assessed',checked_at:stamp(),baseline_digest:digest('a'),protection_digest:digest('c'),missing_banks:256,active_banks:0,permanent_banks:0,created_banks:0,activation_required:true,blockers:[],...updates};}
function job(id='billing',updates={}){return {id:'assess-'+id,server_id:id,operation:'assess',status:'assigned',plan_digest:digest('d'),...updates};}
function fixture({role='admin',demo=false,request}={}){
 const elements=new Map(),listeners={},requests=[],receipts=new Map([['billing',receipt()],['payments',receipt('payments')]]);let prepared=false;
 const element=selector=>{if(!elements.has(selector))elements.set(selector,{innerHTML:'',textContent:'',open:false,disabled:false,checked:false,value:'',name:'',hidden:false});return elements.get(selector);};
 const c={console,JSON,Array,String,Number,Object,Set,Map,Date,Promise,AbortController,errorSlot:'<div id="form-error"></div>',FormData:class{constructor(form){this.values=form.values||{};}get(key){return this.values[key]??null;}getAll(key){const value=this.values[key];return Array.isArray(value)?value:value==null?[]:[value];}},state:{authType:'session',authConfig:{mode:'entra'},role,user:{id:'operator',tenant_id:'tenant'},token:'',csrfToken:'csrf',view:'servers',data:{meta:{demo},servers:[server(),server('payments')],groups:[{id:'billing-group',name:'Billing group'}]}},document:{querySelector:element,addEventListener:(kind,handler)=>{(listeners[kind]||=[]).push(handler);}},$:element,h:value=>String(value??'').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;'),num:value=>Number(value)||0,format:String,humanize:value=>String(value).replaceAll('_',' '),timestamp:String,setTimeout:()=>1,clearTimeout(){},formError:error=>{element('#form-error').textContent=error.message;},showModal:(title,html)=>{element('#modal').open=true;element('#modal-title').textContent=title;element('#modal-content').innerHTML=html;},fetch:async(url,options)=>{
  const body=options.body?JSON.parse(options.body):null;requests.push({url,options,body});
  let data;if(request)data=await request(url,body,c);
  if(data===undefined){
   if(url==='/api/v1/source-banks/query'){const ids=body.server_ids||c.state.data.servers.map(row=>row.id);const selected=c.state.data.servers.filter(row=>ids.includes(row.id)),offset=body.offset;data={items:selected.slice(offset,offset+50).map(row=>({server_id:row.id,hostname:row.hostname,capable:true,job:prepared?job(row.id,{id:'prepare-'+row.id,operation:'prepare_activate'}):job(row.id),receipt:receipts.get(row.id)})),total:selected.length,offset,limit:50,has_more:offset+Math.min(50,selected.length-offset)<selected.length};}
   else if(url==='/api/v1/source-banks/assess'){const ids=body.group_ids.length?['billing','payments']:body.server_ids;data={items:ids.map(id=>job(id)),count:ids.length};}
   else if(url==='/api/v1/source-banks/preview'){data=review(body.server_ids,receipts);}
   else if(url.endsWith('/confirm')){prepared=true;data={id:'review-one',status:'assigned',count:2,items:['billing','payments'].map(id=>job(id,{id:'prepare-'+id,operation:'prepare_activate'}))};}
   else throw new Error('Unexpected request '+url);
  }
  return {ok:true,status:200,json:async()=>data};
 }};
 c.filteredServers=()=>c.state.data.servers;
 vm.createContext(c);const start=app.indexOf('async function api('),end=app.indexOf('\nfunction toast(',start);vm.runInContext(app.slice(start,end),c);vm.runInContext(app.match(/function canWrite\(\)\{[^\n]+/)[0],c);vm.runInContext(fs.readFileSync(path.join(__dirname,'..','source-banks-page.js'),'utf8'),c);
 const state=()=>vm.runInContext('sourceBanksState',c);
 const change=target=>listeners.change.forEach(handler=>handler({target}));
 const input=target=>listeners.input.forEach(handler=>handler({target}));
 return {c,state,element,requests,receipts,change,input};
}
function review(ids,receipts){return {id:'review-one',kind:'source_bank_preparation',status:'preview',digest:digest('e'),confirmation_nonce:nonce,challenge:'PREPARE SOURCE BANKS',expires_at:new Date(Date.now()+120000).toISOString(),can_apply:true,blockers:[],targets:ids.map(id=>{const r=receipts.get(id);return {server_id:id,hostname:id+'-server',missing_banks:256,active_banks:0,permanent_banks:0,activation_required:true,baseline_digest:r.baseline_digest,protection_digest:r.protection_digest,assessed_at:r.checked_at,blockers:[]};})};}
async function assessed(f){await f.c.sourceBanksOpen();await f.c.sourceBanksSubmit({id:'source-bank-selection-form',values:{server_ids:[],group_ids:['billing-group']}});}
async function reviewed(f){await assessed(f);await f.c.sourceBanksPreview();}
function acknowledge(f){const check=f.element('#source-bank-ack');check.checked=true;f.change(check);const phrase=f.element('#source-bank-phrase');phrase.value='PREPARE SOURCE BANKS';f.input(phrase);}
test('Read Only can inspect source-set status through the real client wrapper but cannot assign assessment or preparation',async()=>{
 const f=fixture({role:'read_only'});await f.c.sourceBanksOpen('billing');
 assert.equal(f.requests[0].url,'/api/v1/source-banks/query');assert.equal(f.requests[0].options.headers['X-CSRF-Token'],'csrf');assert.deepEqual(f.requests[0].body.server_ids,['billing']);assert.match(f.element('#modal-content').innerHTML,/Status is available to Read Only/);assert.match(f.element('#modal-content').innerHTML,/type="submit"[^>]*disabled/);
 const before=f.requests.length;await f.c.sourceBanksSubmit({id:'source-bank-selection-form',values:{server_ids:['billing']}});await f.c.sourceBanksPreview();await f.c.sourceBanksConfirm();assert.equal(f.requests.length,before);
 await assert.rejects(()=>f.c.api('/source-banks/assess',{method:'POST',body:{server_ids:['billing']}}),/Read Only access/);
});
test('group assessment freezes exact resolved endpoints and maintenance needs an actual fresh checkbox event plus phrase',async()=>{
 const f=fixture();await reviewed(f);assert.deepEqual(Array.from(f.state().assessedIds),['billing','payments']);
 const preview=f.requests.find(row=>row.url.endsWith('/preview'));assert.deepEqual(preview.body,{server_ids:['billing','payments'],group_ids:[]});
 let html=f.element('#modal-content').innerHTML;assert.match(html,/No extra endpoint CLI|source-set maintenance/i);assert.match(html,/may interrupt traffic/i);assert.match(html,/no second approver/);assert.match(html,/name="acknowledge_downtime"/);assert.doesNotMatch(html,/id="source-bank-ack"[^>]*checked/);assert.equal(f.element('#source-bank-ack').checked,false);assert.equal(f.element('#source-bank-confirm').disabled,true);
 const before=f.requests.length;await f.c.sourceBanksSubmit({id:'source-bank-confirm-form',values:{acknowledge_downtime:'on',confirmation_phrase:'PREPARE SOURCE BANKS'}});assert.equal(f.requests.length,before,'Forged FormData is insufficient');
 f.element('#source-bank-ack').checked=true;f.element('#source-bank-phrase').value='PREPARE SOURCE BANKS';await f.c.sourceBanksConfirm();assert.equal(f.requests.length,before,'Programmatic values without a checkbox event are insufficient');
 acknowledge(f);assert.equal(f.element('#source-bank-confirm').disabled,false);await f.c.sourceBanksConfirm();
 const push=f.requests.find(row=>row.url.endsWith('/confirm'));assert.deepEqual(push.body,{digest:digest('e'),confirmation_nonce:nonce,confirmation_phrase:'PREPARE SOURCE BANKS',acknowledge_downtime:true});assert.equal(push.options.headers['X-CSRF-Token'],'csrf');assert.equal(f.state().review,null);assert.equal(f.state().acknowledged,'');assert.match(f.element('#modal-content').innerHTML,/assignment alone is not completion/);assert.match(f.element('#source-bank-status').innerHTML,/Historical receipt/);
});
test('policy address configuration protection and receipt changes invalidate acknowledgement before any push',async()=>{
 for(const mutate of [f=>{f.c.state.data.servers[0].desired_version++;},f=>{f.c.state.data.servers[0].ips=['192.0.2.99'];},f=>{f.c.state.data.servers[0].configuration_state.digest=digest('f');},f=>{f.c.state.data.servers[0].protection_digest=digest('f');},f=>{f.state().page.items[0].receipt.baseline_digest=digest('f');},f=>{f.state().page.items[0].capable=false;}]){
  const f=fixture();await reviewed(f);acknowledge(f);mutate(f);f.c.sourceBanksInvalidateReview();assert.equal(f.element('#source-bank-ack').checked,false);assert.equal(f.element('#source-bank-phrase').value,'');assert.equal(f.element('#source-bank-confirm').disabled,true);const before=f.requests.length;await f.c.sourceBanksConfirm();assert.equal(f.requests.length,before);
 }
});
test('expired incomplete or foreign endpoint reviews remain blocked and display escaped blockers',async()=>{
 for(const mutate of [plan=>{plan.expires_at=new Date(Date.now()-1).toISOString();},plan=>{plan.targets[0].assessed_at=new Date(Date.now()-181000).toISOString();},plan=>{plan.targets[0].server_id='unselected';},plan=>{plan.targets[0].baseline_digest='';},plan=>{plan.confirmation_nonce='';},plan=>{plan.can_apply=false;plan.blockers=['<script>blocked</script>'];}]){
  const f=fixture({request:(url,body,c)=>{if(url.endsWith('/preview')){const data=review(body.server_ids,f.receipts);mutate(data);return data;}}});await reviewed(f);acknowledge(f);assert.equal(f.element('#source-bank-confirm').disabled,true);const before=f.requests.length;await f.c.sourceBanksConfirm();assert.equal(f.requests.length,before);assert.doesNotMatch(f.element('#modal-content').innerHTML,/<script>/);
 }
});
test('late status assessment and preview responses cannot resurrect a closed modal or cross identity',async()=>{
 for(const endpoint of ['/query','/assess','/preview']){
  const pending=deferred();let hold=false;const f=fixture({request:async(url,body)=>{if(hold&&url.endsWith(endpoint))return pending.promise;}});
  if(endpoint==='/query'){hold=true;const call=f.c.sourceBanksOpen();f.c.sourceBanksClose();f.element('#modal').open=false;pending.resolve({items:[],total:0,offset:0,limit:50,has_more:false});await call;}
  else if(endpoint==='/assess'){await f.c.sourceBanksOpen();hold=true;const call=f.c.sourceBanksSubmit({id:'source-bank-selection-form',values:{server_ids:['billing']}});f.c.state.user={id:'other'};pending.resolve({items:[job()],count:1});await call;}
  else{await assessed(f);hold=true;const call=f.c.sourceBanksPreview();f.c.sourceBanksClose();f.element('#modal').open=false;pending.resolve(review(['billing','payments'],f.receipts));await call;}
  assert.equal(f.state().review,null);
 }
});
test('selection changes fence pending assessment and require another explicit assessment',async()=>{
 const pending=deferred();const f=fixture({request:(url)=>url.endsWith('/assess')?pending.promise:undefined});await f.c.sourceBanksOpen();
 const call=f.c.sourceBanksSubmit({id:'source-bank-selection-form',values:{server_ids:['billing']}}),form={values:{server_ids:['payments']}};
 f.change({name:'server_ids',closest:()=>form});pending.resolve({items:[job()],count:1});await call;assert.equal(f.state().assessedIds.length,0);assert.equal(f.state().busy,false);assert.match(f.element('#modal-content').innerHTML,/Assess the current selection/);assert.doesNotMatch(f.element('#modal-content').innerHTML,/type="submit"[^>]*disabled/);const before=f.requests.length;await f.c.sourceBanksPreview();assert.equal(f.requests.length,before);
});
test('demo mode never activates preparation and terminal receipts remain last reported facts',async()=>{
 const f=fixture({demo:true});await f.c.sourceBanksOpen();const before=f.requests.length;await f.c.sourceBanksSubmit({id:'source-bank-selection-form',values:{server_ids:['billing']}});assert.equal(f.requests.length,before);assert.match(f.element('#modal-content').innerHTML,/installed controller/);
 const row={...server(),source_bank_preparation:receipt('billing',{status:'prepared',operation:'prepare_activate',active_banks:256,permanent_banks:256,missing_banks:0,activation_required:false})};const html=f.c.sourceBanksStatusHTML(row);assert.match(html,/last checked/);assert.match(html,/256\/256/);assert.match(html,/actual result/);
});
test('a fresh review never reuses a previous acknowledgement',async()=>{
 const f=fixture();await reviewed(f);acknowledge(f);assert.equal(f.element('#source-bank-confirm').disabled,false);f.c.sourceBanksShowReview(review(['billing','payments'],f.receipts));assert.equal(f.element('#source-bank-ack').checked,false);assert.equal(f.element('#source-bank-phrase').value,'');assert.equal(f.element('#source-bank-confirm').disabled,true);
});
test('an in-flight confirmed operation cannot be navigated back into another selection',async()=>{
 const pending=deferred(),f=fixture({request:url=>url.endsWith('/confirm')?pending.promise:undefined});await reviewed(f);acknowledge(f);const request=f.c.sourceBanksConfirm();assert.equal(f.state().busy,true);assert.equal(f.element('[data-action="source-bank-back"]').disabled,true);
 await f.c.sourceBanksAction({dataset:{action:'source-bank-back'}});assert.equal(f.state().phase,'review');assert.equal(f.state().busy,true);
 pending.resolve({id:'review-one',status:'assigned',count:2,items:['billing','payments'].map(id=>job(id,{operation:'prepare_activate'}))});await request;assert.equal(f.state().phase,'selection');assert.equal(f.state().review,null);assert.equal(f.state().busy,false);
});
