const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const source=fs.readFileSync(path.join(__dirname,'..','settings-siem-page.js'),'utf8');
const config=()=>({revision:2,enabled:true,health:'queued',queued_events:12,queue_limit:50000,overflow_events:0,last_acknowledged_sequence:400,destination:{destination:'https://siem.example.test/…',host:'siem.example.test',addresses:['8.8.8.8'],audit_enabled:true,alerts_enabled:true,credential_flags:{url_configured:true,auth_token_configured:true}}});
const plan=()=>({id:'review-one',digest:'exact-digest',confirmation_nonce:'exact-nonce',confirmation_phrase:'SAVE REVIEWED SIEM DESTINATION',expires_at:new Date(Date.now()+60000).toISOString(),can_apply:true,blockers:[],summary:{enabled:true,destination:config().destination}});
const batch=()=>({id:'batch-one',status:'uncertain',attempts:1,first_sequence:401,last_sequence:412,event_count:12,destination:'https://old.example.test/…',created_at:'2026-11-04T00:00:00Z'});
function fixture(handler){
 const requests=[],elements=new Map(),modals=[],messages=[];
 const element=(selector)=>{if(!elements.has(selector))elements.set(selector,{open:false,disabled:false,value:''});return elements.get(selector);};
 const context={console,JSON,Object,Array,String,Number,Date,Promise,FormData:class{constructor(form){this.values=form.values||{};}get(key){return this.values[key]??null;}},
  state:{authType:'session',role:'super_admin',user:{id:'super-one'},view:'settings',platformSIEM:config(),siemDeliveries:{items:[batch()],total:1,offset:0,has_more:false}},
  document:{activeElement:null},$:element,$$:()=>[],h:value=>String(value??'').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;'),num:value=>Number(value)||0,badge:(label,tone)=>`<span class="${tone}">${label}</span>`,timestamp:value=>value||'',errorSlot:'<div class="form-error"></div>',
  canManagePlatform:()=>context.state.role==='super_admin',platformHasDraft:()=>false,platformClearDraft(){},render(){},closeModal(){},showModal:(title,html)=>modals.push({title,html}),toast:message=>messages.push(message),platformHAError:(form,error)=>messages.push(error.message),
  api:async(url,options)=>{requests.push({url,options});return handler?handler(url,options):url.includes('deliveries')?{items:[batch()],total:1,offset:0,has_more:false}:url.endsWith('/preview')?plan():config();}};
 vm.createContext(context);vm.runInContext(source,context);context.state.siemOwner=context.siemIdentity();
 return {c:context,requests,elements,modals,messages,element};
}
const submit=(form)=>({target:form,preventDefault(){}});
const deferred=()=>{let resolve;const promise=new Promise(done=>{resolve=done;});return {promise,resolve};};

test('SIEM page distinguishes acceptance, queue overflow and indexing with escaped fields',()=>{
 const f=fixture();f.c.state.platformSIEM.overflow_events=2;f.c.state.platformSIEM.destination.destination='<script>receiver</script>';f.c.state.siemDeliveries.items[0].error='<img src=x>';
 const html=f.c.platformSIEMHTML();assert.match(html,/Overflow export copies/);assert.match(html,/automatic historical backfill is unavailable/i);assert.match(html,/not SIEM indexing/);assert.match(html,/Syslog is not supported/);assert.match(html,/&lt;script&gt;receiver&lt;\/script&gt;/);assert.match(html,/&lt;img src=x&gt;/);assert.doesNotMatch(html,/<script>receiver|<img src=x>/);assert.match(html,/Acknowledgement unknown/);assert.match(html,/Leave blank to preserve saved value/);
});
test('Read Only and Admin can read health but cannot configure or retry',async()=>{
 for(const role of ['read_only','admin']){const f=fixture();f.c.state.role=role;await f.c.loadPlatformSIEM(false);assert.equal(f.requests.length,1);assert.equal(f.requests[0].url,'/platform/siem');const html=f.c.platformSIEMHTML();assert.doesNotMatch(html,/id="platform-siem-form"/);assert.match(html,/Only a Super Admin/);await f.c.platformSIEMSubmit(submit({id:'platform-siem-form'}));await f.c.platformSIEMAction({dataset:{action:'platform-siem-retry',id:'batch-one'}});assert.equal(f.requests.length,1);}
});
test('payload preserves blank secrets and uses explicit booleans without OS details',()=>{
 const f=fixture(),payload=f.c.siemPayload({dataset:{revision:'2'},values:{enabled:'on',audit_enabled:'on',idempotency_supported:'on',url:'',auth_token:'',signing_secret:' ',custom_ca_pem:''}});
 assert.equal(payload.expected_revision,2);assert.equal(payload.enabled,true);assert.equal(payload.alerts_enabled,false);assert.equal(payload.allow_private_network,false);assert.equal(payload.idempotency_supported,true);assert.equal('url' in payload,false);assert.equal('auth_token' in payload,false);assert.equal('signing_secret' in payload,false);
});
test('destination review is current, exact, single-admin and expires or invalidates on identity change',()=>{
 const f=fixture(),review=plan();f.c.showSIEMReview(review);assert.match(f.modals[0].html,/no second approver/i);assert.match(f.modals[0].html,/button type="submit" class="button primary" disabled/);assert.equal(f.c.siemReviewUsable(review,'yes'),false);assert.equal(f.c.siemReviewUsable(review,review.confirmation_phrase),true);
 f.c.platformSIEMInput({target:{id:'siem-review-phrase',value:review.confirmation_phrase}});assert.equal(f.element('button[type="submit"]').disabled,false);
 review.expires_at=new Date(0).toISOString();assert.equal(f.c.siemReviewUsable(review,review.confirmation_phrase),false);review.expires_at=new Date(Date.now()+60000).toISOString();f.c.state.user={id:'other-super'};assert.equal(f.c.siemReviewUsable(review,review.confirmation_phrase),false);
});
test('preview then apply submits exact review nonce and never treats save as delivery',async()=>{
 const f=fixture(),form={id:'platform-siem-form',dataset:{revision:'2'},values:{enabled:'on',audit_enabled:'on',alerts_enabled:'on',url:'https://new.example.test/private'}};
 await f.c.platformSIEMSubmit(submit(form));assert.equal(f.requests[0].url,'/platform/siem/preview');assert.equal(f.modals.length,1);
 await f.c.platformSIEMSubmit(submit({id:'platform-siem-review-form',values:{confirmation_phrase:plan().confirmation_phrase}}));const request=f.requests.find(row=>row.url==='/platform/siem/apply');assert.ok(request);assert.equal(request.options.body.confirmation_nonce,'exact-nonce');assert.equal(request.options.body.digest,'exact-digest');assert.match(f.messages[0],/Delivery acknowledgement is tracked separately/);
});
test('retry requires an explicit duplicate acknowledgement and keeps batch/version binding',async()=>{
 const f=fixture();await f.c.platformSIEMAction({dataset:{action:'platform-siem-retry',id:'batch-one'}});assert.match(f.modals[0].html,/may already have arrived/);const form={id:'platform-siem-retry-form',values:{}};await f.c.platformSIEMSubmit(submit(form));assert.equal(f.requests.length,0);
 form.values.confirm_duplicate='on';await f.c.platformSIEMSubmit(submit(form));const request=f.requests[0];assert.equal(request.url,'/platform/siem/retry');assert.equal(request.options.body.delivery_id,'batch-one');assert.equal(request.options.body.expected_revision,2);assert.equal(request.options.body.expected_attempts,1);assert.equal(request.options.body.confirm_possible_duplicate,true);
});
test('demo never offers external retry and stale loads do not cross identities',async()=>{
 const f=fixture();f.c.state.authType='demo';await f.c.platformSIEMAction({dataset:{action:'platform-siem-retry',id:'batch-one'}});assert.equal(f.modals.length,0);assert.equal(f.requests.length,0);
 const pending=deferred(),g=fixture(()=>pending.promise),loading=g.c.loadPlatformSIEM(false);g.c.state.user={id:'replacement'};pending.resolve(config());await loading;assert.notEqual(g.c.state.siemOwner,g.c.siemIdentity());assert.doesNotMatch(g.c.platformSIEMHTML(),/https:\/\/siem.example.test/);
});
test('a preview response cannot open a review after the user signs out',async()=>{
 const pending=deferred(),f=fixture(()=>pending.promise),saving=f.c.platformSIEMSubmit(submit({id:'platform-siem-form',dataset:{revision:'2'},values:{enabled:'on',audit_enabled:'on'}}));f.c.state.role='read_only';f.c.state.user={id:'reader'};pending.resolve(plan());await saving;assert.equal(f.modals.length,0);
});
