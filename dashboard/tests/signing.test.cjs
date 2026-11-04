const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const source=fs.readFileSync(path.join(__dirname,'..','settings-signing-page.js'),'utf8');
const status=()=>({mode:'online_controller',health:'online_key_available',custody:'Private signing authority is online inside this controller trust boundary.',deployment_id:'deployment-one',key_ids:['public-key-one'],public_fingerprints:{'public-key-one':'public-fingerprint'},public_trust:{deployment_id:'deployment-one',keys:{'public-key-one':'PUBLIC_ONLY'}},checkpoint_available:true,checkpoint_limit:10,checkpoint_scope:'Local Vault only; not off-node disaster recovery.',checkpoints:[{id:'checkpoint-one',key_ids:['public-key-one'],node_id:'node-one',created_by:'super-one',created_at:'2026-11-04T00:00:00Z'}],rotation_available:false,rotation_reason:'Agents pin trust; explicit adoption and retirement are required.',blockers:[]});
const plan=()=>({id:'review-one',checkpoint_id:'checkpoint-one',deployment_id:'deployment-one',key_ids:['public-key-one'],scope:'Recreate only the missing current key; pins remain unchanged.',digest:'exact-digest',confirmation_nonce:'exact-nonce',confirmation_phrase:'RESTORE THE SAME SIGNING KEY',expires_at:new Date(Date.now()+60000).toISOString(),can_apply:true,blockers:[]});
function fixture(handler){
 const requests=[],elements=new Map(),modals=[],messages=[],downloads=[];
 const element=selector=>{if(!elements.has(selector))elements.set(selector,{open:false,disabled:false});return elements.get(selector);};
 const c={console,JSON,Object,Array,String,Number,Date,Promise,Blob,FormData:class{constructor(form){this.values=form.values||{};}get(key){return this.values[key]||null;}},state:{authType:'session',role:'super_admin',user:{id:'super-one'},view:'settings',platformSigning:status()},document:{activeElement:null,createElement:()=>({click(){downloads.push({name:this.download,href:this.href});}})},$:element,h:value=>String(value??'').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;'),num:value=>Number(value)||0,timestamp:value=>value||'',errorSlot:'<div class="form-error"></div>',canManagePlatform:()=>c.state.role==='super_admin',platformHasDraft:()=>false,render(){},closeModal(){},showModal:(title,html)=>modals.push({title,html}),toast:message=>messages.push(message),formError:error=>messages.push(error.message),platformHAError:(form,error)=>messages.push(error.message),URL:{createObjectURL:()=> 'blob:public-only',revokeObjectURL(){}},setTimeout:()=>1,
 api:async(url,options)=>{requests.push({url,options});return handler?handler(url,options):url.endsWith('/preview')?plan():url.endsWith('/apply')?{status:'restored'}:url.endsWith('/check')?{status:'passed'}:status();}};
 vm.createContext(c);vm.runInContext(source,c);c.state.signingOwner=c.signingIdentity();return {c,requests,elements,modals,messages,downloads,element};
}
const submit=form=>({target:form,preventDefault(){}});
const deferred=()=>{let resolve;const promise=new Promise(done=>{resolve=done;});return {promise,resolve};};

test('signing GUI truthfully explains online custody and disables incomplete rotation',()=>{
 const f=fixture(),html=f.c.platformSigningHTML();assert.match(html,/Automatic online policy signatures/);assert.match(html,/does not isolate a compromised controller/);assert.match(html,/Rotation is unavailable/);assert.match(html,/No private-key download/);assert.match(html,/not an off-node backup|not off-node disaster recovery/);assert.match(html,/Review same-key recovery<\/button>/);assert.match(html,/data-id="checkpoint-one" disabled/);assert.doesNotMatch(html,/<input[^>]*(seed|private_key)/);
 f.c.state.platformSigning.blockers=['<script>unsafe</script>'];assert.match(f.c.platformSigningHTML(),/&lt;script&gt;unsafe&lt;\/script&gt;/);
});
test('Read Only and Admin cannot invoke key lifecycle changes and public trust is the only download',async()=>{
 for(const role of ['read_only','admin']){const f=fixture();f.c.state.role=role;await f.c.loadPlatformSigning(false);const html=f.c.platformSigningHTML();assert.doesNotMatch(html,/data-action="platform-signing-check"|data-action="platform-signing-checkpoint"/);await f.c.platformSigningAction({dataset:{action:'platform-signing-check'}});await f.c.platformSigningAction({dataset:{action:'platform-signing-recover',id:'checkpoint-one'}});assert.equal(f.requests.length,1);await f.c.platformSigningAction({dataset:{action:'platform-signing-public-download'}});assert.equal(f.downloads.length,1);assert.equal(f.downloads[0].name,'prthak-policy-signing-public-trust.json');}
});
test('self-check and encrypted checkpoint use fixed GUI operations and honest outcomes',async()=>{
 const f=fixture();await f.c.platformSigningAction({dataset:{action:'platform-signing-check'}});assert.equal(f.requests[0].url,'/platform/signing/check');assert.match(f.messages[0],/Endpoint outcomes remain separate/);await f.c.platformSigningAction({dataset:{action:'platform-signing-checkpoint'}});const request=f.requests.find(row=>row.url.endsWith('/checkpoints'));assert.ok(request);assert.equal(JSON.stringify(request.options.body),'{}');assert.match(f.messages[1],/created on this controller/);
});
test('same-key recovery uses a fresh exact single-admin review and cannot reuse another identity',async()=>{
 const f=fixture();f.c.state.platformSigning.health='unavailable';await f.c.platformSigningAction({dataset:{action:'platform-signing-recover',id:'checkpoint-one'}});assert.equal(f.requests[0].options.body.checkpoint_id,'checkpoint-one');assert.match(f.modals[0].html,/no second person is required/);const review=f.c.state.signingRecoveryReview;assert.equal(f.c.signingReviewUsable(review,'yes'),false);assert.equal(f.c.signingReviewUsable(review,review.confirmation_phrase),true);
 f.c.platformSigningInput({target:{id:'signing-recovery-phrase',value:review.confirmation_phrase}});assert.equal(f.element('button[type="submit"]').disabled,false);await f.c.platformSigningSubmit(submit({id:'platform-signing-recovery-form',values:{confirmation_phrase:review.confirmation_phrase}}));const request=f.requests.find(row=>row.url.endsWith('/recovery/apply'));assert.equal(request.options.body.digest,'exact-digest');assert.equal(request.options.body.confirmation_nonce,'exact-nonce');assert.match(f.messages[0],/same signing key was restored/);
 const g=fixture(),p=plan();g.c.showSigningRecovery(p);g.c.state.user={id:'different'};assert.equal(g.c.signingReviewUsable(p,p.confirmation_phrase),false);p.expires_at=new Date(0).toISOString();assert.equal(g.c.signingReviewUsable(p,p.confirmation_phrase),false);
});
test('stale signing health and recovery reviews cannot cross sign-out or user replacement',async()=>{
 const pending=deferred(),f=fixture(()=>pending.promise),loading=f.c.loadPlatformSigning(false);f.c.state.user={id:'replacement'};pending.resolve(status());await loading;assert.equal(f.c.currentSigning(),null);assert.doesNotMatch(f.c.platformSigningHTML(),/public-fingerprint/);
 const request=deferred(),g=fixture(()=>request.promise),reviewing=g.c.platformSigningAction({dataset:{action:'platform-signing-recover',id:'checkpoint-one'}});g.c.state.role='read_only';request.resolve(plan());await reviewing;assert.equal(g.modals.length,0);
});
