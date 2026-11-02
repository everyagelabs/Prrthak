const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');

function fixture(){
 const nodes=new Map(),readers=[],requests=[],errors=[],reviews=[];
 const element=key=>{if(!nodes.has(key))nodes.set(key,{value:'',textContent:'',disabled:false});return nodes.get(key);};
 class Reader{
  constructor(){this.readyState=0;readers.push(this);}
  readAsDataURL(file){this.file=file;this.readyState=1;}
  abort(){this.readyState=2;this.onabort?.();}
  complete(value){this.result='data:application/x-pkcs12;base64,'+value;this.readyState=2;this.onload();}
 }
 const c={console,JSON,FileReader:Reader,state:{role:'super_admin',authType:'session',user:{id:'admin-a'},token:'',csrfToken:'fixture-csrf',authConfig:{mode:'entra'}},
  $:element,$$:()=>[],canManagePlatform:()=>c.state.role==='super_admin',sessionStorage:{removeItem(){}},
  FormData:class{constructor(form){this.values=form.values;}get(key){return this.values[key];}},
  api:async(path,options)=>{requests.push({path,options});return {id:'review-a'};},
  platformHAError:(form,error)=>errors.push(error.message),platformShowApplianceReview:plan=>reviews.push(plan)};
 vm.createContext(c);
 for(const name of ['settings-certificates-page.js','access-page.js'])vm.runInContext(fs.readFileSync(require.resolve('../'+name),'utf8'),c);
 const select=file=>c.platformCertificateChange({target:{id:'certificate-pkcs12-file',files:file?[file]:[]}});
 const file=name=>({name,size:100});
 const submit=()=>c.platformCertificateSubmit({preventDefault(){},target:{values:{mode:'pkcs12',password:'private-test-password'}}});
 return {c,readers,requests,errors,reviews,element,select,file,submit};
}

test('a replaced PKCS12 reader cannot publish late bytes or erase the replacement',()=>{
 const f=fixture();f.select(f.file('first.p12'));const old=f.readers[0];f.select(f.file('second.p12'));const latest=f.readers[1];
 old.complete('FIRST');assert.equal(f.c.state.platformP12Base64,'');latest.complete('SECOND');old.onerror();
 assert.equal(f.c.state.platformP12Base64,'SECOND');assert.match(f.element('#certificate-file-status').textContent,/second.p12/);
});
test('file cancellation, oversized replacement and mode changes discard stale uploads',()=>{
 for(const action of ['cancel','oversize','mode']){
  const f=fixture();f.select(f.file('first.p12'));const old=f.readers[0];
  if(action==='cancel')f.select(null);
  else if(action==='oversize')f.select({name:'huge.p12',size:2*1024*1024+1});
  else f.c.platformCertificateChange({target:{id:'platform-certificate-mode',value:'pem'}});
  old.complete('STALE');assert.equal(f.c.state.platformP12Base64,'',action);assert.equal(f.c.state.platformP12Loading,false,action);
 }
});
test('signout and identity changes invalidate pending private reads',()=>{
 for(const action of ['logout','different-user','read-only']){
  const f=fixture();f.select(f.file('private.p12'));const old=f.readers[0];
  if(action==='logout')f.c.clearDashboardIdentity();
  else f.c.applyDashboardIdentity({role:action==='read-only'?'read_only':'super_admin',auth_type:'session',user:{id:'admin-b'},csrf_token:'new-csrf'});
  old.complete('PRIVATE');assert.equal(f.c.state.platformP12Base64,'',action);assert.equal(f.c.state.platformP12Loading,false,action);
 }
});
test('refreshing the same signed-in identity preserves the current upload',()=>{
 const f=fixture();f.select(f.file('current.p12'));
 f.c.applyDashboardIdentity({role:'super_admin',auth_type:'session',user:{id:'admin-a'},csrf_token:'refreshed-csrf'});
 f.readers[0].complete('CURRENT');assert.equal(f.c.state.platformP12Base64,'CURRENT');
});
test('submission waits for file reading and clears private upload state after review',async()=>{
 const f=fixture();f.select(f.file('current.p12'));await f.submit();assert.equal(f.requests.length,0);assert.match(f.errors[0],/finish reading/);
 f.readers[0].complete('CURRENT');await f.submit();assert.equal(f.requests.length,1);
 assert.equal(f.requests[0].options.body.pkcs12_base64,'CURRENT');assert.equal(f.c.state.platformP12Base64,'');assert.equal(f.c.state.platformP12Owner,'');assert.equal(f.reviews.length,1);
});
test('old preview responses cannot clear a newer file or replace its review',async()=>{
 const f=fixture();let resolve;f.c.api=(path,options)=>{f.requests.push({path,options});return new Promise(done=>resolve=done);};
 f.select(f.file('first.p12'));f.readers[0].complete('FIRST');const pending=f.submit();
 f.select(f.file('second.p12'));f.readers[1].complete('SECOND');resolve({id:'old-review'});await pending;
 assert.equal(f.c.state.platformP12Base64,'SECOND');assert.equal(f.reviews.length,0);
});
test('already-read uploads cannot cross identity boundaries even without an auth callback',async()=>{
 const f=fixture();f.select(f.file('private.p12'));f.readers[0].complete('PRIVATE');f.c.state.user={id:'admin-b'};await f.submit();
 assert.equal(f.requests.length,0);assert.equal(f.c.state.platformP12Base64,'');assert.match(f.errors[0],/signing in/);
});
test('read failures and synchronous reader errors clear private pending state',()=>{
 const f=fixture();f.select(f.file('broken.p12'));f.readers[0].onerror();assert.equal(f.c.state.platformP12Base64,'');assert.equal(f.c.state.platformP12Loading,false);
 f.c.FileReader=class{readAsDataURL(){throw new Error('private-detail');}};f.select(f.file('unreadable.p12'));assert.equal(f.c.state.platformP12Loading,false);assert.doesNotMatch(f.element('#certificate-file-status').textContent,/private-detail/);
});
