const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');

const profileID='11111111-1111-4111-8111-111111111111';
const secret='PrivateFleetEnrollmentFixture_'.padEnd(64,'X');
const profile=(overrides={})=>({id:profileID,name:'Billing <fleet>',status:'active',expires_at:new Date(Date.now()+86400000).toISOString(),enrollment_count:20,...overrides});
function enrollmentResponse(overrides={}){
 const p=profile();return {profile:p,kit:{schema_version:3,installation_options:{install_dependencies:true,ufw_action:'preserve'},enrollment_profile_id:p.id,expected_hostname:'',issued_at:new Date().toISOString(),expires_at:p.expires_at,enrollment_token:secret,controller_ca_pem:'PUBLIC CA',config:{enforce:false,allow_firewall_changes:false,learning_auto_allow:false,unexpected_port_monitor_enabled:false},...overrides}};
}
const values=(overrides={})=>({setup_mode:'fleet',architecture:'amd64',name:'Production fleet',validity_hours:'24',controller_url:'https://controller.example.test:8787',control_url:'https://controller.example.test:8788',discovery_url:'https://controller.example.test:8789',interval_seconds:'30',discovery_interval_seconds:'900',...overrides});
function deferred(){let resolve;const promise=new Promise(r=>{resolve=r;});return {promise,resolve};}
function fixture({mode='entra',role='admin',profiles=[],total=profiles.length,request}={}){
 const nodes=new Map(),requests=[],downloads=[],errors=[],toasts=[],listeners={},blobs=new Map();let form;
 const element=selector=>{if(!nodes.has(selector))nodes.set(selector,{value:'',innerHTML:'',textContent:'',disabled:false,files:[],open:false,isConnected:true});return nodes.get(selector);};
 const c={console,Date,JSON,Blob,Number,String,Set,Map,Error,
  state:{role,authType:mode==='demo'?'demo':'session',user:{id:'admin-a',tenant_id:'tenant-a'},csrfToken:'fixture-csrf',token:'',authConfig:{mode,tenant_id:'tenant-a',agent_downloads:{amd64:'0.18.1',arm64:'0.18.1'}},data:{meta:{version:'0.10.0'}}},
  canWrite:()=>['admin','super_admin'].includes(c.state.role),
  $:(selector,scope)=>selector==='button[type="submit"]'&&scope?.button?scope.button:element(selector),
  h:value=>String(value).replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;'),timestamp:value=>value,errorSlot:'<div class="form-error"></div>',
  sessionStorage:{removeItem(){},setItem(){throw new Error('Enrollment material must not enter browser storage');}},
  localStorage:{setItem(){throw new Error('Enrollment material must not enter browser storage');}},
  FormData:class{constructor(value){this.values=value.values;}get(key){return this.values[key]??null;}},
  URL:class extends URL{static createObjectURL(blob){const url='blob:fixture-'+blobs.size;blobs.set(url,blob);return url;}static revokeObjectURL(url){blobs.delete(url);}},
  setTimeout:fn=>{fn();return 1;},
  document:{addEventListener:(name,fn)=>(listeners[name]||=[]).push(fn),createElement:()=>({click(){downloads.push({filename:this.download,blob:blobs.get(this.href)});}})},
  showModal:(title,content)=>{c.agentInstallationModalChanged?.(content);element('#modal').open=true;element('#modal-content').innerHTML=content;form={id:'agent-installation-form',values:values(),button:{disabled:false},isConnected:true};nodes.set('#agent-installation-form',form);},
  formError:error=>errors.push(error.message),toast:value=>toasts.push(value),
  api:async(path,options={})=>{requests.push({path,options});if(request){const result=request(path,options);if(result!==undefined)return result;}if(path.startsWith('/agent-installation/fleet-profiles?'))return {items:structuredClone(profiles),total,limit:20,offset:0};return enrollmentResponse();}
 };
 vm.createContext(c);for(const name of ['agent-installation.js','access-page.js'])vm.runInContext(fs.readFileSync(require.resolve('../'+name),'utf8'),c,{filename:name});
 return {c,element,requests,downloads,errors,toasts,listeners,get form(){return form;},run:source=>vm.runInContext(source,c),show:async()=>{c.showAgentInstallation();await new Promise(setImmediate);},submit:(changes={})=>{form.values=values(changes);return c.agentInstallationSubmit({preventDefault(){},target:form});},flush:()=>new Promise(setImmediate)};
}

test('fleet setup is the default with one architecture-specific agent and no hostname or host-count requirement',async()=>{
 const f=fixture();await f.show();const html=f.element('#modal-content').innerHTML;
 assert.match(html,/value="fleet" selected/);assert.match(html,/any number of servers/);assert.match(html,/No hostname list, CSV or per-server download/);assert.match(html,/same binary is used on RHEL and Ubuntu/);assert.doesNotMatch(html,/id="agent-install-hostname"|name="(?:max_hosts|server_count|hostnames)"/);
 assert.match(html,/\/api\/v1\/agent-installation\/releases\/amd64\/archive/);assert.match(f.c.agentInstallationArchive('arm64'),/0\.18\.1-linux-arm64/);
 f.c.state.data.meta.version='<script>wrong</script>';assert.equal(f.c.agentInstallationArchive('amd64'),'prthak-agent-0.18.1-linux-amd64.tar.gz');
 assert.match(html,/enrollment key grants no dashboard or firewall-policy authority/);
});
test('automatic OS detection keeps one installer command while CPU selection changes only the archive',async()=>{
 const f=fixture();await f.show();const command='sudo ./scripts/install-agent-auto.sh --setup-file /root/prthak-agent-setup.json';
 for(const family of ['auto','rhel','ubuntu'])assert.equal(f.c.agentInstallationCommand(family),command);
 assert.doesNotMatch(f.element('#modal-content').innerHTML,/<select[^>]*name="family"/);
 for(const architecture of ['amd64','arm64']){
  f.element('#agent-install-architecture').value=architecture;f.c.agentInstallationChange({target:{id:'agent-install-architecture',value:architecture}});
  assert.equal(f.element('#agent-install-command').textContent,command);assert.equal(f.element('#agent-install-archive').textContent,'prthak-agent-0.18.1-linux-'+architecture+'.tar.gz');
  await f.submit({architecture});const request=f.requests.filter(row=>row.options.method==='POST').at(-1);assert.equal(request.options.body.family,'auto');assert.equal(request.options.body.architecture,architecture);assert.equal(f.errors.length,0);
 }
});
test('one fleet request downloads only the reusable kit and never renders or persists its enrollment secret',async()=>{
 const f=fixture();await f.show();await f.submit();const create=f.requests.find(r=>r.options.method==='POST');
 assert.equal(create.path,'/agent-installation/fleet-profiles');assert.equal(create.options.cache,'no-store');const body=JSON.parse(JSON.stringify(create.options.body));
 assert.equal(body.validity_hours,24);assert.equal(body.name,'Production fleet');assert.equal(body.expected_hostname,undefined);assert.equal(body.setup_mode,undefined);assert.equal(body.control_url,'https://controller.example.test:8788');
 assert.equal(f.downloads.length,1);assert.equal(f.downloads[0].filename,'prthak-agent-setup.json');const kit=JSON.parse(await f.downloads[0].blob.text());assert.equal(kit.schema_version,3);assert.equal(kit.enrollment_profile_id,profileID);assert.equal(kit.enrollment_token,secret);assert.equal(kit.expected_hostname,'');assert.equal(kit.private_key,undefined);
 assert.match(f.element('#agent-installation-result').innerHTML,/Reuse this file on any number/);assert.doesNotMatch(f.element('#modal-content').innerHTML+f.element('#agent-installation-result').innerHTML,new RegExp(secret));assert.equal(JSON.stringify(f.c.state).includes(secret),false);assert.equal(f.errors.length,0);
});
test('optional management pins are saved through GUI setup without granting policy authority',async()=>{
 const f=fixture({request:(path,options)=>options.method==='POST'?enrollmentResponse({config:{...enrollmentResponse().kit.config,management_sources:options.body.management_sources||[]}}):undefined});
 await f.show();const html=f.element('#modal-content').innerHTML;assert.match(html,/id="agent-install-management-sources"/);assert.match(html,/local safety pins, not access-policy grants/);assert.match(html,/management probe in Settings/);
 await f.submit({management_sources:'10.90.0.10, 2001:db8:90::10/128\n10.91.0.0/24'});
 const request=f.requests.find(row=>row.options.method==='POST');assert.deepEqual(JSON.parse(JSON.stringify(request.options.body.management_sources)),['10.90.0.10/32','10.91.0.0/24','2001:db8:90::10/128']);assert.equal(f.downloads.length,1);
 const kit=JSON.parse(await f.downloads[0].blob.text());assert.deepEqual(kit.config.management_sources,['10.90.0.10/32','10.91.0.0/24','2001:db8:90::10/128']);assert.equal(kit.config.enforce,false);assert.equal(kit.config.allow_firewall_changes,false);
});
test('unsafe pins or controller substitution cannot silently widen local management trust',async()=>{
 for(const management_sources of ['0.0.0.0/0','::/0','fe80::1%eth0/128','::ffff:192.0.2.1/128',Array(101).fill('10.1.0.1/32').join(',')]){
  const f=fixture();await f.show();await f.submit({management_sources});assert.equal(f.requests.some(row=>row.options.method==='POST'),false);assert.equal(f.downloads.length,0);
 }
 for(const row of [{requested:'',returned:['10.90.0.0/24']},{requested:'10.90.0.10/32',returned:[]},{requested:'10.90.0.10/32',returned:['0.0.0.0/0']}]){
  const f=fixture({request:(path,options)=>options.method==='POST'?enrollmentResponse({config:{...enrollmentResponse().kit.config,management_sources:row.returned}}):undefined});await f.show();await f.submit({management_sources:row.requested});assert.equal(f.downloads.length,0);assert.equal(f.errors.length,1);
 }
});
test('changing management pins fences an enrollment download pending in another trust scope',async()=>{
 const pending=deferred(),f=fixture({request:(path,options)=>options.method==='POST'?pending.promise:undefined});await f.show();const operation=f.submit({management_sources:'10.90.0.10/32'});f.listeners.input[0]({target:{id:'agent-install-management-sources',value:'10.91.0.10/32'}});pending.resolve(enrollmentResponse({config:{...enrollmentResponse().kit.config,management_sources:['10.90.0.10/32']}}));await operation;assert.equal(f.downloads.length,0);
});
test('dependencies are automatic while optional UFW assessment starts unchecked and cannot authorize migration',async()=>{
 const f=fixture();await f.show();const html=f.element('#modal-content').innerHTML;
 for(const id of ['agent-install-ufw-assess']){const input=html.match(new RegExp('<input[^>]*id="'+id+'"[^>]*>'))?.[0];assert.ok(input);assert.doesNotMatch(input,/\schecked(?:\s|>|=)/);}
 assert.doesNotMatch(html,/id="agent-install-dependencies"|id="agent-install-family"/);assert.match(html,/Automatic OS dependency installation/);assert.match(html,/UFW stays active/);assert.match(html,/private UFW configuration\/status export/);assert.match(html,/does not activate firewalld or apply a migration/);
 assert.match(html,/Full inventory fallback/);assert.match(html,/check listeners every 5 seconds/);
 await f.submit();const body=f.requests.find(row=>row.options.method==='POST').options.body;assert.equal(body.family,'auto');assert.deepEqual(JSON.parse(JSON.stringify(body.installation_options)),{install_dependencies:true,ufw_action:'preserve'});
});
test('automatic dependencies and optional UFW assessment are recorded in every schema-three reusable download',async()=>{
 for(const choices of [{}, {assess_ufw:'on'}, {install_dependencies:'off',assess_ufw:'on'}]){
  const f=fixture({request:(path,options)=>options.method==='POST'?enrollmentResponse({schema_version:3,installation_options:options.body.installation_options}):undefined});await f.show();await f.submit(choices);
  const options=f.requests.find(row=>row.options.method==='POST').options.body.installation_options;
  assert.deepEqual(JSON.parse(JSON.stringify(options)),{install_dependencies:true,ufw_action:choices.assess_ufw==='on'?'assess':'preserve'});
  assert.equal(f.downloads.length,1);const kit=JSON.parse(await f.downloads[0].blob.text());assert.equal(kit.schema_version,3);assert.deepEqual(kit.installation_options,JSON.parse(JSON.stringify(options)));assert.equal(kit.enrollment_profile_id,profileID);assert.equal(kit.config.enforce,false);assert.equal(kit.config.allow_firewall_changes,false);assert.equal(f.errors.length,0);
 }
});
test('unselected, changed, extra or unsupported preparation never downloads a setup file',async()=>{
 const bad=[{requested:{},returned:{schema_version:2,installation_options:{install_dependencies:true,ufw_action:'preserve'}}},
  {requested:{install_dependencies:'on'},returned:{schema_version:2}},
  {requested:{install_dependencies:'on'},returned:{schema_version:3,installation_options:{install_dependencies:false,ufw_action:'assess'}}},
  {requested:{assess_ufw:'on'},returned:{schema_version:3,installation_options:{install_dependencies:false,ufw_action:'migrate'}}},
  {requested:{assess_ufw:'on'},returned:{schema_version:3,installation_options:{install_dependencies:false,ufw_action:'assess',command:'ufw disable'}}}];
 for(const row of bad){const f=fixture({request:(path,options)=>options.method==='POST'?enrollmentResponse(row.returned):undefined});await f.show();await f.submit(row.requested);assert.equal(f.downloads.length,0);assert.equal(f.errors.length,1);}
 for(const invalid of [{assess_ufw:'false'},{assess_ufw:'true'}]){const f=fixture();await f.show();await f.submit(invalid);assert.equal(f.requests.some(row=>row.options.method==='POST'),false);assert.equal(f.downloads.length,0);}
});
test('individual preparation preserves its hostname and never accepts a fleet identity',async()=>{
 const response=options=>{const kit={...enrollmentResponse().kit,schema_version:3,expected_hostname:'billing-01',installation_options:options};delete kit.enrollment_profile_id;return kit;};
 const f=fixture({request:(path,options)=>options.method==='POST'?response(options.body.installation_options):undefined});await f.show();await f.submit({setup_mode:'individual',expected_hostname:'billing-01',install_dependencies:'on'});assert.equal(f.downloads.length,1);const kit=JSON.parse(await f.downloads[0].blob.text());assert.equal(kit.expected_hostname,'billing-01');assert.equal(kit.enrollment_profile_id,undefined);assert.equal(kit.schema_version,3);
 const mismatch=fixture({request:(path,options)=>options.method==='POST'?{...response(options.body.installation_options),enrollment_profile_id:profileID}:undefined});await mismatch.show();await mismatch.submit({setup_mode:'individual',expected_hostname:'billing-01',install_dependencies:'on'});assert.equal(mismatch.downloads.length,0);assert.equal(mismatch.errors.length,1);
});
test('changing optional UFW assessment fences a pending download before blur',async()=>{
 const pending=deferred(),f=fixture({request:(path,options)=>options.method==='POST'?pending.promise:undefined});await f.show();const submission=f.submit();f.listeners.input[0]({target:{id:'agent-install-ufw-assess',checked:true}});pending.resolve(enrollmentResponse());await submission;assert.equal(f.downloads.length,0);assert.equal(f.form.button.disabled,false);
});
test('optional individual setup preserves its one-use endpoint request and installer command',async()=>{
 const f=fixture({request:(path)=>{if(path!=='/agent-installation/kit')return;const kit={...enrollmentResponse().kit,schema_version:3,expected_hostname:'billing-01'};delete kit.enrollment_profile_id;return kit;}});await f.show();
 f.c.agentInstallationChange({target:{id:'agent-install-mode',value:'individual'}});assert.match(f.element('#agent-install-scope-fields').innerHTML,/Expected hostname/);
 await f.submit({setup_mode:'individual',expected_hostname:'billing-01'});const body=f.requests.find(r=>r.path==='/agent-installation/kit').options.body;assert.equal(body.expected_hostname,'billing-01');assert.equal(body.name,undefined);assert.equal(body.validity_hours,undefined);assert.equal(f.downloads.length,1);assert.match(f.element('#agent-installation-result').innerHTML,/Use it for one endpoint/);
 assert.equal(f.c.agentInstallationCommand('ubuntu'),'sudo ./scripts/install-agent-auto.sh --setup-file /root/prthak-agent-setup.json');
});
test('fleet profile listings project public fields, escape names, paginate, and revoke only enrollment',async()=>{
 const p=profile({name:'Production <script>',enrollment_token:secret});const f=fixture({profiles:[p],total:21,request:(path,options)=>{
  if(path.endsWith('/revoke'))return profile({status:'revoked'});
  if(path.endsWith('offset=20'))return {items:[profile({name:'Last profile'})],total:21,limit:20,offset:20};
 }});await f.show();let html=f.element('#agent-fleet-profiles').innerHTML;assert.match(html,/Production &lt;script&gt;/);assert.doesNotMatch(html,/<script>|PrivateFleetEnrollment/);assert.equal(f.run('JSON.stringify(agentFleetProfiles).includes("'+secret+'")'),false);
 await f.c.loadAgentFleetProfiles(20);assert.match(f.element('#agent-fleet-profiles').innerHTML,/21–21 of 21/);assert.ok(f.requests.some(r=>r.path.endsWith('limit=20&offset=20')));
 await f.c.agentFleetAction({disabled:false,dataset:{action:'agent-fleet-revoke',id:profileID}});assert.match(f.element('#agent-fleet-profiles').innerHTML,/revoked/);assert.doesNotMatch(f.element('#agent-fleet-profiles').innerHTML,/data-action="agent-fleet-revoke"/);assert.match(f.toasts.at(-1),/Existing enrolled servers remain connected/);const mutation=f.requests.filter(r=>r.options.method==='POST');assert.equal(mutation.length,1);assert.equal(mutation[0].path,'/agent-installation/fleet-profiles/'+profileID+'/revoke');assert.deepEqual(JSON.parse(JSON.stringify(mutation[0].options.body)),{});
});
test('demo and Read Only cannot create, list or revoke real enrollment credentials',async()=>{
 for(const opts of [{mode:'demo',role:'super_admin'},{mode:'entra',role:'read_only'}]){
  const f=fixture(opts);await f.show();await f.submit();await f.c.agentFleetAction({disabled:false,dataset:{action:'agent-fleet-revoke',id:profileID}});assert.equal(f.requests.length,0);assert.equal(f.downloads.length,0);assert.match(f.element('#modal-content').innerHTML,/type="submit"[^>]*disabled/);
 }
});
test('invalid fleet names, durations, origins and malformed response scopes never download a kit',async()=>{
 const f=fixture();await f.show();for(const invalid of [{name:''},{name:'bad\nname'},{validity_hours:'0'},{validity_hours:'721'},{validity_hours:'1e2'},{controller_url:'http://controller.example.test'},{setup_mode:'other'}])await f.submit(invalid);assert.equal(f.requests.filter(r=>r.options.method==='POST').length,0);
 for(const bad of [{enrollment_profile_id:'22222222-2222-4222-8222-222222222222'},{expected_hostname:'bound-to-one-host'},{expires_at:'2000-01-01T00:00:00Z'},{config:{...enrollmentResponse().kit.config,allow_host_default_deny:true}}]){
  const item=fixture({request:(path,options)=>options.method==='POST'?enrollmentResponse(bad):undefined});await item.show();await item.submit();assert.equal(item.downloads.length,0);assert.equal(item.errors.length,1);
 }
});
test('pending CA reads cannot submit after signout, role loss, file replacement or a changed form',async()=>{
 for(const action of ['signout','read-only','file','mode','field','close']){
  const pending=deferred(),f=fixture();await f.show();const ca={size:100,text:()=>pending.promise};f.element('#agent-install-ca').files=[ca];const submission=f.submit();
  if(action==='signout')f.c.clearDashboardIdentity();
  else if(action==='read-only')f.c.applyDashboardIdentity({role:'read_only',auth_type:'session',user:{id:'admin-a',tenant_id:'tenant-a'},csrf_token:'new'});
  else if(action==='file'){f.element('#agent-install-ca').files=[{size:100,text:async()=>''}];f.c.agentInstallationChange({target:{id:'agent-install-ca'}});}
  else if(action==='mode')f.c.agentInstallationChange({target:{id:'agent-install-mode',value:'individual'}});
  else if(action==='field')f.c.agentInstallationChange({target:{id:'agent-install-controller'}});
  else{f.c.agentInstallationModalChanged('<div>Another modal</div>');f.element('#modal').open=false;}
  pending.resolve('-----BEGIN CERTIFICATE-----\nPUBLIC\n-----END CERTIFICATE-----');await submission;assert.equal(f.requests.filter(r=>r.options.method==='POST').length,0,action);assert.equal(f.downloads.length,0,action);
 }
});
test('late enrollment responses cannot cross identity changes, close/reopen or mode changes',async()=>{
 for(const action of ['user','signout','reopen','mode']){
  const pending=deferred(),f=fixture({request:(path,options)=>options.method==='POST'?pending.promise:undefined});await f.show();const submission=f.submit();assert.equal(f.requests.filter(r=>r.options.method==='POST').length,1);
  if(action==='user')f.c.applyDashboardIdentity({role:'admin',auth_type:'session',user:{id:'admin-b',tenant_id:'tenant-a'},csrf_token:'new'});
  else if(action==='signout')f.c.clearDashboardIdentity();
  else if(action==='reopen')await f.show();
  else f.c.agentInstallationChange({target:{id:'agent-install-mode',value:'individual'}});
  pending.resolve(enrollmentResponse());await submission;assert.equal(f.downloads.length,0,action);assert.equal(f.element('#agent-installation-result').innerHTML.includes(secret),false,action);
 }
});
test('same-identity CSRF refresh preserves a pending legitimate fleet download',async()=>{
 const pending=deferred(),f=fixture({request:(path,options)=>options.method==='POST'?pending.promise:undefined});await f.show();const submission=f.submit();f.c.applyDashboardIdentity({role:'admin',auth_type:'session',user:{id:'admin-a',tenant_id:'tenant-a'},csrf_token:'refreshed'});pending.resolve(enrollmentResponse());await submission;assert.equal(f.downloads.length,1);assert.equal(f.errors.length,0);
});
test('typing a changed setup draft immediately fences its pending download before blur',async()=>{
 const pending=deferred(),f=fixture({request:(path,options)=>options.method==='POST'?pending.promise:undefined});await f.show();const submission=f.submit();f.listeners.input[0]({target:{id:'agent-install-controller',value:'https://replacement.example.test'}});pending.resolve(enrollmentResponse());await submission;assert.equal(f.downloads.length,0);assert.equal(f.form.button.disabled,false);
});
test('a stale profile-page response cannot replace the current page or show data after signout',async()=>{
 const first=deferred(),second=deferred();const f=fixture({request:(path)=>path.endsWith('offset=0')?first.promise:path.endsWith('offset=20')?second.promise:undefined});f.c.showAgentInstallation();const latest=f.c.loadAgentFleetProfiles(20);second.resolve({items:[profile({name:'Latest page'})],total:21,limit:20,offset:20});await latest;first.resolve({items:[profile({name:'Stale page'})],total:21,limit:20,offset:0});await f.flush();assert.match(f.element('#agent-fleet-profiles').innerHTML,/Latest page/);assert.doesNotMatch(f.element('#agent-fleet-profiles').innerHTML,/Stale page/);
 const late=deferred(),other=fixture({request:()=>late.promise});other.c.showAgentInstallation();other.c.clearDashboardIdentity();late.resolve({items:[profile({name:'Other identity'})],total:1});await other.flush();assert.doesNotMatch(other.element('#agent-fleet-profiles').innerHTML,/Other identity/);
});
test('a profile listing read before revocation cannot paint the revoked key as active again',async()=>{
 const pending=deferred();let reads=0;const f=fixture({profiles:[profile()],request:(path)=>{
  if(path.endsWith('/revoke'))return profile({status:'revoked'});
  if(path.includes('fleet-profiles?')&&++reads===2)return pending.promise;
 }});await f.show();const refresh=f.c.loadAgentFleetProfiles();await f.c.agentFleetAction({disabled:false,dataset:{action:'agent-fleet-revoke',id:profileID}});pending.resolve({items:[profile()],total:1,limit:20,offset:0});await refresh;assert.match(f.element('#agent-fleet-profiles').innerHTML,/revoked/);assert.doesNotMatch(f.element('#agent-fleet-profiles').innerHTML,/data-action="agent-fleet-revoke"/);
});
