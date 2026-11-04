const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const location={id:'loc-1',key:'location:loc-1',name:'Mumbai primary',location:'Mumbai facility A',type:'datacenter',aliases:['Mumbai']};
const host={id:'host-1',hostname:'lab-api',ips:['10.1.0.2'],os:'rhel',os_version:'9',status:'healthy',tags:{application:'billing',owner:'finance',dc:'Legacy only'},location_id:location.id,location,listeners:[{port:2022,protocol:'tcp',process:'sshd'},{port:8443,protocol:'tcp',process:'billing-api'}],desired_version:2,applied_version:0,apply_status:'preview',last_seen:new Date().toISOString(),collector_status:'off',capabilities:['learning_discovery_v1','traffic_capture_v1']};
const policy={id:'policy-1',revision:1,name:'Billing policy',mode:'enforce',selector:{application:'billing',location_id:location.id},group_ids:[],services:[{port:8443,protocol:'tcp',sources:['10.1.0.1/32'],source_selector:{}}]};
const serviceGroup={id:'web-ports',name:'Web application',description:'Reusable application ports',revision:2,ports:[{port:443,protocol:'tcp'},{port:8443,protocol:'tcp'}],policy_ids:['policy-1'],policy_count:1};
const fixture={learning_policies:[],service_groups:[serviceGroup],servers:[host],locations:[location],policies:[policy],groups:[],flows:[],alerts:[],learning_sessions:[],meta:{demo:true,version:'0.1.0',traffic_retention_hours:24}};
async function workspace(view='overview',options={}) {
 const elements=new Map(),listeners={},windowListeners={},requests=[],navigation=[],routeHistory=[],storageChanges=[],storage=new Map(Object.entries(options.storage || {})),displayStorage=new Map(Object.entries(options.localStorage || {})),displayStorageChanges=[];
 const mode=options.mode || 'demo',role=options.role || 'super_admin';
 const identity=options.identity || {role,demo:mode==='demo',auth_type:mode==='demo'?'demo':mode==='tokens'?'token':'session',csrf_token:mode==='entra'?'session-csrf-fixture':'',user:{id:mode==='demo'?'demo':'super-self',display_name:mode==='demo'?'Demo administrator':'Priya Operator',email:'priya@example.test',role}};
 const authStatus=options.authStatus;
 const config={mode,configured:mode==='entra',login_url:mode==='entra'?'/api/v1/auth/login':null,...options.config};
 function element(selector){if(!elements.has(selector))elements.set(selector,{id:selector.startsWith('#')?selector.slice(1):'',attributes:{},innerHTML:'',textContent:'',hidden:false,open:false,disabled:false,value:'',dataset:{},style:{},classList:{values:new Set(),add(...names){names.forEach(name=>this.values.add(name));},remove(...names){names.forEach(name=>this.values.delete(name));},toggle(name,force){const enabled=force===undefined?!this.values.has(name):force;if(enabled)this.values.add(name);else this.values.delete(name);return enabled;},contains(name){return this.values.has(name);}},querySelector:element,querySelectorAll:()=>[],eventListeners:{},addEventListener(type,handler){(this.eventListeners[type] ||= []).push(handler);},removeEventListener(){},setAttribute(name,value){this.attributes[name]=String(value);},getAttribute(name){return this.attributes[name] ?? null;},append(){},remove(){},replaceChildren(){this.innerHTML='';},focus(){document.activeElement=this;},matches:()=>false,showModal(){this.open=true;},close(){this.open=false;},setSelectionRange(){},click(){}});return elements.get(selector);}
 element('#workspace-shell').hidden=true;
 element('#sign-in-page').hidden=true;
 const document={body:element('body'),createElement:tag=>element('created:'+tag),querySelector:element,querySelectorAll:()=>[],getElementById:id=>element('#'+id),activeElement:null,hidden:false,addEventListener:(type,handler)=>{(listeners[type] ||= []).push(handler)}};
 function setRoute(url) {
  const next = new URL(url, 'https://controller.test');
  Object.assign(context.location, {pathname: next.pathname, search: next.search, hash: next.hash});
 }
 const context={console,Date,Map,Set,JSON,Array,String,Number,Error,URL,URLSearchParams,Intl,AbortController,TextEncoder,Blob,document,location:{origin:'https://controller.test',pathname:'/'+view,hash:'',search:'',assign:url=>navigation.push(url),replace:url=>navigation.push(url)},history:{replaceState(_state,_title,url){setRoute(url);},pushState(_state,_title,url){routeHistory.push(url);setRoute(url);}},window:{scrollTo(){},addEventListener(type,handler){(windowListeners[type] ||= []).push(handler);},localStorage:{getItem:key=>displayStorage.get(key) ?? null,setItem(key,value){displayStorage.set(key,String(value));displayStorageChanges.push({key,value:String(value)});}}},sessionStorage:{getItem:key=>storage.get(key) ?? null,setItem(key,value){storage.set(key,String(value));storageChanges.push({operation:'set',key,value:String(value)});},removeItem(key){storage.delete(key);storageChanges.push({operation:'remove',key});}},setInterval:()=>1,setTimeout:()=>1,clearTimeout(){},fetch:async(url,options={})=>{
  requests.push({url,options});let data={};
  const override=context.apiResponses?.[(options.method || 'GET')+' '+url] ?? context.apiResponses?.[url];
  if(override!==undefined)data=typeof override==='function'?await override(options):structuredClone(override);
  else if(url==='/api/v1/auth/config')data=structuredClone(config);
  else if(url==='/api/v1/auth')data=authStatus?{responseStatus:authStatus,data:{error:'Sign in required'}}:structuredClone(identity);
  else if(url.startsWith('/api/v1/overview')){data=structuredClone(fixture);data.meta.demo=mode==='demo';}
  else if(url.startsWith('/api/v1/cluster'))data={mode:'standalone',nodes:[]};
  else if(url==='/api/v1/firewall')data={servers:[],common_rules:[],changes:[]};
  else if(url==='/api/v1/enrollment-tokens')data={token:'synthetic-unit-test-token',expires_at:new Date(Date.now()+60000).toISOString()};
  else if(url==='/api/v1/policies/policy-1')data=structuredClone(policy);
  else if(url==='/api/v1/learning-policies/learned-1')data=structuredClone(learnedPolicy);
  else if(url.startsWith('/api/v1/servers/'))data={server:structuredClone(host)};
  else data={items:[]};
  const status=data.responseStatus || 200;return {ok:status>=200&&status<300,status,headers:new Headers(data.headers),json:async()=>data.responseStatus?data.data:data,blob:async()=>new Blob([data.csvText || 'server_id,source_ip,port,protocol\r\nhost-1,192.0.2.44,8443,tcp\r\n'],{type:'text/csv'})};
 }};
 context.apiResponses=options.responses || {};
 context.FormData=class{constructor(form){this.values=form.values || {};}get(key){return this.values[key] ?? null;}getAll(key){const value=this.values[key];return Array.isArray(value)?value:value==null?[]:[value];}};
 vm.createContext(context);
 for(const file of ['locations.js','filters.js','country-outlines.js','topology.js','routing.js','services.js','firewall.js','firewall-page.js','managed.js','managed-page.js','default-deny-page.js','locations-page.js','metadata-page.js','access-page.js','server-lifecycle-page.js','service-groups-page.js','learning-page.js','hit-monitoring-page.js','recommendations.js','approvals-page.js','recommendations-page.js','platform.js','settings-setup-page.js','settings-page.js','settings-ha-page.js','settings-appliance-page.js','settings-certificates-page.js','settings-agents-page.js','settings-notifications-page.js','settings-siem-page.js','settings-signing-page.js','firewall-counters-page.js','firewall-activation-page.js','network-control-page.js','settings-endpoint-certificates-page.js','settings-recovery-page.js','settings-application-port-page.js','settings-updates-page.js','settings-agent-upgrades-page.js','policy-catalogue-page.js','alerts-catalogue-page.js','account-menu.js','risk-page.js','agent-installation.js','traffic-catalogue-page.js','audit-catalogue-page.js','source-banks-page.js','policy-deployments-page.js','app.js'])vm.runInContext(fs.readFileSync(path.join(__dirname,'..',file),'utf8'),context,{filename:file});
 await new Promise(setImmediate);
 const run=script=>vm.runInContext(script,context);
 async function click(action,dataset={}){context.testButton={disabled:false,dataset:{action,...dataset}};return run('handleAction({target:{closest:()=>testButton}})');}
 async function submit(formId,values={}){const match=(element('#modal-content').innerHTML+element('#sign-in-content').innerHTML).match(new RegExp('<form[^>]*id=\"'+formId+'\"[^>]*>'));assert.ok(match,formId+' must be a rendered production form');const dataset={};for(const attr of match[0].matchAll(/data-([a-z-]+)=\"([^\"]*)\"/g))dataset[attr[1].replace(/-([a-z])/g,(_,letter)=>letter.toUpperCase())]=attr[2];return listeners.submit.at(-1)({preventDefault(){},target:{id:formId,dataset,values,querySelector:element}});}
 function popRoute(url) {
  setRoute(url);
  for (const handler of windowListeners.popstate || []) handler();
 }
 return {context,elements,listeners,requests,element,run,click,submit,navigation,routeHistory,popRoute,storage,storageChanges,displayStorage,displayStorageChanges};
}
function accountTestItems(env){const panel=env.element('#account-menu-panel');panel.querySelectorAll=()=>[...panel.innerHTML.matchAll(/<button role="menuitem"[^>]*data-action="([^"]+)"/g)].map(match=>{const item=env.element('account-item:'+match[1]);item.dataset.action=match[1];item.closest=selector=>selector==='#account-menu-panel'?panel:selector==='#account-menu'?env.element('#account-menu'):null;return item;});const trigger=env.element('#account-menu-toggle');trigger.closest=selector=>selector==='#account-menu-toggle'?trigger:selector==='#account-menu'?env.element('#account-menu'):null;return {panel,trigger};}
function accountKey(env,key,target){let prevented=false,stopped=false;env.listeners.keydown.find(handler=>handler.name==='accountMenuKeydown')({key,target,preventDefault(){prevented=true;},stopImmediatePropagation(){stopped=true;}});return {prevented,stopped};}
function clickWorkspaceLink(env, path, {target = '', download = false, ...options} = {}) {
 const link = {href: new URL(path, env.context.location.origin).href, target, hasAttribute: name => name === 'download' && download};
 let prevented = false;
 env.listeners.click.find(handler => handler.name === 'handleWorkspaceLink')({
  button: 0, ...options, target: {closest: () => link}, preventDefault() { prevented = true; }
 });
 return prevented;
}
test('workspace links switch views without another sign-in check and restore Back and Forward', async () => {
 const env = await workspace('overview', {mode: 'entra', role: 'admin'});
 const startupRequests = env.requests.filter(({url}) => /\/api\/v1\/(auth|overview)/.test(url)).length;
 env.run('state.search = "billing"; state.detail = "host-1"');
 for (const [path, title, label] of [
  ['/locations', 'Location catalogue', ''],
  ['/policies', 'Access policies', 'Discover policy'],
  ['/traffic', 'Traffic', 'Discover traffic'],
  ['/servers', 'Server inventory', '']
 ]) {
  assert.equal(clickWorkspaceLink(env, path), true);
  assert.equal(env.context.location.pathname, path);
  assert.equal(env.element('#page-title').textContent, title);
  assert.equal(env.element('#workspace-shell').hidden, false);
  assert.equal(env.element('#learn-button').hidden, !label);
  assert.ok(env.element('#learn-button').innerHTML.endsWith(label));
 }
 await new Promise(setImmediate);
 assert.equal(env.run('state.search'), 'billing');
 assert.equal(env.run('state.detail'), null);
 assert.ok(env.requests.some(({url}) => url === '/api/v1/metadata/subnets'));
 assert.deepEqual(env.routeHistory, ['/locations', '/policies', '/traffic', '/servers']);
 env.popRoute('/traffic');
 assert.equal(env.element('#page-title').textContent, 'Traffic');
 env.popRoute('/servers');
 assert.equal(env.element('#page-title').textContent, 'Server inventory');
 assert.equal(env.context.document.activeElement, env.element('#main'));
 assert.equal(env.requests.filter(({url}) => /\/api\/v1\/(auth|overview)/.test(url)).length, startupRequests);
 assert.deepEqual(env.navigation, []);
 assert.equal(env.routeHistory.length, 4);
});
test('workspace routing preserves modified links and keeps signed-out history private', async () => {
 const env = await workspace('servers', {mode: 'entra', role: 'admin'});
 for (const [path, options] of [
  ['/overview', {metaKey: true}], ['/overview', {ctrlKey: true}], ['/overview', {button: 1}],
  ['/overview', {target: '_blank'}], ['/overview', {download: true}],
  ['/api/v1/auth/login', {}], ['https://other.test/overview', {}], ['#main', {}]
 ]) assert.equal(clickWorkspaceLink(env, path, options), false);
 await env.run('dashboardLogout()');
 env.popRoute('/locations');
 assert.equal(env.context.location.pathname, '/login');
 assert.equal(env.context.location.search, '?next=locations');
 assert.equal(env.element('#workspace-shell').hidden, true);
 assert.deepEqual(env.routeHistory, []);
});
test('Super Admin can save the selected controller display name and the sidebar updates', async () => {
 const runtime = {controller_id: 'node-1', controller_display_name: 'Original'};
 const env = await workspace('settings', {mode: 'entra', role: 'super_admin', responses: {
  '/api/v1/overview': {...fixture, meta: {...fixture.meta, ...runtime}},
  '/api/v1/platform/status': {runtime},
  'PUT /api/v1/platform/controller-name': {controller_id: 'node-1', display_name: 'Primary DC'}
 }});
 assert.equal(env.element('#controller-display-name').textContent, 'Original');
 assert.doesNotMatch(env.element('#view-content').innerHTML, /Edit display name/);
 await env.click('platform-tab', {tab:'setup'});
 assert.match(env.element('#view-content').innerHTML, /Edit display name/);
 await env.click('platform-appliance-controller-name');
 assert.match(env.element('#modal-content').innerHTML, /value="Original"/);
 await env.submit('platform-controller-name-form', {display_name: 'Primary DC'});
 const request = mutations(env)[0];
 assert.equal(request.url, '/api/v1/platform/controller-name');
 assert.deepEqual(JSON.parse(request.options.body), {controller_id: 'node-1', display_name: 'Primary DC'});
 assertCookieMutation(request);
 assert.equal(env.element('#controller-display-name').textContent, 'Primary DC');
 const admin = await workspace('settings', {mode: 'entra', role: 'admin', responses: {'/api/v1/platform/status': {runtime}}});
 assert.doesNotMatch(admin.element('#view-content').innerHTML, /Edit display name/);
});
test('account shell moves real identity to the top right and keeps controller and agent setup in the sidebar',async()=>{
 const shell=fs.readFileSync(path.join(__dirname,'..','index.html'),'utf8');assert.doesNotMatch(shell,/sidebar-profile|id="logout-button"|>OP<\/span>/);assert.match(shell,/id="account-menu-toggle"[^>]*aria-haspopup="menu"/);assert.match(shell,/id="account-menu-panel"[^>]*role="menu"/);assert.match(shell,/id="connection-label"/);assert.match(shell,/id="setup-button"/);assert.match(shell,/airtel-payments-bank\.png/);
 const env=await workspace('servers',{mode:'entra',role:'admin',identity:{role:'admin',auth_type:'session',csrf_token:'session-csrf-fixture',user:{id:'own-user',display_name:'Maya <Owner>',email:'maya@example.test',role:'admin',tenant_id:'tenant-one',object_id:'object-one'}}});assert.equal(env.element('#identity-avatar').textContent,'MO');assert.equal(env.element('#identity-name').textContent,'Maya <Owner>');assert.equal(env.element('#role-label').textContent,'Admin');await env.click('account-toggle');assert.equal(env.element('#account-menu-toggle').getAttribute('aria-expanded'),'true');assert.match(env.element('#account-menu-panel').innerHTML,/Maya &lt;Owner&gt;/);assert.doesNotMatch(env.element('#account-menu-panel').innerHTML,/<Owner>/);await env.click('account-profile');const html=env.element('#modal-content').innerHTML;assert.match(html,/Entra-managed identity is read-only/);assert.match(html,/Microsoft Entra ID/);assert.match(html,/maya@example\.test/);assert.match(html,/tenant-one/);assert.doesNotMatch(html,/<form|name="role"|name="display_name"/);assert.equal(mutations(env).length,0);
});
test('sidebar shows standalone controller connection and only fetches HA health when active outside Overview', async () => {
 const shell=fs.readFileSync(path.join(__dirname,'..','index.html'),'utf8');
 assert.doesNotMatch(shell,/controller-badge/);
 assert.match(shell,/<aside[\s\S]*id="setup-button"[\s\S]*id="sidebar-controller-health"[\s\S]*id="controller-display-name"[\s\S]*id="sidebar-ha-health"[^>]*hidden[\s\S]*<\/aside>/);
 const env=await workspace('servers');
 assert.equal(env.element('#sidebar-controller-health').dataset.state,'healthy');
 assert.equal(env.element('#sidebar-controller-health').title,'Controller connected');
 assert.equal(env.element('#sidebar-ha-health').hidden,true);
 assert.equal(env.requests.some(({url})=>url==='/api/v1/cluster'),false);
 env.context.apiResponses['/api/v1/overview']={responseStatus:503,data:{error:'Temporarily unavailable'}};
 await env.run('load()');
 assert.equal(env.element('#sidebar-controller-health').dataset.state,'offline');
 assert.equal(env.element('#sidebar-controller-health').title,'Controller unavailable');
 delete env.context.apiResponses['/api/v1/overview'];
 await env.run('load()');
 assert.equal(env.element('#sidebar-controller-health').dataset.state,'healthy');
});
test('active HA sidebar reports controller readiness from direct entry and degrades without ready peers', async () => {
 const overview={...fixture,meta:{...fixture.meta,ha:true,controller_display_name:'Primary DC'}};
 const primary={id:'primary',status:'healthy',ready:true};
 const cluster={ha:true,mode:'active-active',controller_id:'primary',nodes:[primary,{id:'secondary',status:'healthy',ready:true}]};
 const env=await workspace('traffic',{responses:{'/api/v1/overview':overview,'/api/v1/cluster':cluster}});
 const ha=env.element('#sidebar-ha-health'),controller=env.element('#sidebar-controller-health');
 assert.equal(controller.title,'Primary DC connected');
 assert.equal(ha.hidden,false);
 assert.equal(ha.dataset.state,'healthy');
 assert.match(ha.title,/2\/2 controllers ready/);
 env.context.apiResponses['/api/v1/cluster']={...cluster,nodes:[{...primary,ready:false},cluster.nodes[1]]};
 await env.run('refreshClusterStatus()');
 assert.equal(controller.dataset.state,'warning');
 assert.equal(controller.title,'Primary DC not ready');
 assert.equal(ha.dataset.state,'warning');
 assert.match(ha.title,/1\/2 controllers ready/);
 env.context.apiResponses['/api/v1/cluster']={...cluster,nodes:[primary]};
 await env.run('refreshClusterStatus()');
 assert.equal(ha.dataset.state,'warning');
 assert.match(ha.title,/Only one controller reporting/);
 env.context.apiResponses['/api/v1/cluster']={responseStatus:503,data:{error:'Not available'}};
 await env.run('refreshClusterStatus()');
 assert.equal(ha.dataset.state,'offline');
 assert.equal(ha.title,'HA status unavailable');
});
test('account Manage users shortcut preserves existing Super Admin gates and profile access for all three roles',async()=>{
 for(const role of ['read_only','admin','super_admin']){const env=await workspace('servers',{mode:'entra',role});await env.click('account-toggle');const html=env.element('#account-menu-panel').innerHTML;assert.match(html,/My profile|Display preferences/);assert.equal(html.includes('data-action="account-users"'),role==='super_admin');assert.equal(env.element('#navigation').innerHTML.includes('href="/access"'),false);assert.equal(env.element('#view-tabs').innerHTML.includes('href="/access"'),false);await env.click('account-users');assert.deepEqual(env.routeHistory,role==='super_admin'?['/access']:[]);assert.deepEqual(env.navigation,[]);await env.click('account-profile');assert.match(env.element('#modal-content').innerHTML,new RegExp(role==='read_only'?'Read Only':role==='super_admin'?'Super Admin':'Admin'));assert.equal(mutations(env).length,0);}
});
test('account menu supports arrow Home End Escape Tab outside click and returns focus after profile closes',async()=>{
 const env=await workspace('servers',{mode:'entra'}),{panel,trigger}=accountTestItems(env);let result=accountKey(env,'ArrowDown',trigger);assert.equal(result.prevented,true);assert.equal(env.run('state.accountMenuOpen'),true);assert.equal(env.context.document.activeElement.dataset.action,'account-profile');accountKey(env,'ArrowDown',env.context.document.activeElement);assert.equal(env.context.document.activeElement.dataset.action,'account-preferences');accountKey(env,'End',env.context.document.activeElement);assert.equal(env.context.document.activeElement.dataset.action,'account-signout');accountKey(env,'Home',env.context.document.activeElement);assert.equal(env.context.document.activeElement.dataset.action,'account-profile');result=accountKey(env,'Escape',env.context.document.activeElement);assert.equal(result.stopped,true);assert.equal(panel.hidden,true);assert.equal(env.context.document.activeElement,trigger);
 accountKey(env,'ArrowUp',trigger);assert.equal(env.context.document.activeElement.dataset.action,'account-signout');result=accountKey(env,'Tab',env.context.document.activeElement);assert.equal(result.prevented,false);assert.equal(panel.hidden,true);await env.click('account-toggle');env.listeners.click.find(handler=>handler.name==='accountOutsideClick')({target:{closest:()=>null}});assert.equal(panel.hidden,true);assert.equal(trigger.getAttribute('aria-expanded'),'false');await env.click('account-profile');assert.equal(env.run('state.accountDialogOpen'),true);env.run('state.detail="host-1"');result=accountKey(env,'Escape',env.element('#modal'));assert.equal(result.stopped,true);assert.equal(env.element('#modal').open,false);assert.equal(env.context.document.activeElement,trigger);assert.equal(env.run('state.detail'),'host-1');
});
test('browser display preferences change real classes and persist only approved booleans without identity or credentials',async()=>{
 const key='prthak-display-preferences-v1',env=await workspace('servers',{mode:'entra',role:'read_only',localStorage:{unrelated:'keep',[key]:JSON.stringify({compact_tables:true,reduce_motion:true,role:'super_admin',token:'do-not-copy',profile:{email:'do-not-copy@example.test'}})}});assert.equal(env.run('state.role'),'read_only');assert.equal(env.context.document.body.classList.contains('display-compact-tables'),true);assert.equal(env.context.document.body.classList.contains('display-reduce-motion'),true);await env.click('account-preferences');const before=env.requests.length;await env.submit('account-preferences-form',{compact_tables:'on',role:'super_admin',token:'never-save',display_name:'Never save this'});assert.equal(env.requests.length,before);assert.equal(env.context.document.body.classList.contains('display-compact-tables'),true);assert.equal(env.context.document.body.classList.contains('display-reduce-motion'),false);assert.deepEqual(JSON.parse(env.displayStorage.get(key)),{compact_tables:true,reduce_motion:false});assert.equal(env.displayStorage.get('unrelated'),'keep');assert.equal(env.displayStorageChanges.every(change=>change.key===key&&!/token|profile|email|display_name|super_admin/.test(change.value)),true);assert.equal(env.run('state.role'),'read_only');assert.equal(env.context.document.activeElement,env.element('#account-menu-toggle'));
 const reopened=await workspace('servers',{localStorage:Object.fromEntries(env.displayStorage)});assert.equal(reopened.context.document.body.classList.contains('display-compact-tables'),true);await reopened.click('account-preferences');await reopened.click('account-preferences-reset');assert.deepEqual(JSON.parse(reopened.displayStorage.get(key)),{compact_tables:false,reduce_motion:false});assert.equal(reopened.context.document.body.classList.contains('display-compact-tables'),false);assert.equal(mutations(env).length,0);assert.equal(mutations(reopened).length,0);
});
test('display preference defaults remain unchanged and storage failure is reported without losing the local setting',async()=>{
 const env=await workspace('servers',{localStorage:{'prthak-display-preferences-v1':'{invalid'}});assert.equal(env.context.document.body.classList.contains('display-compact-tables'),false);assert.equal(env.context.document.body.classList.contains('display-reduce-motion'),false);env.context.window.localStorage.setItem=()=>{throw new Error('Storage denied');};await env.click('account-preferences');await env.submit('account-preferences-form',{reduce_motion:'on'});assert.equal(env.context.document.body.classList.contains('display-reduce-motion'),true);assert.match(env.element('created:div').textContent,/Browser storage is unavailable/);assert.equal(mutations(env).length,0);
});
test('closing an account dialog preserves in-progress page forms and catalogue filter drafts',async()=>{
 const env=await workspace('settings',{mode:'entra'}),before=env.requests.length;env.element('#view-content').innerHTML='<form id="existing-platform-draft">Unsaved polling override</form>';env.element('#service-filter-input').value='9443';await env.click('account-profile');await env.click('close-modal');assert.equal(env.element('#view-content').innerHTML,'<form id="existing-platform-draft">Unsaved polling override</form>');assert.equal(env.element('#service-filter-input').value,'9443');assert.equal(env.requests.length,before);assert.equal(env.context.document.activeElement,env.element('#account-menu-toggle'));
});
test('account sign-out uses existing Entra flow while token disconnect and demo remain truthful',async()=>{
 const entra=await workspace('servers',{mode:'entra',role:'read_only'});await entra.click('account-toggle');assert.match(entra.element('#account-menu-panel').innerHTML,/>Sign out<\/button>/);await entra.click('account-signout');assert.equal(mutations(entra).length,1);assert.equal(mutations(entra)[0].url,'/api/v1/auth/logout');assertCookieMutation(mutations(entra)[0]);assert.equal(entra.run('state.authType'),null);assert.equal(entra.element('#account-menu-toggle').disabled,true);
 const tokens=await workspace('servers',{mode:'tokens',role:'admin',storage:{'segment-token':'private-fixture-token'}});await tokens.click('account-toggle');assert.match(tokens.element('#account-menu-panel').innerHTML,/Disconnect token session/);await tokens.click('account-profile');assert.match(tokens.element('#modal-content').innerHTML,/does not revoke that token/);await tokens.click('account-signout');assert.equal(tokens.storage.has('segment-token'),false);assert.equal(mutations(tokens).length,0);assert.equal(tokens.displayStorageChanges.length,0);
 const demo=await workspace('servers');await demo.click('account-toggle');assert.match(demo.element('#account-menu-panel').innerHTML,/No authenticated session to sign out/);assert.doesNotMatch(demo.element('#account-menu-panel').innerHTML,/data-action="account-signout"/);await demo.click('account-signout');assert.equal(demo.run('state.authType'),'demo');assert.equal(mutations(demo).length,0);
});
test('all eleven direct page components render with the actual shared shell and module contracts',async()=>{
 for(const view of ['overview','servers','locations','services','firewall','policies','traffic','risk','alerts','activity','settings','access']){
  const env=await workspace(view),html=env.element('#view-content').innerHTML;
  assert.ok(html.length>30,view+' has rendered content');assert.notEqual(env.element('#page-title').textContent,'',view+' has a title');
  assert.doesNotMatch(html,/\bNaN\b/);assert.equal(env.run('state.view'),view);
  if(view==='overview')assert.doesNotMatch(html,/id="server-table-body"/);
  if(view==='locations'){assert.match(html,/Mumbai primary/);assert.match(html,/manually/);assert.doesNotMatch(html,/Legacy only/);}
  if(view==='services'){assert.match(html,/Web application/);assert.match(html,/443\/tcp/);assert.match(html,/Discovered services/);}
  if(view==='policies'){assert.match(html,/Discovered policies/);assert.match(html,/Managed policies/);assert.match(html,/Changes & history/);assert.doesNotMatch(html,/role="tablist"/);}
 }
});
test('Overview maps actual sites, counts each listener pair once per host, and drills into the same scope',async()=>{
 const secondLocation={id:'loc-cloud',name:'AWS region',type:'cloud',provider:'aws'};
 const secondHost={...host,id:'host-2',hostname:'billing cloud',location_id:secondLocation.id,location:secondLocation,
  listeners:[{port:2022,protocol:'tcp',process:'sshd'},{port:2022,protocol:'udp',process:'other service'}]};
 const duplicateListener={...host,listeners:[...host.listeners,{...host.listeners[0],address:'::'}]};
 const env=await workspace('overview',{responses:{'/api/v1/overview':{...fixture,servers:[duplicateListener,secondHost],locations:[location,secondLocation]}}});
 const html=env.element('#view-content').innerHTML;
 assert.equal(env.element('#page-title').textContent,'Network overview');
 assert.match(env.element('#overview-quick-filters').innerHTML,/All locations.*All applications/);
 assert.match(html,/India · 1 data centre · 0 cloud regions/);
 assert.match(html,/Unmapped sites.*AWS region/);
 assert.match(html,/Distinct port \/ protocol pairs/);
 assert.match(html,/data-port="2022\/tcp" aria-label="View 2 endpoints listening on 2022\/tcp"/);
 assert.match(html,/data-port="2022\/udp" aria-label="View 1 endpoints listening on 2022\/udp"/);
 assert.doesNotMatch(html,/Recent activity|id="server-search"/);
 await env.click('overview-location',{key:'location:loc-cloud'});
 const scoped=env.element('#view-content').innerHTML;
 assert.match(scoped,/0 data centres · 1 cloud region/);
 assert.match(scoped,/View 1 matching endpoint/);
 assert.doesNotMatch(scoped,/data-port="8443\/tcp"/);
 await env.click('overview-service',{port:'2022/tcp'});
 assert.equal(env.run('state.view'),'servers');
 assert.equal(env.run('state.filters.locations[0]'),'location:loc-cloud');
 assert.equal(env.run('state.filters.ports[0]'),'2022/tcp');
 assert.match(env.element('#view-content').innerHTML,/billing cloud/);
});
test('Overview time selector requests the selected observation window',async()=>{
 const env=await workspace('overview',{responses:{'/api/v1/flows?window=21600':{items:[{server_id:'host-1',source_ip:'192.0.2.1',port:8443,protocol:'tcp',count:1,last_seen:new Date().toISOString()}]}}});
 await env.run('changeTrafficWindow(21600)');
 assert.equal(env.run('state.window'),21600);
 assert.match(env.element('#view-content').innerHTML,/1 observed link/);
 assert.match(env.element('#overview-quick-filters').innerHTML,/value="21600" selected/);
});
test('server settings keep one saved location separate from tags and block Read Only edits',async()=>{
 const env=await workspace('servers',{mode:'entra',role:'admin'});await env.click('edit-server',{id:'host-1'});const html=env.element('#modal-content').innerHTML;
 assert.match(html,/<select id="server-location" name="location_id"/);assert.doesNotMatch(html,/<select id="server-location"[^>]*multiple/);assert.match(html,/value="loc-1" selected/);
 const tags=html.match(/<textarea id="server-tags"[^>]*>([^<]*)<\/textarea>/)[1];assert.doesNotMatch(tags,/dc=/);assert.match(tags,/owner=finance/);
 for(const role of ['read_only','operator','viewer']){const denied=await workspace('servers',{mode:'entra',role});denied.element('#modal-content').innerHTML='unchanged';await denied.click('edit-server',{id:'host-1'});assert.equal(denied.element('#modal-content').innerHTML,'unchanged');assert.equal(denied.run('state.role'),'read_only');}
});
test('Read Only never submits server updates while Admin and Super Admin can save metadata with cookie CSRF',async()=>{
 for(const role of ['read_only','operator','viewer']){const env=await workspace('servers',{mode:'entra',role});const event=metadataForm(env,'server-form',{expected:'2022/tcp',tags:'owner=finance'},{id:'host-1'});await env.listeners.submit.at(-1)(event);assert.equal(env.requests.filter(request=>request.options.method==='PATCH').length,0);}
 for(const role of ['admin','super_admin']){const env=await workspace('servers',{mode:'entra',role});await env.click('edit-server',{id:'host-1'});env.element('#server-location').value='loc-1';env.element('#server-location-mode').value='manual';await env.submit('server-form',{expected:'2022/tcp',tags:'application=billing, owner=finance'});const request=env.requests.find(request=>request.options.method==='PATCH'),body=JSON.parse(request.options.body);assert.equal(body.location_id,'loc-1');assert.equal(body.tags.owner,'finance');assert.equal(body.tags.dc,undefined);assert.equal(request.options.credentials,'same-origin');assert.equal(request.options.headers['X-CSRF-Token'],'session-csrf-fixture');assert.equal(request.options.headers.Authorization,undefined);}
});
test('location targeting and source location selectors use catalogue IDs without raw DC tags',async()=>{
 const env=await workspace('policies');await env.run('showPolicy("policy-1")');const html=env.element('#modal-content').innerHTML;
 assert.match(html,/id="policy-location-id"/);assert.match(html,/name="target_location_id"/);assert.match(html,/value="loc-1" selected/);assert.match(html,/name="rule_location_id"/);assert.doesNotMatch(html,/dc=Legacy/);
});
const applicationGroups=[
 {id:'saved-billing',name:'Billing fleet',type:'dynamic',selector:{application:'billing'},application:'billing',managed:false,origin:'saved'},
 {id:'auto-payments',name:'Payments',type:'dynamic',selector:{application:'payments'},application:'payments',managed:true,origin:'application'},
 {id:'auto-platform',name:'Platform',type:'dynamic',selector:{application:'platform'},application:'platform',managed:true,origin:'application'},
 {id:'custom-finance',name:'Finance production',type:'dynamic',selector:{owner:'finance',environment:'production'},managed:false,origin:'saved'}
];
function groupFixtures(env){env.run(`state.data.groups=${JSON.stringify(applicationGroups)};F.setGroups(state.data.groups);state.data.servers.push(${JSON.stringify({...host,id:'payments-1',hostname:'payments-api',tags:{application:'payments'},listeners:[{port:8443,protocol:'tcp'}]})},${JSON.stringify({...host,id:'platform-1',hostname:'platform-api',tags:{application:'platform'},listeners:[{port:2022,protocol:'tcp'}]})});`);}
test('server group manager displays all applications once while preserving custom group actions',async()=>{
 const env=await workspace('servers');groupFixtures(env);env.run('showGroups()');const html=env.element('#modal-content').innerHTML;
 assert.match(html,/Applications<\/h3><span>3 groups/);assert.match(html,/Custom groups<\/h3><span>1 group/);
 for(const name of ['Billing fleet','Payments','Platform','Finance production'])assert.equal(html.split(`<strong>${name}</strong>`).length-1,1);
 const billing=html.match(/<article[^>]+data-group-id="saved-billing"[\s\S]*?<\/article>/)[0],payments=html.match(/<article[^>]+data-group-id="auto-payments"[\s\S]*?<\/article>/)[0];
 assert.match(billing,/data-action="edit-group"/);assert.match(billing,/data-action="delete-group"/);assert.match(payments,/Automatic application membership/);assert.match(payments,/>Rename<\/button>/);assert.doesNotMatch(payments,/data-action="delete-group"/);
 assert.equal(env.requests.filter(request=>['POST','PUT','DELETE'].includes(request.options.method)).length,0);
});
test('automatic application rename keeps membership fixed while saved application groups remain editable',async()=>{
 const env=await workspace('servers');groupFixtures(env);env.run('showGroupForm("auto-payments")');let html=env.element('#modal-content').innerHTML;
 assert.match(html,/<select id="group-type"[^>]*disabled/);assert.match(html,/<input id="group-selector"[^>]*readonly/);assert.doesNotMatch(html,/id="group-location-id"/);
 env.context.FormData=class{get(key){return {group_type:'static',group_selector:'application=platform',group_name:'Payment services'}[key]}getAll(){return[]}};
 await env.listeners.submit.at(-1)({preventDefault(){},target:{id:'group-form',dataset:{id:'auto-payments',memberIds:'["platform-1"]'},querySelector:env.element}});
 const request=env.requests.find(request=>request.url==='/api/v1/groups/auto-payments'&&request.options.method==='PUT');assert.ok(request);assert.deepEqual(JSON.parse(request.options.body),{name:'Payment services',type:'dynamic',selector:{application:'payments'},server_ids:[]});
 env.run('showGroupForm("saved-billing")');html=env.element('#modal-content').innerHTML;assert.doesNotMatch(html,/<select id="group-type"[^>]*disabled/);assert.doesNotMatch(html,/<input id="group-selector"[^>]*readonly/);
});
test('view group members preserves combined service/location filters and uses fresh dynamic membership',async()=>{
 const env=await workspace('servers');groupFixtures(env);env.run('state.filters.ports=["8443/tcp"];state.filters.locations=["location:loc-1"];showGroups();viewGroup("saved-billing")');
 assert.deepEqual(JSON.parse(env.run('JSON.stringify(state.filters.groups)')),['saved-billing']);assert.deepEqual(JSON.parse(env.run('JSON.stringify(state.filters.ports)')),['8443/tcp']);assert.equal(env.run('filteredServers().length'),1);
 env.run(`state.data.servers.push(${JSON.stringify({...host,id:'future-billing',hostname:'future-billing'})});`);assert.equal(env.run('filteredServers().length'),2);
 env.run('state.filters.ports=["9999/tcp"]');assert.equal(env.run('filteredServers().length'),0,'group browsing must not discard a restrictive port scope');
});
test('automatic and saved application groups are both reusable policy targets',async()=>{
 const env=await workspace('policies');groupFixtures(env);env.run('showPolicy()');const html=env.element('#modal-content').innerHTML;
 for(const id of ['saved-billing','auto-payments','auto-platform','custom-finance'])assert.match(html,new RegExp(`name="target_groups" value="${id}"`));
 assert.match(html,/Automatic application · 1/);assert.equal(env.run('policyTargetServers({selector:{},group_ids:["auto-platform"]})[0].id'),'platform-1');
});
test('legacy duplicate application groups keep every saved ID while only one canonical representative appears under Applications',async()=>{
 const env=await workspace('servers');groupFixtures(env);env.run(`state.data.groups.push(${JSON.stringify({...applicationGroups[0],id:'older-billing',name:'Legacy billing',created_at:'2020-01-01T00:00:00Z'})});state.data.groups.find(group=>group.id==='saved-billing').created_at='2021-01-01T00:00:00Z';showGroups();`);
 const html=env.element('#modal-content').innerHTML,applicationSection=html.split('<h3>Custom groups</h3>')[0];
 assert.match(applicationSection,/data-group-id="older-billing"/);assert.doesNotMatch(applicationSection,/data-group-id="saved-billing"/);assert.match(html,/data-group-id="saved-billing"/);assert.match(html,/Custom groups<\/h3><span>2 groups/);
 env.run(`state.data.groups.push(${JSON.stringify({...applicationGroups[0],id:'auto-billing',name:'Billing automatic',managed:true,origin:'application',created_at:'2026-01-01T00:00:00Z'})});showGroups();`);
 const updated=env.element('#modal-content').innerHTML.split('<h3>Custom groups</h3>')[0];assert.match(updated,/data-group-id="auto-billing"/);assert.doesNotMatch(updated,/data-group-id="older-billing"/);
 assert.equal(env.run('state.data.groups.filter(group=>group.application==="billing").length'),3,'saved IDs must remain available for existing policy references');
});
test('saved application deletion explains that automatic application grouping remains',async()=>{
 const env=await workspace('servers');groupFixtures(env);
 await env.run('handleAction({target:{closest:()=>({disabled:false,dataset:{action:"delete-group",id:"saved-billing"}})}})');
 assert.match(env.element('#modal-content').innerHTML,/application tags and automatic application grouping remain/);
 assert.equal(env.requests.filter(request=>request.options.method==='DELETE').length,0);
 env.element('#modal-content').innerHTML='unchanged';await env.run('handleAction({target:{closest:()=>({disabled:false,dataset:{action:"delete-group",id:"auto-payments"}})}})');
 assert.equal(env.element('#modal-content').innerHTML,'unchanged');
});

function metadataPlan(overrides={}){
 return {id:'review-1',kind:'bulk',payload:{server_ids:[host.id],patch:{tag_updates:{application:'billing'}},rule:{id:'rule-1',cidr:'10.241.0.0/16',location_id:location.id,name:'Noida 81 network'}},status:'draft',confirmation_nonce:'reviewed-nonce',expires_at:new Date(Date.now()+60000).toISOString(),items:[{server_id:host.id,hostname:host.hostname,before:{tags:{},location_id:null},after:{tags:{application:'billing'},location_id:location.id},conflicts:[]}],summary:{matched_servers:1,changed_servers:1},errors:[],...overrides};
}
function metadataForm(env,id,values,dataset={}){
 env.context.FormData=class{get(key){return values[key]}getAll(key){return values[key] || []}};
 return {preventDefault(){},target:{id,dataset,querySelector:env.element}};
}
test('agent setup is identity-only and enrollment requests contain no central metadata defaults',async()=>{
 const env=await workspace('servers');env.run('showSetup()');const html=env.element('#modal-content').innerHTML;
 assert.match(html,/Enrollment is identity-only/);assert.doesNotMatch(html,/id="enrollment-(?:tags|location)"/);
 env.element('#enrollment-name').value='RHEL endpoint';
 await env.run('handleAction({target:{closest:()=>({disabled:false,dataset:{action:"generate-token"}})}})');
 assert.deepEqual(JSON.parse(env.requests.find(item=>item.url==='/api/v1/enrollment-tokens').options.body),{name:'RHEL endpoint'});
});
test('metadata selection keeps explicit server IDs and exposes hidden selections when filters change',async()=>{
 const env=await workspace('servers');groupFixtures(env);
 assert.equal(env.run('metadataSelectedServers().length'),0);
 env.run('metadataChange({target:{dataset:{metadataSelect:"host-1"},checked:true}});state.filters.application=["payments"];render()');
 const html=env.element('#view-content').innerHTML;
 assert.match(html,/1 outside current filters/);assert.match(html,/Select all 1 matching/);
 await env.run('metadataAction({dataset:{action:"metadata-select-matching"}})');
 assert.deepEqual(JSON.parse(env.run('JSON.stringify(metadataSelectedServers().map(server=>server.id))')),['host-1','payments-1']);
 env.run('showMetadataBulk()');assert.match(env.element('#modal-content').innerHTML,/2 explicit servers selected/);
 assert.equal(env.requests.filter(item=>item.options.method==='POST').length,0,'selecting/opening an editor must not write metadata');
 env.run('metadataChange({target:{id:"metadata-select-all",dataset:{},checked:false}})');
 assert.deepEqual(JSON.parse(env.run('JSON.stringify(metadataSelectedServers().map(server=>server.id))')),['host-1'],'unchecking matching rows must preserve explicit selections outside scope');
});
test('bulk assignment reviews the selected IDs and preserves every untouched tag and location',async()=>{
 const env=await workspace('servers');env.context.apiResponses={'/api/v1/metadata/bulk/preview':metadataPlan()};
 env.run('metadataSelection().add("host-1");showMetadataBulk()');
 await env.listeners.submit.at(-1)(metadataForm(env,'metadata-bulk-form',{tag_mode:'merge',tags:'owner=security',location_mode:'keep'}));
 const writes=env.requests.filter(item=>item.options.method==='POST');assert.equal(writes.length,1);assert.equal(writes[0].url,'/api/v1/metadata/bulk/preview');
 assert.deepEqual(JSON.parse(writes[0].options.body),{server_ids:['host-1'],tag_updates:{owner:'security'}});
 assert.match(env.element('#modal-content').innerHTML,/Before<\/th><th>Effective after/);
 assert.match(env.element('#modal-content').innerHTML,/Apply central assignments/);
 await env.run('metadataAction({dataset:{action:"metadata-plan-apply"}})');
 const apply=env.requests.find(item=>item.url==='/api/v1/metadata/bulk/review-1/apply');assert.ok(apply);
 assert.deepEqual(JSON.parse(apply.options.body),{confirmation_nonce:'reviewed-nonce'});
});
test('bulk remove and automatic reset are explicit, while reserved DC tags and empty changes never preview',async()=>{
 const env=await workspace('servers');env.context.apiResponses={'/api/v1/metadata/bulk/preview':metadataPlan()};env.run('state.metadataBulkIds=["host-1"]');
 for(const [tagMode,expected] of [['remove',{tag_updates:{owner:null}}],['automatic',{reset_tag_keys:['owner']}]] ){
  env.run('showMetadataBulk(["host-1"])');
  await env.listeners.submit.at(-1)(metadataForm(env,'metadata-bulk-form',{tag_mode:tagMode,tags:'owner',location_mode:'automatic'}));
  const body=JSON.parse(env.requests.filter(item=>item.url==='/api/v1/metadata/bulk/preview').at(-1).options.body);
  assert.deepEqual(body,{server_ids:['host-1'],...expected,location_mode:'automatic'});
 }
 const before=env.requests.length;
 env.run('showMetadataBulk(["host-1"])');
 await env.listeners.submit.at(-1)(metadataForm(env,'metadata-bulk-form',{tag_mode:'merge',tags:'dc=Untrusted',location_mode:'keep'}));
 assert.equal(env.requests.length,before);assert.match(env.element('#form-error').textContent,/location|DC/i);
 await env.listeners.submit.at(-1)(metadataForm(env,'metadata-bulk-form',{tag_mode:'merge',tags:'',location_mode:'keep'}));assert.equal(env.requests.length,before);
});
test('single-server saves preserve automatic assignments unless the administrator explicitly pins or resets them',async()=>{
 const env=await workspace('servers');const values={expected:'2022/tcp',tags:'application=billing,owner=finance'};
 env.element('#server-location').value=location.id;env.element('#server-location-mode').value='keep';
 env.run('showEditServer("host-1")');const event=metadataForm(env,'server-form',values,{id:host.id});await env.listeners.submit.at(-1)(event);
 let body=JSON.parse(env.requests.filter(item=>item.options.method==='PATCH').at(-1).options.body);assert.equal(body.location_id,undefined);assert.equal(body.location_mode,undefined);
 env.run('showEditServer("host-1")');env.element('#server-location-mode').value='automatic';values.reset_tag_keys='owner';await env.listeners.submit.at(-1)(event);
 body=JSON.parse(env.requests.filter(item=>item.options.method==='PATCH').at(-1).options.body);assert.equal(body.location_mode,'automatic');assert.equal(body.location_id,undefined);assert.deepEqual(body.reset_tag_keys,['owner']);
 env.run('showEditServer("host-1")');env.element('#server-location').value='';env.element('#server-location-mode').value='manual';await env.listeners.submit.at(-1)(event);
 body=JSON.parse(env.requests.filter(item=>item.options.method==='PATCH').at(-1).options.body);assert.equal(body.location_id,null,'explicit unassignment remains a manual pin');
});
test('subnet changes and removals use preview routes before applying to saved locations',async()=>{
 const env=await workspace('locations');env.context.apiResponses={'/api/v1/metadata/subnets/preview':metadataPlan({kind:'subnet'}),'/api/v1/metadata/subnets/rule-1/delete-preview':metadataPlan({kind:'subnet_delete'})};
 env.run('showMetadataSubnet()');assert.match(env.element('#modal-content').innerHTML,/Create the DC in the catalogue first/);
 await env.listeners.submit.at(-1)(metadataForm(env,'metadata-subnet-form',{cidr:'10.241.0.0/16',location_id:'',name:'Noida'}));assert.equal(env.requests.filter(item=>item.options.method==='POST').length,0);
 await env.listeners.submit.at(-1)(metadataForm(env,'metadata-subnet-form',{cidr:'10.241.0.0/16',location_id:location.id,name:'Noida'}));
 const preview=env.requests.find(item=>item.url==='/api/v1/metadata/subnets/preview');assert.deepEqual(JSON.parse(preview.options.body),{cidr:'10.241.0.0/16',location_id:location.id,name:'Noida'});
 assert.equal(env.requests.filter(item=>item.url.endsWith('/apply')).length,0);
 await env.run('metadataAction({dataset:{action:"metadata-subnet-delete",id:"rule-1"}})');assert.ok(env.requests.find(item=>item.url==='/api/v1/metadata/subnets/rule-1/delete-preview'));assert.equal(env.requests.filter(item=>item.options.method==='DELETE').length,0);
 await env.run('metadataAction({dataset:{action:"metadata-plan-apply"}})');assert.ok(env.requests.find(item=>item.url==='/api/v1/metadata/subnets/review-1/apply'));
});
test('CSV file reading is local and imports have bounded escaped previews with a separate reviewed apply',async()=>{
 const env=await workspace('servers');const csv='ip,application,dc,network_zone,criticality,tag.owner\n10.1.0.2,billing,,production,high,finance\n';
 const rows=Array.from({length:105},(_,i)=>({line:i+2,ip:'10.1.0.'+i,status:i?'future':'overridden',before:null,after:null,profile_after:{tags:{application:i?'<img src=x>':'billing'},location_id:location.id},overridden_fields:i?[]:['application']}));
 env.context.apiResponses={'/api/v1/metadata/imports/preview':metadataPlan({kind:'csv',rows,summary:{rows:105,current_servers:1,future_ips:104,overridden_fields:1}})};
 env.run('showMetadataCSV()');assert.match(env.element('#modal-content').innerHTML,/Blank cells preserve/);
 env.context.localCSV=csv;env.run('metadataChange({target:{id:"metadata-csv-file",files:[{size:localCSV.length,text:async()=>localCSV}]}})');await new Promise(setImmediate);
 assert.equal(env.element('#metadata-csv-text').value,csv);assert.equal(env.requests.filter(item=>item.options.method==='POST').length,0);
 await env.listeners.submit.at(-1)(metadataForm(env,'metadata-csv-form',{csv}));let html=env.element('#modal-content').innerHTML;
 assert.match(html,/Showing 1–100 of 105 frozen review rows/);assert.match(html,/Manual overrides preserved: application/);assert.match(html,/Stored for future discovery/);assert.match(html,/&lt;img src=x&gt;/);assert.doesNotMatch(html,/<img src=x>/);
 assert.equal(env.requests.filter(item=>item.url.endsWith('/apply')).length,0);await env.run('metadataAction({dataset:{action:"metadata-plan-apply"}})');
 const apply=env.requests.find(item=>item.url==='/api/v1/metadata/imports/review-1/apply');assert.deepEqual(JSON.parse(apply.options.body),{confirmation_nonce:'reviewed-nonce'});
});
test('invalid, expired and applied previews cannot expose an apply control; metadata sources and conflicts are escaped',async()=>{
 const env=await workspace('servers');
 for(const plan of [metadataPlan({status:'invalid',confirmation_nonce:null,errors:[{line:2,field:'dc',message:'Unknown <location>'}]}),metadataPlan({expires_at:'2000-01-01T00:00:00Z'}),metadataPlan({status:'applied'})]){
  env.context.preview=plan;const html=env.run('metadataPreviewHTML(preview,"csv")');assert.match(html,/data-action="metadata-plan-apply" disabled/);
 }
 env.run('state.data.servers[0].location_source={type:"subnet",cidr:"10.241.0.0/16"};state.data.servers[0].tag_sources={application:{type:"csv"},owner:{type:"manual"}};state.data.servers[0].metadata_conflicts=["<script>ambiguous</script>"];showEditServer("host-1")');
 const html=env.element('#modal-content').innerHTML;assert.match(html,/Subnet mapping · 10.241.0.0\/16/);assert.match(html,/application: CSV IP profile/);assert.match(html,/owner: Manual override/);assert.match(html,/&lt;script&gt;ambiguous/);assert.doesNotMatch(html,/<script>/);
});
test('imported IP profile manager paginates existing and future profiles without changing assignments',async()=>{
 const env=await workspace('servers'),profile={id:'profile-1',ip:'10.241.1.10',tags:{application:'<billing>'},location_id:location.id,server_count:0,binding_status:'future'};
 env.context.apiResponses={'/api/v1/metadata/imports/profiles?limit=100&offset=0':{items:Array.from({length:100},(_,i)=>({...profile,ip:'10.241.1.'+i})),total:101,limit:100,offset:0},'/api/v1/metadata/imports/profiles?limit=100&offset=100':{items:[{...profile,ip:'2001:db8::1',server_count:1,binding_status:'current'}],total:101,limit:100,offset:100}};
 env.run('showMetadataCSV()');assert.match(env.element('#modal-content').innerHTML,/Manage imported IP profiles/);await env.run('metadataAction({dataset:{action:"metadata-profiles"}})');
 let html=env.element('#modal-content').innerHTML;assert.match(html,/1–100 of 101 imported profiles/);assert.match(html,/Future discovery/);assert.match(html,/&lt;billing&gt;/);assert.doesNotMatch(html,/<billing>/);assert.equal(env.requests.filter(item=>item.options.method==='POST').length,0);
 await env.run('metadataAction({dataset:{action:"metadata-profiles-page",offset:"100"}})');html=env.element('#modal-content').innerHTML;assert.match(html,/101–101 of 101/);assert.match(html,/1 discovered server/);assert.match(html,/data-offset="200" disabled/);
});
test('removing an imported future profile reviews its stored values before explicitly applying a nonce',async()=>{
 const env=await workspace('servers'),ip='2001:db8::1',plan=metadataPlan({kind:'csv_profile_delete',rows:[{ip,status:'future',before:null,after:null,profile_before:{tags:{application:'billing'},location_id:location.id},profile_after:null,overridden_fields:[]}],summary:{rows:1,current_servers:0,future_ips:1,changed_servers:0}});
 env.context.apiResponses={'/api/v1/metadata/imports/profiles/2001%3Adb8%3A%3A1/delete-preview':plan,'/api/v1/metadata/imports/profiles?limit=100&offset=0':{items:[],total:0,limit:100,offset:0}};
 await env.run('metadataAction({dataset:{action:"metadata-profile-delete",id:"2001:db8::1"}})');let html=env.element('#modal-content').innerHTML;
 assert.match(html,/billing/);assert.match(html,/Mumbai primary/);assert.match(html,/Future profile removed/);assert.match(html,/CSV profile removed/);assert.match(html,/>Remove IP profile<\/button>/);assert.equal(env.requests.filter(item=>item.url.endsWith('/apply')).length,0);
 await env.run('metadataAction({dataset:{action:"metadata-plan-apply"}})');
 const apply=env.requests.find(item=>item.url==='/api/v1/metadata/imports/review-1/apply');assert.deepEqual(JSON.parse(apply.options.body),{confirmation_nonce:'reviewed-nonce'});assert.match(env.element('#modal-content').innerHTML,/No imported IP profiles/);
});
test('zero-current-host subnet previews show the frozen network, saved DC and name for create, edit and removal',async()=>{
 const env=await workspace('locations');
 env.run('L.setCatalog([{id:"loc-future",name:"Noida <DC>",type:"datacenter"}]);state.metadataSubnets=[{id:"rule-future",cidr:"10.99.0.0/16",name:"Unreviewed local name",location_id:"loc-1"}]');
 for(const kind of ['subnet','subnet_delete']){
  env.context.preview=metadataPlan({kind,payload:{rule_id:'rule-future',rule:{id:'rule-future',cidr:'10.241.0.0/16',name:'Noida <servers>',location_id:'loc-future'}},items:[],summary:{matched_servers:0,changed_servers:0}});
  const html=env.run(`metadataPreviewHTML(preview,${JSON.stringify(kind)})`);
  assert.match(html,/10\.241\.0\.0\/16 → Noida &lt;DC&gt;/);assert.match(html,/Mapping name: Noida &lt;servers&gt;/);assert.match(html,/Saved location ID: loc-future/);
  assert.match(html,/No current endpoint values change/);assert.doesNotMatch(html,/Unreviewed local name|10\.99\.0\.0|<servers>|<DC>/);
  assert.doesNotMatch(html,/data-action="metadata-plan-apply" disabled/);
  if(kind==='subnet_delete')assert.match(html,/Remove mapping:|Future discoveries stop using this mapping/);
 }
});
test('source-only bulk changes expose frozen tag operations and resulting pin/reset provenance despite identical values',async()=>{
 const env=await workspace('servers'),same={tags:{application:'billing',owner:'finance'},location_id:location.id};
 env.context.preview=metadataPlan({payload:{server_ids:[host.id],patch:{tag_updates:{application:'billing',obsolete:null},reset_tag_keys:['owner'],location_mode:'automatic'}},items:[{server_id:host.id,hostname:host.hostname,before:same,after:same,changed:true,location_source:{type:'subnet',cidr:'10.241.0.0/16'},tag_sources:{application:{type:'manual'},owner:{type:'csv',ip:'10.241.1.10'},obsolete:{type:'manual',removed:true}}}],summary:{matched_servers:1,changed_servers:1}});
 let html=env.run('metadataPreviewHTML(preview,"bulk")');
 assert.match(html,/Reviewed operation · 1 explicit server/);assert.match(html,/Set manual tags: application=billing/);assert.match(html,/Remove tags \(persistent manual override\): obsolete/);assert.match(html,/Return tags to automatic: owner/);assert.match(html,/Return location to automatic CSV \/ subnet mapping/);
 assert.match(html,/Effective values stay the same; the assignment source is updated/);assert.match(html,/Location source after: Subnet mapping · 10\.241\.0\.0\/16/);assert.match(html,/application: Manual override/);assert.match(html,/owner: CSV IP profile · 10\.241\.1\.10/);assert.match(html,/obsolete: Manual override \(removed until reset\)/);
 env.run('preview.payload.patch={tag_updates:{application:"billing <script>"},location_id:null};preview.items[0].location_source={type:"manual",cleared:true}');html=env.run('metadataPreviewHTML(preview,"bulk")');assert.match(html,/Pin manual location: Unassigned/);assert.match(html,/Manual override \(pinned Unassigned\)/);assert.match(html,/billing &lt;script&gt;/);assert.doesNotMatch(html,/<script>/);
});
test('bulk and subnet plans missing their reviewed definition cannot offer or trigger apply',async()=>{
 const env=await workspace('servers');
 for(const kind of ['bulk','subnet','subnet_delete']){
  env.context.preview=metadataPlan({kind,payload:{}});const html=env.run(`metadataPreviewHTML(preview,${JSON.stringify(kind)})`);
  assert.match(html,/reviewed operation definition is missing/);assert.match(html,/data-action="metadata-plan-apply" disabled/);
  env.run(`state.metadataPlan={plan:preview,kind:${JSON.stringify(kind)}}`);await env.run('metadataAction({dataset:{action:"metadata-plan-apply"}})');
 }
 assert.equal(env.requests.filter(item=>item.url.endsWith('/apply')).length,0);
});

const approvedUser={id:'entra-user/42',object_id:'ebfe2ac7-5fb4-4672-8979-80a63d3b690c',display_name:'Approved <Operator>',email:'approved@example.test',role:'read_only',enabled:true,last_login_at:null};
function accessWorkspace(role='super_admin',extra={}){return workspace('access',{mode:'entra',role,responses:{'/api/v1/access/users':{items:[approvedUser]},...extra.responses},...extra});}
function mutations(env){return env.requests.filter(item=>['POST','PUT','PATCH','DELETE'].includes(item.options.method)&&!['/api/v1/firewall/query','/api/v1/policies/query','/api/v1/learning-policies/query','/api/v1/policy-rollouts/query','/api/v1/host-default-deny/query'].includes(item.url));}
function assertCookieMutation(request){assert.equal(request.options.credentials,'same-origin');assert.equal(request.options.headers['X-CSRF-Token'],'session-csrf-fixture');assert.equal(request.options.headers.Authorization,undefined);}
test('only Super Admin sees Users & access and fetches the approved Entra user list',async()=>{
 const superEnv=await accessWorkspace();assert.doesNotMatch(superEnv.element('#navigation').innerHTML,/href="\/access"/);assert.doesNotMatch(superEnv.element('#view-tabs').innerHTML,/href="\/access"/);assert.match(superEnv.element('#view-content').innerHTML,/Approved &lt;Operator&gt;/);assert.doesNotMatch(superEnv.element('#view-content').innerHTML,/<Operator>/);assert.match(superEnv.element('#view-content').innerHTML,/data-action="access-user-new"/);assert.equal(superEnv.element('#identity-name').textContent,'Priya Operator');assert.equal(superEnv.element('#role-label').textContent,'Super Admin');
 for(const role of ['admin','read_only','operator','viewer']){const env=await accessWorkspace(role);assert.doesNotMatch(env.element('#navigation').innerHTML,/href="\/access"/);assert.doesNotMatch(env.element('#view-tabs').innerHTML,/href="\/access"/);assert.match(env.element('#view-content').innerHTML,/Super Admin access required/);assert.doesNotMatch(env.element('#view-content').innerHTML,/Approved|data-action="access-user/);assert.equal(env.requests.some(item=>item.url==='/api/v1/access/users'),false);await env.click('access-user-new');assert.doesNotMatch(env.element('#modal-content').innerHTML,/id="access-user-form"/);assert.equal(mutations(env).length,0);}
});
test('Super Admin grants access only with an explicit existing Entra Object ID and one valid role',async()=>{
 const env=await accessWorkspace();await env.click('access-user-new');let html=env.element('#modal-content').innerHTML;assert.match(env.element('#modal-title').textContent,/existing Entra user/);assert.match(html,/name="object_id"/);assert.match(html,/Email \(display only\)/);assert.match(html,/value="read_only" selected/);assert.doesNotMatch(html,/Create Microsoft|password/i);
 const values={object_id:'new-user@example.test',display_name:'New Analyst',email:'analyst@example.test',role:'admin'};await env.submit('access-user-form',values);assert.equal(mutations(env).length,0);assert.match(env.element('#form-error').textContent,/Object ID as a GUID/);
 values.object_id='4a367933-74fd-4645-ab4a-4a35e1a26de8';values.role='owner';await env.submit('access-user-form',values);assert.equal(mutations(env).length,0);
 values.role='admin';await env.submit('access-user-form',values);const request=mutations(env)[0];assert.equal(request.url,'/api/v1/access/users');assert.deepEqual(JSON.parse(request.options.body),values);assertCookieMutation(request);assert.equal(env.storageChanges.some(change=>change.operation==='set'&&change.key==='segment-token'),false);
});
test('Super Admin edits approved users and disables access through an encoded user route',async()=>{
 const env=await accessWorkspace();await env.click('access-user-edit',{id:approvedUser.id});const html=env.element('#modal-content').innerHTML;assert.match(html,/name="object_id"[^>]*readonly/);assert.match(html,/Existing identity bindings cannot be changed/);
 await env.submit('access-user-form',{display_name:'Updated Operator',email:'updated@example.test',role:'super_admin',enabled:'false',object_id:'ignored-attempt-to-rebind'});
 const request=mutations(env)[0];assert.equal(request.url,'/api/v1/access/users/entra-user%2F42');assert.equal(request.options.method,'PATCH');assert.deepEqual(JSON.parse(request.options.body),{display_name:'Updated Operator',email:'updated@example.test',role:'super_admin',enabled:false});assertCookieMutation(request);
});
test('revoking user sessions is a separate reviewed Super Admin action',async()=>{
 const env=await accessWorkspace();await env.click('access-user-revoke-review',{id:approvedUser.id});assert.equal(mutations(env).length,0);assert.match(env.element('#modal-content').innerHTML,/Sign out all active/);assert.match(env.element('#modal-content').innerHTML,/Approved &lt;Operator&gt;/);
 await env.click('access-user-revoke-confirm',{id:approvedUser.id});const request=mutations(env)[0];assert.equal(request.url,'/api/v1/access/users/entra-user%2F42/revoke-sessions');assert.deepEqual(JSON.parse(request.options.body),{});assertCookieMutation(request);
 for(const role of ['admin','read_only']){const denied=await accessWorkspace(role);await denied.click('access-user-edit',{id:approvedUser.id});await denied.click('access-user-revoke-confirm',{id:approvedUser.id});assert.equal(mutations(denied).length,0);}
});
test('configured Entra sign-in redirects to the controller without storing a bearer token',async()=>{
 const env=await workspace('overview',{mode:'entra',authStatus:401,storage:{'segment-token':'stale-role-token'}});const html=env.element('#sign-in-content').innerHTML;assert.match(html,/Sign in with SSO/);assert.doesNotMatch(html,/Microsoft|id="login-token"|id="login-form"/);assert.equal(env.storage.has('segment-token'),false);assert.equal(env.requests.every(request=>request.options.headers.Authorization===undefined),true);
 await env.click('auth-entra-login');assert.deepEqual(env.navigation,['/api/v1/auth/login']);assert.equal(mutations(env).length,0);assert.equal(env.requests.every(request=>request.options.credentials==='same-origin'),true);
});
test('unconfigured Entra has no synthetic user or token sign-in and cannot redirect',async()=>{
 const env=await workspace('access',{mode:'entra',authStatus:401,config:{configured:false,login_url:null}});const html=env.element('#sign-in-content').innerHTML;assert.match(html,/Single sign-on is unavailable/);assert.doesNotMatch(html,/data-action="auth-entra-login"|id="login-token"|Demo administrator/);assert.equal(env.element('#workspace-shell').hidden,true);assert.equal(env.context.location.pathname,'/login');assert.equal(env.run('state.user'),null);assert.equal(env.requests.some(request=>request.url==='/api/v1/access/users'),false);await env.click('auth-entra-login');assert.deepEqual(env.navigation,[]);
});
test('role token entry is limited to explicit tokens mode and carries no cookie CSRF secret',async()=>{
 const env=await workspace('servers',{mode:'tokens',authStatus:401});assert.match(env.element('#sign-in-content').innerHTML,/id="login-form"/);env.context.apiResponses['/api/v1/auth']={role:'admin',demo:false,auth_type:'token',user:null};await env.submit('login-form',{token:'controller-issued-fixture'});
 assert.equal(env.run('state.role'),'admin');assert.equal(env.storage.get('segment-token'),'controller-issued-fixture');const authenticated=env.requests.filter(request=>request.url==='/api/v1/auth').at(-1);assert.equal(authenticated.options.headers.Authorization,'Bearer controller-issued-fixture');assert.equal(authenticated.options.headers['X-CSRF-Token'],undefined);assert.equal(env.element('#identity-name').textContent,'Role-token session');
});
test('session sign-out sends cookie CSRF then clears the displayed identity',async()=>{
 const env=await workspace('servers',{mode:'entra',role:'admin'});await env.run('dashboardLogout()');const request=mutations(env)[0];assert.equal(request.url,'/api/v1/auth/logout');assert.deepEqual(JSON.parse(request.options.body),{});assertCookieMutation(request);assert.equal(env.run('state.user'),null);assert.equal(env.run('state.csrfToken'),'');assert.equal(env.element('#identity-name').textContent,'Sign in required');assert.match(env.element('#sign-in-content').innerHTML,/Sign in with SSO/);
});
test('display email and directory role/group claims cannot grant application roles',async()=>{
 for(const identity of [
  {demo:false,auth_type:'session',csrf_token:'session-csrf-fixture',role:'operator',user:{id:'oid',email:'super_admin@example.test',role:'super_admin'},groups:['super_admin']},
  {demo:false,auth_type:'session',csrf_token:'session-csrf-fixture',user:{id:'oid',email:'admin@example.test',roles:['super_admin']},roles:['super_admin']}
 ]){const env=await workspace('access',{mode:'entra',identity});assert.equal(env.run('state.role'),'read_only');assert.doesNotMatch(env.element('#navigation').innerHTML,/href="\/access"/);assert.equal(env.requests.some(request=>request.url==='/api/v1/access/users'),false);}
});
test('demo identity and access status explicitly identify a synthetic workspace',async()=>{
 const env=await workspace('access');assert.match(env.element('#role-label').textContent,/Demo.*Super Admin/);assert.equal(env.element('#identity-name').textContent,'Demo administrator');assert.match(env.element('#view-content').innerHTML,/Synthetic demo workspace/);assert.doesNotMatch(env.element('#view-content').innerHTML,/Configure SAML|Microsoft/);assert.doesNotMatch(env.element('#account-menu-panel').innerHTML,/data-action="account-signout"/);assert.match(env.element('#view-content').innerHTML,/data-action="access-user-new" disabled/);
});

test('an Entra page rejects a fabricated role-token form and never treats a demo claim as production elevation',async()=>{
 const env=await workspace('servers',{mode:'entra',identity:{demo:true,role:'read_only',auth_type:'session',csrf_token:'session-csrf-fixture',user:{id:'oid',display_name:'Approved Reader',role:'read_only'}}});assert.equal(env.run('state.role'),'read_only');
 await env.listeners.submit.at(-1)({preventDefault(){},target:{id:'login-form',dataset:{},values:{token:'unexpected-bearer'},querySelector:env.element}});assert.equal(env.storage.has('segment-token'),false);assert.equal(env.requests.some(request=>request.options.headers.Authorization!==undefined),false);assert.equal(env.run('state.role'),'read_only');
});
const pendingServer={id:'pending/host-1',hostname:'future-api-21',ips:['10.241.1.21','2001:db8::21'],status:'pending',created_at:new Date().toISOString()};
function deletionPlan(server=host,overrides={}){return {id:'retirement-plan-1',server_id:server.id,kind:server===host?'server':'reservation',before:server,status:'draft',can_delete:true,blockers:[],confirmation_nonce:'retirement-nonce',expires_at:new Date(Date.now()+60000).toISOString(),impact:{identity_revoked:true,static_groups:['group-1']},warnings:['Historical audit records remain available.'],...overrides};}
test('Admin and Super Admin create a pending server with explicit hostname, then request a token bound to its reservation',async()=>{
 for(const role of ['admin','super_admin']){let created=false;const env=await workspace('servers',{mode:'entra',role,responses:{'POST /api/v1/servers':()=>{created=true;return pendingServer;},'/api/v1/server-reservations':()=>({items:created?[pendingServer]:[]})}});assert.match(env.element('#view-content').innerHTML,/data-action="reservation-new"/);await env.click('reservation-new');assert.match(env.element('#modal-content').innerHTML,/agent must report this exact hostname/);assert.match(env.element('#modal-content').innerHTML,/planning information, not verified endpoint ownership/);
  await env.submit('server-reservation-form',{hostname:'future-api-21',ips:'10.241.1.21, 2001:db8::21'});let request=mutations(env)[0];assert.equal(request.url,'/api/v1/servers');assert.deepEqual(JSON.parse(request.options.body),{hostname:pendingServer.hostname,ips:pendingServer.ips});assertCookieMutation(request);assert.equal(mutations(env).length,1,'creating the reservation does not issue a secret automatically');
  assert.match(env.element('#modal-content').innerHTML,/single-use token is bound to the planned server/);assert.match(env.element('#modal-content').innerHTML,/discovered hostname must match/);await env.click('reservation-token-generate',{id:pendingServer.id});request=mutations(env)[1];assert.equal(request.url,'/api/v1/enrollment-tokens');assert.deepEqual(JSON.parse(request.options.body),{name:'Enroll '+pendingServer.hostname,server_id:pendingServer.id});assertCookieMutation(request);assert.equal(env.run('state.data.servers.length'),1);assert.equal(env.run('state.data.servers.some(server=>server.ips.includes("10.241.1.21"))'),false);
  env.run('closeModal();render()');assert.match(env.element('#view-content').innerHTML,/Pending enrollment/);assert.match(env.element('#view-content').innerHTML,/future-api-21/);assert.match(env.element('#view-content').innerHTML,/Planned addresses do not enter source-policy membership/);
 }
});
test('Read Only can inspect pending servers without add, token or retirement actions',async()=>{
 const env=await workspace('servers',{mode:'entra',role:'read_only',responses:{'/api/v1/server-reservations':{items:[pendingServer]}}});assert.match(env.element('#view-content').innerHTML,/future-api-21/);assert.doesNotMatch(env.element('#view-content').innerHTML,/data-action="(?:reservation-new|reservation-token|server-lifecycle-delete-review)"/);
 await env.click('server',{id:host.id});await env.click('firewall-drawer-tab',{tab:'services'});assert.doesNotMatch(env.element('#server-drawer').innerHTML,/data-action="server-lifecycle-delete-review"/);await env.click('reservation-new');await env.click('reservation-token-generate',{id:pendingServer.id});await env.click('server-lifecycle-delete-review',{id:host.id});await env.click('server-lifecycle-delete-confirm');assert.equal(mutations(env).length,0);
});
test('retiring either an active or pending registration requires a preview and an explicit plan-bound confirmation',async()=>{
 for(const [server,role] of [[host,'admin'],[pendingServer,'super_admin']]){const encoded=encodeURIComponent(server.id),plan=deletionPlan(server);const env=await workspace('servers',{mode:'entra',role,responses:{'/api/v1/server-reservations':{items:[pendingServer]},['/api/v1/servers/'+encoded+'/delete-preview']:plan,['/api/v1/servers/'+encoded+'/delete-confirm']:{id:server.id,status:'retired'}}});await env.click('server-lifecycle-delete-review',{id:server.id});let requests=mutations(env);assert.equal(requests.length,1);assert.equal(requests[0].url,'/api/v1/servers/'+encoded+'/delete-preview');assert.deepEqual(JSON.parse(requests[0].options.body),{});assertCookieMutation(requests[0]);let html=env.element('#modal-content').innerHTML;assert.match(html,new RegExp(server.hostname));assert.match(html,/Reviewed impact/);assert.match(html,/Historical audit records remain available/);assert.doesNotMatch(html,/data-action="server-lifecycle-delete-confirm" disabled/);
  await env.click('server-lifecycle-delete-confirm');requests=mutations(env);assert.equal(requests.length,2);assert.equal(requests[1].url,'/api/v1/servers/'+encoded+'/delete-confirm');assert.deepEqual(JSON.parse(requests[1].options.body),{plan_id:plan.id,confirmation_nonce:plan.confirmation_nonce});assertCookieMutation(requests[1]);assert.equal(env.requests.some(request=>request.options.method==='DELETE'),false);
 }
});
test('blocked, expired or incomplete server retirement reviews cannot be confirmed',async()=>{
 for(const override of [
  {can_delete:false,blockers:['Active managed firewall rules need approved cleanup. <unsafe>']},
  {expires_at:'2000-01-01T00:00:00Z'},
  {id:null},
  {confirmation_nonce:null},
  {expires_at:null}
 ]){const env=await workspace('servers',{mode:'entra',role:'admin',responses:{'/api/v1/servers/host-1/delete-preview':deletionPlan(host,override)}});await env.click('server-lifecycle-delete-review',{id:host.id});const html=env.element('#modal-content').innerHTML;assert.match(html,/data-action="server-lifecycle-delete-confirm" disabled/);assert.doesNotMatch(html,/<unsafe>/);if(override.blockers)assert.match(html,/approved cleanup.*&lt;unsafe&gt;/);await env.click('server-lifecycle-delete-confirm');assert.equal(mutations(env).length,1);assert.equal(env.requests.some(request=>request.url.endsWith('/delete-confirm')),false);}
});
test('a role downgrade during an open deletion review cannot submit its stale confirmation',async()=>{
 const env=await workspace('policies',{mode:'entra',role:'admin'});await env.click('delete-policy',{id:policy.id});assert.match(env.element('#modal-content').innerHTML,/data-action="confirm-delete"/);
 env.context.apiResponses['/api/v1/auth']={role:'read_only',demo:false,auth_type:'session',csrf_token:'session-csrf-fixture',user:{id:'super-self',display_name:'Approved reader',role:'read_only'}};await env.run('load()');assert.equal(env.run('state.role'),'read_only');await env.click('confirm-delete',{id:policy.id});assert.equal(mutations(env).length,0);assert.match(env.element('#form-error').textContent,/Read Only access/);
});
test('a session without a CSRF secret cannot submit a rendered infrastructure form',async()=>{
 const env=await workspace('servers',{mode:'entra',identity:{role:'admin',demo:false,auth_type:'session',user:{id:'oid',display_name:'Approved administrator',role:'admin'}}});await env.click('reservation-new');await env.submit('server-reservation-form',{hostname:'future-node',ips:''});assert.equal(mutations(env).length,0);assert.match(env.element('#form-error').textContent,/fresh sign-in/);
});

function renderedForm(env,id,values={}) {
 const html=env.element('#modal-content').innerHTML+env.element('#view-content').innerHTML,tag=html.match(new RegExp('<form[^>]*id="'+id+'"[^>]*>'));
 assert.ok(tag,id+' is a production rendered form');
 const form=env.element('#'+id);form.id=id;form.values=values;form.dataset={};
 for(const attr of tag[0].matchAll(/data-([a-z-]+)="([^"]*)"/g))form.dataset[attr[1].replace(/-([a-z])/g,(_,letter)=>letter.toUpperCase())]=attr[2];
 return form;
}
function submitRendered(env,form) {return env.listeners.submit.at(-1)({preventDefault(){},target:form});}
function servicePreview(overrides={}) {return {before:serviceGroup,after:{...serviceGroup,revision:3,ports:[{port:443,protocol:'tcp'},{port:9443,protocol:'tcp'}]},ports_changed:true,effective_change_count:2,target_server_count:3,affected_policies:[{id:'policy-1',name:'Billing policy',revision:4}],affected_servers:[{id:'host-1',hostname:'api <one>'},{id:'host-2',hostname:'api-two'}],requires_managed_review:true,...overrides};}
test('Service groups shows different discovered services on one port and only prefills a draft',async()=>{
 const listeners=[{port:443,protocol:'tcp',service:'HTTPS',application:'Payments <web>'},{port:443,protocol:'tcp',process:'sshd'},{port:53,protocol:'udp',service:'DNS',process:'named'}];
 const responses={'/api/v1/overview':{...fixture,servers:[{...host,listeners}],meta:{...fixture.meta,demo:false}}};
 const env=await workspace('services',{mode:'entra',role:'admin',responses}),html=env.element('#view-content').innerHTML;
 assert.match(html,/Discovered services/);
 assert.match(html,/HTTPS.*Payments &lt;web&gt;.*443\/tcp/);
 assert.match(html,/SSH.*sshd.*443\/tcp/);
 assert.equal((html.match(/data-port="443" data-protocol="tcp"/g)||[]).length,2);
 env.run('serviceGroupInput({target:{id:"service-group-discovered-search",value:"sshd"}})');
 assert.match(env.element('#service-group-discovered-results').innerHTML,/SSH/);
 assert.doesNotMatch(env.element('#service-group-discovered-results').innerHTML,/HTTPS/);
 await env.click('service-group-use-discovered',{port:'443',protocol:'tcp'});
 assert.match(env.element('#modal-content').innerHTML,/name="ports"[^>]*>443\/tcp<\/textarea>/);
 assert.match(env.element('#modal-content').innerHTML,/Add discovered services/);
 const ports=env.element('#service-group-ports');ports.value='443/tcp';
 await env.click('service-group-add-discovered',{port:'443',protocol:'tcp'});
 assert.equal(ports.value,'443/tcp');
 await env.click('service-group-add-discovered',{port:'53',protocol:'udp'});
 assert.equal(ports.value,'443/tcp, 53/udp');
 assert.match(env.element('#service-group-impact').innerHTML,/Changes need a new impact preview/);
 assert.match(env.element('#modal-content').innerHTML,/Preview impact/);
 assert.equal(mutations(env).length,0);
 const readOnly=await workspace('services',{mode:'entra',role:'read_only',responses});
 assert.match(readOnly.element('#view-content').innerHTML,/Payments &lt;web&gt;/);
 assert.doesNotMatch(readOnly.element('#view-content').innerHTML,/Use port in new group/);
});
test('service group changes require an impact preview of exact ports, policies and hosts before saving',async()=>{
 for(const role of ['admin','super_admin']) {
  const env=await workspace('services',{mode:'entra',role,responses:{'POST /api/v1/service-groups/preview':servicePreview()}});
  await env.click('service-group-edit',{id:serviceGroup.id});const html=env.element('#modal-content').innerHTML;
  assert.match(html,/Preview impact/);assert.match(html,/data-action="service-group-save" disabled/);assert.match(html,/Nested groups and port ranges are not supported/);
  const form=renderedForm(env,'service-group-form',{name:'Web application',description:'Updated ports',ports:'443/tcp, 9443/tcp'});
  await env.click('service-group-save');assert.equal(mutations(env).length,0,'unreviewed draft cannot be saved');
  await submitRendered(env,form);let requests=mutations(env);assert.equal(requests.length,1);assert.equal(requests[0].url,'/api/v1/service-groups/preview');
  assert.deepEqual(JSON.parse(requests[0].options.body),{id:'web-ports',name:'Web application',description:'Updated ports',ports:[{port:443,protocol:'tcp'},{port:9443,protocol:'tcp'}],expected_revision:2});assertCookieMutation(requests[0]);
  const impact=env.element('#service-group-impact').innerHTML;assert.match(impact,/443\/tcp, 8443\/tcp/);assert.match(impact,/443\/tcp, 9443\/tcp/);assert.match(impact,/Billing policy/);assert.match(impact,/api &lt;one&gt;/);assert.doesNotMatch(impact,/<one>/);assert.match(impact,/api-two/);assert.match(impact,/fresh managed enforcement review/);
  await env.click('service-group-save');requests=mutations(env);assert.equal(requests.length,2);assert.equal(requests[1].url,'/api/v1/service-groups/web-ports');assert.equal(requests[1].options.method,'PUT');assert.equal(JSON.parse(requests[1].options.body).expected_revision,2);assertCookieMutation(requests[1]);
 }
});
test('every changed draft and stale catalogue revision requires a fresh review',async()=>{
 const env=await workspace('services',{mode:'entra',role:'admin',responses:{'POST /api/v1/service-groups/preview':servicePreview(),'PUT /api/v1/service-groups/web-ports':{responseStatus:409,data:{error:'Service group changed since it was loaded'}}}});
 await env.click('service-group-edit',{id:'web-ports'});const form=renderedForm(env,'service-group-form',{name:'Web application',description:'',ports:'443/tcp, 9443/tcp'});
 await submitRendered(env,form);form.values.ports='443/tcp, 10443/tcp';
 await env.click('service-group-save');assert.equal(mutations(env).length,1);assert.match(env.element('#form-error').textContent,/Preview the current changes/);
 await submitRendered(env,form);await env.click('service-group-save');assert.equal(mutations(env).length,3);assert.match(env.element('#service-group-impact').innerHTML,/changed since you opened it/);assert.equal(form.reviewedDraft,null);
 await env.click('service-group-save');assert.equal(mutations(env).length,3,'stale review cannot be retried as a save');
});
test('service catalogue is visible to Read Only without any creation, editing or deletion requests',async()=>{
 const env=await workspace('services',{mode:'entra',role:'read_only'});assert.match(env.element('#view-content').innerHTML,/Web application/);assert.doesNotMatch(env.element('#view-content').innerHTML,/data-action="service-group-(?:edit|delete)/);
 env.element('#modal-content').innerHTML='unchanged';await env.click('service-group-edit',{id:'web-ports'});await env.click('service-group-create');await env.click('service-group-delete-confirm',{id:'web-ports'});assert.equal(env.element('#modal-content').innerHTML,'unchanged');
 await env.listeners.submit.at(-1)({preventDefault(){},target:{id:'service-group-form',values:{name:'Attempt',ports:'443/tcp'},dataset:{},querySelector:env.element}});assert.equal(mutations(env).length,0);
 await env.click('service-group-view',{id:'web-ports'});assert.match(env.element('#modal-content').innerHTML,/443\/tcp/);assert.equal(mutations(env).length,0);
});
test('a missing session CSRF secret blocks catalogue previews before network access',async()=>{
 const env=await workspace('services',{mode:'entra',identity:{role:'admin',demo:false,auth_type:'session',user:{id:'admin',display_name:'Administrator'}}});
 await env.click('service-group-edit',{id:'web-ports'});const form=renderedForm(env,'service-group-form',{name:'Web application',ports:'443/tcp'});await submitRendered(env,form);assert.equal(mutations(env).length,0);assert.match(env.element('#form-error').textContent,/fresh sign-in/);
});
function policyRow(values,sourceGroups=[]) {
 const controls=new Map(Object.entries(values).map(([name,value])=>['[name="'+name+'"]',{value}]));
 return {querySelector:selector=>controls.get(selector),querySelectorAll:selector=>selector==='[name="rule_source_groups"]:checked'?sourceGroups.map(value=>({value})):[]};
}
test('policy form keeps multiple source groups aligned with each selected port or service group',async()=>{
 const env=await workspace('policies',{mode:'entra',role:'admin'});groupFixtures(env);env.run('showPolicy()');const html=env.element('#modal-content').innerHTML;
 assert.match(html,/name="rule_type"/);assert.match(html,/name="rule_service_group"/);assert.match(html,/name="rule_source_groups"/);assert.match(html,/Every allowed source below applies to every port in this row/);
 const form=renderedForm(env,'policy-form',{name:'Grouped access',target_type:'all',mode:'monitor'});
 const rows=[policyRow({rule_type:'group',rule_service_group:'web-ports',rule_sources:'192.0.2.0/24, 192.0.2.42',rule_selector:'owner=finance',rule_location_id:'loc-1'},['auto-payments','custom-finance']),policyRow({rule_type:'port',rule_port:'5432',rule_protocol:'tcp',rule_sources:'198.51.100.0/24',rule_selector:'',rule_location_id:''},['auto-platform'])];
 form.querySelectorAll=selector=>selector==='.rule-row'?rows:[];await submitRendered(env,form);
 const request=mutations(env)[0];assert.equal(request.url,'/api/v1/policies');assertCookieMutation(request);
 assert.deepEqual(JSON.parse(request.options.body).services,[{service_group_id:'web-ports',sources:['192.0.2.0/24','192.0.2.42'],source_selector:{owner:'finance',location_id:'loc-1'},source_group_ids:['auto-payments','custom-finance']},{port:5432,protocol:'tcp',sources:['198.51.100.0/24'],source_selector:{},source_group_ids:['auto-platform']}]);
});

test('automatic learning is the rendered default and submits only explicitly selected hosts without a fleet port union',async()=>{
 const env=await workspace('traffic',{mode:'entra',role:'admin'});await env.click('learn');const html=env.element('#modal-content').innerHTML;
 assert.match(html,/name="selection_mode"/);assert.match(html,/value="discovered" selected/);assert.match(html,/Loopback-only listeners are excluded/);assert.match(html,/name="ports" value=""/);assert.doesNotMatch(html,/name="ports"[^>]*required/);assert.match(html,/Each endpoint can run one discovery session at a time/);
 const form=renderedForm(env,'learning-form',{server_ids:['host-1'],selection_mode:'discovered',ports:'22/tcp, 80/tcp',duration:'15',unit:'60'});
 await submitRendered(env,form);const request=mutations(env).find(item=>item.url==='/api/v1/learning');assert.ok(request);assert.deepEqual(JSON.parse(request.options.body),{server_ids:['host-1'],selection_mode:'discovered',duration_seconds:900,policy_action:'observe'});assertCookieMutation(request);
});
test('manual learning is an explicit opt in and a service group copies exact ports for the window',async()=>{
 const env=await workspace('traffic',{mode:'entra',role:'admin'});await env.click('learn');
 env.context.changeEvent={target:{id:'learning-mode',value:'manual'}};assert.equal(env.run('learningChange(changeEvent)'),true);assert.equal(env.element('#learning-manual-fields').hidden,false);assert.equal(env.element('#learning-auto-fields').hidden,true);assert.equal(env.element('#learning-ports').required,true);
 env.context.changeEvent={target:{id:'learning-service-group',value:'web-ports'}};env.run('learningChange(changeEvent)');assert.equal(env.element('#learning-ports').value,'443/tcp, 8443/tcp');
 const form=renderedForm(env,'learning-form',{server_ids:['host-1'],selection_mode:'manual',ports:env.element('#learning-ports').value,duration:'1',unit:'3600'});
 await submitRendered(env,form);const request=mutations(env).find(item=>item.url==='/api/v1/learning');assert.deepEqual(JSON.parse(request.options.body),{server_ids:['host-1'],selection_mode:'manual',duration_seconds:3600,policy_action:'observe',ports:[{port:443,protocol:'tcp'},{port:8443,protocol:'tcp'}]});assertCookieMutation(request);
});
test('learning validates explicit hosts, duration and ports and new scopes require typed capture agents',async()=>{
 const env=await workspace('traffic',{mode:'entra',role:'admin'});env.run('state.data.servers[0].capabilities=[]');await env.click('learn');assert.match(env.element('#modal-content').innerHTML,/Agent upgrade required/);
 const form=renderedForm(env,'learning-form',{server_ids:[],selection_mode:'discovered',duration:'1',unit:'3600'});await submitRendered(env,form);assert.equal(mutations(env).length,0);assert.match(env.element('#form-error').textContent,/Select at least one/);
 form.values.server_ids=['host-1'];await submitRendered(env,form);assert.equal(mutations(env).length,0);assert.match(env.element('#form-error').textContent,/Upgrade these agents to start discovery: lab-api/);
 form.values.selection_mode='manual';form.values.ports='2022/tcp';await submitRendered(env,form);assert.equal(mutations(env).length,0);assert.match(env.element('#form-error').textContent,/Upgrade these agents to start discovery: lab-api/);
 env.run('state.data.servers[0].capabilities.push("traffic_capture_v1")');
 form.values.selection_mode='manual';form.values.ports='';await submitRendered(env,form);assert.equal(mutations(env).length,0);assert.match(env.element('#form-error').textContent,/exact ports/);
 form.values.ports='2022/tcp';form.values.duration='0';await submitRendered(env,form);assert.equal(mutations(env).length,0);assert.match(env.element('#form-error').textContent,/1 minute and 7 days/);
 form.values.duration='1';await submitRendered(env,form);const request=mutations(env).find(item=>item.url==='/api/v1/learning');assert.equal(JSON.parse(request.options.body).selection_mode,'manual');
});
test('cached listener preview is requested again for each changed endpoint selection and stays host specific',async()=>{
 const secondHost={...host,id:'host-2',hostname:'db-two',listeners:[{port:5432,protocol:'tcp',address:'0.0.0.0'}]};
 const env=await workspace('traffic',{mode:'entra',role:'admin',responses:{'POST /api/v1/learning/preview':options=>{const ids=JSON.parse(options.body).server_ids;return {message:'Cached inventory preview. Start learning requests a fresh scan on every selected server.',servers:ids.map(id=>({server_id:id,hostname:id==='host-1'?'api-one':'db-two',ports:id==='host-1'?[{port:2022,protocol:'tcp'},{port:8080,protocol:'tcp'}]:[{port:5432,protocol:'tcp'}],supported:true,offline:id==='host-2',freshness:'cached_preview',last_discovery_at:'2026-10-30T10:00:00Z'}))};}}});
 env.run(`state.data.servers.push(${JSON.stringify(secondHost)})`);await env.click('learn');const form=renderedForm(env,'learning-form',{server_ids:['host-1'],duration:'1',unit:'3600'});form.values.server_ids=['host-1'];
 await env.run('refreshLearningPreview()');let preview=env.element('#learning-preview').innerHTML;assert.match(preview,/api-one/);assert.match(preview,/2022\/tcp/);assert.match(preview,/8080\/tcp/);assert.doesNotMatch(preview,/db-two|5432/);assert.match(preview,/Cached preview/);assert.match(preview,/fresh scan/);
 form.values.server_ids=['host-2'];await env.run('refreshLearningPreview()');preview=env.element('#learning-preview').innerHTML;assert.match(preview,/db-two/);assert.match(preview,/5432\/tcp/);assert.doesNotMatch(preview,/api-one|8080|2022/);assert.match(preview,/Offline.*awaiting connection/);
 const requests=mutations(env);assert.deepEqual(requests.map(request=>JSON.parse(request.options.body).server_ids),[['host-1'],['host-2']]);assert.equal(requests.every(request=>request.url==='/api/v1/learning/preview'),true);requests.forEach(assertCookieMutation);
 form.values.server_ids=[];await env.run('refreshLearningPreview()');assert.match(env.element('#learning-preview').innerHTML,/Select endpoints/);assert.equal(mutations(env).length,2,'clearing all hosts clears preview without an invalid network call');
});
test('per-host session state reports pending, error, empty and frozen listener scopes without cross-host ports',async()=>{
 const env=await workspace('traffic');const a={...host,hostname:'api-one'},b={...host,id:'host-2',hostname:'db-two'};
 env.context.session={selection_mode:'discovered',server_ids:['host-1','host-2'],server_ports:{'host-1':[{port:2022,protocol:'tcp'},{port:8080,protocol:'tcp'}],'host-2':[{port:5432,protocol:'tcp'}]},ports:[{port:2022,protocol:'tcp'},{port:8080,protocol:'tcp'},{port:5432,protocol:'tcp'}],discovery_pending_server_ids:[],discovery_results:{'host-1':{status:'ready'},'host-2':{status:'ready'}}};env.context.testHost=a;let html=env.run('learningHostSessionHTML(session,testHost)');assert.match(html,/2022\/tcp, 8080\/tcp/);assert.doesNotMatch(html,/5432/);assert.match(html,/Ready.*awaiting collector/);
 env.context.testHost=b;html=env.run('learningHostSessionHTML(session,testHost)');assert.match(html,/5432\/tcp/);assert.doesNotMatch(html,/8080|2022/);
 env.run('session.discovery_pending_server_ids=["host-2"];session.server_ports["host-2"]=[];session.discovery_results["host-2"]={status:"pending"}');html=env.run('learningHostSessionHTML(session,testHost)');assert.match(html,/Fresh discovery pending/);assert.doesNotMatch(html,/>Collecting</);
 env.run('session.discovery_results["host-2"]={status:"error",error:"scan <failed>"}');html=env.run('learningHostSessionHTML(session,testHost)');assert.match(html,/Discovery error/);assert.match(html,/scan &lt;failed&gt;/);
 env.run('session.discovery_pending_server_ids=[];session.discovery_results["host-2"]={status:"no_listeners"}');html=env.run('learningHostSessionHTML(session,testHost)');assert.match(html,/No network listeners/);
});
test('Read Only cannot open, preview or submit learning and cookie sessions require CSRF',async()=>{
 const env=await workspace('traffic',{mode:'entra',role:'read_only'});env.element('#modal-content').innerHTML='unchanged';await env.click('learn');assert.equal(env.element('#modal-content').innerHTML,'unchanged');await env.run('refreshLearningPreview()');
 const form=env.element('#learning-form');form.id='learning-form';form.values={server_ids:['host-1'],selection_mode:'discovered',duration:'1',unit:'3600'};await submitRendered(env,form);assert.equal(mutations(env).length,0);assert.match(env.element('#form-error').textContent,/Read Only/);
 const missing=await workspace('traffic',{mode:'entra',identity:{role:'admin',demo:false,auth_type:'session',user:{id:'admin'}}});await missing.click('learn');const missingForm=renderedForm(missing,'learning-form',form.values);await submitRendered(missing,missingForm);assert.equal(mutations(missing).length,0);assert.match(missing.element('#form-error').textContent,/fresh sign-in/);
});

test('a delayed cached preview cannot replace the latest selected-host preview',async()=>{
 let releaseFirst;const firstResult=new Promise(resolve=>{releaseFirst=resolve;});let previewCalls=0;
 const env=await workspace('traffic',{mode:'entra',role:'admin',responses:{'POST /api/v1/learning/preview':()=>++previewCalls===1?firstResult:{servers:[{server_id:'host-2',hostname:'latest-db',ports:[{port:5432,protocol:'tcp'}],supported:true}]}}});
 await env.click('learn');const form=renderedForm(env,'learning-form');form.values.server_ids=['host-1'];
 const earlier=env.run('refreshLearningPreview()');form.values.server_ids=['host-2'];await env.run('refreshLearningPreview()');assert.match(env.element('#learning-preview').innerHTML,/latest-db/);
 releaseFirst({servers:[{server_id:'host-1',hostname:'superseded-api',ports:[{port:8080,protocol:'tcp'}],supported:true}]});await earlier;
 assert.match(env.element('#learning-preview').innerHTML,/latest-db/);assert.doesNotMatch(env.element('#learning-preview').innerHTML,/superseded-api|8080/);
});

test('ended automatic sessions show their frozen snapshot without inheriting a current collector state',async()=>{
 const env=await workspace('traffic');env.context.historySession={selection_mode:'discovered',server_ids:['host-1'],server_ports:{'host-1':[{port:2022,protocol:'tcp'},{port:8080,protocol:'tcp'}]},ports:[{port:443,protocol:'tcp'}],discovery_results:{'host-1':{status:'ready'}}};env.context.historyHost={...host,collector_status:'learning'};
 const html=env.run('learningHostSessionHTML(historySession,historyHost,false)');assert.match(html,/Ended · snapshot ready/);assert.match(html,/2022\/tcp, 8080\/tcp/);assert.doesNotMatch(html,/Collecting|443\/tcp/);
 for(const input of [null,undefined,'']){env.context.missingTimestamp=input;assert.equal(env.run('timestamp(missingTimestamp)'),'Not reported');assert.equal(env.run('age(missingTimestamp)'),'Not reported');}
});

const observedRows=[
 {id:'observed-web',server_id:'host-1',hostname:'lab-api',source_ip:'192.0.2.44',source_cidr:'192.0.2.44/32',port:8443,protocol:'tcp',service:'Billing API',process:'billing-api',count:12,verdicts:['observed'],first_seen:'2026-10-30T11:00:00Z',last_seen:'2026-10-30T11:10:00Z',eligible_for_auto:true},
 {id:'observed-ssh',server_id:'host-1',hostname:'lab-api',source_ip:'192.0.2.55',source_cidr:'192.0.2.55/32',port:2022,protocol:'tcp',service:'SSH',count:3,verdicts:['denied'],first_seen:'2026-10-30T11:00:00Z',last_seen:'2026-10-30T11:10:00Z',eligible_for_auto:false,excluded_reason:'Source requires <review>'}
];
function evidencePage(overrides={}) {return {session_id:'session-1',policy_action:'observe',evidence_revision:'evidence-1',rows:observedRows,total_rows:2,limit:200,offset:0,has_more:false,coverage:{message:'Retained session evidence. Sources are not proof of trust.',servers:[],rate_limited:false},generated_policies:[],...overrides};}
function allowancePreview(overrides={}) {return {status:'reviewed',confirmation_count:0,confirmation_nonce:'maker-nonce',confirmation_phrase:'ALLOW LEARNED EXACT',approval:{mode:'single_admin',stage:'draft',requester:{user_id:'super-self',actor:'entra:super-self'}},session_id:'session-1',id:'access-review-1',digest:'a'.repeat(64),expires_at:new Date(Date.now()+60000).toISOString(),services:[{port:8443,protocol:'tcp',sources:['192.0.2.44/32']}],target_server_ids:['host-1'],targets:[{server_id:'host-1',hostname:'lab-api',services:[{port:8443,protocol:'tcp',sources:['192.0.2.44/32']}],blocked_reasons:[]}],warnings:[],...overrides};}
async function selectObserved(env,id='observed-web') {env.context.observationEvent={target:{name:'recommendation_rows',value:id,checked:true}};env.run('recommendationChange(observationEvent)');}
const learnedPolicy={id:'learned-1',name:'Billing observed clients',session_id:'session-1',server_id:'host-1',hostname:'lab-api',origin:'auto',revision:3,services:[{port:8443,protocol:'tcp',sources:['192.0.2.44/32','192.0.2.45/32']},{port:2022,protocol:'tcp',sources:['192.0.2.55/32']}],status:'blocked',error:'Endpoint opt-in required',auto_updates:true,authority_expires_at:new Date(Date.now()+3600000).toISOString()};
test('auto-allow is separately opted in, requires explicit consent, fresh discovered scope and capable agents',async()=>{
 const env=await workspace('traffic',{mode:'entra',role:'admin'});await env.click('learn');let html=env.element('#modal-content').innerHTML;
 assert.match(html,/name="policy_action"/);assert.match(html,/value="observe" selected/);assert.match(html,/this can include unwanted clients/);assert.match(html,/id="learning-auto-allow-confirmation" hidden/);
 const form=renderedForm(env,'learning-form',{server_ids:['host-1'],selection_mode:'discovered',policy_action:'auto_allow',duration:'1',unit:'3600'});
 await submitRendered(env,form);assert.equal(mutations(env).length,0);assert.match(env.element('#form-error').textContent,/Confirm.*unwanted clients/);
 form.values.auto_allow_confirmed='on';await submitRendered(env,form);assert.equal(mutations(env).length,0);assert.match(env.element('#form-error').textContent,/agent 0.4.0.*lab-api/);
 env.run('state.data.servers[0].capabilities.push("learning_auto_allow_v1")');form.values.selection_mode='manual';form.values.ports='8443/tcp';await submitRendered(env,form);assert.equal(mutations(env).length,0);assert.match(env.element('#form-error').textContent,/automatic per-server service discovery/);
 form.values.selection_mode='discovered';await submitRendered(env,form);const request=mutations(env)[0];assert.deepEqual(JSON.parse(request.options.body),{server_ids:['host-1'],selection_mode:'discovered',duration_seconds:3600,policy_action:'auto_allow',auto_allow_confirmed:true});assertCookieMutation(request);
});
test('observed access remains exact evidence until an explicit source selection, target selection, preview and apply',async()=>{
 const env=await workspace('traffic',{mode:'entra',role:'admin',responses:{'/api/v1/learning/session-1/recommendations?limit=200&offset=0':evidencePage(),'POST /api/v1/learning/session-1/recommendations/preview':allowancePreview(),'POST /api/v1/learning/session-1/recommendations/apply':{pending_approval:false,policies:[learnedPolicy]}}});
 await env.click('recommendation-open',{id:'session-1'});const html=env.element('#modal-content').innerHTML;
 assert.match(html,/192.0.2.44/);assert.match(html,/8443\/tcp/);assert.match(html,/2022\/tcp/);assert.match(html,/Source requires &lt;review&gt;/);assert.doesNotMatch(html,/<review>/);assert.doesNotMatch(html,/name="recommendation_server_ids"[^>]*checked/);assert.match(html,/future group members are excluded/);assert.equal(mutations(env).length,0);
 const form=renderedForm(env,'recommendation-form',{name:'Reviewed billing clients',target_type:'servers',recommendation_server_ids:['host-1']});
 await submitRendered(env,form);assert.equal(mutations(env).length,0);assert.match(env.element('#form-error').textContent,/Select at least one observed/);
 await selectObserved(env);form.values.recommendation_server_ids=[];await submitRendered(env,form);assert.equal(mutations(env).length,0);assert.match(env.element('#form-error').textContent,/Select at least one target server/);
 form.values.recommendation_server_ids=['host-1'];await submitRendered(env,form);let requests=mutations(env);assert.equal(requests.length,1);assert.deepEqual(JSON.parse(requests[0].options.body),{row_ids:['observed-web'],server_ids:['host-1'],group_ids:[],name:'Reviewed billing clients',expected_evidence_revision:'evidence-1'});assertCookieMutation(requests[0]);
 const preview=env.element('#recommendation-preview').innerHTML;assert.match(preview,/8443\/tcp/);assert.match(preview,/192.0.2.44\/32/);assert.doesNotMatch(preview,/192.0.2.55|2022\/tcp/);assert.match(preview,/Only an agent verification report confirms/);
 await env.click('recommendation-apply');requests=mutations(env);assert.equal(requests.length,2);assert.equal(requests[1].url,'/api/v1/learning/session-1/recommendations/apply');assert.deepEqual(JSON.parse(requests[1].options.body),{preview_id:'access-review-1',digest:'a'.repeat(64),confirmation_nonce:'maker-nonce',confirm:true});assertCookieMutation(requests[1]);assert.equal(env.requests.some(request=>request.url.includes('/policy-rollouts')),false);assert.equal(env.run('state.currentRecommendation'),null);
});
test('recommendation pagination preserves selections only for the same evidence revision and targets groups explicitly',async()=>{
 const env=await workspace('traffic',{mode:'entra',role:'admin',responses:{'/api/v1/learning/session-1/recommendations?limit=200&offset=0':evidencePage({has_more:true,total_rows:201}),'/api/v1/learning/session-1/recommendations?limit=200&offset=200':evidencePage({rows:[{...observedRows[0],id:'page-two',source_ip:'198.51.100.9'}],offset:200,total_rows:201}),'POST /api/v1/learning/session-1/recommendations/preview':allowancePreview()}});
 groupFixtures(env);await env.click('recommendation-open',{id:'session-1'});await selectObserved(env);const form=renderedForm(env,'recommendation-form',{name:'Reviewed group access',target_type:'groups',recommendation_group_ids:['custom-finance']});
 await env.click('recommendation-page',{offset:'200'});assert.equal(env.run('state.currentRecommendation.selection.size'),1);assert.match(env.element('#modal-content').innerHTML,/Showing 201–201 of 201/);await selectObserved(env,'page-two');
 await submitRendered(env,form);const request=mutations(env)[0];assert.deepEqual(JSON.parse(request.options.body).group_ids,['custom-finance']);assert.deepEqual(JSON.parse(request.options.body).server_ids,[]);assert.deepEqual(JSON.parse(request.options.body).row_ids,['observed-web','page-two']);
 env.context.apiResponses['/api/v1/learning/session-1/recommendations?limit=200&offset=200']=evidencePage({evidence_revision:'evidence-2',rows:[],offset:200});await env.click('recommendation-refresh');assert.equal(env.run('state.currentRecommendation.selection.size'),0);assert.equal(env.run('state.currentRecommendation.preview'),null);assert.match(env.element('#modal-content').innerHTML,/Evidence changed/);
});
test('changed or expired recommendation reviews cannot apply and stale server replies require fresh evidence',async()=>{
 const env=await workspace('traffic',{mode:'entra',role:'admin',responses:{'/api/v1/learning/session-1/recommendations?limit=200&offset=0':evidencePage(),'POST /api/v1/learning/session-1/recommendations/preview':allowancePreview(),'POST /api/v1/learning/session-1/recommendations/apply':{responseStatus:409,data:{error:'Evidence or target membership changed'}}}});
 await env.click('recommendation-open',{id:'session-1'});await selectObserved(env);const form=renderedForm(env,'recommendation-form',{name:'Review access',target_type:'servers',recommendation_server_ids:['host-1']});await submitRendered(env,form);
 form.values.name='Changed after preview';await env.click('recommendation-apply');assert.equal(mutations(env).length,1);assert.match(env.element('#form-error').textContent,/Preview the current/);
 await submitRendered(env,form);env.run('state.currentRecommendation.preview.expires_at="2000-01-01T00:00:00Z"');await env.click('recommendation-apply');assert.equal(mutations(env).length,2);
 await submitRendered(env,form);await env.click('recommendation-apply');assert.equal(mutations(env).length,4);assert.equal(env.run('state.currentRecommendation.preview'),null);assert.equal(env.run('state.activeLearningApproval'),null);assert.match(env.element('#form-error').textContent,/Evidence or target membership changed/);await env.click('recommendation-apply');assert.equal(mutations(env).length,4);
});
test('Read Only can inspect and export evidence but cannot preview, apply or edit learned allowances',async()=>{
 const env=await workspace('traffic',{mode:'entra',role:'read_only',responses:{'/api/v1/learning/session-1/recommendations?limit=200&offset=0':evidencePage()}});
 await env.click('recommendation-open',{id:'session-1'});assert.match(env.element('#modal-content').innerHTML,/192.0.2.44/);assert.match(env.element('#modal-content').innerHTML,/Export all observed pairs/);assert.doesNotMatch(env.element('#modal-content').innerHTML,/recommendation-target-type|data-action="recommendation-apply"/);
 await env.click('recommendation-apply');await env.click('learned-policy-edit',{id:'learned-1'});await env.click('learned-policy-remove-confirm',{id:'learned-1'});await env.listeners.submit.at(-1)({preventDefault(){},target:{id:'recommendation-form',values:{}}});assert.equal(mutations(env).length,0);
 await env.click('recommendation-export',{id:'session-1'});const request=env.requests.find(request=>request.url.endsWith('/export.csv'));assert.ok(request);assert.equal(request.options.credentials,'same-origin');assert.equal(request.options.headers.Authorization,undefined);assert.equal(request.options.headers['X-CSRF-Token'],undefined);
});
test('CSV export carries bearer auth only in explicit token mode and never exports the visible page alone',async()=>{
 const env=await workspace('traffic',{mode:'tokens',role:'admin',storage:{'segment-token':'role-token'}});await env.click('recommendation-export',{id:'session/one'});const request=env.requests.find(request=>request.url.includes('/export.csv'));assert.equal(request.url,'/api/v1/learning/session%2Fone/export.csv');assert.equal(request.options.headers.Authorization,'Bearer role-token');assert.equal(request.url.includes('limit='),false);assert.equal(mutations(env).length,0);
});
test('read-only inventory and policy exports send complete current scopes with CSRF',async()=>{
 const csv={headers:{'Content-Type':'text/csv; charset=utf-8'},csvText:'hostname,listening_port\r\nlab-api,8443\r\n'};
 const env=await workspace('servers',{mode:'entra',role:'read_only',responses:{
  'POST /api/v1/servers/export.csv':csv,
  'POST /api/v1/policies/export.csv':csv
 }});
 env.run('state.filters.application=["billing"];state.filters.ports=["8443/tcp"];render()');
 assert.match(env.element('#view-content').innerHTML,/data-action="inventory-export"/);
 await env.click('inventory-export');
 let request=env.requests.findLast(({url})=>url==='/api/v1/servers/export.csv');
 assert.deepEqual(JSON.parse(request.options.body),{server_ids:['host-1']});
 assert.equal(request.options.headers['X-CSRF-Token'],'session-csrf-fixture');
 assert.equal(env.element('created:a').download,'prthak-servers.csv');
 env.run('navigate("policies");state.policyShowUnusedZones=true;render()');
 for(const kind of ['discovered','managed','learned']){
  assert.match(env.element('#view-content').innerHTML,new RegExp('data-action="policy-catalogue-export" data-kind="'+kind+'"'));
  await env.click('policy-catalogue-export',{kind});
  request=env.requests.findLast(({url})=>url==='/api/v1/policies/export.csv');
  const body=JSON.parse(request.options.body);
  assert.deepEqual(body.server_ids,['host-1']);
  assert.deepEqual(body.ports,['8443/tcp']);
  assert.equal(body.kind,kind);
  assert.equal(body.limit,undefined);
  assert.equal(body.offset,undefined);
  if(kind==='discovered')assert.equal(body.zone_usage,'all');
  assert.equal(env.element('created:a').download,'prthak-'+kind+'-policies.csv');
 }
});
function compactSession(id,extra={}){return {id,name:'Window '+id,status:'active',summary_only:true,server_ids:['host-1'],server_count:1,selection_mode:'discovered',policy_action:'observe',starts_at:new Date(Date.now()-60000).toISOString(),expires_at:new Date(Date.now()+600000).toISOString(),discovery_pending_count:0,discovery_error_count:0,discovery_no_listeners_count:0,...extra};}
function compactSessionPage(items,extra={}){return {items,total:14,active_total:9,offset:0,limit:6,has_more:true,...extra};}
function compactOverview(items,extra={}){const page=compactSessionPage(items,extra);return {...fixture,learning_sessions:items,learning_session_pagination:{...page,items:undefined},stats:{active_learning:page.active_total}};}
test('discovery tabs show only their running sessions and load separate bounded history on demand',async()=>{
 const runningTraffic=compactSession('traffic-live',{purpose:'traffic',traffic_collection_mode:'sampled'});
 const runningPolicy=compactSession('policy-live',{policy_action:'auto_allow'});
 const endedTraffic=Array.from({length:20},(_,i)=>compactSession('traffic-ended-'+i,{purpose:'traffic',status:'stopped'}));
 const endedPolicy=compactSession('policy-ended',{status:'stopped'});
 for(const catalogue of [false,true]){
  const overview=compactOverview([runningTraffic,runningPolicy],{total:30});
  overview.meta={...overview.meta,traffic_query_v1:catalogue};
  const now=new Date().toISOString();
  const responses={
   '/api/v1/overview':overview,
   '/api/v1/learning?limit=20&offset=0&purpose=traffic&active_only=true':compactSessionPage([runningTraffic,runningPolicy],{purpose:'traffic',active_only:true,limit:20,total:1,has_more:false}),
   '/api/v1/learning?limit=20&offset=0&purpose=traffic':compactSessionPage([...endedTraffic.slice(0,19),endedPolicy],{purpose:'traffic',limit:20,total:30}),
   '/api/v1/learning?limit=20&offset=0&purpose=policy&active_only=true':compactSessionPage([runningPolicy,runningTraffic],{purpose:'policy',active_only:true,limit:20,total:1,has_more:false}),
   '/api/v1/learning?limit=20&offset=0&purpose=policy':compactSessionPage([endedPolicy,endedTraffic[0]],{purpose:'policy',limit:20,total:1,has_more:false}),
   'POST /api/v1/flows/query':options=>({purpose:'traffic',items:[],total:0,endpoint_count:0,counts_by_unit:{connections:0,packets:0,log_records:0},limit:50,offset:0,has_more:false,window_seconds:JSON.parse(options.body).window_seconds,as_of:now,from_time:now,coverage:'None reported.',filter_before_pagination:true})
  };
  const env=await workspace('traffic',{mode:'entra',role:'admin',responses});
  const html=()=>env.element('#view-content').innerHTML,historyReads=()=>env.requests.filter(row=>row.url.includes('/learning?limit=20')&&!row.url.includes('active_only'));
  await new Promise(setImmediate);
  assert.match(html(),/aria-expanded="false" aria-controls="traffic-learning-sessions"/);
  assert.match(html(),/Window traffic-live[\s\S]*View observed traffic[\s\S]*Stop collection/);
  assert.doesNotMatch(html(),/Window policy-|Review policy recommendations|policy-learning-sessions|Window traffic-ended/);
  assert.match(env.element('#learn-button').innerHTML,/Discover traffic/);
  assert.equal(historyReads().length,0);
  await env.click('traffic-learning-sessions');
  assert.match(html(),/Latest|latest 20 traffic sessions/);
  assert.match(html(),/Window traffic-ended-18/);
  assert.doesNotMatch(html(),/Window traffic-ended-19|Window policy-ended|Previous sessions|Next sessions|id="traffic-history-purpose"/);
  assert.equal(historyReads().length,1);
  await env.run('load({quiet:true})');await new Promise(setImmediate);
  assert.match(html(),/Window traffic-ended-18/);
  env.run('state.search="missing-endpoint";render()');
  assert.match(html(),/No matching ended sessions in recent history/);
  env.run('state.search="";navigate("policies")');await new Promise(setImmediate);
  assert.match(html(),/Window policy-live[\s\S]*Review policy recommendations[\s\S]*Stop policy discovery/);
  assert.doesNotMatch(html(),/Window traffic-|View observed traffic|Window policy-ended/);
  assert.match(env.element('#learn-button').innerHTML,/Discover policy/);
  await env.click('policy-learning-sessions');
  assert.match(html(),/Window policy-ended/);
  assert.doesNotMatch(html(),/Window traffic-ended/);
  assert.deepEqual(mutations(env).filter(row=>row.url.startsWith('/api/v1/learning')),[]);
 }
});
test('server drawer has independent paged history and returning to page one keeps the fresh GET result',async()=>{
 const fleet=[compactSession('fleet')],first=Array.from({length:6},(_,i)=>compactSession('host-first-'+i)),second=[compactSession('host-second')],server={...host,learning_sessions:first,learning_session_pagination:{total:7,active_total:4,limit:6,offset:0,has_more:true}},env=await workspace('traffic',{mode:'entra',role:'read_only',responses:{'/api/v1/overview':compactOverview(fleet),'/api/v1/servers/host-1':server,'/api/v1/learning?limit=6&offset=6&server_id=host-1':compactSessionPage(second,{total:7,offset:6,has_more:false}),'/api/v1/learning?limit=6&offset=0&server_id=host-1':compactSessionPage([compactSession('fresh-first')],{total:1,has_more:false})}});
 await env.click('server',{id:'host-1'});await env.click('firewall-drawer-tab',{tab:'services'});assert.match(env.element('#server-drawer').innerHTML,/Loaded 6 · 1–6 of 7 sessions/);await env.click('learning-session-page',{serverId:'host-1',offset:'6'});assert.match(env.element('#server-drawer').innerHTML,/Loaded 1 · 7–7 of 7 sessions/);assert.match(env.element('#server-drawer').innerHTML,/Window host-second/);assert.equal(env.run('learningSessionPage().offset'),0);
 await env.click('learning-session-page',{serverId:'host-1',offset:'0'});assert.match(env.element('#server-drawer').innerHTML,/Window fresh-first/);assert.doesNotMatch(env.element('#server-drawer').innerHTML,/Window host-first-0/);assert.equal(mutations(env).length,0);
});
test('large compact membership stays exact while frozen host ports and failures load as a bounded separate page',async()=>{
 const ids=Array.from({length:20000},(_,i)=>'endpoint-'+i);ids[19999]='host-1';const session=compactSession('large',{purpose:'traffic',server_ids:ids,server_count:20000,discovery_pending_count:1}),page={session_id:'large',items:[{server_id:'host-1',ports:[{port:443,protocol:'tcp'}],status:'ready'},{server_id:'endpoint-1',ports:[{port:5432,protocol:'tcp'}],status:'ready'},{server_id:'endpoint-2',ports:[],status:'pending',pending:true},{server_id:'endpoint-3',ports:[],status:'error',error:'<script>not executable</script>'}],total:20000,limit:50,offset:19950,has_more:false},env=await workspace('traffic',{mode:'entra',role:'read_only',responses:{'/api/v1/overview':compactOverview([session],{total:1,has_more:false}),'/api/v1/learning?limit=20&offset=0&purpose=traffic&active_only=true':compactSessionPage([session],{purpose:'traffic',active_only:true,limit:20,total:1,has_more:false}),'/api/v1/learning/large/hosts?limit=50&offset=19950':page}});
 await env.click('traffic-learning-sessions');const html=env.element('#view-content').innerHTML;assert.match(html,/20[ ,]000 endpoints/);assert.match(html,/Window large/);assert.doesNotMatch(html,/No ports selected/);env.run('globalThis.nameCalls=0;globalThis.originalServerName=serverName;serverName=()=>{nameCalls++;return "host"}');assert.equal(env.run('sessionTitle({server_ids:Array.from({length:20000},(_,i)=>String(i))})'),'20000 endpoints');assert.equal(env.run('nameCalls'),0);env.run('serverName=originalServerName');
 await env.click('learning-host-scope',{id:'large',serverId:'host-1'});const scope=env.element('#modal-content').innerHTML;assert.match(scope,/19951–19954 of 20[ ,]000 endpoints/);assert.match(scope,/not proof that traffic was collected or firewall allowances applied/);const rows=scope.match(/<article class="learning-session-host">[\s\S]*?<\/article>/g);assert.match(rows[0],/443\/tcp/);assert.doesNotMatch(rows[0],/5432\/tcp/);assert.match(rows[1],/5432\/tcp/);assert.doesNotMatch(rows[1],/443\/tcp/);assert.match(rows[2],/Fresh discovery pending/);assert.match(rows[3],/&lt;script&gt;/);assert.doesNotMatch(scope,/<script>/);assert.match(rows[0],/data-server-id="host-1"/);assert.equal(mutations(env).length,0);
});
test('late host-scope requests cannot overwrite a different modal and failures never imply empty scope',async()=>{
 let resolveScope;const delayed=new Promise(resolve=>{resolveScope=resolve}),session=compactSession('slow'),env=await workspace('traffic',{responses:{'/api/v1/overview':compactOverview([session],{total:1,has_more:false}),'/api/v1/learning/slow/hosts?limit=50&offset=0':()=>delayed,'/api/v1/learning/slow/hosts?limit=50&offset=50':{responseStatus:503,data:{error:'Discovery page unavailable'}}}});
 const pending=env.click('learning-host-scope',{id:'slow'});await new Promise(setImmediate);env.run('showModal("Different operation","<p>Keep this draft</p>")');resolveScope({session_id:'slow',items:[],total:0,limit:50,offset:0,has_more:false});await pending;assert.equal(env.element('#modal-title').textContent,'Different operation');assert.match(env.element('#modal-content').innerHTML,/Keep this draft/);
 await env.click('learning-host-page',{id:'slow',offset:'50'});assert.match(env.element('#modal-content').innerHTML,/Discovery page unavailable/);assert.match(env.element('#modal-content').innerHTML,/No empty or successful host scope was inferred/);assert.doesNotMatch(env.element('#modal-content').innerHTML,/No endpoints on this scope page/);
});
test('endpoint CSV export forwards exact encoded membership filter with existing authenticated transport',async()=>{
 for(const mode of ['entra','tokens']){const env=await workspace('traffic',{mode,role:'read_only',storage:mode==='tokens'?{'segment-token':'reader-token'}:{}});await env.click('recommendation-export',{id:'session/one',serverId:'host/one'});const request=env.requests.find(request=>request.url.includes('/export.csv'));assert.equal(request.url,'/api/v1/learning/session%2Fone/export.csv?server_id=host%2Fone');assert.equal(request.options.credentials,'same-origin');assert.equal(request.options.headers.Authorization,mode==='tokens'?'Bearer reader-token':undefined);assert.equal(request.options.headers['X-CSRF-Token'],undefined);assert.equal(mutations(env).length,0);}
});
function catalogueSummary(value){return {...value,summary_only:true,service_count:value.services.length,source_count:value.services.reduce((sum,row)=>sum+(row.sources || []).length,0),services:value.services.map(({sources,...row})=>({...row,source_count:(sources || []).length,sources_omitted:true}))};}
function cataloguePage(items,extra={}){return {items,total:53,limit:20,offset:0,next_offset:items.length,has_more:true,summary_only:true,...extra};}
function catalogueOverview(managed=[catalogueSummary(policy)],learned=[catalogueSummary(learnedPolicy)]){return {...fixture,policies:managed,learning_policies:learned,policy_pagination:cataloguePage(managed),learning_policy_pagination:cataloguePage(learned)};}
test('policy catalogues page independently using byte-budget next offsets and keep navigation summaries honest',async()=>{
 const first=catalogueSummary(policy),next=catalogueSummary({...policy,id:'later-policy',name:'Later managed intent'}),lp=catalogueSummary(learnedPolicy),env=await workspace('policies',{mode:'entra',role:'read_only',responses:{'/api/v1/overview':catalogueOverview([first],[lp]),'POST /api/v1/policies/query':options=>{const {offset}=JSON.parse(options.body);return cataloguePage(offset?[next]:[first],{offset,next_offset:offset+1});},'POST /api/v1/learning-policies/query':options=>{const {offset}=JSON.parse(options.body);return cataloguePage([{...lp,id:'later-learned',name:'Later learned intent'}],{offset,next_offset:offset+1});}}});
 let html=env.element('#view-content').innerHTML;assert.match(html,/Loaded 1 · 1–1 of 53 matching managed policies/);assert.match(html,/1 managed policies on loaded page/);assert.match(html,/literal source CIDRs/);assert.match(html,/data-action="policy-catalogue-detail"/);assert.doesNotMatch(html,/No static source addresses|No allowed sources|192\.0\.2\.44/);
 await env.click('policy-catalogue-page',{kind:'managed',offset:'1'});html=env.element('#view-content').innerHTML;assert.match(html,/Loaded 1 · 2–2 of 53 matching managed policies/);assert.match(html,/Later managed intent/);assert.equal(env.run('policyCataloguePage("learned").offset'),0);assert.match(html,/data-kind="managed" data-offset="0"/);await env.run('load({quiet:true})');assert.equal(env.run('policyCataloguePage("managed").offset'),1);
 await env.click('policy-catalogue-page',{kind:'learned',offset:'1'});assert.match(env.element('#view-content').innerHTML,/Later learned intent/);assert.equal(env.run('policyCataloguePage("managed").offset'),1);assert.equal(mutations(env).length,0);for(const request of env.requests.filter(item=>item.url.endsWith('/query')))assert.equal(request.options.headers['X-CSRF-Token'],'session-csrf-fixture');
});
test('combined application DC group and port filters query the complete catalogue before paging',async()=>{
 const seen=[],later=catalogueSummary({...policy,id:'policy-21',name:'Matching beyond first twenty'}),env=await workspace('policies',{mode:'entra',role:'read_only',responses:{'/api/v1/overview':catalogueOverview(),'POST /api/v1/policies/query':options=>{seen.push(JSON.parse(options.body));return cataloguePage([later],{total:1,has_more:false});},'POST /api/v1/learning-policies/query':()=>cataloguePage([],{total:0,has_more:false})}});groupFixtures(env);env.run('state.data.servers[0].listeners=[{port:2022,protocol:"tcp"}];state.filters.application=["billing"];state.filters.dc=["loc-1"];state.filters.groups=["saved-billing"];state.filters.ports=["8443/tcp"];state.search="lab";render()');await new Promise(setImmediate);
 assert.deepEqual(seen.at(-1),{server_ids:['host-1'],search_server_ids:['host-1'],ports:['8443/tcp'],search:'lab',limit:20,offset:0});assert.match(env.element('#view-content').innerHTML,/Matching beyond first twenty/);assert.match(env.element('#view-content').innerHTML,/1–1 of 1 matching managed policies/);assert.match(env.element('#view-content').innerHTML,/select the full catalogue before pagination/);assert.equal(mutations(env).length,0);
});
test('ordinary policy editing waits for fresh exact sources and saves their expected revision',async()=>{
 let release;const reply=new Promise(resolve=>{release=resolve}),exact={...policy,revision:9,services:[{port:8443,protocol:'tcp',sources:['198.51.100.77/32'],source_selector:{}}]},env=await workspace('policies',{mode:'entra',role:'admin',responses:{'/api/v1/overview':catalogueOverview(),'/api/v1/policies/policy-1':()=>reply}});const pending=env.click('edit-policy',{id:'policy-1'});await new Promise(setImmediate);assert.doesNotMatch(env.element('#modal-content').innerHTML,/<form|name="rule_sources"/);release(exact);await pending;assert.match(env.element('#modal-content').innerHTML,/198\.51\.100\.77\/32/);assert.doesNotMatch(env.element('#modal-content').innerHTML,/value="80"/);
 const form=renderedForm(env,'policy-form',{name:'Exact edit',target_type:'all',mode:'monitor'});form.querySelectorAll=selector=>selector==='.rule-row'?[policyRow({rule_type:'port',rule_port:'8443',rule_protocol:'tcp',rule_sources:'198.51.100.77/32',rule_selector:'',rule_location_id:''})]:[];await submitRendered(env,form);const request=mutations(env)[0];assert.equal(request.options.method,'PUT');assert.equal(JSON.parse(request.options.body).expected_revision,9);assert.deepEqual(JSON.parse(request.options.body).services[0].sources,['198.51.100.77/32']);assertCookieMutation(request);
});
test('summary, incomplete, mismatched or failed exact detail cannot open an editable allowlist',async()=>{
 for(const kind of ['managed','learned'])for(const bad of ['summary','omitted','wrong-id','failure']){const original=kind==='managed'?policy:learnedPolicy,id=original.id,summary=catalogueSummary(original),data=bad==='summary'?summary:bad==='omitted'?{...original,services:original.services.map(({sources,...row})=>row)}:bad==='wrong-id'?{...original,id:'different-policy'}:{responseStatus:503,data:{error:'Exact configuration unavailable'}},path=kind==='managed'?'/api/v1/policies/':'/api/v1/learning-policies/',env=await workspace('policies',{mode:'entra',role:'admin',responses:{'/api/v1/overview':catalogueOverview(),[path+id]:data}});await env.click(kind==='managed'?'edit-policy':'learned-policy-edit',{id});const html=env.element('#modal-content').innerHTML;assert.doesNotMatch(html,/<form|name="rule_sources"|name="learned_sources_/);assert.match(html,/No editable or approvable allowlist was inferred/);assert.equal(env.run('state.activePolicyEditor'),null);assert.equal(mutations(env).length,0);}
});
test('Read Only may fetch exact policy details while edit and removal actions remain unavailable',async()=>{
 const env=await workspace('policies',{mode:'entra',role:'read_only',responses:{'/api/v1/overview':catalogueOverview()}});await env.click('policy-catalogue-detail',{kind:'managed',id:'policy-1'});assert.match(env.element('#modal-content').innerHTML,/Exact saved intent/);assert.match(env.element('#modal-content').innerHTML,/10\.1\.0\.1\/32/);assert.doesNotMatch(env.element('#modal-content').innerHTML,/<form/);await env.click('policy-catalogue-detail',{kind:'learned',id:'learned-1'});assert.match(env.element('#modal-content').innerHTML,/192\.0\.2\.44\/32/);const count=env.requests.length;await env.click('edit-policy',{id:'policy-1'});await env.click('delete-policy',{id:'policy-1'});await env.click('learned-policy-edit',{id:'learned-1'});await env.click('learned-policy-remove-review',{id:'learned-1'});assert.equal(env.requests.length,count);assert.equal(mutations(env).length,0);
});
test('stale exact-policy replies cannot replace another editor or accept an older navigation revision',async()=>{
 let release;const delayed=new Promise(resolve=>{release=resolve}),second={...policy,id:'policy-2',name:'Second exact policy'},env=await workspace('policies',{responses:{'/api/v1/policies/policy-1':()=>delayed,'/api/v1/policies/policy-2':second}});const first=env.click('edit-policy',{id:'policy-1'});await new Promise(setImmediate);await env.click('edit-policy',{id:'policy-2'});release(policy);await first;assert.match(env.element('#modal-content').innerHTML,/Second exact policy/);assert.equal(env.run('state.activePolicyEditor.id'),'policy-2');
 env.context.apiResponses['/api/v1/policies/policy-1']=policy;env.run('state.data.policies[0].revision=2');await env.click('edit-policy',{id:'policy-1'});assert.match(env.element('#modal-content').innerHTML,/changed while its details loaded/);assert.doesNotMatch(env.element('#modal-content').innerHTML,/<form/);
});
test('late catalogue replies preserve unsubmitted filter drafts and cannot replace a newer filter result',async()=>{
 let release;const delayed=new Promise(resolve=>{release=resolve}),env=await workspace('policies',{responses:{'/api/v1/overview':catalogueOverview(),'POST /api/v1/policies/query':options=>{const body=JSON.parse(options.body);return body.ports[0]==='8443/tcp'?delayed:cataloguePage([catalogueSummary({...policy,name:'Current 443 result',services:[{port:443,protocol:'tcp',sources:[],source_selector:{}}]})],{total:1,has_more:false});},'POST /api/v1/learning-policies/query':()=>cataloguePage([],{total:0,has_more:false})}});env.run('state.filters.ports=["8443/tcp"];render()');await new Promise(setImmediate);env.element('#service-filter-input').value='9443';env.run('state.filters.ports=["443/tcp"];render()');env.element('#service-filter-input').value='9443';await new Promise(setImmediate);assert.match(env.element('#view-content').innerHTML,/Current 443 result/);assert.equal(env.element('#service-filter-input').value,'9443');release(cataloguePage([catalogueSummary({...policy,name:'Stale 8443 result'})],{total:1,has_more:false}));await new Promise(setImmediate);assert.match(env.element('#view-content').innerHTML,/Current 443 result/);assert.doesNotMatch(env.element('#view-content').innerHTML,/Stale 8443 result/);assert.equal(env.element('#service-filter-input').value,'9443');
});
test('learned source changes and queued policy-change reviews load exact current source associations',async()=>{
 const plan=allowancePreview({id:'change-exact',kind:'policy_change',policy_id:'learned-1',change:{expected_revision:3,name:learnedPolicy.name,services:learnedPolicy.services,remove:false}}),env=await workspace('policies',{mode:'entra',role:'admin',responses:{'/api/v1/overview':catalogueOverview(),'/api/v1/learning-policies/approvals/change-exact':plan}});await env.click('learned-policy-edit',{id:'learned-1'});let html=env.element('#modal-content').innerHTML;assert.match(html,/name="learned_sources_0" value="192\.0\.2\.44\/32"/);assert.match(html,/name="learned_sources_1" value="192\.0\.2\.55\/32"/);await env.click('recommendation-approval-open',{id:'change-exact'});html=env.element('#modal-content').innerHTML;assert.match(html,/Current services/);assert.match(html,/192\.0\.2\.44\/32/);assert.equal(env.requests.filter(request=>request.url==='/api/v1/learning-policies/learned-1').length,2);
 env.context.apiResponses['/api/v1/learning-policies/learned-1']=catalogueSummary(learnedPolicy);await env.click('recommendation-approval-open',{id:'change-exact'});assert.equal(env.run('state.activeLearningApproval'),null);assert.doesNotMatch(env.element('#modal-content').innerHTML,/<form|Approve exact/);assert.equal(mutations(env).length,0);
});
test('grouped policy summaries keep exact port filters and distinguish dynamic sources from omitted literal CIDRs',async()=>{
 const grouped={...catalogueSummary(policy),services:[{service_group_id:serviceGroup.id,service_group_snapshot:serviceGroup,source_count:0,sources_omitted:true,source_selector:{owner:'finance'},source_group_ids:['source-finance']}]},env=await workspace('policies',{responses:{'/api/v1/overview':catalogueOverview([grouped]),'POST /api/v1/policies/query':()=>cataloguePage([grouped],{total:1,has_more:false}),'POST /api/v1/learning-policies/query':()=>cataloguePage([],{total:0,has_more:false})}});env.run('state.data.groups.push({id:"source-finance",name:"Finance sources",type:"static",server_ids:[]});F.setGroups(state.data.groups);state.filters.ports=["443/tcp"];render()');await new Promise(setImmediate);const html=env.element('#view-content').innerHTML;assert.match(html,/443\/tcp/);assert.match(html,/Web application · r2/);assert.match(html,/0 literal source CIDRs/);assert.match(html,/owner=finance/);assert.match(html,/Source server groups: Finance sources/);assert.doesNotMatch(html,/No static source addresses/);assert.throws(()=>env.run('renderPolicyEditor(policyCataloguePage("managed").items[0],"policy-1")'),/summary cannot populate/);
});
test('learned policies display actual endpoint outcomes separately and source edits keep exact service associations',async()=>{
 const env=await workspace('policies',{mode:'entra',role:'admin'});env.run(`state.data.learning_policies=[${JSON.stringify(learnedPolicy)}];render()`);let html=env.element('#view-content').innerHTML;
 assert.match(html,/Learned allow policies/);assert.match(html,/Billing observed clients/);assert.match(html,/>Blocked</);assert.match(html,/Endpoint opt-in required/);assert.doesNotMatch(html,/Applied · agent verified/);
 await env.click('learned-policy-edit',{id:'learned-1'});assert.match(env.element('#modal-content').innerHTML,/Removed source\/service pairs stay suppressed/);
 const form=renderedForm(env,'learned-policy-form',{name:'Reviewed clients',learned_sources_0:['192.0.2.45/32'],learned_sources_1:[]});await submitRendered(env,form);const request=mutations(env)[0];assert.equal(request.url,'/api/v1/learning-policies/learned-1/change-preview');assert.equal(request.options.method,'POST');assert.deepEqual(JSON.parse(request.options.body),{expected_revision:3,name:'Reviewed clients',services:[{port:8443,protocol:'tcp',sources:['192.0.2.45/32']}]});assertCookieMutation(request);
 env.context.statePolicy={...learnedPolicy,status:'applied',applied_revision:2};assert.match(env.run('learnedPolicyStatus(statePolicy)[0]'),/New revision pending agent/);env.context.statePolicy.applied_revision=3;assert.match(env.run('learnedPolicyStatus(statePolicy)[0]'),/Applied · agent verified/);
});
test('learned policy removal previews the exact displayed revision before requester submission',async()=>{
 const plan=allowancePreview({id:'remove-review',kind:'policy_change',policy_id:'learned-1',change:{expected_revision:3,name:learnedPolicy.name,services:[],remove:true}}),env=await workspace('policies',{mode:'entra',role:'admin',responses:{'POST /api/v1/learning-policies/learned-1/change-preview':plan,'POST /api/v1/learning-policies/learned-1/change-confirm':{pending_approval:true,preview:{...plan,status:'awaiting_second_confirmation',confirmation_count:1,confirmation_nonce:'checker-nonce'}}}});env.run(`state.data.learning_policies=[${JSON.stringify(learnedPolicy)}]`);await env.click('learned-policy-remove-review',{id:'learned-1'});const request=mutations(env)[0];assert.equal(request.url,'/api/v1/learning-policies/learned-1/change-preview');assert.deepEqual(JSON.parse(request.options.body),{expected_revision:3,remove:true});assertCookieMutation(request);const form=renderedForm(env,'learned-policy-form',{});await submitRendered(env,form);assert.equal(mutations(env)[1].url,'/api/v1/learning-policies/learned-1/change-confirm');assert.equal(mutations(env).some(request=>request.options.method==='DELETE'),false);assert.equal(env.run('state.activeLearningApproval.confirmation_count'),1);
});

test('blocked suggestion previews stay reviewable without an apply request and report session policy outcomes',async()=>{
 const blocked=allowancePreview({warnings:['lab-api: management protection incomplete'],targets:[{server_id:'host-1',hostname:'lab-api',services:[{port:8443,protocol:'tcp',sources:['192.0.2.44/32']}],blocked_reasons:['Endpoint <guard> incomplete']}]});
 const env=await workspace('traffic',{mode:'entra',role:'admin',responses:{'/api/v1/learning/session-1/recommendations?limit=200&offset=0':evidencePage({generated_policies:[learnedPolicy]}),'POST /api/v1/learning/session-1/recommendations/preview':blocked}});
 await env.click('recommendation-open',{id:'session-1'});assert.match(env.element('#modal-content').innerHTML,/1 learned allow policies from this session/);assert.match(env.element('#modal-content').innerHTML,/Endpoint opt-in required/);
 await selectObserved(env);const form=renderedForm(env,'recommendation-form',{name:'Guarded review',target_type:'servers',recommendation_server_ids:['host-1']});await submitRendered(env,form);
 assert.match(env.element('#recommendation-preview').innerHTML,/Endpoint &lt;guard&gt; incomplete/);assert.match(env.element('#recommendation-preview').innerHTML,/Resolve the reported blockers/);assert.equal(env.element('[data-action="recommendation-apply"]').disabled,true);await env.click('recommendation-apply');assert.equal(mutations(env).length,1);assert.equal(env.requests.some(request=>request.url.endsWith('/recommendations/apply')),false);
});
test('an absent CSRF secret blocks an otherwise valid recommendation preview before any mutation',async()=>{
 const env=await workspace('traffic',{mode:'entra',identity:{role:'admin',demo:false,auth_type:'session',user:{id:'admin'}},responses:{'/api/v1/learning/session-1/recommendations?limit=200&offset=0':evidencePage()}});
 await env.click('recommendation-open',{id:'session-1'});await selectObserved(env);const form=renderedForm(env,'recommendation-form',{name:'Reviewed clients',target_type:'servers',recommendation_server_ids:['host-1']});await submitRendered(env,form);assert.equal(mutations(env).length,0);assert.match(env.element('#form-error').textContent,/fresh sign-in/);
});
test('a learned policy changed during a removal review requires another review instead of deleting the new revision',async()=>{
 const plan=allowancePreview({id:'stale-removal',kind:'policy_change',policy_id:'learned-1',change:{expected_revision:3,name:learnedPolicy.name,services:[],remove:true}}),env=await workspace('policies',{mode:'entra',role:'admin',responses:{'POST /api/v1/learning-policies/learned-1/change-preview':plan}});env.run(`state.data.learning_policies=[${JSON.stringify(learnedPolicy)}]`);await env.click('learned-policy-remove-review',{id:'learned-1'});const form=renderedForm(env,'learned-policy-form',{});env.run('state.data.learning_policies[0].revision=4');await submitRendered(env,form);assert.equal(mutations(env).length,1);assert.match(env.element('#form-error').textContent,/changed.*Reopen/);
});

test('learned policy removal stays visible as pending or blocked until endpoint verification without offering stale edits',async()=>{
 const env=await workspace('policies',{mode:'entra',role:'admin'});env.context.removingPolicy={...learnedPolicy,removed:true,removal_pending:true,status:'pending',services:[],auto_updates:false};env.run('state.data.learning_policies=[removingPolicy];render()');let html=env.element('#view-content').innerHTML;assert.match(html,/Removal pending agent/);assert.doesNotMatch(html,/data-action="learned-policy-edit"|data-action="learned-policy-remove-review"/);
 env.run('removingPolicy.status="blocked";removingPolicy.error="Endpoint is offline";render()');html=env.element('#view-content').innerHTML;assert.match(html,/Removal blocked/);assert.match(html,/Endpoint is offline/);assert.doesNotMatch(html,/Applied · agent verified/);
 env.run('removingPolicy.removal_pending=false;removingPolicy.status="removed";render()');assert.doesNotMatch(env.element('#view-content').innerHTML,/Billing observed clients/);
});

test('a discovered auto-allow session can limit itself to 443 while leaving other inventory services outside its request',async()=>{
 const env=await workspace('traffic',{mode:'entra',role:'admin'});env.run('state.data.servers[0].capabilities.push("learning_auto_allow_v1");state.data.servers[0].listeners=[{port:22,protocol:"tcp"},{port:443,protocol:"tcp"},{port:80,protocol:"tcp"}]');await env.click('learn');const html=env.element('#modal-content').innerHTML;
 assert.match(html,/Limit to selected ports/);assert.match(html,/name="port_filter" value="" placeholder="443\/tcp" disabled/);assert.match(html,/The agent includes only matching network listeners/);
 const form=renderedForm(env,'learning-form',{server_ids:['host-1'],selection_mode:'discovered',policy_action:'auto_allow',auto_allow_confirmed:'on',port_filter_enabled:'on',port_filter:'443/tcp',ports:'22/tcp, 80/tcp',duration:'1',unit:'3600'});await submitRendered(env,form);
 const request=mutations(env)[0],body=JSON.parse(request.options.body);assert.deepEqual(body,{server_ids:['host-1'],selection_mode:'discovered',duration_seconds:3600,policy_action:'auto_allow',auto_allow_confirmed:true,port_filter:[{port:443,protocol:'tcp'}]});assert.equal(body.ports,undefined);assertCookieMutation(request);assert.equal(body.port_filter.some(port=>[22,80].includes(port.port)),false);
});
test('a discovery port limit validates only when enabled and does not alter manual learning semantics',async()=>{
 const env=await workspace('traffic',{mode:'entra',role:'admin'});await env.click('learn');const form=renderedForm(env,'learning-form',{server_ids:['host-1'],selection_mode:'discovered',port_filter_enabled:'on',port_filter:'',duration:'1',unit:'3600'});
 await submitRendered(env,form);assert.equal(mutations(env).length,0);assert.match(env.element('#form-error').textContent,/1 and 100 exact ports/);
 form.values.port_filter='443-445/tcp';await submitRendered(env,form);assert.equal(mutations(env).length,0);assert.match(env.element('#form-error').textContent,/Ranges are not supported/);
 form.values.port_filter=Array.from({length:101},(_,index)=>(index+1)+'/tcp').join(',');await submitRendered(env,form);assert.equal(mutations(env).length,0);assert.match(env.element('#form-error').textContent,/1 and 100/);
 form.values.port_filter_enabled=null;form.values.port_filter='443/tcp';await submitRendered(env,form);let request=mutations(env).find(item=>item.url==='/api/v1/learning');assert.equal(JSON.parse(request.options.body).port_filter,undefined,'disabled means all newly discovered network listeners');
 await env.click('learn');const manual=renderedForm(env,'learning-form',{server_ids:['host-1'],selection_mode:'manual',port_filter_enabled:'on',port_filter:'443/tcp',ports:'8443/tcp',duration:'1',unit:'3600'});await submitRendered(env,manual);request=mutations(env).filter(item=>item.url==='/api/v1/learning').at(-1);assert.deepEqual(JSON.parse(request.options.body).ports,[{port:8443,protocol:'tcp'}]);assert.equal(JSON.parse(request.options.body).port_filter,undefined);
});
test('cached preview sends the exact port filter and hides unselected host listeners without modifying inventory',async()=>{
 const env=await workspace('traffic',{mode:'entra',role:'admin',responses:{'POST /api/v1/learning/preview':{servers:[{server_id:'host-1',hostname:'web-one',supported:true,ports:[{port:22,protocol:'tcp'},{port:443,protocol:'tcp'},{port:80,protocol:'tcp'}]},{server_id:'host-2',hostname:'other-host',supported:true,ports:[{port:22,protocol:'tcp'}]}]}}});await env.click('learn');const form=renderedForm(env,'learning-form',{selection_mode:'discovered',port_filter_enabled:'on',port_filter:'443/tcp'});form.values.server_ids=['host-1','host-2'];
 await env.run('refreshLearningPreview()');const request=mutations(env)[0];assert.deepEqual(JSON.parse(request.options.body),{server_ids:['host-1','host-2'],port_filter:[{port:443,protocol:'tcp'}]});const preview=env.element('#learning-preview').innerHTML;assert.match(preview,/Only 443\/tcp will be observed/);assert.match(preview,/443\/tcp/);assert.doesNotMatch(preview,/22\/tcp|80\/tcp/);assert.match(preview,/No selected network listeners in cached inventory/);assert.equal(env.run('state.data.servers[0].listeners[0].port'),2022);
});
test('saved service groups copy into the optional discovery limit and no-match session scopes stay explicit',async()=>{
 const env=await workspace('traffic');await env.click('learn');env.element('#learning-port-filter-enabled').checked=true;env.element('#learning-mode').value='discovered';env.context.filterChange={target:{id:'learning-port-filter-enabled'}};env.run('learningChange(filterChange)');assert.equal(env.element('#learning-port-filter-fields').hidden,false);assert.equal(env.element('#learning-port-filter').required,true);assert.equal(env.element('#learning-port-filter').disabled,false);
 env.context.filterChange={target:{id:'learning-filter-service-group',value:'web-ports'}};env.run('learningChange(filterChange)');assert.equal(env.element('#learning-port-filter').value,'443/tcp, 8443/tcp');
 env.context.filteredSession={id:'443-session',purpose:'traffic',status:'active',selection_mode:'discovered',policy_action:'auto_allow',port_filter:[{port:443,protocol:'tcp'}],server_ids:['host-1'],starts_at:new Date(Date.now()-60000).toISOString(),expires_at:new Date(Date.now()+3600000).toISOString(),server_ports:{'host-1':[]},discovery_results:{'host-1':{status:'no_listeners'}}};env.context.filteredHost=host;assert.match(env.run('learningHostSessionHTML(filteredSession,filteredHost)'),/No selected network listeners/);env.context.apiResponses['/api/v1/learning?limit=20&offset=0&purpose=traffic&active_only=true']=compactSessionPage([env.context.filteredSession],{purpose:'traffic',active_only:true,limit:20,total:1,has_more:false});env.run('closeModal()');await env.run("refreshDiscoveryPage('traffic',true)");const html=env.run('learningHTML()');assert.match(html,/Automatic · only 443\/tcp/);assert.match(html,/No selected network listeners/);assert.doesNotMatch(html,/Awaiting agents/);
});

test('Policies keeps managed and learned access on one page with service actions in details',async()=>{
 const env=await workspace('policies');env.run(`state.data.policies=[];state.data.learning_policies=[${JSON.stringify(learnedPolicy)}];render()`);const html=env.element('#view-content').innerHTML;
 assert.match(html,/0 managed policies in selected scope/);assert.match(html,/No managed policies match this scope/);assert.match(html,/Learned allow policies/);assert.match(html,/Billing observed clients/);assert.match(html,/Automatically learned/);assert.match(html,/192\.0\.2\.44\/32/);assert.match(html,/8443\/tcp/);assert.doesNotMatch(html,/role="tablist"|data-action="learned-policy-edit"/);
 await env.click('policy-catalogue-detail',{kind:'learned',id:'learned-1'});
 const details=env.element('#modal-content').innerHTML;assert.match(details,/192\.0\.2\.44\/32/);assert.match(details,/data-action="learned-policy-edit"/);
});

test('discovered policy access view shows configured decisions and can include unused zones',async()=>{
 const queries=[],source={rule_key:'default-accept',kind:'target',value:'ACCEPT',source:'Any source',destination:'Endpoint',destination_port:'Any port',zone:'public',zone_usage:'default',decision:'allow',server_ids:['host-1'],host_count:1};
 const unused={...source,rule_key:'unused-zone',zone:'drop',zone_usage:'unbound',decision:'deny'};
 const env=await workspace('policies',{mode:'entra',role:'read_only',responses:{'POST /api/v1/firewall/query':options=>{
  const body=JSON.parse(options.body);queries.push(body);
  return {view:'access',scoped_query:true,servers:[],changes:[],common_rules:body.zone_usage==='all'?[source,unused]:[source],pagination:{next_cursor:null}};
 }}});
 await env.run('refreshFirewallData()');
 const initial=env.element('#discovered-policy-results').innerHTML;
 assert.equal(queries.at(-1).view,'access');assert.match(initial,/Any source/);assert.match(initial,/lab-api/);assert.match(initial,/Any port/);assert.match(initial,/Default zone/);assert.match(initial,/>Allow</);assert.doesNotMatch(initial,/No active binding/);
 await env.click('policy-catalogue-zones');
 assert.equal(queries.at(-1).zone_usage,'all');assert.match(env.element('#discovered-policy-results').innerHTML,/No active binding/);assert.match(env.element('#discovered-policy-results').innerHTML,/>Deny</);assert.equal(mutations(env).length,0);
});

const platformStatus={runtime:{storage:'sqlite',ha:false},cluster:{mode:'standalone',controller_id:'controller-one',site:'Mumbai',storage:{metadata:'sqlite',traffic:'sqlite'},nodes:[{id:'controller-one',site:'Mumbai',ready:true,role:'active',last_seen:new Date().toISOString()}]},configuration:{database_url:'postgresql://private:do-not-display@db.example.test/inventory'},capabilities:{}};
const backupRecord={id:'backup-one',created_at:new Date().toISOString(),created_by:'Super Admin',reason:'manual',backend:'sqlite',status:'complete',size_bytes:4096,verified:true,format_version:1,members:[{name:'metadata.sqlite',kind:'metadata',sha256:'b'.repeat(64),size_bytes:2048}],consistency:'Controller metadata and traffic snapshot',controller_local:true};
function demoCleanupReview(overrides={}){return {id:'demo-review-one',counts:{servers:14,policies:2,locations:4},preserved:{real_servers:2,users:3},blockers:[],can_clear:true,confirmation_nonce:'review-nonce',confirmation_phrase:'CLEAR DEFAULT DEMO DATA',fingerprint:'c'.repeat(64),expires_at:new Date(Date.now()+60000).toISOString(),...overrides};}
test('Platform settings exposes actual node health to every role and configuration tabs only to Super Admin',async()=>{
 for(const role of ['read_only','admin','super_admin']){const env=await workspace('settings',{mode:'entra',role,responses:{'/api/v1/platform/status':platformStatus}});const html=env.element('#view-content').innerHTML;assert.match(html,/Controller nodes/);assert.match(html,/controller-one/);assert.match(html,/Mumbai/);assert.doesNotMatch(html,/do-not-display|postgresql:\/\/private/);assert.equal(env.element('#learn-button').hidden,true);assert.equal(env.element('#enroll-button').hidden,true);assert.equal(env.requests.some(request=>request.url==='/api/v1/platform/backups'),false);
  if(role==='super_admin'){for(const tab of ['Setup','Cluster','Backups','Services','Certificates'])assert.match(html,new RegExp(tab));}else{assert.doesNotMatch(html,/data-tab="(?:setup|storage|backups|recovery|demo|database|controllers)"/);await env.click('platform-tab',{tab:'backups'});assert.equal(env.run('state.platformTab'),'overview');assert.equal(env.requests.some(request=>request.url==='/api/v1/platform/backups'),false);await env.click('platform-backup-create');await env.click('platform-backup-inspect',{id:'backup-one'});await env.click('platform-backup-download',{id:'backup-one'});await env.click('platform-demo-preview');assert.equal(mutations(env).length,0);}
 }
});
test('Super Admin creates, inspects, downloads and validates a backup without replacing the live database',async()=>{
 const env=await workspace('settings',{mode:'entra',role:'super_admin',responses:{'/api/v1/platform/status':platformStatus,'/api/v1/platform/backups':{items:[backupRecord]},'/api/v1/platform/backups/backup-one/inspect':{backup:backupRecord,manifest:{version:'0.4.0',created_at:backupRecord.created_at,members:backupRecord.members,excludes:['PKI private keys','environment']},verified:true,checks:['Archive members verified']},'POST /api/v1/platform/backups/backup-one/restore-validation':{backup_id:'backup-one',backend:'sqlite',valid:true,verified:true,can_restore_live:false,requires_offline_restore:true,schema_compatible:true,checks:['SQLite integrity passed'],requirements:['Stop writers before an offline restore']}}});
 await env.click('platform-tab',{tab:'backups'});await new Promise(setImmediate);let html=env.element('#view-content').innerHTML;assert.match(html,/backup-one/);assert.match(html,/4.0 KB/);assert.match(html,/Backups are stored on the controller/);assert.match(html,/>Complete</);
 await env.click('platform-backup-create');let request=mutations(env)[0];assert.equal(request.url,'/api/v1/platform/backups');assert.deepEqual(JSON.parse(request.options.body),{});assertCookieMutation(request);
 await env.click('platform-backup-inspect',{id:'backup-one'});html=env.element('#modal-content').innerHTML;assert.match(html,/metadata.sqlite/);assert.match(html,/Archive integrity verified/);assert.match(html,/PKI private keys, environment/);assert.doesNotMatch(html,/do-not-display/);
 await env.click('platform-backup-download',{id:'backup-one'});request=env.requests.find(request=>request.url.endsWith('/backup-one/download'));assert.equal(request.options.credentials,'same-origin');assert.equal(request.options.headers.Authorization,undefined);
 await env.click('platform-backup-validate',{id:'backup-one'});html=env.element('#modal-content').innerHTML;assert.match(html,/Validation passed/);assert.match(html,/running database was not replaced/);assert.match(html,/SQLite integrity passed/);assert.match(html,/supervised restore with two explicit Super Admin confirmations/);assert.match(html,/Offline recovery requires its own controlled procedure/);request=mutations(env).at(-1);assert.equal(request.url,'/api/v1/platform/backups/backup-one/restore-validation');assertCookieMutation(request);assert.equal(env.requests.some(request=>request.url.endsWith('/restore')),false);
});
test('demo cleanup uses an exact expiring impact review, typed phrase and backup-bound controller action',async()=>{
 const env=await workspace('settings',{mode:'entra',role:'super_admin',responses:{'/api/v1/platform/status':platformStatus,'POST /api/v1/platform/demo/preview':demoCleanupReview(),'POST /api/v1/platform/demo/clear':{backup_id:'automatic-backup',counts:{servers:14,policies:2},seed_disabled:true}}});await env.click('platform-tab',{tab:'demo'});assert.match(env.element('#view-content').innerHTML,/server retirement review/);await env.click('platform-demo-preview');let html=env.element('#modal-content').innerHTML;assert.match(html,/CLEAR DEFAULT DEMO DATA/);assert.match(html,/Real servers/);assert.match(html,/Users/);assert.match(html,/type="submit" disabled/);assert.equal(mutations(env).length,1);
 const form=renderedForm(env,'platform-demo-form',{confirmation_phrase:'clear default demo data'});await submitRendered(env,form);assert.equal(mutations(env).length,1);assert.match(env.element('#form-error').textContent,/exact confirmation phrase/);
 form.values.confirmation_phrase='CLEAR DEFAULT DEMO DATA';env.context.confirmationInput={target:{id:'platform-demo-phrase',value:form.values.confirmation_phrase}};env.run('platformInput(confirmationInput)');assert.equal(env.element('button[type="submit"]').disabled,false);await submitRendered(env,form);const request=mutations(env).at(-1);assert.equal(request.url,'/api/v1/platform/demo/clear');assert.deepEqual(JSON.parse(request.options.body),{preview_id:'demo-review-one',confirmation_nonce:'review-nonce',confirmation_phrase:'CLEAR DEFAULT DEMO DATA'});assertCookieMutation(request);assert.match(env.element('#view-content').innerHTML,/automatic-backup/);assert.match(env.element('#view-content').innerHTML,/Automatic demo seeding is disabled/);
});
test('blocked, expired, stale and incomplete demo reviews never trigger cleanup',async()=>{
 for(const changes of [{can_clear:false,blockers:['Real policy references sample <group>']},{expires_at:'2000-01-01T00:00:00Z'},{confirmation_nonce:null},{fingerprint:null}]){const env=await workspace('settings',{mode:'entra',role:'super_admin',responses:{'POST /api/v1/platform/demo/preview':demoCleanupReview(changes)}});await env.click('platform-demo-preview');const form=renderedForm(env,'platform-demo-form',{confirmation_phrase:'CLEAR DEFAULT DEMO DATA'});await submitRendered(env,form);assert.equal(env.requests.some(request=>request.url.endsWith('/demo/clear')),false);assert.doesNotMatch(env.element('#modal-content').innerHTML,/<group>/);}
 const env=await workspace('settings',{mode:'entra',role:'super_admin',responses:{'POST /api/v1/platform/demo/preview':demoCleanupReview(),'POST /api/v1/platform/demo/clear':{responseStatus:409,data:{error:'Demo records changed'}}}});await env.click('platform-demo-preview');const form=renderedForm(env,'platform-demo-form',{confirmation_phrase:'CLEAR DEFAULT DEMO DATA'});await submitRendered(env,form);assert.equal(env.run('state.platformDemoReview'),null);await submitRendered(env,form);assert.equal(env.requests.filter(request=>request.url.endsWith('/demo/clear')).length,1);
});
test('Admin cannot mutate platform through shared API and Super Admin cookie mutations require CSRF',async()=>{
 const admin=await workspace('settings',{mode:'entra',role:'admin'});await assert.rejects(admin.run('api("/platform/backups",{method:"POST",body:{}})'),/Only Super Admins/);assert.equal(mutations(admin).length,0);
 const missing=await workspace('settings',{mode:'entra',identity:{role:'super_admin',auth_type:'session',demo:false,user:{id:'super'}}});await missing.click('platform-backup-create');assert.equal(mutations(missing).length,0);assert.match(missing.element('#form-error').textContent,/fresh sign-in/);
});

const clusterSpec={cluster_id:'f1cd9913-5db4-40b3-aeb8-57c463715283',name:'billing-cluster',controller_origin:'https://prthak.example.test',mode:'dc_dr',rpo:'synchronous_strict',nodes:[0,1,2].map(index=>({id:['database-a','database-b','witness'][index],ip:`10.241.${index+1}.10`,site:['primary-site','dr-site','witness-site'][index],role:index===2?'witness':'database',ssh:{user:'ubuntu',port:22,host_key:'ssh-ed25519 AAAA-public-pinned-key',private_key_configured:true}})),controller_cidrs:['10.241.10.0/24','10.241.20.0/24'],database:{metadata_name:'prthak_metadata',traffic_name:'prthak_traffic',metadata_user:'prthak_metadata',traffic_user:'prthak_traffic'},watchdog:{mode:'required',device:'/dev/watchdog',approved:true}};
const productionPlatform={...platformStatus,runtime:{storage:'sqlite',ha:false,demo:false,controller_id:'controller-primary',site:'primary-site'},configuration:{revision:2,spec:clusterSpec},capabilities:{remote_provisioning:true,supervised:true,supported_installer:'ubuntu24.04-amd64'},jobs:[],active:null};
function haFormValues(){return {name:clusterSpec.name,controller_origin:clusterSpec.controller_origin,mode:'dc_dr',controller_cidrs:'10.241.10.0/24, 10.241.20.0/24',...clusterSpec.database,watchdog_device:'/dev/watchdog',watchdog_approved:'on',...Object.fromEntries(clusterSpec.nodes.flatMap((node,index)=>Object.entries({id:node.id,ip:node.ip,site:node.site,ssh_user:node.ssh.user,ssh_port:'22',host_key:node.ssh.host_key,private_key:''}).map(([key,value])=>[`node_${index}_${key}`,value])))};}
function haJob(id,operation,status='queued',extra={}){return {id,operation,status,phase:status==='ready'?'verified':'queued',created_at:new Date().toISOString(),updated_at:new Date().toISOString(),...extra};}
function installationReview(overrides={}){return {id:'installation-review',revision:2,digest:'d'.repeat(64),confirmation_nonce:'install-nonce',confirmation_phrase:'INSTALL billing-cluster',expires_at:new Date(Date.now()+60000).toISOString(),summary:clusterSpec,blockers:[],warnings:['Strict synchronous replication stops writes while the sole standby is unavailable.'],configuration_recovery:[{node_id:'database-a',status:'recoverable',snapshot_digest:'e'.repeat(64)}],...overrides};}
test('HA configuration is a structured three-site install draft with pinned keys and blank preservation of stored private credentials',async()=>{
 const env=await workspace('settings',{mode:'entra',role:'super_admin',responses:{'/api/v1/platform/status':productionPlatform}});await env.click('platform-start-create');const html=env.element('#view-content').innerHTML;assert.match(html,/Ubuntu 24.04 AMD64/);assert.match(html,/sole standby is unavailable/);assert.match(html,/hardware watchdog/);assert.equal((html.match(/class="platform-node"/g) || []).length,3);assert.match(html,/Leave blank to preserve the stored key/);assert.doesNotMatch(html,/private_key_ref|do-not-display/);assert.match(html,/does not install external DNS or a load balancer/);
 const form=renderedForm(env,'platform-ha-form',haFormValues());await submitRendered(env,form);const request=mutations(env)[0],body=JSON.parse(request.options.body);assert.equal(request.url,'/api/v1/platform/ha/config');assert.equal(body.expected_revision,2);assert.equal(body.spec.cluster_id,clusterSpec.cluster_id);assert.equal(body.spec.rpo,'synchronous_strict');assert.deepEqual(body.spec.watchdog,{mode:'required',device:'/dev/watchdog',approved:true});assert.equal(body.spec.nodes.filter(node=>node.role==='database').length,2);assert.equal(body.spec.nodes.filter(node=>node.role==='witness').length,1);assert.equal(body.spec.nodes[0].ssh.private_key,'');assert.equal(body.spec.nodes[0].ssh.host_key,clusterSpec.nodes[0].ssh.host_key);assert.deepEqual(body.spec.controller_cidrs,clusterSpec.controller_cidrs);assertCookieMutation(request);assert.equal(env.requests.some(request=>request.url.endsWith('/ha/test')||request.url.endsWith('/ha/apply')),false,'saving a draft does not test or provision it');
});
test('HA setup rejects unapproved watchdogs and duplicate failure domains before saving',async()=>{
 const env=await workspace('settings',{mode:'entra',role:'super_admin',responses:{'/api/v1/platform/status':productionPlatform}});await env.click('platform-start-create');const form=renderedForm(env,'platform-ha-form',{...haFormValues(),watchdog_approved:null});await submitRendered(env,form);assert.equal(mutations(env).length,0);assert.match(env.element('#platform-ha-error').textContent,/approve.*watchdog/);
 form.values.watchdog_approved='on';form.values.node_2_site='dr-site';await submitRendered(env,form);assert.equal(mutations(env).length,0);assert.match(env.element('#platform-ha-error').textContent,/three distinct.*failure-domain sites/);
});
test('HA test, typed installation review and separate runtime activation keep queued provisioning distinct from active storage',async()=>{
 const preflight=haJob('test-one','preflight','ready',{result:{checks:['All three pinned hosts inspected']}}),provision=haJob('provision-one','provision','ready',{result:{nodes:[{node_id:'database-a',status:'leader'},{node_id:'database-b',status:'streaming'}]}});
 const env=await workspace('settings',{mode:'entra',role:'super_admin',responses:{'/api/v1/platform/status':{...productionPlatform,jobs:[preflight]},'POST /api/v1/platform/ha/test':haJob('test-new','preflight'),'POST /api/v1/platform/ha/preview':installationReview(),'POST /api/v1/platform/ha/apply':haJob('provision-one','provision'),'POST /api/v1/platform/ha/activate':haJob('activation-one','activate')}});
 await env.click('platform-ha-test');let request=mutations(env)[0];assert.deepEqual(JSON.parse(request.options.body),{expected_revision:2});assertCookieMutation(request);assert.equal(env.run('platformJob("preflight").status'),'queued');assert.match(env.run('platformJobsHTML()'),/Queued/);assert.doesNotMatch(env.run('platformJobsHTML()'),/Activated · runtime verified/);
 env.run(`platformStoreJob(${JSON.stringify(preflight)});state.platformInfo.jobs=state.platformInfo.jobs.filter(job=>job.id!=='test-new')`);await env.click('platform-ha-preview');request=mutations(env)[1];assert.deepEqual(JSON.parse(request.options.body),{expected_revision:2,test_job_id:'test-one'});let html=env.element('#modal-content').innerHTML;assert.match(html,/configuration recovery/);assert.match(html,/eeeeeeee/);assert.match(html,/separate explicit action/);assert.match(html,/type="submit" disabled/);
 const form=renderedForm(env,'platform-review-form',{confirmation_phrase:'install billing-cluster'});await submitRendered(env,form);assert.equal(mutations(env).length,2);form.values.confirmation_phrase='INSTALL billing-cluster';await submitRendered(env,form);request=mutations(env)[2];assert.deepEqual(JSON.parse(request.options.body),{preview_id:'installation-review',digest:'d'.repeat(64),confirmation_nonce:'install-nonce',confirmation_phrase:'INSTALL billing-cluster'});assertCookieMutation(request);assert.equal(env.run('platformJob("provision").status'),'queued');assert.doesNotMatch(env.run('platformDatabaseHTML()'),/Activated · runtime verified/);
 env.run(`platformStoreJob(${JSON.stringify(provision)})`);await env.click('platform-ha-activate-review');assert.match(env.element('#modal-content').innerHTML,/migrates its existing data/);assert.match(env.element('#modal-content').innerHTML,/dashboard may disconnect/);assert.equal(mutations(env).length,3);await env.click('platform-ha-activate-confirm');request=mutations(env)[3];assert.deepEqual(JSON.parse(request.options.body),{provision_job_id:'provision-one',confirm:true});assertCookieMutation(request);assert.equal(env.run('state.platformRuntimePending'),true);assert.equal(env.run('state.platformInfo.runtime.ha'),false);assert.match(env.run('platformDatabaseHTML()'),/Not activated/);
});
test('expired or blocked installation reviews and unsupervised activation cannot start infrastructure work',async()=>{
 for(const override of [{expires_at:'2000-01-01T00:00:00Z'},{blockers:['Foreign database found']},{confirmation_nonce:null}]){const env=await workspace('settings',{mode:'entra',role:'super_admin',responses:{'/api/v1/platform/status':productionPlatform}});env.context.review=installationReview(override);env.run('platformShowHAReview(review)');const form=renderedForm(env,'platform-review-form',{confirmation_phrase:'INSTALL billing-cluster'});await submitRendered(env,form);assert.equal(mutations(env).length,0);}
 const env=await workspace('settings',{mode:'entra',role:'super_admin',responses:{'/api/v1/platform/status':{...productionPlatform,capabilities:{...productionPlatform.capabilities,supervised:false},jobs:[haJob('provision-one','provision','ready')]}}});await env.click('platform-ha-activate-review');assert.equal(mutations(env).length,0);assert.match(env.element('#form-error').textContent,/runtime supervisor/);
});
test('DR joining asks for peer origin, one-time code and this node identity, then submits only a confirmed plan',async()=>{
 const joinPlan={...installationReview(),id:'join-review',operation:'join',confirmation_phrase:'JOIN controller-dr',summary:{peer_url:'https://primary.example.test:8787',node_id:'controller-dr',node_ip:'10.241.20.11',site:'dr-site',deployment_id:clusterSpec.cluster_id,local_snapshot_preserved:true},warnings:[],configuration_recovery:[]};
 const env=await workspace('settings',{mode:'entra',role:'super_admin',responses:{'/api/v1/platform/status':productionPlatform,'POST /api/v1/platform/join/preview':joinPlan,'POST /api/v1/platform/join/apply':haJob('join-one','join')}});await env.click('platform-start-join');let html=env.element('#view-content').innerHTML;assert.match(html,/Existing controller node IP \/ HTTPS origin/);assert.match(html,/This DR controller(?:&#39;|')s management IP/);assert.match(html,/one-time join code and trusted HTTPS origin/);assert.match(html,/IP address alone does not establish trust/);
 const form=renderedForm(env,'platform-join-form',{peer_url:'https://primary.example.test:8787',node_id:'controller-dr',site:'dr-site',node_ip:'10.241.20.11',join_code:'PRTHAKJOIN1.private-one-time-code'});await submitRendered(env,form);let request=mutations(env)[0];assert.deepEqual(JSON.parse(request.options.body),form.values);assertCookieMutation(request);html=env.element('#modal-content').innerHTML;assert.match(html,/cluster authentication/);assert.doesNotMatch(html,/private-one-time-code/);const review=renderedForm(env,'platform-review-form',{confirmation_phrase:'JOIN controller-dr'});await submitRendered(env,review);request=mutations(env)[1];assert.equal(request.url,'/api/v1/platform/join/apply');assert.equal(JSON.parse(request.options.body).preview_id,'join-review');assert.equal(env.run('state.platformRuntimePending'),true);assert.doesNotMatch(env.run('platformJobsHTML()'),/Activated · runtime verified/);
});
test('active clusters issue a one-time code bound to the exact new controller and never put that code in persistent browser storage',async()=>{
 const active={deployment_id:clusterSpec.cluster_id,active_revision:2,controller_origin:clusterSpec.controller_origin,mode:'dc_dr'},status={...productionPlatform,active,runtime:{...productionPlatform.runtime,ha:true,storage:'postgresql'}};
 const env=await workspace('settings',{mode:'entra',role:'super_admin',responses:{'/api/v1/platform/status':status,'POST /api/v1/platform/join-tokens':{join_code:'PRTHAKJOIN1.private-one-time-code',peer_url:clusterSpec.controller_origin,node_id:'controller-dr',site:'dr-site',node_ip:'10.241.20.11',expires_at:new Date(Date.now()+60000).toISOString()}}});await env.click('platform-tab',{tab:'controllers'});const form=renderedForm(env,'platform-join-token-form',{node_id:'controller-dr',site:'dr-site',node_ip:'10.241.20.11'});await submitRendered(env,form);const request=mutations(env)[0];assert.deepEqual(JSON.parse(request.options.body),form.values);assertCookieMutation(request);assert.match(env.element('#modal-content').innerHTML,/private-one-time-code/);assert.match(env.element('#modal-content').innerHTML,/can be used once|single bound controller enrollment/);assert.equal(env.storageChanges.some(change=>String(change.value).includes('private-one-time-code')),false);
});
test('demo and non-Super Admin users cannot install, activate or join and job polling reports uncertainty during restarts',async()=>{
 const demo=await workspace('settings');await demo.click('platform-start-join');assert.match(demo.element('#view-content').innerHTML,/Remote installation and DR joining are blocked in demo mode/);await demo.click('platform-ha-test');assert.equal(mutations(demo).length,0);
 for(const role of ['read_only','admin']){const env=await workspace('settings',{mode:'entra',role,responses:{'/api/v1/platform/status':productionPlatform}});await env.click('platform-ha-test');await env.click('platform-ha-preview');await env.click('platform-ha-activate-confirm');await env.listeners.submit.at(-1)({preventDefault(){},target:{id:'platform-join-form',values:{},querySelector:env.element}});assert.equal(mutations(env).length,0);}
 const env=await workspace('settings',{mode:'entra',role:'super_admin',responses:{'/api/v1/platform/status':productionPlatform,'/api/v1/platform/jobs/activation-one':{responseStatus:401,data:{error:'Sign in required'}}}});env.run('state.platformRuntimePending=true');await env.click('platform-job-refresh',{id:'activation-one'});assert.match(env.run('state.platformOperationNotice'),/authentication changed.*Sign in/);assert.equal(env.run('state.platformRuntimePending'),true);assert.doesNotMatch(env.run('platformJobsHTML()'),/Activated · runtime verified/);
});

test('demo cleanup explains and lists retained legacy or modified policies without offering extra deletion controls',async()=>{
 const retained=[{id:'legacy-policy',name:'Legacy management <policy>',reason:'Original demo ownership could not be established.'},{id:'edited-policy',name:'Edited billing access',reason:'Policy changed after seeding; preserve the operator revision.'}];
 const review=demoCleanupReview({counts:{servers:14,policies:0},preserved:{real_servers:2,users:3,service_groups:4,retained_policies:retained}});
 const env=await workspace('settings',{mode:'entra',role:'super_admin',responses:{'POST /api/v1/platform/demo/preview':review}});await env.click('platform-demo-preview');const html=env.element('#modal-content').innerHTML;
 assert.match(html,/2 policies are preserved/);assert.match(html,/not eligible for automatic demo cleanup/);assert.match(html,/Legacy management &lt;policy&gt;/);assert.match(html,/Original demo ownership could not be established/);assert.match(html,/Edited billing access/);assert.match(html,/preserve the operator revision/);assert.match(html,/<dt>Service groups<\/dt><dd>4<\/dd>/);assert.match(html,/<dt>Retained policies<\/dt><dd>2<\/dd>/);assert.doesNotMatch(html,/\[object Object\]|<policy>|delete retained|remove retained/);assert.equal((html.match(/type="checkbox"/g)||[]).length,0);assert.equal(env.requests.some(request=>request.url.endsWith('/demo/clear')),false);
});

test('cleanup review keeps six main counts visible while exact history diagnostics are collapsed and retained policies remain visible',async()=>{
 const counts={servers:14,policies:0,groups:4,locations:3,sessions:2,flows:99,policy_revisions:8,learning_allow_history:6,learning_evidence_receipts:17,batches:10};
 const plan=demoCleanupReview({counts,preserved:{retained_policies:[{id:'keep-one',name:'Preserved management policy',reason:'Operator modified policy revision'}],service_groups:2}});
 const env=await workspace('settings',{mode:'entra',role:'super_admin',responses:{'POST /api/v1/platform/demo/preview':plan}});await env.click('platform-demo-preview');const html=env.element('#modal-content').innerHTML,related=html.match(/<details class="platform-related-counts"[^>]*>[\s\S]*?<\/details>/)[0],before=html.slice(0,html.indexOf(related));
 assert.match(before,/<dt>Servers<\/dt><dd>14<\/dd>/);assert.match(before,/<dt>Policies<\/dt><dd>0<\/dd>/);assert.match(before,/<dt>Server groups<\/dt><dd>4<\/dd>/);assert.match(before,/<dt>Locations<\/dt><dd>3<\/dd>/);assert.match(before,/<dt>Learning sessions<\/dt><dd>2<\/dd>/);assert.match(before,/<dt>Traffic flows<\/dt><dd>99<\/dd>/);
 assert.match(related,/<summary>Related history and learning records<\/summary>/);assert.match(related,/<dt>Policy revisions<\/dt><dd>8<\/dd>/);assert.match(related,/<dt>Learning evidence receipts<\/dt><dd>17<\/dd>/);assert.doesNotMatch(related,/class="platform-related-counts"[^>]*\bopen\b|Preserved management policy/);assert.doesNotMatch(before,/Policy revisions|Learning evidence receipts/);
 assert.match(html,/<details class="platform-preserved-summary" open>/);assert.match(html,/Preserved management policy/);assert.match(html,/Operator modified policy revision/);assert.match(html,/id="platform-demo-phrase"/);assert.equal(env.requests.some(request=>request.url.endsWith('/demo/clear')),false);
});

const applianceState={revision:4,installed:true,identity:{id:'controller-noida',site:'Noida',ip:'10.241.10.11'},data_root:'/var/lib/prthak',cluster:{configured:true,name:'Production cluster',origin:'https://prthak.example.test',nodes:[{id:'controller-noida',site:'Noida',health:'healthy'},{id:'controller-pune',site:'Pune',health:'unknown'}],replication_state:'unknown',cluster_password_configured:true,replication_password_configured:true},services:[{id:'controller',name:'Controller',state:'active',enabled:true,can_restart:true,can_stop:false},{id:'postgresql',name:'Database',state:'unknown',enabled:true,can_restart:true,can_stop:true}],routing:{mode:'site_affinity',site:'Noida',preferred_controller_url:'https://noida.example.test',fallback_controller_url:'https://pune.example.test',failover_state:'configured',pools:[{site:'Noida',url:'https://noida.example.test',role:'preferred',health:'healthy'},{site:'Pune',url:'https://pune.example.test',role:'fallback',health:'unknown'}]}};
const backupSchedule={revision:3,enabled:true,frequency:'daily',time:'02:00',timezone:'Asia/Kolkata',weekday:0,interval_hours:24,retention_count:7,next_run_at:'2026-10-31T20:30:00Z',last_success_at:'2026-10-29T20:30:00Z',last_error:''};
function applianceReview(overrides={}){return {id:'appliance-review-one',digest:'f'.repeat(64),confirmation_nonce:'appliance-nonce',confirmation_phrase:'APPLY REVIEWED CHANGE',expires_at:new Date(Date.now()+60000).toISOString(),summary:{service:'controller',action:'restart'},blockers:[],warnings:[],...overrides};}
async function applianceWorkspace(extra={}){return workspace('settings',{mode:'entra',role:'super_admin',responses:{'/api/v1/platform/status':productionPlatform,'/api/v1/platform/appliance':applianceState,'/api/v1/platform/backup-schedule':backupSchedule,...extra}});}
test('default platform navigation is simple appliance operations and avoids all dedicated database and SSH fields',async()=>{
 const env=await applianceWorkspace();let html=env.element('#view-content').innerHTML;for(const label of ['Overview','Setup','Cluster','Backups','Services','Certificates'])assert.match(html,new RegExp('>'+label+'<'));assert.doesNotMatch(html,/data-tab="(?:storage|recovery|signing|database|controllers)"|data-action="platform-appliance-(?:create|connect|service-review)"|SSH private key|Database node 1|Issue a DR join code/);assert.doesNotMatch(html,/Site routing|Noida-local pool|Pune-local pool/);assert.match(html,/Not reported/);assert.match(html,/>Standalone<\/strong>/);assert.match(html,/>Appliance service health<\/h2>/);assert.match(html,/>Active<\/span>/);
 await env.click('platform-tab',{tab:'cluster'});html=env.element('#view-content').innerHTML;assert.match(html,/same appliance package/);assert.match(html,/Noida-local pool/);assert.match(html,/Pune-local pool/);assert.match(html,/name="cluster_password" type="password"/);assert.match(html,/name="replication_password" type="password"/);assert.doesNotMatch(html,/node_0_|host_key|private_key|PRTHAKJOIN1/);
});
test('signing recovery stays under advanced Setup with no separate navigation',async()=>{
 const env=await applianceWorkspace({'/api/v1/platform/signing':{mode:'online_controller',health:'online_key_available'}});
 await env.click('platform-tab',{tab:'setup'});
 let html=env.element('#view-content').innerHTML;
 assert.doesNotMatch(html,/data-tab="signing"/);
 assert.match(html,/id="platform-advanced-signing"[^>]*><summary>\s*Advanced policy signing recovery|id="platform-advanced-signing"[^>]*>\s*<summary>Advanced policy signing recovery/);
 assert.doesNotMatch(html,/id="platform-advanced-signing"[^>]* open>/);
 assert.equal(env.requests.filter(row=>row.url==='/api/v1/platform/signing').length,0);
 await env.click('platform-tab',{tab:'signing'});
 await new Promise(setImmediate);
 html=env.element('#view-content').innerHTML;
 assert.equal(env.run('state.platformTab'),'setup');
 assert.match(html,/id="platform-advanced-signing"[^>]* open>/);
 assert.match(html,/Automatic online policy signatures/);
 assert.equal(env.requests.filter(row=>row.url==='/api/v1/platform/signing').length,1);
 assert.equal(mutations(env).length,0);
});
test('appliance cluster settings preserve blank passwords and shared-password joining only sends existing peer and password',async()=>{
 const env=await applianceWorkspace({'POST /api/v1/platform/appliance/join/preview':applianceReview({summary:{peer_url:'https://noida.example.test',node_id:'controller-pune'}}),'POST /api/v1/platform/appliance/join/apply':haJob('appliance-join-job','appliance_join')});await env.click('platform-appliance-create');const form=renderedForm(env,'platform-appliance-config-form',{cluster_name:'Production cluster',site:'Noida',node_ip:'10.241.10.11',controller_origin:'https://prthak.example.test',cluster_password:'',replication_password:'',preferred_controller_url:'https://noida.example.test',fallback_controller_url:'https://pune.example.test'});await submitRendered(env,form);let request=mutations(env)[0],body=JSON.parse(request.options.body);assert.equal(request.url,'/api/v1/platform/appliance/config');assert.equal(body.expected_revision,4);assert.equal(body.cluster_password,undefined);assert.equal(body.replication_password,undefined);assertCookieMutation(request);
 await env.click('platform-appliance-connect');const join=renderedForm(env,'platform-appliance-join-form',{peer_url:'https://noida.example.test',cluster_password:'shared-private-cluster-password'});await submitRendered(env,join);request=mutations(env)[1];assert.deepEqual(JSON.parse(request.options.body),join.values);assert.equal(request.url,'/api/v1/platform/appliance/join/preview');assert.doesNotMatch(env.element('#modal-content').innerHTML,/shared-private-cluster-password/);const review=renderedForm(env,'platform-appliance-review-form',{confirmation_phrase:'APPLY REVIEWED CHANGE'});await submitRendered(env,review);request=mutations(env)[2];assert.equal(request.url,'/api/v1/platform/appliance/join/apply');assert.deepEqual(JSON.parse(request.options.body),{preview_id:'appliance-review-one',digest:'f'.repeat(64),confirmation_nonce:'appliance-nonce',confirmation_phrase:'APPLY REVIEWED CHANGE'});assert.equal(env.storageChanges.some(change=>String(change.value).includes('shared-private')),false);assert.equal(env.run('state.platformInfo.runtime.ha'),false);
});
test('simple cluster creation exposes explicit host fencing approval and validates replication secrets',async()=>{
 const env=await applianceWorkspace({'/api/v1/platform/appliance':{...applianceState,cluster:{...applianceState.cluster,configured:false},watchdog_approved:true}});await env.click('platform-appliance-create');let html=env.element('#view-content').innerHTML;assert.match(html,/>Create cluster settings<\/button>/);assert.match(html,/three site voters and approved host fencing/);assert.match(html,/name="watchdog_approved" type="checkbox" checked/);assert.match(html,/Enable approved host fencing for automatic failover/);assert.match(html,/can restart a database host/);assert.match(html,/\/dev\/watchdog0/);assert.doesNotMatch(html,/SSH private key|node_0_|host_key/);
 const form=renderedForm(env,'platform-appliance-config-form',{cluster_name:'New cluster',site:'Noida',node_ip:'10.241.10.11',controller_origin:'https://prthak.example.test',watchdog_approved:'on',cluster_password:'',replication_password:'too-short'});await submitRendered(env,form);assert.equal(mutations(env).length,0);assert.match(env.element('#platform-appliance-config-error').textContent,/32–128/);form.values.replication_password='';await submitRendered(env,form);const body=JSON.parse(mutations(env)[0].options.body);assert.equal(body.watchdog_approved,true);assert.equal(body.replication_password,undefined);assert.equal(env.storageChanges.some(change=>String(change.value).includes('too-short')),false);
});
test('pruned backup history is identifiable and archive operations remain disabled',async()=>{
 const env=await applianceWorkspace({'/api/v1/platform/backups':{items:[{...backupRecord,status:'pruned'}]}});await env.click('platform-tab',{tab:'backups'});await new Promise(setImmediate);const html=env.element('#view-content').innerHTML;assert.match(html,/>Pruned<\/span>/);for(const action of ['inspect','download','validate'])assert.match(html,new RegExp('data-action="platform-backup-'+action+'"[^>]*disabled'));assert.match(html,/Archive removed by retention; history is preserved/);
});
test('storage and fixed service actions need an expiring typed review before queued changes',async()=>{
 const env=await applianceWorkspace({'POST /api/v1/platform/appliance/storage/review':applianceReview({summary:{current_data_root:'/var/lib/prthak',data_root:'/srv/prthak-data'}}),'POST /api/v1/platform/appliance/storage/apply':haJob('storage-job','appliance_storage'),'POST /api/v1/platform/appliance/services/review':applianceReview(),'POST /api/v1/platform/appliance/services/apply':haJob('service-job','appliance_service')});await env.click('platform-tab',{tab:'storage'});assert.equal(env.run('state.platformTab'),'setup');await env.click('platform-tab',{tab:'setup'});const html=env.element('#view-content').innerHTML;assert.match(html,/>Current data path<\/dt><dd><code>\/var\/lib\/prthak<\/code>/);assert.equal((html.match(/id="platform-appliance-storage-form"/g)||[]).length,1);assert.equal((html.match(/>Deployment operations/g)||[]).length,1);const form=renderedForm(env,'platform-appliance-storage-form',{data_root:'relative/path'});await submitRendered(env,form);assert.equal(mutations(env).length,0);form.values.data_root='/srv/prthak-data';await submitRendered(env,form);let request=mutations(env)[0];assert.deepEqual(JSON.parse(request.options.body),{data_root:'/srv/prthak-data'});assert.match(env.element('#modal-content').innerHTML,/\/srv\/prthak-data/);let review=renderedForm(env,'platform-appliance-review-form',{confirmation_phrase:'wrong'});await submitRendered(env,review);assert.equal(mutations(env).length,1);review.values.confirmation_phrase='APPLY REVIEWED CHANGE';await submitRendered(env,review);assert.equal(mutations(env)[1].url,'/api/v1/platform/appliance/storage/apply');assert.equal(env.run('state.platformAppliance.data_root'),'/var/lib/prthak','queued migration does not change displayed actual mount path');
 await env.click('platform-tab',{tab:'services'});await env.click('platform-appliance-service-review',{id:'arbitrary-service',serviceAction:'restart'});assert.equal(mutations(env).length,2);await env.click('platform-appliance-service-review',{id:'controller',serviceAction:'restart'});request=mutations(env)[2];assert.deepEqual(JSON.parse(request.options.body),{service:'controller',action:'restart'});review=renderedForm(env,'platform-appliance-review-form',{confirmation_phrase:'APPLY REVIEWED CHANGE'});await submitRendered(env,review);assert.equal(mutations(env)[3].url,'/api/v1/platform/appliance/services/apply');assertCookieMutation(mutations(env)[3]);
});
test('deployment history lives only in Setup and shows a safe visible blocker before expanding the job',async()=>{
 const reason='Database start waits for authenticated etcd quorum <review voter health>';
 const jobs=[
  haJob('older-blocked','appliance','blocked',{phase:'node_manager',error:reason}),
  haJob('generic-blocked','appliance','blocked',{error:'Appliance blocked',result:{blockers:['The selected storage target must be empty']}}),
  haJob('unknown-blocked','appliance','blocked'),
  haJob('failed','appliance','failed',{error:'A separate failure'})
 ];
 const env=await applianceWorkspace({'/api/v1/platform/status':{...productionPlatform,jobs}});
 for(const tab of ['overview','cluster','services','backups','recovery','certificates','database','controllers']){
  await env.click('platform-tab',{tab});
  assert.doesNotMatch(env.element('#view-content').innerHTML,/id="platform-deployment-operations"/);
 }
 await env.click('platform-tab',{tab:'services'});
 assert.match(env.element('#view-content').innerHTML,/View operation history in Setup/);
 await env.click('platform-operation-history');
 assert.equal(env.run('state.platformTab'),'setup');
 const html=env.element('#view-content').innerHTML;
 assert.equal((html.match(/id="platform-deployment-operations"/g)||[]).length,1);
 const rows=Array.from(html.matchAll(/<details class="platform-job"([^>]*)>\s*<summary>([\s\S]*?)<\/summary>/g));
 assert.equal(rows.length,4);
 assert.ok(rows.every(row=>!row[1].includes('open')));
 assert.ok(rows.some(row=>row[2].includes('Database start waits for authenticated etcd quorum &lt;review voter health&gt;')));
 assert.ok(rows.some(row=>row[2].includes('The selected storage target must be empty')));
 assert.ok(rows.some(row=>row[2].includes('The controller did not report a specific blocker')));
 assert.ok(rows.every(row=>!row[2].includes('A separate failure')));
});
test('unused local HA services have no controls while stopped services on a voter remain visible as faults',async()=>{
 const haServices=[{id:'database',name:'PostgreSQL 16 / Patroni'},{id:'etcd',name:'etcd quorum'}];
 const localServices=enabled=>[applianceState.services[0],{id:'router',name:'TLS router',state:'running',enabled:true},...haServices.map(service=>({...service,state:'stopped',enabled,can_restart:true,can_stop:true}))];
 const standalone=await applianceWorkspace({'/api/v1/platform/appliance':{...applianceState,manager_available:true,services:localServices(false)}});
 let html=standalone.element('#view-content').innerHTML;
 const [,localHealth,clusterHealth]=html.match(/<section aria-labelledby="appliance-standalone-health">([\s\S]*?)<\/section>\s*<section aria-labelledby="appliance-cluster-health">([\s\S]*?)<\/section>/);
 assert.match(localHealth,/Standalone Health[\s\S]*<dt>Controller<\/dt>[\s\S]*<dt>TLS router<\/dt>[\s\S]*Appliance node manager/);
 assert.doesNotMatch(localHealth,/PostgreSQL|etcd quorum/);
 assert.match(clusterHealth,/Cluster Health[\s\S]*PostgreSQL 16 \/ Patroni[\s\S]*etcd quorum/);
 assert.doesNotMatch(clusterHealth,/TLS router|Appliance node manager/);
 assert.match(html,/<p class="appliance-health-note help-text">This standalone controller stores its data in SQLite\. Cluster health applies only to cluster deployments\.<\/p>/);
 assert.equal((html.match(/Not required on this node/g)||[]).length,2);
 assert.match(html,/Required on HA database voters for shared database storage and failover/);
 assert.match(html,/Required on HA database voters for quorum and database leader election/);
 await standalone.click('platform-tab',{tab:'services'});
 html=standalone.element('#view-content').innerHTML;
 assert.equal((html.match(/Not required on this node/g)||[]).length,2);
 assert.match(html,/standalone controller stores its data in SQLite/);
 assert.match(html,/Appliance node manager.*prthak-appliance-manager\.service.*>Reachable/);
 assert.doesNotMatch(html,/data-id="(?:database|etcd)" data-service-action/);
 await standalone.click('platform-appliance-service-review',{id:'database',serviceAction:'restart'});
 await standalone.click('platform-appliance-service-review',{id:'etcd',serviceAction:'stop'});
 assert.equal(mutations(standalone).length,0);
 const voter=await applianceWorkspace({'/api/v1/platform/status':{...productionPlatform,runtime:{...productionPlatform.runtime,ha:true,storage:'postgresql'}},'/api/v1/platform/appliance':{...applianceState,services:localServices(true)}});
 await voter.click('platform-tab',{tab:'services'});
 html=voter.element('#view-content').innerHTML;
 assert.equal((html.match(/class="badge danger"><i><\/i>Stopped/g)||[]).length,2);
 assert.match(html,/Required on this HA database voter for shared database storage and failover/);
 assert.match(html,/data-id="database" data-service-action="restart"/);
 assert.match(html,/data-id="etcd" data-service-action="restart"/);
 assert.doesNotMatch(html,/Not required on this node|standalone controller/);
 const unreachable=await applianceWorkspace({'/api/v1/platform/appliance':{...applianceState,manager_available:false,services:[]}});
 await unreachable.click('platform-tab',{tab:'services'});
 assert.match(unreachable.element('#view-content').innerHTML,/Appliance node manager.*class="badge danger"><i><\/i>Unreachable/);
 assert.doesNotMatch(unreachable.element('#view-content').innerHTML,/data-action="platform-appliance-service-review"/);
});
test('service health explains management-only HA and keeps unreported voter status distinct',async()=>{
 const sharedPlatform={...productionPlatform,runtime:{...productionPlatform.runtime,ha:true,storage:'postgresql'}};
 const haServices=[{id:'database',name:'PostgreSQL 16 / Patroni'},{id:'etcd',name:'etcd quorum'}];
 const management=await applianceWorkspace({'/api/v1/platform/status':sharedPlatform,'/api/v1/platform/appliance':{...applianceState,services:haServices.map(service=>({...service,state:'stopped',enabled:false}))}});
 let html=management.element('#view-content').innerHTML;
 assert.equal((html.match(/Not required on this node/g)||[]).length,2);
 assert.match(html,/This management controller connects to the shared database/);
 assert.doesNotMatch(html,/stores its data in SQLite/);
 const voter=await applianceWorkspace({'/api/v1/platform/status':sharedPlatform,'/api/v1/platform/appliance':{...applianceState,services:haServices.map(service=>({...service,state:'unknown',enabled:true}))}});
 html=voter.element('#view-content').innerHTML;
 assert.equal((html.match(/class="badge warning"><i><\/i>Not reported/g)||[]).length,2);
 assert.match(html,/Required on this HA database voter for quorum and database leader election/);
 assert.doesNotMatch(html,/Not required on this node|>Stopped<|management controller connects/);
});
test('backup scheduling saves exact local timezone, weekday, interval and retention with stale revision protection',async()=>{
 const env=await applianceWorkspace();await env.click('platform-tab',{tab:'backups'});await new Promise(setImmediate);const html=env.element('#view-content').innerHTML;assert.match(html,/Automatic backups/);assert.match(html,/value="Asia\/Kolkata"/);assert.match(html,/Last successful run/);const form=renderedForm(env,'platform-backup-schedule-form',{enabled:'on',frequency:'weekly',time:'02:30',timezone:'Asia/Kolkata',weekday:'5',interval_hours:'24',retention_count:'14'});await submitRendered(env,form);const request=mutations(env)[0];assert.equal(request.url,'/api/v1/platform/backup-schedule');assert.deepEqual(JSON.parse(request.options.body),{expected_revision:3,enabled:true,frequency:'weekly',time:'02:30',timezone:'Asia/Kolkata',weekday:5,interval_hours:24,retention_count:14});assertCookieMutation(request);
 form.values.interval_hours='169';await submitRendered(env,form);assert.equal(mutations(env).length,1);assert.match(env.element('#platform-backup-schedule-error').textContent,/1–168/);form.values.interval_hours='24';form.values.timezone='Not/A/Timezone';await submitRendered(env,form);assert.equal(mutations(env).length,1);assert.match(env.element('#platform-backup-schedule-error').textContent,/IANA timezone/);
});
test('certificate GUI imports private material without showing it in the typed review and never equates generated with active',async()=>{
 const certificate={subject:'CN=prthak.example.test',issuer:'CN=Test CA',sans:['prthak.example.test','10.241.10.11'],not_after:'2027-10-30T00:00:00Z',fingerprint_sha256:'ab:cd:ef'};
 const env=await applianceWorkspace({'/api/v1/platform/certificates':{current:certificate},'POST /api/v1/platform/certificates/preview':applianceReview({summary:{certificate}}),'POST /api/v1/platform/certificates/apply':haJob('cert-job','certificates')});await env.click('platform-tab',{tab:'certificates'});await new Promise(setImmediate);assert.match(env.element('#view-content').innerHTML,/ab:cd:ef/);assert.match(env.element('#view-content').innerHTML,/A replacement takes effect after restart and verification/);const pem={certificate_pem:'PEM public certificate',private_key_pem:'PRIVATE KEY secret fixture'};let form=renderedForm(env,'platform-certificate-form',{mode:'ca_signed',format:'pem',...pem});await submitRendered(env,form);let request=mutations(env)[0];assert.deepEqual(JSON.parse(request.options.body),{mode:'pem',...pem});assert.equal(request.url,'/api/v1/platform/certificates/preview');assert.match(env.element('#modal-content').innerHTML,/CN=prthak.example.test/);assert.doesNotMatch(env.element('#modal-content').innerHTML,/PRIVATE KEY secret fixture/);const review=renderedForm(env,'platform-appliance-review-form',{confirmation_phrase:'APPLY REVIEWED CHANGE'});await submitRendered(env,review);assert.equal(mutations(env)[1].url,'/api/v1/platform/certificates/apply');assert.equal(env.storageChanges.some(change=>String(change.value).includes('PRIVATE KEY')),false);
 env.run('closeModal()');await env.click('platform-tab',{tab:'certificates'});await new Promise(setImmediate);form=renderedForm(env,'platform-certificate-form',{mode:'self_signed',hostname:'controller-pune.example.test',sans:'10.241.20.11, controller-pune.example.test'});await submitRendered(env,form);request=mutations(env).at(-1);assert.deepEqual(JSON.parse(request.options.body),{mode:'self_signed',hostname:'controller-pune.example.test',sans:['10.241.20.11','controller-pune.example.test']});
});
test('encrypted PEM key passwords are optional, masked and sent only with their certificate review',async()=>{
 const env=await applianceWorkspace({'/api/v1/platform/certificates':{current:{}},'POST /api/v1/platform/certificates/preview':applianceReview({summary:{certificate:{subject:'CN=encrypted-key.example.test'}}})});await env.click('platform-tab',{tab:'certificates'});await new Promise(setImmediate);assert.match(env.element('#view-content').innerHTML,/name="key_password" type="password" autocomplete="off"/);const form=renderedForm(env,'platform-certificate-form',{mode:'pem',certificate_pem:'PUBLIC CERTIFICATE fixture',private_key_pem:'ENCRYPTED PRIVATE KEY fixture',key_password:'private-encrypted-pem-password'});await submitRendered(env,form);const request=mutations(env)[0];assert.deepEqual(JSON.parse(request.options.body),form.values);assertCookieMutation(request);assert.doesNotMatch(env.element('#modal-content').innerHTML,/private-encrypted-pem-password|ENCRYPTED PRIVATE KEY fixture/);assert.equal(env.storageChanges.some(change=>String(change.value).includes('private-encrypted-pem-password')),false);
});
test('replication password bounds reject non-ASCII and oversized input while preserving blank saved secrets',async()=>{
 const env=await applianceWorkspace();await env.click('platform-appliance-create');const html=env.element('#view-content').innerHTML;assert.match(html,/name="replication_password" type="password" minlength="32" maxlength="128"/);assert.match(html,/32–128 printable ASCII/);const form=renderedForm(env,'platform-appliance-config-form',{cluster_name:'Production cluster',site:'Noida',node_ip:'10.241.10.11',controller_origin:'https://prthak.example.test',cluster_password:'',replication_password:''});for(const secret of ['a'.repeat(31),'a'.repeat(129),'é'.repeat(32),'a'.repeat(32)+'\n']){form.values.replication_password=secret;await submitRendered(env,form);assert.equal(mutations(env).length,0);}form.values.replication_password='r'.repeat(128);await submitRendered(env,form);assert.equal(JSON.parse(mutations(env)[0].options.body).replication_password,'r'.repeat(128));assertCookieMutation(mutations(env)[0]);
});
test('replication rotation shows exact voter acknowledgements and cancellation remains requested until peer cleanup completes',async()=>{
 const voters=[{id:'noida',site:'Noida'},{id:'pune',site:'Pune'},{id:'witness',site:'Third site'}],rotation={rotation_id:'rotation-one',phase:'prepare',pending:true,can_abort:true,voters,acks:{prepare:{noida:'2026-10-31T00:00:00Z',pune:'2026-10-31T00:00:01Z'}},errors:{witness:'Awaiting verified node manager response'},role_change_intent:false,updated_at:'2026-10-31T00:00:02Z'},env=await applianceWorkspace({'/api/v1/platform/appliance':{...applianceState,cluster:{...applianceState.cluster,replication_password_pending:true,replication_rotation:rotation}},'POST /api/v1/platform/appliance/replication/abort':{...rotation,phase:'abort',acks:{},errors:{}}});await env.click('platform-appliance-create');let html=env.element('#view-content').innerHTML;assert.match(html,/2 of 3 voters acknowledged Prepare credentials/);assert.match(html,/Third site: Awaiting verified node manager response/);assert.match(html,/Cancel pending rotation/);assert.doesNotMatch(html,/new replication password active/);await env.click('platform-appliance-replication-abort');assert.equal(mutations(env)[0].url,'/api/v1/platform/appliance/replication/abort');assert.deepEqual(JSON.parse(mutations(env)[0].options.body),{});assertCookieMutation(mutations(env)[0]);html=env.element('#view-content').innerHTML;assert.match(html,/Cancellation is requested/);assert.doesNotMatch(html,/Cancellation completed|Cancel pending rotation|new replication password active/);await env.click('platform-appliance-replication-abort');assert.equal(mutations(env).length,1);
 env.context.nextRotation={...rotation,phase:'verify',can_abort:false,role_change_intent:true,acks:{verify:{noida:'2026-10-31T00:00:03Z'}}};env.run('state.platformAppliance.cluster.replication_rotation=nextRotation;render()');html=env.element('#view-content').innerHTML;assert.match(html,/1 of 3 voters acknowledged Verify every voter/);assert.match(html,/must recover forward/);assert.doesNotMatch(html,/Cancel pending rotation|new replication password active/);await env.click('platform-appliance-replication-abort');assert.equal(mutations(env).length,1);
 env.context.nextRotation={...rotation,phase:'completed',pending:false,can_abort:false,acks:{finalize:Object.fromEntries(voters.map(voter=>[voter.id,'2026-10-31T00:00:04Z']))},errors:{}};env.run('state.platformAppliance.cluster.replication_rotation=nextRotation;render()');html=env.element('#view-content').innerHTML;assert.match(html,/new replication password active after verification/);assert.match(html,/3 of 3 voters acknowledged Finalize credentials/);
});
test('saved appliance settings do not imply active shared storage and rotation cancellation remains Super Admin only',async()=>{
 const env=await applianceWorkspace({'/api/v1/platform/appliance':{...applianceState,cluster:{...applianceState.cluster,configured:false,settings_saved:true}}});assert.match(env.element('#view-content').innerHTML,/>Settings saved<\/strong>/);await env.click('platform-appliance-create');assert.match(env.element('#view-content').innerHTML,/>Save cluster settings<\/button>/);for(const role of ['read_only','admin']){const denied=await workspace('settings',{mode:'entra',role});await denied.click('platform-appliance-replication-abort');assert.equal(mutations(denied).length,0);}
});
test('new platform mutation forms remain Super Admin only and demo service or storage actions cannot run',async()=>{
 for(const role of ['read_only','admin']){const env=await workspace('settings',{mode:'entra',role,responses:{'/api/v1/platform/status':productionPlatform}});await env.listeners.submit.at(-1)({preventDefault(){},target:{id:'platform-appliance-config-form',values:{}}});await env.listeners.submit.at(-1)({preventDefault(){},target:{id:'platform-certificate-form',values:{}}});await env.click('platform-appliance-service-review',{id:'controller',serviceAction:'restart'});assert.equal(mutations(env).length,0);assert.doesNotMatch(env.element('#view-content').innerHTML,/data-tab="(?:cluster|storage|services|certificates)"/);}
 const env=await workspace('settings',{responses:{'/api/v1/platform/appliance':{...applianceState,installed:false},'/api/v1/platform/status':{...productionPlatform,runtime:{demo:true,ha:false,storage:'sqlite'}}}});await env.click('platform-tab',{tab:'services'});assert.match(env.element('#view-content').innerHTML,/Real cluster joining, storage moves and service restarts are disabled/);await env.click('platform-appliance-service-review',{id:'controller',serviceAction:'restart'});assert.equal(mutations(env).length,0);
});
test('bilingual scalable wordmarks replace the cube and keep accessible product naming and the Airtel header',()=>{
 const index=fs.readFileSync(path.join(__dirname,'../index.html'),'utf8'),full=fs.readFileSync(path.join(__dirname,'../assets/prthak-wordmark.svg'),'utf8'),compact=fs.readFileSync(path.join(__dirname,'../assets/prthak-monogram.svg'),'utf8');assert.match(index,/aria-label="Prṛthak · पृथक् overview"/);assert.match(index,/src="\/assets\/prthak-wordmark.svg" alt="Prṛthak · पृथक्"/);assert.match(index,/class="brand-logo-compact"/);assert.doesNotMatch(index,/M16 2 28 9|class="brand-mark"/);assert.match(index,/class="topbar-client-logo" src="\/assets\/airtel-payments-bank.png"/);for(const svg of [full,compact]){assert.match(svg,/<title[^>]*>Prṛthak · पृथक्<\/title>/);assert.match(svg,/viewBox=/);assert.match(svg,/>पृ<\/text>/);}assert.match(full,/>thak<\/text>/);assert.match(compact,/>k<\/text>/);
});

test('server inventory and details use only agent-reported addresses and keep planning values explicitly unverified',async()=>{
 const env=await workspace('servers');env.context.unreportedHost={...host,ips:[],peer_ip:'198.51.100.10',remote_ip:'198.51.100.11',connection_ip:'198.51.100.12',forwarded_for:'198.51.100.13',planned_ips:['198.51.100.14']};env.run('state.data.servers=[unreportedHost]');let html=env.run('serverRows().html');assert.match(html,/Not reported/);assert.doesNotMatch(html,/198\.51\.100\./);html=env.run('serverDrawerHeaderHTML(unreportedHost)');assert.match(html,/Agent IPs not reported/);assert.doesNotMatch(html,/198\.51\.100\./);
 env.run('unreportedHost.ips=["10.241.55.21"]');html=env.run('serverRows().html');assert.match(html,/10\.241\.55\.21/);assert.doesNotMatch(html,/198\.51\.100\./);html=env.run('serverDrawerHeaderHTML(unreportedHost)');assert.match(html,/10\.241\.55\.21/);assert.doesNotMatch(html,/198\.51\.100\./);
 env.run('state.reservations=[{id:"planned-one",hostname:"future-server",ips:[],planned_ips:["198.51.100.14"]}]');html=env.run('serverReservationsHTML()');assert.match(html,/Planned addresses · unverified/);assert.match(html,/198\.51\.100\.14/);assert.match(html,/do not enter source-policy membership/);
});

const pollingSettings={revision:2,defaults:{control_interval_seconds:60,discovery_interval_seconds:900},rules:[],servers:[{server_id:'host-1',hostname:'lab-api',desired:{version:2,digest:'a'.repeat(64),control_interval_seconds:15,discovery_interval_seconds:120},reported_control_interval_seconds:60,reported_discovery_interval_seconds:900,supported:true,status:'pending',observed:{version:1,status:'applied',reported_at:'2026-10-30T10:00:00Z'}},{server_id:'old-agent',hostname:'legacy-agent',desired:{version:2,control_interval_seconds:60,discovery_interval_seconds:900},supported:false,status:'unsupported'}]};
function pollingPreview(){return {before:pollingSettings,after:{...pollingSettings,revision:3},effective_change_count:1,target_server_count:2,affected_servers:[{server_id:'host-1',hostname:'lab-api',supported:true,before:{control_interval_seconds:60,discovery_interval_seconds:900},after:{control_interval_seconds:15,discovery_interval_seconds:120}}]};}
function pollingRuleRow(values){const controls=new Map(Object.entries(values).map(([name,value])=>[name,typeof value==='object'?value:{value}]));return {dataset:{id:values.id || ''},querySelector:selector=>controls.get(selector.match(/name="([^"]+)"/)?.[1])};}
test('central agent polling previews exact global and scoped timing intent then saves only the reviewed revision',async()=>{
 const env=await workspace('settings',{mode:'entra',role:'super_admin',responses:{'/api/v1/platform/agent-settings':pollingSettings,'POST /api/v1/platform/agent-settings/preview':pollingPreview()}});await env.click('platform-tab',{tab:'agents'});await new Promise(setImmediate);let html=env.element('#view-content').innerHTML;assert.match(html,/Agent polling and discovery/);assert.match(html,/Agent 0.5.0 or later/);assert.match(html,/Last reported polling \/ discovery/);assert.match(html,/Pending agent/);assert.match(html,/Upgrade agent/);assert.doesNotMatch(html,/Current · agent applied/);
 const form=renderedForm(env,'platform-agent-settings-form',{control_interval_seconds:'60',discovery_interval_seconds:'900'});const billing=pollingRuleRow({id:'billing-rule',polling_rule_name:'Billing fast polling',polling_rule_priority:'10',polling_rule_enabled:{checked:true},polling_rule_target:'tags',polling_rule_selector:'application=billing',polling_rule_control:'15',polling_rule_discovery:'120'}),payments=pollingRuleRow({id:'payments-rule',polling_rule_name:'Payments group',polling_rule_priority:'20',polling_rule_enabled:{checked:true},polling_rule_target:'groups',polling_rule_groups:{selectedOptions:[{value:'payments-group'}]},polling_rule_control:'30',polling_rule_discovery:''});form.querySelectorAll=selector=>selector==='.agent-polling-rule'?[billing,payments]:[];
 await env.click('platform-agents-save');assert.equal(mutations(env).length,0);await submitRendered(env,form);let request=mutations(env)[0],body=JSON.parse(request.options.body);assert.equal(request.url,'/api/v1/platform/agent-settings/preview');assert.equal(body.expected_revision,2);assert.deepEqual(body.defaults,{control_interval_seconds:60,discovery_interval_seconds:900});assert.deepEqual(body.rules,[{id:'billing-rule',name:'Billing fast polling',priority:10,enabled:true,server_ids:[],group_ids:[],selector:{application:'billing'},control_interval_seconds:15,discovery_interval_seconds:120},{id:'payments-rule',name:'Payments group',priority:20,enabled:true,server_ids:[],group_ids:['payments-group'],selector:{},control_interval_seconds:30}]);assert.equal(body.enforce,undefined);assert.match(env.element('#agent-polling-impact').innerHTML,/60s \/ 900s → 15s \/ 120s/);assert.match(env.element('#agent-polling-impact').innerHTML,/Saving creates versioned timing intent/);
 await env.click('platform-agents-save');request=mutations(env)[1];assert.equal(request.url,'/api/v1/platform/agent-settings');assert.deepEqual(JSON.parse(request.options.body),body);assertCookieMutation(request);html=env.element('#view-content').innerHTML;assert.match(html,/Pending agent/);
});
test('polling interval bounds, changed drafts, stale revisions and role guards cannot save unintended timing',async()=>{
 const env=await workspace('settings',{mode:'entra',role:'super_admin',responses:{'/api/v1/platform/agent-settings':pollingSettings,'POST /api/v1/platform/agent-settings/preview':pollingPreview(),'POST /api/v1/platform/agent-settings':{responseStatus:409,data:{error:'Polling settings changed; reload'}}}});await env.click('platform-tab',{tab:'agents'});await new Promise(setImmediate);const form=renderedForm(env,'platform-agent-settings-form',{control_interval_seconds:'4',discovery_interval_seconds:'900'});await submitRendered(env,form);assert.equal(mutations(env).length,0);assert.match(env.element('#platform-agent-settings-error').textContent,/5 to 3600/);form.values.control_interval_seconds='60';form.values.discovery_interval_seconds='86401';await submitRendered(env,form);assert.equal(mutations(env).length,0);form.values.discovery_interval_seconds='900';await submitRendered(env,form);form.values.control_interval_seconds='90';await env.click('platform-agents-save');assert.equal(mutations(env).length,1);assert.match(env.element('#platform-agent-settings-error').textContent,/Preview the current polling changes/);await submitRendered(env,form);await env.click('platform-agents-save');assert.equal(mutations(env).length,3);assert.equal(form.reviewedPolling,null);await env.click('platform-agents-save');assert.equal(mutations(env).length,3);
 for(const role of ['read_only','admin']){const denied=await workspace('settings',{mode:'entra',role});await denied.click('platform-tab',{tab:'agents'});assert.equal(denied.run('state.platformTab'),'overview');await denied.click('platform-agents-save');await denied.listeners.submit.at(-1)({preventDefault(){},target:{id:'platform-agent-settings-form',values:{}}});assert.equal(mutations(denied).length,0);}
});
test('background overview and platform refresh preserve an added polling override, reviewed draft and expansion after focus leaves the form',async()=>{
 const env=await workspace('settings',{mode:'entra',role:'super_admin',responses:{'/api/v1/platform/agent-settings':pollingSettings,'POST /api/v1/platform/agent-settings/preview':pollingPreview()}});await env.click('platform-tab',{tab:'agents'});await new Promise(setImmediate);env.listeners.toggle.at(-1)({target:{open:true,matches:selector=>selector==='.agent-polling-overrides'}});await env.run('loadPlatformAgentSettings()');assert.match(env.element('#view-content').innerHTML,/<details class="agent-polling-overrides" open>/);
 const form=renderedForm(env,'platform-agent-settings-form',{control_interval_seconds:'60',discovery_interval_seconds:'900'}),container=env.element('#agent-polling-rules');container.insertAdjacentHTML=(_,html)=>{container.innerHTML+=html;};await env.click('platform-agent-rule-add');assert.match(container.innerHTML,/name="polling_rule_name"/);assert.equal(env.run('platformHasDraft()'),true);
 const row=pollingRuleRow({id:'',polling_rule_name:'Billing draft kept after blur',polling_rule_priority:'10',polling_rule_enabled:{checked:true},polling_rule_target:'tags',polling_rule_selector:'application=billing',polling_rule_control:'15',polling_rule_discovery:'120'});form.querySelectorAll=selector=>selector==='.agent-polling-rule'?[row]:[];env.listeners.input.at(-1)({target:{id:'polling-rule-name',closest:()=>form}});assert.equal(env.element('#agent-polling-override-count').textContent,'1');await submitRendered(env,form);const reviewed=structuredClone(form.reviewedPolling),view=env.element('#view-content');let writes=0,html=view.innerHTML;Object.defineProperty(view,'innerHTML',{get(){return html;},set(value){writes++;html=value;}});
 await env.run('load({quiet:true})');await new Promise(setImmediate);await env.run('loadPlatformSettings()');await env.run('loadPlatformAgentSettings()');assert.equal(writes,0,'background refresh must not replace the live form DOM after Add override or preview');assert.equal(JSON.stringify(form.reviewedPolling),JSON.stringify(reviewed));assert.equal(env.run('state.platformAgentOverridesOpen'),true);assert.equal(env.element('[data-action="platform-agents-discard"]').hidden,false);
 await env.click('platform-agents-save');assert.equal(mutations(env).filter(request=>request.url==='/api/v1/platform/agent-settings').length,1);assert.equal(env.run('platformHasDraft()'),false);assert.ok(writes>0,'successful save may refresh the clean form');
});
test('platform credential and schedule drafts survive background refresh and explicit discard reloads saved polling settings',async()=>{
 for(const [tab,id,values] of [['cluster','platform-appliance-config-form',{cluster_password:'unsaved-private-password'}],['backups','platform-backup-schedule-form',{time:'03:15'}],['certificates','platform-certificate-form',{key_password:'unsaved-private-pem-password'}]]){const env=await applianceWorkspace({'/api/v1/platform/certificates':{current:{}}});await env.click('platform-tab',{tab});await new Promise(setImmediate);const form=renderedForm(env,id,values);env.listeners.input.at(-1)({target:{id:'draft-field',closest:selector=>selector==='form'?form:null}});const view=env.element('#view-content');let writes=0,html=view.innerHTML;Object.defineProperty(view,'innerHTML',{get(){return html;},set(value){writes++;html=value;}});await env.run('load({quiet:true})');await new Promise(setImmediate);await env.run('loadPlatformBackupSchedule()');await env.run('loadPlatformCertificates()');assert.equal(writes,0,id+' must retain its DOM when focus leaves a dirty platform form');assert.equal(env.storageChanges.some(change=>String(change.value).includes('unsaved-private')),false);}
 const env=await workspace('settings',{mode:'entra',role:'super_admin',responses:{'/api/v1/platform/agent-settings':pollingSettings}});await env.click('platform-tab',{tab:'agents'});await new Promise(setImmediate);const form=renderedForm(env,'platform-agent-settings-form',{control_interval_seconds:'15',discovery_interval_seconds:'120'});env.context.draft=form;env.run('platformMarkDraft(draft)');await env.click('platform-agents-discard');assert.equal(env.run('platformHasDraft()'),false);assert.match(env.element('#view-content').innerHTML,/id="agent-global-control"[^>]*value="60"/);assert.equal(mutations(env).length,0);
});
test('PKCS12 files are read locally for one review and private archive/password contents never appear in review output',async()=>{
 const env=await applianceWorkspace({'/api/v1/platform/certificates':{current:{}},'POST /api/v1/platform/certificates/preview':applianceReview({summary:{certificate:{subject:'CN=uploaded.example.test',sans:['uploaded.example.test']}}})});await env.click('platform-tab',{tab:'certificates'});await new Promise(setImmediate);env.context.FileReader=class{readAsDataURL(file){this.result='data:application/x-pkcs12;base64,'+file.base64;this.onload();}};env.context.fileEvent={target:{id:'certificate-pkcs12-file',files:[{name:'controller.p12',size:1234,base64:'cHJpdmF0ZS1wa2NzMTI='}]}};env.run('platformCertificateChange(fileEvent)');assert.match(env.element('#certificate-file-status').textContent,/loaded locally/);const form=renderedForm(env,'platform-certificate-form',{mode:'pkcs12',password:'private-p12-password'});await submitRendered(env,form);const request=mutations(env)[0];assert.deepEqual(JSON.parse(request.options.body),{mode:'pkcs12',pkcs12_base64:'cHJpdmF0ZS1wa2NzMTI=',password:'private-p12-password'});assert.equal(env.run('state.platformP12Base64'),'');assert.doesNotMatch(env.element('#modal-content').innerHTML,/cHJpdmF0ZS1wa2NzMTI|private-p12-password/);assert.equal(env.storageChanges.some(change=>String(change.value).includes('cHJpdmF0ZS')),false);
});

const notificationConfig={revision:4,enabled:false,channels:[{id:'security-hooks',name:'Security webhooks',type:'webhook',enabled:true,minimum_severity:'warning',event_types:['*'],host:'alerts.example.test',port:443,addresses:['8.8.8.8'],destination:'https://alerts.example.test/…',credential_flags:{url_configured:true,signing_secret_configured:true}}]};
const notificationDelivery={id:'delivery-one',channel_id:'security-hooks',channel_name:'Security webhooks',channel_type:'webhook',destination:'https://alerts.example.test/…',event:{kind:'port_scan'},status:'uncertain',attempts:2,error:'Acknowledgement unknown',created_at:'2026-10-31T00:00:00Z'};
function notificationFixtureRow(values={},choices=['*']){const defaults={name:'Security webhooks',type:'webhook',enabled:{checked:true},minimum_severity:'warning',event_types:'',allow_private_network:{checked:false},idempotency_supported:{checked:false},url:'',signing_secret:'',auth_token:'',smtp_host:'',smtp_port:'587',smtp_security:'starttls',username:'',password:'',from_address:'',to_addresses:'',custom_ca_pem:''},controls=new Map(Object.entries({...defaults,...values}).map(([name,value])=>['channel_'+name,typeof value==='object'?value:{value}]));return {dataset:{id:'security-hooks'},querySelector:selector=>controls.get(selector.match(/name="([^"]+)"/)?.[1]),querySelectorAll:selector=>selector==='input[name="channel_event_choice"]:checked'?choices.map(value=>({value})):[]};}
async function notificationWorkspace(extra={}){return applianceWorkspace({'/api/v1/platform/notifications':notificationConfig,'/api/v1/platform/notifications/deliveries?limit=50&offset=0':{items:[notificationDelivery],total:1,limit:50,offset:0,has_more:false},...extra});}
test('notification forms require an exact destination review and never display or store submitted credentials',async()=>{
 const plan=applianceReview({id:'notification-review',summary:{enabled:true,channels:notificationConfig.channels},confirmation_phrase:'ENABLE REVIEWED NOTIFICATIONS'}),env=await notificationWorkspace({'POST /api/v1/platform/notifications/preview':plan,'POST /api/v1/platform/notifications/apply':{...notificationConfig,revision:5}});await env.click('platform-tab',{tab:'notifications'});await new Promise(setImmediate);let html=env.element('#view-content').innerHTML;assert.match(html,/Credentials stay encrypted/);assert.match(html,/Acknowledgement unknown/);assert.match(html,/name="channel_url" type="password"/);assert.doesNotMatch(html,/private-notification-token/);
 const form=renderedForm(env,'platform-notification-form',{enabled:'on'}),row=notificationFixtureRow({url:'https://alerts.example.test/private-notification-token',signing_secret:'private-hmac-secret'});form.querySelectorAll=selector=>selector==='.notification-channel'?[row]:[];await submitRendered(env,form);let request=mutations(env)[0],body=JSON.parse(request.options.body);assert.equal(request.url,'/api/v1/platform/notifications/preview');assert.equal(body.expected_revision,4);assert.equal(body.enabled,true);assert.equal(body.channels[0].url,'https://alerts.example.test/private-notification-token');assert.equal(body.channels[0].signing_secret,'private-hmac-secret');assertCookieMutation(request);html=env.element('#modal-content').innerHTML;assert.match(html,/8\.8\.8\.8/);assert.doesNotMatch(html,/private-notification-token|private-hmac-secret/);
 const review=renderedForm(env,'platform-notification-review-form',{confirmation_phrase:'yes'});await submitRendered(env,review);assert.equal(mutations(env).length,1);review.values.confirmation_phrase=plan.confirmation_phrase;await submitRendered(env,review);request=mutations(env)[1];assert.equal(request.url,'/api/v1/platform/notifications/apply');assert.deepEqual(JSON.parse(request.options.body),{preview_id:plan.id,digest:plan.digest,confirmation_nonce:plan.confirmation_nonce,confirmation_phrase:plan.confirmation_phrase});assertCookieMutation(request);assert.equal(env.storageChanges.some(change=>String(change.value).includes('private-hmac-secret')),false);
});
test('actual notification test and uncertain retry each require explicit saved-destination confirmation',async()=>{
 const env=await notificationWorkspace({'POST /api/v1/platform/notifications/channels/security-hooks/test':{id:'test-delivery',status:'pending'},'POST /api/v1/platform/notifications/deliveries/delivery-one/retry':{...notificationDelivery,status:'retry'}});await env.click('platform-tab',{tab:'notifications'});await new Promise(setImmediate);await env.click('platform-notification-test',{id:'security-hooks'});assert.equal(mutations(env).length,0);assert.match(env.element('#modal-content').innerHTML,/real configuration-test message/);let form=renderedForm(env,'platform-notification-send-form',{});await submitRendered(env,form);let request=mutations(env)[0],body=JSON.parse(request.options.body);assert.equal(request.url,'/api/v1/platform/notifications/channels/security-hooks/test');assert.equal(body.confirm,true);assert.equal(body.expected_revision,4);assert.ok(body.request_id);assertCookieMutation(request);
 await env.click('platform-notification-retry',{id:'delivery-one'});form=renderedForm(env,'platform-notification-send-form',{});await submitRendered(env,form);assert.equal(mutations(env).length,1);form.values.confirm_duplicate='on';await submitRendered(env,form);request=mutations(env)[1];assert.deepEqual(JSON.parse(request.options.body),{expected_revision:4,expected_attempts:2,confirm_possible_duplicate:true});assertCookieMutation(request);assert.match(env.element('#view-content').innerHTML,/Acknowledgement unknown/);
});
test('SMTP channels start with no alerts selected and submit only chosen event types',async()=>{
 const email={id:'security-email',name:'Security email',type:'email',enabled:true,minimum_severity:'info',event_types:['service_discovered','service_down','traffic_burst','admin_change','port_allowed','agent_offline'],destination:'smtp.example.test:587',addresses:['192.0.2.23'],to_addresses:['oncall@example.test']};
 const plan=applianceReview({summary:{enabled:true,channels:[email]},confirmation_phrase:'ENABLE REVIEWED NOTIFICATIONS'});
 const env=await notificationWorkspace({'POST /api/v1/platform/notifications/preview':plan});
 await env.click('platform-tab',{tab:'notifications'});
 await new Promise(setImmediate);
 assert.match(env.element('#view-content').innerHTML,/Add email channel/);
 const channels=env.element('#notification-channels');
 channels.insertAdjacentHTML=(_,html)=>{channels.innerHTML=html;};
 await env.click('platform-notification-add-email');
 assert.match(channels.innerHTML,/<option value="email" selected>/);
 assert.match(channels.innerHTML,/<option value="warning" selected>/);
 assert.match(channels.innerHTML,/SMTP hostname/);
 assert.match(channels.innerHTML,/value="service_down" >Service down/);
 assert.match(channels.innerHTML,/value="controller_resource_pressure" >Controller CPU, memory and storage/);
 assert.match(channels.innerHTML,/value="agent_resource_pressure" >Endpoint agent CPU, memory and storage/);
 assert.match(channels.innerHTML,/100 observed connections or denied packets/);
 assert.doesNotMatch(channels.innerHTML,/name="channel_event_choice"[^>]*checked/);
 const form=renderedForm(env,'platform-notification-form',{enabled:'on'});
 const fields={type:'email',name:'Security email',minimum_severity:'info',smtp_host:'smtp.example.test',from_address:'alerts@example.test',to_addresses:'oncall@example.test',password:'smtp-private-pass'};
 form.querySelectorAll=selector=>selector==='.notification-channel'?[notificationFixtureRow(fields,[])]:[];
 await submitRendered(env,form);
 assert.equal(mutations(env).length,0);
 assert.match(env.element('#platform-notification-error').textContent,/Select at least one alert type/);
 const choices=['service_discovered','service_down','traffic_burst','admin_change','port_allowed'];
 const row=notificationFixtureRow({...fields,event_types:'agent_offline, traffic_burst'},choices);
 delete row.dataset.id;
 form.querySelectorAll=selector=>selector==='.notification-channel'?[row]:[];
 await submitRendered(env,form);
 const request=mutations(env)[0];
 assert.equal(request.url,'/api/v1/platform/notifications/preview');
 const channel=JSON.parse(request.options.body).channels[0];
 assert.deepEqual(channel.event_types,email.event_types);
 assert.equal(channel.minimum_severity,'info');
 assert.equal(channel.smtp_host,'smtp.example.test');
 assert.equal(channel.password,'smtp-private-pass');
 assert.match(env.element('#modal-content').innerHTML,/Service down, Monitored traffic bursts, Admin changes, Confirmed port allowances/);
 assert.doesNotMatch(env.element('#modal-content').innerHTML,/smtp-private-pass/);
});
test('saved SMTP filters preserve standard alerts, explicit categories and custom event codes',async()=>{
 const channel={...notificationConfig.channels[0],type:'email',minimum_severity:'info',event_types:['*','port_allowed','recovered']};
 const env=await notificationWorkspace({'/api/v1/platform/notifications':{...notificationConfig,channels:[channel]}});
 await env.click('platform-tab',{tab:'notifications'});
 await new Promise(setImmediate);
 const html=env.element('#view-content').innerHTML;
 assert.match(html,/value="\*" checked>All standard alerts \(includes new services\)/);
 assert.match(html,/value="port_allowed" checked>Confirmed port allowances/);
 assert.match(html,/name="channel_event_types" value="recovered"/);
 const row=notificationFixtureRow({type:'email',event_types:'recovered'},['*','port_allowed']);
 env.context.testNotificationRow=row;
 assert.deepEqual(Array.from(env.run('notificationEventTypes(testNotificationRow,"email")')),channel.event_types);
 assert.deepEqual(Array.from(env.run('notificationEventTypes(testNotificationRow,"webhook")')),['*','recovered']);
});
test('notification send actions are blocked in demo and all notification forms stay Super Admin only',async()=>{
 for(const role of ['read_only','admin']){const env=await workspace('settings',{mode:'entra',role});await env.click('platform-tab',{tab:'notifications'});assert.equal(env.run('state.platformTab'),'overview');await env.click('platform-notification-test',{id:'security-hooks'});await env.listeners.submit.at(-1)({preventDefault(){},target:{id:'platform-notification-form',values:{}}});assert.equal(mutations(env).length,0);}
 const demo=await workspace('settings',{responses:{'/api/v1/platform/notifications':notificationConfig}});await demo.click('platform-tab',{tab:'notifications'});await new Promise(setImmediate);await demo.click('platform-notification-test',{id:'security-hooks'});assert.equal(mutations(demo).length,0);assert.match(demo.element('#view-content').innerHTML,/External notification sends are blocked/);
});
const endpointCertificate={id:'endpoint_certificate:one',server_id:'host-1',hostname:'lab-api',fingerprint_sha256:'c'.repeat(64),serial_number:'abcd',status:'active',not_after:'2027-10-31T00:00:00Z'};
test('bulk endpoint certificate renewal requires a reviewed phrase and distinguishes confirmation from scheduling',async()=>{
 const endpointAPI='/api/v1/platform/endpoint-certificates';
 const certificateListing={items:[endpointCertificate],renewal_available:true,renewal_eligible:2,renewal_rollout:null};
 const plan={id:'endpoint_renewal_review:fixture',digest:'a'.repeat(64),confirmation_nonce:'renewal-nonce',confirmation_phrase:'RENEW ENDPOINT CERTIFICATES',expires_at:new Date(Date.now()+60000).toISOString(),target_count:2,skipped_count:1,batch_size:20,interval_seconds:60};
 const running={id:'rollout-1',status:'running',target_count:2,counts:{issued:1,confirmed:1,expired:0,superseded:0}};
 const env=await applianceWorkspace({[endpointAPI]:certificateListing,['POST '+endpointAPI+'/renewal-preview']:plan,['POST '+endpointAPI+'/renewal-apply']:running});
 await env.click('platform-tab',{tab:'certificates'});
 await new Promise(setImmediate);
 assert.match(env.element('#view-content').innerHTML,/2 eligible endpoints · No agent restart/);
 env.listeners.toggle.at(-1)({target:{id:'platform-certificate-operations',open:true}});
 await env.click('platform-endpoint-renewal-preview');
 assert.equal(env.element('#modal-title').textContent,'Review bulk certificate renewal');
 assert.match(env.element('#modal-content').innerHTML,/2 eligible endpoints<\/strong> · 1 skipped/);
 assert.match(env.element('#modal-content').innerHTML,/20 endpoints per 60 seconds/);
 assert.deepEqual(JSON.parse(mutations(env)[0].options.body),{});
 const form=renderedForm(env,'platform-endpoint-renewal-form',{confirmation_phrase:'renew endpoint certificates'});
 await submitRendered(env,form);
 assert.equal(mutations(env).length,1);
 env.context.apiResponses[endpointAPI]={...certificateListing,renewal_rollout:running,items:[{...endpointCertificate,renewal_status:'issued'}]};
 form.values.confirmation_phrase=plan.confirmation_phrase;
 await submitRendered(env,form);
 const request=mutations(env)[1];
 assert.equal(request.url,endpointAPI+'/renewal-apply');
 assert.deepEqual(JSON.parse(request.options.body),{preview_id:plan.id,digest:plan.digest,confirmation_nonce:plan.confirmation_nonce,confirmation_phrase:plan.confirmation_phrase});
 assertCookieMutation(request);
 const html=env.element('#view-content').innerHTML;
 assert.match(html,/id="platform-certificate-operations"[^>]* open>/);
 assert.match(html,/1 confirmed of 2 · 1 waiting/);
 assert.match(html,/Awaiting confirmation/);
 assert.match(html,/data-action="platform-endpoint-renewal-preview" disabled/);
});
test('bulk endpoint renewal hides on old controllers and blocks unavailable, empty, and non-Super Admin requests',async()=>{
 const endpointAPI='/api/v1/platform/endpoint-certificates';
 for(const listing of [{items:[]},{items:[],renewal_available:false,renewal_eligible:2},{items:[],renewal_available:true,renewal_eligible:0}]){
  const env=await applianceWorkspace({[endpointAPI]:listing});
  await env.click('platform-tab',{tab:'certificates'});
  await new Promise(setImmediate);
  const html=env.element('#view-content').innerHTML;
  if('renewal_available' in listing)assert.match(html,/data-action="platform-endpoint-renewal-preview" disabled/);
  else assert.doesNotMatch(html,/Bulk certificate renewal/);
  await env.click('platform-endpoint-renewal-preview');
  assert.equal(mutations(env).length,0);
 }
 for(const role of ['read_only','admin']){
  const env=await workspace('settings',{mode:'entra',role});
  env.run('state.platformEndpointCertificates={renewal_available:true,renewal_eligible:2}');
  await env.click('platform-endpoint-renewal-preview');
  await env.listeners.submit.at(-1)({preventDefault(){},target:{id:'platform-endpoint-renewal-form'}});
  assert.equal(mutations(env).length,0);
 }
});
test('endpoint revocation is typed and exact while recovery credentials are shown once without browser storage',async()=>{
 const plan={id:'endpoint_revoke:one',digest:'d'.repeat(64),confirmation_nonce:'endpoint-revoke-nonce',confirmation_phrase:'REVOKE lab-api',certificate_ids:[endpointCertificate.id],expires_at:new Date(Date.now()+60000).toISOString(),message:'Registered identities will stop authenticating; existing firewall rules remain.'},env=await applianceWorkspace({'/api/v1/platform/endpoint-certificates':{items:[endpointCertificate],renewal_window_days:30,old_certificate_overlap_hours:24},'POST /api/v1/platform/endpoint-certificates/revoke-preview':plan,'POST /api/v1/platform/endpoint-certificates/revoke-apply':{status:'revoked'},'POST /api/v1/platform/endpoint-certificates/recovery-token':{token:'private-one-time-recovery-token',server_id:'host-1',expires_at:new Date(Date.now()+900000).toISOString(),one_time:true}});await env.click('platform-tab',{tab:'certificates'});await new Promise(setImmediate);assert.match(env.element('#view-content').innerHTML,/Endpoint certificate identities/);assert.match(env.element('#view-content').innerHTML,/old|Previous-credential overlap/);await env.click('platform-endpoint-revoke',{id:'host-1'});assert.equal(mutations(env)[0].url,'/api/v1/platform/endpoint-certificates/revoke-preview');const form=renderedForm(env,'platform-endpoint-revoke-form',{confirmation_phrase:'REVOKE somebody-else'});await submitRendered(env,form);assert.equal(mutations(env).length,1);form.values.confirmation_phrase=plan.confirmation_phrase;await submitRendered(env,form);const request=mutations(env)[1];assert.equal(request.url,'/api/v1/platform/endpoint-certificates/revoke-apply');assert.deepEqual(JSON.parse(request.options.body),{preview_id:plan.id,digest:plan.digest,confirmation_nonce:plan.confirmation_nonce,confirmation_phrase:plan.confirmation_phrase});assertCookieMutation(request);
 await env.click('platform-endpoint-recovery',{id:'host-1'});assert.match(env.element('#modal-content').innerHTML,/private-one-time-recovery-token/);assert.equal(env.storageChanges.some(change=>String(change.value).includes('private-one-time-recovery-token')),false);env.run('closeModal()');assert.doesNotMatch(env.element('#modal-content').innerHTML,/private-one-time-recovery-token/);
});
test('endpoint status and signing trust show actual expiry, full public-key fingerprint and an exact public JSON download',async()=>{
 const bytes=Buffer.alloc(32,7),trust={deployment_id:'trust-deployment',keys:{'signing-key':bytes.toString('base64')}},env=await applianceWorkspace({'/api/v1/platform/endpoint-certificates':{items:[{...endpointCertificate,not_after:'2020-01-01T00:00:00Z'},{...endpointCertificate,id:'revoked',status:'revoked'}]},'/api/v1/platform/policy-signing-trust':trust});env.context.crypto=require('node:crypto').webcrypto;env.context.atob=globalThis.atob;await env.click('platform-tab',{tab:'certificates'});await new Promise(resolve=>setTimeout(resolve,20));const html=env.element('#view-content').innerHTML;assert.match(html,/Expired/);assert.match(html,/Revoked/);assert.match(html,new RegExp(require('node:crypto').createHash('sha256').update(bytes).digest('hex')));let download;env.context.URL.createObjectURL=blob=>{download=blob;return 'blob:public-trust';};env.context.URL.revokeObjectURL=()=>{};await env.click('platform-policy-trust-download');assert.deepEqual(JSON.parse(await download.text()),trust);assert.equal(env.element('created:a').download,'prthak-policy-trust.json');assert.equal(mutations(env).length,0);
});
test('Read Only and Admin cannot revoke identities or obtain endpoint recovery credentials through GUI actions',async()=>{
 for(const role of ['read_only','admin']){const env=await workspace('settings',{mode:'entra',role});await env.click('platform-endpoint-revoke',{id:'host-1'});await env.click('platform-endpoint-recovery',{id:'host-1'});await env.listeners.submit.at(-1)({preventDefault(){},target:{id:'platform-endpoint-revoke-form',values:{}}});assert.equal(mutations(env).length,0);}
});


const approvalTenant='11111111-1111-1111-1111-111111111111',approvalMakerId=approvalTenant+':22222222-2222-2222-2222-222222222222',approvalCheckerId=approvalTenant+':33333333-3333-3333-3333-333333333333';
function approvalPerson(id){return {role:'admin',demo:false,auth_type:'session',csrf_token:'session-csrf-fixture',user:{id,tenant_id:approvalTenant,display_name:id===approvalMakerId?'Maker administrator':'Checker administrator',role:'admin'}};}
function accessAuthorityPlan(count=0,extra={}){return allowancePreview({name:'Exact Billing source allowance',status:count?'awaiting_second_confirmation':'reviewed',confirmation_count:count,confirmation_nonce:count?'checker-current-nonce':'maker-current-nonce',approval:{mode:'single_admin',stage:count?'submitted':'draft',requester:{user_id:approvalMakerId,tenant_id:approvalTenant,actor:'entra:'+approvalMakerId}},...extra});}
function approvalNavigation(plan){const {id,session_id,kind,name,status,created_at,expires_at,approval,confirmation_count}=plan;return {id,session_id,kind,name,status,created_at,expires_at,approval,confirmation_count,summary_only:true};}
test('learned changes queue loads exact details and the same current Admin applies once',async()=>{
 const plan=accessAuthorityPlan(),queue='/api/v1/learning-policies/approvals?limit=200&offset=0',route='POST /api/v1/learning/session-1/recommendations/apply';
 const env=await workspace('policies',{mode:'entra',role:'admin',identity:approvalPerson(approvalMakerId),responses:{[queue]:{items:[approvalNavigation(plan)],total:1},['/api/v1/learning-policies/approvals/'+plan.id]:plan,[route]:{pending_approval:false,policies:[learnedPolicy]}}});
 await env.run('loadLearningApprovals()');await env.click('recommendation-approval-open',{id:plan.id});assert.match(env.element('#modal-content').innerHTML,/192\.0\.2\.44\/32/);
 assert.doesNotMatch(env.element('#modal-content').innerHTML,/different.*administrator|pilot|Submit for independent/i);
 await submitRendered(env,renderedForm(env,'learned-policy-form',{}));assert.equal(mutations(env).length,1);assert.equal(mutations(env)[0].url,route.slice(5));
 assert.deepEqual(JSON.parse(mutations(env)[0].options.body),{confirm:true,preview_id:plan.id,confirmation_nonce:plan.confirmation_nonce,digest:plan.digest});assertCookieMutation(mutations(env)[0]);
});
test('automatic learning starts with the Admin session action and has no separate reviewer workflow',async()=>{
 const env=await workspace('traffic',{mode:'entra',role:'admin'});env.context.session={id:'session-1',status:'active',policy_action:'auto_allow',initial_approval_state:'approved',server_ports:{'host-1':[{port:443,protocol:'tcp'}]}};
 const html=env.run('initialLearningApprovalHTML(session)');assert.match(html,/frozen endpoint ports/);assert.match(html,/exact port it hit/);assert.doesNotMatch(html,/button|independent|approver|pilot/i);
 assert.equal(env.requests.some(row=>/approval-preview|approval-confirm/.test(row.url)),false);
});
test('production role tokens and expired reviews cannot replace the current authenticated Admin change',async()=>{
 const plan=accessAuthorityPlan(1),env=await workspace('policies',{mode:'tokens',role:'admin',storage:{'segment-token':'fixture-role-token'}});env.context.pendingPlan=plan;env.run('showLearningApprovalReview(pendingPlan)');assert.equal(env.run('learningApprovalReady(state.activeLearningApproval)'),false);const form=renderedForm(env,'learned-policy-form',{challenge:plan.confirmation_phrase});await submitRendered(env,form);assert.equal(mutations(env).length,0);
 const checker=await workspace('policies',{mode:'entra',role:'admin',identity:approvalPerson(approvalCheckerId)});checker.context.expiredPlan={...plan,expires_at:'2000-01-01T00:00:00Z'};checker.run('showLearningApprovalReview(expiredPlan)');await submitRendered(checker,renderedForm(checker,'learned-policy-form',{challenge:plan.confirmation_phrase}));assert.equal(mutations(checker).length,0);
});

test('learning review navigation fetches the fresh exact matrix and cannot authorize a summary or failed lookup',async()=>{
 const plan=accessAuthorityPlan(1),summary=approvalNavigation(plan),path='/api/v1/learning-policies/approvals/'+plan.id,env=await workspace('policies',{mode:'entra',identity:approvalPerson(approvalCheckerId),responses:{[path]:plan}});
 env.context.summary={...summary,confirmation_nonce:plan.confirmation_nonce};env.run('state.activeLearningApproval=summary');assert.equal(env.run('learningApprovalReady(summary)'),false);env.run('showLearningApprovalReview(summary)');assert.equal(env.run('state.activeLearningApproval'),null);
 await env.click('recommendation-approval-open',{id:plan.id});assert.equal(env.requests.filter(row=>row.url===path).length,1);assert.match(env.element('#modal-content').innerHTML,/192\.0\.2\.44\/32/);assert.equal(env.run('state.activeLearningApproval.confirmation_nonce'),plan.confirmation_nonce);
 for(const response of [{...summary,confirmation_nonce:plan.confirmation_nonce},{...plan,id:'another-review'},{responseStatus:400,data:{error:'Exact review exceeds its supported size'}}]){
  env.context.apiResponses[path]=response;await env.click('recommendation-approval-open',{id:plan.id});assert.equal(env.run('state.activeLearningApproval'),null);
 }
 assert.equal(mutations(env).length,0);
});


test('internal controller suspension is typed, blocks last-member reviews and never claims copied runtime credentials were revoked',async()=>{
 const info={revision:6,renew_before_days:30,leaf_lifetime_days:90,nodes:[{id:'controller-a',site:'Noida',ip:'10.1.50.11',state:'active',renewal_allowed:true,days_remaining:40,certificate:{fingerprint:'internal-fingerprint-a',not_after:'2027-10-31T00:00:00Z'},applied:{fingerprint:'internal-fingerprint-a',runtime_verified:true},decommission_gate:{can_suspend:true,blockers:['Fence the retired controller before offline CA and secret rotation']}},{id:'controller-b',site:'Pune',ip:'10.1.51.11',state:'suspended',renewal_allowed:false,certificate:{fingerprint:'internal-fingerprint-b'},applied:{fingerprint:'internal-fingerprint-b',runtime_verified:true},decommission_gate:{can_suspend:false,blockers:[]}}]},plan=applianceReview({id:'internal-suspension',confirmation_phrase:'SUSPEND CONTROLLER controller-a',can_apply:true,summary:{node:{id:'controller-a',site:'Noida',ip:'10.1.50.11'},warning:'Suspension does not revoke copied runtime credentials.'}}),env=await applianceWorkspace({'/api/v1/platform/internal-certificates':info,'POST /api/v1/platform/internal-certificates/suspend-preview':plan,'POST /api/v1/platform/internal-certificates/suspend-apply':{node_id:'controller-a',state:'suspended',runtime_credentials_revoked:false,requires_offline_recovery:true}});await env.click('platform-tab',{tab:'certificates'});await new Promise(setImmediate);let html=env.element('#view-content').innerHTML;assert.match(html,/Internal appliance identities/);assert.match(html,/Exact identity verified/);assert.match(html,/Suspended · credentials may remain valid/);assert.doesNotMatch(html,/>Revoked<\/span>/);await env.click('platform-internal-suspend',{id:'controller-a'});assert.deepEqual(JSON.parse(mutations(env)[0].options.body),{node_id:'controller-a',expected_revision:6});let form=renderedForm(env,'platform-internal-suspend-form',{confirmation_phrase:'yes'});await submitRendered(env,form);assert.equal(mutations(env).length,1);form.values.confirmation_phrase=plan.confirmation_phrase;await submitRendered(env,form);assert.equal(mutations(env)[1].url,'/api/v1/platform/internal-certificates/suspend-apply');assert.deepEqual(JSON.parse(mutations(env)[1].options.body),{preview_id:plan.id,digest:plan.digest,confirmation_nonce:plan.confirmation_nonce,confirmation_phrase:plan.confirmation_phrase});assertCookieMutation(mutations(env)[1]);
 env.context.apiResponses['POST /api/v1/platform/internal-certificates/suspend-preview']={...plan,can_apply:false,blockers:['Do not suspend the last active controller']};await env.click('platform-internal-suspend',{id:'controller-a'});form=renderedForm(env,'platform-internal-suspend-form',{confirmation_phrase:plan.confirmation_phrase});await submitRendered(env,form);assert.equal(mutations(env).length,3);assert.match(env.element('#modal-content').innerHTML,/Do not suspend the last active controller/);
});


function recoveryFixture(count=0){const digest='e'.repeat(64);return {id:'recovery-1',kind:'database-recovery-v1',status:count?'awaiting_second_confirmation':'draft',backend:'sqlite',source_node:'controller-noida',controller_ids:['controller-noida','controller-pune'],voters:[],backup:{id:'archive-1',created_at:'2026-10-30T12:00:00Z',backend:'sqlite',verified:true,status:'complete'},reason:'Recover from verified incident archive',digest,plan_digest:digest,can_restore:true,blockers:[],warnings:['All controllers must drain before the restored database is admitted.'],expires_at:new Date(Date.now()+60000).toISOString(),confirmation_count:count,confirmation_nonce:'recovery-nonce-'+count,confirmation_phrase:'RESTORE DATABASE '+digest.slice(0,12),approval:{mode:'single_admin',stage:count?'submitted':'requested',plan_digest:digest,requester:{user_id:'recovery-maker',tenant_id:'tenant-one',actor:'entra:recovery-maker',display_name:'Recovery maker',role:'super_admin'}}};}
function recoveryIdentity(id='recovery-maker',role='super_admin'){return {role,auth_type:'session',demo:false,csrf_token:'session-csrf-fixture',user:{id,tenant_id:'tenant-one',role,display_name:id}};}
async function recoveryWorkspace({id='recovery-maker',plan=recoveryFixture(),active=null,extra={}}={}){const env=await workspace('settings',{mode:'entra',identity:recoveryIdentity(id),responses:{'/api/v1/platform/status':{runtime:{demo:false},capabilities:{supervised:true},cluster:{nodes:[]}},'/api/v1/platform/recovery':{active,pending_reviews:plan?[plan]:[],requires_supervisor:true},'/api/v1/platform/backups':{items:[recoveryFixture().backup,{...recoveryFixture().backup,id:'pruned-archive',status:'pruned'},{...recoveryFixture().backup,id:'unverified-archive',verified:false}]},...extra}});await env.click('platform-tab',{tab:'recovery'});await new Promise(setImmediate);return env;}
test('Backups has one collapsed restore option and legacy recovery navigation opens it',async()=>{
 const env=await applianceWorkspace({'/api/v1/platform/recovery':{active:null,pending_reviews:[],requires_supervisor:true}});
 await env.click('platform-tab',{tab:'backups'});
 await new Promise(setImmediate);
 let html=env.element('#view-content').innerHTML;
 assert.doesNotMatch(html,/data-tab="recovery"|id="platform-recovery-request-form"/);
 assert.match(html,/aria-expanded="false" aria-controls="platform-restore-options">Restore a backup/);
 assert.equal(env.requests.filter(row=>row.url==='/api/v1/platform/recovery').length,0);
 await env.click('platform-restore-toggle');
 html=env.element('#view-content').innerHTML;
 assert.match(html,/aria-expanded="true" aria-controls="platform-restore-options">Restore a backup/);
 assert.match(html,/id="platform-recovery-request-form"/);
 assert.ok(html.indexOf('Database backups')<html.indexOf('Restore a backup'));
 await env.click('platform-restore-toggle');
 assert.doesNotMatch(env.element('#view-content').innerHTML,/id="platform-recovery-request-form"/);
 await env.click('platform-tab',{tab:'recovery'});
 await new Promise(setImmediate);
 assert.equal(env.run('state.platformTab'),'backups');
 assert.match(env.element('#view-content').innerHTML,/id="platform-recovery-request-form"/);
 assert.equal(mutations(env).length,0);
});
test('recovery keeps two explicit typed confirmations by the same live Super Admin',async()=>{
 const first=recoveryFixture(),second=recoveryFixture(1),env=await recoveryWorkspace({extra:{'POST /api/v1/platform/recovery/preview':first,'POST /api/v1/platform/recovery/confirm':{pending_approval:true,preview:second}}});
 assert.match(env.element('#view-content').innerHTML,/two explicit confirmations/);assert.doesNotMatch(env.element('#view-content').innerHTML,/different.*Super Admin|TWO SUPER ADMINS/i);
 await submitRendered(env,renderedForm(env,'platform-recovery-request-form',{backup_id:'archive-1',reason:first.reason}));
 await env.submit('platform-recovery-confirm-form',{confirmation_phrase:'wrong'});assert.equal(mutations(env).filter(row=>row.url.endsWith('/confirm')).length,0);
 await env.submit('platform-recovery-confirm-form',{confirmation_phrase:first.confirmation_phrase});let calls=mutations(env).filter(row=>row.url.endsWith('/confirm'));assert.equal(calls.length,1);assert.equal(JSON.parse(calls[0].options.body).confirmation_nonce,first.confirmation_nonce);
 assert.equal(env.run('platformRecoveryPlanReady(state.platformRecoveryReview,state.platformRecoveryReview.confirmation_phrase)'),true);
 env.context.apiResponses['POST /api/v1/platform/recovery/confirm']={pending_approval:false,job:{id:first.id,operation:'recovery',status:'queued',phase:'queued'}};
 await env.submit('platform-recovery-confirm-form',{confirmation_phrase:second.confirmation_phrase});calls=mutations(env).filter(row=>row.url.endsWith('/confirm'));assert.equal(calls.length,2);assert.notEqual(JSON.parse(calls[0].options.body).confirmation_nonce,JSON.parse(calls[1].options.body).confirmation_nonce);
 assert.match(env.element('#view-content').innerHTML,/Queued · not restored/);assert.doesNotMatch(env.element('#view-content').innerHTML,/Recovery verified/);
});
test('recovery fails closed for demo, role tokens, Admins, stale reviews and changed archive bindings',async()=>{
 const demo=await workspace('settings');await demo.click('platform-tab',{tab:'recovery'});await new Promise(setImmediate);assert.match(demo.element('#view-content').innerHTML,/unavailable in the synthetic demo/);assert.equal(demo.requests.filter(row=>row.url==='/api/v1/platform/recovery').length,0);
 const tokens=await workspace('settings',{mode:'tokens',storage:{'segment-token':'lab-token'}});tokens.run('state.platformInfo={runtime:{demo:false},capabilities:{supervised:true}};state.platformTab="recovery";render()');assert.equal(tokens.run('platformRecoveryCanRequest()'),false);assert.match(tokens.element('#view-content').innerHTML,/Shared role tokens cannot/);
 for(const role of ['admin','read_only']){const env=await workspace('settings',{mode:'entra',role,identity:recoveryIdentity('other',role)});assert.equal(env.run('platformRecoveryIdentityReady()'),false);await env.click('platform-recovery-review',{id:'recovery-1'});assert.equal(env.requests.filter(row=>row.url.includes('/platform/recovery')).length,0);}
 const checker=await recoveryWorkspace({id:'recovery-maker',plan:recoveryFixture(1),extra:{'POST /api/v1/platform/recovery/confirm':{responseStatus:409,data:{error:'Archive or deployment binding changed'}}}});await checker.click('platform-recovery-review',{id:'recovery-1'});checker.run('state.platformRecoveryReview.expires_at="2000-01-01T00:00:00Z"');await checker.submit('platform-recovery-confirm-form',{confirmation_phrase:recoveryFixture().confirmation_phrase});assert.equal(checker.requests.filter(row=>row.url==='/api/v1/platform/recovery/confirm').length,0);checker.context.testPlan=recoveryFixture(1);checker.run('state.platformRecoveryReview=testPlan');await checker.submit('platform-recovery-confirm-form',{confirmation_phrase:recoveryFixture().confirmation_phrase});assert.equal(checker.run('state.platformRecoveryReview'),null);assert.match(checker.run('state.platformRecoveryError'),/binding changed or expired/);
});
test('recovery status distinguishes verified completion, blocked controller receipts and session invalidation',async()=>{
 const active={id:'recovery-live',operation:'recovery',status:'blocked',phase:'draining',backup_id:'archive-1',controller_ids:['controller-noida','controller-pune'],acks:{drained:{'controller-noida':{verified:true}}},errors:{'controller-pune':'Waiting for this controller to fence its writer'}};
 const env=await recoveryWorkspace({active});assert.equal(env.run('platformRecoveryCanRequest()'),false);assert.match(env.element('#view-content').innerHTML,/Waiting for this controller to fence its writer/);assert.match(env.element('#view-content').innerHTML,/Exact controller receipts/);assert.doesNotMatch(env.element('#view-content').innerHTML,/Recovery verified/);
 env.context.apiResponses['/api/v1/platform/recovery']={active:{...active,status:'applied',phase:'completed',errors:{},result:{}},pending_reviews:[],requires_supervisor:true};await env.click('platform-recovery-refresh');assert.match(env.element('#view-content').innerHTML,/Completion verification not reported/);
 env.context.apiResponses['/api/v1/platform/recovery'].active.result={verified:true};await env.click('platform-recovery-refresh');assert.match(env.element('#view-content').innerHTML,/Recovery verified/);assert.match(env.element('#view-content').innerHTML,/Policy application and learning automation need fresh review/);
 env.context.apiResponses['/api/v1/platform/recovery']={responseStatus:401,data:{error:'Sessions invalidated by recovery'}};await env.click('platform-recovery-refresh');assert.equal(env.run('state.authType'),null);assert.match(env.run('state.authError'),/Sign in again with Entra.*durable outcome/);assert.equal(env.run('state.platformRecoveryReconnect'),true);
});
test('a background recovery refresh preserves an in-progress archive and reason draft',async()=>{
 const env=await recoveryWorkspace(),form=env.element('#platform-recovery-request-form');form.id='platform-recovery-request-form';form.values={backup_id:'archive-1',reason:'Keep the operator incident reason'};env.context.recoveryForm=form;env.run('platformMarkDraft(recoveryForm)');assert.equal(env.run('platformHasDraft()'),true);const before=env.element('#view-content').innerHTML;await env.run('loadPlatformRecovery()');assert.equal(env.element('#view-content').innerHTML,before);assert.equal(form.values.reason,'Keep the operator incident reason');
});
test('an incomplete recovery status cannot erase the last known active writer drain',async()=>{
 const active={id:'recovery-live',operation:'recovery',status:'running',phase:'draining',backup_id:'archive-1'};const env=await recoveryWorkspace({active});env.context.apiResponses['/api/v1/platform/recovery']={};await env.click('platform-recovery-refresh');assert.equal(env.run('state.platformRecovery.active.id'),'recovery-live');assert.match(env.run('state.platformRecoveryError'),/complete recovery status/);assert.match(env.element('#view-content').innerHTML,/Draining/);assert.doesNotMatch(env.element('#view-content').innerHTML,/Recovery verified/);
});

function applicationPortFixture(extra={}){return {revision:2,mode:'appliance_public',current_port:8787,desired_port:8787,applied_port:8787,bind_address:'192.0.2.18',current_url:'https://controller.example.test:8787',new_url:'https://controller.example.test:8787',controller_origin:'https://prthak.example.test',origin_mode:'preserve',allowed_range:{min:1,max:65535},can_apply:true,blockers:[],last_job:null,...extra};}
function applicationPortPlan(extra={}){return {id:'port-review-1',preview_id:'port-review-1',digest:'c'.repeat(64),expected_revision:2,current_port:8787,new_port:9443,current_url:'https://controller.example.test:8787',new_url:'https://controller.example.test:9443',bind_address:'192.0.2.18',can_apply:true,blockers:[],dependency_ack_required:true,dependencies:['Update the external load balancer target deliberately.','Direct agent URLs and Entra callbacks are not rewritten.'],confirmation_nonce:'port-nonce',confirmation_phrase:'CHANGE APPLICATION PORT 9443',expires_at:new Date(Date.now()+60000).toISOString(),...extra};}
async function applicationPortWorkspace(extra={}){const env=await workspace('settings',{mode:'entra',identity:recoveryIdentity(),responses:{'/api/v1/platform/status':{runtime:{demo:false},capabilities:{supervised:true},jobs:[]},'/api/v1/platform/appliance':{installed:true,manager_available:true,services:[]},'/api/v1/platform/application-port':applicationPortFixture(),...extra}});await env.click('platform-tab',{tab:'services'});await new Promise(setImmediate);return env;}
async function submitApplicationPort(env,port){assert.match(env.element('#view-content').innerHTML,/id="platform-application-port-form"/);return env.listeners.submit.at(-1)({preventDefault(){},target:{id:'platform-application-port-form',dataset:{revision:'2'},values:{port},querySelector:env.element}});}
test('Application port production form freezes revision, dependencies and typed phrase before queuing a local change',async()=>{
 const plan=applicationPortPlan(),env=await applicationPortWorkspace({'POST /api/v1/platform/application-port/preview':plan,'POST /api/v1/platform/application-port/apply':{id:'port-job',operation:'application-port',status:'queued',phase:'queued'}});let html=env.element('#view-content').innerHTML;assert.match(html,/Application port/);assert.match(html,/Last verified port/);assert.match(html,/configured application origin is preserved/);assert.match(html,/min="1" max="65535"/);assert.match(html,/Current direct address · last reported/);assert.match(html,/Open current address/);assert.doesNotMatch(html,/Proposed direct address|Open proposed address/);
 await submitApplicationPort(env,'9443');let request=env.requests.find(row=>row.url.endsWith('/application-port/preview'));assert.deepEqual(JSON.parse(request.options.body),{expected_revision:2,port:9443});assert.equal(request.options.headers['X-CSRF-Token'],'session-csrf-fixture');html=env.element('#modal-content').innerHTML;assert.match(html,/9443/);assert.match(html,/Direct agent URLs and Entra callbacks are not rewritten/);assert.match(html,/acknowledge_dependencies/);
 await env.submit('platform-application-port-review-form',{confirmation_phrase:plan.confirmation_phrase});assert.equal(env.requests.some(row=>row.url.endsWith('/application-port/apply')),false);await env.submit('platform-application-port-review-form',{confirmation_phrase:'wrong',acknowledge_dependencies:'on'});assert.equal(env.requests.some(row=>row.url.endsWith('/application-port/apply')),false);
 await env.submit('platform-application-port-review-form',{confirmation_phrase:plan.confirmation_phrase,acknowledge_dependencies:'on'});request=env.requests.find(row=>row.url.endsWith('/application-port/apply'));assert.deepEqual(JSON.parse(request.options.body),{preview_id:plan.id,digest:plan.digest,expected_revision:2,confirmation_nonce:plan.confirmation_nonce,confirmation_phrase:plan.confirmation_phrase,acknowledge_dependencies:true});assert.equal(request.options.headers['X-CSRF-Token'],'session-csrf-fixture');html=env.element('#view-content').innerHTML;assert.match(html,/Queued · awaiting port verification/);assert.match(html,/href="https:\/\/controller.example.test:9443\/"/);assert.match(html,/Open proposed address/);assert.doesNotMatch(html,/Open verified address/);assert.equal(env.run('state.platformApplicationPort.applied_port'),8787);assert.equal(env.navigation.length,0,'No automatic cross-port navigation');
});
test('port receipts distinguish active, verified rollback and failed rollback without inventing an applied listener',async()=>{
 const env=await applicationPortWorkspace(),job={id:'port-job',operation:'application-port',status:'applied',phase:'active',result:{applied_port:9443,new_url:'https://controller.example.test:9443',verified:false}};env.context.portJob=job;env.run('platformStoreJob(portJob);render()');assert.match(env.element('#view-content').innerHTML,/Port outcome not verified/);assert.match(env.element('#view-content').innerHTML,/Unknown · outcome unverified/);assert.notEqual(env.run('platformJobTone(portJob)'),'');
 job.result.verified=true;env.context.portJob=job;env.run('state.platformApplicationPort.current_port=9443;state.platformApplicationPort.desired_port=9443;state.platformApplicationPort.applied_port=9443;platformStoreJob(portJob);render()');assert.match(env.element('#view-content').innerHTML,/Open verified address/);
 job.status='rolled_back';job.phase='previous_port_restored';job.result={applied_port:8787,current_url:'https://controller.example.test:8787',verified:true};env.context.portJob=job;env.run('state.platformApplicationPort.current_port=8787;platformStoreJob(portJob);render()');assert.match(env.element('#view-content').innerHTML,/Previous port restored · verified/);assert.match(env.element('#view-content').innerHTML,/Open restored address/);assert.match(env.element('#view-content').innerHTML,/href="https:\/\/controller.example.test:8787\/"/);
 job.status='blocked';job.phase='rollback_failed';job.result.verified=false;env.context.portJob=job;env.run('platformStoreJob(portJob);render()');assert.match(env.element('#view-content').innerHTML,/listener not verified/);assert.match(env.element('#view-content').innerHTML,/Unknown · outcome unverified/);assert.doesNotMatch(env.element('#view-content').innerHTML,/Open verified address/);
});
test('port bounds support appliance443 while stale, unsafe and role-forged requests cannot apply',async()=>{
 const env=await applicationPortWorkspace({'POST /api/v1/platform/application-port/preview':applicationPortPlan({new_port:443,new_url:'https://controller.example.test:443'}),'POST /api/v1/platform/application-port/apply':{responseStatus:409,data:{error:'Port revision changed'}}});for(const value of ['0','65536','1e3','443.5','port443']){await submitApplicationPort(env,value);assert.equal(env.requests.some(row=>row.url.endsWith('/application-port/preview')),false);}
 await submitApplicationPort(env,'443');assert.equal(JSON.parse(env.requests.find(row=>row.url.endsWith('/application-port/preview')).options.body).port,443);const plan=applicationPortPlan();env.context.portPlan=plan;env.run('state.platformApplicationPortReview=portPlan;state.platformApplicationPortReview.expires_at="2000-01-01T00:00:00Z"');await env.submit('platform-application-port-review-form',{confirmation_phrase:plan.confirmation_phrase,acknowledge_dependencies:'on'});assert.equal(env.requests.some(row=>row.url.endsWith('/application-port/apply')),false);env.context.portPlan=applicationPortPlan();env.run('state.platformApplicationPortReview=portPlan');await env.submit('platform-application-port-review-form',{confirmation_phrase:plan.confirmation_phrase,acknowledge_dependencies:'on'});assert.equal(env.run('state.platformApplicationPortReview'),null);
 for(const role of ['admin','read_only']){const denied=await workspace('settings',{mode:'entra',role,identity:recoveryIdentity('viewer',role)});await denied.listeners.submit.at(-1)({preventDefault(){},target:{id:'platform-application-port-form',dataset:{revision:'2'},values:{port:'9443'},querySelector:denied.element}});assert.equal(denied.requests.some(row=>row.url.includes('/application-port')),false);}
 for(const url of ['javascript:alert(1)','https://operator:secret@example.test:9443','https://example.test:9443/?token=private','https://0.0.0.0:9443']){env.context.portURL=url;assert.equal(env.run('applicationPortURL(portURL)'),'');}
});
test('demo can review application port but never apply, and a dirty port draft survives status refresh',async()=>{
 const plan=applicationPortPlan({can_apply:false,blockers:['Synthetic demo cannot change its listener']}),demo=await workspace('settings',{responses:{'/api/v1/platform/application-port':applicationPortFixture({mode:'standalone',current_url:'http://localhost:8787',new_url:'http://localhost:8787',can_apply:false,blockers:plan.blockers}),'POST /api/v1/platform/application-port/preview':plan}});await demo.click('platform-tab',{tab:'services'});await new Promise(setImmediate);assert.match(demo.element('#view-content').innerHTML,/This controller’s application listener/);assert.doesNotMatch(demo.element('#view-content').innerHTML,/This controller’s HTTPS listener|Proposed direct address/);assert.match(demo.element('#view-content').innerHTML,/href="http:\/\/localhost:8787\/"/);await submitApplicationPort(demo,'9443');assert.match(demo.element('#modal-content').innerHTML,/Synthetic demo cannot/);await demo.submit('platform-application-port-review-form',{confirmation_phrase:plan.confirmation_phrase,acknowledge_dependencies:'on'});assert.equal(demo.requests.some(row=>row.url.endsWith('/application-port/apply')),false);
 const env=await applicationPortWorkspace(),form=env.element('#platform-application-port-form');form.id='platform-application-port-form';form.values={port:'9443'};env.context.portForm=form;env.run('platformMarkDraft(portForm)');const before=env.element('#view-content').innerHTML;env.context.apiResponses['/api/v1/platform/application-port']=applicationPortFixture({revision:3});await env.run('loadPlatformSettings()');assert.equal(env.element('#view-content').innerHTML,before);assert.equal(form.values.port,'9443');await env.click('platform-application-port-discard');assert.equal(env.run('platformHasDraft()'),false);assert.match(env.element('#view-content').innerHTML,/data-revision="3"/);
});
test('old-port disconnect keeps the proposed address and an unverified queued outcome available',async()=>{
 const plan=applicationPortPlan(),env=await applicationPortWorkspace({'POST /api/v1/platform/application-port/preview':plan,'POST /api/v1/platform/application-port/apply':{id:'port-job',operation:'application-port',status:'queued',phase:'queued'},'/api/v1/platform/jobs/port-job':{responseStatus:503,data:{error:'Previous listener is held'}}});await submitApplicationPort(env,'9443');await env.submit('platform-application-port-review-form',{confirmation_phrase:plan.confirmation_phrase,acknowledge_dependencies:'on'});await env.run('platformPollJob("port-job")');assert.match(env.run('state.platformOperationNotice'),/application port may have changed/);assert.match(env.element('#view-content').innerHTML,/Open proposed address/);assert.match(env.element('#view-content').innerHTML,/awaiting port verification/);assert.equal(env.run('state.platformApplicationPort.applied_port'),8787);assert.equal(env.navigation.length,0);
 env.context.apiResponses['/api/v1/platform/application-port']={};await env.run('loadPlatformApplicationPort()');assert.equal(env.run('state.platformApplicationPort.last_job.id'),'port-job');assert.match(env.run('state.platformApplicationPortError'),/complete application-port status/);assert.match(env.element('#view-content').innerHTML,/https:\/\/controller.example.test:9443/);
});
test('a missing local listener context displays its actual blocker and disables preview rather than inventing port8787',async()=>{
 const env=await applicationPortWorkspace({'/api/v1/platform/application-port':{revision:0,current_port:null,desired_port:null,applied_port:null,can_apply:false,blockers:['A local supervised controller is required'],allowed_range:{min:1,max:65535}}});assert.match(env.element('#view-content').innerHTML,/local supervised controller is required/);assert.match(env.element('#view-content').innerHTML,/Listener context unavailable/);assert.equal(env.run('applicationPortCanPreview()'),false);await submitApplicationPort(env,'9443');assert.equal(env.requests.some(row=>row.url.endsWith('/application-port/preview')),false);
});
test('a verified receipt for the wrong requested application port is not displayed as active',async()=>{
 const env=await applicationPortWorkspace();env.context.portJob={id:'bound-port-job',operation:'application-port',status:'applied',phase:'active',result:{verified:true,applied_port:8787,new_url:'https://controller.example.test:8787'}};env.run('state.platformApplicationPortTransition={id:"bound-port-job",new_port:9443,current_port:8787,new_url:"https://controller.example.test:9443"};platformStoreJob(portJob);render()');assert.equal(env.run('applicationPortVerified(portJob)'),false);assert.match(env.element('#view-content').innerHTML,/Port outcome not verified/);assert.doesNotMatch(env.element('#view-content').innerHTML,/Open verified address/);
 env.run('state.platformApplicationPortTransition.current_port=443;portJob.status="rolled_back";portJob.phase="previous_port_restored";portJob.result={verified:true,applied_port:8787,current_url:"https://controller.example.test:8787"};platformStoreJob(portJob);render()');assert.equal(env.run('applicationPortVerified(portJob)'),false,'An internal container port cannot stand in for the previous published port');assert.doesNotMatch(env.element('#view-content').innerHTML,/Open restored address/);
 env.run('portJob.result.applied_port=443;portJob.result.current_url="https://controller.example.test:443";platformStoreJob(portJob);render()');assert.equal(env.run('applicationPortVerified(portJob)'),true);assert.match(env.element('#view-content').innerHTML,/<dt>Last verified port<\/dt><dd>443<\/dd>/,'The exact verified receipt remains visible even before the next status refresh');assert.match(env.element('#view-content').innerHTML,/Open restored address/);
});
test('the reviewed new address survives an apply response lost during listener handover',async()=>{
 const plan=applicationPortPlan(),env=await applicationPortWorkspace({'POST /api/v1/platform/application-port/preview':plan,'POST /api/v1/platform/application-port/apply':()=>{throw new Error('Old listener disconnected before acknowledgement');}});await submitApplicationPort(env,'9443');assert.match(env.element('#modal-content').innerHTML,/href="https:\/\/controller.example.test:9443\/"/);await env.submit('platform-application-port-review-form',{confirmation_phrase:plan.confirmation_phrase,acknowledge_dependencies:'on'});assert.equal(env.run('state.platformApplicationPortCandidate.new_url'),plan.new_url);assert.equal(env.run('state.platformApplicationPort.last_job'),null);assert.match(env.element('#modal-content').innerHTML,/Open proposed address/);assert.equal(env.navigation.length,0);
});

function guiSetupStatus(overrides={}){return {installed:true,capabilities:{configuration:true},revision:2,configuration_digest:'d'.repeat(64),environment:{SEG_HTTP_WORKERS:'',SEG_HTTP_THREADS:'32',SEG_DB_POOL_META_MAX:'8',SEG_DB_POOL_TRAFFIC_MAX:'2',SEG_DB_POOL_WAIT_SECONDS:'5'},entra_configured:false,setup_pending:null,blockers:[],...overrides};}
function guiSetupPlan(overrides={}){return {id:'gui-review',digest:'a'.repeat(64),confirmation_nonce:'gui-confirmation',confirmation_phrase:'ACTIVATE CONTROLLER CONFIGURATION',expires_at:new Date(Date.now()+60000).toISOString(),can_apply:true,blockers:[],summary:{runtime:guiSetupStatus().environment,auth:{tenant_id:'11111111-1111-1111-1111-111111111111',client_id:'22222222-2222-2222-2222-222222222222',redirect_uri:'https://controller.example.test/api/v1/auth/callback',bootstrap_oid:'33333333-3333-3333-3333-333333333333'}},candidate_login_required:true,candidate_login_verified:false,...overrides};}
function guiSetupValues(overrides={}){return {SEG_HTTP_WORKERS:'',SEG_HTTP_THREADS:'32',SEG_DB_POOL_META_MAX:'8',SEG_DB_POOL_TRAFFIC_MAX:'2',SEG_DB_POOL_WAIT_SECONDS:'5',...overrides};}
async function guiSetupWorkspace(extra={},options={}){const env=await workspace('settings',{mode:'tokens',storage:{'segment-token':'private-bootstrap-fixture'},responses:{'/api/v1/platform/status':{runtime:{demo:false,ha:false},configuration:{revision:0},capabilities:{supervised:true}},'/api/v1/platform/setup':guiSetupStatus(),...extra},...options});await env.click('platform-tab',{tab:'setup'});await new Promise(setImmediate);return env;}
function endpointKit(overrides={}){return {schema_version:3,installation_options:{install_dependencies:true,ufw_action:'preserve'},issued_at:new Date().toISOString(),expires_at:new Date(Date.now()+60000).toISOString(),expected_hostname:'linux-pilot-01',controller_ca_pem:'-----BEGIN CERTIFICATE-----\nPUBLIC FIXTURE\n-----END CERTIFICATE-----',enrollment_token:'private-setup-fixture-token',config:{enforce:false,allow_firewall_changes:false,learning_auto_allow:false,unexpected_port_monitor_enabled:false},...overrides};}
function agentKitValues(overrides={}){return {setup_mode:'individual',architecture:'amd64',expected_hostname:'linux-pilot-01',controller_url:'https://controller.example.test',interval_seconds:'30',discovery_interval_seconds:'900',...overrides};}

test('GUI optional individual setup downloads a fresh data-only private kit with CSRF and no token rendering or browser persistence',async()=>{
 const kit=endpointKit(),env=await workspace('servers',{mode:'entra',role:'admin',config:{agent_downloads:{arm64:'0.18.1'}},responses:{'POST /api/v1/agent-installation/kit':kit}});env.run('showSetup()');const html=env.element('#modal-content').innerHTML;assert.match(html,/No agent JSON or environment-file editing/);assert.match(html,/--setup-file \/root\/prthak-agent-setup.json/);assert.match(html,/Enrollment is identity-only/);assert.doesNotMatch(html,/id="enrollment-(?:token|name|tags|location)"/);
 await env.submit('agent-installation-form',agentKitValues());const request=env.requests.find(row=>row.url==='/api/v1/agent-installation/kit');assert.equal(request.options.cache,'no-store');assertCookieMutation(request);assert.deepEqual(JSON.parse(request.options.body),{family:'auto',architecture:'amd64',expected_hostname:'linux-pilot-01',controller_url:'https://controller.example.test',interval_seconds:30,discovery_interval_seconds:900,installation_options:{install_dependencies:true,ufw_action:'preserve'}});assert.equal(env.element('created:a').download,'prthak-agent-setup.json');assert.match(env.element('#agent-installation-result').innerHTML,/Use it for one endpoint/);assert.doesNotMatch(env.element('#modal-content').innerHTML+env.element('#agent-installation-result').innerHTML,RegExp(kit.enrollment_token));assert.equal(env.run('JSON.stringify(state).includes("private-setup-fixture-token")'),false);assert.equal(env.storageChanges.some(row=>String(row.value).includes(kit.enrollment_token)),false);assert.equal(env.displayStorageChanges.some(row=>row.value.includes(kit.enrollment_token)),false);
 env.element('#agent-install-architecture').value='arm64';env.run('agentInstallationChange({target:{id:"agent-install-architecture"}})');assert.match(env.element('#agent-install-command').textContent,/install-agent-auto.sh --setup-file/);assert.match(env.element('#agent-install-archive').textContent,/linux-arm64.tar.gz/);
});

test('agent archive and private setup JSON are separate actions in Agent setup',async()=>{
 const env=await workspace('servers',{mode:'entra',role:'admin',config:{agent_downloads:{amd64:'0.18.0',arm64:'0.18.1'}}});
 env.run('showSetup()');
 const modal=env.element('#modal-content').innerHTML;
 assert.match(modal,/href="\/api\/v1\/agent-installation\/releases\/amd64\/signature"/);
 assert.match(modal,/<div class="modal-footer">.*href="\/api\/v1\/agent-installation\/releases\/amd64\/archive".*Download agent \(\.tar\.gz\).*Download private setup JSON/);
 env.element('#agent-install-architecture').value='arm64';
 env.run('agentInstallationChange({target:{id:"agent-install-architecture"}})');
 assert.match(env.element('#agent-install-archive-action').innerHTML,/href="\/api\/v1\/agent-installation\/releases\/arm64\/archive" download="prthak-agent-0\.18\.1-linux-arm64\.tar\.gz"/);
 assert.match(env.element('#agent-install-download-links').innerHTML,/linux-arm64\.tar\.gz\.signature\.json"/);
 env.run('state.authConfig.agent_downloads.arm64="https://foreign.invalid/archive";agentInstallationChange({target:{id:"agent-install-architecture"}})');
 assert.match(env.element('#agent-install-archive-action').innerHTML,/<button[^>]*disabled/);
 assert.match(env.element('#agent-install-download-links').innerHTML,/unavailable on this controller/);
 assert.doesNotMatch(env.element('#agent-install-download-links').innerHTML,/href=/);
 assert.equal(mutations(env).length,0);
});

test('agent downloads in a token session send authentication only to the controller',async()=>{
 const url='/api/v1/agent-installation/releases/arm64/archive';
 const env=await workspace('servers',{mode:'tokens',role:'admin',storage:{'segment-token':'private-fixture-token'},config:{agent_downloads:{arm64:'0.18.1'}},responses:{[url]:{headers:{'Content-Type':'application/octet-stream'}}}});
 env.run('showSetup()');
 env.element('#agent-install-architecture').value='arm64';
 env.run('agentInstallationChange({target:{id:"agent-install-architecture"}})');
 assert.match(env.element('#agent-install-archive-action').innerHTML,/data-agent-release-asset="archive"/);
 await env.run('downloadTokenAgentAsset({dataset:{agentReleaseAsset:"archive"}})');
 const request=env.requests.find(row=>row.url===url);
 assert.equal(request.options.headers.Authorization,'Bearer private-fixture-token');
 assert.equal(request.options.credentials,'same-origin');
 assert.equal(env.element('created:a').download,'prthak-agent-0.18.1-linux-arm64.tar.gz');
});

test('GUI endpoint setup refuses unsafe origins, invalid intervals, private-key uploads and Read Only requests',async()=>{
 const env=await workspace('servers',{mode:'entra',role:'admin'});env.run('showSetup()');for(const change of [{controller_url:'http://controller.example.test'},{controller_url:'https://user:password@controller.example.test'},{controller_url:'https://controller.example.test/api/v1'},{interval_seconds:'1e2'},{discovery_interval_seconds:'59'},{expected_hostname:'bad..host'}])await env.submit('agent-installation-form',agentKitValues(change));assert.equal(env.requests.some(row=>row.url==='/api/v1/agent-installation/kit'),false);
 env.element('#agent-install-ca').files=[{size:200,text:async()=>'-----BEGIN CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----'}];await env.submit('agent-installation-form',agentKitValues());assert.equal(env.requests.some(row=>row.url==='/api/v1/agent-installation/kit'),false);
 const readonly=await workspace('servers',{mode:'entra',role:'read_only'});readonly.run('showSetup()');assert.match(readonly.element('#modal-content').innerHTML,/Admin or Super Admin access/);await readonly.submit('agent-installation-form',agentKitValues());assert.equal(readonly.requests.some(row=>row.url==='/api/v1/agent-installation/kit'),false);
});

test('public web CA upload is sent only in the protected kit request and unsafe or stale kit responses cannot be downloaded',async()=>{
 const publicCA='-----BEGIN CERTIFICATE-----\nPUBLIC CA FIXTURE\n-----END CERTIFICATE-----',env=await workspace('servers',{mode:'entra',role:'admin',responses:{'POST /api/v1/agent-installation/kit':endpointKit({config:{enforce:true}})}});env.run('showSetup()');env.element('#agent-install-ca').files=[{size:publicCA.length,text:async()=>publicCA}];await env.submit('agent-installation-form',agentKitValues());assert.equal(JSON.parse(env.requests.find(row=>row.url==='/api/v1/agent-installation/kit').options.body).controller_ca_pem,publicCA);assert.equal(env.element('created:a').download,undefined);assert.equal(env.element('#agent-installation-result').innerHTML,'');assert.equal(env.run('JSON.stringify(state).includes("PUBLIC CA FIXTURE")'),false);
 env.context.apiResponses['POST /api/v1/agent-installation/kit']=endpointKit({expires_at:'2000-01-01T00:00:00Z'});await env.submit('agent-installation-form',agentKitValues());assert.equal(env.element('created:a').download,undefined);
});

test('the shared dashboard API creates and revokes a reusable fleet key with actual session CSRF and no hostname scope',async()=>{
 const expires=new Date(Date.now()+86400000).toISOString(),id='11111111-1111-4111-8111-111111111111',profile={id,name:'Pilot rollout',status:'active',expires_at:expires,enrollment_count:20};
 const kit=endpointKit({schema_version:3,enrollment_profile_id:id,expected_hostname:'',expires_at:expires});
 const env=await workspace('servers',{mode:'entra',role:'admin',responses:{'/api/v1/agent-installation/fleet-profiles?limit=20&offset=0':{items:[profile],total:1,limit:20,offset:0},'POST /api/v1/agent-installation/fleet-profiles':{profile,kit},['POST /api/v1/agent-installation/fleet-profiles/'+id+'/revoke']:{...profile,status:'revoked'}}});
 env.run('showSetup()');await new Promise(setImmediate);assert.match(env.element('#modal-content').innerHTML,/value="fleet" selected/);assert.doesNotMatch(env.element('#modal-content').innerHTML,/id="agent-install-hostname"/);
 await env.submit('agent-installation-form',agentKitValues({setup_mode:'fleet',name:'Pilot rollout',validity_hours:'24'}));const request=env.requests.find(row=>row.url==='/api/v1/agent-installation/fleet-profiles'&&row.options.method==='POST');assertCookieMutation(request);assert.equal(request.options.cache,'no-store');const body=JSON.parse(request.options.body);assert.equal(body.name,'Pilot rollout');assert.equal(body.validity_hours,24);assert.equal(body.expected_hostname,undefined);assert.equal(env.element('created:a').download,'prthak-agent-setup.json');
 env.context.fleetButton={disabled:false,dataset:{action:'agent-fleet-revoke',id}};await env.run('agentFleetAction(fleetButton)');const revoke=env.requests.find(row=>row.url.endsWith('/'+id+'/revoke'));assertCookieMutation(revoke);assert.deepEqual(JSON.parse(revoke.options.body),{});assert.match(env.element('#agent-fleet-profiles').innerHTML,/revoked/);assert.doesNotMatch(env.element('#agent-fleet-profiles').innerHTML,/data-action="agent-fleet-revoke"/);
});

test('GUI controller setup is Super Admin only and presents reviewed runtime and initial Entra fields without a raw env editor',async()=>{
 const env=await guiSetupWorkspace();let html=env.element('#view-content').innerHTML;assert.match(html,/Controller setup/);assert.match(html,/No manual .env editing/);assert.match(html,/Use recommended pilot profile/);assert.match(html,/type="password"[^>]*autocomplete="new-password"/);assert.doesNotMatch(html,/<textarea|name="environment"/);env.run('platformSetupInput({target:{id:"setup-enable-entra",checked:true}})');assert.equal(env.element('#setup-entra-fields').hidden,false);
 await env.click('platform-setup-preset');assert.equal(env.element('#setup-meta-pool').value,'8');assert.equal(env.element('#setup-workers').value,'');assert.equal(env.run('platformHasDraft()'),true);
 for(const role of ['admin','read_only']){const other=await guiSetupWorkspace({}, {mode:'entra',role});await other.click('platform-tab',{tab:'setup'});assert.equal(other.run('state.platformTab'),'overview');assert.equal(other.requests.some(row=>row.url==='/api/v1/platform/setup'),false);await other.click('platform-setup-login');assert.equal(other.requests.some(row=>row.url==='/api/v1/platform/setup/login'),false);}
});

test('SSH reachability fields are advanced, retain saved values and can be cleared as a pair',async()=>{
 const env=await guiSetupWorkspace();
 let html=env.element('#view-content').innerHTML;
 assert.match(html,/<details id="setup-ssh-probe" class="platform-advanced">/);
 assert.match(html,/SSH service banner and ends the connection before authentication/);
 assert.match(html,/Leave both fields blank for inventory and monitoring/);
 const source='SEG_MANAGEMENT_PROBE_SOURCE_IP',targets='SEG_MANAGEMENT_PROBE_TARGET_CIDRS';
 const values=guiSetupValues({[source]:'192.0.2.10',[targets]:'192.0.2.20/32'});
 env.context.setupInfo=guiSetupStatus({environment:values});
 html=env.run('state.platformSetup=setupInfo; platformSetupHTML()');
 assert.match(html,/<details id="setup-ssh-probe" class="platform-advanced" open>/);
 assert.match(html,/name="SEG_MANAGEMENT_PROBE_SOURCE_IP" value="192\.0\.2\.10"/);
 assert.match(html,/name="SEG_MANAGEMENT_PROBE_TARGET_CIDRS" value="192\.0\.2\.20\/32"/);
 const form=renderedForm(env,'platform-setup-form',values);
 env.context.setupForm=form;
 let payload=env.run('platformSetupPayload(setupForm)');
 assert.equal(payload.environment[source],values[source]);
 assert.equal(payload.environment[targets],values[targets]);
 form.values[source]='';
 assert.throws(()=>env.run('platformSetupPayload(setupForm)'),/Enter both/);
 form.values[targets]='';
 payload=env.run('platformSetupPayload(setupForm)');
 assert.equal(payload.environment[source],'');
 assert.equal(payload.environment[targets],'');
});

test('initial Entra setup sends the secret once, clears its field and requires a verified candidate before exact activation',async()=>{
 const plan=guiSetupPlan(),env=await guiSetupWorkspace({'POST /api/v1/platform/setup/preview':plan,'POST /api/v1/platform/setup/apply':{id:'setup-job',operation:'controller-config',status:'queued',phase:'queued'}});const values=guiSetupValues({configure_entra:'on',SEG_ENTRA_TENANT_ID:plan.summary.auth.tenant_id,SEG_ENTRA_CLIENT_ID:plan.summary.auth.client_id,SEG_ENTRA_REDIRECT_URI:plan.summary.auth.redirect_uri,SEG_BOOTSTRAP_SUPER_ADMIN_OID:plan.summary.auth.bootstrap_oid,client_secret:'private-entra-fixture'}),form=renderedForm(env,'platform-setup-form',values,{revision:'2',configDigest:'d'.repeat(64)});env.element('#setup-client-secret').value='private-entra-fixture';await submitRendered(env,form);const request=env.requests.find(row=>row.url.endsWith('/setup/preview')),body=JSON.parse(request.options.body);assert.equal(body.client_secret,'private-entra-fixture');assert.equal(body.expected_revision,2);assert.equal(body.environment.SEG_HTTP_WORKERS,'');assert.equal(env.element('#setup-client-secret').value,'');assert.equal(env.run('JSON.stringify(state).includes("private-entra-fixture")'),false);assert.doesNotMatch(env.element('#modal-content').innerHTML,/private-entra-fixture/);assert.match(env.element('#modal-content').innerHTML,/11111111-1111-1111-1111-111111111111/);
 await env.submit('platform-setup-review-form',{confirmation_phrase:plan.confirmation_phrase});assert.equal(env.requests.some(row=>row.url.endsWith('/setup/apply')),false);
 const verified={...plan,candidate_login_verified:true};env.context.apiResponses['/api/v1/platform/setup']=guiSetupStatus({setup_pending:verified});await env.click('platform-setup-review-refresh');assert.match(env.element('#modal-content').innerHTML,/Candidate sign-in verified/);await env.submit('platform-setup-review-form',{confirmation_phrase:'wrong'});assert.equal(env.requests.some(row=>row.url.endsWith('/setup/apply')),false);await env.submit('platform-setup-review-form',{confirmation_phrase:plan.confirmation_phrase});assert.deepEqual(JSON.parse(env.requests.find(row=>row.url.endsWith('/setup/apply')).options.body),{preview_id:plan.id,digest:plan.digest,confirmation_nonce:plan.confirmation_nonce,confirmation_phrase:plan.confirmation_phrase});assert.equal(env.run('state.platformSetupReview'),null);
});

test('candidate sign-in starts with authenticated POST and refuses non-Microsoft redirects, expired reviews and changed setup bindings',async()=>{
 const plan=guiSetupPlan(),env=await guiSetupWorkspace({'POST /api/v1/platform/setup/login':{location:'https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/oauth2/v2.0/authorize?state=public-fixture'}});env.context.setupPlan=plan;env.run('platformShowSetupReview(setupPlan)');await env.click('platform-setup-login');const request=env.requests.find(row=>row.url.endsWith('/setup/login'));assert.equal(request.options.headers.Authorization,'Bearer private-bootstrap-fixture');assert.deepEqual(JSON.parse(request.options.body),{preview_id:plan.id});assert.match(env.navigation[0],/^https:\/\/login.microsoftonline.com\//);
 env.context.apiResponses['POST /api/v1/platform/setup/login']={location:'https://untrusted.example.test/steal'};await env.click('platform-setup-login');assert.equal(env.navigation.length,1);env.run('state.platformSetupReview.expires_at="2000-01-01T00:00:00Z"');await env.click('platform-setup-login');assert.equal(env.requests.filter(row=>row.url.endsWith('/setup/login')).length,2);
 env.context.apiResponses['/api/v1/platform/setup']=guiSetupStatus({setup_pending:guiSetupPlan({id:'different-review',candidate_login_verified:true})});await env.click('platform-setup-review-refresh');assert.equal(env.run('state.platformSetupReview'),null);
});

test('controller setup preserves dirty forms during background refresh and refuses incomplete configuration status',async()=>{
 const env=await guiSetupWorkspace(),form=env.element('#platform-setup-form');form.values={client_secret:'unsaved-private-value'};env.context.setupForm=form;env.run('platformMarkDraft(setupForm)');const before=env.element('#view-content').innerHTML;await env.run('loadPlatformSettings()');assert.equal(env.element('#view-content').innerHTML,before);assert.equal(form.values.client_secret,'unsaved-private-value');env.context.apiResponses['/api/v1/platform/setup']={};await env.run('loadPlatformSetup(false)');assert.match(env.run('state.platformSetupError'),/complete setup status/);assert.equal(env.run('state.platformSetup.revision'),2);
});

test('fresh installed token-only controller opens Setup without overriding explicit navigation or demo settings',async()=>{
 const responses={'/api/v1/platform/status':{runtime:{demo:false,ha:false},configuration:{revision:0},capabilities:{supervised:true}},'/api/v1/platform/setup':guiSetupStatus({revision:0})},fresh=await workspace('settings',{mode:'tokens',storage:{'segment-token':'private-bootstrap-fixture'},responses});assert.equal(fresh.run('state.platformTab'),'setup');assert.match(fresh.element('#view-content').innerHTML,/Controller setup/);await fresh.click('platform-tab',{tab:'overview'});await fresh.run('loadPlatformSettings()');assert.equal(fresh.run('state.platformTab'),'overview');
 const demo=await workspace('settings',{responses});assert.notEqual(demo.run('state.platformTab'),'setup');assert.equal(demo.requests.some(row=>row.url==='/api/v1/platform/setup'),false);
});

test('uninstalled setup preserves the real manager blocker and disables mutation without inventing a configuration revision',async()=>{
 const env=await guiSetupWorkspace({'/api/v1/platform/setup':{installed:false,capabilities:{configuration:false},environment:{},entra_configured:false,setup_pending:null,blockers:['Install the fixed appliance manager first']}});assert.equal(env.run('platformSetupCanConfigure()'),false);assert.match(env.element('#view-content').innerHTML,/Install the fixed appliance manager first/);assert.doesNotMatch(env.element('#view-content').innerHTML,/did not return complete setup status/);await submitRendered(env,renderedForm(env,'platform-setup-form',guiSetupValues(),{revision:'0',configDigest:''}));assert.equal(env.requests.some(row=>row.url.endsWith('/setup/preview')),false);
});

test('provider setup uses one current Super Admin action after candidate verification and tracks real transition status',async()=>{
 const plan=guiSetupPlan({requires_independent:false,candidate_login_verified:true,approval:{stage:'approved',requester:{display_name:'Current Super'}}}),env=await guiSetupWorkspace({'/api/v1/platform/setup':guiSetupStatus({entra_configured:true}),'POST /api/v1/platform/setup/preview':plan,'POST /api/v1/platform/setup/apply':{provider_transition:{id:'transition-1'}}},{mode:'entra'});
 const values=guiSetupValues({configure_entra:'on',SEG_ENTRA_TENANT_ID:'11111111-1111-1111-1111-111111111111',SEG_ENTRA_CLIENT_ID:'22222222-2222-2222-2222-222222222222',SEG_ENTRA_REDIRECT_URI:'https://controller.example.test/api/v1/auth/callback',candidate_object_id:'33333333-3333-3333-3333-333333333333',client_secret:'private-new-rotation',retain_old_origin:'on',SEG_CONTROL_PORT:'9448',SEG_DISCOVERY_PORT:'9449'});
 await submitRendered(env,renderedForm(env,'platform-setup-form',values,{revision:'2',configDigest:'d'.repeat(64)}));const body=JSON.parse(env.requests.find(row=>row.url.endsWith('/setup/preview')).options.body);assert.equal(body.environment.SEG_CONTROL_PORT,'9448');assert.equal(body.environment.SEG_DISCOVERY_PORT,'9449');assert.equal(body.candidate_object_id,values.candidate_object_id);
 assert.match(env.element('#modal-content').innerHTML,/Activate reviewed configuration/);assert.doesNotMatch(env.element('#modal-content').innerHTML,/second Super Admin|independent Super Admin approval/);
 await env.submit('platform-setup-review-form',{confirmation_phrase:plan.confirmation_phrase});assert.equal(env.requests.filter(row=>row.url.endsWith('/setup/apply')).length,1);assert.equal(env.run('state.platformRuntimePending'),undefined);assert.equal(env.run('JSON.stringify(state).includes("private-new-rotation")'),false);
});

test('new callback origin verification shows a transient code without URL secrets or browser persistence',async()=>{
 const plan=guiSetupPlan({summary:{environment:{SEG_ENTRA_REDIRECT_URI:'https://new.example.test/api/v1/auth/callback'}},cross_origin_verification:true}),code='f'.repeat(32)+'.'+'s'.repeat(43),env=await guiSetupWorkspace({'POST /api/v1/platform/setup/login':{verification_url:'https://new.example.test/provider-verification.html',verification_code:code}});env.context.review=plan;env.run('platformShowSetupReview(review)');await env.click('platform-setup-login');assert.match(env.element('#modal-content').innerHTML,/https:\/\/new.example.test\/provider-verification.html/);assert.match(env.element('#modal-content').innerHTML,new RegExp(code.replace('.','\\.')));assert.equal(env.run('JSON.stringify(state).includes("'+code+'")'),false);assert.equal(env.storageChanges.some(row=>String(row.value).includes(code)),false);assert.equal(env.navigation.length,0);
});


function endpointConfigurationFixture(overrides={}){return {controller_url:'https://controller.example.test',control_url:'https://controller.example.test:8788',discovery_url:'https://controller.example.test:8789',enforce:false,allow_firewall_changes:false,learning_auto_allow:false,unexpected_port_monitor_enabled:false,management_sources:[],protected_ssh_ports:[],zone:'',digest:'b'.repeat(64),...overrides};}
function endpointConfigurationPlan(overrides={}){return {id:'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',plan_digest:'a'.repeat(64),status:'approved',expires_at:new Date(Date.now()+600000).toISOString(),scope:{server_id:'host-1',hostname:'lab-api',ips:['10.1.0.2'],expected_config_digest:'b'.repeat(64),settings:endpointConfigurationFixture({enforce:true,management_sources:['10.90.0.0/24'],protected_ssh_ports:[2022],zone:'public'})},approval:{mode:'single_admin',stage:'approved',requester:{display_name:'Admin <operator>',user_id:'maker'}},...overrides};}
async function endpointConfigurationWorkspace(responses={}){const env=await workspace('servers',{mode:'entra',role:'admin',responses:{'/api/v1/agent-installation/configuration':{items:[]},...responses}});env.context.receipt=endpointConfigurationFixture();env.run('state.data.servers[0].configuration_state=receipt;state.data.servers[0].capabilities.push("endpoint_configuration_v1")');await env.run('showEndpointConfiguration()');return env;}
test('agent bootstrap GUI uses actual advertised channel origins and keeps optional combined fallback',async()=>{
 const env=await workspace('servers',{mode:'entra',role:'admin',config:{agent_channels:{controller_url:'https://management.example.test:9443',control_url:'https://control.example.test:9448',discovery_url:'https://discovery.example.test:9449'}}});env.run('showSetup()');const html=env.element('#modal-content').innerHTML;assert.match(html,/value="https:\/\/management.example.test:9443"/);assert.match(html,/value="https:\/\/control.example.test:9448"/);assert.match(html,/value="https:\/\/discovery.example.test:9449"/);env.context.channelForm={values:agentKitValues({control_url:'https://control.example.test:9448',discovery_url:'https://discovery.example.test:9449'})};const payload=JSON.parse(env.run('JSON.stringify(agentInstallationPayload(channelForm))'));assert.equal(payload.control_url,'https://control.example.test:9448');assert.equal(payload.discovery_url,'https://discovery.example.test:9449');
});
test('endpoint configuration GUI previews exact explicit opt-ins and management scope without applying live changes',async()=>{
 const plan=endpointConfigurationPlan(),env=await endpointConfigurationWorkspace({'POST /api/v1/agent-installation/configuration/preview':plan});assert.match(env.element('#modal-content').innerHTML,/Choose a fresh endpoint/);env.context.receipt=endpointConfigurationFixture();const fields=env.run('endpointConfigurationFields(state.data.servers[0])');assert.match(fields,/Root must apply it locally/);assert.doesNotMatch(fields,/pilot|two people|allow_single_admin_pilot/i);assert.match(fields,/90-second independent timer/);assert.match(fields,/Turning off an opt-in retains committed firewall rules/);env.context.configForm={id:'endpoint-configuration-form',dataset:{},values:{server_id:'host-1',...endpointConfigurationFixture(),enforce:'on',management_sources:'10.90.0.0/24',protected_ssh_ports:'2022',zone:'public',retain_old_origin:'on'}};env.context.configForm.querySelector=env.element;await env.run('endpointConfigurationSubmit({target:configForm,preventDefault(){},stopImmediatePropagation(){}})');const request=env.requests.find(row=>row.url.endsWith('/configuration/preview'));assertCookieMutation(request);const body=JSON.parse(request.options.body);assert.equal(body.settings.enforce,true);assert.equal(body.settings.learning_auto_allow,false);assert.deepEqual(body.settings.protected_ssh_ports,[2022]);assert.equal(body.retain_old_origin,true);assert.match(env.element('#modal-content').innerHTML,/Download signed configuration kit/);assert.match(env.element('#modal-content').innerHTML,/Admin &lt;operator&gt;/);assert.doesNotMatch(env.element('#modal-content').innerHTML,/<operator>/);assert.equal(env.requests.some(row=>row.url.includes('/configuration/check')),false);
});
test('endpoint configuration GUI downloads an Admin-authorized kit without a second reviewer or live opt-in changes',async()=>{
 const plan=endpointConfigurationPlan(),env=await endpointConfigurationWorkspace();env.context.plan=plan;env.run('showEndpointConfigurationReview(plan)');assert.match(env.element('#modal-content').innerHTML,/Download signed configuration kit/);assert.match(env.element('#modal-content').innerHTML,/must apply it locally/);assert.doesNotMatch(env.element('#modal-content').innerHTML,/Submit as requester|independent administrator|pilot/i);
 env.context.apiResponses['POST /api/v1/agent-installation/configuration/'+plan.id+'/kit']={schema_version:1,manifest:{kind:'prthak-endpoint-configuration-v1',approval:{stage:'approved',mode:'single_admin'}},signature:{algorithm:'Ed25519'}};
 await env.run('endpointConfigurationAction({dataset:{action:"endpoint-configuration-download",id:plan.id}})');assert.equal(env.element('created:a').download,'prthak-endpoint-configuration.json');assert.equal(env.requests.some(row=>row.url.includes('/agent/configuration/check')||row.url.endsWith('/confirm')),false);assert.equal(env.storageChanges.some(row=>String(row.value).includes('prthak-endpoint-configuration-v1')),false);
});

test('approval-mode selectors and their settings calls are absent for every role',async()=>{
 for(const role of ['super_admin','admin','read_only']){const env=await workspace('settings',{mode:'entra',role});await env.click('platform-tab',{tab:'approvals'});assert.equal(env.run('state.platformTab'),'overview');assert.doesNotMatch(env.element('#view-content').innerHTML,/Approval mode|SINGLE_ADMIN_PILOT|Two-person production/);assert.equal(env.requests.some(row=>row.url.includes('/approval-settings')),false);}
});

test('normal Admin authority has no pilot nonce, host-count cap or seven-day approval setting',async()=>{
 const env=await workspace('overview',{mode:'entra',role:'super_admin'}),user=env.run('state.user'),plan={id:'admin-action',status:'reviewed',confirmation_count:0,confirmation_nonce:'exact-current',confirmation_phrase:'APPLY EXACT',expires_at:new Date(Date.now()+60000).toISOString(),approval:{mode:'single_admin',stage:'draft',requester:{user_id:user.id,tenant_id:user.tenant_id}}};
 env.context.directPlan=plan;assert.equal(env.run('PrthakApprovals.canAct(directPlan,{role:state.role,authType:state.authType,userId:state.user.id,tenantId:state.user.tenant_id})'),true);const body=env.run('PrthakApprovals.confirmationBody(directPlan,{confirm:true})');assert.equal(body.confirmation_nonce,'exact-current');assert.equal(body.pilot_confirmation_nonce,undefined);assert.doesNotMatch(env.run('PrthakApprovals.explain(directPlan)'),/pilot|seven|20 endpoint/i);
});

test('optional continuous monitoring is separate, default off, bounded and only loaded on Traffic',async()=>{
 const env=await workspace('traffic',{mode:'entra',role:'read_only'}),html=env.element('#view-content').innerHTML;assert.match(html,/Continuous port hit monitoring/);assert.match(html,/disabled by default/);assert.match(html,/<details class="traffic-monitor-coverage"><summary>Monitoring details<\/summary>/);assert.match(html,/120-second capture leases/);assert.match(html,/200 per second per rule, port and IP family/);assert.match(html,/Backend or storage gaps may reduce counts/);assert.equal(env.requests.some(row=>row.url==='/api/v1/hit-monitors?limit=20&offset=0'),true);await env.click('hit-monitor-new');assert.equal(env.element('#modal').open,false);
 const other=await workspace('servers',{mode:'entra'});assert.equal(other.requests.some(row=>row.url.includes('hit-monitors')),false);
});
function hitMonitorTestPlan(extra={}){return {id:'monitor-review',operation:'enable',name:'HTTPS observation',target_count:1,ports:[{port:443,protocol:'tcp'}],digest:'exact-digest',confirmation_nonce:'exact-nonce',confirmation_phrase:'START HIT MONITOR ABC123',expires_at:new Date(Date.now()+60000).toISOString(),...extra};}
test('monitoring review freezes current endpoint scope and only exact typed confirmation applies log intent',async()=>{
 const plan=hitMonitorTestPlan(),env=await workspace('traffic',{mode:'entra',role:'admin',responses:{'POST /api/v1/hit-monitors/preview':plan,'POST /api/v1/hit-monitors/apply':{id:'new-monitor',enabled:true}}});await env.click('hit-monitor-new');await env.submit('hit-monitor-form',{name:'HTTPS observation',ports:'443/tcp,22/tcp',retention_hours:'24'});const preview=env.requests.find(row=>row.url==='/api/v1/hit-monitors/preview');assert.deepEqual(JSON.parse(preview.options.body),{name:'HTTPS observation',selection:{server_ids:['host-1'],group_ids:[],selector:{}},ports:[{port:443,protocol:'tcp'},{port:22,protocol:'tcp'}],retention_hours:24});assert.match(env.element('#modal-content').innerHTML,/No access policies are generated/);await env.submit('hit-monitor-review-form',{confirmation_phrase:'wrong'});assert.equal(env.requests.some(row=>row.url==='/api/v1/hit-monitors/apply'),false);await env.submit('hit-monitor-review-form',{confirmation_phrase:plan.confirmation_phrase});assert.deepEqual(JSON.parse(env.requests.find(row=>row.url==='/api/v1/hit-monitors/apply').options.body),{preview_id:plan.id,digest:plan.digest,confirmation_nonce:plan.confirmation_nonce,confirmation_phrase:plan.confirmation_phrase});assert.equal(env.requests.some(row=>row.options.method==='POST'&&/\/learning|\/policies/.test(row.url)),false);
});
test('monitoring pair validation rejects CIDR-like authority, ranges and malformed ports before preview',async()=>{
 const env=await workspace('traffic',{mode:'entra'});assert.deepEqual(JSON.parse(env.run('JSON.stringify(hitMonitorPorts("22/tcp,65535/udp,22/tcp"))')),[{port:22,protocol:'tcp'},{port:65535,protocol:'udp'}]);for(const value of ['0/tcp','65536/tcp','443/tcp:10.0.0.1','20-22/tcp','443/sctp',''])assert.throws(()=>env.run('hitMonitorPorts('+JSON.stringify(value)+')'));await env.click('hit-monitor-new');await env.submit('hit-monitor-form',{name:'Invalid',ports:'443/tcp:10.0.0.1',retention_hours:'1'});assert.equal(env.requests.some(row=>row.options.method==='POST'&&row.url.includes('/hit-monitors')),false);
});
test('monitor hits and exact per-host receipt page escape IPv6 service metadata and never label desired off as verified',async()=>{
 const monitor={id:'m1',name:'<img src=x>',target_count:120,ports:[{port:443,protocol:'tcp'}],retention_hours:24,enabled:false,revision:2},env=await workspace('traffic',{mode:'entra',responses:{'/api/v1/hit-monitors?limit=20&offset=0':{items:[monitor],total:1,offset:0,limit:20,storage_budget:{event_count:10,max_events:2000000}},'/api/v1/hit-monitors/m1/hits?window_hours=1&limit=100&offset=0':{items:[{server_id:'host-1',hostname:'<host>',source_ip:'2001:db8::12',port:443,protocol:'tcp',count:2,service:'<script>unsafe()</script>',first_seen:new Date().toISOString(),last_seen:new Date().toISOString()}],total:1,monitor},'/api/v1/hit-monitors/m1/targets?limit=50&offset=0':{items:[{server_id:'host-1',hostname:'<host>',last_outcome:{status:'error',error:'<img onerror=bad>',checked_at:new Date().toISOString()}}],total:120,offset:0,has_more:true}}});await env.click('hit-monitor-open',{id:'m1'});const html=env.element('#view-content').innerHTML;assert.match(html,/2001:db8::12/);assert.match(html,/&lt;script&gt;/);assert.doesNotMatch(html,/<script>|<img/);assert.match(html,/Central off is not an endpoint cleanup acknowledgement/);assert.match(html,/Loaded 1 of 120 frozen endpoints/);assert.match(html,/2,000,000/);assert.match(html,/Backend or storage gaps may reduce counts/);
});
test('stop preview binds current monitor revision and old detail response cannot replace the newly selected monitor',async()=>{
 const env=await workspace('traffic',{mode:'entra',responses:{'/api/v1/hit-monitors?limit=20&offset=0':{items:[{id:'one',name:'One',revision:8,enabled:true,ports:[],target_count:1,retention_hours:1}],total:1},'POST /api/v1/hit-monitors/one/stop-preview':hitMonitorTestPlan({operation:'disable'})}});await env.click('hit-monitor-stop',{id:'one'});assert.deepEqual(JSON.parse(env.requests.find(row=>row.url.endsWith('/one/stop-preview')).options.body),{expected_revision:8});let release;const gate=new Promise(resolve=>release=resolve);env.context.apiResponses ||= {};env.context.apiResponses['/api/v1/hit-monitors/one/hits?window_hours=1&limit=100&offset=0']=async()=>{await gate;return {items:[],monitor:{id:'one'}};};env.context.apiResponses['/api/v1/hit-monitors/two/hits?window_hours=1&limit=100&offset=0']={items:[],monitor:{id:'two'}};const first=env.run('state.hitMonitorId="one";loadHitMonitorDetails(false)');await new Promise(setImmediate);await env.run('state.hitMonitorId="two";loadHitMonitorDetails(false)');release();await first;assert.equal(env.run('state.hitMonitorHits.monitor.id'),'two');
});
test('expired monitoring reviews and demo capture apply are rejected without creating a policy',async()=>{
 for(const options of [{mode:'entra',plan:hitMonitorTestPlan({expires_at:'invalid'})},{mode:'demo',plan:hitMonitorTestPlan()}]){const env=await workspace('traffic',{mode:options.mode});env.context.testPlan=options.plan;env.run('showHitMonitorReview(testPlan)');await env.submit('hit-monitor-review-form',{confirmation_phrase:options.plan.confirmation_phrase});assert.equal(env.requests.some(row=>row.options.method==='POST'&&row.url.endsWith('/hit-monitors/apply')),false);}
});
test('pilot polling is Super Admin only and reviews exact endpoints before saving the unchanged fleet defaults',async()=>{
 const configuration={expected_revision:4,defaults:{control_interval_seconds:30,discovery_interval_seconds:900},rules:[{id:'pilot-30-60',server_ids:['host-1'],control_interval_seconds:30,discovery_interval_seconds:60}]},result={configuration,pilot:{server_ids:['host-1'],removed_server_ids:['old-host']},affected_servers:[{hostname:'lab-api',before:{control_interval_seconds:30,discovery_interval_seconds:900},after:{control_interval_seconds:30,discovery_interval_seconds:60}}]},env=await workspace('settings',{mode:'entra',responses:{'POST /api/v1/platform/agent-settings/pilot-preview':result}});env.run('state.platformAgentSettings={revision:4,defaults:{control_interval_seconds:30,discovery_interval_seconds:900},rules:[]}');await env.click('platform-agents-pilot');await env.submit('pilot-polling-form',{server_ids:['host-1']});assert.deepEqual(JSON.parse(env.requests.find(row=>row.url.endsWith('/pilot-preview')).options.body),{server_ids:['host-1'],expected_revision:4});assert.match(env.element('#modal-content').innerHTML,/previous pilot members return/);assert.match(env.element('#modal-content').innerHTML,/Global defaults remain unchanged/);await env.submit('pilot-polling-review-form',{});assert.equal(env.requests.some(row=>row.options.method==='POST'&&row.url==='/api/v1/platform/agent-settings'),false);await env.submit('pilot-polling-review-form',{confirm:'on'});assert.deepEqual(JSON.parse(env.requests.find(row=>row.options.method==='POST'&&row.url==='/api/v1/platform/agent-settings').options.body),configuration);const admin=await workspace('settings',{mode:'entra',role:'admin'});await admin.click('platform-agents-pilot');assert.equal(admin.requests.some(row=>row.url.endsWith('/pilot-preview')),false);
});

test('normal Admin policy save publishes with one exact CRUD request and no separate rollout action',async()=>{
 const env=await workspace('policies',{mode:'entra',role:'admin'});env.run('showPolicy()');
 const form=renderedForm(env,'policy-form',{name:'Direct application access',target_type:'all',mode:'enforce'});
 const row=policyRow({rule_type:'port',rule_port:'8443',rule_protocol:'tcp',rule_sources:'192.0.2.44/32',rule_selector:'',rule_location_id:''});
 form.querySelectorAll=selector=>selector==='.rule-row'?[row]:[];await submitRendered(env,form);
 const writes=mutations(env);assert.equal(writes.length,1);assert.equal(writes[0].url,'/api/v1/policies');assert.equal(writes[0].options.method,'POST');assertCookieMutation(writes[0]);assert.equal(JSON.parse(writes[0].options.body).mode,'enforce');
 assert.equal(env.requests.some(row=>/policy-rollouts(?:\/?$|.*confirm)|approval-settings/.test(row.url)&&row.options.method==='POST'),false);assert.equal(env.element('#modal').open,false);
});

test('restrictive learned removal keeps rotated two-step confirmation with the same Admin identity',async()=>{
 const first=accessAuthorityPlan(0,{kind:'policy_change',policy_id:'learned-1',requires_double_confirmation:true,change:{expected_revision:3,name:learnedPolicy.name,services:[],remove:true}}),second={...first,status:'awaiting_second_confirmation',confirmation_count:1,confirmation_nonce:'destructive-second',approval:{...first.approval,stage:'submitted'}};
 const env=await workspace('policies',{mode:'entra',role:'admin',identity:approvalPerson(approvalMakerId),responses:{'POST /api/v1/learning-policies/learned-1/change-preview':first,'POST /api/v1/learning-policies/learned-1/change-confirm':{pending_approval:true,preview:second}}});
 await env.click('learned-policy-remove-review',{id:'learned-1'});await submitRendered(env,renderedForm(env,'learned-policy-form',{}));assert.equal(env.run('learningApprovalReady(state.activeLearningApproval)'),true);
 await submitRendered(env,renderedForm(env,'learned-policy-form',{challenge:'wrong'}));assert.equal(mutations(env).filter(row=>row.url.endsWith('/change-confirm')).length,1);
 env.context.apiResponses['POST /api/v1/learning-policies/learned-1/change-confirm']={pending_approval:false,policies:[]};
 await submitRendered(env,renderedForm(env,'learned-policy-form',{challenge:second.confirmation_phrase}));const changes=mutations(env).filter(row=>row.url.endsWith('/change-confirm'));assert.equal(changes.length,2);assert.equal(JSON.parse(changes[1].options.body).confirmation_nonce,'destructive-second');assert.equal(JSON.parse(changes[1].options.body).challenge,second.confirmation_phrase);assertCookieMutation(changes[1]);
});

test('risk navigation uses real page hooks and escaped badges identify each risky listener without enforcement',async()=>{
 const finding={server_id:'host-1',hostname:'lab-api',port:23,protocol:'tcp',severity:'high',reason:'Plaintext <service>',recommendation:'Remove or isolate',source_ids:[]};
 const env=await workspace('risk',{mode:'entra',role:'read_only',responses:{'/api/v1/risk/findings?limit=100&offset=0':{items:[finding],total:1},'/api/v1/risk/catalog':{revision:1,rules:[],sources:[]},'/api/v1/risk/regulatory':{controls:[],sources:[]}}});
 assert.equal(env.run('R.viewFromPath("/risk")'),'risk');assert.match(env.element('#navigation').innerHTML,/Risk &amp; compliance/);
 env.context.riskyFixture={...host,risky_ports:[finding],risk_summary:{total:1}};env.context.riskyListener={port:23,protocol:'tcp',service:'Telnet'};
 const details=env.run('listenerDetailsHTML(riskyListener,riskyFixture)');assert.match(details,/Risky port/);assert.match(details,/Plaintext &lt;service&gt;/);assert.doesNotMatch(details,/<service>/);assert.match(env.run('serverDrawerHeaderHTML(riskyFixture)'),/1 risk indicators/);
 assert.equal(mutations(env).length,0);
});

function defaultDenyWorkspaceReview(){return {id:'deny-workspace',revision:1,digest:'a'.repeat(64),confirmation_nonce:'current-downtime-review',action:'enable',server_ids:['host-1'],group_ids:[],can_apply:true,blockers:[],status:'draft',expires_at:new Date(Date.now()+600000).toISOString(),preview:{targets:[{server_id:'host-1',hostname:'lab-api',revision:0,base_version:2,version:3,digest:'b'.repeat(64),services:[{port:8443,protocol:'tcp',sources:['10.1.0.1/32']}],protection:{digest:'c'.repeat(64),ssh_ports:[2022],management_sources:['10.1.0.1/32'],host_default_deny_control_profile:'host-inbound-control-v1'},ips:['10.1.0.2'],blockers:[]}]}};}
test('whole-server default deny is a separate Admin preview and one fresh acknowledged cookie push',async()=>{
 const plan=defaultDenyWorkspaceReview(),env=await workspace('policies',{mode:'entra',role:'admin',responses:{'POST /api/v1/host-default-deny/query':{items:[],total:0,limit:20,offset:0,has_more:false},'POST /api/v1/host-default-deny/preview':plan,'POST /api/v1/host-default-deny/deny-workspace/confirm':{status:'queued'}}});
 await env.click('managed-workspace-tab',{tab:'default-deny'});assert.match(env.element('#view-content').innerHTML,/Whole-server default deny/);assert.match(env.element('#view-content').innerHTML,/Ordinary policy saves do not activate/);
 const query=env.requests.find(item=>item.url==='/api/v1/host-default-deny/query');assertCookieMutation(query);assert.equal(mutations(env).length,0);
 await env.click('default-deny-new');await env.submit('default-deny-selection-form',{operation:'enable',server_ids:['host-1'],group_ids:[]});assert.equal(mutations(env).length,1);assert.deepEqual(JSON.parse(mutations(env)[0].options.body),{action:'enable',server_ids:['host-1'],group_ids:[]});assert.equal(env.element('#default-deny-ack').checked,false);assert.equal(env.element('button[type="submit"]').disabled,true);
 await env.submit('default-deny-review-form',{acknowledge_downtime:'on'});assert.equal(mutations(env).length,1,'FormData alone cannot impersonate the unchecked box');
 env.element('#default-deny-ack').checked=true;env.listeners.change.at(-1)({target:{id:'default-deny-ack',checked:true}});assert.equal(env.element('button[type="submit"]').disabled,false);
 await env.submit('default-deny-review-form',{acknowledge_downtime:'on'});const push=mutations(env)[1];assert.equal(push.url,'/api/v1/host-default-deny/deny-workspace/confirm');assertCookieMutation(push);assert.deepEqual(JSON.parse(push.options.body),{digest:plan.digest,expected_revision:1,confirmation_nonce:plan.confirmation_nonce,acknowledge_downtime:true});assert.equal(env.run('defaultDenyState.review'),null);assert.equal(env.element('#default-deny-ack').checked,false);
});
test('Read Only can navigate default-deny status but cannot preview or push it',async()=>{
 const env=await workspace('policies',{mode:'entra',role:'read_only',responses:{'POST /api/v1/host-default-deny/query':{items:[],total:0,limit:20,offset:0,has_more:false}}});await env.click('managed-workspace-tab',{tab:'default-deny'});assert.equal(env.run('state.policyTab'),'default-deny');assert.ok(env.requests.some(item=>item.url==='/api/v1/host-default-deny/query'));assert.match(env.element('#view-content').innerHTML,/data-action="default-deny-new" disabled/);await env.click('default-deny-new');assert.equal(mutations(env).length,0);assert.equal(env.element('#modal').open,false);
});
test('endpoint default-deny opt-in is unchecked when absent and is true only from the actual checkbox value',async()=>{
 const env=await workspace('servers',{mode:'entra',role:'admin'});env.context.endpointFixture={configuration_state:{controller_url:'https://prthak.test',management_sources:['10.1.0.1/32'],protected_ssh_ports:[2022],zone:'public'}};
 const html=env.run('endpointConfigurationFields(endpointFixture)');assert.match(html,/name="allow_host_default_deny"/);assert.doesNotMatch(html,/name="allow_host_default_deny"[^>]*checked/);assert.match(html,/host_default_deny_v1/);assert.match(html,/separate acknowledged push/);
 env.context.endpointForm={values:{server_id:'host-1',controller_url:'https://prthak.test',management_sources:'10.1.0.1/32',protected_ssh_ports:'2022',zone:'public'}};assert.equal(env.run('endpointConfigurationPayload(endpointForm).settings.allow_host_default_deny'),false);env.context.endpointForm.values.allow_host_default_deny='true';assert.equal(env.run('endpointConfigurationPayload(endpointForm).settings.allow_host_default_deny'),false);env.context.endpointForm.values.allow_host_default_deny='on';assert.equal(env.run('endpointConfigurationPayload(endpointForm).settings.allow_host_default_deny'),true);
});

test('endpoint drawer opens applied access first with distinct agent and runtime evidence and exact scoped pagination',async()=>{
 const applied='/api/v1/servers/host-1/applied-policies';
 const managedRow={policy_name:'Billing <edge>',sources:['192.0.2.20/32','192.0.2.21/32'],source_groups:['Approved & tested'],destination_port:'8443/tcp',action:'allow',status:'Agent confirmed'};
 const discoveredRow={policy_name:'Reject custom port',sources:['198.51.100.0/24'],destination_port:'2222/tcp',action:'deny',status:'Last reported',zone:'external',zone_usage:'active'};
 const evidence={server_id:host.id,managed:{state:'confirmed',rows:[managedRow],total:2,offset:0,limit:1,has_more:true},learned:{state:'unverified',rows:[],total:0,reason:'No matching authenticated receipt.'},discovered:{state:'last_reported',rows:[discoveredRow],total:1,offset:0,limit:1,zones:[{name:'external',interfaces:['eno1'],sources:['198.51.100.0/24']}]}};
 const env=await workspace('servers',{mode:'entra',role:'read_only',responses:{
  [applied]:evidence,[applied+'?managed_offset=1']:{...evidence,managed:{state:'confirmed',rows:[{...managedRow,policy_name:'Second approved policy'}],total:2,offset:1,limit:1,has_more:false}},
 }});
 await env.click('server',{id:host.id});
 const html=env.element('#server-drawer').innerHTML;
 assert.match(html,/aria-pressed="true">Access policies/);
 for(const pattern of [/Policy name/,/Source IP or group/,/Destination port/,/Billing &lt;edge&gt;/,/Approved &amp; tested/,/192\.0\.2\.20\/32/,/8443\/tcp/,/>Allow</,/Agent confirmed/,/No matching authenticated receipt/,/>Deny</,/Last reported/,/external · Bound/,/Interfaces: eno1/,/Source bindings: 198\.51\.100\.0\/24/])assert.match(html,pattern);
 assert.doesNotMatch(html,/<edge>|Desired bundle/);
 await env.click('endpoint-access-page',{section:'managed',offset:'1'});
 assert.match(env.element('#server-drawer').innerHTML,/Second approved policy/);
 assert.match(env.element('#server-drawer').innerHTML,/2–2 of 2 rows/);
 assert.match(env.element('#server-drawer').innerHTML,/Reject custom port/);
 assert.equal(mutations(env).length,0);
});
test('endpoint access refresh rejects evidence returned for another server',async()=>{
 const path='/api/v1/servers/host-1/applied-policies';
 const env=await workspace('servers',{responses:{[path]:{server_id:'host-2',managed:{state:'confirmed',rows:[{policy_name:'Wrong endpoint allow'}]}}}});
 await env.click('server',{id:host.id});
 assert.match(env.element('#server-drawer').innerHTML,/policy response did not match this endpoint/);
 assert.doesNotMatch(env.element('#server-drawer').innerHTML,/Wrong endpoint allow/);
 env.context.apiResponses[path]={server_id:host.id,managed:{state:'none',rows:[]}};
 await env.click('endpoint-access-refresh');
 assert.match(env.element('#server-drawer').innerHTML,/No recorded rules/);
 assert.doesNotMatch(env.element('#server-drawer').innerHTML,/policy response did not match this endpoint/);
});

test('endpoint drawer separates fast listener checks from full inventory and labels offline data as last reported',async()=>{
 const env=await workspace('servers',{mode:'entra',role:'read_only'});
 env.context.diagnosticHost={...host,status:'offline',discovery_interval_seconds:900,fast_discovery:{backend:'inet_diag',status:'active',interval_seconds:5,checked_at:'2026-11-01T09:00:00Z',last_change_at:'2026-11-01T08:59:00Z'}};
 const html=env.run('serverDrawerServicesHTML(diagnosticHost)');
 assert.match(html,/Full inventory fallback/);assert.match(html,/15 minutes/);assert.match(html,/Listener change checks/);assert.match(html,/Last reported: Active · every 5 seconds/);assert.match(html,/Last listener inventory/);assert.match(html,/Last check:/);assert.doesNotMatch(html,/Expected next discovery|>Listening<|guaranteed|event-driven/);assert.equal(mutations(env).length,0);
});
test('endpoint preparation receipt keeps unknown activity distinct and never presents rule export as a controller download',async()=>{
 const env=await workspace('servers',{mode:'entra',role:'read_only'});
 env.context.diagnosticHost={...host,preparation_status:{schema_version:1,status:'assessment_only',checked_at:'2026-11-01T09:00:00Z',install_dependencies:false,dependencies_changed:false,ufw:{installed:true,active:true,assessment:'exported',migration_required:true,export_path:'/var/lib/seg-agent/host-preparation/ufw-export.json'},firewalld:{installed:true}}};
 const html=env.run('serverDrawerServicesHTML(diagnosticHost)');
 assert.match(html,/Installation preparation/);assert.match(html,/UFW at preparation<\/dt><dd>Active/);assert.match(html,/firewalld at preparation<\/dt><dd>Not verified/);assert.match(html,/Dependencies changed<\/dt><dd>No/);assert.match(html,/UFW was preserved/);assert.match(html,/Rule contents stay on the server/);assert.match(html,/host-preparation\/ufw-export\.json/);assert.doesNotMatch(html,/href="[^"]*ufw-export|data-action="[^"]*ufw/);assert.equal(mutations(env).length,0);
});
test('unavailable fast discovery and preparation errors remain escaped diagnostic text',async()=>{
 const env=await workspace('servers');
 env.context.diagnosticHost={...host,fast_discovery:{status:'unsupported',interval_seconds:5,error:'<script>snapshot</script>'},preparation_status:{status:'error',dependencies_changed:true,ufw:{assessment:'error'},firewalld:{active:false},error:'<img src=x onerror=alert(1)>'}};
 const html=env.run('serverDrawerServicesHTML(diagnosticHost)');
 assert.match(html,/Unavailable on this kernel/);assert.match(html,/&lt;script&gt;snapshot&lt;\/script&gt;/);assert.match(html,/&lt;img src=x onerror=alert\(1\)&gt;/);assert.match(html,/firewalld at preparation<\/dt><dd>Inactive/);assert.doesNotMatch(html,/<script>|<img src=x/);
 const legacy=env.run('discoveryTimingHTML({})');assert.match(legacy,/using full inventory scans/);assert.doesNotMatch(legacy,/every 5 seconds|Active/);
});

test('production API wrapper permits Read Only catalogue queries with CSRF and still refuses mutations',async()=>{
 const env=await workspace('alerts',{mode:'entra',role:'read_only'});
 for(const route of ['/alerts/query','/flows/query','/audit/query','/source-banks/query']){
  const before=env.requests.length;env.context.readQueryRoute=route;
  await env.run('api(readQueryRoute,{method:"POST",body:{limit:50,offset:50}})');
  assert.equal(env.requests.length,before+1);const request=env.requests.at(-1);
  assert.equal(request.url,'/api/v1'+route);assertCookieMutation(request);
 }
 for(const route of ['/alerts/example/ack','/alerts/query/ack','/flows/query/delete','/audit/query/clear','/policies']){
  const before=env.requests.length;env.context.writeRoute=route;
  await assert.rejects(env.run('api(writeRoute,{method:"POST",body:{}})'),/Read Only access cannot change/);
  assert.equal(env.requests.length,before);
 }
});

test('policy editor explains direct Admin publication and retains distinct downtime acknowledgement',async()=>{
 const env=await workspace('policies',{mode:'entra',role:'admin'});await env.run('showPolicy("policy-1")');
 const html=env.element('#modal-content').innerHTML;
 assert.match(html,/Admin save publishes/);assert.match(html,/endpoint receipt confirms/);assert.match(html,/separate downtime acknowledgement/);
 assert.doesNotMatch(html,/requires reviewed rollout|second approver|two.person/i);
});

test('Read Only Traffic finds older matching relationships beyond the overview preview using application and historical port filters',async()=>{
 const at=new Date().toISOString(),before=new Date(Date.now()-3600000).toISOString();
 const other={...host,id:'payment-host',hostname:'payments-app',tags:{application:'payments'},listeners:[{port:443,protocol:'tcp'}]},preview={server_id:other.id,source_ip:'192.0.2.2',port:443,protocol:'tcp',verdict:'allowed',capture_kind:'accepted_connection',capture_backend:'conntrack',count_unit:'connections',address_family:'ipv4',count:1,first_seen:at,last_seen:at};
 const overview={...structuredClone(fixture),servers:[structuredClone(host),other],flows:[preview],meta:{...fixture.meta,traffic_query_v1:true}};
 const query=options=>{const value=JSON.parse(options.body),filtered=value.server_ids?.includes('host-1')&&value.ports.includes('443/tcp');return {purpose:'traffic',items:filtered?[{...preview,server_id:'host-1',source_ip:'198.51.100.99',count:7}]:[preview],total:filtered?1:602,endpoint_count:filtered?1:2,counts_by_unit:{connections:filtered?7:608,packets:0,log_records:0},limit:50,offset:value.offset,has_more:!filtered,window_seconds:value.window_seconds,as_of:value.as_of||at,from_time:before,coverage:'Complete matching retained relationships; graph shows only the loaded page.',filter_before_pagination:true};};
 const env=await workspace('traffic',{mode:'entra',role:'read_only',responses:{'/api/v1/overview':overview,'POST /api/v1/flows/query':query}});
 env.run("state.filters.application=['billing'];state.filters.ports=['443/tcp'];render()");await new Promise(setImmediate);
 const request=env.requests.filter(row=>row.url==='/api/v1/flows/query').at(-1),body=JSON.parse(request.options.body);assert.deepEqual(body.server_ids,['host-1']);assert.deepEqual(body.ports,['443/tcp']);assertCookieMutation(request);
 const html=env.element('#view-content').innerHTML;assert.match(html,/198\.51\.100\.99/);assert.doesNotMatch(html,/192\.0\.2\.2/);assert.match(html,/1–1 of 1 matching relationships/);assert.match(html,/Export matching CSV/);assert.match(env.element('#filter-result-count').innerHTML||html,/1 matching relationships/);assert.equal(env.run('visibleFlows()[0].source_ip'),'198.51.100.99');
});

test('Read Only Traffic page actions reach the shared API and show exact full-scope counts beyond500',async()=>{
 const at=new Date().toISOString(),before=new Date(Date.now()-3600000).toISOString(),overview={...structuredClone(fixture),meta:{...fixture.meta,traffic_query_v1:true}};
 const env=await workspace('traffic',{mode:'entra',role:'read_only',responses:{'/api/v1/overview':overview,'POST /api/v1/flows/query':options=>{const query=JSON.parse(options.body),count=Math.min(50,507-query.offset);return {purpose:'traffic',items:Array.from({length:count},(_,index)=>({server_id:'host-1',source_ip:`198.51.${Math.floor((query.offset+index)/255)}.${(query.offset+index)%255}`,port:8443,protocol:'tcp',count:1,verdict:'allowed',count_unit:'connections',capture_kind:'accepted_connection',capture_backend:'conntrack',address_family:'ipv4',first_seen:at,last_seen:at})),total:507,endpoint_count:1,counts_by_unit:{connections:507,packets:0,log_records:0},limit:50,offset:query.offset,has_more:query.offset+count<507,window_seconds:query.window_seconds,as_of:query.as_of||at,from_time:before,coverage:'All matching retained traffic before pagination.',filter_before_pagination:true};}}});
 await env.click('traffic-catalogue-page',{offset:'500'});const request=env.requests.filter(row=>row.url==='/api/v1/flows/query').at(-1);assert.equal(JSON.parse(request.options.body).offset,500);assertCookieMutation(request);assert.match(env.element('#view-content').innerHTML,/501–507 of 507 matching relationships/);assert.match(env.element('#view-content').innerHTML,/Charts show the current page\./);assert.equal(env.run('visibleFlows().length'),7);assert.match(env.run("filterResultText('traffic')"),/507 matching relationships/);
});


test('source-set preparation uses the shared modal action submit and actual checkbox event path for Admin and Read Only',async()=>{
 const sha=letter=>letter.repeat(64),at=new Date().toISOString(),sourceHost={...host,capabilities:[...host.capabilities,'signed_assignments_v1','source_bank_preparation_v1'],configuration_state:{digest:sha('b')},protection_digest:sha('c')};
 const overview={...structuredClone(fixture),servers:[sourceHost],meta:{...fixture.meta,demo:false}};
 const receipt={schema_version:1,id:'bank-assess-one',operation:'assess',plan_digest:sha('d'),status:'assessed',checked_at:at,baseline_digest:sha('a'),protection_digest:sha('c'),missing_banks:256,active_banks:0,permanent_banks:0,created_banks:0,activation_required:true,blockers:[]};
 let activated=false;
 const assessment={id:receipt.id,server_id:'host-1',operation:'assess',status:'assigned',plan_digest:sha('d')};
 const review={id:'bank-review-one',kind:'source_bank_preparation',status:'preview',digest:sha('e'),confirmation_nonce:'n'.repeat(43),challenge:'PREPARE SOURCE BANKS',expires_at:new Date(Date.now()+120000).toISOString(),can_apply:true,blockers:[],targets:[{server_id:'host-1',hostname:'lab-api',missing_banks:256,active_banks:0,permanent_banks:0,activation_required:true,baseline_digest:sha('a'),protection_digest:sha('c'),assessed_at:at,blockers:[]}]};
 const responses={'/api/v1/overview':overview,'POST /api/v1/source-banks/query':()=>({items:[{server_id:'host-1',hostname:'lab-api',capable:true,job:activated?{...assessment,id:'bank-activate-one',operation:'prepare_activate'}:assessment,receipt}],total:1,limit:50,offset:0,has_more:false}),'POST /api/v1/source-banks/assess':{items:[assessment],count:1},'POST /api/v1/source-banks/preview':review,'POST /api/v1/source-banks/bank-review-one/confirm':()=>{activated=true;return {id:review.id,status:'assigned',count:1,items:[{...assessment,id:'bank-activate-one',operation:'prepare_activate'}]};}};
 const env=await workspace('servers',{mode:'entra',role:'admin',responses});assert.match(env.element('#view-content').innerHTML,/data-action="source-bank-open"/);
 await env.click('source-bank-open',{id:'host-1'});assert.equal(env.element('#modal-title').textContent,'Prepare source banks');await env.submit('source-bank-selection-form',{server_ids:['host-1'],group_ids:[]});
 await env.click('source-bank-preview');assert.equal(env.element('#modal-title').textContent,'Review source-bank maintenance');assert.match(env.element('#modal-content').innerHTML,/reload firewalld/);assert.doesNotMatch(env.element('#modal-content').innerHTML,/id="source-bank-ack"[^>]*checked/);
 await env.submit('source-bank-confirm-form',{acknowledge_downtime:'on',confirmation_phrase:'PREPARE SOURCE BANKS'});assert.equal(env.requests.some(row=>row.url.endsWith('/bank-review-one/confirm')),false);
 const check=env.element('#source-bank-ack'),phrase=env.element('#source-bank-phrase');check.closest=()=>null;phrase.closest=()=>null;check.checked=true;env.listeners.change.forEach(handler=>handler({target:check}));phrase.value='PREPARE SOURCE BANKS';env.listeners.input.forEach(handler=>handler({target:phrase}));assert.equal(env.element('#source-bank-confirm').disabled,false);
 await env.submit('source-bank-confirm-form',{});const push=env.requests.find(row=>row.url.endsWith('/bank-review-one/confirm'));assertCookieMutation(push);assert.deepEqual(JSON.parse(push.options.body),{digest:sha('e'),confirmation_nonce:review.confirmation_nonce,confirmation_phrase:'PREPARE SOURCE BANKS',acknowledge_downtime:true});assert.match(env.element('#source-bank-status').innerHTML,/Historical receipt/);assert.equal(env.run('sourceBanksState.review'),null);assert.equal(env.run('sourceBanksState.acknowledged'),'');
 const readonly=await workspace('servers',{mode:'entra',role:'read_only',responses});await readonly.click('source-bank-open',{id:'host-1'});assert.match(readonly.element('#modal-content').innerHTML,/Status is available to Read Only/);const before=readonly.requests.length;await readonly.submit('source-bank-selection-form',{server_ids:['host-1']});await readonly.click('source-bank-preview');assert.equal(readonly.requests.length,before);assertCookieMutation(readonly.requests.find(row=>row.url==='/api/v1/source-banks/query'));
});

function deploymentWorkspaceSummary(){return {id:'deployment-workspace',label:'Billing rollout',origin:'policy',policy_id:'policy-1',created_at:'2026-11-02T12:00:00Z',created_by:'Admin',deadline_at:'2026-11-02T12:10:00Z',target_count:1,applied_count:1,traffic_verified_count:0,active_count:1,failed_count:0,awaiting_count:1,unverified_count:0,unavailable_count:0,rolled_back_count:0,superseded_count:0,state:'active'};}
test('actual Admin policy Save starts top-right durable progress with one authorized change and no synthetic traffic',async()=>{
 const change=deploymentWorkspaceSummary();let published=false;
 const env=await workspace('policies',{mode:'entra',role:'admin',responses:{'PUT /api/v1/policies/policy-1':()=>{published=true;return {...policy,revision:2,deployment:change};},'/api/v1/policy-deployments?limit=10&offset=0':()=>({items:published?[change]:[],total:published?1:0,active_total:published?1:0,limit:10,offset:0,has_more:false})}});
 const shell=fs.readFileSync(path.join(__dirname,'..','index.html'),'utf8');assert.match(shell,/policy-deployments\.css/);assert.match(shell,/policy-deployments-page\.js/);assert.ok(shell.indexOf('id="policy-deployments"')<shell.indexOf('id="account-menu"'));
 const container=env.element('#policy-deployments');container.querySelector=selector=>container.innerHTML.includes('id="'+selector.slice(1)+'"')?env.element(selector):null;env.run('renderPolicyDeploymentsChrome()');assert.match(container.innerHTML,/aria-controls="policy-deployments-panel"/);
 await env.click('edit-policy',{id:'policy-1'});const form=renderedForm(env,'policy-form',{name:'Billing rollout',target_type:'all',mode:'enforce'});form.querySelectorAll=selector=>selector==='.rule-row'?[policyRow({rule_type:'port',rule_port:'8443',rule_protocol:'tcp',rule_sources:'192.0.2.1/32',rule_selector:'',rule_location_id:''})]:[];
 await submitRendered(env,form);await new Promise(setImmediate);const writes=mutations(env);assert.equal(writes.length,1);assert.equal(writes[0].url,'/api/v1/policies/policy-1');assertCookieMutation(writes[0]);assert.equal(JSON.parse(writes[0].options.body).expected_revision,1);assert.equal(env.run('policyDeploymentsState.open'),true);assert.equal(env.element('#policy-deployments-count').textContent,'1');assert.match(env.element('#policy-deployments-list').innerHTML,/Billing rollout/);assert.match(env.element('#policy-deployments-list').innerHTML,/1 \/ 1<\/strong> Applied/);assert.match(env.element('#policy-deployments-list').innerHTML,/0 \/ 1<\/strong> Traffic verified/);assert.equal(env.element('#modal').open,false);assert.equal(env.requests.some(row=>/probe|test-traffic|learning.*apply/.test(row.url)),false);
});
test('shared top-right progress gives Read Only lazy per-port proof, preserves CSRF refresh and clears identity changes',async()=>{
 const change=deploymentWorkspaceSummary(),target={server_id:'host-1',hostname:'lab-api',version:2,digest:'a'.repeat(64),approval_id:'approval-1',apply_status:'applied',traffic_status:'awaiting',readback_at:'2026-11-02T12:01:00Z',last_seen:'2026-11-02T12:01:01Z',reason:'No denied traffic observed',port_count:1,verified_port_count:0};
 const env=await workspace('servers',{mode:'entra',role:'read_only',responses:{'/api/v1/policy-deployments?limit=10&offset=0':{items:[change],total:1,active_total:1,limit:10,offset:0,has_more:false},'/api/v1/policy-deployments/deployment-workspace':change,'/api/v1/policy-deployments/deployment-workspace/targets?limit=50&offset=0':{items:[target],total:1,limit:50,offset:0,has_more:false},'/api/v1/policy-deployments/deployment-workspace/targets/host-1':{...target,ports:[{port:8443,protocol:'tcp',status:'awaiting',allow:{status:'verified',evidence:{source_ip:'192.0.2.4',destination_ip:'10.1.0.2',capture_kind:'conntrack',observed_at:'2026-11-02T12:01:05Z',expected_action:'allow'}},deny:{status:'awaiting',reason:'No denied packet observed'}}]}}});
 await env.click('policy-deployment-toggle');assert.equal(env.element('#policy-deployments-panel').hidden,false);await env.click('policy-deployment-open',{id:change.id});assert.equal(env.element('#modal-title').textContent,'Policy rollout status');assert.match(env.element('#policy-deployment-detail').innerHTML,/deployment-status-badge verified">Applied/);assert.match(env.element('#policy-deployment-detail').innerHTML,/Awaiting traffic/);assert.doesNotMatch(env.element('#policy-deployment-detail').innerHTML,/deployment-status-badge verified">Traffic verified/);assert.equal(env.requests.some(row=>row.url.endsWith('/targets/host-1')),false);
 await env.click('policy-deployment-target',{id:'host-1'});assert.match(env.element('#policy-deployment-detail').innerHTML,/8443\/tcp/);assert.match(env.element('#policy-deployment-detail').innerHTML,/192\.0\.2\.4/);assert.match(env.element('#policy-deployment-detail').innerHTML,/No denied packet observed/);assert.equal(mutations(env).length,0);
 const generation=env.run('policyDeploymentsState.generation');env.run('applyDashboardIdentity({role:state.role,auth_type:state.authType,user:{...state.user},csrf_token:"rotated-session-csrf"})');assert.equal(env.run('policyDeploymentsState.generation'),generation);assert.equal(env.run('policyDeploymentsState.selectedId'),change.id);
 await env.click('close-modal');assert.equal(env.run('policyDeploymentsState.detailOpen'),false);assert.equal(env.run('policyDeploymentsState.selectedId'),'');await env.click('policy-deployment-toggle');env.run('applyDashboardIdentity({role:"admin",auth_type:"session",user:{id:"another-user"},csrf_token:"other-csrf"})');assert.equal(env.run('policyDeploymentsState.page'),null);assert.equal(env.element('#policy-deployments-panel').hidden,true);assert.equal(env.element('#policy-deployments-list').innerHTML,'');assert.equal(mutations(env).length,0);
});
test('immediate single-Admin bulk rollout form opens durable progress with exactly one authorized mutation',async()=>{
 const change={...deploymentWorkspaceSummary(),target_count:2,applied_count:0,active_count:2,awaiting_count:2},ids=['host-1','host-2'],sha='a'.repeat(64);let published=false;
 const plan={id:'bulk-immediate',name:'Billing selected hosts',status:'queued',server_ids:ids,bindings:Object.fromEntries(ids.map(id=>[id,{version:2,digest:sha,protection_digest:sha}])),preview:{targets:ids.map(id=>({server_id:id,hostname:id,protection_status:'ready',blockers:[]}))},requires_double_confirmation:false,confirmation_count:1,confirmation_nonce:'nonce-used',plan_digest:sha,expires_at:new Date(Date.now()+600000).toISOString(),results:{},approval:{mode:'single_admin',stage:'approved',requester:{user_id:'super-self'}},deployment:change};
 const overview={...structuredClone(fixture),servers:[structuredClone(host),{...structuredClone(host),id:'host-2',hostname:'billing-02'}]};
 const env=await workspace('policies',{mode:'entra',role:'admin',responses:{'/api/v1/overview':overview,'POST /api/v1/policy-rollouts':()=>{published=true;return plan;},'/api/v1/policy-deployments?limit=10&offset=0':()=>({items:published?[change]:[],total:published?1:0,active_total:published?1:0,limit:10,offset:0,has_more:false}),'POST /api/v1/policy-rollouts/query':{items:[],total:0,limit:20,offset:0,has_more:false}}});
 await env.click('managed-new-rollout');const formHTML=env.element('#modal-content').innerHTML;assert.equal(env.element('#modal-title').textContent,'Apply managed policies');assert.match(formHTML,/can change its live firewall rules/);assert.match(formHTML,/One current Admin performs this action/);assert.match(formHTML,/SSH\/controller protection and rollback readiness/);assert.match(formHTML,/dedicated downtime acknowledgement/);assert.match(formHTML,/>Apply selected policies</);assert.doesNotMatch(formHTML,/review only|NO LIVE CHANGE AUTHORIZED|name="server_ids"[^>]*checked/);await env.submit('managed-rollout-form',{name:plan.name,server_ids:ids});await new Promise(setImmediate);
 const writes=mutations(env);assert.equal(writes.length,1);assert.equal(writes[0].url,'/api/v1/policy-rollouts');assert.deepEqual(JSON.parse(writes[0].options.body),{name:plan.name,server_ids:ids});assertCookieMutation(writes[0]);assert.equal(env.run('state.activeManagedRollout.status'),'queued');assert.equal(env.run('policyDeploymentsState.open'),true);assert.equal(env.element('#policy-deployments-count').textContent,'1');assert.match(env.element('#policy-deployments-list').innerHTML,/0 \/ 2<\/strong> Applied/);assert.match(env.element('#policy-deployments-list').innerHTML,/0 \/ 2<\/strong> Traffic verified/);assert.equal(env.requests.some(row=>row.url.endsWith('/confirm')),false);
});
test('policy deletion exposes its returned cleanup deployment in top-right progress through the actual shared mutation path',async()=>{
 const change={...deploymentWorkspaceSummary(),label:'Remove Billing policy',applied_count:0};let deleted=false;
 const env=await workspace('policies',{mode:'entra',role:'admin',responses:{'DELETE /api/v1/policies/policy-1':()=>{deleted=true;return {deleted:true,deployment:change};},'/api/v1/policy-deployments?limit=10&offset=0':()=>({items:deleted?[change]:[],total:deleted?1:0,active_total:deleted?1:0,limit:10,offset:0,has_more:false})}});
 await env.click('delete-policy',{id:'policy-1'});assert.equal(mutations(env).length,0);await env.click('confirm-delete',{id:'policy-1'});await new Promise(setImmediate);
 const writes=mutations(env);assert.equal(writes.length,1);assert.equal(writes[0].url,'/api/v1/policies/policy-1');assert.equal(writes[0].options.method,'DELETE');assert.deepEqual(JSON.parse(writes[0].options.body),{expected_revision:1});assertCookieMutation(writes[0]);assert.equal(env.run('policyDeploymentsState.open'),true);assert.match(env.element('#policy-deployments-list').innerHTML,/Remove Billing policy/);assert.match(env.element('#policy-deployments-list').innerHTML,/0 \/ 1<\/strong> Applied/);assert.equal(env.requests.some(row=>row.url.endsWith('/confirm')),false);
});

// The browser queues close events; a replacement dialog may already be open.
test('metadata native close invalidates its own request and delayed close cannot invalidate a reopened dialog',async()=>{
 const env=await workspace('servers',{mode:'entra',role:'admin'}),modal=env.element('#modal');await env.click('metadata-import');env.element('#metadata-csv-text').value='private draft';const closed=modal.eventListeners.close.at(-1);assert.equal(env.run('metadataAsync.active'),true);modal.open=false;closed();assert.equal(env.run('metadataAsync.active'),false);assert.equal(env.run('state.metadataPlan'),null);
 await env.click('metadata-import');const generation=env.run('metadataAsync.generation');assert.equal(modal.open,true);closed();assert.equal(env.run('metadataAsync.generation'),generation);assert.equal(env.run('metadataAsync.active'),true);assert.match(env.element('#modal-content').innerHTML,/metadata-csv-form/);
});

// Local and SSO accounts share RBAC; browser-side limited sessions cannot load infrastructure.
function localPerson(role='super_admin',required=false){return {role,auth_type:'session',auth_provider:'local',csrf_token:'session-csrf-fixture',password_change_required:required,user:{id:'local-realm:person-one',provider:'local',username:'admin',display_name:'Local Administrator',role,password_change_required:required}};}
function localWorkspace(view='access',extra={}){return workspace(view,{mode:'local',identity:localPerson(),config:{local_enabled:true,origin:'https://controller.example.test',providers:['local']},...extra});}
const localUserFixture={id:'realm:analyst',provider:'local',username:'analyst',display_name:'Local <Analyst>',role:'read_only',enabled:true,password_change_required:true};
function localDeferred(){let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject};}
test('hybrid login offers local and configured Entra/SAML without saving credentials',async()=>{
 const env=await workspace('overview',{mode:'hybrid',authStatus:401,config:{local_enabled:true,providers:['local','entra','saml'],saml:{enabled:true,display_name:'Corporate SSO'}}});
 const html=env.element('#sign-in-content').innerHTML;assert.match(html,/id="local-login-form"/);assert.match(html,/name="username" autocomplete="username"/);assert.match(html,/name="password" type="password" autocomplete="current-password"/);assert.match(html,/Sign in with existing SSO/);assert.match(html,/Sign in with Corporate SSO/);assert.doesNotMatch(html,/Microsoft/);assert.doesNotMatch(html,/value="admin"|id="login-token"/);
 await env.click('auth-entra-login');await env.click('auth-saml-login');assert.deepEqual(env.navigation,['/api/v1/auth/login','/api/v1/auth/saml/login']);assert.equal(mutations(env).length,0);assert.equal(env.storageChanges.some(row=>row.operation==='set'&&/password|username|admin/.test(row.value)),false);
});
test('Users & access offers generic SAML setup without a legacy provider on a local installation',async()=>{
 const env=await localWorkspace('access');
 const html=env.element('#view-content').innerHTML;
 assert.match(html,/<strong>Local accounts<\/strong>/);
 assert.match(html,/<strong>SAML SSO<\/strong>/);
 assert.doesNotMatch(html,/Microsoft|existing directory SSO/);
 assert.equal((html.match(/data-action="access-saml-edit"/g)||[]).length,1);
 await env.click('access-saml-edit');
 assert.match(env.element('#modal-content').innerHTML,/Identity provider metadata XML/);
 await env.click('close-modal');
 await env.click('access-user-new');
 const picker=env.element('#modal-content').innerHTML.match(/<select id="access-provider"[\s\S]*?<\/select>/)[0];
 assert.deepEqual([...picker.matchAll(/<option value="([^"]+)"/g)].map(([,value])=>value),['local','saml']);
});
test('authenticated reload holds the requested route on a neutral screen until the first data arrives',async()=>{
 const index=fs.readFileSync(path.join(__dirname,'..','index.html'),'utf8');
 assert.match(index,/<main id="sign-in-page"[^>]* hidden>/);
 assert.match(index,/<h1 id="sign-in-title">Sign in to Prṛthak<\/h1>/);
 assert.match(index,/<main id="workspace-connection"[^>]*>[\s\S]*?Checking your session…/);
 let config,auth,overview;
 const configReply=new Promise(resolve=>config=resolve),authReply=new Promise(resolve=>auth=resolve),overviewReply=new Promise(resolve=>overview=resolve);
 const env=await workspace('locations',{mode:'local',responses:{'/api/v1/auth/config':()=>configReply,'/api/v1/auth':()=>authReply,'/api/v1/overview':()=>overviewReply}});
 function assertChecking(){
   assert.equal(env.element('#workspace-connection').hidden,false);
   assert.equal(env.element('#sign-in-page').hidden,true);
   assert.equal(env.element('#workspace-shell').hidden,true);
   assert.equal(env.context.location.pathname,'/locations');
 }
 assertChecking();
 config({mode:'local',local_enabled:true});await new Promise(setImmediate);assertChecking();
 auth(localPerson('admin'));await new Promise(setImmediate);assertChecking();
 overview(fixture);await new Promise(setImmediate);
 assert.equal(env.requests.filter(({url})=>url==='/api/v1/auth').length,1);
 assert.equal(env.element('#workspace-connection').hidden,true);
 assert.equal(env.element('#sign-in-page').hidden,true);
 assert.equal(env.element('#workspace-shell').hidden,false);
 assert.equal(env.context.location.pathname,'/locations');
});
test('initial connection failures stay on the requested route and retry without showing sign-in',async()=>{
 const env=await workspace('servers',{mode:'local',config:{local_enabled:true},identity:localPerson('admin'),responses:{'/api/v1/auth':{responseStatus:503,data:{error:'Controller starting'}}}});
 assert.equal(env.context.location.pathname,'/servers');
 assert.equal(env.element('#sign-in-page').hidden,true);
 assert.equal(env.element('#workspace-shell').hidden,true);
 assert.match(env.element('#workspace-connection-status').innerHTML,/Controller starting.*Retry connection/);
 delete env.context.apiResponses['/api/v1/auth'];
 await env.click('refresh');
 assert.equal(env.context.location.pathname,'/servers');
 assert.equal(env.element('#workspace-connection').hidden,true);
 assert.equal(env.element('#sign-in-page').hidden,true);
 assert.equal(env.element('#workspace-shell').hidden,false);
});
test('signed-out deep links show only sign-in and return to the requested page after authentication',async()=>{
 const identity=localPerson('admin',false);
 const env=await workspace('firewall',{mode:'local',authStatus:401,config:{local_enabled:true},responses:{'POST /api/v1/auth/local':identity}});
 assert.equal(env.context.location.pathname,'/login');
 assert.equal(env.context.location.search,'?next=firewall');
 assert.equal(env.element('#workspace-shell').hidden,true);
 assert.equal(env.element('#sign-in-page').hidden,false);
 assert.equal(env.element('#workspace-connection').hidden,true);
 assert.equal(env.requests.some(row=>row.url==='/api/v1/overview'),false);
 env.context.apiResponses['GET /api/v1/auth']=identity;
 await env.submit('local-login-form',{username:'operator',password:'test-only'});
 assert.equal(env.context.location.pathname,'/firewall');
 assert.equal(env.element('#workspace-shell').hidden,false);
 assert.equal(env.element('#sign-in-page').hidden,true);
});
test('local login posts credentials once and forces password replacement before any infrastructure request',async()=>{
 const response=localPerson('super_admin',true),env=await workspace('overview',{mode:'local',authStatus:401,config:{local_enabled:true},responses:{'POST /api/v1/auth/local':response}});
 await env.submit('local-login-form',{username:'admin',password:'admin'});const request=mutations(env)[0];assert.equal(request.url,'/api/v1/auth/local');assert.deepEqual(JSON.parse(request.options.body),{username:'admin',password:'admin'});assert.equal(request.options.headers.Authorization,undefined);assert.equal(request.options.headers['X-CSRF-Token'],undefined);
 assert.equal(env.requests.some(row=>row.url==='/api/v1/overview'),false);assert.equal(env.run('state.passwordChangeRequired'),true);assert.equal(env.run('canWrite()'),false);assert.equal(env.run('canManageUsers()'),false);assert.match(env.element('#modal-content').innerHTML,/id="local-password-form"/);assert.match(env.element('#modal-content').innerHTML,/data-required="true"/);assert.doesNotMatch(env.element('#modal-content').innerHTML,/data-action="close-modal"/);assert.equal(env.storageChanges.some(row=>row.operation==='set'),false);
 const before=env.element('#modal-content').innerHTML;await env.click('close-modal');env.run('closeModal();navigate("servers");load()');assert.equal(env.element('#modal-content').innerHTML,before);assert.deepEqual(env.navigation,[]);assert.equal(env.requests.some(row=>row.url==='/api/v1/overview'),false);let prevented=false;env.element('#modal').eventListeners.cancel[0]({preventDefault(){prevented=true;}});assert.equal(prevented,true);
 await assert.rejects(env.run('api("/servers")'),/Change your temporary password/);await env.click('access-user-new');assert.doesNotMatch(env.element('#modal-content').innerHTML,/id="access-user-form"/);
});
test('first-login Read Only user can change own password with CSRF then enter workspace',async()=>{
 const limited=localPerson('read_only',true),full=localPerson('read_only',false),env=await localWorkspace('servers',{identity:limited,responses:{'POST /api/v1/auth/password':full}});
 assert.equal(env.requests.some(row=>row.url==='/api/v1/overview'),false);await env.submit('local-password-form',{current_password:'admin',new_password:'Long personal secret 42',confirm_password:'mismatch'});assert.equal(mutations(env).length,0);assert.match(env.element('#form-error').textContent,/do not match/);
 env.context.apiResponses['GET /api/v1/auth']=full;await env.submit('local-password-form',{current_password:'admin',new_password:'Long personal secret 42',confirm_password:'Long personal secret 42'});const request=mutations(env)[0];assert.equal(request.url,'/api/v1/auth/password');assertCookieMutation(request);assert.equal(env.run('state.passwordChangeRequired'),false);assert.equal(env.run('state.role'),'read_only');assert.equal(env.run('canWrite()'),false);assert.equal(env.requests.some(row=>row.url==='/api/v1/overview'),true);assert.equal(env.storageChanges.some(row=>row.operation==='set'&&row.value.includes('secret')),false);
});
test('local accounts get Change password in top-right account menu and SAML accounts use truthful provider copy',async()=>{
 const local=await localWorkspace('servers',{identity:localPerson('read_only')});await local.click('account-toggle');assert.match(local.element('#account-menu-panel').innerHTML,/Local account/);assert.match(local.element('#account-menu-panel').innerHTML,/data-action="account-password"/);await local.click('account-profile');assert.match(local.element('#modal-content').innerHTML,/local account uses a Prṛthak password/);assert.match(local.element('#modal-content').innerHTML,/Username/);await local.click('account-password');assert.match(local.element('#modal-content').innerHTML,/id="local-password-form"/);assert.match(local.element('#modal-content').innerHTML,/data-required="false"/);
 const saml=await workspace('servers',{mode:'hybrid',config:{local_enabled:true},identity:{...localPerson('admin'),auth_provider:'saml',user:{id:'saml-user',provider:'saml',subject:'persistent-subject',display_name:'Directory user'}}});await saml.click('account-toggle');assert.match(saml.element('#account-menu-panel').innerHTML,/SAML SSO/);assert.doesNotMatch(saml.element('#account-menu-panel').innerHTML,/account-password/);await saml.click('account-profile');assert.match(saml.element('#modal-content').innerHTML,/organisation manages your SAML sign-in/);assert.match(saml.element('#modal-content').innerHTML,/persistent-subject/);assert.doesNotMatch(saml.element('#modal-content').innerHTML,/Entra object ID|local-password-form/);
});
test('only Super Admin can create local users in any of the same three roles and passwords never enter state/storage',async()=>{
 for(const role of ['read_only','admin','super_admin']){const env=await localWorkspace('access',{responses:{'GET /api/v1/access/users':{items:[localUserFixture]}}});await env.click('access-user-new');assert.match(env.element('#modal-content').innerHTML,/name="provider"/);await env.submit('access-user-form',{provider:'local',username:'operations',password:'Temporary personal 42',confirm_password:'Temporary personal 42',display_name:'Operations',email:'ops@example.test',role});const request=mutations(env)[0];assert.equal(request.url,'/api/v1/access/users');assertCookieMutation(request);assert.deepEqual(JSON.parse(request.options.body),{provider:'local',username:'operations',password:'Temporary personal 42',confirm_password:'Temporary personal 42',display_name:'Operations',email:'ops@example.test',role});assert.equal(env.run('JSON.stringify(state).includes("Temporary personal 42")'),false);assert.equal(env.storageChanges.some(row=>String(row.value).includes('Temporary')),false);}
 for(const role of ['admin','read_only']){const denied=await localWorkspace('access',{identity:localPerson(role)});await denied.click('access-user-new');await denied.click('access-user-reset-review',{id:localUserFixture.id});await denied.click('access-saml-edit');assert.equal(mutations(denied).length,0);assert.equal(denied.requests.some(row=>row.url==='/api/v1/auth/providers'),false);assert.doesNotMatch(denied.element('#modal-content').innerHTML,/access-user-form|access-password-reset-form|access-saml-form/);}
});
test('Super Admin resets local credentials with forced-next-login change and cannot use reset UI for SSO or self',async()=>{
 const env=await localWorkspace('access',{responses:{'GET /api/v1/access/users':{items:[localUserFixture,approvedUser]}}});assert.match(env.element('#view-content').innerHTML,/Local &lt;Analyst&gt;/);assert.match(env.element('#view-content').innerHTML,/Password change required/);await env.click('access-user-reset-review',{id:localUserFixture.id});assert.match(env.element('#modal-content').innerHTML,/All active sessions will be revoked/);await env.submit('access-password-reset-form',{password:'A reset credential 42',confirm_password:'not matching'});assert.equal(mutations(env).length,0);await env.submit('access-password-reset-form',{password:'A reset credential 42',confirm_password:'A reset credential 42'});const request=mutations(env)[0];assert.equal(request.url,'/api/v1/access/users/realm%3Aanalyst/reset-password');assertCookieMutation(request);
 env.run('state.accessUsers.push(state.user)');await env.click('access-user-reset-review',{id:env.run('state.user.id')});assert.equal(env.element('#modal').open,false);await env.click('access-user-reset-review',{id:approvedUser.id});assert.equal(env.element('#modal').open,false);assert.equal(env.run('JSON.stringify(state).includes("A reset credential")'),false);
});
test('SAML form submits HTTPS origin, public metadata and explicit configuration without CLI or automatic role claims',async()=>{
 const status={local:{enabled:true},entra:{configured:false},saml:{enabled:false,configured:false}},env=await localWorkspace('access',{responses:{'GET /api/v1/auth/providers':status,'PUT /api/v1/auth/providers/saml':{...status,saml:{enabled:true,configured:true,origin:'https://controller.example.test',sp_entity_id:'prthak-pilot',idp_entity_id:'https://idp.example.test'}}}});await new Promise(setImmediate);await env.click('access-saml-edit');const html=env.element('#modal-content').innerHTML;assert.match(html,/id="access-saml-form"/);assert.match(html,/sign both the SAML response and assertion/);assert.match(html,/exact subject/);assert.match(html,/Local accounts stay available/);assert.match(html,/https:\/\/controller.example.test/);
 await env.submit('access-saml-form',{enabled:'on',origin:'https://controller.example.test',sp_entity_id:'prthak-pilot',idp_metadata_xml:'<EntityDescriptor>public fixture only</EntityDescriptor>',display_name:'Corporate SSO'});const request=mutations(env)[0];assert.equal(request.url,'/api/v1/auth/providers/saml');assert.equal(request.options.method,'PUT');assertCookieMutation(request);assert.deepEqual(JSON.parse(request.options.body),{expected_revision:0,enabled:true,origin:'https://controller.example.test',sp_entity_id:'prthak-pilot',idp_metadata_xml:'<EntityDescriptor>public fixture only</EntityDescriptor>',display_name:'Corporate SSO'});assert.equal(env.storageChanges.some(row=>row.operation==='set'&&row.value.includes('EntityDescriptor')),false);
});
test('late local login and account mutations cannot replace a newer dialog or identity',async()=>{
 const pending=localDeferred(),env=await workspace('overview',{mode:'local',authStatus:401,config:{local_enabled:true},responses:{'POST /api/v1/auth/local':()=>pending.promise}});const call=env.submit('local-login-form',{username:'admin',password:'admin'});env.run('showModal("Unrelated dialog","Keep my newer draft")');pending.resolve(localPerson('super_admin',true));await call;assert.equal(env.element('#modal-content').innerHTML,'Keep my newer draft');assert.equal(env.run('state.user'),null);assert.equal(env.requests.some(row=>row.url==='/api/v1/overview'),false);
 const delayed=localDeferred(),other=await localWorkspace('access',{responses:{'GET /api/v1/access/users':{items:[localUserFixture]},'POST /api/v1/access/users':()=>delayed.promise}});await other.click('access-user-new');const save=other.submit('access-user-form',{provider:'local',username:'newuser',password:'Long temporary secret',confirm_password:'Long temporary secret',role:'admin'});other.run('showModal("Keep this","Newer draft");clearDashboardIdentity()');delayed.resolve({id:'created'});await save;assert.equal(other.element('#modal-content').innerHTML,'Newer draft');assert.equal(other.run('state.user'),null);assert.equal(other.element('created:div').textContent,'');
});
test('late user-list responses cannot restore a revoked Super Admin list, while CSRF-only refresh preserves a current draft',async()=>{
 const pending=localDeferred(),env=await localWorkspace('servers',{responses:{'GET /api/v1/access/users':()=>pending.promise}});env.run('state.view="access"');const load=env.run('loadAccessUsers()');env.run('clearDashboardIdentity()');pending.resolve({items:[localUserFixture]});await load;assert.equal(env.run('state.accessUsers.length'),0);assert.equal(env.run('state.accessLoaded'),false);
 const current=await localWorkspace('access');await current.click('access-user-new');const before=current.element('#modal-content').innerHTML,generation=current.run('accessAsync.generation');current.context.same=localPerson();current.context.same.csrf_token='new-csrf';current.run('applyDashboardIdentity(same)');assert.equal(current.run('accessAsync.generation'),generation);assert.equal(current.element('#modal-content').innerHTML,before);
});
test('late SAML file reads cannot overwrite typed replacements, closed dialogs or another user',async()=>{
 for(const replacement of ['typing','closed','identity','cancel']){const env=await localWorkspace('access');await env.click('access-saml-edit');const pending=localDeferred();env.context.fileInput={files:[{size:20,text:()=>pending.promise}],value:'fixture.xml'};const reading=env.run('accessSAMLFile(fileInput)');env.element('#saml-metadata').value='Keep newer XML';if(replacement==='typing')env.run('accessInput({target:{id:"saml-metadata"}})');if(replacement==='closed')env.run('closeModal()');if(replacement==='identity')env.run('clearDashboardIdentity()');if(replacement==='cancel'){env.context.cancelled={files:[],value:''};await env.run('accessSAMLFile(cancelled)');}pending.resolve('Obsolete XML');await reading;assert.equal(env.element('#saml-metadata').value,'Keep newer XML',replacement);}
});
test('password input nodes are cleared on submit and backend must-change errors force a limited session gate',async()=>{
 const env=await localWorkspace('servers',{identity:localPerson('read_only'),responses:{'POST /api/v1/auth/password':{responseStatus:400,data:{error:'Current password is incorrect'}}}});await env.click('account-password');const secretNodes=[{value:'Current secret 42'},{value:'New personal secret 42'}],form={id:'local-password-form',dataset:{},values:{current_password:'Current secret 42',new_password:'New personal secret 42',confirm_password:'New personal secret 42'},querySelector:env.element,querySelectorAll:()=>secretNodes};env.context.secretForm=form;await env.run('localAuthSubmit({preventDefault(){},target:secretForm})');assert.equal(secretNodes.every(node=>node.value===''),true);assert.match(env.element('#form-error').textContent,/Current password is incorrect/);
 const gated=await localWorkspace('servers',{responses:{'POST /api/v1/policies':{responseStatus:403,data:{error:'Change password',code:'password_change_required'}}}});await assert.rejects(gated.run('api("/policies",{method:"POST",body:{}})'),/Change password/);assert.equal(gated.run('state.passwordChangeRequired'),true);assert.equal(gated.run('state.data'),null);assert.match(gated.element('#modal-content').innerHTML,/id="local-password-form"/);assert.equal(gated.run('canWrite()'),false);
});
test('password requirement survives stale auth refresh and in-flight inventory results until a successful password change',async()=>{
 const limited=await localWorkspace('servers',{identity:localPerson('admin',true)});limited.context.oldAuth=localPerson('admin',false);limited.run('applyDashboardIdentity(oldAuth)');assert.equal(limited.run('state.passwordChangeRequired'),true);assert.equal(limited.run('canWrite()'),false);assert.equal(limited.element('#modal-close').hidden,true);
 const pending=localDeferred(),env=await localWorkspace('servers',{responses:{'GET /api/v1/overview':()=>pending.promise,'POST /api/v1/policies':{responseStatus:403,data:{error:'Change password',code:'password_change_required'}}}});await assert.rejects(env.run('api("/policies",{method:"POST",body:{}})'),/Change password/);pending.resolve(structuredClone(fixture));await new Promise(setImmediate);assert.equal(env.run('state.data'),null);assert.equal(env.run('state.passwordChangeRequired'),true);assert.match(env.element('#modal-content').innerHTML,/local-password-form/);assert.doesNotMatch(env.element('#view-content').innerHTML,/lab-api/);
});
test('disabled SSO providers never get actionable sign-in buttons and configuration errors are escaped',async()=>{
 const env=await workspace('overview',{mode:'hybrid',authStatus:401,config:{local_enabled:true,providers:[{provider:'local',enabled:true},{provider:'entra',enabled:false},{provider:'saml',enabled:false}],saml:{enabled:false,error:'Expired <certificate>'}}});const html=env.element('#sign-in-content').innerHTML;assert.match(html,/Expired &lt;certificate&gt;/);assert.doesNotMatch(html,/data-action="auth-entra-login"|data-action="auth-saml-login"|<certificate>/);await env.click('auth-entra-login');await env.click('auth-saml-login');assert.deepEqual(env.navigation,[]);
});
test('SAML provider changes that revoke their caller return to sign-in without claiming an active session',async()=>{
 const identity={...localPerson(),auth_provider:'saml',user:{id:'saml:operator',provider:'saml',subject:'operator-subject',role:'super_admin',display_name:'SSO Operator'}},status={local:{enabled:true},entra:{configured:false},saml:{enabled:true,configured:true,origin:'https://controller.example.test',sp_entity_id:'pilot',display_name:'Company SSO'}},env=await workspace('access',{mode:'hybrid',identity,config:{local_enabled:true,saml:status.saml,providers:['local','saml']},responses:{'GET /api/v1/auth/providers':status,'PUT /api/v1/auth/providers/saml':{...status,signed_out:true}}});await new Promise(setImmediate);await env.click('access-saml-edit');await env.submit('access-saml-form',{enabled:'on',origin:'https://controller.example.test',sp_entity_id:'pilot',display_name:'Company SSO',idp_metadata_xml:''});assert.equal(env.run('state.authType'),null);assert.equal(env.run('state.user'),null);assert.equal(env.run('state.data'),null);assert.match(env.element('#sign-in-content').innerHTML,/id="local-login-form"/);assert.equal(mutations(env).length,1);
});
test('local and SAML operators must explicitly identify the Entra candidate instead of reusing their own object ID',async()=>{
 for(const provider of ['local','saml']){const identity={...localPerson(),auth_provider:provider,user:{...localPerson().user,provider,object_id:'not-an-entra-object-id'}},env=await guiSetupWorkspace({'/api/v1/platform/setup':guiSetupStatus({entra_configured:true})},{mode:'hybrid',identity,config:{local_enabled:true}});const html=env.element('#view-content').innerHTML;assert.match(html,/Candidate Super Admin Entra Object ID \(required for local or SAML operator\)/);assert.match(html,/id="setup-bootstrap-oid" data-required="true" name="candidate_object_id"/);const candidate=env.element('#setup-bootstrap-oid');candidate.dataset.required='true';assert.notEqual(candidate.required,true);env.run('platformSetupInput({target:{id:"setup-enable-entra",checked:true}})');assert.equal(candidate.required,true);env.run('platformSetupInput({target:{id:"setup-enable-entra",checked:false}})');assert.equal(candidate.required,false);assert.match(html,/actual Entra Object ID/);assert.doesNotMatch(html,/value="not-an-entra-object-id"/);
 const values=guiSetupValues({configure_entra:'on',SEG_ENTRA_TENANT_ID:'11111111-1111-1111-1111-111111111111',SEG_ENTRA_CLIENT_ID:'22222222-2222-2222-2222-222222222222',SEG_ENTRA_REDIRECT_URI:'https://controller.example.test/api/v1/auth/callback'});await submitRendered(env,renderedForm(env,'platform-setup-form',values));assert.equal(mutations(env).length,0);assert.match(env.element('#form-error').textContent,/actual Entra Object ID/);values.candidate_object_id='33333333-3333-3333-3333-333333333333';env.context.apiResponses['POST /api/v1/platform/setup/preview']=guiSetupPlan();await submitRendered(env,renderedForm(env,'platform-setup-form',values));const body=JSON.parse(mutations(env)[0].options.body);assert.equal(body.candidate_object_id,values.candidate_object_id);assert.equal(body.candidate_object_id==='not-an-entra-object-id',false);}
});
test('password forms use POST and Unicode password validation matches character and byte boundaries',async()=>{
 const env=await localWorkspace('servers',{identity:localPerson('read_only')});await env.click('account-password');assert.match(env.element('#modal-content').innerHTML,/<form id="local-password-form" method="post" action="\/api\/v1\/auth\/password"/);assert.equal(env.run('accessPasswordValid("😀".repeat(12))'),true);assert.equal(env.run('accessPasswordValid("😀".repeat(256))'),true);assert.equal(env.run('accessPasswordValid("😀".repeat(257))'),false);assert.equal(env.run('accessPasswordValid("😀".repeat(6))'),false);assert.equal(env.run('accessPasswordValid("Long secret\\n42")'),false);
});

test('demo preview stays synthetic when public status also describes installed local-auth capability',async()=>{const env=await workspace('access',{mode:'demo',config:{local_enabled:true,providers:[{provider:'local',enabled:true}]}});assert.match(env.element('#view-content').innerHTML,/Synthetic demo workspace/);assert.match(env.element('#view-content').innerHTML,/data-action="access-user-new" disabled/);assert.doesNotMatch(env.element('#view-content').innerHTML,/access-saml-edit|Local accounts and organisation SSO/);await env.click('access-saml-edit');assert.doesNotMatch(env.element('#modal-content').innerHTML,/id="access-saml-form"/);});

test('SAML trust updates bind the form-open revision and preserve a rejected stale draft without adopting newer trust',async()=>{
 const status={local:{enabled:true},saml:{revision:7,enabled:true,configured:true,origin:'https://controller.example.test',sp_entity_id:'pilot',idp_entity_id:'https://idp.example.test'}},env=await localWorkspace('access',{responses:{'GET /api/v1/auth/providers':status,'PUT /api/v1/auth/providers/saml':{responseStatus:409,data:{error:'Provider configuration changed'}}}});await new Promise(setImmediate);await env.click('access-saml-edit');const before=env.element('#modal-content').innerHTML;assert.match(before,/<form id="access-saml-form" data-revision="7"/);env.run('state.accessProviders.saml.revision=8');env.element('#saml-metadata').value='Keep my public XML draft';await env.submit('access-saml-form',{enabled:'on',origin:'https://controller.example.test',sp_entity_id:'pilot',idp_metadata_xml:'New reviewed XML'});const request=mutations(env)[0];assert.equal(JSON.parse(request.options.body).expected_revision,7);assert.equal(env.element('#modal').open,true);assert.equal(env.element('#modal-content').innerHTML,before);assert.equal(env.element('#saml-metadata').value,'Keep my public XML draft');assert.match(env.element('#form-error').textContent,/Close this draft, refresh Users & access/);assert.equal(env.run('state.accessProviders'),null);assert.equal(mutations(env).length,1);
});


// Built-in identity protection is flagged by the controller, never guessed from a username.
test('built-in admin row offers password changes while ordinary accounts remain editable',async()=>{
 const builtin={...localPerson().user,protected_account:true,enabled:true},ordinary={...localUserFixture,username:'admin',protected_account:false};
 const env=await localWorkspace('access',{identity:{...localPerson(),user:builtin},responses:{'GET /api/v1/access/users':{items:[builtin,ordinary]}}});
 const html=env.element('#view-content').innerHTML,builtinRow=html.match(/<tr><td><strong>Local Administrator[\s\S]*?<\/tr>/)[0];
 assert.match(builtinRow,/Built-in admin/);assert.match(builtinRow,/Protected account/);assert.match(builtinRow,/data-action="account-password"/);assert.doesNotMatch(builtinRow,/access-user-edit|access-user-reset-review|access-user-delete/);
 assert.match(html,/data-action="access-user-edit" data-id="realm:analyst"/);await env.click('account-password');assert.match(env.element('#modal-content').innerHTML,/id="local-password-form"/);
 await env.click('access-user-edit',{id:builtin.id});const modal=env.element('#modal-content').innerHTML;assert.match(modal,/username, role and access are fixed/);assert.doesNotMatch(modal,/access-user-form|name="role"|name="enabled"/);assert.equal(mutations(env).length,0);
 await env.click('access-user-edit',{id:ordinary.id});assert.match(env.element('#modal-content').innerHTML,/id="access-user-form"/);
});
test('another Super Admin may reset built-in password but cannot submit a stale access edit',async()=>{
 const builtin={...localPerson().user,protected_account:true,enabled:true},identity={...localPerson(),user:{...localPerson().user,id:'second-super',username:'second-super'}};
 const env=await localWorkspace('access',{identity,responses:{'GET /api/v1/access/users':{items:[builtin]}}});
 const html=env.element('#view-content').innerHTML;assert.match(html,/access-user-reset-review/);assert.doesNotMatch(html,/data-action="access-user-edit"/);
 await env.click('access-user-reset-review',{id:builtin.id});assert.match(env.element('#modal-content').innerHTML,/id="access-password-reset-form"/);
 env.run('state.accessUsers[0].protected_account=false');await env.click('access-user-edit',{id:builtin.id});
 const form=renderedForm(env,'access-user-form',{display_name:'Replacement',email:'replacement@example.test',role:'read_only',enabled:'false'});env.run('state.accessUsers[0].protected_account=true');
 await submitRendered(env,form);assert.equal(mutations(env).length,0);assert.match(env.element('#form-error').textContent,/account’s access is protected/);
});
test('built-in admin can save display details through My profile while its username and role stay fixed',async()=>{
 const person=localPerson();Object.assign(person.user,{protected_account:true,display_name:'Admin'});
 const result={...person.user,display_name:'Pratik <Admin>',email:'admin@example.test'};
 const env=await localWorkspace('servers',{identity:person,responses:{['PATCH /api/v1/access/users/'+encodeURIComponent(person.user.id)]:result}});
 await env.click('account-profile');
 const html=env.element('#modal-content').innerHTML;
 assert.match(html,/username and Super Admin role are fixed/);
 assert.match(html,/data-action="account-password"/);
 await env.click('account-profile-edit');
 const edit=env.element('#modal-content').innerHTML;
 assert.match(edit,/id="account-profile-form"/);
 assert.doesNotMatch(edit,/name="username"|name="role"|name="enabled"/);
 await env.submit('account-profile-form',{display_name:'Pratik <Admin>',email:'admin@example.test',username:'forged',role:'read_only'});
 const [request]=mutations(env);
 assertCookieMutation(request);
 assert.deepEqual(JSON.parse(request.options.body),{display_name:'Pratik <Admin>',email:'admin@example.test'});
 assert.equal(env.element('#identity-name').textContent,'Pratik <Admin>');
 assert.equal(env.run('state.user.username'),'admin');
 assert.equal(env.run('state.role'),'super_admin');
 await env.click('account-profile');
 assert.match(env.element('#modal-content').innerHTML,/Pratik &lt;Admin&gt;|admin@example\.test/);
});

test('network controls open under Policies with compatible links and accurate endpoint status',async()=>{
 const env=await workspace('network-control',{mode:'entra',role:'read_only'});
 assert.equal(env.run('state.view'),'policies');assert.doesNotMatch(env.element('#navigation').innerHTML,/href="\/network-control"/);
 assert.doesNotMatch(env.element('#view-tabs').innerHTML,/href="\/network-control"/);
 assert.match(env.element('#view-content').innerHTML,/<details id="advanced-network-controls"[^>]* open>/);
 assert.match(env.element('#view-content').innerHTML,/Outbound &amp; quarantine|Outbound & quarantine/);
 assert.ok(env.requests.some(request=>request.url==='/api/v1/network-control?limit=50&offset=0'));
 env.run(`state.data.servers[0].network_control={checked_at:"2026-11-04T00:00:00Z",stale:true,egress:{status:"enforced"},quarantine:{status:"expiry_unconfirmed",expiry_unconfirmed:true,expires_at:"2026-11-04T01:00:00Z",error:"<unsafe>"}};state.view="servers";render();`);
 let html=env.element('#view-content').innerHTML;assert.match(html,/Quarantine expiry unconfirmed/);assert.match(html,/Outbound · stale receipt/);assert.doesNotMatch(html,/Quarantine released|Outbound applied/);
 html=env.run('networkControlStatusHTML(state.data.servers[0],true)');assert.match(html,/&lt;unsafe&gt;/);assert.doesNotMatch(html,/<unsafe>/);
 assert.match(html,/href="\/policies\?section=advanced"/);
 await assert.rejects(env.run(`api('/network-control/assess',{method:'POST',body:{}})`),/Read Only/);
 const before=env.requests.length;await env.run(`api('/firewall-activation/query',{method:'POST',body:{}})`);assert.equal(env.requests.length,before+1);
});

test('Policies opens Advanced controls only on demand or from a direct link',async()=>{
 const env=await workspace('policies',{mode:'entra',role:'admin'});
 const historyRequests=()=>env.requests.filter(request=>request.url.startsWith('/api/v1/network-control?')).length;
 assert.match(env.element('#view-content').innerHTML,/<details id="advanced-network-controls"[^>]*>\s*<summary>Advanced controls/);
 assert.doesNotMatch(env.element('#view-content').innerHTML,/<details id="advanced-network-controls"[^>]* open>/);
 assert.equal(historyRequests(),0);
 const toggle=env.listeners.toggle.at(-1);
 toggle({target:{id:'advanced-network-controls',open:true}});
 await new Promise(setImmediate);
 assert.equal(historyRequests(),1);
 assert.match(env.element('#view-content').innerHTML,/data-action="network-control-new-quarantine"/);
 await env.click('network-control-new-quarantine');
 assert.equal(env.element('#modal-title').textContent,'Emergency quarantine');
 assert.equal(mutations(env).length,0);
 await env.click('close-modal');
 assert.equal(clickWorkspaceLink(env,'/servers'),true);
 assert.equal(clickWorkspaceLink(env,'/policies?section=advanced'),true);
 assert.equal(env.run('state.view'),'policies');
 assert.equal(env.run('state.networkControlOpen'),true);
 assert.equal(env.routeHistory.at(-1),'/policies?section=advanced');
 env.popRoute('/policies');
 assert.equal(env.run('state.networkControlOpen'),false);
});

test('a signed-out Network controls bookmark returns to Advanced controls after login',async()=>{
 const identity=localPerson('admin',false);
 const env=await workspace('network-control',{mode:'local',authStatus:401,config:{local_enabled:true},responses:{'POST /api/v1/auth/local':identity}});
 assert.equal(env.context.location.pathname,'/login');
 assert.equal(env.context.location.search,'?next=network-control');
 assert.equal(env.requests.some(request=>request.url.startsWith('/api/v1/network-control?')),false);
 env.context.apiResponses['GET /api/v1/auth']=identity;
 await env.submit('local-login-form',{username:'operator',password:'test-only'});
 assert.equal(env.context.location.pathname,'/policies');
 assert.equal(env.context.location.search,'?section=advanced');
 assert.match(env.element('#view-content').innerHTML,/<details id="advanced-network-controls"[^>]* open>/);
});

test('failed quarantine replacement keeps prior active isolation visible',async()=>{
 const env=await workspace('servers');
 env.run(`state.data.servers[0].network_control={checked_at:new Date().toISOString(),stale:false,egress:{status:"rolled_back",last_operation_status:"rolled_back",active:true},quarantine:{status:"rolled_back",last_operation_status:"rolled_back",active:true,expires_at:new Date(Date.now()+60000).toISOString()}};render();`);
 const html=env.element('#view-content').innerHTML;assert.match(html,/>Quarantined</);assert.match(html,/Quarantine Rolled Back|Quarantine Rolled back|Quarantine rolled back/);assert.match(html,/Outbound applied/);assert.match(html,/Outbound Rolled Back|Outbound Rolled back|Outbound rolled back/);assert.doesNotMatch(html,/Quarantine released/);
});

const updateAPI = '/api/v1/platform/updates';
const updatePhrase = 'INSTALL CONTROLLER UPDATE';
const updateID = 'b'.repeat(32);
const updateName = 'prthak-controller-0.18.3-offline-rhel9-x86_64.tar.gz';
const updateStatus = update => ({available:true,blockers:[],max_bytes:1024,chunk_bytes:4,update});
const updateRecord = (extra={}) => ({id:updateID,name:updateName,status:'uploading',size:11,offset:4,can_cancel:true,...extra});

test('Platform Updates resumes binary chunks, checks the package and applies only after exact confirmation', async () => {
 let record=updateRecord();
 const sig={algorithm:'Ed25519',signature:'fixture'};
 const review={version:'0.18.3',sha256:'a'.repeat(64),expires_at:new Date(Date.now()+60000).toISOString(),host_rpms:'validated_only'};
 const updatePath=updateAPI+'/'+updateID;
 const env=await workspace('settings',{mode:'entra',responses:{
  [updateAPI]:()=>updateStatus(record),
  ['POST '+updateAPI+'/upload']:()=>record,
  ['PUT '+updatePath+'/chunks/4']:()=>record=updateRecord({offset:8}),
  ['PUT '+updatePath+'/chunks/8']:()=>record=updateRecord({offset:11}),
  ['POST '+updatePath+'/review']:()=>record=updateRecord({status:'ready',offset:11,review,confirmation_phrase:updatePhrase}),
  ['POST '+updatePath+'/apply']:()=>record=updateRecord({status:'applying',offset:11,can_cancel:false,review})
 }});
 await env.click('platform-tab',{tab:'updates'});
 await new Promise(setImmediate);
 assert.match(env.element('#view-content').innerHTML,/Resume upload and check package/);
 assert.match(env.element('#view-content').innerHTML,/Changes to RHEL host packages require the host installer/);
 const archive=Object.assign(new Blob(['hello-world']),{name:updateName});
 const signature=Object.assign(new Blob([JSON.stringify(sig)]),{name:updateName+'.signature.json'});
 await submitRendered(env,renderedForm(env,'platform-update-upload-form',{archive,signature}));
 const writes=mutations(env).filter(request=>request.url.startsWith(updateAPI));
 assert.deepEqual(writes.map(request=>[request.options.method,request.url]),[
  ['POST',updateAPI+'/upload'],['PUT',updatePath+'/chunks/4'],['PUT',updatePath+'/chunks/8'],['POST',updatePath+'/review']
 ]);
 assert.deepEqual(JSON.parse(writes[0].options.body),{name:updateName,size:11,signature:sig});
 assert.deepEqual(await Promise.all(writes.slice(1,3).map(request=>request.options.body.text())),['o-wo','rld']);
 for(const chunk of writes.slice(1,3))assert.equal(chunk.options.headers['Content-Type'],'application/octet-stream');
 for(const request of writes)assertCookieMutation(request);
 await env.click('platform-update-open-review');
 assert.match(env.element('#modal-content').innerHTML,/Verified package SHA-256/);
 await env.submit('platform-update-review-form',{confirmation:'wrong'});
 assert.equal(env.requests.some(request=>request.url===updatePath+'/apply'),false);
 await env.submit('platform-update-review-form',{confirmation:updatePhrase});
 const apply=env.requests.find(request=>request.url===updatePath+'/apply');
 assert.deepEqual(JSON.parse(apply.options.body),{confirmation:updatePhrase});
 assertCookieMutation(apply);
 assert.match(env.element('#view-content').innerHTML,/Installation in progress/);
 assert.doesNotMatch(env.element('#view-content').innerHTML,/Update verified/);
 record=updateRecord({status:'applied',result:{phase:'committed',verified:false}});
 await env.click('platform-update-refresh');
 assert.match(env.element('#view-content').innerHTML,/Update verification unavailable/);
 record=updateRecord({status:'rolled_back',failure_step:'Verify candidate HTTPS and the update fence on loopback',result:{phase:'rolled_back',verified:false,rolled_back:true}});
 await env.click('platform-update-refresh');
 assert.match(env.element('#view-content').innerHTML,/Previous controller restored/);
 assert.match(env.element('#view-content').innerHTML,/Failure step/);
 assert.match(env.element('#view-content').innerHTML,/Verify candidate HTTPS/);
});

test('Platform Updates caps chunks at 1 MiB and replays the same bytes after a network failure and lost 500 response', async () => {
 const oneMiB=1024*1024, priorOffset=4*oneMiB, nextOffset=priorOffset+oneMiB;
 const archive=Object.assign(new Blob([Buffer.alloc(priorOffset),Buffer.alloc(oneMiB,3),'tail']),{name:updateName});
 const signature=Object.assign(new Blob(['{"algorithm":"Ed25519","signature":"fixture"}']),{name:updateName+'.signature.json'});
 const path=updateAPI+'/'+updateID, firstChunk=path+'/chunks/'+priorOffset;
 let record=updateRecord({size:archive.size,offset:priorOffset}), attempts=0;
 const env=await workspace('settings',{mode:'entra',responses:{
  [updateAPI]:()=>({...updateStatus(record),max_bytes:8*oneMiB,chunk_bytes:4*oneMiB}),
  ['POST '+updateAPI+'/upload']:()=>record,
  ['PUT '+firstChunk]:()=>{
   attempts++;
   if(attempts===1)throw new TypeError('Network request failed');
   if(attempts===2){record={...record,offset:nextOffset};return {responseStatus:500,data:{}};}
   return record;
  },
  ['PUT '+path+'/chunks/'+nextOffset]:()=>record={...record,offset:archive.size},
  ['POST '+path+'/review']:()=>record={...record,status:'ready'}
 }});
 await env.click('platform-tab',{tab:'updates'});
 await new Promise(setImmediate);
 const delays=[];
 env.context.setTimeout=(callback,delay)=>{if(delay<3500){delays.push(delay);queueMicrotask(callback);}return 1;};
 await submitRendered(env,renderedForm(env,'platform-update-upload-form',{archive,signature}));
 const writes=mutations(env).filter(request=>request.url.startsWith(updateAPI));
 assert.deepEqual(writes.map(request=>request.url),[updateAPI+'/upload',firstChunk,firstChunk,firstChunk,path+'/chunks/'+nextOffset,path+'/review']);
 assert.deepEqual(delays,[1000,2000]);
 assert.equal(writes[1].options.body.size,oneMiB);
 assert.equal(writes[1].options.body,writes[2].options.body);
 assert.equal(writes[2].options.body,writes[3].options.body);
 assert.equal(await writes[4].options.body.text(),'tail');
 for(const request of writes)assertCookieMutation(request);
});

test('Platform Updates pauses after bounded timeouts and resumes from refreshed progress with the same files', async () => {
 const archive=Object.assign(new Blob(['hello-world']),{name:updateName});
 const signature=Object.assign(new Blob(['{"algorithm":"Ed25519","signature":"fixture"}']),{name:updateName+'.signature.json'});
 const path=updateAPI+'/'+updateID;
 let record=updateRecord(), recovered=false;
 const env=await workspace('settings',{mode:'entra',responses:{
  [updateAPI]:()=>updateStatus(record),
  ['POST '+updateAPI+'/upload']:()=>record,
  ['PUT '+path+'/chunks/4']:()=>record={...record,offset:8},
  ['PUT '+path+'/chunks/8']:()=>{
   if(!recovered)throw new DOMException('Request aborted','AbortError');
   return record={...record,offset:11};
  },
  ['POST '+path+'/review']:()=>record={...record,status:'ready'}
 }});
 await env.click('platform-tab',{tab:'updates'});
 await new Promise(setImmediate);
 const delays=[];
 env.context.setTimeout=(callback,delay)=>{if([1000,2000,4000].includes(delay)){delays.push(delay);queueMicrotask(callback);}return 1;};
 await submitRendered(env,renderedForm(env,'platform-update-upload-form',{archive,signature}));
 assert.deepEqual(delays,[1000,2000,4000]);
 assert.equal(env.requests.filter(request=>request.url===path+'/chunks/8').length,4);
 assert.equal(env.run('state.platformUpdates.update.offset'),8);
 assert.match(env.element('#platform-update-upload-error').textContent,/Upload paused.*same package and signature/);
 assert.equal(env.requests.some(request=>request.url===path+'/review'),false);
 recovered=true;
 await submitRendered(env,renderedForm(env,'platform-update-upload-form',{archive,signature}));
 const writes=mutations(env).filter(request=>request.url.startsWith(updateAPI));
 assert.deepEqual(writes.slice(-3).map(request=>request.url),[updateAPI+'/upload',path+'/chunks/8',path+'/review']);
 assert.equal(writes[0].options.body,writes.at(-3).options.body);
 assert.equal(env.element('#platform-update-upload-error').hidden,true);
});

test('Platform Updates keeps uploads disabled without the appliance capability or a Super Admin session',async()=>{
 const appliance=await workspace('settings',{mode:'entra',responses:{[updateAPI]:{
  ...updateStatus(null),available:false,blockers:['Install an updater-enabled release']
 }}});
 await appliance.click('platform-tab',{tab:'updates'});
 await new Promise(setImmediate);
 assert.match(appliance.element('#view-content').innerHTML,/Install an updater-enabled standalone RHEL 9 x86_64 appliance release once/);
 assert.match(appliance.element('#view-content').innerHTML,/id="platform-update-archive"[^>]+disabled/);
 const roleToken=await workspace('settings',{mode:'tokens',storage:{'segment-token':'lab-token'}});
 await roleToken.click('platform-tab',{tab:'updates'});
 assert.equal(roleToken.requests.some(request=>request.url===updateAPI),false);
 assert.match(roleToken.element('#view-content').innerHTML,/Sign in with a Super Admin account/);
 const admin=await workspace('settings',{mode:'entra',role:'admin'});
 await admin.click('platform-tab',{tab:'updates'});
 assert.doesNotMatch(admin.element('#view-content').innerHTML,/data-tab="updates"/);
 assert.equal(admin.requests.some(request=>request.url===updateAPI),false);
});

test('Platform Updates can resume a durable request after an uncertain host acknowledgment',async()=>{
 let record=updateRecord({status:'reviewing',can_cancel:false,can_retry:true});
 const updatePath=updateAPI+'/'+updateID;
 const env=await workspace('settings',{mode:'entra',responses:{
  [updateAPI]:()=>updateStatus(record),
  ['POST '+updatePath+'/review']:()=>record=updateRecord({status:'reviewing',can_cancel:false,can_retry:false}),
  ['POST '+updatePath+'/apply']:()=>record=updateRecord({status:'applying',can_cancel:false,can_retry:false})
 }});
 await env.click('platform-tab',{tab:'updates'});
 await new Promise(setImmediate);
 assert.match(env.element('#view-content').innerHTML,/Resume package check/);
 await env.click('platform-update-retry-review');
 assert.equal(env.requests.filter(request=>request.url===updatePath+'/review').length,1);
 record=updateRecord({status:'applying',can_cancel:false,can_retry:true,confirmation_phrase:updatePhrase});
 await env.click('platform-update-refresh');
 assert.match(env.element('#view-content').innerHTML,/Resume installation request/);
 await env.click('platform-update-open-review');
 await env.submit('platform-update-review-form',{confirmation:updatePhrase});
 assert.equal(env.requests.filter(request=>request.url===updatePath+'/apply').length,1);
 assert.doesNotMatch(env.element('#view-content').innerHTML,/Update verified/);
});

test('Policies offers discovery and a manual policy saves exact enrolled endpoint IDs',async()=>{
 const env=await workspace('policies',{mode:'entra',role:'admin'});
 const action=env.element('#learn-button');
 assert.equal(action.hidden,false);assert.match(action.innerHTML,/Discover policy/);
 action.eventListeners.click[0]();assert.equal(env.element('#modal-title').textContent,'Discover policy');
 assert.match(env.element('#modal-content').innerHTML,/name="policy_action"[\s\S]*value="auto_allow" selected/);
 env.run('showPolicy()');assert.match(env.element('#modal-content').innerHTML,/Specific endpoints by IP or name/);
 const form=renderedForm(env,'policy-form',{name:'Exact Billing endpoint',target_type:'endpoints',target_endpoints:['host-1'],mode:'enforce'});
 form.querySelectorAll=selector=>selector==='.rule-row'?[policyRow({rule_type:'port',rule_port:'8443',rule_protocol:'tcp',rule_sources:'192.0.2.10',rule_selector:'',rule_location_id:''})]:[];
 await submitRendered(env,form);
 const request=mutations(env)[0],body=JSON.parse(request.options.body);
 assert.equal(request.url,'/api/v1/policies');assert.deepEqual(body.endpoint_ids,['host-1']);assert.deepEqual(body.selector,{});assert.deepEqual(body.group_ids,[]);assertCookieMutation(request);
});
test('Traffic discovery reports typed rate and retention with CSV access and no policy actions',async()=>{
 const data=evidencePage(),row={...data.rows[0],capture_kind:'accepted_connection',count_unit:'connections',peak_observed_per_second:37,rate_window_seconds:1,rate_is_lower_bound:true};
 const env=await workspace('traffic',{mode:'entra',role:'admin',responses:{'/api/v1/learning/session-1/recommendations?limit=200&offset=0':{...data,purpose:'traffic',rows:[row],evidence_expires_at:'2026-12-20T00:00:00Z'}}});
 assert.match(env.element('#learn-button').innerHTML,/Discover traffic/);
 await env.click('recommendation-open',{id:'session-1',purpose:'traffic'});
 assert.equal(env.element('#modal-title').textContent,'Traffic discovery observations');
 const html=env.element('#modal-content').innerHTML;
 assert.match(html,/37 connections\/s/);assert.match(html,/retention ends/);assert.match(html,/Export CSV/);
 assert.doesNotMatch(html,/recommendation-form|recommendation-apply|Preview selected access/);
 assert.equal(mutations(env).length,0);
});

test('Discover traffic sends sampled by default and requires an explicit opt-in to count hits on older agents',async()=>{
 for(const supported of [false,true]){
  const server={...host,capabilities:[...host.capabilities,...(supported?['traffic_minute_sampling_v1']:[])]};
  const env=await workspace('traffic',{mode:'entra',role:'admin',responses:{'/api/v1/overview':{...fixture,servers:[server]}}});
  await env.click('discover-traffic');
  const form=renderedForm(env,'learning-form',{server_ids:[server.id],purpose:'traffic',duration:'1',unit:'3600'});
  await submitRendered(env,form);
  if(!supported){
   assert.equal(mutations(env).length,0);
   assert.match(env.element('#form-error').textContent,/Communication sampling requires updated agents/);
   form.values.traffic_hit_count='on';
   await submitRendered(env,form);
  }
  const [request]=mutations(env);
  assert.equal(request.url,'/api/v1/learning');
  assert.equal(JSON.parse(request.options.body).traffic_collection_mode,supported?'sampled':'hits');
 }
});

test('sampled traffic discovery observations display communication samples without a peak rate column',async()=>{
 const data=evidencePage(),row={...data.rows[0],capture_kind:'accepted_connection',count_unit:'sample_minutes',count:3};
 const env=await workspace('traffic',{responses:{'/api/v1/learning/session-1/recommendations?limit=200&offset=0':{...data,purpose:'traffic',traffic_collection_mode:'sampled',rows:[row]}}});
 await env.click('recommendation-open',{id:'session-1',purpose:'traffic'});
 const html=env.element('#modal-content').innerHTML;
 assert.match(html,/one communication sample per source and destination service per minute/);
 assert.match(html,/3<small>communication samples<\/small>/);
 assert.doesNotMatch(html,/Peak observed rate|connections\/s/);
});

test('certificate source has two choices and generation defaults to saved cluster and node details', async () => {
 const current = {
  subject: 'CN=controller-label',
  issuer: 'CN=Existing CA',
  common_name: 'controller-label',
  organization: 'Network & Cloud',
  organizational_unit: 'Operations',
  sans: ['prthak.example.test', '10.241.10.11', '10.241.10.11', 'old.example.test']
 };
 const env = await applianceWorkspace({
  '/api/v1/platform/certificates': {current, hostname: 'old.example.test', generation_issuer: 'existing_local_issuer'},
  'POST /api/v1/platform/certificates/preview': applianceReview({summary: {certificate: current}})
 });
 await env.click('platform-tab', {tab: 'certificates'});
 await new Promise(setImmediate);
 const html = env.element('#view-content').innerHTML;
 assert.match(html, />Reload details<\/button>/);
 const source = html.match(/<select id="platform-certificate-mode"[\s\S]*?<\/select>/)[0];
 assert.deepEqual([...source.matchAll(/<option value="([^"]+)"/g)].map(([, value]) => value), ['ca_signed', 'self_signed']);
 assert.match(html, /name="subject_common_name" value="prthak.example.test"/);
 assert.match(html, /name="subject_organization" value="Production cluster"/);
 assert.match(html, /name="subject_organizational_unit" value="Noida"/);
 assert.match(html, /name="hostname" value="prthak.example.test"/);
 assert.match(html, /name="sans"[^>]*>old\.example\.test\n10\.241\.10\.11<\/textarea>/);
 assert.match(html, /configured local CA signs the replacement/);

 env.run('platformCertificateChange({target:{id:"platform-certificate-mode",value:"self_signed"}})');
 assert.equal(env.element('#certificate-self-signed-fields').hidden, false);
 assert.equal(env.element('#certificate-ca-signed-fields').hidden, true);
 assert.equal(mutations(env).length, 0);
 const formWithEditedValues = renderedForm(env, 'platform-certificate-form', {
   mode: 'self_signed',
   hostname: 'prthak.example.test',
   subject_common_name: 'Edited label',
   subject_organization: 'Network & Cloud',
   subject_organizational_unit: 'Operations',
   sans: '10.241.10.11, controller-pune.example.test'
 });
 await submitRendered(env, formWithEditedValues);
 const [request] = mutations(env);
 assert.equal(request.url, '/api/v1/platform/certificates/preview');
 assert.deepEqual(JSON.parse(request.options.body), {
  mode: 'self_signed',
  hostname: 'prthak.example.test',
  subject_common_name: 'Edited label',
  subject_organization: 'Network & Cloud',
  subject_organizational_unit: 'Operations',
  sans: ['10.241.10.11', 'controller-pune.example.test']
 });
 assertCookieMutation(request);
 assert.match(env.element('#modal-content').innerHTML, /CN=Existing CA/);
 assert.equal(mutations(env).length, 1);
});

const agentUpgradeAPI = '/api/v1/platform/agent-upgrades';
const agentUpgradeId = 'd'.repeat(32);
const agentUpgradeVersion = '0.19.0';
const agentUpgradeTarget = {server_id: 'host-1', hostname: 'api <one>', previous_version: '0.18.5', architecture: 'amd64', status: 'queued'};
const agentUpgradeReview = overrides => ({
  id: agentUpgradeId, version: agentUpgradeVersion, digest: 'e'.repeat(64), status: 'reviewed',
  created_at: new Date().toISOString(), expires_at: new Date(Date.now() + 60000).toISOString(),
  target_count: 1, targets: [agentUpgradeTarget], exclusions: [], outcomes: {}, can_apply: true, ...overrides,
});
const agentUpgradeIndex = rollouts => ({capability: 'agent_pull_upgrade_v1', releases: [{
  version: agentUpgradeVersion, architectures: {amd64: {bytes: 1234, sha256: 'a'.repeat(64)}},
}], rollouts});

test('Agent upgrades review exact enrolled targets and send only the reviewed digest when explicitly scheduled', async () => {
  const review = agentUpgradeReview({exclusions: [{server_id: 'host-2', hostname: 'legacy <two>', reason: 'Updater required'}]});
  let active = null;
  let finishScheduling;
  const scheduling = new Promise(resolve => { finishScheduling = resolve; });
  const env = await workspace('settings', {mode: 'entra', responses: {
    [agentUpgradeAPI]: () => agentUpgradeIndex(active ? [active] : [review]),
    ['POST ' + agentUpgradeAPI + '/preview']: review,
    ['POST ' + agentUpgradeAPI + '/' + agentUpgradeId + '/confirm']: async () => {
      await scheduling;
      return active = {...review, status: 'completed', can_apply: false, confirmed_at: new Date().toISOString(), outcomes: {applied: 1},
        targets: [{...agentUpgradeTarget, status: 'applied', reported_version: agentUpgradeVersion}]};
    },
    [agentUpgradeAPI + '/' + agentUpgradeId]: () => active,
  }});
  await env.click('platform-tab', {tab: 'agent-upgrades'});
  await new Promise(setImmediate);
  const html = env.element('#view-content').innerHTML;
  assert.match(html, /Agents begin only after a Super Admin schedules/);
  assert.match(html, /0\.19\.0 · amd64/);
  assert.doesNotMatch(html, /View outcomes/);
  const form = renderedForm(env, 'platform-agent-upgrade-scope-form', {
    version: agentUpgradeVersion, scope: 'endpoints', upgrade_endpoint_ids: ['host-1', 'host-1'], tags: 'ignored=value',
  });
  await submitRendered(env, form);
  const modal = env.element('#modal-content').innerHTML;
  assert.match(modal, /api &lt;one&gt;/);
  assert.match(modal, /legacy &lt;two&gt;/);
  assert.match(modal, /Updater required/);
  assert.match(modal, /Schedule upgrade/);
  assert.doesNotMatch(modal, /confirmation_phrase/);
  let writes = mutations(env).filter(request => request.url.startsWith(agentUpgradeAPI));
  assert.deepEqual(writes.map(request => request.url), [agentUpgradeAPI + '/preview']);
  assert.deepEqual(JSON.parse(writes[0].options.body), {version: agentUpgradeVersion, server_ids: ['host-1']});
  assertCookieMutation(writes[0]);
  const confirmation = renderedForm(env, 'platform-agent-upgrade-confirm-form');
  const first = submitRendered(env, confirmation);
  await submitRendered(env, confirmation);
  finishScheduling();
  await first;
  writes = mutations(env).filter(request => request.url.startsWith(agentUpgradeAPI));
  assert.deepEqual(writes.map(request => request.url), [agentUpgradeAPI + '/preview', agentUpgradeAPI + '/' + agentUpgradeId + '/confirm']);
  assert.deepEqual(JSON.parse(writes[1].options.body), {digest: review.digest});
  assertCookieMutation(writes[1]);
  const history = env.element('#view-content').innerHTML;
  assert.match(history, /Endpoint outcomes/);
  assert.match(history, /Applied/);
  assert.match(history, /Reported version/);
});

test('Agent upgrades scope by tags or saved location and skip the schedule action for an empty or expired review', async () => {
  const cases = [
    {
      fields: {scope: 'tags', tags: 'application=billing, owner=finance', upgrade_endpoint_ids: ['ignored']},
      selector: {application: 'billing', owner: 'finance'},
      plan: agentUpgradeReview({can_apply: false, target_count: 0, targets: []}),
    },
    {
      fields: {scope: 'location', location_id: location.id},
      selector: {location_id: location.id},
      plan: agentUpgradeReview({expires_at: new Date(Date.now() - 1000).toISOString()}),
    },
  ];
  for (const {fields, selector, plan} of cases) {
    const env = await workspace('settings', {mode: 'entra', responses: {
      [agentUpgradeAPI]: agentUpgradeIndex([]),
      ['POST ' + agentUpgradeAPI + '/preview']: plan,
    }});
    await env.click('platform-tab', {tab: 'agent-upgrades'});
    await new Promise(setImmediate);
    await submitRendered(env, renderedForm(env, 'platform-agent-upgrade-scope-form', {version: agentUpgradeVersion, ...fields}));
    assert.match(env.element('#modal-title').textContent, /Review agent upgrade/);
    assert.doesNotMatch(env.element('#modal-content').innerHTML, /Schedule upgrade/);
    const writes = mutations(env).filter(request => request.url.startsWith(agentUpgradeAPI));
    assert.deepEqual(writes.map(request => JSON.parse(request.options.body)), [{version: agentUpgradeVersion, selector}]);
  }
});

test('Agent upgrades withhold scheduling from demo, token and non-Super Admin identities', async () => {
  for (const options of [{mode:'demo'}, {mode:'tokens'}, {mode:'entra',role:'admin'}]) {
    const env = await workspace('settings', options);
    await env.click('platform-tab', {tab: 'agent-upgrades'});
    await env.click('platform-agent-upgrades-refresh');
    assert.doesNotMatch(env.element('#view-content').innerHTML, /platform-agent-upgrade-scope-form/);
    assert.equal(env.requests.some(request => request.url.startsWith(agentUpgradeAPI)), false);
  }
});
