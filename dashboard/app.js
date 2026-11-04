'use strict';

const icons = {
  settings:'<path d="M9 3h6l1 3 3 1v6l-3 1-1 3H9l-1-3-3-1V7l3-1 1-3Z"/><circle cx="12" cy="10" r="3"/>',
  access:'<circle cx="9" cy="8" r="3"/><path d="M3 21v-3a6 6 0 0 1 12 0v3m3-14 3 2v4c0 3-3 5-3 5s-3-2-3-5V9l3-2Z"/>',
  locations:'<path d="M4 21V7l8-4 8 4v14M2 21h20M8 9h.01M16 9h.01M8 13h.01M16 13h.01M10 21v-5h4v5"/>',
  cloud:'<path d="M7 18a5 5 0 0 1-1-10 6.5 6.5 0 0 1 12 1 4.5 4.5 0 0 1-1 9H7Z"/>',
  services:'<path d="M4 6h16M4 12h16M4 18h16"/><circle cx="8" cy="6" r="2"/><circle cx="16" cy="12" r="2"/><circle cx="10" cy="18" r="2"/>',
  firewall:'<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 9h18M3 14h18M9 4v5M15 9v5M9 14v6"/>',
  filter:'<path d="M4 7h16M7 12h10M10 17h4"/>',
  overview: '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
  servers: '<rect x="3" y="3" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="7" rx="2"/><path d="M7 6.5h.01M7 17.5h.01M15 6.5h3M15 17.5h3"/>',
  policies: '<path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6l8-3Z"/><path d="m8.5 11.5 2.5 2.5 4.5-5"/>',
  traffic: '<path d="M3 6h15m-4-4 4 4-4 4M21 18H6m4-4-4 4 4 4"/>',
  alerts: '<path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9M10 21h4"/>',
  activity: '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  refresh: '<path d="M20 7v5h-5M4 17v-5h5"/><path d="M6.1 6a8 8 0 0 1 13 2M4.9 16a8 8 0 0 0 13 2"/>',
  search: '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 4 4"/>',
  learning: '<path d="M9 3h6M10 3v6l-6 10a1.3 1.3 0 0 0 1.2 2h13.6a1.3 1.3 0 0 0 1.2-2L14 9V3M7 15h10"/>',
  setup: '<path d="m8 7-5 5 5 5m8-10 5 5-5 5m-3-14-2 18"/>',
  arrow: '<path d="M5 12h14m-5-5 5 5-5 5"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7h.01"/>',
  check: '<path d="m5 12 4 4L19 6"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  link: '<path d="m10 13 4-4m-6 6-2 2a4 4 0 0 1-6-6l4-4a4 4 0 0 1 6 0m4 2 2-2a4 4 0 0 1 6 6l-4 4a4 4 0 0 1-6 0"/>',
  warning: '<path d="m12 3 10 18H2L12 3Z"/><path d="M12 9v5M12 17h.01"/>'
};
const icon = name => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${icons[name] || icons.info}</svg>`;
const h = value => String(value ?? '').replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const num = value => Number.isFinite(Number(value)) ? Number(value) : 0;
const format = value => new Intl.NumberFormat('en-US').format(num(value));
const date = value => {if(value===null||value===undefined||value==='')return null;const d = new Date(value); return Number.isNaN(d.getTime()) ? null : d;};
const timestamp = value => date(value)?.toLocaleString([], {month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'}) || 'Not reported';
const age = value => {const d = date(value); if (!d) return 'Not reported'; const seconds = Math.max(0,(Date.now()-d.getTime())/1000); return seconds<60?'Just now':seconds<3600?`${Math.floor(seconds/60)}m ago`:seconds<86400?`${Math.floor(seconds/3600)}h ago`:`${Math.floor(seconds/86400)}d ago`;};
const compact = value => num(value)>=1000000?`${(num(value)/1000000).toFixed(1)}m`:num(value)>=1000?`${(num(value)/1000).toFixed(1)}k`:format(value);
const views = {overview:['Overview','Network overview','Endpoint health, discovered services and observed communication across your sites.'],servers:['Servers','Server inventory','Discovered services, endpoint health, and applied policy.'],locations:['Locations','Location catalogue','Manage data centres and cloud locations. Each endpoint has one assignment.'],services:['Service groups','Reusable service groups','Name exact TCP and UDP ports once, then reuse them in access policies.'],firewall:['Firewall','Firewall services','Check firewalld status and start the service after an endpoint assessment.'],policies:['Policies','Access policies','Define which sources can reach each service.'],risk:['Risk & compliance','Risk & compliance','Review risky listeners and source-backed regulatory mappings.'],traffic:['Traffic','Traffic','See which sources hit your service ports.'],alerts:['Alerts','Health & alerts','Service changes, stale endpoints, and policy drift.'],activity:['Activity','Workspace activity','An audit trail of policy and workspace changes.'],settings:['Platform settings','Platform settings','Manage platform data, backups and deployment availability.'],access:['Users & access','Users & access','Manage local accounts, organisation SSO and workspace roles.']};
const F = globalThis.PSegraFilters;
const R = globalThis.PrithakRoutes;
const D = globalThis.PrithakServices;
const L = globalThis.PrithakLocations;
const W = globalThis.PrithakFirewall;
const M = globalThis.PrithakManaged;
const scopeStorageKey='prithak-scope-v1';
function restoreScope(){const restored={search:'',filters:F.empty(),flowServer:'all',window:3600,alertIncludeResolved:false};try{const saved=JSON.parse(sessionStorage.getItem(scopeStorageKey)||'null');if(!saved||typeof saved!=='object')return restored;for(const category of F.categories)if(Array.isArray(saved.filters?.[category]))restored.filters[category]=saved.filters[category].filter(value=>typeof value==='string'&&value.length<=(category==='locations'?1024:128)).slice(0,64);if(Array.isArray(saved.filters?.ports))restored.filters.ports=F.parsePorts(saved.filters.ports.join(','));for(const [key,values]of Object.entries(saved.filters?.custom||{}).slice(0,32)){if(/^[A-Za-z][A-Za-z0-9_.-]{0,63}$/.test(key)&&Array.isArray(values))restored.filters.custom[key]=values.filter(value=>typeof value==='string'&&value.length<=128).slice(0,64);}if(typeof saved.search==='string')restored.search=saved.search.slice(0,256);if(typeof saved.flowServer==='string')restored.flowServer=saved.flowServer.slice(0,128);if([3600,21600,86400].includes(Number(saved.window)))restored.window=Number(saved.window);restored.alertIncludeResolved=!!saved.alertIncludeResolved;}catch{}return restored;}
function persistScope(){try{sessionStorage.setItem(scopeStorageKey,JSON.stringify({search:state.search,filters:state.filters,flowServer:state.flowServer,window:state.window,alertIncludeResolved:state.alertIncludeResolved}));}catch{}}
function showWorkspaceView(view, advancedControls = false) {
  const changed = state.view !== view;
  if (changed) {
    if ($('#modal').open) closeModal();
    if (state.view === 'settings') platformClearDraft();
    if (state.view === 'traffic') state.trafficLearningSessionsOpen = false;
    closeDrawer();
    closeAccountMenu();
    state.filtersOpen = view !== 'overview';
  }
  state.view = view;
  state.networkControlOpen = advancedControls;
  openWorkspaceAfterSignIn();
  render();
  if (changed) {
    window.scrollTo(0, 0);
    $('#main').focus({preventScroll: true});
  }
  if (advancedControls) $('#advanced-network-controls')?.scrollIntoView?.({block: 'start'});
  refreshWorkspaceView();
}

function navigate(view, advancedControls = false) {
  if (state.passwordChangeRequired) return showLocalPasswordChange(true);
  if (!state.authType || !state.data || !R.pages.includes(view)) return;
  const url = advancedControls ? R.advancedPoliciesHref : R.href(view);
  if (location.pathname.replace(/\/$/, '') + location.search !== url || location.hash) {
    history.pushState(null, '', url);
  }
  showWorkspaceView(view, advancedControls);
}

function handleWorkspaceLink(event) {
  if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
  if (!state.authType || !state.data || $('#workspace-shell').hidden) return;
  const link = event.target.closest('a[href]');
  if (!link || (link.target && link.target !== '_self') || link.hasAttribute('download')) return;
  const url = new URL(link.href);
  const view = R.viewFromPath(url.pathname);
  const advancedControls = view === 'policies' && R.advancedPolicies(url.pathname, url.search);
  if (url.origin !== location.origin || url.hash || (!advancedControls && (url.pathname !== R.href(view) || url.search))) return;
  event.preventDefault();
  navigate(view, advancedControls);
}

function restoreWorkspaceView() {
  const view = signInReturnView();
  const advancedControls = R.advancedPolicies(location.pathname, location.search);
  state.networkControlOpen = advancedControls;
  if (state.passwordChangeRequired) {
    state.view = view;
    return showLocalPasswordChange(true);
  }
  if (!$('#workspace-connection').hidden) {
    state.view = view;
    return;
  }
  if (!state.authType) return showLogin();
  if (!state.data) {
    state.view = view;
    return load({quiet: true});
  }
  showWorkspaceView(view, advancedControls);
}
function migrateLegacyHash(){const destination=R.legacyDestination(location.pathname,location.hash,location.search);if(destination){persistScope();location.replace(destination);return true;}return false;}
const restoredScope=restoreScope();
const state = {policyTab:['policies','rollouts','default-deny'].includes(sessionStorage.getItem('prithak-policy-tab'))?sessionStorage.getItem('prithak-policy-tab'):'policies',data:null,filtersOpen:R.viewFromPath(location.pathname)!=='overview',cluster:null,clusterError:false,firewallData:null,firewallError:'',firewallLoading:false,firewallSnapshots:{},firewallSnapshotErrors:{},drawerTab:'services',detailData:null,activeFirewallPlan:null,view:R.viewFromPath(location.pathname),search:restoredScope.search,filters:restoredScope.filters,alertIncludeResolved:restoredScope.alertIncludeResolved,flowServer:restoredScope.flowServer,window:restoredScope.window,role:'read_only',user:null,authType:null,authProvider:'',passwordChangeRequired:false,csrfToken:'',authConfig:null,authError:'',accessUsers:[],accessError:'',accessLoaded:false,accessLoading:false,reservations:[],reservationsLoaded:false,reservationsLoading:false,token:sessionStorage.getItem('segment-token') || '',lastSync:null,activity:[],detail:null,polling:false};

if(state.view==='settings'&&/[?&]setup=(?:verified|failed)(?:&|$)/.test(location.search||''))state.platformTab='setup';
state.networkControlOpen = R.advancedPolicies(location.pathname, location.search);

async function api(path, options={}) {
  const {rawBody, ...requestOptions} = options;
  const mutation=['POST','PUT','PATCH','DELETE'].includes(String(options.method || 'GET').toUpperCase());
  const readOnlyQuery=String(options.method || 'GET').toUpperCase()==='POST'&&(/^[\/]policies[\/][A-Za-z0-9_.-]{1,100}[\/]impact$/.test(path)||['/firewall/query','/policies/query','/learning-policies/query','/policy-rollouts/query','/host-default-deny/query','/alerts/query','/flows/query','/flows/export.csv','/audit/query','/audit/export.csv','/servers/export.csv','/policies/export.csv','/source-banks/query','/firewall-activation/query'].includes(path));
  if(state.passwordChangeRequired&&!['/auth','/auth/config','/auth/password','/auth/logout'].includes(path))throw new Error('Change your temporary password before using the workspace.');
  if(mutation&&!readOnlyQuery&&!['/auth/logout','/auth/local','/auth/password'].includes(path)){
    if(path.startsWith('/platform/')&&!canManagePlatform())throw new Error('Only Super Admins can change platform settings.');
    if(path.startsWith('/access/')&&!canManageUsers())throw new Error('Only Super Admins can manage workspace users.');
    if(!canWrite())throw new Error('Read Only access cannot change the workspace.');
  }
  const headers = {'Accept':'application/json',...options.headers};
  if (state.token && state.authConfig?.mode==='tokens') headers.Authorization = `Bearer ${state.token}`;
  if (mutation && state.authType==='session') {
    if(!state.csrfToken)throw new Error('Your session needs a fresh sign-in before this request.');
    headers['X-CSRF-Token']=state.csrfToken;
  }
  if (options.body !== undefined) headers['Content-Type'] = 'application/json';
  if (rawBody !== undefined) headers['Content-Type'] = 'application/octet-stream';
  const controller = new AbortController();
  const timeout = setTimeout(()=>controller.abort(),20000);
  try {
    const response = await fetch(`/api/v1${path}`, {...requestOptions,credentials:'same-origin',headers,body:rawBody===undefined?(options.body===undefined?undefined:JSON.stringify(options.body)):rawBody,signal:controller.signal});
    if (options.download && response.ok) {
      if (response.headers.get('Content-Type')!=='application/octet-stream') throw new Error('The controller did not return a download.');
      return await response.blob();
    }
    if (options.csv && response.ok) {
      if (response.headers.get('Content-Type')?.split(';')[0] !== 'text/csv') throw new Error('The controller did not return a CSV file.');
      const blob = await response.blob();
      if (blob.size > 64 * 1024 * 1024) throw new Error('The CSV exceeds the browser download limit.');
      return blob;
    }
    const result = response.status===204 ? {} : await response.json().catch(()=>({}));
    if (!response.ok) {if(response.status===403&&result.code==='password_change_required'){state.passwordChangeRequired=true;state.authProvider='local';state.data=null;if(typeof showLocalPasswordChange==='function')showLocalPasswordChange(true);}const error = new Error(result.error || result.message || `Request failed (${response.status})`);error.status=response.status;error.payload=result;throw error;}
    return result;
  } finally {clearTimeout(timeout);}
}
function workspaceCSVIdentity(){return JSON.stringify([state.authType,state.role,state.user?.id,state.user?.tenant_id,state.token]);}
async function downloadWorkspaceCSV(path,filename,body,scope){
  if(!state.authType)return;
  const scopeAtClick=scope(),identity=workspaceCSVIdentity(),view=state.view;
  const current=()=>state.data&&state.view===view&&workspaceCSVIdentity()===identity&&scope()===scopeAtClick;
  try{
    const blob=await api(path,{method:'POST',body,csv:true,headers:{Accept:'text/csv'}});
    if(!current())return;
    const url=URL.createObjectURL(blob),link=document.createElement('a');
    try{link.href=url;link.download=filename;link.click();}
    finally{setTimeout(()=>URL.revokeObjectURL(url),1000);}
  }catch(error){if(current())toast(error.message,true);}
}
function toast(message, error=false) {const item=document.createElement('div');item.className=`toast${error?' error':''}`;item.textContent=message;$('#toasts').append(item);setTimeout(()=>item.remove(),5000);}
function badge(label,kind=''){return `<span class="badge ${h(kind)}"><i></i>${h(label)}</span>`;}
function serverName(id){return state.data?.servers.find(server=>server.id===id)?.hostname || id || 'Endpoint';}
function serverHealth(server){return server.status==='offline'?badge('Offline','danger'):server.status==='warning'?badge('Attention','warning'):badge('Healthy');}
function networkControlStatusHTML(server,details=false){
  const receipt=server.network_control;if(!receipt)return '';
  const quarantine=receipt.quarantine||{},egress=receipt.egress||{},parts=[];
  if(quarantine.expiry_unconfirmed||quarantine.status==='expiry_unconfirmed')parts.push(badge('Quarantine expiry unconfirmed','warning'));
  else if(quarantine.active===true||quarantine.status==='quarantined')parts.push(badge((receipt.stale||quarantine.stale||quarantine.unverified)?'Quarantine · unverified receipt':'Quarantined','danger'));
  const quarantineOutcome=quarantine.last_operation_status||quarantine.status;
  if(['error','rolled_back','blocked'].includes(quarantineOutcome))parts.push(badge('Quarantine '+humanize(quarantineOutcome),'warning'));
  if(egress.active===true||egress.status==='enforced')parts.push(badge((receipt.stale||egress.stale||egress.unverified)?'Outbound · stale receipt':'Outbound applied',(receipt.stale||egress.stale||egress.unverified)?'warning':'neutral'));
  const egressOutcome=egress.last_operation_status||egress.status;
  if(['error','rolled_back','blocked'].includes(egressOutcome))parts.push(badge('Outbound '+humanize(egressOutcome),'warning'));
  if(!details)return parts.length?'<div class="tag-row">'+parts.join('')+'</div>':'';
  return '<div class="detail-heading">Network controls<a class="text-button" href="'+R.advancedPoliciesHref+'">Review operations</a></div><div class="tag-row">'+(parts.join('')||badge('No active network control reported','neutral'))+'</div><p class="help-text">Last native check: '+h(timestamp(receipt.checked_at))+(receipt.stale||quarantine.unverified||egress.unverified?' · Retained active state is unverified; current enforcement is unconfirmed.':'')+(quarantine.expires_at?' · Quarantine expiry: '+h(timestamp(quarantine.expires_at)):'')+'</p>'+[quarantine.error,egress.error].filter(Boolean).map(error=>'<p class="form-error">'+h(error)+'</p>').join('');
}
function firewallMaintenanceSummaryHTML(server){
  const receipt=server.firewall_activation;if(!receipt)return '';
  return '<div class="detail-heading">Firewall maintenance</div><p>'+badge(humanize(receipt.status||'unknown'),['error','rolled_back','blocked'].includes(receipt.status)?'warning':'neutral')+' '+h(humanize(receipt.target_operation||receipt.operation||''))+'</p><p class="help-text">Native receipt: '+h(timestamp(receipt.checked_at))+'</p>'+(receipt.error?'<p class="form-error">'+h(receipt.error)+'</p>':'');
}
function activeSessions(){return (state.data?.learning_sessions || []).filter(session=>['active','learning'].includes(session.status) && num(date(session.expires_at)?.getTime())>Date.now());}
function listenerChip(listener){const metadata=[D.application(listener),listener.systemd_unit?`Unit: ${listener.systemd_unit}`:'',listener.first_seen?`First observed: ${timestamp(listener.first_seen)}`:''].filter(Boolean).join(' · ');return `<span class="service-pill ${listener.is_new?'new-service':''}" title="${h(metadata)}">${h(D.label(listener))}${listener.is_new?`<span class="new-service-label">${listener.change_kind==='changed'?'Changed':'New'}</span>`:''}</span>`;}
function listenerDetailsHTML(listener,server){const stale=server.status==='offline'||['stale','error','unknown'].includes(server.discovery_status);return `<div class="detail-service ${listener.is_new?'new-service-row':''}"><span class="server-icon">${icon('link')}</span><div class="detail-service-content"><strong>${h(D.label(listener))}</strong>${riskyPortBadge(server,listener)}<small>Application: ${h(D.application(listener))}</small><small>Process: ${h(listener.process||'Not reported')}${listener.pid?' · PID '+num(listener.pid):''}${listener.systemd_unit?' · Unit: '+h(listener.systemd_unit):''}</small><small>Bind address: ${h(listener.address||'*')}${listener.first_seen?' · First seen '+h(timestamp(listener.first_seen)):''}${listener.last_seen?' · Last seen '+h(timestamp(listener.last_seen)):''}</small></div>${badge(listener.is_new?(listener.change_kind==='changed'?'Changed':'New'):stale?'Last observed':'Listening',listener.is_new?'learning':stale?'neutral':'')}</div>`;}
function discoveryChangesHTML(server){const changes=server.discovery_changes||[];if(!changes.length)return '';return `<div class="detail-heading">Latest discovery changes<span class="host-os">${changes.length} changes</span></div><div class="discovery-change-list">${changes.map(change=>`<div class="discovery-change"><span class="badge ${change.kind==='removed'?'neutral':'learning'}">${h(humanize(change.kind||'Changed'))}</span><div><strong>${h(D.label(change))}</strong><small>${h(D.application(change))}${change.detected_at?' · '+h(timestamp(change.detected_at)):''}</small></div></div>`).join('')}</div>`;}
function alertServiceDetailsHTML(alert){const raw=alert.details||alert.detail;if(!raw||typeof raw!=='object')return '';const listener=raw.listener||raw.service_details||raw;if(!listener.port)return '';return `<div class="alert-service-detail"><strong>${h(D.label(listener))}</strong><span>${h(D.application(listener))}${listener.process?' · Process: '+h(listener.process):''}${listener.systemd_unit?' · Unit: '+h(listener.systemd_unit):''}</span>${listener.first_seen?`<span>First observed ${h(timestamp(listener.first_seen))}</span>`:''}</div>`;}
function discoveryTimingHTML(server){
  const fast=server.fast_discovery,states={active:'Active',unsupported:'Unavailable on this kernel',error:'Check failed',off:'Off'};
  const checks=fast?`${server.status==='offline'?'Last reported: ':''}${h(states[fast.status]||'Unknown')} · every ${num(fast.interval_seconds)} seconds`:'Not reported; using full inventory scans';
  return `<div><dt>Service discovery</dt><dd>${h(humanize(server.discovery_status||'unknown'))}</dd></div><div><dt>Control interval</dt><dd>${num(server.control_interval_seconds||60)} seconds</dd></div><div><dt>Heartbeat timeout</dt><dd>${num(server.heartbeat_timeout_seconds||180)} seconds</dd></div><div><dt>Full inventory fallback</dt><dd>${Math.round(num(server.discovery_interval_seconds||900)/60)} minutes</dd></div><div><dt>Last listener inventory</dt><dd>${server.last_discovery_at?h(timestamp(server.last_discovery_at)):'Not reported'}</dd></div><div><dt>Inventory freshness deadline</dt><dd>${server.next_discovery_at?h(timestamp(server.next_discovery_at)):'Not reported'}</dd></div><div><dt>Listener change checks</dt><dd>${checks}${fast?.checked_at?`<small>Last check: ${h(timestamp(fast.checked_at))}</small>`:''}${fast?.last_change_at?`<small>Last change: ${h(timestamp(fast.last_change_at))}</small>`:''}${fast?.error?`<small>${h(fast.error)}</small>`:''}</dd></div>`;
}
function hostPreparationHTML(server){
  const receipt=server.preparation_status;if(!receipt)return '';
  const active=value=>value===true?'Active':value===false?'Inactive':'Not verified';
  return `<div class="detail-heading">Installation preparation</div><dl class="detail-grid"><div><dt>Outcome</dt><dd>${h(humanize(receipt.status||'unknown'))}</dd></div><div><dt>Checked</dt><dd>${receipt.checked_at?h(timestamp(receipt.checked_at)):'Not reported'}</dd></div><div><dt>Dependencies changed</dt><dd>${receipt.dependencies_changed===true?'Yes':receipt.dependencies_changed===false?'No':'Not reported'}</dd></div><div><dt>UFW at preparation</dt><dd>${active(receipt.ufw?.active)}</dd></div><div><dt>firewalld at preparation</dt><dd>${active(receipt.firewalld?.active)}</dd></div><div><dt>UFW assessment</dt><dd>${h(humanize(receipt.ufw?.assessment||'not_requested'))}</dd></div></dl>${receipt.ufw?.migration_required?'<div class="inline-notice warning">UFW was preserved. Review its existing rules and plan migration before enabling firewalld enforcement.</div>':''}${receipt.ufw?.export_path?`<p class="help-text">Private export on the endpoint: <code>${h(receipt.ufw.export_path)}</code>. Rule contents stay on the server.</p>`:''}${receipt.error?`<div class="inline-notice warning">${h(receipt.error)}</div>`:''}`;
}

function currentPolicy(server){return F.policyStatus(server)==='current';}
function policyBadge(server){const status=F.policyStatus(server);return status==='current'?badge('Current'):managedBadge(status);}
function tagsHTML(tags={}, all=false){return Object.entries(tags).slice(0,all?100:3).map(([key,value],index)=>`<span class="tag ${['teal','','purple'][index%3]}" title="${h(key)}=${h(value)}">${h(all?`${key}=${value}`:value)}</span>`).join('') || '<span class="host-os">No tags</span>';}
function sessionTitle(session){const ids=session.server_ids || [];return session.name || (ids.length===1?serverName(ids[0]):`${num(session.server_count ?? ids.length)} endpoints`);}
function visibleFlows(){if(state.view==='traffic'&&trafficCatalogueEnabled())return trafficCataloguePage().items;const cutoff=Date.now()-state.window*1000;const servers=new Map((state.data?.servers||[]).map(server=>[server.id,server]));return (state.data?.flows||[]).filter(flow=>(state.flowServer==='all'||flow.server_id===state.flowServer)&&num(date(flow.last_seen)?.getTime())>=cutoff&&F.matchFlow(flow,servers.get(flow.server_id),state.filters,state.search));}
function canWrite(){return !state.passwordChangeRequired&&['admin','super_admin'].includes(state.role);}
function acknowledged(alert){return !!alert.acknowledged || alert.status==='acknowledged';}

const filterLabels={application:'Application',dc:'DC',network_zone:'Zone',criticality:'Criticality',os:'OS',status:'Health',policy_status:'Policy status',learning:'Learning',locations:'Location',groups:'Server group'};
const filterValueLabels={status:{healthy:'Healthy',warning:'Attention',offline:'Offline'},policy_status:{current:'Current',pending:'Pending',pending_approval:'Pending delivery',preview:'Preview',staging:'Staging runtime',runtime_healthchecking:'Checking runtime health',committing:'Committing permanent',rolled_back:'Rolled back',removed:'Managed rules removed',error:'Apply error'},learning:{collecting:'Collecting',assigned:'Assigned / pending',discovering:'Fresh discovery pending',discovery_error:'Discovery error',no_listeners:'No network listeners',stop_pending:'Stop requested',off:'Off',unknown:'Unknown / stale'}};
function filterLabel(category,value){if(category==='groups')return F.groupById(value)?.name || 'Unavailable group';if(category==='dc')return value===''?'Unassigned':L.find(value)?.name || value;if(category==='locations')return L.describe(value);if(value==='__no_match__')return 'No matches in current scope';if(value==='')return 'Unassigned';return filterValueLabels[category]?.[value] || value;}
function scopedSummary(){return F.summarize(state.data.servers.filter(server=>state.flowServer==='all'||server.id===state.flowServer),state.data.alerts,state.filters,state.search);}
function activeFilterCount(){return F.count(state.filters)+(state.search?1:0)+(state.flowServer!=='all'?1:0);}
function filterOptions(category){if(category==='groups')return [...new Set([...(state.data.groups||[]).map(group=>group.id),...state.filters.groups])].sort((a,b)=>filterLabel(category,a).localeCompare(filterLabel(category,b)));const values=new Set(category==='dc'?L.catalog().filter(record=>record.type==='datacenter').map(record=>record.id):[]);for(const server of state.data.servers){const value=category==='dc'?(L.of(server).kind==='datacenter'?server.location_id:undefined):F.tagCategories.includes(category)?server.tags?.[category]:category==='policy_status'?F.policyStatus(server):category==='learning'?F.learningStatus(server):server[category];if(value!==undefined&&value!=='')values.add(String(value));}for(const value of state.filters[category])values.add(value);return [...values].sort((a,b)=>a.localeCompare(b));}
function filterChipsHTML(){
  const chips=[];for(const category of F.categories)for(const value of state.filters[category])chips.push({category,value,label:`${filterLabels[category]}: ${filterLabel(category,value)}`});
  for(const value of state.filters.ports)chips.push({category:'ports',value,label:`Port: ${value}`});
  for(const [key,values] of Object.entries(state.filters.custom))for(const value of values)chips.push({category:'custom',key,value,label:`${key}=${value}`});
  if(state.search)chips.push({category:'search',value:state.search,label:`Search: ${state.search}`});
  if(state.flowServer!=='all')chips.push({category:'endpoint',value:state.flowServer,label:`Endpoint: ${serverName(state.flowServer)}`});
  return chips.map(chip=>`<button type="button" class="filter-chip" data-action="remove-filter" data-filter-category="${h(chip.category)}" data-filter-key="${h(chip.key||'')}" data-filter-value="${h(chip.value)}" aria-label="Remove ${h(chip.label)} filter"><span>${h(chip.label)}</span><span aria-hidden="true">×</span></button>`).join('');
}
function filterResultText(context){const count=filteredServers().length;if(context==='traffic'){if(trafficCatalogueEnabled())return trafficCatalogueResultText();const flows=visibleFlows();return `${format(flows.length)} relationships · ${format(new Set(flows.map(flow=>flow.server_id)).size)} endpoints`;}if(context==='firewall')return `${format(firewallRules().length)} common rules in selected scope`;if(context==='policies')return `${format(filteredPolicies().length)} managed policies ${policyCataloguePage('managed').remote?'on loaded page':'in selected scope'}`;if(context==='rollouts'){const rollouts=managedVisibleRollouts().length;return `${format(rollouts)} rollout${rollouts===1?'':'s'} · ${format(count)} matching endpoint${count===1?'':'s'}`;}if(context==='alerts'){return `${alertCatalogueCounts()?.matchedTotal===null?'…':format(alertCatalogueCounts()?.matchedTotal??filteredAlerts().length)} ${state.alertIncludeResolved?'alerts':'unresolved alerts'} · ${format(count)} matching endpoint${count===1?'':'s'}`;}return `${format(count)} of ${format(state.data.servers.length)} endpoint${state.data.servers.length===1?'':'s'}`;}
function locationFilterMenuHTML(label='Location'){return `<details class="filter-menu location-filter-menu" data-filter-menu="locations"><summary aria-label="Filter Location">${label==='Location'?icon('servers'):''}${h(label)}${state.filters.locations.length?`<span>${state.filters.locations.length}</span>`:''}<span class="filter-chevron" aria-hidden="true">⌄</span></summary><div class="filter-menu-options" role="group" aria-label="Location choices">${L.all(state.data.servers,true).map(location=>`<label><input type="checkbox" data-filter-category="locations" value="${h(location.key)}" ${state.filters.locations.some(key=>L.equivalent(key,location.key))?'checked':''} aria-label="Location: ${h(L.describe(location.key))}"><span>${h(location.label)}<small>${h(location.typeLabel)}${location.account?' · '+h(location.account):''} · ${location.members.length} host${location.members.length===1?'':'s'}</small></span></label>`).join('')||'<span class="help-text">No saved locations. Create a catalogue entry first.</span>'}<button class="text-button location-help-link" data-action="firewall-location-help">How locations are assigned</button></div></details>`;}
function filterMenuHTML(category,label=filterLabels[category]){return `<details class="filter-menu" data-filter-menu="${category}"><summary aria-label="Filter ${h(filterLabels[category])}">${h(label)}${state.filters[category].length?`<span>${state.filters[category].length}</span>`:''}<span class="filter-chevron" aria-hidden="true">⌄</span></summary><div class="filter-menu-options" role="group" aria-label="${h(filterLabels[category])} choices">${filterOptions(category).map(value=>`<label><input type="checkbox" data-filter-category="${category}" value="${h(value)}" ${state.filters[category].includes(value)?'checked':''} aria-label="${h(filterLabels[category])}: ${h(filterLabel(category,value))}"><span>${h(filterLabel(category,value))}</span></label>`).join('')||'<span class="help-text">No values reported.</span>'}</div></details>`;}
function filterBarHTML(context='inventory'){
  const active=activeFilterCount(),overview=context==='overview';return `<section class="scope-filter-bar ${overview?'overview-advanced-filters':''} ${state.filtersOpen?'filters-expanded':'filters-collapsed'}" aria-label="Combined ${context==='traffic'?'traffic':context==='alerts'?'alert':['policies','rollouts'].includes(context)?'policy':context==='firewall'?'firewall':'endpoint'} filters">${overview?'':`<div class="scope-search-row"><label class="search-field">${icon('search')}<input id="${context==='traffic'?'traffic-search':context==='alerts'?'alerts-search':context==='firewall'?'firewall-search':'server-search'}" type="search" value="${h(state.search)}" placeholder="Search servers, IPs, tags…" aria-label="Search ${context==='traffic'?'traffic':'servers'}"></label><span class="filter-result-count" id="filter-result-count">${filterResultText(context)}</span><button class="button secondary small scope-filter-toggle" type="button" data-action="toggle-filters" aria-expanded="${state.filtersOpen}" aria-controls="scope-filter-panel">${icon('filter')}Filters${active?`<span>${active}</span>`:''}</button></div>`}<div class="scope-filter-panel" id="scope-filter-panel" ${!state.filtersOpen?'hidden':''}><div class="scope-filter-controls">${overview?'':locationFilterMenuHTML()}${F.categories.filter(category=>category!=='locations'&&(!overview||category!=='application')).map(category=>filterMenuHTML(category)).join('')}<div class="filter-entry"><label class="sr-only" for="service-filter-input">Service port filter</label><input id="service-filter-input" placeholder="Port: 8443 or 8443/tcp" aria-label="Service port filter"><button type="button" data-action="add-port-filter" aria-label="Add service port filter">+</button></div><div class="filter-entry custom"><label class="sr-only" for="custom-tag-filter-input">Custom tag filter</label><input id="custom-tag-filter-input" placeholder="Custom: owner=finance" aria-label="Custom tag filter"><button type="button" data-action="add-custom-filter" aria-label="Add custom tag filter">+</button></div></div><p class="filter-hint">Combine categories with AND; values within a category use OR.${context==='traffic'?' Port filters match observed flow services, including historical listeners.':context==='policies'?' Port filters match policy services, independently of current listeners.':context==='rollouts'?' Port filters select endpoints by discovered listeners; each authorization covers its complete bundle.':context==='firewall'?' Port filters use imported rule ports and reported service definitions, independently of listeners.':''}</p></div><div class="filter-chip-row" id="filter-chip-row" ${!active?'hidden':''}><div id="active-filter-chips">${filterChipsHTML()}</div><button class="text-button" type="button" data-action="clear-filters">Clear all <span class="filter-active-count">(${active})</span></button></div><div id="filter-input-error" class="filter-validation" role="alert" hidden></div></section>`;
}
function controlPlaneHTML(){if(!state.cluster)return state.clusterError?'<section class="control-plane-strip is-unavailable"><span class="control-plane-title">Control plane</span><span>Status temporarily unavailable. Inventory remains available.</span></section>':'';const cluster=state.cluster;return `<section class="control-plane-strip" aria-label="Controller availability"><span class="control-plane-title">${icon('servers')}Control plane</span><strong>${cluster.mode==='active-active'?'Active-active':cluster.mode==='standalone'?'Standalone':'Mode not reported'}</strong><div class="cluster-node-list">${(cluster.nodes||[]).map(node=>`<span class="cluster-node ${node.status==='healthy'&&node.ready?'is-healthy':node.status==='offline'?'is-offline':'is-unavailable'}" title="${h(node.id)} · Last report ${h(timestamp(node.last_seen))}"><i></i>${h(node.site||node.id||'Unassigned site')}<small>${node.status==='healthy'&&node.ready?'Ready':node.status==='offline'?'Offline':node.status==='unavailable'?'Unavailable':'Not ready'}</small></span>`).join('')||'<span class="help-text">No controller node status reported.</span>'}</div></section>`;}
function refreshSearchResults(){const active=document.activeElement,id=active?.id,position=active?.selectionStart;render();const input=id?document.getElementById(id):null;input?.focus();if(position!==null&&position!==undefined)input?.setSelectionRange(position,position);}
function renderPreservingFilterFocus(){const active=document.activeElement;const focused=active?.dataset?.filterCategory?{category:active.dataset.filterCategory,value:active.value}:null;const menus=$$('.filter-menu[open]').map(menu=>menu.dataset.filterMenu);render();menus.forEach(category=>{const menu=$$('.filter-menu').find(item=>item.dataset.filterMenu===category);if(menu)menu.open=true;});if(focused)$$('input[data-filter-category]').find(input=>input.dataset.filterCategory===focused.category&&input.value===focused.value)?.focus();}
function applyFilterEntry(kind){const input=$(kind==='ports'?'#service-filter-input':'#custom-tag-filter-input');try{if(!input.value.trim())throw new Error(kind==='ports'?'Enter a service port, such as 8443/tcp.':'Enter a custom tag, such as owner=finance.');if(kind==='ports')for(const value of F.parsePorts(input.value))if(!state.filters.ports.includes(value))state.filters.ports.push(value);if(kind==='custom')F.addCustom(state.filters,input.value);render();$(kind==='ports'?'#service-filter-input':'#custom-tag-filter-input')?.focus();}catch(error){$('#filter-input-error').hidden=false;$('#filter-input-error').textContent=error.message;input.setAttribute('aria-invalid','true');}}
function scopedAlerts(includeResolved=false){const scopedById=new Map(state.data.servers.filter(server=>state.flowServer==='all'||server.id===state.flowServer).map(server=>[server.id,server]));return state.data.alerts.filter(alert=>(includeResolved||F.unresolved(alert))&&[alert.server_id,...(alert.kind==='possible_lateral_movement'&&Array.isArray(alert.details?.target_server_ids)?alert.details.target_server_ids:[])].some(id=>F.matchAlert(alert,scopedById.get(id),state.filters,state.search)));}
function filteredAlerts(){return scopedAlerts(state.alertIncludeResolved);}
function filteredPolicies(){const page=policyCataloguePage('managed');return page.remote?page.items:page.items.filter(policy=>F.policyScope(policy,state.data.servers,state.data.groups||[],state.filters,state.search,state.flowServer).matches);}
function topologyHTML(servers){
  const ids=new Set(servers.map(server=>server.id));
  const sessions=learningSessionPage();
  return `<div id="topology-root">${PSegraTopology.render({servers,inventory:state.data.servers,flows:visibleFlows().filter(flow=>ids.has(flow.server_id)),learningSessions:sessions.remote?sessions.items:state.data.learning_sessions, sessionsLimited:sessions.remote&&sessions.has_more})}</div>`;
}
function overviewQuickFiltersHTML(){
  const windows=[[3600,'Last hour'],[21600,'Last 6 hours'],[86400,'Last 24 hours']];
  return `${locationFilterMenuHTML(state.filters.locations.length?'Location':'All locations')}${filterMenuHTML('application',state.filters.application.length?'Application':'All applications')}
    <select id="overview-traffic-window" class="button secondary small" aria-label="Observed traffic window">${windows.map(([seconds,label])=>`<option value="${seconds}" ${state.window===seconds?'selected':''}>${label}</option>`).join('')}</select>
    <button type="button" class="button secondary small" data-action="toggle-filters" aria-expanded="${state.filtersOpen}" aria-controls="scope-filter-panel">${icon('filter')}<span class="sr-only">More </span>Filters</button>`;
}


function renderChrome(){
  const unack=state.alertGlobalCounts?.unacknowledged_count??(state.data?.alerts||[]).filter(alert=>!acknowledged(alert) && !alert.resolved_at && alert.status!=='resolved').length;
  const navigationViews=Object.entries(views).filter(([key])=>key!=='access');
  $('#navigation').innerHTML=navigationViews.map(([key,[label]])=>`<a class="nav-item ${state.view===key?'active':''}" href="/${key}" aria-label="${h(label)}" ${state.view===key?'aria-current="page"':''}><span>${icon(key)}</span><span>${h(label)}</span>${key==='alerts'&&unack?`<span class="nav-count">${unack}</span>`:''}</a>`).join('');
  $('#view-tabs').innerHTML=navigationViews.map(([key,[label]])=>`<a class="view-tab ${state.view===key?'active':''}" href="/${key}" aria-label="${h(label)}" ${state.view===key?'aria-current="page"':''}>${h(label)}</a>`).join('');
  $('#main').classList.toggle('overview-page',state.view==='overview');
  $('#overview-quick-filters').hidden=state.view!=='overview';
  document.title=`${views[state.view][0]} · Prṛthak`;$('#page-title').textContent=views[state.view][1];$('#page-description').textContent=views[state.view][2];
  $('#last-updated').textContent=state.lastSync?`Updated ${state.lastSync.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})}`:'Waiting for first sync';
  $('#demo-banner').hidden=state.authType!=='demo';
  const version = state.data?.meta?.version;
  $('#controller-version').textContent = version ? `v${version}` : '—';
  const controllerName = $('#controller-display-name');
  if (controllerName) {
    controllerName.textContent = state.data?.meta?.controller_display_name || 'Controller';
    controllerName.title = controllerName.textContent;
  }
  renderAccountMenu();
  renderPolicyDeploymentsChrome();
  $('#connection-label').textContent=state.lastSync?'Controller connected':'Connecting to controller';
  const createLabel = {policies: 'Create policy', locations: 'Create location', services: 'Create service group'}[state.view];
  const createButton = $('#enroll-button');
  createButton.innerHTML = createLabel ? icon('plus') + createLabel : '';
  createButton.hidden = !createLabel;
  createButton.disabled = !createLabel || !canWrite() || (state.view !== 'policies' && !['admin', 'super_admin'].includes(state.role));
  const learningLabel = {policies: 'Discover policy', traffic: 'Discover traffic'}[state.view];
  const learnButton = $('#learn-button');
  learnButton.innerHTML = learningLabel ? icon('learning') + learningLabel : '';
  learnButton.hidden = !learningLabel;
  learnButton.disabled = !learningLabel || !canWrite();
}

function statsHTML(){
  const summary=scopedSummary(),servers=summary.servers,healthy=servers.filter(server=>server.status==='healthy').length,current=summary.current.length,alerts=summary.alerts,critical=alerts.filter(alert=>['critical','high','error'].includes(alert.severity)).length,unack=alerts.filter(alert=>!acknowledged(alert)).length,alertCounts=alertCatalogueCounts(),alertTotal=alertCounts?alertCounts.total:alerts.length,alertCritical=alertCounts?alertCounts.critical:critical,alertUnack=alertCounts?alertCounts.unacknowledged:unack;
  return `<div class="stats-grid">
    <button type="button" class="stat-card stat-interactive" data-action="drilldown" data-scope="servers" aria-label="View ${servers.length} matching endpoint${servers.length===1?'':'s'}"><div class="stat-label">${activeFilterCount()?'Matching endpoints':'Managed endpoints'}${icon('servers')}</div><div class="stat-value">${format(servers.length)}</div><div class="metric-meter health" aria-hidden="true"><span style="width:${servers.length?healthy/servers.length*100:0}%"></span></div><div class="stat-note"><span class="dot"></span><span class="number">${format(healthy)} healthy</span><span>in selected scope</span><span class="stat-drill-arrow">↗</span></div></button>
    <button type="button" class="stat-card stat-interactive" data-action="drilldown" data-scope="current" aria-label="View ${current} policy-current endpoints"><div class="stat-label">Policy current${icon('policies')}</div><div class="stat-value">${servers.length?Math.round(current/servers.length*100):0}<span class="unit">%</span></div><div class="metric-meter" aria-hidden="true"><span style="width:${servers.length?current/servers.length*100:0}%"></span></div><div class="stat-note"><span class="dot ${current<servers.length?'amber':''}"></span>${format(current)} of ${format(servers.length)} synchronized<span class="stat-drill-arrow">↗</span></div></button>
    <button type="button" class="stat-card stat-interactive" data-action="drilldown" data-scope="learning" aria-label="View ${summary.collecting.length} endpoints collecting traffic"><div class="stat-label">Learning endpoints${icon('learning')}</div><div class="stat-value">${format(summary.collecting.length)}</div><div class="metric-meter subtle" aria-hidden="true"><span style="width:${servers.length?summary.collecting.length/servers.length*100:0}%"></span></div><div class="stat-note"><span class="dot"></span>Confirmed collecting${summary.assigned.length?` · ${summary.assigned.length} awaiting start`:''}<span class="stat-drill-arrow">↗</span></div></button>
    <button type="button" class="stat-card stat-interactive" data-action="drilldown" data-scope="alerts" aria-label="View ${alertTotal===null?'pending':alertTotal} unresolved alerts for matching endpoints"><div class="stat-label">Open alerts${icon('alerts')}</div><div class="stat-value">${alertTotal===null?'…':format(alertTotal)}</div><div class="metric-meter" aria-hidden="true"><span style="width:${alertTotal?alertCritical/alertTotal*100:0}%"></span></div><div class="stat-note"><span class="dot ${alertCritical?'red':'amber'}"></span><span class="number ${alertCritical?'red':''}">${alertCritical===null?'…':format(alertCritical)} critical / high</span><span>· ${alertUnack===null?'…':alertUnack} unacknowledged</span><span class="stat-drill-arrow">↗</span></div></button>
  </div>`;
}

function chartHTML(){
  const allFlows=visibleFlows(),units=trafficCountUnits,available=units.filter(unit=>allFlows.some(flow=>captureEvidence(flow).unit===unit)),unit=units.includes(state.captureUnit)?state.captureUnit:available[0] || 'log_records',flows=allFlows.filter(flow=>captureEvidence(flow).unit===unit);const total=flows.reduce((sum,flow)=>sum+num(flow.count),0);const binCount=20;const bins=Array.from({length:binCount},()=>({observed:0,allowed:0,denied:0}));const start=Date.now()-state.window*1000;
  flows.forEach(flow=>{const index=Math.max(0,Math.min(binCount-1,Math.floor((date(flow.last_seen).getTime()-start)/(state.window*1000)*binCount)));bins[index][['allowed','denied'].includes(flow.verdict)?flow.verdict:'observed']+=num(flow.count);});
  const max=Math.max(1,...bins.map(bin=>bin.allowed+bin.denied+bin.observed));const top=18,bottom=133,left=36,right=590,width=(right-left)/binCount;
  let bars='';bins.forEach((bin,index)=>{let y=bottom;['observed','allowed','denied'].forEach(kind=>{const height=bin[kind]/max*(bottom-top);y-=height;if(height>0)bars+=`<rect x="${(left+index*width+4).toFixed(1)}" y="${y.toFixed(1)}" width="${(width-8).toFixed(1)}" height="${height.toFixed(1)}" rx="2" fill="${{allowed:'#e40000',denied:'#efa0a5',observed:'#c7c8d1'}[kind]}"><title>${h(kind)}: ${format(bin[kind])} ${h(captureUnitLabel(unit))}</title></rect>`;});});
  let grid='';[0,.5,1].forEach(fraction=>{const y=bottom-fraction*(bottom-top);grid+=`<line x1="${left}" x2="${right}" y1="${y}" y2="${y}" class="chart-grid"/><text x="27" y="${y+3}" text-anchor="end" class="chart-axis">${compact(max*fraction)}</text>`;});
  const labels=[0,.25,.5,.75,1].map(fraction=>{const t=new Date(start+fraction*state.window*1000);return `<text x="${left+fraction*(right-left)}" y="154" text-anchor="${fraction===0?'start':fraction===1?'end':'middle'}" class="chart-axis">${h(t.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'}))}</text>`;}).join('');
  const traffic=state.view==='traffic',unitLabel=h(captureUnitLabel(unit));
  const headerControl=traffic
    ?`<select id="traffic-chart-unit" class="filter-select" aria-label="Chart count unit">${units.map(value=>`<option value="${value}" ${unit===value?'selected':''}>${h(captureUnitLabel(value))}</option>`).join('')}</select>`
    :`<div class="chart-controls" aria-label="Traffic window">${[[3600,'1h'],[21600,'6h'],[86400,'24h']].map(([value,label])=>`<button class="${state.window===value?'selected':''}" data-action="window" data-value="${value}" aria-pressed="${state.window===value}">${label}</button>`).join('')}</div>`;
  const unitControls=traffic?'':`<div class="chart-controls" aria-label="Capture count unit">${units.map(value=>`<button class="${unit===value?'selected':''}" data-action="capture-unit" data-value="${value}" aria-pressed="${unit===value}">${h(captureUnitLabel(value))}</button>`).join('')}</div>`;
  const legend=unit==='sample_minutes'||(traffic&&unit!=='log_records')?'':`<div class="chart-footer"><div class="legend"><span><i></i>${unit==='log_records'?'Legacy reported allowed':'Conntrack observed'}</span><span><i class="denied"></i>${unit==='log_records'?'Legacy reported denied':'Terminal NFLOG'}</span><span><i class="observed"></i>Legacy observed</span></div>${traffic?'':'<span>Transport evidence is not application success; legacy verdicts remain unverified</span>'}</div>`;
  const showSampleNote=traffic&&unit==='sample_minutes';
  let sampleNote='Up to one observation per source IP and endpoint port/protocol each minute.';
  if(showSampleNote&&!total){
    const page=trafficCataloguePage();
    if(page?.loading)sampleNote='Loading communication samples…';
    else if(page?.error)sampleNote='Could not load communication samples.';
    else if(page?.counts_by_unit.sample_minutes>0)sampleNote=`${format(page.counts_by_unit.sample_minutes)} samples match your filters on other pages of Observed sources.`;
    else sampleNote='No samples in this window. Start Discover traffic with Count traffic hits turned off to collect samples.';
  }
  return `<section class="card"><div class="card-header"><div><h2 class="card-title">${traffic?'Traffic by time':activeFilterCount()?'Filtered observed traffic':'Observed traffic'}</h2>${traffic?'':`<p class="card-subtitle">${unitLabel} grouped by last observation; units are never summed</p>`}</div>${headerControl}</div>${unitControls}
    <div class="chart-topline"><strong>${compact(total)}</strong><span>${unitLabel}${traffic?'':` · last ${state.window/3600}h`}</span></div>
    <div class="traffic-chart"><svg viewBox="0 0 610 163" role="img" aria-label="${format(total)} ${unitLabel} grouped by last observation time">${grid}${bars}${labels}${!total&&!showSampleNote?`<text x="310" y="80" text-anchor="middle" class="chart-axis">${traffic?'No observations for this unit':'No traffic recorded in this window'}</text>`:''}</svg></div>${showSampleNote?`<p class="traffic-chart-note">${h(sampleNote)}</p>`:''}${legend}</section>`;
}
function postureHTML(servers){
  const current=servers.filter(currentPolicy).length,total=servers.length;
  return `<section class="card overview-summary-card"><div><h2>Policy posture</h2><p>${format(current)} of ${format(total)} endpoints synchronized</p></div>
    <button type="button" data-action="drilldown" data-scope="current" aria-label="View ${format(current)} synchronized endpoints">${total?Math.round(current/total*100):0}%</button></section>`;
}
function overviewServicesHTML(servers){
  const pairs=new Map();
  for(const server of servers){
    for(const listener of server.listeners || []){
      const port=Number(listener.port),protocol=String(listener.protocol || '').toLowerCase();
      if(!Number.isInteger(port)||port<1||port>65535||!['tcp','udp'].includes(protocol))continue;
      const key=`${port}/${protocol}`;
      if(state.filters.ports.length&&!state.filters.ports.some(selected=>selected===key||selected===String(port)))continue;
      if(!pairs.has(key))pairs.set(key,{key,port,protocol,hosts:new Set(),names:new Map()});
      const pair=pairs.get(key),name=D.name(listener);
      pair.hosts.add(server.id);
      if(!pair.names.has(name))pair.names.set(name,new Set());
      pair.names.get(name).add(server.id);
    }
  }
  const rows=[...pairs.values()].sort((a,b)=>b.hosts.size-a.hosts.size||a.port-b.port||a.protocol.localeCompare(b.protocol)).slice(0,5);
  const entries=rows.map(pair=>{
    const [[name]]= [...pair.names].sort(([a,hostsA],[b,hostsB])=>Number(a==='Unknown service')-Number(b==='Unknown service')||hostsB.size-hostsA.size||a.localeCompare(b));
    const count=pair.hosts.size;
    return `<li><button type="button" data-action="overview-service" data-port="${pair.key}" aria-label="View ${format(count)} endpoints listening on ${pair.key}">
      <span class="overview-service-icon">${icon(name==='SSH'?'setup':/ssl|https/i.test(name)?'policies':'services')}</span>
      <span class="overview-service-name"><strong>${h(name)}</strong><small>${pair.key}</small></span>
      <span class="overview-service-count">${format(count)} host${count===1?'':'s'}</span>
    </button><span class="overview-service-meter" aria-hidden="true"><i style="width:${count/rows[0].hosts.size*100}%"></i></span></li>`;
  }).join('');
  return `<section class="card overview-services"><header class="overview-panel-head"><div><h2>Discovered services</h2><p>Most common listeners in this scope</p></div></header>
    <div class="overview-service-total"><div><strong>${format(pairs.size)}</strong><span>Distinct port / protocol pairs</span></div>${icon('servers')}</div>
    ${entries?`<ul>${entries}</ul>`:'<p class="overview-services-empty">No listeners reported in this scope.</p>'}
    <a href="/servers" class="overview-services-link">Explore services on Servers ${icon('arrow')}</a>
  </section>`;
}

function filteredServers(){return state.data.servers.filter(server=>(state.flowServer==='all'||server.id===state.flowServer)&&F.matchServer(server,state.filters,{search:state.search}));}
function serverRows(limit,selectable=state.view==='servers'){const list=filteredServers();let offset=0;if(!limit&&selectable){const key=JSON.stringify([state.filters,state.search,state.flowServer]);if(state.inventoryPageKey!==key){state.inventoryOffset=0;state.inventoryPageKey=key;}offset=Math.min(state.inventoryOffset||0,Math.max(0,Math.floor((list.length-1)/200)*200));state.inventoryOffset=offset;limit=200;}return {list,offset,limit,html:list.slice(offset,offset+(limit||list.length)).map(server=>`<tr class="server-row ${server.listeners?.some(listener=>listener.is_new)?'has-new-services':''}" data-action="server" data-id="${h(server.id)}" tabindex="0" aria-label="View ${h(server.hostname)}">${selectable?metadataSelectionCell(server):''}<td><div class="server-cell"><span class="server-icon">${icon('servers')}</span><div><div class="host-name">${h(server.hostname)} ${riskyServerBadge(server)}</div><div class="host-os">${h(server.os || 'Linux')} ${h(server.os_version)}</div></div></div></td><td class="mono">${h((server.ips||[])[0] || 'Not reported')}</td><td><div class="service-pills">${(server.listeners||[]).slice(0,3).map(listener=>listenerChip(listener)+riskyPortBadge(server,listener)).join('') || '<span class="host-os">No listeners</span>'}${server.listeners?.length>3?`<span class="host-os">+${server.listeners.length-3}</span>`:''}</div></td><td class="tag-column"><div class="tag-row">${serverLocationHTML(server)}<div class="tag-row">${tagsHTML(L.customTags(server.tags))}</div></div></td><td>${serverHealth(server)}${networkControlStatusHTML(server)}</td><td>${policyBadge(server)}</td><td><span class="version">v${num(server.applied_version)} <span style="color:#bac6cf">/ ${num(server.desired_version)}</span></span></td><td class="row-arrow">›</td></tr>`).join('')};}
function inventoryHTML(overview=false){const {list,html,offset,limit}=serverRows(overview?6:undefined,!overview);return `${!overview?filterBarHTML('inventory')+'<div class="section-line">'+sourceBanksToolbarHTML()+'</div>':''}<div class="section-line"><h2>${overview?'Fleet inventory':'Matching endpoints'}<span>${format(list.length)} endpoint${list.length===1?'':'s'}</span></h2>${overview?'<a class="button quiet" href="/servers">View matching servers '+icon('arrow')+'</a>':`<div class="toolbar-group"><button class="button secondary small" type="button" data-action="inventory-export" title="Export all discovered listeners on matching endpoints" ${!list.length?'disabled':''}>Export matching CSV</button>${canWrite()?`<button class="button secondary small" data-action="reservation-new">${icon('plus')}Add server</button>`:''}<button class="button secondary small" data-action="manage-groups">Server groups <span class="group-count">${(state.data.groups||[]).length}</span></button><button class="button secondary small" data-action="create-group" ${!canWrite()?'disabled':''}>${icon('plus')}Save scope as group</button></div>`}</div>${!overview?metadataSelectionHTML(list):''}<section class="card table-card"><div class="table-scroll"><table><thead><tr>${!overview?metadataSelectionHeader(list):''}<th>Server</th><th>Agent IP address</th><th>Discovered services</th><th class="tag-column">Location & tags</th><th>Health</th><th>Policy</th><th>Version</th><th></th></tr></thead><tbody id="server-table-body">${html || `<tr><td colspan="${!overview&&metadataAdmin()?9:8}"><div class="empty-state" style="padding:35px">No endpoints match these combined filters. Remove a filter or clear all to broaden the scope.</div></td></tr>`}</tbody></table></div><div class="table-footer"><span id="server-table-count">Showing ${list.length?offset+1:0}–${Math.min(list.length,offset+limit)} of ${format(list.length)} matching endpoint${list.length===1?'':'s'}</span><span>Agent defaults: discovery 15 min · control 60 sec</span>${!overview?`<div><button class="button secondary small" data-action="inventory-page" data-offset="${Math.max(0,offset-200)}" ${!offset?'disabled':''}>Previous</button><button class="button secondary small" data-action="inventory-page" data-offset="${offset+200}" ${offset+200>=list.length?'disabled':''}>Next</button></div>`:''}</div></section>${!overview?serverReservationsHTML():''}`;}
function overviewHTML(){
  const servers=filteredServers();
  return `${filterBarHTML('overview')}<div id="scoped-kpis">${statsHTML()}</div>
    <div class="overview-panels">${topologyHTML(servers)}${overviewServicesHTML(servers)}</div>
    <div class="overview-summaries">${PSegraTopology.healthHTML(servers)}${postureHTML(servers)}</div>
    ${controlPlaneHTML()}${firewallHighRiskHTML()}`;
}

function policiesHTML(){return policyWorkspaceHTML();}
function flowGraphHTML(){
  const flows=visibleFlows().slice().sort((a,b)=>num(b.count)-num(a.count));const sources=[...new Set(flows.map(flow=>flow.source_ip))].slice(0,4);const destinations=[...new Set(flows.map(flow=>`${flow.server_id}|${flow.port}|${flow.protocol}`))].slice(0,4);const sourceY=index=>62+index*55,destY=index=>62+index*55;
  const edges=flows.filter(flow=>sources.includes(flow.source_ip)&&destinations.includes(`${flow.server_id}|${flow.port}|${flow.protocol}`)).slice(0,16).map(flow=>{const sy=sourceY(sources.indexOf(flow.source_ip)),dy=destY(destinations.indexOf(`${flow.server_id}|${flow.port}|${flow.protocol}`));return `<path class="flow-edge ${h(['denied','observed'].includes(flow.verdict)?flow.verdict:'')}" d="M177 ${sy}C240 ${sy} 290 ${dy} 354 ${dy}"><title>${h(flow.source_ip)} → ${h(serverName(flow.server_id))}:${num(flow.port)} · ${format(flow.count)} ${h(captureUnitLabel(captureEvidence(flow).unit))} · ${h(captureEvidence(flow).label)}</title></path>`;}).join('');
  const nodes=sources.map((source,index)=>`<rect x="12" y="${sourceY(index)-18}" width="165" height="36" rx="6" fill="#fafafb" stroke="#e7e7ed"/><circle cx="27" cy="${sourceY(index)}" r="3" fill="#b0b0bf"/><text x="39" y="${sourceY(index)+4}">${h(source)}</text>`).join('')+destinations.map((destination,index)=>{const [id,port,protocol]=destination.split('|');const hostname=serverName(id);return `<rect x="354" y="${destY(index)-21}" width="190" height="42" rx="6" fill="#fff5f6" stroke="#f1d8dc"/><text x="366" y="${destY(index)-2}">${h(hostname.length>25?hostname.slice(0,23)+'…':hostname)}</text><text x="366" y="${destY(index)+12}" class="flow-label">${num(port)}/${h(protocol)}</text>`;}).join('');
  return `<section class="card"><div class="card-header"><div><h2 class="card-title">Source → service map</h2></div></div><div class="flow-map"><svg viewBox="0 0 558 ${Math.max(165,64+Math.max(sources.length,destinations.length)*55)}" role="img" aria-label="Observed traffic from source addresses to endpoint services"><text x="12" y="20" class="flow-label">OBSERVED SOURCES</text><text x="354" y="20" class="flow-label">ENDPOINT SERVICES</text>${edges}${nodes}${!sources.length?'<text x="279" y="100" text-anchor="middle">No sources to map</text>':''}</svg></div></section>`;
}
function trafficHTML(){if(trafficCatalogueEnabled())return trafficCatalogueHTML();const flows=visibleFlows();return `${filterBarHTML('traffic')}${trafficControlsHTML()}<div class="traffic-layout">${flowGraphHTML()}${chartHTML()}</div><div class="section-line"><h2>Observed sources<span>${flows.length} relationships</span></h2></div><section class="card"><div class="table-scroll"><table><thead><tr><th>Source IP</th><th>Endpoint</th><th>Service</th><th>Observation</th><th class="number-cell">Count</th><th>Last observed</th></tr></thead><tbody>${flows.map(flow=>`<tr><td class="mono">${h(flow.source_ip)}</td><td><button class="text-button" data-action="server" data-id="${h(flow.server_id)}">${h(serverName(flow.server_id))}</button></td><td><span class="service-pill">${num(flow.port)}/${h(flow.protocol)}</span></td><td>${captureEvidenceHTML(flow)}</td><td class="number-cell">${captureCountHTML(flow)}</td><td title="${h(timestamp(flow.last_seen))}">${age(flow.last_seen)}</td></tr>`).join('') || '<tr><td colspan="6"><div class="empty-state" style="padding:35px">No observations for this endpoint and time window.</div></td></tr>'}</tbody></table></div><div class="table-footer"><span>Showing up to 500 aggregated relationships</span><span>Retention: ${num(state.data.meta?.traffic_retention_hours || 24)} hours</span></div></section><div style="margin-top:24px">${learningHTML()}</div>${hitMonitoringHTML()}`;}
function alertsHTML(){const page=alertCataloguePage(),alerts=[...page.items].sort((a,b)=>(date(b.created_at)||0)-(date(a.created_at)||0));return `${filterBarHTML('alerts')}<div class="alert-view-controls"><label><input type="checkbox" id="show-resolved-alerts" ${state.alertIncludeResolved?'checked':''}> Include recovered / resolved alerts</label><span>${page.remote?(page.total===null?'…':format(page.total)):alerts.length} results in selected scope</span></div><div class="inline-notice">Health checks continue independently of traffic learning. An offline agent makes service status unknown; it does not prove the services are down.</div>${alerts.length?`<div class="alert-list">${alerts.map(alert=>{const resolved=!!alert.resolved_at||alert.status==='resolved';const ack=acknowledged(alert);const kind=resolved?'info':['critical','high','error'].includes(alert.severity)?'':'warning';return `<article class="card alert-card ${ack||resolved?'acknowledged':''}"><span class="alert-symbol ${kind}">${icon(resolved?'check':kind==='warning'?'warning':'alerts')}</span><div class="alert-body"><h2 class="alert-title">${h(alert.title || humanize(alert.kind || alert.type || 'Endpoint alert'))}</h2><p class="alert-message">${h(alert.message || (typeof alert.detail==='string'?alert.detail:'') || 'Review the endpoint for more details.')}</p>${alertServiceDetailsHTML(alert)}${securityAlertDetailsHTML(alert)}<div class="alert-meta"><button class="text-button" data-action="server" data-id="${h(alert.server_id)}">${h(serverName(alert.server_id))}</button><span>${timestamp(alert.created_at)}</span><span>${h(resolved?(alert.resolution_reason==='expectation_withdrawn'?'Expectation withdrawn':'Recovered'):ack?'Acknowledged':alert.severity||'Warning')}</span></div></div>${!resolved&&!ack?`<button class="button secondary small" data-action="ack-alert" data-id="${h(alert.id)}" ${!canWrite()?'disabled':''}>Acknowledge</button>`:''}</article>`;}).join('')}</div>`:emptyHTML(page.loading?'Loading alerts':'No alerts to review',page.error?'Alert history could not be loaded. Use Retry below.':'The health evaluator will report service changes and missing heartbeats here.','check')}${alertCatalogueFooter(page)}`;}
function humanize(value){return String(value).replace(/[_.-]/g,' ').replace(/^\w/,char=>char.toUpperCase());}
function activityHTML(){return auditCatalogueHTML();}
function emptyHTML(title,description,name='info',label='',action=''){return `<div class="empty-state">${icon(name)}<h2>${h(title)}</h2><p>${h(description)}</p>${label?`<button class="button secondary" data-action="${h(action)}" ${!canWrite()?'disabled':''}>${h(label)}</button>`:''}</div>`;}
let topologyCleanup=null;
function render(){const captureDetails=$('.traffic-coverage');if(captureDetails)state.trafficCoverageOpen=captureDetails.open;if(state.passwordChangeRequired){state.data=null;if(!$('#modal').open||$('#modal-title').textContent!=='Change your password')showLocalPasswordChange(true);return;}if(!state.data)return;persistScope();if(topologyCleanup){topologyCleanup();topologyCleanup=null;}renderChrome();$('#overview-quick-filters').innerHTML=state.view==='overview'?overviewQuickFiltersHTML():'';$('#view-content').innerHTML=({overview:overviewHTML,servers:()=>inventoryHTML(false),locations:locationsHTML,services:serviceGroupsHTML,firewall:firewallHTML,policies:policiesHTML,traffic:trafficHTML,risk:()=>riskHTML(),alerts:alertsHTML,activity:activityHTML,settings:settingsHTML,access:accessHTML}[state.view])();if($('#topology-root')&&globalThis.PSegraTopology){topologyCleanup=PSegraTopology.bind($('#topology-root'),{onLocationHelp:showLocationHelp,onLocationSelect:overviewSelectLocation,onCountryChange:()=>{render();$('#topology-country')?.focus();}});}}

function overviewSelectLocation(key){
  state.filters.locations=[key];
  render();
  $('[data-filter-menu="locations"] summary')?.focus();
}
let trafficWindowRequest=0;
async function changeTrafficWindow(seconds){
  if(![3600,21600,86400].includes(seconds))return;
  const previous=state.window,sequence=++trafficWindowRequest,identity=workspaceCSVIdentity();
  const current=()=>sequence===trafficWindowRequest&&state.window===seconds&&identity===workspaceCSVIdentity()&&state.data;
  state.window=seconds;
  if(state.view==='traffic'&&trafficCatalogueEnabled()){render();await loadTrafficCatalogue(0,{fresh:true});return;}
  try{
    const result=await api(`/flows?window=${seconds}`);
    if(!current())return;
    state.data.flows=result.items||[];
    render();
    if(state.view==='overview')$('#overview-traffic-window')?.focus();
  }catch(error){
    if(!current())return;
    state.window=previous;
    render();
    toast(error.message,true);
  }
}
async function refreshOverviewExtras(){
  if(state.extrasLoading)return;
  state.extrasLoading=true;
  try{state.cluster=await api('/cluster');state.clusterError=false;}
  catch{state.cluster=null;state.clusterError=true;}
  finally{state.extrasLoading=false;}
  if(state.data&&state.view==='overview'&&!$('#modal').open&&!document.activeElement?.matches('input,select,textarea')&&!$$('.filter-menu[open]').length)render();
}

function refreshWorkspaceView() {
  switch (state.view) {
    case 'overview':
      refreshOverviewExtras();
      refreshFirewallData();
      if (state.alertCatalogue?.remote && state.alertCatalogue.scopeKey !== alertCatalogueEmptyScopeKey()) loadAlertCatalogue(0);
      break;
    case 'policies':
      refreshFirewallData();
      refreshManagedRollouts();
      if (state.networkControlOpen) loadNetworkControl();
      break;
    case 'traffic':
      loadHitMonitors();
      if (state.trafficLearningSessionsOpen && !$('#modal').open) loadTrafficLearningHistory({quiet: true});
      if (trafficCatalogueEnabled() && !state.trafficCatalogue?.loading) loadTrafficCatalogue(state.trafficCatalogue?.offset || 0, {fresh: true});
      break;
    case 'firewall': loadFirewallActivation(); break;
    case 'activity': loadActivity(); break;
    case 'alerts': loadAlertCatalogue(state.alertCatalogue?.offset || 0); break;
    case 'risk': riskLoad(); break;
    case 'locations': loadMetadataSubnets(); break;
    case 'access': loadAccessUsers(); break;
    case 'settings': loadPlatformSettings(); break;
    case 'servers': loadServerReservations(); break;
  }
}

async function load({quiet=false,sessionChecked=false}={}){
  if(state.passwordChangeRequired){if(!$('#modal').open||$('#modal-title').textContent!=='Change your password')showLocalPasswordChange(true);return;}
  if(state.polling)return;state.polling=true;
  try{
    if(!sessionChecked&&state.authType&&state.authType!=='demo')applyDashboardIdentity(await api('/auth'));
    if(state.passwordChangeRequired){showLocalPasswordChange(true);return;}
    const result=await api('/overview');if(state.passwordChangeRequired){showLocalPasswordChange(true);return;}state.data={...result,servers:result.servers||[],groups:result.groups||[],service_groups:result.service_groups||[],policies:result.policies||[],locations:result.locations||[],learning_policies:result.learning_policies||[],learning_sessions:result.learning_sessions||[],alerts:result.alerts||[],flows:result.flows||[]};learningReceiveOverview(result);defaultDenyInvalidateReview();policyCatalogueReceiveOverview(result);alertsReceiveOverview(result);L.setCatalog(state.data.locations);F.setGroups(state.data.groups);sourceBanksReceiveOverview();refreshPolicyDeployments({quiet:true});if($('#modal').open&&$('#modal-title').textContent==='Server groups'){const scroll=$('#modal').scrollTop;showGroups();$('#modal').scrollTop=scroll;}if(state.window!==3600&&!(state.view==='traffic'&&trafficCatalogueEnabled())){const seconds=state.window,identity=workspaceCSVIdentity();const traffic=await api(`/flows?window=${seconds}`);if(state.window===seconds&&state.data&&identity===workspaceCSVIdentity())state.data.flows=traffic.items||[];}state.lastSync=new Date();openWorkspaceAfterSignIn();$('#global-error').hidden=true;$$('.connection-dot').forEach(dot=>dot.classList.remove('offline'));if(!platformHasDraft() && !$('#modal').open && !document.activeElement?.matches('input,select,textarea') && !$$('.filter-menu[open]').length)render();else renderChrome();refreshWorkspaceView();
  }
  catch(error){if(error.status===401){clearDashboardIdentity();state.data=null;closeDrawer();if(state.platformRecoveryReconnect)state.authError='Database recovery may have restarted the controller and invalidated this session. Sign in and reopen Recovery to verify the durable outcome.';else if(state.platformRuntimePending)state.authError='Controller authentication changed during activation or joining. Sign in with the existing cluster credentials, then refresh Platform settings.';$('#view-content').innerHTML=emptyHTML('Sign in required',state.platformRuntimePending?'Sign in with approved existing-cluster credentials to check the deployment operation.':'Your session has ended. Sign in again to view the workspace.','access');showLogin();}else{if($('#workspace-shell').hidden){showWorkspaceConnection(error);return;}$('#global-error').hidden=false;$('#global-error').textContent=`Controller unavailable: ${error.message}. Existing server policies remain in place. Retrying automatically.`;$$('.connection-dot').forEach(dot=>dot.classList.add('offline'));$('#connection-label').textContent='Controller unavailable';if(!state.data)$('#view-content').innerHTML=emptyHTML('Could not load the workspace','Check the controller connection and try again.','info','Retry connection','refresh');if(!quiet)toast(error.message,true);}}
  finally{state.polling=false;}
}

function showModal(title,content,eyebrow='WORKSPACE'){if(state.passwordChangeRequired&&title!=='Change your password')return showLocalPasswordChange(true);if(typeof accessDialogChanged==='function')accessDialogChanged();$('#modal-close').hidden=!!state.passwordChangeRequired;if(typeof metadataModalChanged==='function')metadataModalChanged(content);if(typeof agentInstallationModalChanged==='function')agentInstallationModalChanged(content);state.accountDialogOpen=false;$('#modal-title').textContent=title;$('#modal-eyebrow').textContent=eyebrow;$('#modal-content').innerHTML=content;$('#modal').scrollTop=0;if(!$('#modal').open)$('#modal').showModal();}
function closeModal(){if(state.passwordChangeRequired)return;if(typeof accessDialogClosed==='function')accessDialogClosed();if(typeof metadataModalClosed==='function')metadataModalClosed();policyDeploymentsModalClosed();sourceBanksClose();if(typeof clearAgentInstallation==='function')clearAgentInstallation();defaultDenyClose();state.firewallCounterGeneration=(state.firewallCounterGeneration||0)+1;const account=state.accountDialogOpen;state.accountDialogOpen=false;$('#modal').close();$('#modal-content').innerHTML='';if(account){renderChrome();$('#account-menu-toggle').focus();}else render();}
const formError=error=>{const element=$('#form-error');if(element){element.hidden=false;element.textContent=error.message||String(error);}else toast(error.message||String(error),true);};
const errorSlot='<div id="form-error" class="form-error" role="alert" hidden></div>';
function modalFooter(label){return `<div class="modal-footer"><button class="button secondary" type="button" data-action="close-modal">Cancel</button><button class="button primary" type="submit">${h(label)}</button></div>`;}
function tagString(tags={}){return Object.entries(tags).map(([key,value])=>`${key}=${value}`).join(', ');}
function parseTags(text){const result={};if(!text.trim())return result;text.split(',').map(item=>item.trim()).filter(Boolean).forEach(item=>{const eq=item.indexOf('=');if(eq<1||eq===item.length-1)throw new Error('Use key=value pairs separated by commas, for example application=billing, dc=mumbai.');const key=item.slice(0,eq).trim(),value=item.slice(eq+1).trim();if(!/^[A-Za-z][A-Za-z0-9_.-]{0,63}$/.test(key)||value.length>128)throw new Error('Tag keys must begin with a letter and use letters, numbers, dots, underscores, or hyphens.');if(Object.hasOwn(result,key))throw new Error(`Duplicate tag key: ${key}`);result[key]=value;});return result;}
function parsePorts(text){const ports=[];text.split(',').map(item=>item.trim()).filter(Boolean).forEach(item=>{const match=item.match(/^(\d{1,5})\/(tcp|udp)$/i);if(!match||Number(match[1])<1||Number(match[1])>65535)throw new Error('Enter services as port/protocol, for example 22/tcp, 80/tcp, 53/udp.');const value={port:Number(match[1]),protocol:match[2].toLowerCase()};if(!ports.some(port=>port.port===value.port&&port.protocol===value.protocol))ports.push(value);});return ports;}
function showLogin(){return showDashboardLogin();}
function policyTargetServers(policy){return F.policyTargets(policy,state.data.servers,state.data.groups||[]);}
function targetPreviewHTML(servers,explanation,emptyText='No current endpoints match. Future matching endpoints can inherit a dynamic target.'){return `<div class="target-preview"><div class="target-preview-top"><strong>${format(servers.length)} affected endpoint${servers.length===1?'':'s'}</strong><span>Current membership</span></div><p>${h(explanation)}</p><div class="target-preview-members">${servers.slice(0,8).map(server=>`<span class="target-member">${icon('servers')}${h(server.hostname)}</span>`).join('')||`<span class="help-text">${h(emptyText)}</span>`}${servers.length>8?`<span class="target-more">+${servers.length-8} more</span>`:''}</div></div>`;}
function policyEditorTarget(fields,{validate=true}={}){
  const type=fields.get('target_type'),selector=type==='tags'?L.withLocation(parseTags(String(fields.get('selector') || '')),String(fields.get('target_location_id') || '')):{};
  const group_ids=type==='groups'?fields.getAll('target_groups'):[];
  const endpoint_ids=type==='endpoints'?[...new Set(fields.getAll('target_endpoints'))]:[];
  const expand=type==='all'&&state.activePolicyEditor?.policy?.endpoint_ids?.length;
  if(validate){
    if(type==='tags'&&!Object.keys(selector).length)throw new Error('Enter a target tag or choose a saved location.');
    if(type==='groups'&&!group_ids.length)throw new Error('Select at least one saved server group.');
    if(type==='endpoints'&&(!endpoint_ids.length||endpoint_ids.length>100))throw new Error('Select between 1 and 100 enrolled endpoints.');
    if(expand&&fields.get('confirm_match_all')!=='on')throw new Error('Confirm the fleet-wide expansion before continuing.');
  }
  return {selector,group_ids,...(endpoint_ids.length?{endpoint_ids}:{}),...(expand&&fields.get('confirm_match_all')==='on'?{match_all:true}:{})};
}
function updatePolicyTargets(){
  const form=$('#policy-form');if(!form)return;
  const fields=new FormData(form),type=fields.get('target_type');
  $('#policy-tag-target').hidden=type!=='tags';$('#policy-group-target').hidden=type!=='groups';$('#policy-endpoint-target').hidden=type!=='endpoints';
  const fleetConfirmation=$('#policy-confirm-match-all');
  if(fleetConfirmation){
    const input=$('input',fleetConfirmation);
    fleetConfirmation.hidden=type!=='all';
    input.required=type==='all';
    if(type!=='all')input.checked=false;
  }
  try{
    const policy=policyEditorTarget(fields,{validate:false});
    const configured=type==='all'||Object.keys(policy.selector).length||policy.group_ids.length||policy.endpoint_ids?.length;
    const explanation={
      all:'This policy applies to the entire managed fleet, including future enrolled endpoints.',
      tags:'All tag and saved-location constraints must match. Future matching endpoints inherit this policy intent.',
      groups:'Selected group memberships are combined. Dynamic groups include future matching endpoints.',
      endpoints:'Only the selected enrollment IDs receive this policy. Address changes and newly enrolled endpoints do not change membership.'
    };
    $('#policy-target-preview').innerHTML=targetPreviewHTML(configured?policyTargetServers(policy):[],explanation[type],type==='endpoints'?'No selected endpoints are currently listed.':undefined);
  }catch(error){$('#policy-target-preview').innerHTML=`<div class="target-preview"><p>${h(error.message)}</p></div>`;}
}
function renderPolicyEditor(policy,id){
  if(!canWrite())return;if(policy.summary_only===true||policy.services?.some(service=>service.sources_omitted===true))throw new Error('A catalogue summary cannot populate a policy editor.');if(id)policyExactValue('managed',policy,id);const type=!id?'tags':policy.endpoint_ids?.length?'endpoints':policy.group_ids?.length?'groups':Object.keys(policy.selector||{}).length?'tags':'all';const groups=state.data.groups||[];
  state.activePolicyEditor={kind:'managed',id:id || '',policy};
  showModal(id?'Edit access policy':'Create an access policy',`<form id="policy-form" data-id="${h(id||'')}" data-revision="${id?num(policy.revision):''}"><div class="modal-body">${errorSlot}<div class="field"><label for="policy-name">Policy name</label><input id="policy-name" name="name" value="${h(policy.name)}" placeholder="Billing application access" maxlength="120" required autofocus></div><div class="field-row"><div class="field"><label for="policy-target-type">Apply one policy to</label><select id="policy-target-type" name="target_type"><option value="tags" ${type==='tags'?'selected':''}>Endpoints matching tags</option><option value="groups" ${type==='groups'?'selected':''}>Saved server groups</option><option value="endpoints" ${type==='endpoints'?'selected':''}>Specific endpoints by IP or name</option><option value="all" ${type==='all'?'selected':''}>All endpoints</option></select></div><div class="field"><label for="policy-mode">Mode</label><select id="policy-mode" name="mode"><option value="monitor" ${policy.mode==='monitor'?'selected':''}>Monitor / preview</option><option value="enforce" ${policy.mode==='enforce'?'selected':''}>Enforce intent · Admin save publishes</option></select></div></div><div id="policy-tag-target" class="field" ${type!=='tags'?'hidden':''}><label for="policy-selector">Target tags</label><input id="policy-selector" name="selector" value="${h(tagString(L.selectorTags(policy.selector)))}" placeholder="application=billing, owner=finance"><small>Custom tag pairs use AND. Choose a saved location below instead of entering a DC/location tag.</small>${locationSelectorField(policy.selector,'policy-location-id','target_location_id','Within saved location (optional)')}</div><div id="policy-group-target" class="field" ${type!=='groups'?'hidden':''}><div class="field-label">Select server groups</div><div class="host-checklist">${groups.map(group=>`<label class="host-check"><input type="checkbox" name="target_groups" value="${h(group.id)}" ${policy.group_ids?.includes(group.id)?'checked':''}>${h(group.name)}<span>${automaticGroup(group)?'Automatic application':group.type==='dynamic'?'Dynamic':'Static snapshot'} · ${F.groupMembers(group,state.data.servers).length}</span></label>`).join('')||'<p class="help-text" style="padding:12px">No saved groups. Open Servers and save a tag scope as a dynamic group first.</p>'}</div><small>Choosing several groups combines their members. Each endpoint receives a single compiled result.</small></div><div id="policy-endpoint-target" ${type!=='endpoints'?'hidden':''}>${endpointPickerHTML('policy-endpoints','target_endpoints',state.data.servers,policy.endpoint_ids || [])}</div>${policy.endpoint_ids?.length?`<div id="policy-confirm-match-all" hidden><label class="host-check"><input type="checkbox" name="confirm_match_all">Expand this policy from specific endpoints to the entire fleet, including future endpoints.</label></div>`:''}<div id="policy-target-preview"></div><div class="field-label" style="margin-top:22px">Inbound services & allowed sources</div><div id="policy-rules">${policy.services.map(ruleHTML).join('')}</div><button type="button" class="button secondary small" data-action="add-rule">${icon('plus')}Add service</button><div class="inline-notice warning" style="margin:18px 0 0">Saving publishes a new desired bundle to eligible endpoints. Agents apply it when local enforcement opt-ins, current protection checks and rollback support are ready; the endpoint receipt confirms the result. Whole-server default-deny bundles require their separate downtime acknowledgement. Imported-rule edits remain separate in Firewall.</div></div>${modalFooter(id?'Save changes':'Create policy')}</form>`,'GROUP & TAG POLICY');updatePolicyTargets();policyImpactAttachEditor();
}
function suggestedGroupSelector(){return F.scopeSelector(state.filters,state.search,state.flowServer,state.data.servers);}
function applicationGroup(group){return !!group.application && group.type==='dynamic' && Object.keys(group.selector || {}).length===1 && group.selector.application===group.application;}
function automaticGroup(group){return applicationGroup(group) && group.managed===true;}
function applicationRepresentatives(groups){const selected=new Map(),compare=(left,right)=>Number(!automaticGroup(left))-Number(!automaticGroup(right))||String(left.created_at||'').localeCompare(String(right.created_at||''))||String(left.id).localeCompare(String(right.id));for(const group of groups){if(!applicationGroup(group))continue;const current=selected.get(group.application);if(!current||compare(group,current)<0)selected.set(group.application,group);}return [...selected.values()].sort((left,right)=>left.application.localeCompare(right.application));}
function groupRowHTML(group){
  const members=F.groupMembers(group,state.data.servers),automatic=automaticGroup(group),app=applicationGroup(group),matching=members.filter(server=>(state.flowServer==='all'||server.id===state.flowServer)&&F.matchServer(server,state.filters,{search:state.search})).length;
  return `<article class="saved-group" data-group-id="${h(group.id)}"><div><strong>${h(group.name)}</strong><p>${group.type==='dynamic'?h(selectorDescription(group.selector)):'Static endpoint snapshot'}</p><small>${automatic?'Automatic application membership':app?'Saved application group':group.type==='dynamic'?'Custom dynamic group':'Custom static group'}${activeFilterCount()?` · ${format(matching)} in current scope`:''}</small></div><span class="badge ${group.type==='dynamic'?'learning':'neutral'}">${group.type==='dynamic'?'Dynamic':'Static'} · ${format(members.length)}</span><div class="saved-group-actions"><button class="text-button" data-action="view-group" data-id="${h(group.id)}">View members ↗</button><button class="text-button" data-action="edit-group" data-id="${h(group.id)}" ${!canWrite()?'disabled':''}>${automatic?'Rename':'Edit'}</button>${automatic?'':`<button class="text-button" data-action="delete-group" data-id="${h(group.id)}" ${!canWrite()?'disabled':''}>Delete</button>`}</div></article>`;
}
function showGroups(){
  const groups=state.data.groups||[],applications=applicationRepresentatives(groups),applicationIds=new Set(applications.map(group=>group.id)),custom=groups.filter(group=>!applicationIds.has(group.id));
  showModal('Server groups',`<div class="modal-body">${errorSlot}<p class="help-text" style="margin:0 0 18px">Every application tag has a dynamic group. Membership updates when approved tags change or matching endpoints enroll. Saved custom groups remain available alongside them.</p><div class="group-section-heading"><h3>Applications</h3><span>${applications.length} group${applications.length===1?'':'s'}</span></div><div class="saved-group-list">${applications.map(groupRowHTML).join('')||'<div class="empty-state" style="padding:25px">No application tags have been assigned yet.</div>'}</div><div class="group-section-heading"><h3>Custom groups</h3><span>${custom.length} group${custom.length===1?'':'s'}</span></div><div class="saved-group-list">${custom.map(groupRowHTML).join('')||'<p class="help-text">Create a custom group for multiple tags, a location, or an explicit endpoint snapshot.</p>'}</div></div><div class="modal-footer"><button class="button secondary" data-action="close-modal">Close</button><button class="button primary" data-action="create-group" ${!canWrite()?'disabled':''}>${icon('plus')}Create custom group</button></div>`,'REUSABLE TARGETS');
}
function viewGroup(id){if(!(state.data.groups||[]).some(group=>group.id===id))return;state.filters.groups=[id];closeModal();navigate('servers');}
function updateGroupPreview(){const form=$('#group-form');if(!form)return;const dynamic=$('[name="group_type"]',form).value==='dynamic';$('#group-tag-selector').hidden=!dynamic;$('#group-static-members').hidden=dynamic;try{const selector=dynamic?L.withLocation(parseTags($('[name="group_selector"]',form).value),$('#group-location-id')?.value || ''):{};const ids=JSON.parse(form.dataset.memberIds||'[]');const members=dynamic?(Object.keys(selector).length?state.data.servers.filter(server=>L.matchesSelector(server,selector)):[]):state.data.servers.filter(server=>ids.includes(server.id));$('#group-member-preview').innerHTML=targetPreviewHTML(members,dynamic?'Membership follows these tags automatically, including future securely enrolled endpoints.':'This is a static snapshot. Future matching endpoints are not added automatically.');}catch(error){$('#group-member-preview').innerHTML=`<div class="target-preview"><p>${h(error.message)}</p></div>`;}}
function showGroupForm(id){if(!canWrite())return;const existing=(state.data.groups||[]).find(group=>group.id===id);const suggested=suggestedGroupSelector();const group=existing||{name:'',type:suggested?'dynamic':'static',selector:suggested||{},server_ids:filteredServers().map(server=>server.id)};const automatic=automaticGroup(group);showModal(automatic?'Rename application group':existing?'Edit server group':'Save a server group',`<form id="group-form" data-id="${h(id||'')}" data-member-ids="${h(JSON.stringify(group.server_ids||[]))}"><div class="modal-body">${errorSlot}<div class="field"><label for="group-name">Group name</label><input id="group-name" name="group_name" value="${h(group.name)}" placeholder="Billing application" maxlength="120" required autofocus></div><div class="field"><label for="group-type">Membership</label><select id="group-type" name="group_type" ${automatic?'disabled':''}><option value="dynamic" ${group.type==='dynamic'?'selected':''}>Dynamic · follow matching tags</option><option value="static" ${group.type==='static'?'selected':''}>Static · saved endpoint snapshot</option></select><small>${automatic?'Membership is maintained from this approved application tag. Rename the display label here; change endpoint tags to change membership.':'Use dynamic membership for an application or any custom tag. Future matching endpoints inherit group policies.'}</small></div><div id="group-tag-selector" class="field" ${group.type!=='dynamic'?'hidden':''}><label for="group-selector">Group tags</label><input id="group-selector" name="group_selector" ${automatic?'readonly':''} value="${h(tagString(L.selectorTags(group.selector)))}" placeholder="application=billing"><small>At least one custom tag or saved location is required. All constraints must match.</small>${automatic?'':locationSelectorField(group.selector,'group-location-id','group_location_id','Within saved location (optional)')}</div><div id="group-static-members" class="field" ${group.type!=='static'?'hidden':''}><div class="inline-notice">Static snapshot: <span id="static-snapshot-count">${num(group.server_ids?.length)}</span> endpoint IDs. ${suggested?'':state.filters.groups?.length?'The current group and filter intersection is saved as an explicit endpoint snapshot.':'The current filters include conditions that cannot be represented as a simple dynamic tag group.'}</div><button type="button" class="text-button" data-action="replace-group-snapshot">Use current filtered endpoints (${filteredServers().length})</button></div><div id="group-member-preview"></div></div>${modalFooter(existing?'Save group':'Create group')}</form>`,'SERVER GROUP');updateGroupPreview();}
function showEditServer(id){
  const server=state.data.servers.find(item=>item.id===id);if(!server||!canWrite())return;const admin=['admin','super_admin'].includes(state.role),legacy=L.legacyTags(server.tags);
  metadataShowModal('Edit endpoint settings',`<form id="server-form" data-id="${h(id)}"><div class="modal-body">${errorSlot}<p class="help-text">${h(server.hostname)}</p>${metadataIndividualFieldsHTML(server,admin)}${Object.keys(legacy).length?`<p class="location-migration-note">Legacy location tags: ${h(tagString(legacy))}. These are migration hints. DC/location aliases cannot be saved as custom tags.</p>`:''}<div class="field"><label for="server-expected">Expected services</label><input id="server-expected" name="expected" value="${h((server.expected_services||[]).map(port=>`${port.port}/${port.protocol}`).join(', '))}" placeholder="22/tcp, 80/tcp"><small>Missing expected listeners produce health alerts. A firewall allowance alone does not make a service required.</small></div></div>${modalFooter('Save endpoint')}</form>`,'CENTRAL ENDPOINT CONFIGURATION');
}
function showSetup(){return showAgentInstallation();}
function showConfirm(title,text,label,action,id){showModal(title,`<div class="modal-body">${errorSlot}<p style="font-size:12px;color:#6a8494;margin:0">${h(text)}</p></div><div class="modal-footer"><button class="button secondary" data-action="close-modal">Cancel</button><button class="button danger" data-action="${h(action)}" data-id="${h(id)}">${h(label)}</button></div>`,'CONFIRM CHANGE');}

async function openServer(id, tab='access'){
  const server=state.data.servers.find(item=>item.id===id);if(!server)return;
  const request={};
  state.detailRequest=request;
  state.detail=id;
  state.drawerTab=tab;
  state.endpointAccess=null;
  state.learningSessionPages?.delete(learningPageKey(id));
  $('#drawer-backdrop').hidden=false;
  $('#server-drawer').hidden=false;
  renderServerDrawer(server);
  $('#server-drawer').scrollTop=0;
  $('#server-drawer').setAttribute('tabindex','-1');
  $('#server-drawer').focus();
  if(tab==='firewall')refreshServerFirewall(id);
  const access=tab==='access'?loadEndpointAccessPolicies(id):null;
  try{
    const result=await api(`/servers/${encodeURIComponent(id)}`);
    if(state.detailRequest===request)renderServerDrawer(result.server||result);
  }catch(error){
    if(state.detailRequest===request)toast(error.message,true);
  }
  await access;
}
function serverDrawerHeaderHTML(server){
  return `<div class="drawer-header"><div><span class="eyebrow">ENDPOINT DETAILS</span><h2 id="drawer-title">${h(server.hostname)}</h2>${riskyServerBadge(server)}<p>${h(server.os)} ${h(server.os_version)} · ${h((server.ips||[]).join(', ') || 'Agent IPs not reported')}</p></div><button class="icon-button" data-action="close-drawer" aria-label="Close endpoint details">×</button></div>`;
}
function serverDrawerServicesHTML(server){
  const compiled=server.compiled_policy||server.policy;const coverage=server.learning_coverage || {};learningReceiveServer(server);
  return `<div style="display:flex;gap:7px">${serverHealth(server)}${policyBadge(server)}${badge(filterLabel('learning',F.learningStatus(server)),F.isCollecting(server)?'learning':F.learningStatus(server)==='assigned'?'warning':'neutral')}</div><dl class="detail-grid"><div><dt>Last heartbeat</dt><dd>${age(server.last_seen)}</dd></div><div><dt>Firewall service</dt><dd>${h(server.firewalld_state || 'Unknown')}</dd></div><div><dt>Firewalld version</dt><dd>${h(server.firewalld_version || 'Not reported')}</dd></div><div><dt>Backend</dt><dd>${h(server.firewall_backend || 'Not reported')}</dd></div><div><dt>Applied policy</dt><dd>v${num(server.applied_version)}</dd></div><div><dt>Desired policy</dt><dd>v${num(server.desired_version)}</dd></div>${discoveryTimingHTML(server)}</dl>${networkControlStatusHTML(server,true)}${firewallMaintenanceSummaryHTML(server)}${hostPreparationHTML(server)}${sourceBanksStatusHTML(server)}${server.ufw_active?'<div class="inline-notice warning">UFW is active. Review the existing rules and plan a migration before enabling firewalld enforcement.</div>':''}${server.apply_error?`<div class="form-error">${h(server.apply_error)}</div>`:''}${server.discovery_error?`<div class="inline-notice warning">Discovery incomplete: ${h(server.discovery_error)}. Missing listeners cannot be treated as confirmed down.</div>`:''}<div class="detail-heading">Assigned location</div>${serverLocationHTML(server)}${metadataProvenanceHTML(server)}${Object.keys(L.legacyTags(server.tags)).length?`<p class="location-migration-note">Legacy location tags: ${h(tagString(L.legacyTags(server.tags)))}. These do not create or select an assignment. Review them when editing endpoint settings.</p>`:''}<div class="server-lifecycle-actions">${canWrite()?`<button class="button secondary small danger-text" data-action="server-lifecycle-delete-review" data-id="${h(server.id)}">Review server retirement</button>`:''}</div><div class="detail-heading">Custom endpoint tags<button class="text-button" data-action="edit-server" data-id="${h(server.id)}" ${!canWrite()?'disabled':''}>Edit settings</button></div><div class="tag-row">${tagsHTML(L.customTags(server.tags),true)}</div><div class="detail-heading">Discovered services<span class="host-os">${(server.listeners||[]).length} listener${(server.listeners||[]).length===1?'':'s'}</span></div>${(server.listeners||[]).map(listener=>listenerDetailsHTML(listener,server)).join('') || '<p class="help-text">No listening services reported.</p>'}${discoveryChangesHTML(server)}<div class="detail-heading">Expected services</div><div class="service-pills">${(server.expected_services||[]).map(port=>`<span class="service-pill">${num(port.port)}/${h(port.protocol)}</span>`).join('') || '<span class="help-text">No required services configured.</span>'}</div><div class="detail-heading">Traffic learning</div>${coverage.error||coverage.rate_limited||num(coverage.dropped_events)>0?`<div class="inline-notice warning">Learning coverage incomplete: ${num(coverage.dropped_events)} dropped events${coverage.rate_limited?' · rate limiting detected':''}${coverage.error?' · '+h(coverage.error):''}. Observed counts may be incomplete.</div>`:''}${captureCoverageHTML(coverage)}${serverLearningSessionsHTML(server)}${coverage.started_at?`<p class="help-text">Agent collection started: ${h(timestamp(coverage.started_at))}${coverage.ended_at?' · Ended: '+h(timestamp(coverage.ended_at)):''} · ${num(coverage.dropped_events)} dropped events reported.</p>`:''}${compiled?`<div class="detail-heading">Compiled access policy</div><pre class="detail-json">${h(JSON.stringify(compiled,null,2))}</pre>`:''}<p class="help-text" style="margin-top:25px">A listening socket shows local availability. Remote reachability and application health need separate probes.</p>`;
}
function renderServerDrawer(server){
  if(!server)return;
  state.detailData=server;
  const tabs=[['access','Access policies'],['services','Services & health'],['firewall','Existing firewall'],['managed','Managed history']];
  const drawer=$('#server-drawer');
  drawer.classList.toggle('server-drawer-access',state.drawerTab==='access');
  let body;
  switch(state.drawerTab){
    case 'access':body=endpointAccessPoliciesHTML(server);break;
    case 'firewall':body=serverFirewallHTML(server);break;
    case 'managed':body=managedEndpointHTML(server);break;
    default:body=serverDrawerServicesHTML(server);
  }
  drawer.innerHTML=serverDrawerHeaderHTML(server)+`<div class="drawer-body"><nav class="drawer-tabs" aria-label="Endpoint detail sections">${tabs.map(([tab,label])=>`<button type="button" data-action="${tab==='managed'?'managed-drawer-tab':'firewall-drawer-tab'}" data-tab="${tab}" class="${state.drawerTab===tab?'active':''}" aria-pressed="${state.drawerTab===tab}">${label}</button>`).join('')}</nav>${state.drawerTab==='access'?'':securityMonitorHTML(server)}${body}</div>`;
}
function closeDrawer(){$('#server-drawer').hidden=true;$('#drawer-backdrop').hidden=true;state.detail=null;state.detailRequest=null;state.endpointAccess=null;}

async function loadActivity(){return loadAuditCatalogue();}
async function mutate(path,options,message){try{const result=await api(path,options);if($('#modal').open)closeModal();policyDeploymentsPublished(result);toast(message);await load();if(state.view==='activity')await loadActivity();return true;}catch(error){formError(error);return false;}}
async function handleAction(event){
  const button=event.target.closest('[data-action]');if(!button||button.disabled)return;const action=button.dataset.action,id=button.dataset.id;if(state.passwordChangeRequired&&!['auth-signout','account-signout'].includes(action))return;if(action?.startsWith('policy-deployment-'))return policyDeploymentsAction(button);if(action?.startsWith('source-bank-'))return sourceBanksAction(button);if(action?.startsWith('traffic-catalogue-'))return trafficCatalogueAction(button);if(action?.startsWith('audit-'))return auditCatalogueAction(button);if(action?.startsWith('default-deny-'))return defaultDenyAction(button);if(action?.startsWith('risk-'))return riskAction(button);
  if(event.target.dataset?.metadataSelect||event.target.id==='metadata-select-all')return;
  if(action?.startsWith('account-'))return accountAction(button);
  if(action?.startsWith('policy-catalogue-'))return policyCatalogueAction(button);
  if(action?.startsWith('hit-monitor-'))return hitMonitorAction(button);
  if(action?.startsWith('platform-'))return platformAction(button);
  if(action?.startsWith('recommendation-'))return recommendationAction(button);
  if(action?.startsWith('learned-policy-'))return learnedPolicyAction(button);
  if(['traffic-learning-sessions','traffic-learning-refresh','learning-session-page','learning-host-scope','learning-host-page'].includes(action))return learningHistoryAction(button);
  if(action?.startsWith('service-group-'))return serviceGroupAction(button);
  if(action==='learning-refresh-preview')return refreshLearningPreview();
  if(action?.startsWith('metadata-'))return metadataAction(button);
  if(action?.startsWith('location-'))return locationAction(button);
  if(action?.startsWith('access-')||action?.startsWith('auth-'))return accessAction(button);
  if(action?.startsWith('reservation-')||action?.startsWith('server-lifecycle-'))return serverLifecycleAction(button);
  if(action?.startsWith('managed-'))return managedAction(button);
  if(action?.startsWith('firewall-activation-'))return firewallActivationAction(button);
  if(action?.startsWith('network-control-'))return networkControlAction(button);
  if(action?.startsWith('firewall-counters-'))return firewallCounterAction(button);
  if(action?.startsWith('firewall-'))return firewallAction(button);
  if(action==='toggle-filters'){state.filtersOpen=!state.filtersOpen;render();return;}
  if(action==='alert-page'){if(!button.disabled)await loadAlertCatalogue(Number(button.dataset.offset));return;}
  if(action==='drilldown'){const scope=button.dataset.scope;state.filters=F.drilldown(state.filters,scope);state.alertIncludeResolved=false;const view=scope==='alerts'?'alerts':'servers';navigate(view);return;}
  if(action==='add-port-filter')return applyFilterEntry('ports');
  if(action==='add-custom-filter')return applyFilterEntry('custom');
  if(action==='inventory-page'){state.inventoryOffset=Number(button.dataset.offset)||0;render();return;}
  if(action==='inventory-export')return downloadWorkspaceCSV('/servers/export.csv','prthak-servers.csv',{server_ids:filteredServers().map(server=>server.id)},policyCatalogueScopeKey);
  if(action==='clear-filters'){state.filters=F.empty();state.search='';state.flowServer='all';render();return;}
  if(action==='remove-filter'){const category=button.dataset.filterCategory,value=button.dataset.filterValue,key=button.dataset.filterKey;if(category==='search')state.search='';else if(category==='endpoint')state.flowServer='all';else if(category==='custom'){state.filters.custom[key]=state.filters.custom[key].filter(item=>item!==value);if(!state.filters.custom[key].length)delete state.filters.custom[key];}else state.filters[category]=state.filters[category].filter(item=>item!==value);render();return;}
  if(action==='server')return openServer(id);
  if(action==='endpoint-access-refresh')return loadEndpointAccessPolicies(state.detail);
  if(action==='endpoint-access-page')return endpointAccessPage(button.dataset.section,Number(button.dataset.offset));
  if(action==='close-drawer')return closeDrawer();
  if(action==='learn')return showLearning();
  if(action==='discover-traffic')return showLearning(undefined,{purpose:'traffic'});
  if(action?.startsWith('endpoint-picker-'))return endpointPickerAction(button);
  if(action==='edit-server')return showEditServer(id);
  if(action==='manage-groups')return showGroups();
  if(action==='view-group')return viewGroup(id);
  if(action==='create-group')return showGroupForm();
  if(action==='edit-group')return showGroupForm(id);
  if(action==='replace-group-snapshot'){const form=$('#group-form');form.dataset.memberIds=JSON.stringify(filteredServers().map(server=>server.id));if($('#static-snapshot-count'))$('#static-snapshot-count').textContent=filteredServers().length;updateGroupPreview();return;}
  if(action==='delete-group'&&automaticGroup((state.data.groups||[]).find(group=>group.id===id)||{}))return;
  if(action==='delete-group'){const group=(state.data.groups||[]).find(group=>group.id===id),explanation=applicationGroup(group||{})?'Only this saved group is removed. Its application tags and automatic application grouping remain. Groups referenced by a policy cannot be deleted.':'Groups referenced by a policy cannot be deleted. Delete or retarget the policy first.';return showConfirm('Delete this server group?',explanation,'Delete group','confirm-delete-group',id);}
  if(action==='confirm-delete-group'&&automaticGroup((state.data.groups||[]).find(group=>group.id===id)||{}))return;
  if(action==='confirm-delete-group'){button.disabled=true;const group=(state.data.groups||[]).find(group=>group.id===id),success=await mutate(`/groups/${encodeURIComponent(id)}`,{method:'DELETE'},applicationGroup(group||{})?'Saved group deleted. Application grouping remains available.':'Server group deleted.');if(!success)button.disabled=false;return;}
  if(action==='create-policy')return showPolicy();
  if(action==='edit-policy')return showPolicy(id);
  if(action==='close-modal')return closeModal();
  if(action==='refresh')return state.authType?load():init();
  if(action==='refresh-activity')return loadActivity();
  if(action==='add-rule')return $('#policy-rules').insertAdjacentHTML('beforeend',ruleHTML());
  if(action==='remove-rule'){if($$('.rule-row').length===1)return toast('A policy needs at least one service.',true);return button.closest('.rule-row').remove();}
  if(action==='capture-unit'){if(trafficCountUnits.includes(button.dataset.value)){state.captureUnit=button.dataset.value;render();}return;}
  if(action==='window')return changeTrafficWindow(num(button.dataset.value));
  if(action==='overview-location')return overviewSelectLocation(button.dataset.key);
  if(action==='overview-service'&&/^\d{1,5}\/(?:tcp|udp)$/.test(button.dataset.port || '')){
    state.filters.ports=[button.dataset.port];
    return navigate('servers');
  }
  if(action==='stop-learning')return showConfirm('Stop this learning session?','The agent will stop collection on its next policy sync. Existing access policy stays active, and recorded observations are retained.','Stop learning','confirm-stop',id);
  if(action==='confirm-stop'){button.disabled=true;const success=await mutate(`/learning/${encodeURIComponent(id)}/stop`,{method:'POST',body:{}},'Learning session stopped. Agents receive the update on their next sync.');if(!success)button.disabled=false;return;}
  if(action==='delete-policy')return reviewPolicyRemoval(id);
  if(action==='confirm-delete'){if(!canWrite()){formError(new Error('Read Only access cannot change the workspace.'));return;}const policy=state.activePolicyRemoval;if(!policy||policy.id!==id){formError(new Error('Reload the exact policy and review its removal first.'));return;}button.disabled=true;const success=await mutate(`/policies/${encodeURIComponent(id)}`,{method:'DELETE',body:{expected_revision:policy.revision}},'Policy deleted. Follow endpoint cleanup and traffic evidence in Rollouts.');if(!success)button.disabled=false;return;}
  if(action==='ack-alert'){button.disabled=true;const success=await mutate(`/alerts/${encodeURIComponent(id)}/ack`,{method:'POST',body:{}},'Alert acknowledged.');if(!success)button.disabled=false;return;}
  if(action==='generate-token'){button.disabled=true;try{const result=await api('/enrollment-tokens',{method:'POST',body:{name:$('#enrollment-name').value.trim()||'New Linux endpoint'}});$('#enrollment-result').innerHTML=`<p class="help-text" style="margin-top:16px">Single use · Expires ${h(timestamp(result.expires_at))}</p><div class="token-box"><code id="enrollment-token">${h(result.token)}</code></div><button class="button secondary small" data-action="copy-token">Copy token</button><p class="help-text">Shown for this session only. Pass it to the installer through a protected environment variable or file.</p>`;toast('Single-use enrollment token created.');}catch(error){formError(error);}finally{button.disabled=false;}return;}
  if(action==='copy-token'){try{await navigator.clipboard.writeText($('#enrollment-token').textContent);toast('Enrollment token copied.');}catch{const selection=window.getSelection();const range=document.createRange();range.selectNodeContents($('#enrollment-token'));selection.removeAllRanges();selection.addRange(range);toast('Token selected. Use your browser’s copy command.');}return;}
}

document.addEventListener('toggle',event=>{
  if(event.target.matches?.('.agent-polling-overrides'))state.platformAgentOverridesOpen=event.target.open;
  networkControlToggle(event);
  if(event.target.id==='platform-certificate-operations' && event.target.isConnected!==false) state.platformCertificateOperationsOpen=event.target.open;
},true);
document.addEventListener('click',handleWorkspaceLink);
document.addEventListener('click',handleAction);
document.addEventListener('keydown',event=>{if(event.key==='Enter'&&['service-filter-input','custom-tag-filter-input'].includes(event.target.id)){event.preventDefault();applyFilterEntry(event.target.id==='service-filter-input'?'ports':'custom');return;}if(event.key==='Enter' && event.target.matches('.server-row'))openServer(event.target.dataset.id);if(event.key==='Escape' && state.detail)closeDrawer();});
document.addEventListener('input',event=>{accessInput(event);platformMarkDraft(event.target);if(firewallActivationInput(event)||networkControlInput(event))return;if(platformUpdateInput(event)||platformSetupInput(event))return;if(platformSigningInput(event)||platformSIEMInput(event)||platformApplicationPortInput(event)||platformRecoveryInput(event)||platformNotificationInput(event)||platformEndpointCertificateInput(event))return;if(platformAgentSettingsInput(event))return;if(platformApplianceInput(event))return;if(platformHAInput(event)||platformInput(event))return;if(event.target.id==='recommendation-name'&&recommendationChange(event))return;if(serviceGroupInput(event))return;if(event.target.id==='location-catalog-search'){const position=event.target.selectionStart;state.locationSearch=event.target.value;render();const input=$('#location-catalog-search');input?.focus();if(position!==null)input?.setSelectionRange(position,position);return;}if(event.target.matches?.('[data-endpoint-search]')&&endpointPickerInput(event.target))return;if(event.target.id==='policy-selector')updatePolicyTargets();if(event.target.id==='group-selector')updateGroupPreview();if(['server-search','traffic-search','alerts-search','firewall-search'].includes(event.target.id)){state.search=event.target.value;refreshSearchResults();}});
document.addEventListener('change',event=>{accessChange(event);if(defaultDenyChange(event))return;if(hitMonitorChange(event))return;if(agentInstallationChange(event))return;if(firewallChange(event))return;platformMarkDraft(event.target);if(platformAgentUpgradeScopeChange(event))return;if(firewallActivationInput(event)||networkControlInput(event))return;if(platformUpdateInput(event)||platformSetupInput(event))return;if(platformApplicationPortInput(event)||platformNotificationChange(event))return;if(platformAgentSettingsChange(event))return;if(platformApplianceChange(event)||platformCertificateChange(event))return;if(endpointPickerInput(event.target)||recommendationChange(event)||learningChange(event)||policyServiceChange(event)||serviceGroupInput(event))return;if(metadataChange(event))return;if(event.target.id==='traffic-history-purpose'){
  state.learningHistoryPurpose=event.target.value;
  loadTrafficLearningHistory();
  return;
}if(event.target.id==='overview-traffic-window')return changeTrafficWindow(num(event.target.value));if(event.target.id==='location-type')$('#location-cloud-fields').hidden=event.target.value!=='cloud';if(event.target.id==='policy-target-type'||event.target.id==='policy-location-id'||['target_groups','target_endpoints'].includes(event.target.name))updatePolicyTargets();if(event.target.id==='group-type'||event.target.id==='group-location-id')updateGroupPreview();if(event.target.dataset.filterCategory){const key=event.target.dataset.filterCategory,value=event.target.value;if(key==='locations'){state.filters.locations=event.target.checked?(state.filters.locations.some(item=>L.equivalent(item,value))?state.filters.locations:[...state.filters.locations,value]):state.filters.locations.filter(item=>!L.equivalent(item,value));}else state.filters[key]=event.target.checked?[...new Set([...state.filters[key],value])]:state.filters[key].filter(item=>item!==value);renderPreservingFilterFocus();}if(event.target.id==='traffic-chart-unit'&&trafficCountUnits.includes(event.target.value)){state.captureUnit=event.target.value;render();document.getElementById('traffic-chart-unit')?.focus();}if(event.target.id==='flow-server-filter'){state.flowServer=event.target.value;render();if(state.hitMonitorId)loadHitMonitorDetails();}if(event.target.id==='show-resolved-alerts'){state.alertIncludeResolved=event.target.checked;render();}});
document.addEventListener('submit',async event=>{
  const form=event.target;if(['local-login-form','local-password-form'].includes(form.id))return localAuthSubmit(event);if(state.passwordChangeRequired){event.preventDefault();return;}if(['firewall-activation-form','firewall-activation-review-form'].includes(form.id))return firewallActivationSubmit(event);if(['network-control-form','network-control-review-form'].includes(form.id))return networkControlSubmit(event);if(['platform-update-upload-form','platform-update-review-form'].includes(form.id))return platformUpdateSubmit(event);if(form.id==='platform-signing-recovery-form')return platformSigningSubmit(event);if(['platform-siem-form','platform-siem-review-form','platform-siem-retry-form'].includes(form.id))return platformSIEMSubmit(event);if(form.id==='access-password-reset-form')return accessPasswordResetSubmit(event);if(form.id==='access-saml-form')return accessSAMLSubmit(event);if(form.id==='server-form')return metadataServerSubmit(event);if(['source-bank-selection-form','source-bank-confirm-form'].includes(form.id)){event.preventDefault();return sourceBanksSubmit(form);}if(form.id==='audit-filter-form'){event.preventDefault();return auditCatalogueSubmit(form);}if(['default-deny-selection-form','default-deny-review-form'].includes(form.id))return defaultDenySubmit(event);if(form.id==='risk-catalog-form')return riskSubmit(event);if(['hit-monitor-form','hit-monitor-review-form'].includes(form.id))return hitMonitorSubmit(event);if(['pilot-polling-form','pilot-polling-review-form'].includes(form.id))return pilotPollingSubmit(event);if(['platform-setup-form','platform-setup-review-form'].includes(form.id))return platformSetupSubmit(event);if(form.id==='agent-installation-form')return agentInstallationSubmit(event);if(form.id==='account-profile-form')return accountProfileSubmit(event);if(form.id==='account-preferences-form')return accountPreferencesSubmit(event);if(['platform-application-port-form','platform-application-port-review-form'].includes(form.id))return platformApplicationPortSubmit(event);if(['platform-recovery-request-form','platform-recovery-confirm-form'].includes(form.id))return platformRecoverySubmit(event);if(['platform-notification-form','platform-notification-review-form','platform-notification-send-form'].includes(form.id))return platformNotificationSubmit(event);if(form.id==='platform-internal-suspend-form')return platformInternalSuspendSubmit(event);if(form.id==='platform-endpoint-revoke-form')return platformEndpointCertificateSubmit(event);if(form.id==='platform-endpoint-renewal-form')return platformEndpointRenewalSubmit(event);if(form.id==='platform-agent-settings-form')return platformAgentSettingsSubmit(event);if(form.id==='platform-certificate-form')return platformCertificateSubmit(event);if(form.id==='platform-controller-name-form')return saveControllerDisplayName(event);if(['platform-agent-upgrade-scope-form','platform-agent-upgrade-confirm-form'].includes(form.id))return platformAgentUpgradeSubmit(event);if(['platform-appliance-config-form','platform-appliance-join-form','platform-appliance-storage-form','platform-appliance-review-form','platform-backup-schedule-form'].includes(form.id))return platformApplianceSubmit(event);if(['platform-ha-form','platform-join-form','platform-join-token-form'].includes(form.id))return platformHASubmit(event);if(form.id==='platform-review-form')return platformReviewSubmit(event);if(form.id==='platform-demo-form')return platformDemoSubmit(event);if(form.id==='recommendation-form')return recommendationSubmit(event);if(form.id==='learned-policy-form')return learnedPolicySubmit(event);if(form.id==='service-group-form')return serviceGroupSubmit(event);if(form.id==='learning-form')return learningSubmit(event);if(form.id==='access-user-form')return accessSubmit(event);if(form.id==='server-reservation-form')return reservationSubmit(event);if(form.id?.startsWith('metadata-'))return metadataSubmit(event);if(form.id==='location-form')return locationSubmit(event);if(['managed-rollout-form','managed-restore-form'].includes(form.id))return managedSubmit(event);if(form.id==='firewall-rule-form')return firewallSubmit(event);if(!['login-form','learning-form','policy-form','server-form','group-form'].includes(form.id))return;event.preventDefault();const submit=$('button[type="submit"]',form);submit.disabled=true;const formData=new FormData(form);try{
    if(form.id!=='login-form'&&!canWrite())throw new Error('Read Only access cannot change the workspace.');
    if(form.id==='login-form'){if(state.authConfig?.mode!=='tokens')throw new Error('Use Microsoft Entra ID to sign in to this workspace.');state.token=String(formData.get('token') || '').trim();if(!state.token)throw new Error('Enter the controller-issued role token.');try{const auth=await api('/auth');applyDashboardIdentity(auth);sessionStorage.setItem('segment-token',state.token);}catch(error){clearDashboardIdentity();throw error;}closeModal();await load();return;}
    if(form.id==='policy-form'){const services=collectPolicyServices(form);const target=policyEditorTarget(formData);const id=form.dataset.id,editor=state.activePolicyEditor;if(!editor||editor.kind!=='managed'||editor.id!==(id || ''))throw new Error('Open a fresh exact policy editor before saving.');if(id){policyExactValue('managed',editor.policy,id);if(policyCatalogueNavigation('managed',id)?.revision>editor.policy.revision)throw new Error('This policy changed. Reload its exact current revision.');}const body={name:String(formData.get('name')).trim(),...target,mode:formData.get('mode'),services,...(id?{expected_revision:editor.policy.revision}:{})};const saved=await api(`/policies${id?'/'+encodeURIComponent(id):''}`,{method:id?'PUT':'POST',body});state.policyTab='policies';try{sessionStorage.setItem('prithak-policy-tab','policies');}catch{}closeModal();policyDeploymentsPublished(saved);toast('Policy saved. Follow agent application and traffic evidence in Rollouts.');await load();return;}
    if(form.id==='group-form'){const existing=(state.data.groups||[]).find(group=>group.id===form.dataset.id),automatic=automaticGroup(existing||{}),type=automatic?'dynamic':String(formData.get('group_type')),selector=automatic?{application:existing.application}:type==='dynamic'?L.withLocation(parseTags(String(formData.get('group_selector'))),String(formData.get('group_location_id') || '')):{},server_ids=type==='static'?JSON.parse(form.dataset.memberIds||'[]'):[];if(type==='dynamic'&&!Object.keys(selector).length)throw new Error('Dynamic groups need at least one tag pair.');if(type==='static'&&!server_ids.length)throw new Error('A static group needs at least one endpoint.');const id=form.dataset.id;await api(`/groups${id?'/'+encodeURIComponent(id):''}`,{method:id?'PUT':'POST',body:{name:String(formData.get('group_name')).trim(),type,selector,server_ids}});closeModal();toast('Server group saved. Membership and affected policies updated.');await load();return;}
  }catch(error){formError(error);if(form.id==='login-form'){state.token='';sessionStorage.removeItem('segment-token');}}
  finally{submit.disabled=false;}
});
$('#modal').addEventListener('close',()=>{if(typeof metadataModalClosed==='function'&&metadataAsync.active&&!$('#modal').open)metadataModalClosed();});$('#modal').addEventListener('cancel',event=>{if(state.passwordChangeRequired){event.preventDefault();return;}if(state.accountDialogOpen){event.preventDefault();closeModal();}});$('#modal-close').addEventListener('click',closeModal);$('#drawer-backdrop').addEventListener('click',closeDrawer);
$('#refresh-button').innerHTML=icon('refresh');$('#refresh-button').addEventListener('click',()=>load());$('#setup-icon').innerHTML=icon('setup');$('#setup-button').addEventListener('click',showSetup);$('#learn-button').addEventListener('click',()=>showLearning(undefined,{purpose:state.view==='traffic'?'traffic':state.view==='policies'?'automatic':''}));
$('#enroll-button').addEventListener('click', () => {
  const openEditor = {policies: showPolicy, locations: showLocationEditor, services: showServiceGroupEditor}[state.view];
  openEditor?.();
});
const sidebarToggle = $('#sidebar-toggle');
const narrowSidebar = window.matchMedia?.('(max-width: 1050px)');
let sidebarExpanded;
function renderSidebarWidth() {
  const expanded = sidebarExpanded ?? !narrowSidebar?.matches;
  $('#workspace-shell').classList.toggle('sidebar-compact', !expanded);
  const label = expanded ? 'Collapse sidebar' : 'Expand sidebar';
  sidebarToggle.setAttribute('aria-expanded', String(expanded));
  sidebarToggle.setAttribute('aria-label', label);
  sidebarToggle.title = label;
}
sidebarToggle.addEventListener('click', () => {
  sidebarExpanded = $('#workspace-shell').classList.contains('sidebar-compact');
  renderSidebarWidth();
});
narrowSidebar?.addEventListener('change', renderSidebarWidth);
renderSidebarWidth();
window.addEventListener('popstate',restoreWorkspaceView);
window.addEventListener('hashchange',migrateLegacyHash);
window.addEventListener('beforeunload',persistScope);
window.addEventListener('pagehide',persistScope);
window.addEventListener('pageshow',event=>{
  if(!event.persisted)return;
  Object.assign(state,restoreScope());
  state.view=signInReturnView();
  if(!state.authType)return init();
  if(state.passwordChangeRequired)return;
  if($('#modal').open)closeModal();
  showWorkspaceConnection();
  return load({quiet:true});
});
async function init(){
  if(state.initializing||migrateLegacyHash())return;
  state.initializing=true;
  state.view=signInReturnView();
  state.authConfig=null;
  showWorkspaceConnection();
  try{
    const config=await api('/auth/config');
    if(!['tokens','entra','demo','local','hybrid','saml'].includes(config?.mode))throw new Error('Controller returned an invalid authentication configuration.');
    state.authConfig=config;
    if(config.mode!=='tokens'){state.token='';sessionStorage.removeItem('segment-token');}
    applyDashboardIdentity(await api('/auth'));
    if(!state.authType)return showLogin();
    if(state.passwordChangeRequired)return showLocalPasswordChange(true);
    await load({sessionChecked:true});
    if(state.view==='activity'&&state.data&&!state.passwordChangeRequired)await loadActivity();
  }catch(error){
    if(error.status===401&&state.authConfig){
      clearDashboardIdentity();
      state.authError='';
      showLogin();
    }else showWorkspaceConnection(error);
  }finally{state.initializing=false;}
}
init();
setInterval(()=>{if(!document.hidden&&state.authType&&location.pathname!=='/login')load({quiet:true});},15000);

document.addEventListener('click',event=>{if(!event.target.closest('.filter-menu'))$$('.filter-menu[open]').forEach(menu=>menu.open=false);});
