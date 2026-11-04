'use strict';

function policyCatalogueDefinition(kind){return kind==='learned'?{field:'learning_policies',pagination:'learning_policy_pagination',path:'/learning-policies',label:'learned allow policies'}:{field:'policies',pagination:'policy_pagination',path:'/policies',label:'managed policies'};}
function policyCatalogueScope(){return {filters:state.filters,search:state.search,server_id:state.flowServer};}
function policyCatalogueScopeKey(){return JSON.stringify(policyCatalogueScope());}
function policyCatalogueEmptyScopeKey(){return JSON.stringify({filters:F.empty(),search:'',server_id:'all'});}
function policyCatalogueRecord(items,meta,scopeKey){
  if(!Array.isArray(items)||items.length>100||!meta||!Number.isSafeInteger(meta.total)||meta.total<0||!Number.isSafeInteger(meta.offset)||meta.offset<0||!Number.isSafeInteger(meta.limit)||meta.limit<1||meta.limit>100||items.length>meta.limit)throw new Error('The controller did not return a bounded policy catalogue page.');
  return {...meta,items,scopeKey,next_offset:Number.isSafeInteger(meta.next_offset)?meta.next_offset:meta.offset+items.length,remote:true,loading:false,error:''};
}
function policyCatalogueReceiveOverview(result){
  state.policyCatalogues ||= {};
  for(const kind of ['managed','learned']){const definition=policyCatalogueDefinition(kind),meta=result[definition.pagination],current=state.policyCatalogues[kind];if(meta&&(!current||current.scopeKey===policyCatalogueEmptyScopeKey()&&!current.offset&&!current.loading))state.policyCatalogues[kind]=policyCatalogueRecord(result[definition.field] || [],meta,policyCatalogueEmptyScopeKey());}
}
function policyCataloguePage(kind){
  state.policyCatalogues ||= {};const definition=policyCatalogueDefinition(kind),current=state.policyCatalogues[kind],scopeKey=policyCatalogueScopeKey();
  if(current?.remote){if(current.scopeKey!==scopeKey&&!current.pendingScope){state.policyCatalogues[kind]={...current,items:[],total:null,offset:0,scopeKey,pendingScope:true,loading:true,error:''};Promise.resolve().then(()=>loadPolicyCatalogue(kind,0));}return state.policyCatalogues[kind];}
  const items=state.data?.[definition.field] || [];return {items,total:items.length,offset:0,limit:20,has_more:false,scopeKey,remote:false,loading:false,error:''};
}
function policyCatalogueQuery(offset){
  const eligible=state.data.servers.filter(server=>(state.flowServer==='all'||server.id===state.flowServer)&&F.matchServer(server,state.filters,{ignorePorts:true})),metadataScope=F.count({...state.filters,ports:[]})>0||state.flowServer!=='all';
  return {server_ids:metadataScope?eligible.map(server=>server.id):null,search_server_ids:state.search?eligible.filter(server=>F.matchServer(server,state.filters,{ignorePorts:true,search:state.search})).map(server=>server.id):[],ports:[...(state.filters.ports || [])],search:state.search,limit:20,offset};
}
let policyCatalogueRequestSequence=0;
async function loadPolicyCatalogue(kind,offset=0){
  if(!['managed','learned'].includes(kind)||!Number.isSafeInteger(offset)||offset<0)return;
  state.policyCatalogues ||= {};const scopeKey=policyCatalogueScopeKey(),previous=policyCataloguePage(kind),definition=policyCatalogueDefinition(kind),sequence=++policyCatalogueRequestSequence;
  state.policyCatalogues[kind]={...previous,items:previous.scopeKey===scopeKey?previous.items:[],scopeKey,loading:true,pendingScope:false,error:'',sequence};
  try{const page=await api(definition.path+'/query',{method:'POST',body:policyCatalogueQuery(offset)});if(state.policyCatalogues[kind]?.sequence!==sequence||policyCatalogueScopeKey()!==scopeKey)return;let history=previous.scopeKey===scopeKey?[...(previous.history || [])]:[];if(offset>previous.offset)history.push(previous.offset);else if(offset<previous.offset){const at=history.lastIndexOf(offset);history=at<0?[]:history.slice(0,at);}state.policyCatalogues[kind]={...policyCatalogueRecord(page.items,page,scopeKey),history};}
  catch(error){if(state.policyCatalogues[kind]?.sequence===sequence)state.policyCatalogues[kind]={...state.policyCatalogues[kind],loading:false,pendingScope:false,error:'Policy catalogue unavailable: '+error.message};}
  if(state.view==='policies'&&!$('#modal').open)policyCatalogueRedraw();
}
function policyCatalogueRedraw(){
  const drafts=['#service-filter-input','#custom-tag-filter-input'].map(selector=>[selector,$(selector)?.value || '']),active=document.activeElement,focusId=active?.id,start=active?.selectionStart,end=active?.selectionEnd;
  renderPreservingFilterFocus();for(const [selector,value] of drafts){const input=$(selector);if(input)input.value=value;}if(focusId){const input=document.getElementById(focusId);input?.focus();if(Number.isInteger(start)&&input?.setSelectionRange)input.setSelectionRange(start,end ?? start);}
}
function policyCataloguePaginationHTML(kind){
  const page=policyCataloguePage(kind),definition=policyCatalogueDefinition(kind);if(!page.remote)return '';
  const count=page.items.length,first=count?page.offset+1:0,last=count?page.offset+count:0;
  return `<div class="recommendation-pagination"><span>${page.total===null?(page.error?'Matching total unavailable for ':'Loading matching ')+definition.label:`Loaded ${format(count)} · ${first}–${last} of ${format(page.total)} matching ${definition.label}`}${page.loading?' · Loading…':''}</span><div><button class="button secondary small" data-action="policy-catalogue-page" data-kind="${kind}" data-offset="${page.history?.at(-1) ?? 0}" ${!page.offset||page.loading?'disabled':''}>Previous</button><button class="button secondary small" data-action="policy-catalogue-page" data-kind="${kind}" data-offset="${page.next_offset ?? page.offset+page.limit}" ${!page.has_more||page.loading?'disabled':''}>Next</button><button class="text-button" data-action="policy-catalogue-page" data-kind="${kind}" data-offset="${page.offset}" ${page.loading?'disabled':''}>Refresh</button></div></div>${page.error?`<p class="form-error">${h(page.error)}</p>`:''}<p class="help-text">Filters select the full catalogue before pagination.</p>`;
}

function policyGroupNames(ids){
  return (ids || []).map(id=>(state.data.groups || []).find(group=>group.id===id)?.name || id).join(', ');
}

function policyDestination(policy,kind){
  if(kind==='learned'){
    const ids=policy.server_ids || (policy.server_id?[policy.server_id]:[]);
    return policy.hostname || ids.map(serverName).join(', ') || 'Endpoint not reported';
  }
  if(policy.group_ids?.length)return policyGroupNames(policy.group_ids);
  if(Object.keys(policy.selector || {}).length)return selectorDescription(policy.selector);
  return 'All endpoints';
}

function policySourceHTML(service,exact=false){
  const sources=service.sources || [], parts=[];
  if(service.sources_omitted){
    parts.push(`<span>${format(service.source_count)} literal source CIDRs</span>`);
  }else if(sources.length){
    parts.push(`<span>${h(sources.slice(0,3).join(', '))}</span>`);
    if(sources.length>3)parts.push(exact?`<details><summary>All ${format(sources.length)} source addresses</summary><pre class="detail-json">${h(sources.join('\n'))}</pre></details>`:`<small>+${format(sources.length-3)} in details</small>`);
  }
  if(Object.keys(service.source_selector || {}).length)parts.push(`<small>Source tags / location: ${h(selectorDescription(service.source_selector))}</small>`);
  if(service.source_group_ids?.length)parts.push(`<small>Source server groups: ${h(policyGroupNames(service.source_group_ids))}</small>`);
  return parts.join('') || '<span class="help-text">No sources specified</span>';
}

function policyPortHTML(service){
  const direct=F.servicePorts({port:service.port,protocol:service.protocol});
  const ports=(direct.length?direct:F.servicePorts(service)).map(port=>`${port.port}/${port.protocol}`);
  const group=service.service_group_snapshot;
  return `<strong>${h(ports.join(', ') || '—')}</strong>${group?`<small>${h(group.name)} · r${num(group.revision)}</small>`:''}`;
}

function policyTableHTML(entries,kind,empty){
  return `<section class="card table-card"><div class="table-scroll"><table class="managed-table">
    <thead><tr><th>Policy</th><th>Source</th><th>Destination</th><th>Destination port</th><th>Action</th><th>Status</th><th></th></tr></thead>
    ${entries.length?entries.map(({policy,services,targets,status,tone})=>{
      const visible=services.slice(0,12), count=visible.length || 1;
      const name=policy.name || 'Saved policy', destination=policyDestination(policy,kind);
      const details=`<button class="text-button" data-action="policy-catalogue-detail" data-kind="${kind}" data-id="${h(policy.id)}">Details</button>`;
      return `<tbody>${(visible.length?visible:[null]).map((service,index)=>`<tr>
        ${index===0?`<td rowspan="${count}"><strong>${h(name)}</strong>${kind==='learned'?`<small>${policy.origin==='auto'?'Automatically learned':'Reviewed observed access'}</small>`:''}</td>`:''}
        <td>${service?policySourceHTML(policy.summary_only?{...service,sources_omitted:true}:service):'—'}</td>
        ${index===0?`<td rowspan="${count}">${h(destination)}${targets===undefined?'':`<small>${format(targets)} matching endpoint${targets===1?'':'s'}</small>`}</td>`:''}
        <td>${service?policyPortHTML(service):'—'}</td><td>${service?'Allow':'—'}</td>
        ${index===0?`<td rowspan="${count}">${badge(status,tone)}${policy.error?`<small class="danger-text">${h(policy.error)}</small>`:''}</td>
          <td rowspan="${count}">${details}${services.length>visible.length?`<small>+${format(services.length-visible.length)} services</small>`:''}</td>`:''}
      </tr>`).join('')}</tbody>`;
    }).join(''):`<tbody><tr><td colspan="7">${h(empty)}</td></tr></tbody>`}
  </table></div></section>`;
}

function managedPoliciesHTML(){
  const page=policyCataloguePage('managed'),policies=filteredPolicies();
  const entries=policies.map(policy=>{
    const {services,targets}=F.policyScope(policy,state.data.servers,state.data.groups || [],state.filters,state.search,state.flowServer);
    return {policy,services,targets:targets.length,status:policy.mode==='enforce'?'Enforcement requested':'Monitor',tone:policy.mode==='enforce'?'warning':'neutral'};
  });
  return `<section><div class="section-line"><h2>Managed policies<span>${format(entries.length)} ${page.remote?'managed policies on loaded page':'managed policies in scope'}</span></h2></div>
    ${policyTableHTML(entries,'managed',page.loading?'Loading managed policies…':page.error?'Managed policies could not be loaded.':'No managed policies match this scope.')}
    ${policyCataloguePaginationHTML('managed')}</section>`;
}

const discoveredZoneUsageLabels={
  active:'Bound to interface or source',default:'Default zone',unbound:'No active binding',
  unknown:'Zone use unknown',host:'Host-wide',mixed:'Varies by endpoint'
};

function discoveredPolicyResultsHTML(){
  const current=state.firewallScopeKey===firewallScopeKey();
  const ready=current&&state.firewallData?.view==='access';
  const rows=ready?firewallRules():[],paging=ready?state.firewallData.pagination:null;
  const showUnused=state.policyShowUnusedZones===true,loading=state.firewallLoading;
  const status=state.firewallError?'Discovered policies could not be loaded.':loading||!current?'Loading discovered policies…':ready?'No discovered access policies match this scope.':'The controller needs a compatible access policy view.';
  const rowHTML=rows.map(rule=>{
    const counts=Object.entries(rule.zone_usage_counts || {}).filter(([key,count])=>discoveredZoneUsageLabels[key]&&count>0);
    const ids=rule.matching_server_ids || [];
    const endpoints=rule.matching_host_count ?? rule.host_count ?? ids.length;
    const destination=rule.destination==='Endpoint'&&ids.length
      ?ids.slice(0,2).map(serverName).join(', ')+(endpoints>2?` +${format(endpoints-2)}`:'')
      :rule.destination;
    const usage=discoveredZoneUsageLabels[rule.zone_usage] || discoveredZoneUsageLabels.unknown;
    return `<tr><td>${h(rule.source)}</td><td>${h(destination)}<small>${format(endpoints)} endpoint${endpoints===1?'':'s'}</small></td>
      <td><strong>${h(rule.destination_port)}</strong></td><td>${h(rule.zone || '—')}</td>
      <td>${badge(rule.decision==='allow'?'Allow':'Deny',rule.decision==='allow'?'healthy':'danger')}${rule.kind==='target'?'<small>Zone fallback</small>':''}</td>
      <td>${h(usage)}${rule.zone_usage==='mixed'?`<small>${counts.map(([key,count])=>`${format(count)} ${h(discoveredZoneUsageLabels[key])}`).join(' · ')}</small>`:''}</td>
      <td><button class="text-button" data-action="firewall-hosts" data-key="${h(rule.rule_key)}">Details</button></td></tr>`;
  }).join('');
  return `<section><div class="section-line"><h2>Discovered policies<span>Reported by endpoint firewalls</span></h2><div class="inline-actions">
      <button class="button secondary small" type="button" data-action="policy-catalogue-zones" aria-pressed="${showUnused}">${showUnused?'Hide zones without active bindings':'Show zones without active bindings'}</button>
      <button class="button secondary small" type="button" data-action="firewall-refresh" ${loading?'disabled':''}>Refresh</button></div></div>
    <p class="help-text">Zone use comes from reported bindings. It describes firewall configuration and scope.</p>
    ${state.firewallError?`<p class="form-error" role="alert">${h(state.firewallError)}</p>`:''}
    <section class="card table-card"><div class="table-scroll"><table class="managed-table">
      <thead><tr><th>Source</th><th>Destination</th><th>Destination port</th><th>Zone</th><th>Action</th><th>Zone use</th><th></th></tr></thead>
      <tbody>${rowHTML || `<tr><td colspan="7">${status}</td></tr>`}</tbody></table></div>
      ${paging?`<div class="table-footer"><span>${format(rows.length)} on this page</span><div>
        <button class="button secondary small" data-action="firewall-page" data-direction="previous" ${!state.firewallCursorHistory?.length||loading?'disabled':''}>Previous</button>
        <button class="button secondary small" data-action="firewall-page" data-direction="next" ${!paging.next_cursor||loading?'disabled':''}>Next</button>
      </div></div>`:''}
    </section></section>`;
}
function policyCatalogueNavigation(kind,id){const definition=policyCatalogueDefinition(kind),page=(state.policyCatalogues?.[kind]?.items || []).find(policy=>policy.id===id),overview=(state.data?.[definition.field] || []).find(policy=>policy.id===id);return !page?overview:overview&&num(overview.revision)>num(page.revision)?overview:page;}
function policyExactValue(kind,value,id){
  if(!value||value.id!==id||value.summary_only===true||value.sources_omitted===true||!Number.isSafeInteger(value.revision)||value.revision<1||!Array.isArray(value.services)||value.services.some(service=>!service||service.sources_omitted===true||!Array.isArray(service.sources)))throw new Error('Exact policy details are unavailable or incomplete. A catalogue summary cannot be edited or approved. Reload the exact policy.');
  return value;
}
function policyExactRemember(kind,value){state.policyDetails ||= new Map();const key=kind+':'+value.id;state.policyDetails.delete(key);state.policyDetails.set(key,value);while(state.policyDetails.size>4)state.policyDetails.delete(state.policyDetails.keys().next().value);return value;}
function policyExactCurrent(kind,id){const detail=state.policyDetails?.get(kind+':'+id),navigation=policyCatalogueNavigation(kind,id);return detail&&(!navigation||num(navigation.revision)<=detail.revision)?detail:navigation;}
let policyDetailRequestSequence=0;
function policyDetailBegin(title){const token={sequence:++policyDetailRequestSequence,title};state.policyDetailRequest=token;state.activePolicyEditor=null;state.activePolicyRemoval=null;state.activeLearningApproval=null;showModal(title,'<div class="modal-body"><p class="help-text">Loading exact policy configuration and source allowances…</p></div><div class="modal-footer"><button class="button secondary" data-action="close-modal">Close</button></div>','EXACT POLICY DETAILS');return token;}
function policyDetailAlive(token){return state.policyDetailRequest?.sequence===token.sequence&&$('#modal').open&&$('#modal-title').textContent===token.title;}
async function policyExactFetch(kind,id,token){
  const definition=policyCatalogueDefinition(kind),value=await api(definition.path+'/'+encodeURIComponent(id));if(token&&!policyDetailAlive(token))return null;
  policyExactValue(kind,value,id);const navigation=policyCatalogueNavigation(kind,id);if(navigation&&num(navigation.revision)>value.revision)throw new Error('This policy changed while its details loaded. Reload the current revision before editing or reviewing it.');return policyExactRemember(kind,value);
}
function policyDetailFailure(token,error){if(!policyDetailAlive(token))return;showModal('Exact policy unavailable',`<div class="modal-body"><p class="form-error">${h(error.message)}</p><p class="help-text">No editable or approvable allowlist was inferred from the catalogue summary.</p></div><div class="modal-footer"><button class="button secondary" data-action="close-modal">Close</button></div>`,'DETAIL LOAD FAILED');}
function policyDetailActionsHTML(kind,policy){
  const id=h(policy.id);
  if(kind==='learned')return `${policy.session_id?`<button class="button secondary small" data-action="recommendation-open" data-id="${h(policy.session_id)}">Session evidence</button>`:''}${canWrite()&&!policy.removal_pending&&!policy.removed?`<button class="button secondary small" data-action="learned-policy-edit" data-id="${id}">Edit sources</button><button class="button secondary small danger-text" data-action="learned-policy-remove-review" data-id="${id}">Remove</button>`:''}`;
  return `<button class="button secondary small" data-action="policy-catalogue-impact" data-id="${id}">Preview impact</button><button class="button secondary small" data-action="managed-policy-history" data-id="${id}">History</button>${canWrite()?`<button class="button secondary small" data-action="edit-policy" data-id="${id}">Edit policy</button><button class="button secondary small danger-text" data-action="delete-policy" data-id="${id}">Delete</button>`:''}`;
}

async function showPolicyCatalogueDetail(kind,id){
  const token=policyDetailBegin('Loading exact policy');
  try{
    const policy=await policyExactFetch(kind,id,token);if(!policy)return;
    const destination=policyDestination(policy,kind);
    const services=policy.services.map(service=>`<tr><td>${policySourceHTML(service,true)}</td><td>${h(destination)}</td><td>${policyPortHTML(service)}</td><td>Allow</td></tr>`).join('');
    showModal(policy.name || 'Policy details',`<div class="modal-body"><p class="help-text">Exact saved intent · revision ${num(policy.revision)}</p><div class="table-scroll"><table class="managed-table"><thead><tr><th>Source</th><th>Destination</th><th>Destination port</th><th>Action</th></tr></thead><tbody>${services || '<tr><td colspan="4">No service entries.</td></tr>'}</tbody></table></div></div><div class="modal-footer"><button class="button secondary" data-action="close-modal">Close</button>${policyDetailActionsHTML(kind,policy)}</div>`,'SAVED POLICY');
  }catch(error){policyDetailFailure(token,error);}
}

async function policyCatalogueAction(button){
  const {action,kind,id}=button.dataset;
  if(action?.startsWith('policy-catalogue-impact'))return policyImpactAction(button);
  if(action==='policy-catalogue-page')return loadPolicyCatalogue(kind,Number(button.dataset.offset));
  if(action==='policy-catalogue-detail')return showPolicyCatalogueDetail(kind,id);
  if(action==='policy-catalogue-zones'){
    state.policyShowUnusedZones=!state.policyShowUnusedZones;
    const results=$('#discovered-policy-results');
    if(results)results.innerHTML=discoveredPolicyResultsHTML();
    return refreshFirewallData();
  }
}
async function showPolicy(id){
  if(!canWrite())return;
  if(!id){state.policyDetailRequest=null;renderPolicyEditor({name:'',selector:{},group_ids:[],mode:'monitor',services:[{port:80,protocol:'tcp',sources:[],source_selector:{}}]});return;}
  const token=policyDetailBegin('Loading exact policy for editing');try{const policy=await policyExactFetch('managed',id,token);if(policy&&canWrite())renderPolicyEditor(policy,id);}catch(error){policyDetailFailure(token,error);}
}
async function reviewPolicyRemoval(id){
  if(!canWrite())return;const token=policyDetailBegin('Loading exact policy for removal');try{const policy=await policyExactFetch('managed',id,token);if(!policy||!canWrite())return;state.activePolicyRemoval=policy;showModal('Delete this policy?',`<div class="modal-body">${errorSlot}<p>Remove ${h(policy.name)} · exact revision ${num(policy.revision)}.</p><p class="help-text">Deletion creates new desired bundles. Live changes require a separate reviewed authorization. Review overlapping policies and protected management access.</p><pre class="detail-json">${h(JSON.stringify(policy,null,2))}</pre></div><div class="modal-footer"><button class="button secondary" data-action="close-modal">Cancel</button><button class="button danger" data-action="confirm-delete" data-id="${h(id)}">Delete policy</button></div>`,'EXACT POLICY REMOVAL');}catch(error){policyDetailFailure(token,error);}
}

// Impact previews have their own request identity and never call a publishing
// endpoint. Draft controls live inside the editor without replacing its form.
let policyImpactContext=null,policyImpactSequence=0;
function policyImpactIdentity(){return JSON.stringify([state.authType,state.role,state.user?.id,state.user?.tenant_id]);}
function policyImpactScope(){const query=policyCatalogueQuery(0);return {server_ids:query.server_ids,ports:query.ports};}
function policyImpactControlsHTML(draft=false){
  const retention=Math.min(86400,num(state.data?.meta?.traffic_retention_hours || 24)*3600),windows=[[300,'Last 5 minutes'],[3600,'Last hour'],[21600,'Last 6 hours'],[86400,'Last 24 hours']].filter(([seconds])=>seconds<=retention);
  return `<section id="policy-impact-controls"><p class="help-text">${draft?'Preview the current unsaved form. Your draft stays open.':'Preview this saved policy using the current dashboard server scope.'} No policy or firewall changes are made.</p><div class="field-row"><div class="field"><label for="policy-impact-window">Observed window</label><select id="policy-impact-window">${windows.map(([seconds,label])=>`<option value="${seconds}" ${seconds===3600?'selected':''}>${label}</option>`).join('')}</select></div><div class="field"><label for="policy-impact-outcome">Modeled new ingress</label><select id="policy-impact-outcome"><option value="all">All outcomes</option><option value="would_block">Would block</option><option value="would_allow">Would allow</option><option value="unverified">Unverified / unknown</option></select></div></div><div class="field-row"><div class="field"><label for="policy-impact-source">Observed source IP or subnet</label><input id="policy-impact-source" type="search" maxlength="64" placeholder="Optional · 10.20.0.0/16 or IPv6"></div><div class="field"><label for="policy-impact-ports">Observed ports</label><input id="policy-impact-ports" type="search" maxlength="1200" placeholder="Optional · 443/tcp, 8443, 53/udp"></div></div><button type="button" class="button secondary small" data-action="policy-catalogue-impact-${draft?'draft':'run'}">Preview impact</button><p id="policy-impact-error" class="form-error" role="alert" hidden></p><div id="policy-impact-results" aria-live="polite"></div></section>`;
}
function policyImpactAttachEditor(){
  const form=$('#policy-form');if(!form||!canWrite())return;policyImpactContext=null;
  const existing=form.querySelector('#policy-impact-controls');if(existing?.id==='policy-impact-controls')return;
  const section=document.createElement('section');section.id='policy-impact-editor';section.innerHTML=`<div class="detail-heading">What would this change affect?</div>${policyImpactControlsHTML(true)}`;
  form.querySelector('.modal-body')?.append(section);
}
function policyImpactAlive(context){return policyImpactContext===context&&context.identity===policyImpactIdentity()&&$('#modal').open&&(context.kind==='draft'?state.activePolicyEditor===context.editor&&$('#policy-form')===context.form:$('#modal-title').textContent==='Policy impact preview');}
function policyImpactDraftValue(form){
  if(!canWrite())throw new Error('Only Admins can preview unsaved policy changes.');
  const editor=state.activePolicyEditor,id=form.dataset.id || '';if(!editor||editor.kind!=='managed'||editor.id!==id)throw new Error('Open a fresh policy editor before previewing a draft.');
  const fields=new FormData(form),type=fields.get('target_type'),selector=type==='tags'?L.withLocation(parseTags(String(fields.get('selector') || '')),String(fields.get('target_location_id') || '')):{},group_ids=type==='groups'?fields.getAll('target_groups'):[];
  if(type==='tags'&&!Object.keys(selector).length)throw new Error('Enter target tags, or choose All endpoints.');
  if(type==='groups'&&!group_ids.length)throw new Error('Select at least one saved server group.');
  if(id)policyExactValue('managed',editor.policy,id);
  return {policy:{name:String(fields.get('name') || '').trim(),mode:fields.get('mode'),selector,group_ids,services:collectPolicyServices(form)},...(id?{policy_id:id,expected_revision:editor.policy.revision}:{})};
}
function policyImpactOptions(context){
  const ports=String($('#policy-impact-ports')?.value || '').split(/[,\s]+/).filter(Boolean);
  if(ports.length>100||ports.some(port=>!/^([1-9]\d{0,4})(\/(tcp|udp))?$/.test(port)||Number(port.split('/')[0])>65535))throw new Error('Use up to 100 exact ports, optionally /tcp or /udp.');
  return {...context.scope,window_seconds:Number($('#policy-impact-window')?.value || 3600),source_ip:String($('#policy-impact-source')?.value || '').trim(),ports:ports.length?[...new Set(ports)]:context.scope.ports,outcome:$('#policy-impact-outcome')?.value || 'all',limit:50};
}
function policyImpactLabel(value){return ({would_allow:'Would allow new ingress',would_block:'Would block new ingress',unverified:'Unverified / unknown'})[value] || 'Unverified / unknown';}
function policyImpactBackendsHTML(coverage){return (coverage?.capture_backends || []).slice(0,3).map(backend=>`${h(backend.backend)}: ${h(backend.status || 'unknown')} · IPv4 ${backend.ipv4?'reported':'not reported'} / IPv6 ${backend.ipv6?'reported':'not reported'} · ${backend.lost_events===null||backend.lost_events===undefined?'backend loss unknown':format(backend.lost_events)+' backend events lost'}${backend.error?' · '+h(backend.error):''}<br>`).join('');}
function policyImpactResult(value,context){
  if(!value||value.read_only!==true||value.model!=='compiled_ingress_intent'||!Array.isArray(value.items)||value.items.length>100||!value.summary||!Number.isSafeInteger(value.total)||value.total<0||!Number.isSafeInteger(value.offset)||value.offset<0||!Number.isSafeInteger(value.limit)||value.limit<1||value.limit>100||value.items.length>value.limit||!Number.isSafeInteger(value.next_offset)||value.next_offset!==value.offset+value.items.length||typeof value.has_more!=='boolean'||!/^([a-f0-9]{64})$/.test(value.context_digest || '')||!value.policy||(value.policy.id || '')!==context.id||value.policy.proposed!==(context.kind==='draft')||value.coverage?.complete_window!==false||!Array.isArray(value.limitations)||value.limitations.length>20)throw new Error('The controller returned an incomplete or foreign impact preview.');
  for(const row of value.items)if(!row||!['would_allow','would_block','unverified'].includes(row.proposed_decision)||!['would_allow','would_block','unverified'].includes(row.current_decision)||!['learning','monitoring'].includes(row.origin)||!['connections','packets','log_records'].includes(row.count_unit)||!Number.isSafeInteger(row.count)||row.count<1||!Number.isInteger(row.port)||row.port<1||row.port>65535||!['tcp','udp'].includes(row.protocol))throw new Error('Impact evidence has an unsupported outcome or count unit.');
  for(const key of ['target_servers','effective_changed_servers','relationships','servers_with_observations'])if(!Number.isSafeInteger(value.summary[key])||value.summary[key]<0)throw new Error('Impact totals are unavailable.');
  return value;
}
function policyImpactResultsHTML(value){
  const summary=value.summary,by=summary.by_outcome || {},coverage=value.coverage || {},targets=value.targets?.items || [];
  return `<div class="inline-notice warning" style="margin-top:16px"><strong>Analysis only · live enforcement is unverified.</strong> Models new inbound TCP/UDP traffic from retained observations. Existing connections, unmonitored dependencies and application success are not proven.</div><div class="detail-grid"><div><dt>Scoped endpoints</dt><dd>${format(summary.target_servers)}</dd></div><div><dt>Changed effective intent</dt><dd>${format(summary.effective_changed_servers)}</dd></div><div><dt>Would block relationships</dt><dd>${format(by.would_block || 0)}</dd></div><div><dt>Would allow relationships</dt><dd>${format(by.would_allow || 0)}</dd></div><div><dt>Unverified relationships</dt><dd>${format(by.unverified || 0)}</dd></div><div><dt>Endpoints without retained observations</dt><dd>${summary.servers_without_observations===null?'Unknown · evaluation bounded':format(summary.servers_without_observations)}</dd></div></div><p class="help-text">${h(timestamp(value.from_time))} to ${h(timestamp(value.as_of))}. Summary includes every outcome for the selected servers, source, ports and window; the table applies the outcome filter. Packets, connections and logs remain separate on each row.</p>${coverage.evaluation_limit_reached?'<p class="form-error">Evaluation limit reached. Totals are lower bounds and do not cover every relationship. Narrow the server, source, port or time scope.</p>':''}${!summary.relationships?'<p class="inline-notice warning">No retained observations match. Dependencies and traffic impact are unknown; this does not mean it is safe to block.</p>':''}<div class="table-container"><table><thead><tr><th>Endpoint / source</th><th>Service</th><th>Current → proposed intent</th><th>Observed evidence / coverage</th></tr></thead><tbody>${value.items.map(row=>`<tr><td><strong>${h(row.hostname || row.server_id)}</strong><br>${h(row.source_ip)}</td><td>${num(row.port)}/${h(row.protocol)}</td><td>${h(policyImpactLabel(row.current_decision))}<br>→ <strong>${h(policyImpactLabel(row.proposed_decision))}</strong><p class="help-text">${h(row.reason)}</p></td><td>${format(row.count)} ${h(row.count_unit)} · ${h(row.capture_kind)}<br>${h(row.origin)} · ${h(row.capture_scope_id)}<br>${h(timestamp(row.first_seen))} – ${h(timestamp(row.last_seen))}<details><summary>Coverage is incomplete${row.coverage?.endpoint_stale?' · endpoint stale':''}${row.coverage?.legacy_sampled_logs?' · sampled legacy logs':''}</summary><p>${row.coverage?.receipt_available?'Latest matching scope receipt available; full-window completeness is unproven.':'No matching collector coverage receipt.'}</p><p>${row.coverage?.dropped_events===null||row.coverage?.dropped_events===undefined?'Loss count unknown':format(row.coverage.dropped_events)+' dropped observations'}${row.coverage?.rate_limited?' · rate limited':''}</p><p>${policyImpactBackendsHTML(row.coverage)}${h((row.coverage?.capture_gaps || []).join('; '))}${row.coverage?.error?' · '+h(row.coverage.error):''}</p></details></td></tr>`).join('') || '<tr><td colspan="4">No relationships on this outcome page. Unknown dependencies remain outside the observation window.</td></tr>'}</tbody></table></div><div class="recommendation-pagination"><span>${value.total_is_lower_bound?'At least ':''}${format(value.total)} matching relationships · ${value.items.length?value.offset+1:0}–${value.offset+value.items.length}</span><div><button type="button" class="button secondary small" data-action="policy-catalogue-impact-page" data-offset="${Math.max(0,value.offset-value.limit)}" ${!value.offset?'disabled':''}>Previous</button><button type="button" class="button secondary small" data-action="policy-catalogue-impact-page" data-offset="${value.next_offset}" ${!value.has_more?'disabled':''}>Next</button></div></div><details><summary>Endpoint scope and unknowns (${format(summary.target_servers)})</summary><p class="help-text">${targets.slice(0,100).map(target=>`${h(target.hostname || target.server_id)}: ${target.has_observations?'retained observations':target.observation_status==='unknown'?'coverage unknown':'no retained observations'}`).join('<br>')}${value.targets?.has_more?'<br>First 100 endpoints shown. Narrow dashboard filters to inspect another subset.':''}</p></details><details><summary>Assumptions and limitations</summary>${value.limitations.map(text=>`<p class="help-text">${h(text)}</p>`).join('')}</details>`;
}
async function policyImpactLoad(context,offset=0,{fresh=false}={}){
  if(!policyImpactAlive(context))return;
  const sequence=++policyImpactSequence,errorElement=$('#policy-impact-error'),output=$('#policy-impact-results');errorElement.hidden=true;
  try{
    const base={...policyImpactOptions(context),...(context.kind==='draft'?policyImpactDraftValue(context.form):{})},fingerprint=JSON.stringify(base);
    if(!fresh&&context.fingerprint&&context.fingerprint!==fingerprint)throw new Error('The draft or filters changed. Click Preview impact again before navigating.');
    const body={...base,offset,...(!fresh&&context.page?{as_of:context.page.as_of,context_digest:context.page.context_digest}:{})};
    output.innerHTML='<p class="help-text">Evaluating retained observations. No configuration changes are being made…</p>';
    const value=await api(context.kind==='draft'?'/policies/impact':'/policies/'+encodeURIComponent(context.id)+'/impact',{method:'POST',body});
    if(!policyImpactAlive(context)||sequence!==policyImpactSequence)return;
    context.page=policyImpactResult(value,context);context.fingerprint=fingerprint;output.innerHTML=policyImpactResultsHTML(value);
  }catch(error){if(!policyImpactAlive(context)||sequence!==policyImpactSequence)return;errorElement.textContent='Impact preview unavailable: '+error.message;errorElement.hidden=false;output.innerHTML='<p class="help-text">No safe/allow/block conclusion was inferred from the failed preview.</p>';}
}
async function policyImpactOpen(id){
  const context={kind:'saved',id,identity:policyImpactIdentity(),scope:policyImpactScope()};policyImpactContext=context;
  showModal('Policy impact preview',`<div class="modal-body">${policyImpactControlsHTML()}</div><div class="modal-footer"><button type="button" class="button secondary" data-action="close-modal">Close</button></div>`,'READ-ONLY POLICY ANALYSIS');
  return policyImpactLoad(context,0,{fresh:true});
}
async function policyImpactAction(button){
  const action=button.dataset.action;if(action==='policy-catalogue-impact')return policyImpactOpen(button.dataset.id);
  if(action==='policy-catalogue-impact-draft'){
    if(!canWrite())return;const form=$('#policy-form');if(!form||!state.activePolicyEditor)return;
    const context={kind:'draft',id:form.dataset.id || '',form,editor:state.activePolicyEditor,identity:policyImpactIdentity(),scope:policyImpactScope()};policyImpactContext=context;return policyImpactLoad(context,0,{fresh:true});
  }
  const context=policyImpactContext;if(!context)return;
  if(action==='policy-catalogue-impact-run')return policyImpactLoad(context,0,{fresh:true});
  if(action==='policy-catalogue-impact-page'){const offset=Number(button.dataset.offset);if(Number.isSafeInteger(offset)&&offset>=0&&offset<=20000)return policyImpactLoad(context,offset);}
}
document.addEventListener('keydown',function policyImpactKeydown(event){if(event.key==='Enter'&&event.target.closest?.('#policy-impact-controls'))event.preventDefault();});
