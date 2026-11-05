'use strict';

function serviceGroupById(id) { return (state.data?.service_groups || []).find(group=>group.id===id); }
function portList(ports=[]) { return ports.map(port=>`${num(port.port)}/${h(port.protocol)}`).join(', '); }
function serviceGroupPortsHTML(ports=[]) { return ports.map(port=>`<span class="service-pill">${num(port.port)}/${h(port.protocol)}</span>`).join(''); }
let discoveredServiceCache;
function matchingDiscoveredServices(query) {
  const servers=state.data.servers;
  if(discoveredServiceCache?.servers!==servers)discoveredServiceCache={servers,rows:D.catalogue(servers)};
  const search=query.trim().toLowerCase();
  return discoveredServiceCache.rows.filter(row=>`${row.service} ${row.application} ${row.port}/${row.protocol}`.toLowerCase().includes(search));
}
function discoveredServiceResultsHTML() {
  const matches=matchingDiscoveredServices(state.discoveredServiceSearch || '');
  const limit=12,offset=Math.min(state.discoveredServiceOffset || 0,Math.max(0,Math.ceil(matches.length/limit)-1)*limit);
  const rows=matches.slice(offset,offset+limit);
  return `<div class="table-scroll"><table><thead><tr><th>Service</th><th>Application</th><th>Port</th><th>Endpoints</th>${canWrite()?'<th>Action</th>':''}</tr></thead><tbody>${rows.map(row=>`<tr><td><strong>${h(row.service)}</strong></td><td>${h(row.application)}</td><td>${serviceGroupPortsHTML([row])}</td><td>${format(row.endpointCount)}</td>${canWrite()?`<td><button type="button" class="text-button" data-action="service-group-use-discovered" data-port="${row.port}" data-protocol="${row.protocol}">Use port in new group</button></td>`:''}</tr>`).join('') || `<tr><td colspan="${canWrite()?5:4}">No discovered services match.</td></tr>`}</tbody></table></div>${matches.length>limit?`<div class="table-footer"><span>${format(offset+1)}–${format(offset+rows.length)} of ${format(matches.length)}</span><div><button class="text-button" data-action="service-group-discovered-page" data-offset="${Math.max(0,offset-limit)}" ${!offset?'disabled':''}>Previous</button><button class="text-button" data-action="service-group-discovered-page" data-offset="${offset+limit}" ${offset+limit>=matches.length?'disabled':''}>Next</button></div></div>`:''}`;
}
function serviceGroupDiscoveryOptions(query='') {
  const matches=matchingDiscoveredServices(query);
  return matches.slice(0,12).map(row=>`<button type="button" class="button secondary small" data-action="service-group-add-discovered" data-port="${row.port}" data-protocol="${row.protocol}">${h(row.service)} · ${h(row.application)} · ${portList([row])}</button>`).join(' ') +
    (matches.length>12?'<p class="help-text">Search to narrow the list.</p>':matches.length?'':'<p class="help-text">No discovered services match.</p>');
}
function discoveredServicesHTML() {
  return `<section class="card platform-panel"><div class="section-line"><h2>Discovered services</h2><input id="service-group-discovered-search" class="filter-select" type="search" aria-label="Search discovered services by service, application or port" placeholder="Search services" maxlength="120" value="${h(state.discoveredServiceSearch || '')}"></div><p class="help-text">Latest agent reports. Service groups use ports and protocols.</p><div id="service-group-discovered-results">${discoveredServiceResultsHTML()}</div></section>`;
}
function serviceGroupsHTML() {
  const groups=state.data.service_groups || [];
  return `${discoveredServicesHTML()}<div class="section-line"><h2>Service groups<span>${groups.length} reusable groups</span></h2></div><div class="policy-grid">${groups.map(group=>`<article class="card policy-card"><div class="policy-top"><div><h2 class="policy-name">${h(group.name)}</h2><p class="help-text">${h(group.description || 'No description')}</p></div>${badge('r'+num(group.revision),'neutral')}</div><div class="service-pills service-group-port-list">${serviceGroupPortsHTML(group.ports)}</div><div class="policy-footer"><span>${num(group.policy_count)} policy reference${group.policy_count===1?'':'s'}</span><div class="policy-actions"><button class="text-button" data-action="service-group-view" data-id="${h(group.id)}">View</button>${canWrite()?`<button class="text-button" data-action="service-group-edit" data-id="${h(group.id)}">Edit</button><button class="text-button danger-text" data-action="service-group-delete-review" data-id="${h(group.id)}" ${group.policy_count?'disabled':''} title="${group.policy_count?'Remove policy references before deleting':'Delete unused service group'}">Delete</button>`:''}</div></div></article>`).join('') || emptyHTML('No service groups yet','Create a named collection of exact TCP and UDP ports to reuse in policy rules.','services',canWrite()?'Create service group':'','service-group-create')}</div>`;
}
function showServiceGroupEditor(id,viewOnly=false,ports=[]) {
  const group=serviceGroupById(id);if(id&&!group)return;if(!viewOnly&&!canWrite())return;
  if(viewOnly){showModal(group.name,`<div class="modal-body"><p>${h(group.description || 'No description')}</p><div class="service-pills service-group-port-list">${serviceGroupPortsHTML(group.ports)}</div><p class="help-text">Revision ${num(group.revision)} · ${num(group.policy_count)} policy references</p>${(group.policy_ids || []).map(policyId=>`<p>${h(policyCatalogueNavigation('managed',policyId)?.name || policyId)}</p>`).join('')}${group.policy_ids_has_more?`<p class="help-text">Showing the first ${format((group.policy_ids || []).length)} of ${format(group.policy_count)} policy references. Browse the paged policy catalogue for other references.</p>`:''}</div>`,'REUSABLE SERVICE GROUP');return;}
  showModal(id?'Edit service group':'Create service group',`<form id="service-group-form" data-id="${h(id || '')}" data-revision="${num(group?.revision)}"><div class="modal-body">${errorSlot}<div class="field"><label for="service-group-name">Name</label><input id="service-group-name" name="name" value="${h(group?.name || '')}" maxlength="120" required autofocus placeholder="Web application ports"></div><div class="field"><label for="service-group-description">Description</label><textarea id="service-group-description" name="description" maxlength="2000" rows="2">${h(group?.description || '')}</textarea></div><div class="field"><label for="service-group-ports">Exact ports and protocols</label><textarea id="service-group-ports" name="ports" required rows="3" placeholder="443/tcp, 8443/tcp, 53/udp">${portList(group?.ports || ports)}</textarea><small>1–100 distinct port/protocol pairs. Separate entries with commas. Nested groups and port ranges are not supported.</small></div><details class="platform-advanced"><summary>Add discovered services</summary><div class="field"><label for="service-group-discovery-picker-search">Search by service, application or port</label><input id="service-group-discovery-picker-search" type="search" maxlength="120"></div><div id="service-group-discovery-picker-results">${serviceGroupDiscoveryOptions()}</div></details><div id="service-group-impact" aria-live="polite"></div><p class="help-text">Preview the affected policies and endpoints before saving. Saving changes intended configuration; eligible endpoints receive the saved intent automatically.</p></div><div class="modal-footer"><button type="button" class="button secondary" data-action="close-modal">Cancel</button><button type="submit" class="button secondary">Preview impact</button><button type="button" class="button primary" data-action="service-group-save" disabled>Save service group</button></div></form>`,'SERVICE CATALOGUE');
}
function serviceGroupDraft(form) {
  const data=new FormData(form),ports=parsePorts(String(data.get('ports') || '')),name=String(data.get('name') || '').trim();
  if(!name)throw new Error('Enter a service group name.');if(!ports.length||ports.length>100)throw new Error('Provide 1–100 distinct exact port/protocol pairs.');
  const body={name,description:String(data.get('description') || '').trim(),ports};if(form.dataset.id)body.expected_revision=Number(form.dataset.revision);return body;
}
function invalidateServiceGroupReview(form) {
  form.reviewedDraft=null;
  const save=$('[data-action="service-group-save"]',form);
  if(save)save.disabled=true;
  $('#service-group-impact').innerHTML='<p class="help-text">Changes need a new impact preview.</p>';
}
function serviceGroupInput(event) {
  if(event.target.id==='service-group-discovered-search'&&state.view==='services'){
    state.discoveredServiceSearch=event.target.value.slice(0,120);
    state.discoveredServiceOffset=0;
    $('#service-group-discovered-results').innerHTML=discoveredServiceResultsHTML();
    return true;
  }
  if(event.target.id==='service-group-discovery-picker-search'){
    $('#service-group-discovery-picker-results').innerHTML=serviceGroupDiscoveryOptions(event.target.value.slice(0,120));
    return true;
  }
  if(!event.target.closest?.('#service-group-form'))return false;
  const form=$('#service-group-form');if(form)invalidateServiceGroupReview(form);
  return true;
}
async function serviceGroupSubmit(event) {
  event.preventDefault();if(!canWrite())return;const form=event.target,submit=$('button[type="submit"]',form);submit.disabled=true;
  try {
    const body=serviceGroupDraft(form),preview=await api('/service-groups/preview',{method:'POST',body:{...body,...(form.dataset.id?{id:form.dataset.id}:{})}});
    // A response for a superseded draft must never enable Save.
    if($('#service-group-form')!==form||JSON.stringify(body)!==JSON.stringify(serviceGroupDraft(form)))return;
    form.reviewedDraft=body;
    $('#service-group-impact').innerHTML=`<section class="service-group-impact"><h3>Impact preview</h3><p><strong>${num(preview.effective_change_count)}</strong> endpoint bundles change across <strong>${num(preview.target_server_count)}</strong> target endpoints.</p><div class="service-group-diff"><div><strong>Before</strong><p>${preview.before?portList(preview.before.ports):'New group'}</p></div><div><strong>After</strong><p>${portList(preview.after?.ports)}</p></div></div><p>${preview.ports_changed?'Port membership changes.':'Port membership stays the same.'}</p><p><strong>Affected policies</strong></p>${(preview.affected_policies || []).map(policy=>`<p>${h(policy.name)} · r${num(policy.revision)}</p>`).join('') || '<p>No active policy references.</p>'}<p><strong>Endpoints with changed bundles</strong></p><div class="target-preview-members">${(preview.affected_servers || []).map(server=>`<span class="target-member"><span class="target-member-identity"><strong>${h(server.hostname || server.id)}</strong><span class="target-member-addresses">${h((Array.isArray(server.ips)?server.ips:[]).join(', ') || 'IP not reported')}</span></span></span>`).join('') || '<span>No effective endpoint changes.</span>'}</div>${preview.requires_managed_review?'<div class="inline-notice warning">These new bundles require a fresh managed enforcement review.</div>':''}</section>`;
    $('[data-action="service-group-save"]',form).disabled=false;
  }catch(error){form.reviewedDraft=null;if($('#service-group-form')===form)formError(error);if(error.status===409)await load({quiet:true});}finally{submit.disabled=false;}
}
async function serviceGroupAction(button) {
  const {action,id}=button.dataset;
  if(action==='service-group-discovered-page'){
    if(state.view!=='services'||button.disabled)return;
    const offset=Number(button.dataset.offset);
    if(!Number.isSafeInteger(offset)||offset<0)return;
    state.discoveredServiceOffset=offset;
    $('#service-group-discovered-results').innerHTML=discoveredServiceResultsHTML();
    return;
  }
  if(action==='service-group-view')return showServiceGroupEditor(id,true);
  if(!canWrite())return;
  if(['service-group-use-discovered','service-group-add-discovered'].includes(action)){
    const port=Number(button.dataset.port),protocol=button.dataset.protocol;
    if(state.view!=='services'||!Number.isInteger(port)||port<1||port>65535||!['tcp','udp'].includes(protocol))return;
    if(action==='service-group-use-discovered')return showServiceGroupEditor(undefined,false,[{port,protocol}]);
    const form=$('#service-group-form'),field=$('#service-group-ports');
    if(!form||!field)return;
    try {
      const ports=parsePorts(field.value);
      if(ports.some(item=>item.port===port&&item.protocol===protocol))return;
      if(ports.length>=100)throw new Error('A service group can contain up to 100 distinct ports.');
      field.value=portList([...ports,{port,protocol}]);
      invalidateServiceGroupReview(form);
    }catch(error){formError(error);}
    return;
  }
  if(action==='service-group-create')return showServiceGroupEditor();if(action==='service-group-edit')return showServiceGroupEditor(id);
  if(action==='service-group-delete-review')return showConfirm('Delete this service group?','Only unused service groups can be deleted. The controller checks policy references before removal.','Delete service group','service-group-delete-confirm',id);
  if(action==='service-group-delete-confirm'){button.disabled=true;const success=await mutate('/service-groups/'+encodeURIComponent(id),{method:'DELETE'},'Unused service group deleted.');if(!success)button.disabled=false;return;}
  if(action==='service-group-save'){
    const form=$('#service-group-form');if(!form)return;button.disabled=true;
    try {const body=serviceGroupDraft(form);if(!form.reviewedDraft||JSON.stringify(body)!==JSON.stringify(form.reviewedDraft))throw new Error('Preview the current changes before saving.');await api('/service-groups'+(form.dataset.id?'/'+encodeURIComponent(form.dataset.id):''),{method:form.dataset.id?'PUT':'POST',body});closeModal();await load();toast('Service group saved. Affected intent is published to eligible endpoints.');}
    catch(error){form.reviewedDraft=null;formError(error);if(error.status===409){$('#service-group-impact').innerHTML='<p class="form-error">The group changed since you opened it. Close and reopen it, then preview again.</p>';await load({quiet:true});}}
  }
}

let sourceLocationSequence=0;
function ruleHTML(service={port:80,protocol:'tcp',sources:[],source_selector:{}}) {
  const sequence=++sourceLocationSequence,groupMode=!!service.service_group_id,group=serviceGroupById(service.service_group_id),groups=state.data.service_groups || [],locationFieldId='source-location-'+sequence;
  return `<div class="rule-row"><div class="field-row"><div class="field"><label for="rule-type-${sequence}">Service selection</label><select id="rule-type-${sequence}" name="rule_type"><option value="port" ${!groupMode?'selected':''}>Single port</option><option value="group" ${groupMode?'selected':''}>Service group</option></select></div><button class="icon-button" type="button" data-action="remove-rule" aria-label="Remove service">×</button></div><div data-rule-single ${groupMode?'hidden':''}><div class="field-row"><div class="field"><label>Port<input name="rule_port" type="number" value="${groupMode?'':num(service.port)}" min="1" max="65535" ${!groupMode?'required':''} aria-label="Service port"></label></div><div class="field"><label>Protocol<select name="rule_protocol" aria-label="Service protocol"><option value="tcp" ${service.protocol==='tcp'?'selected':''}>TCP</option><option value="udp" ${service.protocol==='udp'?'selected':''}>UDP</option></select></label></div></div></div><div data-rule-group ${!groupMode?'hidden':''}><div class="field"><label for="rule-service-group-${sequence}">Reusable service group</label><select id="rule-service-group-${sequence}" name="rule_service_group" ${groupMode?'required':''}><option value="">Choose a service group</option>${groupMode&&!group?`<option value="${h(service.service_group_id)}" selected>${h(service.service_group_snapshot?.name || 'Unavailable service group')}</option>`:''}${groups.map(item=>`<option value="${h(item.id)}" ${service.service_group_id===item.id?'selected':''}>${h(item.name)} · r${num(item.revision)} · ${portList(item.ports)}</option>`).join('')}</select><div class="service-pills" data-rule-group-ports>${serviceGroupPortsHTML(group?.ports || service.service_group_snapshot?.ports)}</div><small>Every allowed source below applies to every port in this row's service group.</small></div></div><div class="field"><label>Allowed IPs / CIDRs<input name="rule_sources" value="${h((service.sources||[]).join(', '))}" placeholder="10.20.0.0/24, 10.30.0.10" aria-label="Allowed source IPs and CIDRs"></label></div><div class="field"><label>Allowed source tags<input name="rule_selector" value="${h(tagString(L.selectorTags(service.source_selector || {})))}" placeholder="role=load-balancer" aria-label="Allowed source tag selector"></label></div>${locationSelectorField(service.source_selector,locationFieldId,'rule_location_id','Allowed source location (optional)')}<fieldset class="source-server-groups"><legend>Allowed source server groups</legend><div class="host-checklist">${(state.data.groups || []).map(item=>`<label class="host-check"><input type="checkbox" name="rule_source_groups" value="${h(item.id)}" ${(service.source_group_ids || []).includes(item.id)?'checked':''}>${h(item.name)}<span>${item.type==='dynamic'?'Dynamic':'Static'}</span></label>`).join('') || '<p class="help-text">No saved server groups. Create them in Servers.</p>'}</div></fieldset><p class="help-text">Allowed addresses, matching tags/location, and all selected source server groups are combined. This source set applies to every port in this row only. Empty sources allow no addresses.</p></div>`;
}
function policyServiceChange(event) {
  if(!['rule_type','rule_service_group'].includes(event.target.name))return false;const row=event.target.closest('.rule-row');if(!row)return false;const groupMode=$('[name="rule_type"]',row).value==='group';$('[data-rule-single]',row).hidden=groupMode;$('[data-rule-group]',row).hidden=!groupMode;$('[name="rule_port"]',row).required=!groupMode;$('[name="rule_service_group"]',row).required=groupMode;
  const group=serviceGroupById($('[name="rule_service_group"]',row).value);$('[data-rule-group-ports]',row).innerHTML=serviceGroupPortsHTML(group?.ports);return true;
}
function collectPolicyServices(form) {
  const services=$$('.rule-row',form).map(row=>{
    const rule={sources:$('[name="rule_sources"]',row).value.split(',').map(value=>value.trim()).filter(Boolean),source_selector:L.withLocation(parseTags($('[name="rule_selector"]',row).value),$('[name="rule_location_id"]',row)?.value || ''),source_group_ids:$$('[name="rule_source_groups"]:checked',row).map(input=>input.value)};
    if($('[name="rule_type"]',row)?.value==='group'){rule.service_group_id=$('[name="rule_service_group"]',row).value;if(!serviceGroupById(rule.service_group_id))throw new Error('Choose an available reusable service group for each grouped row.');}
    else {rule.port=Number($('[name="rule_port"]',row).value);rule.protocol=$('[name="rule_protocol"]',row).value;}
    return rule;
  });
  const seen=new Set();return services.filter(service=>{
    const key=JSON.stringify([service.service_group_id||null,service.port||null,service.protocol||null,[...new Set(service.sources)].sort(),Object.entries(service.source_selector).sort(([a],[b])=>a.localeCompare(b)),[...new Set(service.source_group_ids)].sort()]);
    if(seen.has(key))return false;seen.add(key);return true;
  });
}
