'use strict';

function savedLocationOptions(selected='',allowAny=false) {
  return `${selected&&!L.find(selected)?`<option value="${h(selected)}" selected>Current assignment · catalogue details unavailable</option>`:''}<option value="">${allowAny?'Any saved location':'Unassigned · choose a saved location'}</option>${L.catalog().map(record=>`<option value="${h(record.id)}" ${selected===record.id?'selected':''}>${h(record.name)} · ${record.type==='cloud'?'Cloud':'DC'}${record.location?' · '+h(record.location):''}</option>`).join('')}`;
}
function locationSelectorField(selector={},id='policy-location',name='location_id',label='Saved location (optional)') {
  const selected=L.selectorLocationId(selector) || '';
  return `<div class="field"><label for="${h(id)}">${h(label)}</label><select id="${h(id)}" name="${h(name)}">${savedLocationOptions(selected,true)}</select><small>Location membership uses a stable catalogue ID, so renaming a location preserves policy targeting.</small></div>`;
}
function selectorDescription(selector={}) {
  const id=L.selectorLocationId(selector),record=id&&L.find(id),tags=L.selectorTags(selector),text=tagString(tags);
  return [record?`Location: ${record.name}`:id?`Unresolved location: ${id}`:'',text].filter(Boolean).join(' · ');
}
function selectorTagsHTML(selector={}) {
  const id=L.selectorLocationId(selector),record=id&&L.find(id);
  return `${id?`<span class="tag location-tag" title="${h(id)}">Location: ${h(record?.name || 'Unresolved assignment')}</span>`:''}${Object.keys(L.selectorTags(selector)).length?tagsHTML(L.selectorTags(selector),true):''}`;
}
function serverLocationHTML(server) {
  const location=L.of(server);
  return `<span class="assigned-location ${location.kind==='unknown'?'unassigned':''}" title="${h(location.id || 'No location assignment')}">${icon(location.kind==='cloud'?'cloud':'locations')}${h(location.label)}</span>`;
}
function locationsHTML() {
  const query=String(state.locationSearch || '').trim().toLowerCase(),records=L.catalog(),matching=records.filter(record=>JSON.stringify([record.name,record.location,record.type,record.provider,record.region]).toLowerCase().includes(query)),unassigned=state.data.servers.filter(server=>!server.location_id);
  return `<div class="inline-notice">Create location names manually before assigning endpoints. Each server has one location field and multiple custom tags. Service discovery and reported tags never create or select a location. Central subnet mappings below can assign eligible servers automatically.</div><div class="location-catalog-toolbar"><label class="search-field">${icon('search')}<input type="search" id="location-catalog-search" value="${h(state.locationSearch || '')}" placeholder="Search names, sites, cloud regions…" aria-label="Search saved locations"></label><span>${matching.length} of ${records.length} saved locations</span></div><div class="location-catalog-stats"><div><strong>${records.filter(record=>record.type==='datacenter').length}</strong><span>Data centres</span></div><div><strong>${records.filter(record=>record.type==='cloud').length}</strong><span>Cloud locations</span></div><button data-action="location-view-unassigned"><strong>${format(unassigned.length)}</strong><span>Unassigned endpoints ↗</span></button><p>Assignment counts use the whole fleet. Location names and addresses are display metadata; policy bindings use immutable IDs.</p></div><div class="location-catalog-grid">${matching.map(record=>{
    const members=state.data.servers.filter(server=>server.location_id===record.id),ids=new Set(members.map(server=>server.id)),healthy=members.filter(server=>server.status==='healthy').length,alerts=state.data.alerts.filter(alert=>ids.has(alert.server_id)&&F.unresolved(alert)).length;
    return `<article class="card location-catalog-card"><div class="location-card-heading"><span class="location-card-icon">${icon(record.type==='cloud'?'cloud':'locations')}</span><div><h2>${h(record.name)}</h2><p>${record.type==='cloud'?'Cloud location':'Data centre'}${record.synthetic?' · Synthetic demo':''}</p></div></div><dl><div><dt>Site / location</dt><dd>${h(record.location || 'Not specified')}</dd></div>${record.type==='cloud'?`<div><dt>Provider · region</dt><dd>${h(L.providerNames[record.provider] || record.provider || 'Unspecified provider')} · ${h(record.region || 'Unspecified region')}</dd></div>`:''}</dl><div class="location-card-counts"><span><strong>${format(members.length)}</strong> endpoint${members.length===1?'':'s'}</span><span><strong>${format(healthy)}</strong> healthy</span><span><strong>${format(alerts)}</strong> open alerts</span></div><code class="managed-digest">${h(record.id)}</code><div class="location-card-actions"><button class="text-button" data-action="location-view-servers" data-id="${h(record.id)}">View endpoints ↗</button><button class="text-button" data-action="location-edit" data-id="${h(record.id)}" ${!['admin','super_admin'].includes(state.role)?'disabled':''}>Edit</button><button class="text-button danger-text" data-action="location-delete-review" data-id="${h(record.id)}" ${!['admin','super_admin'].includes(state.role)||members.length?'disabled':''} title="${members.length?'Reassign endpoints before deleting this location':'Delete unused catalogue location'}">Delete</button></div></article>`;
  }).join('') || '<div class="managed-empty">No saved locations match. Administrators can create data centres or cloud locations before assigning endpoints.</div>'}</div>${!['admin','super_admin'].includes(state.role)?'<p class="help-text">Administrators manage locations and endpoint assignments. Other roles can view the catalogue.</p>':''}${metadataSubnetsHTML()}`;
}
function locationMapFields(record) {
  const map = globalThis.PSegraTopology, selected = record.country_code || '';
  const codes = map?.countries() || [];
  return `<details class="managed-full-configuration" ${selected?'open':''}><summary>Map position (optional)</summary>
    <div class="field"><label for="location-country">Country</label><select id="location-country" name="country_code"><option value="">Infer from saved city or cloud region</option>
      ${selected&&!codes.includes(selected)?`<option value="${h(selected)}" selected>${h(selected)}</option>`:''}
      ${codes.map(code=>`<option value="${h(code)}" ${code===selected?'selected':''}>${h(map.countryName(code))}</option>`).join('')}
    </select></div>
    <div class="field"><label for="location-latitude">Latitude</label><input id="location-latitude" name="latitude" type="number" step="any" min="-90" max="90" value="${h(record.latitude ?? '')}" placeholder="28.5355"></div>
    <div class="field"><label for="location-longitude">Longitude</label><input id="location-longitude" name="longitude" type="number" step="any" min="-180" max="180" value="${h(record.longitude ?? '')}" placeholder="77.3910"><small>Enter both coordinates and a country for an exact pin.</small></div>
  </details>`;
}
function showLocationEditor(id) {
  if(!['admin','super_admin'].includes(state.role))return;
  const record=L.find(id) || {name:'',location:'',type:'datacenter',provider:'',region:''};
  showModal(id?'Edit saved location':'Create a saved location',`<form id="location-form" data-id="${h(id || '')}"><div class="modal-body">${errorSlot}<div class="inline-notice">Location names are created here, then assigned centrally to servers with individual/bulk edits, CSV profiles or subnet mappings. Renaming a location preserves its ID and policy bindings.</div><div class="field"><label for="location-name">Location name</label><input id="location-name" name="name" value="${h(record.name)}" maxlength="120" required placeholder="Hyderabad primary DC" autofocus></div><div class="field"><label for="location-description">Site / location</label><input id="location-description" name="location" value="${h(record.location)}" maxlength="200" required placeholder="Hyderabad · facility A"><small>Describe the city, facility or cloud site. This is not inferred from endpoint addresses.</small></div><div class="field"><label for="location-type">Location type</label><select id="location-type" name="type"><option value="datacenter" ${record.type==='datacenter'?'selected':''}>Physical data centre</option><option value="cloud" ${record.type==='cloud'?'selected':''}>Cloud location</option></select></div><div id="location-cloud-fields" ${record.type!=='cloud'?'hidden':''}><div class="field"><label for="location-provider">Cloud provider</label><select id="location-provider" name="provider"><option value="">Unspecified</option>${record.provider&&!L.providerNames[record.provider]?`<option value="${h(record.provider)}" selected>${h(record.provider)}</option>`:''}${Object.entries(L.providerNames).map(([value,label])=>`<option value="${value}" ${record.provider===value?'selected':''}>${h(label)}</option>`).join('')}</select></div><div class="field"><label for="location-region">Cloud region</label><input id="location-region" name="region" value="${h(record.region || '')}" maxlength="120" placeholder="ap-south-1"><small>Use the actual provider region. Unknown values remain unspecified.</small></div></div>${locationMapFields(record)}${id?`<div class="field-label">Immutable location ID</div><code class="managed-digest">${h(record.id)}</code><details class="managed-full-configuration"><summary>Preserved policy aliases</summary><p class="help-text">${h((record.aliases || []).join(', ') || 'No legacy aliases recorded')}</p></details>`:''}</div>${modalFooter(id?'Save location':'Create location')}</form>`,'MANUAL LOCATION CATALOGUE');
}
async function locationAction(button) {
  const action=button.dataset.action,id=button.dataset.id;
  if(action==='location-create')return showLocationEditor();
  if(action==='location-edit')return showLocationEditor(id);
  if(action==='location-view-servers'){state.filters.locations=['location:'+id];navigate('servers');return;}
  if(action==='location-view-unassigned'){state.filters.locations=['unknown'];navigate('servers');return;}
  if(!['admin','super_admin'].includes(state.role))return;
  if(action==='location-delete-review')return showConfirm('Delete this saved location?','Assigned endpoints must be reassigned first. Locations referenced by policies or groups cannot be deleted. The controller checks all references before removing an unused record.','Delete location','location-delete-confirm',id);
  if(action==='location-delete-confirm'){button.disabled=true;const success=await mutate(`/locations/${encodeURIComponent(id)}`,{method:'DELETE'},'Unused location deleted.');if(!success)button.disabled=false;}
}
async function locationSubmit(event) {
  event.preventDefault();const form=event.target,submit=$('button[type="submit"]',form);submit.disabled=true;
  try {
    if(!['admin','super_admin'].includes(state.role))throw new Error('Administrator access is required to manage the location catalogue.');
    const values=new FormData(form),type=String(values.get('type')),body={name:String(values.get('name') || '').trim(),location:String(values.get('location') || '').trim(),type,provider:type==='cloud'?String(values.get('provider') || ''):'',region:type==='cloud'?String(values.get('region') || '').trim():''};
    body.country_code=String(values.get('country_code') || '');
    for(const field of ['latitude','longitude'])body[field]=values.get(field)?Number(values.get(field)):null;
    if((body.latitude!==null || body.longitude!==null) && (!body.country_code || !Number.isFinite(body.latitude) || !Number.isFinite(body.longitude)))throw new Error('Choose a country and enter both map coordinates.');
    if(!body.name)throw new Error('Enter a location name.');if(!body.location)throw new Error('Enter the geographic site or location.');
    await api(`/locations${form.dataset.id?'/'+encodeURIComponent(form.dataset.id):''}`,{method:form.dataset.id?'PUT':'POST',body});closeModal();await load();toast('Location saved. Its stable ID preserves existing policy targeting.');
  }catch(error){formError(error);}finally{submit.disabled=false;}
}
