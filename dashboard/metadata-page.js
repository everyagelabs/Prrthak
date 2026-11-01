'use strict';

function metadataAdmin() { return ['admin','super_admin'].includes(state.role); }
function metadataSelection() {
  if (!(state.metadataSelected instanceof Set)) state.metadataSelected = new Set();
  return state.metadataSelected;
}
function metadataSelectedServers() {
  const selected = metadataSelection();
  return (state.data?.servers || []).filter(server => selected.has(server.id));
}
function metadataSourceLabel(source, fallback='Unassigned') {
  const value = typeof source === 'string' ? source : source?.type;
  return ({manual:'Manual override',csv:'CSV IP profile',subnet:'Subnet mapping',unassigned:'Unassigned',conflict:'Mapping conflict'})[value] || fallback;
}
function metadataNoteText(note) { return typeof note==='string'?note:note.message || note.reason || JSON.stringify(note); }
function metadataProvenanceHTML(server) {
  const conflicts = server.metadata_conflicts || [];
  return `<div class="metadata-provenance"><span class="metadata-source">Location: ${h(metadataSourceLabel(server.location_source,server.location_id?'Manual override':'Unassigned'))}${server.location_source?.cidr?' · '+h(server.location_source.cidr):''}</span>${Object.entries(server.tag_sources || {}).map(([key,source])=>`<span class="metadata-source">${h(key)}: ${h(metadataSourceLabel(source,'Central assignment'))}${source?.removed?' (removed)':''}</span>`).join('')}</div>${conflicts.length?`<div class="inline-notice warning">${conflicts.map(conflict=>h(metadataNoteText(conflict))).join('<br>')}</div>`:''}`;
}
function metadataSelectionHTML(list) {
  if (!metadataAdmin()) return '';
  const selected = metadataSelectedServers(), visible = new Set(list.map(server=>server.id)), hidden = selected.filter(server=>!visible.has(server.id)).length;
  return `<div class="metadata-selection-bar"><span><strong>${format(selected.length)}</strong> selected${hidden?` · ${format(hidden)} outside current filters`:''}</span><div><button class="button secondary small" data-action="metadata-select-matching" ${!list.length?'disabled':''}>Select all ${format(list.length)} matching</button><button class="text-button" data-action="metadata-clear-selection" ${!selected.length?'disabled':''}>Clear selection</button><button class="button primary small" data-action="metadata-bulk-edit" ${!selected.length?'disabled':''}>Assign tags & location</button><button class="button secondary small" data-action="metadata-import">Import CSV</button></div></div>`;
}
function metadataSelectionCell(server) {
  return metadataAdmin()?`<td class="metadata-select-cell"><input type="checkbox" data-metadata-select="${h(server.id)}" aria-label="Select ${h(server.hostname)}" ${metadataSelection().has(server.id)?'checked':''}></td>`:'';
}
function metadataSelectionHeader(list) {
  return metadataAdmin()?`<th class="metadata-select-cell"><input type="checkbox" id="metadata-select-all" aria-label="Select all matching servers" ${list.length&&list.every(server=>metadataSelection().has(server.id))?'checked':''} ${!list.length?'disabled':''}></th>`:'';
}
function metadataTagKeys(text) {
  const keys = [...new Set(String(text || '').split(',').map(key=>key.trim()).filter(Boolean))];
  for (const key of keys) {
    if (!/^[A-Za-z][A-Za-z0-9_.-]{0,63}$/.test(key)) throw new Error('Enter tag keys separated by commas, such as application, owner.');
    if (L.isReserved(key)) throw new Error('Use the location controls for DC assignment.');
  }
  return keys;
}
function metadataServerPayload(formData, server) {
  const body = {expected_services:parsePorts(String(formData.get('expected') || ''))};
  if (!metadataAdmin()) return body;
  body.tags = L.assertCustomTags(parseTags(String(formData.get('tags') || '')));
  const mode = $('#server-location-mode')?.value || 'keep', selected = $('#server-location')?.value || null;
  if (mode === 'automatic') body.location_mode = 'automatic';
  else if (mode === 'manual' || selected !== (server?.location_id || null)) body.location_id = selected;
  const reset = metadataTagKeys(formData.get('reset_tag_keys'));
  if (reset.length) body.reset_tag_keys = reset;
  return body;
}
function metadataIndividualFieldsHTML(server, admin) {
  return `${metadataProvenanceHTML(server)}<div class="field"><label for="server-location-mode">Location assignment</label><select id="server-location-mode" name="location_mode" ${!admin?'disabled':''}><option value="keep">Keep current assignment</option><option value="manual">Set a manual override</option><option value="automatic">Return to automatic CSV / subnet mapping</option></select><small>Manual choices stay pinned when IP mappings change. Return to automatic explicitly to remove the override.</small></div><div class="field"><label for="server-location">Saved location</label><select id="server-location" name="location_id" ${!admin?'disabled':''}>${savedLocationOptions(server.location_id || '')}</select><small>Select one saved DC/cloud location, or choose Unassigned for a manual unassigned override. ${!admin?'Administrator access is required to change metadata.':''}</small></div><div class="field"><label for="server-tags">Custom tags</label><textarea id="server-tags" name="tags" rows="3" placeholder="application=billing, network_zone=production, owner=finance" ${!admin?'disabled':''}>${h(tagString(L.customTags(server.tags)))}</textarea><small>Only changed fields become manual overrides; other values keep their current source. Removing a tag here keeps it removed until you reset that key to automatic. Affected access intent is published to eligible endpoints.</small></div><div class="field"><label for="server-reset-tags">Tag keys to return to automatic (optional)</label><input id="server-reset-tags" name="reset_tag_keys" placeholder="application, owner" ${!admin?'disabled':''}><small>Clears manual overrides for these keys so the central CSV profile can provide their values. The agent never supplies business tags.</small></div>`;
}
function showMetadataBulk(ids) {
  if (!metadataAdmin()) return;
  const selected = ids || metadataSelectedServers().map(server=>server.id);
  if (!selected.length) return toast('Select at least one server.',true);
  state.metadataBulkIds = [...new Set(selected)];
  const servers = state.data.servers.filter(server=>state.metadataBulkIds.includes(server.id));
  showModal('Assign tags & location',`<form id="metadata-bulk-form"><div class="modal-body">${errorSlot}<div class="inline-notice">${format(servers.length)} explicit server${servers.length===1?'':'s'} selected. Assignments are central and cannot be overwritten by agent reports. Preview before applying.</div><p class="help-text">${h(servers.slice(0,8).map(server=>server.hostname).join(', '))}${servers.length>8?` · +${format(servers.length-8)} more`:''}</p><div class="field"><label for="metadata-tag-mode">Tag operation</label><select id="metadata-tag-mode" name="tag_mode"><option value="merge">Set / update selected keys</option><option value="remove">Remove selected keys</option><option value="automatic">Return selected keys to automatic</option></select></div><div class="field"><label for="metadata-tags">Tags or keys</label><textarea id="metadata-tags" name="tags" rows="3" placeholder="application=billing, owner=finance"></textarea><small id="metadata-tag-help">Set/update preserves all other tags. For Remove or Return to automatic, enter only comma-separated keys.</small></div><div class="field"><label for="metadata-location-mode">Location operation</label><select id="metadata-location-mode" name="location_mode"><option value="keep">Keep each server's current location</option><option value="manual">Assign a manual location</option><option value="automatic">Return to automatic CSV / subnet mapping</option></select></div><div class="field" id="metadata-location-field" hidden><label for="metadata-location">Saved location</label><select id="metadata-location" name="location_id">${savedLocationOptions()}</select><small>Choosing Unassigned creates an explicit manual override.</small></div><div class="inline-notice warning">Tag/location changes can change group membership and desired policy bundles. This does not authorize firewall enforcement.</div></div>${modalFooter('Preview assignments')}</form>`,'CENTRAL METADATA');
}
function metadataSummaryHTML(summary={}) {
  const labels={rows:'CSV rows',current_servers:'Current servers',future_ips:'Future IP profiles',matched_servers:'Matched servers',changed_servers:'Changed servers',conflicted_servers:'Location conflicts',overridden_fields:'Manual fields preserved'};
  return `<div class="metadata-summary">${Object.entries(summary).filter(([key,value])=>labels[key]&&typeof value==='number').map(([key,value])=>`<span><strong>${format(value)}</strong>${labels[key]}</span>`).join('')}</div>`;
}
function metadataValueHTML(value) {
  if (!value) return '<span class="help-text">No discovered server yet</span>';
  const location = value.location_id ? L.find(value.location_id)?.name || value.location_id : 'Unassigned';
  return `<span>${h(location)}</span><code>${h(tagString(value.tags || {}) || 'No tags')}</code>`;
}
function metadataHasReviewedIntent(plan,kind) {
  if(['subnet','subnet_delete'].includes(kind))return !!plan.payload?.rule?.cidr&&!!plan.payload?.rule?.location_id;
  if(kind==='bulk')return !!plan.payload?.patch&&!!plan.payload?.server_ids?.length;
  return true;
}
function metadataIntentHTML(plan,kind) {
  if(!metadataHasReviewedIntent(plan,kind))return '<div class="inline-notice warning">The reviewed operation definition is missing. Preview again before applying.</div>';
  if(['subnet','subnet_delete'].includes(kind)){
    const rule=plan.payload.rule,location=L.find(rule.location_id),action=kind==='subnet_delete'?'Remove mapping':'Create / update mapping';
    return `<div class="inline-notice" aria-label="Reviewed subnet mapping"><strong>${action}: ${h(rule.cidr)} → ${h(location?.name || rule.location_id)}</strong><br>Mapping name: ${h(rule.name || 'Unnamed mapping')}<br><small>Saved location ID: ${h(rule.location_id)}. ${kind==='subnet_delete'?'Future discoveries stop using this mapping. Other mappings and manual overrides remain.':'Applies to eligible current servers and future matching discoveries. Manual overrides remain.'}</small></div>`;
  }
  if(kind!=='bulk')return '';
  const patch=plan.payload.patch,updates=Object.entries(patch.tag_updates || {}).filter(([,value])=>value!==null),removed=Object.entries(patch.tag_updates || {}).filter(([,value])=>value===null).map(([key])=>key),lines=[];
  if(updates.length)lines.push(`Set manual tags: ${tagString(Object.fromEntries(updates))}`);
  if(removed.length)lines.push(`Remove tags (persistent manual override): ${removed.join(', ')}`);
  if(Object.hasOwn(patch,'tags'))lines.push(`Set custom tag values: ${tagString(patch.tags) || 'No tags'}`);
  if(patch.reset_tag_keys?.length)lines.push(`Return tags to automatic: ${patch.reset_tag_keys.join(', ')}`);
  if(!lines.length)lines.push('Keep custom tags as assigned');
  if(Object.hasOwn(patch,'location_id'))lines.push(`Pin manual location: ${patch.location_id?L.find(patch.location_id)?.name || patch.location_id:'Unassigned'}`);
  else if(patch.location_mode==='automatic')lines.push('Return location to automatic CSV / subnet mapping');
  else if(patch.location_mode==='manual')lines.push('Pin each server’s current location as a manual override');
  else lines.push('Keep locations as assigned');
  return `<div class="inline-notice" aria-label="Reviewed bulk operation"><strong>Reviewed operation · ${format(plan.payload.server_ids.length)} explicit server${plan.payload.server_ids.length===1?'':'s'}</strong><br>${lines.map(h).join('<br>')}</div>`;
}
function metadataSourceDetail(source,fallback='Unassigned') {
  return `${metadataSourceLabel(source,fallback)}${source?.removed?' (removed until reset)':source?.cleared?' (pinned Unassigned)':''}${source?.cidr?' · '+source.cidr:source?.ip?' · '+source.ip:''}`;
}
function metadataRowSourcesHTML(row) {
  const before=row.before,after=row.after,locationSource=row.location_source || after?.location_source,tagSources=row.tag_sources || after?.tag_sources,notes=[];
  if(row.changed&&before&&after){
    const keys=new Set([...Object.keys(before.tags || {}),...Object.keys(after.tags || {})]),sameTags=[...keys].every(key=>before.tags?.[key]===after.tags?.[key]);
    if((before.location_id || null)===(after.location_id || null)&&sameTags)notes.push('Effective values stay the same; the assignment source is updated.');
  }
  if(locationSource)notes.push('Location source after: '+metadataSourceDetail(locationSource));
  if(tagSources)notes.push('Tag sources after: '+(Object.entries(tagSources).map(([key,source])=>`${key}: ${metadataSourceDetail(source,'Central assignment')}`).join('; ') || 'No manual or CSV tag values'));
  return notes.map(note=>`<small>${h(note)}</small>`).join('');
}
function metadataPreviewHTML(plan, kind) {
  const rows = ['csv','csv_profile_delete'].includes(kind) ? plan.rows || [] : plan.items || [], errors = plan.errors || [], summary = plan.summary || plan.counts || {};
  const valid = !!plan.id && !!plan.confirmation_nonce && !errors.length && metadataHasReviewedIntent(plan,kind) && (!plan.expires_at || new Date(plan.expires_at)>new Date()) && !['invalid','applied','expired'].includes(plan.status);
  return `<div class="modal-body">${errorSlot}${kind==='csv_profile_delete'?'<div class="inline-notice warning">Remove this stored IP profile. Manual overrides remain. Eligible servers return to their subnet location or become unassigned. Values supplied by this profile are recalculated.</div>':''}<div class="inline-notice">Manual override → CSV IP profile → subnet location → unassigned. Agent reports cannot assign business tags or location. Review the effective values below.</div>${metadataIntentHTML(plan,kind)}${metadataSummaryHTML(summary)}${errors.length?`<div class="form-error">${errors.slice(0,50).map(error=>h(typeof error==='string'?error:`${error.line || error.row?'Row '+(error.line || error.row)+': ':''}${error.field?error.field+' · ':''}${error.message || JSON.stringify(error)}`)).join('<br>')}</div>`:''}${(plan.warnings || []).length?`<div class="inline-notice warning">${plan.warnings.map(warning=>h(metadataNoteText(warning))).join('<br>')}</div>`:''}<div class="table-scroll metadata-preview-table"><table><thead><tr><th>Server / IP</th><th>Before</th><th>Effective after</th><th>Notes</th></tr></thead><tbody>${rows.slice(0,100).map(row=>`<tr><td><strong>${h(row.hostname || row.ip || row.server_id || 'Server')}</strong>${row.line?`<small>CSV row ${num(row.line)}</small>`:''}</td><td>${metadataValueHTML(row.before || row.profile_before)}</td><td>${kind==='csv_profile_delete'&&!row.after?'<span class="help-text">CSV profile removed. Future discovery uses subnet mapping or remains unassigned.</span>':metadataValueHTML(row.after || row.profile_after)}</td><td>${h(row.status==='future' || row.pending?(kind==='csv_profile_delete'?'Future profile removed':'Stored for future discovery'):row.status || '')}${metadataRowSourcesHTML(row)}${(row.overridden_fields || []).length?`<small>Manual overrides preserved: ${h(row.overridden_fields.join(', '))}</small>`:''}${[...(row.conflicts || []),...(row.warnings || [])].map(note=>`<small>${h(metadataNoteText(note))}</small>`).join('')}</td></tr>`).join('') || '<tr><td colspan="4">No current endpoint values change. A mapping/profile may still apply to future discoveries.</td></tr>'}</tbody></table></div>${rows.length>100?`<p class="help-text">Showing the first 100 of ${format(rows.length)} preview rows. Apply uses the complete reviewed plan.</p>`:''}<p class="help-text">${plan.expires_at?'Review expires '+h(timestamp(plan.expires_at))+'. ':''}Updates are atomic. If assignments or inventory change before apply, review again. New policy bundles require their own rollout authorization.</p></div><div class="modal-footer"><button class="button secondary" data-action="metadata-preview-back">Back</button><button class="button primary" data-action="metadata-plan-apply" ${!valid?'disabled':''}>${kind==='subnet_delete'?'Remove subnet mapping':kind==='csv_profile_delete'?'Remove IP profile':'Apply central assignments'}</button></div>`;
}
function showMetadataPreview(plan, kind, returnId) {
  state.metadataPlan = {plan,kind,returnId};
  showModal(kind==='csv'?'Review CSV import':kind==='csv_profile_delete'?'Review IP profile removal':kind==='bulk'?'Review selected servers':kind==='subnet_delete'?'Review subnet removal':'Review subnet mapping',metadataPreviewHTML(plan,kind),'ASSIGNMENT PREVIEW');
}
async function loadMetadataSubnets() {
  if (state.metadataSubnetLoading) return;
  state.metadataSubnetLoading = true;
  try { state.metadataSubnets = (await api('/metadata/subnets')).items || []; state.metadataSubnetError = ''; }
  catch(error) { state.metadataSubnetError = error.message; }
  finally { state.metadataSubnetLoading = false; if(state.view==='locations'&&!$('#modal').open)render(); }
}
function metadataSubnetsHTML() {
  const records=state.metadataSubnets || [];
  return `<section class="card metadata-subnets"><div class="card-header"><div><h2 class="card-title">Subnet location mappings</h2><p class="card-subtitle">Assign existing and future servers by IP. Manual overrides remain in control.</p></div><button class="button secondary small" data-action="metadata-subnet-new" ${!metadataAdmin()?'disabled':''}>Add subnet mapping</button></div>${state.metadataSubnetError?`<div class="inline-notice warning">${h(state.metadataSubnetError)} <button class="text-button" data-action="metadata-subnet-refresh">Retry</button></div>`:''}<div class="table-scroll"><table><thead><tr><th>Subnet</th><th>Saved location</th><th>Automatic assignments</th><th></th></tr></thead><tbody>${records.map(rule=>`<tr><td><strong>${h(rule.cidr)}</strong>${rule.name?`<small>${h(rule.name)}</small>`:''}</td><td>${h(L.find(rule.location_id)?.name || rule.location_id || 'Unassigned')}</td><td>${format(state.data.servers.filter(server=>server.location_source?.type==='subnet'&&server.location_source?.rule_id===rule.id).length)}</td><td><button class="text-button" data-action="metadata-subnet-edit" data-id="${h(rule.id)}" ${!metadataAdmin()?'disabled':''}>Edit</button><button class="text-button danger-text" data-action="metadata-subnet-delete" data-id="${h(rule.id)}" ${!metadataAdmin()?'disabled':''}>Remove</button></td></tr>`).join('') || '<tr><td colspan="4">No subnet mappings yet. Create a saved DC, then map a network such as 10.241.0.0/16 to it.</td></tr>'}</tbody></table></div><p class="help-text metadata-subnet-note">An exact subnet can be saved only once. A reported IP cannot belong to different DCs; conflicting ownership is flagged and its automatic grouping is withheld. The most specific subnet wins per address: a /24 overrides a /16, and a /16 overrides a /8. For example, 10.0.0.0/8 can belong to Noida while 10.241.7.0/24 belongs to Pune. Different DC matches across a server's addresses create a visible conflict instead of guessing a location. Reset a manual DC to automatic before a mapping can replace it.</p></section>`;
}
function showMetadataSubnet(id) {
  if (!metadataAdmin()) return;
  const rule=(state.metadataSubnets || []).find(item=>item.id===id) || {name:'',cidr:'',location_id:''};
  showModal(id?'Edit subnet mapping':'Add subnet mapping',`<form id="metadata-subnet-form" data-id="${h(id || '')}"><div class="modal-body">${errorSlot}<div class="inline-notice">Map an IP network to one saved DC/cloud location. Current eligible endpoints and future discoveries inherit it centrally. Overlapping networks are allowed: the smaller network wins, so a /24 assigned to Pune overrides a matching /16 or /8 assigned to Noida. Manual assignments take precedence.</div><div class="field"><label for="metadata-subnet-name">Mapping name (optional)</label><input id="metadata-subnet-name" name="name" value="${h(rule.name)}" maxlength="120" placeholder="Noida 81 server network"></div><div class="field"><label for="metadata-subnet-cidr">IP subnet</label><input id="metadata-subnet-cidr" name="cidr" value="${h(rule.cidr)}" placeholder="10.241.0.0/16" required></div><div class="field"><label for="metadata-subnet-location">Saved DC / cloud location</label><select id="metadata-subnet-location" name="location_id" required><option value="">Choose a saved location</option>${L.catalog().map(record=>`<option value="${h(record.id)}" ${rule.location_id===record.id?'selected':''}>${h(record.name)}</option>`).join('')}</select><small>Create the DC in the catalogue first. Mapping a subnet never creates a location from a reported agent value.</small></div></div>${modalFooter('Preview mapping')}</form>`,'CENTRAL SUBNET MAPPING');
}
function showMetadataCSV() {
  if (!metadataAdmin()) return;
  showModal('Import central assignments',`<form id="metadata-csv-form"><div class="modal-body">${errorSlot}<div class="inline-notice">Match existing servers by IP, or store a central profile for an IP that has not enrolled yet. Manual overrides win. Blank cells preserve existing profile values.</div><div class="field"><label for="metadata-csv-file">CSV file</label><input id="metadata-csv-file" type="file" accept=".csv,text/csv"><small>UTF-8 CSV · maximum 1 MiB and 10,000 rows. No server credentials are imported.</small></div><button class="button secondary small" type="button" data-action="metadata-csv-template">Download CSV template</button> <button class="button secondary small" type="button" data-action="metadata-profiles">Manage imported IP profiles</button><div class="field"><label for="metadata-csv-text">CSV contents</label><textarea id="metadata-csv-text" name="csv" rows="8" placeholder="ip,application,dc,network_zone,criticality,tag.owner">${h(state.metadataCSV || '')}</textarea><small>Use existing DC names or IDs. Custom tag columns use tag.key, such as tag.owner. Hostname is inventory from the agent and is not overwritten.</small></div><p class="help-text">All rows are validated before apply. Duplicate/ambiguous IPs and unknown locations must be corrected first. Nothing changes when you choose a file or open this dialog.</p></div>${modalFooter('Preview CSV')}</form>`,'CENTRAL CSV IMPORT');
}
async function showMetadataProfiles(offset=0) {
  if(!metadataAdmin())return;
  const limit=100;offset=Math.max(0,Math.floor(offset/limit)*limit);
  showModal('Imported IP profiles',`<div class="modal-body">${errorSlot}<p class="help-text">Loading imported IP profiles…</p></div>`,'CENTRAL IP ASSIGNMENTS');
  try {
    const result=await api(`/metadata/imports/profiles?limit=${limit}&offset=${offset}`),items=result.items || [],total=num(result.total);
    if(total>0&&offset>=total)return showMetadataProfiles(Math.floor((total-1)/limit)*limit);
    state.metadataProfilesOffset=offset;
    showModal('Imported IP profiles',`<div class="modal-body">${errorSlot}<div class="inline-notice">Imported profiles apply by IP to current or future servers. Removing a profile keeps manual overrides; other fields fall back to subnet location or unassigned. Review effective changes before removal.</div><div class="table-scroll metadata-preview-table"><table><thead><tr><th>IP address</th><th>Profile tags & location</th><th>Discovery binding</th><th></th></tr></thead><tbody>${items.map(item=>`<tr><td><strong>${h(item.ip)}</strong></td><td>${metadataValueHTML(item)}</td><td>${num(item.server_count)>0?`${format(item.server_count)} discovered server${num(item.server_count)===1?'':'s'}`:'Future discovery'}${item.binding_status?`<small>${h(item.binding_status)}</small>`:''}</td><td><button class="text-button danger-text" data-action="metadata-profile-delete" data-id="${h(item.ip)}">Remove</button></td></tr>`).join('') || '<tr><td colspan="4">No imported IP profiles. Import a CSV to create central assignments.</td></tr>'}</tbody></table></div><div class="metadata-selection-bar"><span>${total?`${format(offset+1)}–${format(Math.min(offset+items.length,total))}`:'0'} of ${format(total)} imported profiles</span><div><button class="button secondary small" data-action="metadata-profiles-page" data-offset="${Math.max(0,offset-limit)}" ${offset===0?'disabled':''}>Previous</button><button class="button secondary small" data-action="metadata-profiles-page" data-offset="${offset+limit}" ${offset+items.length>=total?'disabled':''}>Next</button></div></div></div><div class="modal-footer"><button class="button secondary" data-action="metadata-import">Back to CSV import</button><button class="button primary" data-action="close-modal">Done</button></div>`,'CENTRAL IP ASSIGNMENTS');
  }catch(error){formError(error);}
}
async function metadataAction(button) {
  const action=button.dataset.action,id=button.dataset.id;
  if (action==='metadata-subnet-refresh') return loadMetadataSubnets();
  if (!metadataAdmin()) return;
  if(action==='metadata-select-matching'){filteredServers().forEach(server=>metadataSelection().add(server.id));render();return;}
  if(action==='metadata-clear-selection'){metadataSelection().clear();render();return;}
  if(action==='metadata-bulk-edit')return showMetadataBulk();
  if(action==='metadata-import')return showMetadataCSV();
  if(action==='metadata-profiles'){const input=$('#metadata-csv-text');if(input)state.metadataCSV=input.value;return showMetadataProfiles(0);}
  if(action==='metadata-profiles-page')return showMetadataProfiles(Number(button.dataset.offset) || 0);
  if(action==='metadata-profile-delete'){button.disabled=true;try{showMetadataPreview(await api(`/metadata/imports/profiles/${encodeURIComponent(id)}/delete-preview`,{method:'POST',body:{}}),'csv_profile_delete',id);}catch(error){formError(error);}finally{button.disabled=false;}return;}
  if(action==='metadata-subnet-new')return showMetadataSubnet();
  if(action==='metadata-subnet-edit')return showMetadataSubnet(id);
  if(action==='metadata-subnet-delete'){
    button.disabled=true;try{showMetadataPreview(await api(`/metadata/subnets/${encodeURIComponent(id)}/delete-preview`,{method:'POST',body:{}}),'subnet_delete',id);}catch(error){toast(error.message,true);}finally{button.disabled=false;}return;
  }
  if(action==='metadata-preview-back'){const current=state.metadataPlan;if(current?.kind==='csv')return showMetadataCSV();if(current?.kind==='csv_profile_delete')return showMetadataProfiles(state.metadataProfilesOffset || 0);if(current?.kind==='bulk')return showMetadataBulk(state.metadataBulkIds);if(current?.kind==='subnet_delete')return closeModal();return showMetadataSubnet(current?.returnId);}
  if(action==='metadata-plan-apply'){
    const current=state.metadataPlan;if(!current?.plan?.id||!current.plan.confirmation_nonce||(current.plan.errors || []).length||!metadataHasReviewedIntent(current.plan,current.kind))return;
    button.disabled=true;try{const base=['csv','csv_profile_delete'].includes(current.kind)?'/metadata/imports':current.kind==='bulk'?'/metadata/bulk':'/metadata/subnets';await api(`${base}/${encodeURIComponent(current.plan.id)}/apply`,{method:'POST',body:{confirmation_nonce:current.plan.confirmation_nonce}});state.metadataPlan=null;metadataSelection().clear();closeModal();await load();await loadMetadataSubnets();if(current.kind==='csv_profile_delete')await showMetadataProfiles(state.metadataProfilesOffset || 0);toast('Central assignments applied. Affected access intent is published to eligible endpoints.');}catch(error){formError(error);}finally{button.disabled=false;}return;
  }
  if(action==='metadata-csv-template'){
    const data='ip,application,dc,network_zone,criticality,tag.owner\n10.241.1.10,billing,,production,high,finance\n';
    const url=URL.createObjectURL(new Blob([data],{type:'text/csv;charset=utf-8'})),link=document.createElement('a');link.href=url;link.download='prthak-central-assignments.csv';document.body.append(link);link.click();link.remove();URL.revokeObjectURL(url);
  }
}
async function metadataSubmit(event) {
  const form=event.target;if(!['metadata-bulk-form','metadata-subnet-form','metadata-csv-form'].includes(form.id))return false;
  event.preventDefault();const submit=$('button[type="submit"]',form);submit.disabled=true;
  try {
    if(!metadataAdmin())throw new Error('Administrator access is required to change central assignments.');
    const values=new FormData(form);
    if(form.id==='metadata-bulk-form'){
      const body={server_ids:state.metadataBulkIds || []},mode=String(values.get('tag_mode') || 'merge'),text=String(values.get('tags') || '').trim();
      if(!body.server_ids.length)throw new Error('Select at least one explicit server.');
      if(text){if(mode==='merge')body.tag_updates=L.assertCustomTags(parseTags(text));else if(mode==='remove')body.tag_updates=Object.fromEntries(metadataTagKeys(text).map(key=>[key,null]));else body.reset_tag_keys=metadataTagKeys(text);}
      const location=String(values.get('location_mode') || 'keep');if(location==='automatic')body.location_mode='automatic';else if(location==='manual')body.location_id=String(values.get('location_id') || '') || null;
      if(Object.keys(body).length===1)throw new Error('Choose a tag or location change to preview.');
      showMetadataPreview(await api('/metadata/bulk/preview',{method:'POST',body}),'bulk');
    }else if(form.id==='metadata-subnet-form'){
      const body={name:String(values.get('name') || '').trim(),cidr:String(values.get('cidr') || '').trim(),location_id:String(values.get('location_id') || '')};if(form.dataset.id)body.id=form.dataset.id;
      if(!body.cidr||!body.location_id)throw new Error('Enter a subnet and choose an existing saved location.');
      showMetadataPreview(await api('/metadata/subnets/preview',{method:'POST',body}),'subnet',form.dataset.id);
    }else{
      state.metadataCSV=String(values.get('csv') || '');if(!state.metadataCSV.trim())throw new Error('Choose or paste a CSV file first.');
      if(new TextEncoder().encode(state.metadataCSV).length>1024*1024)throw new Error('CSV contents exceed the 1 MiB limit.');
      showMetadataPreview(await api('/metadata/imports/preview',{method:'POST',body:{csv:state.metadataCSV}}),'csv');
    }
  }catch(error){formError(error);}finally{submit.disabled=false;}
  return true;
}
function metadataChange(event) {
  if(event.target.dataset?.metadataSelect){if(metadataAdmin()){const selected=metadataSelection();event.target.checked?selected.add(event.target.dataset.metadataSelect):selected.delete(event.target.dataset.metadataSelect);render();}return true;}
  if(event.target.id==='metadata-select-all'){if(metadataAdmin()){filteredServers().forEach(server=>event.target.checked?metadataSelection().add(server.id):metadataSelection().delete(server.id));render();}return true;}
  if(event.target.id==='metadata-location-mode'){const field=$('#metadata-location-field');if(field)field.hidden=event.target.value!=='manual';return true;}
  if(event.target.id==='server-location'){if(metadataAdmin()&&$('#server-location-mode'))$('#server-location-mode').value='manual';return true;}
  if(event.target.id==='metadata-csv-file'){
    const file=event.target.files?.[0];if(!file)return true;if(file.size>1024*1024){formError(new Error('CSV file exceeds the 1 MiB limit.'));return true;}
    file.text().then(text=>{state.metadataCSV=text;const input=$('#metadata-csv-text');if(input)input.value=text;}).catch(()=>formError(new Error('Could not read this CSV file.')));return true;
  }
  return false;
}
