'use strict';

// Definitions are independent of endpoint assignments. Every list is bounded.
const tagCatalogueState = {identity:'',request:0,loaded:false,loading:false,items:[],total:0,allTotal:null,offset:0,q:'',error:''};
let tagPickerSequence = 0;
let tagCreateSequence = 0;
let tagPickerState = null;
function tagCatalogueIdentity(){return workspaceCSVIdentity();}
function tagCatalogueCheckIdentity(){
  const identity=tagCatalogueIdentity();
  if(tagCatalogueState.identity!==identity){
    Object.assign(tagCatalogueState,{identity,request:tagCatalogueState.request+1,loaded:false,loading:false,items:[],total:0,allTotal:null,offset:0,q:'',error:''});
    tagPickerState=null;tagPickerSequence++;
  }
  return identity;
}
async function loadSavedTags(offset=0,q=tagCatalogueState.q){
  if(!state.authType)return;
  const identity=tagCatalogueCheckIdentity(),request=++tagCatalogueState.request;
  Object.assign(tagCatalogueState,{loading:true,items:[],total:0,error:'',offset,q:String(q).slice(0,200)});
  if(state.view==='tags'&&!$('#modal').open)render();
  try{
    const result=await api(`/tags?limit=200&offset=${offset}&q=${encodeURIComponent(tagCatalogueState.q)}`);
    if(identity!==tagCatalogueIdentity()||request!==tagCatalogueState.request)return;
    Object.assign(tagCatalogueState,{items:result.items||[],total:num(result.total),offset:num(result.offset),loaded:true});
    if(!tagCatalogueState.q)tagCatalogueState.allTotal=num(result.total);
  }catch(error){if(identity===tagCatalogueIdentity()&&request===tagCatalogueState.request)tagCatalogueState.error=error.message;}
  finally{if(identity===tagCatalogueIdentity()&&request===tagCatalogueState.request){tagCatalogueState.loading=false;if(state.view==='tags'&&!$('#modal').open)render();}}
}
function tagMemberServers(tag){return state.data.servers.filter(server=>L.customTags(server.tags)[tag.key]===tag.value);}
function tagCatalogueHTML(){
  tagCatalogueCheckIdentity();
  const groups=state.data.groups||[],section=state.tagsSection==='groups'?'groups':'tags',catalog=tagCatalogueState;
  return `<div class="section-line"><div class="toolbar-group" role="group" aria-label="Tags and server groups"><button class="button ${section==='tags'?'primary':'secondary'}" data-action="tag-catalogue-section" data-section="tags" aria-pressed="${section==='tags'}">Tags${catalog.allTotal!==null?` (${format(catalog.allTotal)})`:''}</button><button class="button ${section==='groups'?'primary':'secondary'}" data-action="tag-catalogue-section" data-section="groups" aria-pressed="${section==='groups'}">Server Groups (${format(groups.length)})</button></div><div class="toolbar-group"><button class="button secondary" data-action="tag-catalogue-new" ${!metadataAdmin()?'disabled':''}>${icon('plus')}Create Tag</button><button class="button secondary" data-action="create-group" ${!canWrite()?'disabled':''}>${icon('plus')}Create Server Group</button></div></div>${section==='groups'?serverGroupCatalogueHTML(groups):`<section class="card table-card"><div class="tag-catalogue-toolbar"><label class="search-field">${icon('search')}<input type="search" id="tag-catalogue-search" value="${h(catalog.q)}" placeholder="Search saved tags…" maxlength="200" aria-label="Search saved tags"></label><button class="button secondary small" data-action="tag-catalogue-search" ${catalog.loading?'disabled':''}>Search</button><button class="button secondary small" data-action="tag-catalogue-refresh" ${catalog.loading?'disabled':''}>Refresh</button></div>${catalog.error?`<div class="inline-notice warning" role="alert">${h(catalog.error)}</div>`:''}<div class="table-scroll"><table><thead><tr><th>Tag</th><th>Assigned servers</th><th></th></tr></thead><tbody>${catalog.items.map(tag=>{const members=tagMemberServers(tag);return `<tr><td><span class="tag">${h(tag.key)} = ${h(tag.value)}</span></td><td>${format(members.length)} server${members.length===1?'':'s'}</td><td><button class="button secondary small" data-action="tag-catalogue-members" data-key="${h(tag.key)}" data-value="${h(tag.value)}">View servers</button></td></tr>`;}).join('')||`<tr><td colspan="3">${catalog.loading?'Loading tags…':catalog.q?'No saved tags match this search.':'No saved tags yet. Create a tag, then select it when assigning servers.'}</td></tr>`}</tbody></table></div><div class="table-footer"><span>${catalog.total?catalog.offset+1:0}–${Math.min(catalog.offset+200,catalog.total)} of ${format(catalog.total)} saved tags</span><div class="toolbar-group"><button class="button secondary small" data-action="tag-catalogue-page" data-offset="${Math.max(0,catalog.offset-200)}" ${!catalog.offset||catalog.loading?'disabled':''}>Previous</button><button class="button secondary small" data-action="tag-catalogue-page" data-offset="${catalog.offset+200}" ${catalog.offset+200>=catalog.total||catalog.loading?'disabled':''}>Next</button></div></div></section>`}`;
}
function serverGroupCatalogueHTML(groups){
  const q=String(state.serverGroupSearch||'').trim().toLowerCase(),matching=groups.filter(group=>[group.name,selectorDescription(group.selector||{})].join(' ').toLowerCase().includes(q)).sort((a,b)=>a.name.localeCompare(b.name));
  const offset=Math.min(num(state.serverGroupOffset),Math.max(0,Math.floor((matching.length-1)/100)*100));state.serverGroupOffset=offset;
  return `<section class="card table-card"><div class="tag-catalogue-toolbar"><label class="search-field">${icon('search')}<input type="search" id="server-group-search" value="${h(state.serverGroupSearch||'')}" maxlength="200" placeholder="Search server groups…" aria-label="Search server groups"></label><button class="button secondary small" data-action="tag-catalogue-group-search">Search</button><span>${format(groups.length)} server groups in total</span></div><div class="table-scroll"><table><thead><tr><th>Server group</th><th>Membership</th><th>Servers</th><th></th></tr></thead><tbody>${matching.slice(offset,offset+100).map(group=>{const members=F.groupMembers(group,state.data.servers);return `<tr><td><strong>${h(group.name)}</strong><small>${group.type==='dynamic'?h(selectorDescription(group.selector)):'Selected servers'}</small></td><td>${automaticGroup(group)?'Automatic application':group.type==='dynamic'?'Dynamic':'Static'}</td><td><strong>${format(members.length)}</strong> servers<small>${members.slice(0,3).map(server=>h(server.hostname)+' · '+h((server.ips||[]).join(', ')||'IP not reported')).join('<br>')}${members.length>3?'<br>+ '+format(members.length-3)+' more':''}</small></td><td><div class="toolbar-group"><button class="button secondary small" data-action="tag-catalogue-group-members" data-id="${h(group.id)}">View servers</button><button class="button secondary small" data-action="edit-group" data-id="${h(group.id)}" ${!canWrite()?'disabled':''}>${automaticGroup(group)?'Rename':'Edit'}</button>${automaticGroup(group)?'':`<button class="button secondary small danger-text" data-action="delete-group" data-id="${h(group.id)}" ${!canWrite()?'disabled':''}>Delete</button>`}</div></td></tr>`;}).join('')||'<tr><td colspan="4">No server groups match. Create a group using saved tags or selected servers.</td></tr>'}</tbody></table></div><div class="table-footer"><span>${matching.length?offset+1:0}–${Math.min(offset+100,matching.length)} of ${format(matching.length)} groups</span><div class="toolbar-group"><button class="button secondary small" data-action="tag-catalogue-group-page" data-offset="${Math.max(0,offset-100)}" ${!offset?'disabled':''}>Previous</button><button class="button secondary small" data-action="tag-catalogue-group-page" data-offset="${offset+100}" ${offset+100>=matching.length?'disabled':''}>Next</button></div></div></section>`;
}
function showTagCreate(){
  if(!metadataAdmin())return;
  showModal('Create Tag',`<form id="tag-catalogue-create-form" data-create-ticket="${++tagCreateSequence}" data-identity="${h(tagCatalogueIdentity())}"><div class="modal-body">${errorSlot}<div class="field"><label for="tag-key">Tag key</label><input id="tag-key" name="key" maxlength="64" pattern="[A-Za-z][A-Za-z0-9_.-]{0,63}" required placeholder="application" autofocus></div><div class="field"><label for="tag-value">Tag value</label><input id="tag-value" name="value" maxlength="128" required placeholder="billing"></div><p class="help-text">Saved tags can be selected for one server, many servers or a dynamic group.</p></div>${modalFooter('Create Tag')}</form>`,'TAG CATALOGUE');
}
async function tagCatalogueSubmit(event){
  event.preventDefault();const form=event.target;if(!metadataAdmin()||form.dataset.identity!==tagCatalogueIdentity())return;
  const identity=tagCatalogueIdentity(),ticket=num(form.dataset.createTicket),fields=new FormData(form),button=$('button[type="submit"]',form);
  const current=()=>identity===tagCatalogueIdentity()&&ticket===tagCreateSequence&&$('#modal').open&&String($('#modal-content').innerHTML).includes(`data-create-ticket="${ticket}"`);
  if(!current())return;button.disabled=true;
  try{
    await api('/tags',{method:'POST',body:{key:String(fields.get('key')||'').trim(),value:String(fields.get('value')||'').trim()}});
    if(identity!==tagCatalogueIdentity())return;
    // Do not close an unrelated dialog opened while the save was in flight.
    if(current())closeModal();
    toast('Tag saved. Select it when assigning servers.');await loadSavedTags(0,'');
  }catch(error){if(current())formError(error);}
  finally{button.disabled=false;}
}
function showTagMembers({groupId,key,value,offset=0}){
  const group=groupId&&(state.data.groups||[]).find(item=>item.id===groupId);if(groupId&&!group)return;
  const members=(group?F.groupMembers(group,state.data.servers):tagMemberServers({key,value})).slice().sort((a,b)=>String(a.hostname||'').localeCompare(String(b.hostname||''))||a.id.localeCompare(b.id));
  offset=Math.min(Math.max(0,num(offset)),Math.max(0,Math.floor((members.length-1)/200)*200));
  const attrs=group?`data-id="${h(group.id)}"`:`data-key="${h(key)}" data-value="${h(value)}"`,action=group?'tag-catalogue-group-members':'tag-catalogue-members';
  showModal(group?group.name:`${key} = ${value}`,`<div class="modal-body"><p class="help-text"><strong>${format(members.length)}</strong> member servers</p><div class="table-scroll"><table><thead><tr><th>Server</th><th>Agent IP addresses</th><th>Location</th><th>Health</th></tr></thead><tbody>${members.slice(offset,offset+200).map(server=>`<tr><td><button class="text-button" data-action="tag-catalogue-server" data-id="${h(server.id)}">${h(server.hostname)}</button></td><td class="mono">${h((server.ips||[]).join(', ')||'Not reported')}</td><td>${serverLocationHTML(server)}</td><td>${serverHealth(server)}</td></tr>`).join('')||'<tr><td colspan="4">No servers currently match.</td></tr>'}</tbody></table></div></div><div class="modal-footer"><span>${members.length?offset+1:0}–${Math.min(offset+200,members.length)} of ${format(members.length)}</span><button class="button secondary" data-action="${action}" ${attrs} data-offset="${Math.max(0,offset-200)}" ${!offset?'disabled':''}>Previous</button><button class="button secondary" data-action="${action}" ${attrs} data-offset="${offset+200}" ${offset+200>=members.length?'disabled':''}>Next</button><button class="button secondary" data-action="close-modal">Close</button></div>`,'MEMBER SERVERS');
}
async function tagCatalogueAction(button){
  if(button.disabled)return;const action=button.dataset.action;
  if(action==='tag-catalogue-new')return showTagCreate();
  if(action==='tag-catalogue-server'){closeModal();return openServer(button.dataset.id);}
  if(action==='tag-catalogue-section'){state.tagsSection=button.dataset.section==='groups'?'groups':'tags';render();if(state.tagsSection==='tags'&&!tagCatalogueState.loaded&&!tagCatalogueState.loading)await loadSavedTags();return;}
  if(action==='tag-catalogue-search')return loadSavedTags(0,$('#tag-catalogue-search').value);
  if(action==='tag-catalogue-refresh')return loadSavedTags(tagCatalogueState.offset);
  if(action==='tag-catalogue-page')return loadSavedTags(num(button.dataset.offset));
  if(action==='tag-catalogue-group-search'){state.serverGroupSearch=$('#server-group-search').value;state.serverGroupOffset=0;render();return;}
  if(action==='tag-catalogue-group-page'){state.serverGroupOffset=num(button.dataset.offset);render();return;}
  if(action==='tag-catalogue-group-members')return showTagMembers({groupId:button.dataset.id,offset:num(button.dataset.offset)});
  if(action==='tag-catalogue-members')return showTagMembers({key:button.dataset.key,value:button.dataset.value,offset:num(button.dataset.offset)});
  if(action==='tag-picker-search')return loadTagPicker(0,$('#saved-tag-search').value);
  if(action==='tag-picker-page')return loadTagPicker(num(button.dataset.offset),tagPickerState?.q||'');
  if(action==='tag-picker-remove')return changeSavedTag(button.dataset.key,button.dataset.value,false);
}

// Keep the established assignment/review fields authoritative. This picker
// edits those same values, so saved-tag selection follows the existing safety flow.
function savedTagPickerHTML(targetId,selectedTags){
  tagPickerState={id:++tagPickerSequence,targetId,selected:selectedTags?{...selectedTags}:null,text:selectedTags?tagString(selectedTags):null,items:[],offset:0,total:0,q:'',error:'',request:0};
  return `<section class="saved-tag-picker" data-tag-picker-id="${tagPickerState.id}"><div class="field-label">Select saved tags</div><div id="saved-tag-selected" class="tag-row"></div><div class="tag-picker-search"><label class="search-field">${icon('search')}<input id="saved-tag-search" type="search" maxlength="200" placeholder="Search tags…" aria-label="Search tags for assignment"></label><button type="button" class="button secondary small" data-action="tag-picker-search">Search</button></div><div id="saved-tag-options"><p class="help-text">Loading saved tags…</p></div><small>Select several tags. Each key has one value; choosing another value updates that key.</small></section>`;
}
function tagPickerCurrent(picker){return picker===tagPickerState&&picker.identity===tagCatalogueIdentity()&&$('#modal').open&&String($('#modal-content').innerHTML).includes(`data-tag-picker-id="${picker.id}"`);}
function savedTagDraftValues(targetId,text){try{return savedTagValues(targetId,text);}catch{return null;}}
function savedTagValues(targetId,text){
  const picker=tagPickerState;
  if(picker?.targetId===targetId&&tagPickerCurrent(picker)&&picker.selected&&String(text||'')===picker.text)return {...picker.selected};
  return parseTags(String(text||''));
}
function tagPickerValues(){const field=tagPickerState&&$('#'+tagPickerState.targetId);return field?savedTagValues(tagPickerState.targetId,field.value):{};}
function tagPickerRender(){
  const picker=tagPickerState;if(!picker||!tagPickerCurrent(picker))return;
  let selected;try{selected=tagPickerValues();}catch{return;}
  $('#saved-tag-selected').innerHTML=Object.entries(selected).map(([key,value])=>`<button type="button" class="tag selected-tag" data-action="tag-picker-remove" data-key="${h(key)}" data-value="${h(value)}" aria-label="Remove ${h(key)} = ${h(value)}">${h(key)} = ${h(value)} <span aria-hidden="true">×</span></button>`).join('')||'<span class="help-text">No tags selected</span>';
  $('#saved-tag-options').innerHTML=`${picker.error?`<p class="form-error">${h(picker.error)}</p>`:''}<div class="saved-tag-options">${picker.items.map(tag=>`<label class="saved-tag-option"><input type="checkbox" data-saved-tag-key="${h(tag.key)}" data-saved-tag-value="${h(tag.value)}" ${selected[tag.key]===tag.value?'checked':''}><span>${h(tag.key)} <strong>= ${h(tag.value)}</strong></span></label>`).join('')||'<p class="help-text">No saved tags match. Create tags in Tags &amp; Groups.</p>'}</div><div class="tag-picker-pager"><span>${picker.total?picker.offset+1:0}–${Math.min(picker.offset+200,picker.total)} of ${format(picker.total)}</span><div class="toolbar-group"><button type="button" class="button secondary small" data-action="tag-picker-page" data-offset="${Math.max(0,picker.offset-200)}" ${!picker.offset?'disabled':''}>Previous</button><button type="button" class="button secondary small" data-action="tag-picker-page" data-offset="${picker.offset+200}" ${picker.offset+200>=picker.total?'disabled':''}>Next</button></div></div>`;
}
async function loadTagPicker(offset=0,q=''){
  const picker=tagPickerState;if(!picker||!state.authType)return;
  picker.identity=tagCatalogueIdentity();picker.offset=offset;picker.q=String(q).slice(0,200);const request=++picker.request;tagPickerRender();
  try{const result=await api(`/tags?limit=200&offset=${offset}&q=${encodeURIComponent(picker.q)}`);if(!tagPickerCurrent(picker)||request!==picker.request)return;Object.assign(picker,{items:result.items||[],total:num(result.total),offset:num(result.offset),error:''});}
  catch(error){if(!tagPickerCurrent(picker)||request!==picker.request)return;picker.error=error.message;}
  if(tagPickerCurrent(picker))tagPickerRender();
}
function changeSavedTag(key,value,checked){
  const picker=tagPickerState;if(!metadataAdmin()||!picker||!tagPickerCurrent(picker))return;
  const field=$('#'+picker.targetId);let selected;try{selected=tagPickerValues();}catch(error){return formError(error);}
  if(checked)selected[key]=value;else if(selected[key]===value)delete selected[key];
  picker.selected={...selected};picker.text=tagString(selected);field.value=picker.text;
  const bulk=picker.targetId==='metadata-tags',mode=$('#metadata-tag-mode');
  if(bulk&&mode)mode.value='merge';
  if(picker.targetId==='group-selector')updateGroupPreview();
  else metadataInput({target:field});
  tagPickerRender();
}
document.addEventListener('change',event=>{if(event.target.dataset?.savedTagKey)changeSavedTag(event.target.dataset.savedTagKey,event.target.dataset.savedTagValue,event.target.checked);});

function groupStaticMembersHTML(selected){
  return `<p class="help-text">Select the member servers. New enrollments are added only to dynamic groups.</p>${endpointPickerHTML('group-endpoints','group_members',state.data.servers,selected,{location:true,bulk:true})}<button type="button" class="button secondary small" data-action="replace-group-snapshot">Use current filtered servers (${format(filteredServers().length)})</button>`;
}
document.addEventListener('change',event=>{if(event.target.name==='group_members')updateGroupPreview();});
