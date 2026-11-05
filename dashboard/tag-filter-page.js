'use strict';

let tagFilterPicker = null;
let tagFilterSequence = 0;
const tagFilterCategories = ['application','network_zone','criticality'];

function tagFilterAuthenticated() {
  return !!state.authType&&!state.passwordChangeRequired&&['read_only','admin','super_admin'].includes(state.role);
}
function tagFilterClose() {
  const picker=tagFilterPicker;tagFilterPicker=null;
  if(!picker)return;
  if(picker.timer)clearTimeout(picker.timer);
  picker.sequence++;picker.draft=null;picker.page=null;picker.q='';picker.error='';
}
function tagFilterModalChanged(content) {
  const picker=tagFilterPicker;
  if(picker&&(!tagFilterAuthenticated()||picker.identity!==workspaceCSVIdentity()||!String(content).includes(`data-tag-filter-id="${picker.id}"`)))tagFilterClose();
}
function tagFilterCurrent(picker) {
  if(!picker||picker!==tagFilterPicker)return false;
  if(!tagFilterAuthenticated()||picker.identity!==workspaceCSVIdentity()||!$('#modal')?.open
      ||!String($('#modal-content')?.innerHTML || '').includes(`data-tag-filter-id="${picker.id}"`)){
    tagFilterClose();return false;
  }
  return true;
}
function tagFilterValues(filters, key) {
  const values=tagFilterCategories.includes(key) ? filters[key] : filters.custom?.[key];
  return Array.isArray(values)?values:[];
}
function tagFilterCount(filters) {
  return tagFilterCategories.reduce((total,key)=>total+(filters[key]?.length || 0),0)
    + Object.values(filters.custom || {}).reduce((total,values)=>total+values.length,0);
}
function savedTagFilterHTML() {
  if(tagFilterPicker&&(!tagFilterAuthenticated()||tagFilterPicker.identity!==workspaceCSVIdentity()))tagFilterClose();
  const count=tagFilterCount(state.filters);
  return `<button type="button" class="button secondary small saved-tag-filter-button" data-action="tag-filter-open" aria-label="Choose saved tag filters">Tags${count?`<span class="tag-filter-count">${format(count)}</span>`:''}${icon('filter')}</button>`;
}
function tagFilterResultsHTML(picker=tagFilterPicker) {
  if(!picker)return '';
  if(picker.loading)return '<p class="help-text" role="status">Loading tags…</p>';
  if(picker.error)return `<div class="form-error" role="alert">${h(picker.error)}</div><button type="button" class="button secondary small" data-action="tag-filter-retry">Try again</button>`;
  const page=picker.page,items=page?.items || [],offset=page?.offset || 0;
  return `<div class="saved-tag-filter-list" role="group" aria-label="Saved tag choices">${items.map(row=>`<label class="host-check"><input type="checkbox" data-action="tag-filter-select" data-key="${h(row.key)}" data-value="${h(row.value)}" ${tagFilterValues(picker.draft,row.key).includes(row.value)?'checked':''}><span><strong>${h(row.key)}</strong><small>${h(row.value)}</small></span></label>`).join('') || '<p class="help-text">No saved tags match this search.</p>'}</div><div class="table-footer saved-tag-filter-footer"><span>${items.length?format(offset+1):0}–${format(offset+items.length)} of ${format(page?.total || 0)} tags</span><div><button type="button" class="button secondary small" data-action="tag-filter-page" data-offset="${Math.max(0,offset-200)}" ${!offset?'disabled':''}>Previous</button><button type="button" class="button secondary small" data-action="tag-filter-page" data-offset="${offset+200}" ${!page?.has_more?'disabled':''}>Next</button></div></div>`;
}
function redrawTagFilterResults() {
  if(!tagFilterCurrent(tagFilterPicker))return;
  const result=$('#tag-filter-results');if(result)result.innerHTML=tagFilterResultsHTML();
  const count=$('#tag-filter-selected');if(count&&tagFilterPicker)count.textContent=`${format(tagFilterCount(tagFilterPicker.draft))} tag filters selected`;
}
async function loadTagFilterPage(offset=0) {
  const picker=tagFilterPicker;if(!tagFilterCurrent(picker))return;
  const sequence=++picker.sequence,q=picker.q;
  picker.offset=offset;picker.loading=true;picker.error='';redrawTagFilterResults();
  try {
    const result=await api('/tags?limit=200&offset='+offset+'&q='+encodeURIComponent(q));
    if(!tagFilterCurrent(picker)||sequence!==picker.sequence)return;
    if(!Array.isArray(result.items)||result.items.length>200)throw new Error('Saved tag results are unavailable. Try again.');
    picker.page={...result,offset,items:result.items.filter(row=>typeof row.key==='string'&&/^[A-Za-z][A-Za-z0-9_.-]{0,63}$/.test(row.key)&&!L.isReserved(row.key)&&typeof row.value==='string'&&row.value.length>0&&row.value.length<=128)};
  } catch(error) {
    if(!tagFilterCurrent(picker)||sequence!==picker.sequence)return;
    picker.error=error.message || 'Could not load saved tags.';
  } finally {
    if(tagFilterCurrent(picker)&&sequence===picker.sequence){picker.loading=false;redrawTagFilterResults();}
  }
}
function showTagFilter() {
  if(!tagFilterAuthenticated()){tagFilterClose();return;}
  tagFilterClose();
  tagFilterPicker={id:++tagFilterSequence,identity:workspaceCSVIdentity(),draft:JSON.parse(JSON.stringify(state.filters)),q:'',sequence:0,loading:true,error:'',page:null};
  showModal('Filter by tags',`<div class="modal-body" data-tag-filter-id="${tagFilterPicker.id}"><div class="field"><label for="tag-filter-search">Find a saved tag</label><input id="tag-filter-search" type="search" maxlength="200" placeholder="Search by tag name or value" autocomplete="off"></div><p class="help-text" id="tag-filter-selected">${format(tagFilterCount(tagFilterPicker.draft))} tag filters selected</p><div id="tag-filter-results" aria-live="polite">${tagFilterResultsHTML()}</div></div><div class="modal-footer"><button type="button" class="button secondary" data-action="tag-filter-cancel">Cancel</button><button type="button" class="button primary" data-action="tag-filter-apply">Apply filters</button></div>`,'SAVED TAGS');
  if(!tagFilterCurrent(tagFilterPicker))return;
  $('#tag-filter-search')?.focus();
  return loadTagFilterPage();
}
function tagFilterInput(event) {
  if(event.target.id!=='tag-filter-search'||!tagFilterCurrent(tagFilterPicker))return false;
  const picker=tagFilterPicker;
  picker.q=event.target.value.slice(0,200);picker.sequence++;picker.loading=true;picker.error='';
  if(picker.timer)clearTimeout(picker.timer);
  redrawTagFilterResults();
  picker.timer=setTimeout(()=>{if(tagFilterCurrent(picker))loadTagFilterPage(0);},250);
  return true;
}
async function tagFilterAction(button) {
  const action=button.dataset.action;
  if(action==='tag-filter-open')return showTagFilter();
  const picker=tagFilterPicker;if(!tagFilterCurrent(picker)||button.disabled)return;
  if(action==='tag-filter-page'){
    const offset=Number(button.dataset.offset);
    if(picker.loading||!Number.isInteger(offset)||offset<0||offset>10000)return;
    if(picker.timer)clearTimeout(picker.timer);
    return loadTagFilterPage(offset);
  }
  if(action==='tag-filter-retry')return loadTagFilterPage(picker.offset || 0);
  if(action==='tag-filter-select'){
    const {key,value}=button.dataset;
    if(!picker.page?.items.some(row=>row.key===key&&row.value===value))return;
    const values=tagFilterValues(picker.draft,key),selected=!!button.checked;
    const next=selected?[...new Set([...values,value])]:values.filter(item=>item!==value);
    if(tagFilterCategories.includes(key))picker.draft[key]=next;
    else {picker.draft.custom ||= {};if(next.length)picker.draft.custom[key]=next;else delete picker.draft.custom[key];}
    const count=$('#tag-filter-selected');if(count)count.textContent=`${format(tagFilterCount(picker.draft))} tag filters selected`;
    return;
  }
  if(action==='tag-filter-apply'){
    for(const key of tagFilterCategories)state.filters[key]=[...(picker.draft[key] || [])];
    state.filters.custom=JSON.parse(JSON.stringify(picker.draft.custom || {}));
    tagFilterClose();
    closeModal();render();return;
  }
  if(action==='tag-filter-cancel'){tagFilterClose();closeModal();}
}
