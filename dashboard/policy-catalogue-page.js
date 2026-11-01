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
  return `<div class="recommendation-pagination"><span>${page.total===null?(page.error?'Matching total unavailable for ':'Loading matching ')+definition.label:`Loaded ${format(count)} · ${first}–${last} of ${format(page.total)} matching ${definition.label}`}${page.loading?' · Loading…':''}</span><div><button class="button secondary small" data-action="policy-catalogue-page" data-kind="${kind}" data-offset="${page.history?.at(-1) ?? 0}" ${!page.offset||page.loading?'disabled':''}>Previous</button><button class="button secondary small" data-action="policy-catalogue-page" data-kind="${kind}" data-offset="${page.next_offset ?? page.offset+page.limit}" ${!page.has_more||page.loading?'disabled':''}>Next</button><button class="text-button" data-action="policy-catalogue-page" data-kind="${kind}" data-offset="${page.offset}" ${page.loading?'disabled':''}>Refresh</button></div></div>${page.error?`<p class="form-error">${h(page.error)}</p>`:''}<p class="help-text">Combined application, DC, group, port and search filters select the full catalogue before pagination. Cards show only the loaded page; source addresses load from exact policy details.</p>`;
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
async function showPolicyCatalogueDetail(kind,id){const token=policyDetailBegin('Loading exact policy');try{const policy=await policyExactFetch(kind,id,token);if(!policy)return;showModal(policy.name || 'Exact policy',`<div class="modal-body"><p class="help-text">Exact saved intent · revision ${num(policy.revision)}. This view does not authorize or prove endpoint enforcement.</p><pre class="detail-json">${h(JSON.stringify(policy,null,2))}</pre></div><div class="modal-footer"><button class="button secondary" data-action="close-modal">Close</button></div>`,'EXACT SAVED POLICY');}catch(error){policyDetailFailure(token,error);}}
async function policyCatalogueAction(button){const {action,kind,id}=button.dataset;if(action==='policy-catalogue-page')return loadPolicyCatalogue(kind,Number(button.dataset.offset));if(action==='policy-catalogue-detail')return showPolicyCatalogueDetail(kind,id);}
async function showPolicy(id){
  if(!canWrite())return;
  if(!id){state.policyDetailRequest=null;renderPolicyEditor({name:'',selector:{},group_ids:[],mode:'monitor',services:[{port:80,protocol:'tcp',sources:[],source_selector:{}}]});return;}
  const token=policyDetailBegin('Loading exact policy for editing');try{const policy=await policyExactFetch('managed',id,token);if(policy&&canWrite())renderPolicyEditor(policy,id);}catch(error){policyDetailFailure(token,error);}
}
async function reviewPolicyRemoval(id){
  if(!canWrite())return;const token=policyDetailBegin('Loading exact policy for removal');try{const policy=await policyExactFetch('managed',id,token);if(!policy||!canWrite())return;state.activePolicyRemoval=policy;showModal('Delete this policy?',`<div class="modal-body">${errorSlot}<p>Remove ${h(policy.name)} · exact revision ${num(policy.revision)}.</p><p class="help-text">Deletion creates new desired bundles. Live changes require a separate reviewed authorization. Review overlapping policies and protected management access.</p><pre class="detail-json">${h(JSON.stringify(policy,null,2))}</pre></div><div class="modal-footer"><button class="button secondary" data-action="close-modal">Cancel</button><button class="button danger" data-action="confirm-delete" data-id="${h(id)}">Delete policy</button></div>`,'EXACT POLICY REMOVAL');}catch(error){policyDetailFailure(token,error);}
}
