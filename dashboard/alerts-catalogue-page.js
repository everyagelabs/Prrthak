'use strict';

let alertCatalogueSequence=0;
function alertCatalogueIdentity(){return JSON.stringify([state.authType,state.role,state.user?.id,state.user?.tenant_id,state.token]);}
function alertCatalogueScopeKey(){return JSON.stringify([state.filters,state.search,state.flowServer,!!state.alertIncludeResolved]);}
function alertCatalogueEmptyScopeKey(){return JSON.stringify([F.empty(),'','all',false]);}
function alertCatalogueRecord(page,scopeKey){
  if(!page||!Array.isArray(page.items)||page.items.length>100||!Number.isSafeInteger(page.limit)||page.limit<1||page.limit>100||page.items.length>page.limit||!Number.isSafeInteger(page.offset)||page.offset<0||typeof page.has_more!=='boolean')throw new Error('The controller did not return a bounded alert page.');
  for(const key of ['total','all_count','unresolved_count','critical_count','unacknowledged_count','open_count'])if(!Number.isSafeInteger(page[key])||page[key]<0)throw new Error('The controller did not return exact alert counts.');
  if(typeof page.include_resolved!=='boolean'||page.total!==(page.include_resolved?page.all_count:page.unresolved_count)||page.unresolved_count>page.all_count||page.critical_count>page.unresolved_count||page.unacknowledged_count>page.unresolved_count||page.open_count>page.unresolved_count||page.offset+page.items.length>Math.max(page.offset,page.total)||page.has_more!==(page.offset+page.items.length<page.total))throw new Error('The controller returned inconsistent alert counts.');
  return {...page,scopeKey,identity:alertCatalogueIdentity(),remote:true,loading:false,error:''};
}
function alertsReceiveOverview(result){
  if(!result.alert_pagination){state.alertCatalogue=null;state.alertGlobalCounts=null;return;}
  const page=alertCatalogueRecord({...result.alert_pagination,items:result.alerts||[]},alertCatalogueEmptyScopeKey());
  state.alertGlobalCounts=page;
  if(!state.alertCatalogue||state.alertCatalogue.identity!==page.identity||state.alertCatalogue.scopeKey===page.scopeKey&&!state.alertCatalogue.offset){alertCatalogueSequence++;state.alertCatalogue=page;}
}
function alertCataloguePage(){
  const scopeKey=alertCatalogueScopeKey(),current=state.alertCatalogue;
  if(current?.remote){if(current.scopeKey!==scopeKey||current.identity!==alertCatalogueIdentity()){state.alertCatalogue={...current,items:[],total:null,scopeKey,identity:alertCatalogueIdentity(),offset:0,loading:true,error:''};Promise.resolve().then(()=>loadAlertCatalogue(0));}return state.alertCatalogue;}
  return {items:filteredAlerts(),remote:false,loading:false};
}
function alertCatalogueCounts(){const page=alertCataloguePage();return page.remote?{matchedTotal:page.total,total:page.total===null?null:page.unresolved_count,critical:page.total===null?null:page.critical_count,unacknowledged:page.total===null?null:page.unacknowledged_count}:null;}
function alertCatalogueQuery(offset){
  const eligible=state.data.servers.filter(server=>(state.flowServer==='all'||state.flowServer===server.id)&&F.matchServer(server,state.filters,{ignorePorts:true}));
  const scope=F.count({...state.filters,ports:[]})>0||state.flowServer!=='all';
  const search=String(state.search||'');
  return {limit:50,offset,include_resolved:!!state.alertIncludeResolved,server_ids:scope?eligible.map(server=>server.id):null,listener_server_ids:state.filters.ports?.length?eligible.filter(server=>F.matchServer(server,state.filters)).map(server=>server.id):[],search_server_ids:search?eligible.filter(server=>JSON.stringify([server.hostname,server.ips,server.tags,server.os,server.listeners]).toLowerCase().includes(search.toLowerCase())).map(server=>server.id):[],ports:[...(state.filters.ports||[])],search};
}
async function loadAlertCatalogue(offset=0){
  if(!state.authType||!state.data||!Number.isSafeInteger(offset)||offset<0)return;
  const current=alertCataloguePage();if(!current.remote)return;
  const scopeKey=alertCatalogueScopeKey(),identity=alertCatalogueIdentity(),sequence=++alertCatalogueSequence;
  state.alertCatalogue={...current,loading:true,error:''};
  try{const page=await api('/alerts/query',{method:'POST',body:alertCatalogueQuery(offset)});if(sequence!==alertCatalogueSequence||scopeKey!==alertCatalogueScopeKey()||identity!==alertCatalogueIdentity()||!state.authType)return;if(page.offset!==offset||page.include_resolved!==!!state.alertIncludeResolved)throw new Error('The controller returned a different alert navigation scope.');state.alertCatalogue=alertCatalogueRecord(page,scopeKey);}
  catch(error){if(sequence!==alertCatalogueSequence||scopeKey!==alertCatalogueScopeKey()||identity!==alertCatalogueIdentity()||!state.authType)return;state.alertCatalogue={...state.alertCatalogue,loading:false,error:'Alert catalogue unavailable: '+error.message};}
  if(['alerts','overview'].includes(state.view)&&!$('#modal').open)render();
}
function alertCatalogueFooter(page){
  if(!page.remote)return '';
  const total=page.total===null?'…':format(page.total),start=page.items.length?page.offset+1:0,end=page.offset+page.items.length;
  return `${page.error?`<p class="form-error" role="alert">${h(page.error)} <button class="text-button" data-action="alert-page" data-offset="${page.offset}">Retry</button></p>`:''}<div class="table-footer" aria-live="polite"><span>${page.loading?'Refreshing · ':''}${start}–${end} of ${total} matching alerts${state.alertIncludeResolved?' · includes recovered / resolved':''}</span><div><button class="text-button" data-action="alert-page" data-offset="${Math.max(0,page.offset-page.limit)}" ${page.loading||!page.offset?'disabled':''}>Previous</button><button class="text-button" data-action="alert-page" data-offset="${page.offset+page.items.length}" ${page.loading||!page.has_more?'disabled':''}>Next</button></div></div>`;
}
