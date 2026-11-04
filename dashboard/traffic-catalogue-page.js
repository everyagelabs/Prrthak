'use strict';

let trafficCatalogueSequence=0,trafficExportSequence=0;
function trafficCatalogueEnabled(){return state.data?.meta?.traffic_query_v1===true;}
function trafficCatalogueIdentity(){return JSON.stringify([state.authType,state.role,state.user?.id,state.user?.tenant_id,state.token]);}
function trafficCatalogueScopeValues(){
  const eligible=state.data.servers.filter(server=>(state.flowServer==='all'||state.flowServer===server.id)&&F.matchServer(server,state.filters,{ignorePorts:true}));
  const scoped=F.count({...state.filters,ports:[]})>0||state.flowServer!=='all',search=String(state.search||'');
  return {purpose:'traffic',window_seconds:state.window,server_ids:scoped?eligible.map(server=>server.id).sort():null,search_server_ids:search?eligible.filter(server=>JSON.stringify([server.hostname,server.ips,server.tags,server.os]).toLowerCase().includes(search.toLowerCase())).map(server=>server.id).sort():[],ports:[...(state.filters.ports||[])],search};
}
function trafficCatalogueScopeKey(){return JSON.stringify(trafficCatalogueScopeValues());}
function trafficCatalogueRecord(page,scopeKey){
  if(page?.purpose!=='traffic')throw new Error('The controller did not confirm the traffic discovery scope.');
  if(!page||!Array.isArray(page.items)||page.items.length>100||!Number.isSafeInteger(page.limit)||page.limit<1||page.limit>100||page.items.length>page.limit||!Number.isSafeInteger(page.offset)||page.offset<0||!Number.isSafeInteger(page.total)||page.total<0||!Number.isSafeInteger(page.endpoint_count)||page.endpoint_count<0||page.endpoint_count>page.total||typeof page.has_more!=='boolean'||page.has_more!==(page.offset+page.items.length<page.total)||page.offset+page.items.length>Math.max(page.offset,page.total)||page.filter_before_pagination!==true)throw new Error('The controller did not return a bounded, completely filtered traffic page.');
  if(!Number.isSafeInteger(page.window_seconds)||page.window_seconds!==state.window||!Number.isFinite(Date.parse(page.as_of))||!Number.isFinite(Date.parse(page.from_time))||Date.parse(page.from_time)>Date.parse(page.as_of)||typeof page.coverage!=='string'||page.coverage.length>2048)throw new Error('The controller returned an invalid traffic window.');
  if(!page.counts_by_unit||['connections','packets','log_records'].some(unit=>!Number.isSafeInteger(page.counts_by_unit[unit])||page.counts_by_unit[unit]<0))throw new Error('The controller did not preserve separate traffic count units.');
  if('sample_minutes' in page.counts_by_unit&&(!Number.isSafeInteger(page.counts_by_unit.sample_minutes)||page.counts_by_unit.sample_minutes<0))throw new Error('The controller returned an invalid communication sample count.');
  return {...page,scopeKey,identity:trafficCatalogueIdentity(),remote:true,loading:false,pending:false,error:''};
}
function trafficCataloguePage(){
  if(!trafficCatalogueEnabled())return null;
  const scopeKey=trafficCatalogueScopeKey(),identity=trafficCatalogueIdentity(),current=state.trafficCatalogue;
  if(!current||current.scopeKey!==scopeKey||current.identity!==identity){
    state.trafficCatalogue={items:[],total:null,endpoint_count:null,counts_by_unit:{},offset:0,limit:50,has_more:false,scopeKey,identity,remote:true,loading:true,pending:true,error:''};
    Promise.resolve().then(()=>{if(state.trafficCatalogue?.pending&&scopeKey===trafficCatalogueScopeKey()&&identity===trafficCatalogueIdentity())loadTrafficCatalogue(0,{fresh:true});});
  }
  return state.trafficCatalogue;
}
function trafficCatalogueQuery(offset,{fresh=false}={}){
  const query={limit:50,offset,...trafficCatalogueScopeValues()};
  if(!fresh&&state.trafficCatalogue?.scopeKey===trafficCatalogueScopeKey()&&state.trafficCatalogue.as_of)query.as_of=state.trafficCatalogue.as_of;
  return query;
}
async function loadTrafficCatalogue(offset=0,{fresh=false}={}){
  if(!trafficCatalogueEnabled()||!state.authType||!Number.isSafeInteger(offset)||offset<0)return;
  const current=trafficCataloguePage(),scopeKey=trafficCatalogueScopeKey(),identity=trafficCatalogueIdentity(),sequence=++trafficCatalogueSequence,query=trafficCatalogueQuery(offset,{fresh});
  state.trafficCatalogue={...current,loading:true,pending:false,error:''};
  try{const page=await api('/flows/query',{method:'POST',body:query});if(sequence!==trafficCatalogueSequence||scopeKey!==trafficCatalogueScopeKey()||identity!==trafficCatalogueIdentity()||!state.authType)return;if(page.offset!==offset||page.window_seconds!==query.window_seconds||query.as_of&&page.as_of!==query.as_of)throw new Error('The controller returned a different traffic scope.');state.trafficCatalogue=trafficCatalogueRecord(page,scopeKey);}
  catch(error){if(sequence!==trafficCatalogueSequence||scopeKey!==trafficCatalogueScopeKey()||identity!==trafficCatalogueIdentity()||!state.authType)return;state.trafficCatalogue={...state.trafficCatalogue,loading:false,error:'Traffic catalogue unavailable: '+error.message};}
  if(state.view==='traffic'&&!$('#modal').open)renderPreservingFilterFocus();
}
function trafficCatalogueResultText(){const page=trafficCataloguePage();return page?`${page.total===null?'…':format(page.total)} matching relationships · ${page.endpoint_count===null?'…':format(page.endpoint_count)} endpoints`:null;}
function trafficCatalogueFooter(page){
  const first=page.items.length?page.offset+1:0,last=page.items.length?page.offset+page.items.length:0;
  return `${page.error?`<p class="form-error" role="alert">${h(page.error)}</p>`:''}<div class="table-footer">
    <span role="status">${page.loading?'Refreshing · ':''}${first}–${last} of ${page.total===null?'…':format(page.total)} matching relationships</span>
    <div role="group" aria-label="Traffic results pages">
      <button type="button" class="text-button" data-action="traffic-catalogue-page" data-offset="${Math.max(0,page.offset-page.limit)}" ${page.loading||!page.offset?'disabled':''}>Previous</button>
      <button type="button" class="text-button" data-action="traffic-catalogue-page" data-offset="${page.offset+page.items.length}" ${page.loading||!page.has_more?'disabled':''}>Next</button>
      <button type="button" class="text-button" data-action="traffic-catalogue-refresh" ${page.loading?'disabled':''}>Refresh</button>
    </div>
  </div>`;
}
function trafficControlsHTML(page){
  const windowButtons=[[3600,'1h'],[21600,'6h'],[86400,'24h']].map(([value,label])=>`<button type="button" class="${state.window===value?'selected':''}" data-action="window" data-value="${value}" aria-pressed="${state.window===value}">${label}</button>`).join('');
  return `<div class="traffic-tools">${trafficCaptureStatusHTML(page)}<div class="traffic-tools-filters"><select class="filter-select" id="flow-server-filter" aria-label="Filter traffic by endpoint"><option value="all">All endpoints</option>${state.data.servers.map(server=>`<option value="${h(server.id)}" ${state.flowServer===server.id?'selected':''}>${h(server.hostname)}</option>`).join('')}</select><div class="chart-controls" aria-label="Traffic window">${windowButtons}</div></div></div>`;
}
function trafficCatalogueHTML(){
  const page=trafficCataloguePage(),flows=page.items;
  return `${filterBarHTML('traffic')}${learningHTML()}${trafficControlsHTML(page)}<p class="traffic-charts-scope">Charts show the current page.</p><div class="traffic-layout">${flowGraphHTML()}${chartHTML()}</div><div class="section-line"><h2>Observed sources<span>${page.total===null?'…':format(page.total)} matching relationships</span></h2><button class="button secondary small" data-action="traffic-catalogue-export" ${page.loading||page.total===null||!page.total?'disabled':''}>Export matching CSV</button></div><section class="card"><div class="table-scroll"><table><thead><tr><th>Source IP</th><th>Endpoint</th><th>Service</th><th>Observation</th><th class="number-cell">Count</th><th>Last observed</th></tr></thead><tbody>${flows.map(flow=>`<tr><td class="mono">${h(flow.source_ip)}</td><td><button class="text-button" data-action="server" data-id="${h(flow.server_id)}">${h(serverName(flow.server_id))}</button></td><td><span class="service-pill">${num(flow.port)}/${h(flow.protocol)}</span></td><td>${captureEvidenceHTML(flow)}</td><td class="number-cell">${captureCountHTML(flow)}</td><td title="${h(timestamp(flow.last_seen))}">${age(flow.last_seen)}</td></tr>`).join('')||`<tr><td colspan="6"><div class="empty-state" style="padding:35px">${page.loading?'Loading observations…':page.error?'Traffic data could not be loaded.':'No observations match these filters.'}</div></td></tr>`}</tbody></table></div>${trafficCatalogueFooter(page)}</section>${hitMonitoringHTML()}`;
}
async function downloadTrafficCatalogueCSV(){
  if(!trafficCatalogueEnabled()||!state.authType)return;
  const scopeKey=trafficCatalogueScopeKey(),identity=trafficCatalogueIdentity(),sequence=++trafficExportSequence,query=trafficCatalogueQuery(0);delete query.limit;delete query.offset;
  const headers={Accept:'text/csv','Content-Type':'application/json'};
  if(state.token&&state.authConfig?.mode==='tokens')headers.Authorization='Bearer '+state.token;
  if(state.authType==='session'){if(!state.csrfToken){toast('Sign in again before exporting traffic.',true);return;}headers['X-CSRF-Token']=state.csrfToken;}
  const controller=new AbortController(),timeout=setTimeout(()=>controller.abort(),20000);
  try{const response=await fetch('/api/v1/flows/export.csv',{method:'POST',credentials:'same-origin',headers,body:JSON.stringify(query),signal:controller.signal});if(!response.ok){const error=await response.json().catch(()=>({}));throw new Error(error.error||'Traffic export failed.');}const blob=await response.blob();if(blob.size>64*1024*1024)throw new Error('Traffic export exceeds the browser download bound.');if(sequence!==trafficExportSequence||scopeKey!==trafficCatalogueScopeKey()||identity!==trafficCatalogueIdentity()||!state.authType)return;const url=URL.createObjectURL(blob),link=document.createElement('a');try{link.href=url;link.download='prthak-filtered-traffic.csv';link.click();}finally{setTimeout(()=>URL.revokeObjectURL(url),1000);}}
  catch(error){if(sequence===trafficExportSequence&&scopeKey===trafficCatalogueScopeKey()&&identity===trafficCatalogueIdentity()&&state.authType)toast(error.message,true);}
  finally{clearTimeout(timeout);}
}
async function trafficCatalogueAction(button){if(button.disabled)return;const action=button.dataset.action;if(action==='traffic-catalogue-page')return loadTrafficCatalogue(Number(button.dataset.offset));if(action==='traffic-catalogue-refresh')return loadTrafficCatalogue(state.trafficCatalogue?.offset||0,{fresh:true});if(action==='traffic-catalogue-export')return downloadTrafficCatalogueCSV();}
