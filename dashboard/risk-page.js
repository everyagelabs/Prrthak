'use strict';
const riskState={catalog:null,findings:null,regulatory:null,tab:'findings',loading:false,error:'',sequence:0,inFlight:null,findingsScope:null,fetchedAt:null,offset:0,search:'',severity:'',port:''};
function riskyPortBadge(server,listener){const matches=(server.risky_ports||[]).filter(f=>f.port===listener.port&&f.protocol===listener.protocol);if(!matches.length)return '';return `<span class="badge ${matches.some(f=>f.severity==='high')?'danger':'warning'}" title="${h(matches.map(f=>f.reason).join(' · '))}">Risky port</span><small class="risk-port-reason">${h(matches.map(f=>f.reason).join(" · "))}</small>`;}
function riskyServerBadge(server){return Number(server.risk_summary?.total)>0?`<span class="badge warning" title="Review listener reasons under Risk & compliance">${num(server.risk_summary.total)} risk indicators</span>`:'';}
function riskRefs(ids,sources){return (ids||[]).map(id=>sources?.[id]).filter(Boolean).map(source=>`<a href="${h(source.url)}" target="_blank" rel="noopener noreferrer">${h(source.title)}</a>`).join(' · ');}
function riskScope(){return JSON.stringify({offset:riskState.offset,search:riskState.search,severity:riskState.severity,port:riskState.port});}
function riskCoverageHTML(data){
 if(!data)return '<p class="inline-notice warning">Classification results have not loaded for the selected filters. No all-clear is established.</p>';
 const pending=data.classification_pending_servers,known=Number.isSafeInteger(pending)&&pending>=0,limited=num(data.truncated_server_count),detailLimit=data.stored_reason_limit;
 let html=known?(pending?`<p class="inline-notice warning"><strong>Partial coverage:</strong> ${formatRiskCount(pending)} server${pending===1?' awaits':'s await'} classification. Counts cover classified listeners only; zero matches is not an all-clear.</p>`:'<p class="help-text">Classification is available for the reported scope. Results remain based on last-known agent listeners, not a reachability or security test.</p>'):'<p class="inline-notice warning">Classification coverage is not reported. Treat these last-known results as partial; zero matches is not an all-clear.</p>';
 if(limited)html+=Number.isSafeInteger(detailLimit)&&detailLimit>0?`<p class="inline-notice warning">${formatRiskCount(limited)} server${limited===1?' has':'s have'} stored detailed reasons limited to ${formatRiskCount(detailLimit)} per host. This is a host-detail limit; this query filters and counts the available listener classification before paging.</p>`:`<p class="inline-notice warning">Partial retained results: ${formatRiskCount(limited)} server${limited===1?' exceeds':'s exceed'} the reported indicator limit. Matching counts may omit indicators; verify host coverage.</p>`;
 return html;
}
function formatRiskCount(value){return String(num(value));}
function riskEmptyMessage(data){
 if(!data)return riskState.loading?'Loading classification for the selected filters…':'Findings are unavailable for the selected filters. Refresh to retry.';
 if(!Number.isSafeInteger(data.classification_pending_servers)||data.classification_pending_servers>0)return 'No matching indicators among the available classified listeners. Pending or unreported coverage prevents an all-clear.';
 return 'No matching risky-port indicators in the available listener classification. Stale or failed discovery still requires review.';
}
function riskFindingsHTML(data){
 const findings=data?.items||[],start=data?.total?riskState.offset+1:0,end=Math.min(riskState.offset+findings.length,data?.total||0);
 const refreshed=riskState.fetchedAt&&data?`Risk results last refreshed: ${h(timestamp(riskState.fetchedAt))}`:'';
 return `<section class="card table-card risk-card" aria-labelledby="risk-findings-title">
   <header class="card-header"><div><h2 class="card-title" id="risk-findings-title">Risky listeners</h2>
     <p class="card-subtitle">${data?`${num(data.total)} indicators · ${num(data.server_count)} servers`:riskState.loading?'Loading classification':'Classification not loaded'}</p></div>
     <button class="button secondary small" type="button" data-action="risk-refresh">Refresh</button>
   </header>
   <div class="risk-card-copy">
     <div class="risk-filters" role="group" aria-label="Risky listener filters">
       <div class="field"><label for="risk-search">Search</label><input id="risk-search" type="search" value="${h(riskState.search)}" placeholder="Server, IP, service or port"></div>
       <div class="field"><label for="risk-severity">Severity</label><select id="risk-severity"><option value="">All severities</option>${['high','medium','low'].map(value=>`<option value="${value}" ${riskState.severity===value?'selected':''}>${value[0].toUpperCase()+value.slice(1)}</option>`).join('')}</select></div>
       <div class="field"><label for="risk-port">Exact port</label><input id="risk-port" value="${h(riskState.port)}" type="number" min="1" max="65535" placeholder="e.g. 443"></div>
       <button class="button secondary" type="button" data-action="risk-filter">Apply filters</button>
     </div>
     ${riskCoverageHTML(data)}
     ${refreshed||riskState.loading?`<p class="help-text" role="status">${riskState.loading?'Refreshing risk findings…':refreshed}</p>`:''}
   </div>
   ${findings.length?`<div class="table-scroll" tabindex="0" role="region" aria-label="Risky listeners table"><table class="risk-table"><thead><tr><th>Server</th><th>Port / listener</th><th>Risk / binding</th><th>Why marked risky</th><th>Recommended action / reference</th></tr></thead><tbody>
     ${findings.map(item=>`<tr><td><button class="text-button" type="button" data-action="risk-server" data-id="${h(item.server_id)}">${h(item.hostname)}</button><small>${h((item.ips||[]).join(', '))}</small></td><td><strong class="danger-text">${num(item.port)}/${h(item.protocol)}</strong> <span class="badge warning">Risky port</span><small>${h(item.service||item.name)} · ${h(item.process||'process not reported')}</small></td><td>${badge(item.severity,item.severity==='high'?'danger':'warning')}<small>${h(item.exposure)} · ${h(item.address||'binding unknown')}<br>${h(item.discovery_status)} discovery · ${h(item.server_status)}<br>Observed: ${h(item.observed_at||'Timestamp not reported')}</small></td><td>${h(item.reason)}</td><td>${h(item.recommendation)}<small>${riskRefs(item.source_ids,data.sources)}</small></td></tr>`).join('')}
   </tbody></table></div>`:`<div class="empty-state risk-empty-state"><p>${h(riskEmptyMessage(data))}</p></div>`}
   <div class="table-footer" aria-live="polite"><span>${data?`${start}–${end} of ${num(data.total)} indicators`:'Results not loaded'}</span><div>
     <button class="text-button" type="button" data-action="risk-prev" ${riskState.offset===0?'disabled':''}>Previous</button>
     <button class="text-button" type="button" data-action="risk-next" ${!data||riskState.offset+findings.length>=data.total?'disabled':''}>Next</button>
   </div></div>
   <p class="risk-card-copy risk-table-note help-text">${h(data?.basis||'Latest agent listener reports')} Loopback bindings remain visible and do not generate a network-listener alert.</p>
 </section>`;
}
function riskHTML(){
 const data=riskState.findingsScope===riskScope()?riskState.findings:null,catalog=riskState.catalog,reg=riskState.regulatory;
 const tabs=`<div class="view-toolbar"><div class="view-tabs" aria-label="Risk sections">${[['findings','Risky ports in use'],['catalog','Port catalogue'],['regulatory','CERT-In & RBI']].map(([id,label])=>`<button class="view-tab ${riskState.tab===id?'active':''}" type="button" data-action="risk-tab" data-tab="${id}" aria-pressed="${riskState.tab===id}">${label}</button>`).join('')}</div></div>`;
 const notice='<div class="inline-notice">Flags identify listeners needing review. Every flag includes a reason, next action and reference. A port number does not establish a vulnerability, public reachability, failed encryption or regulatory non-compliance.</div>';
 let body='';
 if(riskState.tab==='findings')body=riskFindingsHTML(data);
 if(riskState.tab==='catalog')body=`<section class="card table-card risk-card"><header class="card-header"><div><h2 class="card-title">Configurable review catalogue</h2><p class="card-subtitle">Revision ${num(catalog?.revision)} · ${num(catalog?.rules?.length)} rules</p></div>${canWrite()?'<button class="button primary small" type="button" data-action="risk-catalog-edit">Edit catalogue</button>':''}</header>
   <p class="risk-card-copy help-text">Defaults combine service-port references and security guidance with product review judgments. They are not a regulator-issued blocked-port list.</p>
   <div class="table-scroll" tabindex="0" role="region" aria-label="Port catalogue table"><table class="risk-table"><thead><tr><th>Service</th><th>Ports</th><th>Severity / state</th><th>Reason</th><th>Next action / sources</th></tr></thead><tbody>${(catalog?.rules||[]).map(rule=>`<tr><td>${h(rule.name)}</td><td>${num(rule.port_start)}${rule.port_end!==rule.port_start?'–'+num(rule.port_end):''}/${h(rule.protocol)}</td><td>${h(rule.severity)} · ${rule.enabled?'Enabled':'Disabled'}</td><td>${h(rule.reason)}</td><td>${h(rule.recommendation)}<small>${riskRefs(rule.source_ids,catalog.sources)}</small></td></tr>`).join('')}</tbody></table></div></section>`;
 if(riskState.tab==='regulatory')body=`<section class="card table-card risk-card"><header class="card-header"><div><h2 class="card-title">CERT-In & RBI control mapping</h2><p class="card-subtitle">Source review ${h(reg?.checked_on||'pending')}</p></div></header>
   <p class="risk-card-copy help-text">${h(reg?.notice||'Loading verified references.')}</p>
   <div class="table-scroll" tabindex="0" role="region" aria-label="Regulatory mapping table"><table class="risk-table"><thead><tr><th>Framework / clause</th><th>Requirement</th><th>Evidence status</th><th>Product support / remaining evidence</th></tr></thead><tbody>${(reg?.controls||[]).map(row=>`<tr><td>${h(row.framework)} · ${h(row.clause)}<small>${riskRefs([row.source_id],reg.sources)}</small></td><td>${h(row.requirement)}</td><td>${badge(row.status.replaceAll('_',' '),'warning')}</td><td>${h(row.support)}</td></tr>`).join('')}</tbody></table></div>
   <p class="risk-card-copy risk-table-note help-text">This page supports an assessment. It does not certify the deployment or submit incident reports. Operational evidence, security-log archives, MFA and actual DC/DR testing remain the organization’s responsibility.</p></section>`;
 return tabs+notice+(riskState.error?`<div class="error-banner">${h(riskState.error)}</div>`:'')+(riskState.loading&&!catalog?'<div class="loading-state">Loading risk information…</div>':body);
}
function riskRender(){
 if(state.view!=='risk')return;const target=$('#view-content');if(!target)return;
 const fields=['risk-search','risk-severity','risk-port'],drafts=fields.map(id=>[id,$('#'+id)?.value]).filter(([,value])=>typeof value==='string'),active=typeof document==='undefined'?null:document.activeElement,focused=fields.includes(active?.id),start=active?.selectionStart,end=active?.selectionEnd;
 target.innerHTML=riskHTML();for(const [id,value]of drafts){const field=$('#'+id);if(field)field.value=value;}
 if(focused){const field=$('#'+active.id);field?.focus?.();if(Number.isInteger(start)&&field?.setSelectionRange)field.setSelectionRange(start,end??start);}
}
function riskLoad(force=false){
 if(riskState.loading&&!force)return riskState.inFlight;
 const seq=++riskState.sequence,scope=riskScope(),refreshReference=force||!riskState.catalog||!riskState.regulatory;riskState.loading=true;riskState.error='';riskRender();
 const query=new URLSearchParams({offset:String(riskState.offset),limit:'100',search:riskState.search,severity:riskState.severity,port:riskState.port});
 const request=(async()=>{try{
   const calls=refreshReference?[api('/risk/catalog'),api('/risk/findings?'+query),api('/risk/regulatory')]:[api('/risk/findings?'+query)],results=await Promise.all(calls);
   if(seq!==riskState.sequence||scope!==riskScope())return;
   const findings=results[refreshReference?1:0];riskState.findings=findings;riskState.findingsScope=scope;riskState.fetchedAt=Date.now();
   if(refreshReference){riskState.catalog=results[0];riskState.regulatory=results[2];}
  }catch(error){if(seq===riskState.sequence)riskState.error=error.message;}finally{if(seq===riskState.sequence){riskState.loading=false;riskState.inFlight=null;riskRender();}}
 })();riskState.inFlight=request;return request;
}
function riskEditorRow(rule){return `<fieldset class="rule-row" data-risk-rule="${h(rule.id)}" data-category="${h(rule.category)}" data-sources="${h(JSON.stringify(rule.source_ids||[]))}"><legend>${h(rule.id)}</legend><div class="field-row"><label>Service name<input name="name" maxlength="120" value="${h(rule.name)}" required></label><label>Start port<input name="port_start" type="number" min="1" max="65535" value="${num(rule.port_start)}" required></label><label>End port<input name="port_end" type="number" min="1" max="65535" value="${num(rule.port_end)}" required></label><label>Protocol<select name="protocol">${['tcp','udp'].map(p=>`<option ${p===rule.protocol?'selected':''}>${p}</option>`).join('')}</select></label><label>Severity<select name="severity">${['high','medium','low'].map(p=>`<option ${p===rule.severity?'selected':''}>${p}</option>`).join('')}</select></label></div><div class="field"><label>Reason<textarea name="reason" maxlength="600" required>${h(rule.reason)}</textarea></label></div><div class="field"><label>Recommended action<textarea name="recommendation" maxlength="600" required>${h(rule.recommendation)}</textarea></label></div><label><input type="checkbox" name="enabled" ${rule.enabled?'checked':''}>Enabled</label><button class="text-button danger-text" type="button" data-action="risk-rule-remove">Remove rule</button></fieldset>`;}
async function riskAction(button){
 const action=button.dataset.action;
 if(action==='risk-server')return openServer(button.dataset.id);
 if(action==='risk-tab'){riskState.tab=button.dataset.tab;riskRender();if(riskState.tab==='catalog')return riskLoad(true);return;}
 if(action==='risk-filter'){riskState.search=$('#risk-search').value;riskState.severity=$('#risk-severity').value;riskState.port=$('#risk-port').value;riskState.offset=0;return riskLoad(true);}
 if(action==='risk-next'||action==='risk-prev'){riskState.offset=Math.max(0,riskState.offset+(action==='risk-next'?100:-100));return riskLoad(true);}
 if(action==='risk-refresh')return riskLoad(true);
 if(!canWrite())return;
 if(action==='risk-catalog-edit'){showModal('Edit risky-port catalogue',`<form id="risk-catalog-form" data-revision="${num(riskState.catalog.revision)}"><div class="modal-body"><div id="risk-catalog-error" class="form-error" role="alert"></div><p class="help-text">Saving updates review indicators and alerts. It does not change firewall access.</p><div id="risk-rules">${riskState.catalog.rules.map(riskEditorRow).join('')}</div><button class="button secondary" type="button" data-action="risk-rule-add">Add custom rule</button></div><div class="modal-footer"><button class="button secondary" type="button" data-action="close-modal">Cancel</button><button class="button primary" type="submit">Save catalogue</button></div></form>`,'ADMIN CONFIGURATION');return;}
 if(action==='risk-rule-remove'){button.closest('[data-risk-rule]').remove();return;}
 if(action==='risk-rule-add'){if($$('[data-risk-rule]',$('#risk-catalog-form')).length>=100)return;$('#risk-rules').insertAdjacentHTML('beforeend',riskEditorRow({id:'custom-'+Date.now().toString(36)+'-'+Math.random().toString(36).slice(2,6),name:'Custom service',port_start:8443,port_end:8443,protocol:'tcp',severity:'medium',reason:'Organization-defined sensitive service requiring review.',recommendation:'Restrict to approved clients and verify service security.',category:'custom',source_ids:[],enabled:true}));}
}
async function riskSubmit(event){event.preventDefault();if(!canWrite())return;const form=event.target,button=$('button[type="submit"]',form);button.disabled=true;
 try{const rules=$$('[data-risk-rule]',form).map(row=>{const v=name=>$('[name="'+name+'"]',row);return {id:row.dataset.riskRule,name:v('name').value.trim(),port_start:Number(v('port_start').value),port_end:Number(v('port_end').value),protocol:v('protocol').value,severity:v('severity').value,reason:v('reason').value.trim(),recommendation:v('recommendation').value.trim(),enabled:v('enabled').checked,category:row.dataset.category,source_ids:JSON.parse(row.dataset.sources)};});await api('/risk/catalog',{method:'PUT',body:{expected_revision:Number(form.dataset.revision),rules}});closeModal();await riskLoad(true);toast('Risk catalogue saved. Listener indicators refreshed.');}catch(error){$('#risk-catalog-error').textContent=error.message;button.disabled=false;}}
