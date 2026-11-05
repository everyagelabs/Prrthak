'use strict';

const firewallMaintenanceOperations={activate_existing:'Start firewalld with existing rules',activate_allow_all:'Start firewalld with default allow',deactivate_existing:'Stop and disable firewalld',migrate_ufw:'Assess and migrate supported UFW rules',prepare_egress:'Prepare empty outbound policy template',enable_native_counters:'Enable native firewalld counters'};
const firewallMaintenanceStatuses = {
 assessed: {label: 'Assessed', tone: ''},
 blocked: {label: 'Blocked', tone: 'danger'},
 applying: {label: 'Applying', tone: 'warning'},
 completed: {label: 'Completed', tone: ''},
 rolled_back: {label: 'Rolled back', tone: 'warning'},
 error: {label: 'Error', tone: 'danger'},
};
const agentFirewallServiceOperations=new Set(['activate_existing','activate_allow_all','deactivate_existing']);
function firewallActivationIdentity(){return JSON.stringify([state.authType,state.role,state.user||null,state.token||'',state.csrfToken||'']);}
function firewallActivationPage(){return state.firewallActivationOwner===firewallActivationIdentity()?state.firewallActivationPage||{}:{};}
function firewallServiceState(value){
 const service=String(value||'').toLowerCase().replaceAll('_','-');
 if(service==='running'||service==='active')return {label:'Running',tone:''};
 if(['not running','not-running','inactive','stopped','failed'].includes(service))return {label:'Stopped',tone:'warning'};
 return {label:'Not reported',tone:'neutral'};
}
function firewallActivationHTML(){
 const page=firewallActivationPage();
 const rows=(page.items||[]).map(item=>{
  const service=firewallServiceState(item.firewalld_state);
  const operation=item.ufw_active?'migrate_ufw':service.label==='Running'?'deactivate_existing':'activate_existing';
  const action=item.ufw_active?'Review UFW migration':service.label==='Running'?'Stop and disable':service.label==='Stopped'?'Start firewalld':'Assess firewalld';
  return `<tr>
   <td class="firewall-service-endpoint"><strong>${h(item.hostname || item.server_id)}</strong>
    <ul class="firewall-service-addresses" aria-label="IP addresses">${(item.ips || []).map(ip => `<li>${h(ip)}</li>`).join('')}</ul>
   </td>
   <td><span class="firewall-service-mobile-label" aria-hidden="true">firewalld</span>
    ${badge(service.label, service.tone)}${item.ufw_active ? '<small class="firewall-service-ufw">UFW is active</small>' : ''}
   </td>
   <td><span class="firewall-service-mobile-label" aria-hidden="true">Maintenance report</span>${firewallActivationReceiptHTML(item)}</td>
   <td><div class="inline-actions">${canWrite()?`<button type="button" class="button secondary small" data-action="firewall-activation-open" data-id="${h(item.server_id)}" data-operation="${operation}">${action}</button>`:''}
    <button type="button" class="text-button" data-action="firewall-activation-inspect" data-id="${h(item.server_id)}">Details</button>
   </div></td>
  </tr>`;
 }).join('');
 const offset = num(page.offset), count = (page.items || []).length;
 return `<section class="card firewall-services">
  <div class="firewall-services-intro">
   <div class="section-line"><h2>Endpoint status</h2><div class="inline-actions">
    <button type="button" class="button secondary small" data-action="firewall-activation-refresh">Refresh status</button>
    ${canWrite()?'<button type="button" class="button secondary small" data-action="firewall-activation-open">Firewall maintenance</button>':''}
   </div></div>
   <p>Review a start or stop request. The agent applies the approved change on its next control poll.</p>
   <p class="help-text">The agent uses its outbound connection for start and stop. Changes can affect live access even in monitor mode. A watchdog can roll back unsuccessful changes.</p>
   ${state.firewallActivationError?`<p class="form-error">${h(state.firewallActivationError)}</p>`:''}
  </div>
  <div class="table-scroll"><table class="firewall-services-table">
   <thead><tr><th scope="col">Endpoint</th><th scope="col">firewalld</th><th scope="col">Maintenance report</th><th scope="col">Actions</th></tr></thead>
   <tbody>${rows||'<tr><td colspan="4">Endpoint firewall status will appear after the first agent report.</td></tr>'}</tbody>
  </table></div>
  <div class="table-footer">
   <span>${count ? offset+1 : 0}–${count ? offset+count : 0} of ${num(page.total)} endpoints</span>
   ${offset || page.has_more ? `<div class="inline-actions" role="group" aria-label="Firewall results pages">
    <button type="button" class="button secondary small" data-action="firewall-activation-previous" ${offset?'':'disabled'}>Previous</button>
    <button type="button" class="button secondary small" data-action="firewall-activation-next" ${page.has_more?'':'disabled'}>Next</button>
   </div>` : ''}
  </div>
  <details class="firewall-service-help">
   <summary>Service maintenance details</summary>
   <p class="help-text">Assessment leaves UFW in place. Migration requires a separate review. Support depends on the rules, profiles and hooks on the host.</p>
  </details>
 </section>`;
}
function firewallMaintenanceReason(reason){
 if(reason==='stop traffic learning and monitoring before source-bank maintenance')return 'Traffic capture must stop before firewall maintenance. In Traffic, stop learning and monitoring for this endpoint, wait for collection to finish, then request a fresh assessment.';
 if(reason==='stop continuous hit monitoring before source-bank maintenance')return 'Turn off continuous hit monitoring for this endpoint in Traffic, then request a fresh assessment.';
 if(reason==='Remove active or pending managed enforcement and whole-host deny before this operation')return 'Remove the active or pending managed policies and whole-server default deny, wait for the agent to confirm removal, then request a fresh assessment.';
 if(reason==='Turn off managed enforcement in the endpoint configuration before this operation')return 'Managed enforcement is enabled in this endpoint’s configuration. Turn it off through a reviewed endpoint configuration change, wait for the agent to report the change, then request a fresh assessment.';
 if(reason==='Remove active or pending learned access rules before this operation')return 'Remove the active or pending learned access rules in Policies, wait for the agent to confirm removal, then request a fresh assessment.';
 return reason;
}
function firewallActivationErrorDetails(error){
 const payload=error?.payload,plan=payload?.plan;
 const reasons=[...(Array.isArray(payload?.blockers)?payload.blockers:[]),...(Array.isArray(plan?.blockers)?plan.blockers:[])];
 const blockers=[...new Set(reasons.filter(reason=>typeof reason==='string'&&reason.trim()).map(reason=>firewallMaintenanceReason(reason.slice(0,4096))))].slice(0,50);
 const id=typeof plan?.server_id==='string'?plan.server_id:typeof payload?.server_id==='string'?payload.server_id:'';
 const server=(state.data?.servers||[]).find(item=>item.id===id);
 return {message:typeof error?.message==='string'?error.message.slice(0,4096):'Firewall assessment could not complete.',endpoint:server?.hostname||id,blockers};
}
function firewallActivationErrorHTML(error){
 const detail=firewallActivationErrorDetails(error);
 return `<strong>${h(detail.message)}</strong>${detail.endpoint?`<p>Endpoint: ${h(detail.endpoint)}</p>`:''}${detail.blockers.length?`<ul>${detail.blockers.map(reason=>`<li>${h(reason)}</li>`).join('')}</ul>`:''}`;
}
function showFirewallActivationError(error,form){
 const slot=form?$('#form-error',form):$('#form-error');
 if(slot){slot.hidden=false;slot.innerHTML=firewallActivationErrorHTML(error);}
 else{const detail=firewallActivationErrorDetails(error);formError(new Error([detail.message,detail.endpoint,...detail.blockers].filter(Boolean).join('\n')));}
}
function firewallActivationReceiptHTML(item){
 const {receipt, job} = item;
 const awaitingReport = job && (!receipt || receipt.id !== job.id || receipt.plan_digest !== job.plan_digest);
 const requestExpired = awaitingReport && Date.parse(job.expires_at) <= Date.now();
 const requestNote = requestExpired ? 'Current request expired before the agent responded.' : 'Waiting for the agent to report on the current request.';
 if (!receipt) {
  if (requestExpired) return `<div class="firewall-service-receipt">${badge('Request expired', 'warning')}<small>${requestNote}</small></div>`;
  return `<span class="help-text">${job ? requestNote : 'No maintenance report yet.'}</span>`;
 }
 const operation = firewallMaintenanceOperations[receipt.target_operation];
 const status = firewallMaintenanceStatuses[receipt.status] || {label: 'Unknown status', tone: 'neutral'};
 return `<div class="firewall-service-receipt">
  <div class="firewall-service-result">${badge(status.label, status.tone)}${awaitingReport ? '<small>Previous request</small>' : ''}</div>
  ${operation ? `<strong>${h(operation)}</strong>` : ''}
  ${receipt.checked_at ? `<time datetime="${h(receipt.checked_at)}">Reported ${h(timestamp(receipt.checked_at))}</time>` : ''}
  ${receipt.error ? `<p class="firewall-service-reason"><strong>Reason</strong> ${h(firewallMaintenanceReason(receipt.error))}</p>` : ''}
  ${awaitingReport ? `<small>${requestNote}</small>` : ''}
 </div>`;
}
async function loadFirewallActivation(redraw=true){
 const owner=firewallActivationIdentity(),serial=(state.firewallActivationSerial||0)+1;state.firewallActivationSerial=serial;
 try{const page=await api('/firewall-activation/query',{method:'POST',body:{limit:50,offset:num(state.firewallActivationOffset)}});if(owner!==firewallActivationIdentity()||serial!==state.firewallActivationSerial)return;state.firewallActivationOwner=owner;state.firewallActivationPage=page;state.firewallActivationError='';}catch(error){if(owner!==firewallActivationIdentity()||serial!==state.firewallActivationSerial)return;state.firewallActivationError='Firewall maintenance outcomes unavailable: '+error.message;}
 if(redraw){
  if(!$('#modal').open)render();
  else if(state.firewallActivationAssessment)await refreshFirewallActivationAssessment();
 }
}
function showFirewallActivationForm(id='',operation=''){
 if(!canWrite())return;state.firewallActivationReview=null;state.firewallActivationAssessment=null;const servers=state.data?.servers||[],groups=state.data?.groups||[];
 showModal(operation==='activate_existing'?'Start firewalld':firewallMaintenanceOperations[operation]||'Firewall service maintenance',`<form id="firewall-activation-form" class="firewall-maintenance-form">
  <div class="modal-body">
   ${errorSlot}
   <p class="firewall-maintenance-note"><strong>Check first, apply after review.</strong> The assessment is read-only. Start and stop use the agent’s outbound connection and need no controller SSH access.</p>
   <div class="field"><label>Operation<select name="operation">${Object.entries(firewallMaintenanceOperations).map(([key,label])=>`<option value="${key}" ${key===operation?'selected':''}>${h(label)}</option>`).join('')}</select></label></div>
   <fieldset class="firewall-maintenance-scope"><legend>Endpoints <small>Up to 20 per review</small></legend>
    <div class="host-checklist">${servers.map(server=>`<label class="host-check"><input name="server_ids" type="checkbox" value="${h(server.id)}" ${server.id===id?'checked':''}><span><strong>${h(server.hostname||server.id)}</strong>${server.ips?.length?`<small>${h(server.ips.join(', '))}</small>`:''}</span></label>`).join('')||'<p>No endpoints loaded.</p>'}</div>
   </fieldset>
   <fieldset class="firewall-maintenance-scope"><legend>Saved groups <small>Current members only</small></legend>
    <div class="host-checklist">${groups.map(group=>`<label class="host-check"><input name="group_ids" type="checkbox" value="${h(group.id)}"><span><strong>${h(group.name)}</strong></span></label>`).join('')||'<p>No saved groups loaded.</p>'}</div>
   </fieldset>
   <div id="firewall-assessment-status" aria-live="polite"><p class="help-text">Request an assessment to check the selected endpoints.</p></div>
  </div>
  <div class="modal-footer">
   <button class="button secondary" type="button" data-action="close-modal">Close</button>
   <button class="button secondary" type="button" data-action="firewall-activation-assess">Request fresh assessment</button>
   <button class="button primary" type="submit" disabled>Review activation</button>
  </div>
 </form>`,'ENDPOINT FIREWALL');
}
function firewallActivationSelection(form){
 const fields=new FormData(form),selection={operation:String(fields.get('operation')||''),server_ids:$$('input[name="server_ids"]:checked',form).map(input=>input.value),group_ids:$$('input[name="group_ids"]:checked',form).map(input=>input.value)};
 if(!Object.hasOwn(firewallMaintenanceOperations,selection.operation))throw new Error('Choose a supported maintenance operation.');if(!selection.server_ids.length&&!selection.group_ids.length)throw new Error('Select at least one explicit endpoint or saved group.');if(selection.server_ids.length>20)throw new Error('Review at most 20 endpoints at a time.');return selection;
}
function firewallAssessmentKey(selection){
 return JSON.stringify([selection.operation,[...selection.server_ids].sort(),[...selection.group_ids].sort()]);
}
function currentFirewallAssessment(form){
 const result=state.firewallActivationAssessment;
 if(!result||result.form!==form||result.owner!==firewallActivationIdentity())return null;
 try{return result.key===firewallAssessmentKey(firewallActivationSelection(form))?result:null;}
 catch{return null;}
}
function renderFirewallAssessment(form){
 const result=currentFirewallAssessment(form);
 const status=$('#firewall-assessment-status');
 if(!status)return;
 const submit=$('button[type="submit"]',form);
 if(submit)submit.disabled=!(result?.ready&&result.expires>Date.now());
 status.innerHTML=result?.message||'<p class="help-text">Request an assessment to check the selected endpoints.</p>';
}
async function refreshFirewallActivationAssessment(){
 const result=state.firewallActivationAssessment;
 if(!result||!result.jobs?.length||result.loading||!$('#modal').open||$('#firewall-activation-form')!==result.form||currentFirewallAssessment(result.form)!==result)return;
 result.loading=true;
 try{
  const response=await api('/firewall-activation/query',{method:'POST',body:{server_ids:result.jobs.map(job=>job.server_id),limit:result.jobs.length}});
  if(!$('#modal').open||$('#firewall-activation-form')!==result.form||currentFirewallAssessment(result.form)!==result)return;
  let ready=true,expires=Infinity;
  const now=Date.now();
  const byEndpoint=new Map((response.items||[]).map(item=>[item.server_id,item]));
  const lines=result.jobs.map(job=>{
   const item=byEndpoint.get(job.server_id),receipt=item?.receipt;
   const matches=receipt?.id===job.id&&receipt?.plan_digest===job.plan_digest;
   const deadline=matches?Date.parse(receipt.checked_at)+180000:0;
   const passed=matches&&receipt.status==='assessed'&&deadline>now;
   if(passed)expires=Math.min(expires,deadline);
   else ready=false;
   let status='Ready to review',tone='ready',detail='';
   if(!passed){
    status='Waiting';tone='waiting';detail='Waiting for the agent to report its assessment.';
    if(matches){
     const stale=receipt.status==='assessed';
     status=stale?'Expired':firewallMaintenanceStatuses[receipt.status]?.label||'Blocked';tone=stale?'waiting':'blocked';
     detail=firewallMaintenanceReason(receipt.error)||(stale?'Request a fresh assessment.':'Open endpoint details for the reason.');
    }else if(item?.job?.id&&item.job.id!==job.id){
     status='Replaced';detail='Request a fresh assessment.';
    }else if(Date.parse(item?.job?.expires_at||job.expires_at)<=now){
     status='Expired';detail='Assessment request expired before the agent responded. Check the agent connection and request a fresh assessment.';
    }
   }
   return `<li><strong>${h(item?.hostname||job.server_id)}</strong><span class="firewall-assessment-pill ${tone}">${h(status)}</span>${detail?`<p>${h(detail)}</p>`:''}</li>`;
  });
  result.ready=ready;result.expires=expires;
  result.message=`<h3>Assessment results</h3><ul class="firewall-assessment-list">${lines.join('')}</ul>`;
 }catch(error){result.ready=false;result.message=`<div class="form-error">${firewallActivationErrorHTML(error)}</div>`;}
 finally{result.loading=false;if($('#modal').open&&$('#firewall-activation-form')===result.form)renderFirewallAssessment(result.form);}
}
function firewallActivationFactsHTML(facts={},operation=''){
 const management=agentFirewallServiceOperations.has(operation)
  ?'Health check: authenticated outbound control connection from the agent to the controller.'
  :`<strong>Protected actual SSH listeners:</strong> ${h((facts.ssh_ports||[]).join(', ')||'Unverified')}<br><strong>Restricted management sources:</strong> ${h((facts.management_sources||[]).join(', ')||'Unverified')}`;
 return `<p>firewalld: ${facts.firewalld_active?'active':'inactive / unknown'} (${h(facts.firewalld_enabled||'unknown')}) · UFW: ${facts.ufw_active?'active':'inactive / absent / unknown'} · ${h(facts.version||'unknown version')} / ${h(facts.backend||'unknown backend')}</p><p>${management}<br><strong>Agent-reported interface IPs:</strong> ${h((facts.ips||[]).join(', ')||'Unverified')}</p><details><summary>Discovered services / exact numeric translation</summary><p>Listeners: ${h((facts.discovered_ports||[]).map(row=>row.port+'/'+row.protocol).join(', ')||'None reported')}</p><div class="table-scroll"><table><thead><tr><th>Order / family</th><th>Source</th><th>Port</th><th>Action</th></tr></thead><tbody>${(facts.translated_rules||[]).map(row=>`<tr><td>${num(row.priority)} / ${h(row.family)}</td><td>${h(row.source)}</td><td>${num(row.port)}/${h(row.protocol)}</td><td>${h(row.action)}</td></tr>`).join('')||'<tr><td colspan="4">No numeric UFW rules translated for this operation.</td></tr>'}</tbody></table></div></details>${(facts.blockers||[]).map(text=>`<p class="form-error">${h(firewallMaintenanceReason(text))}</p>`).join('')}${(facts.notes||[]).map(text=>`<p class="help-text">${h(text)}</p>`).join('')}`;
}
function showFirewallActivationReview(plan){
 state.firewallActivationReview=plan;state.firewallActivationReviewOwner=firewallActivationIdentity();
 const canApply=canWrite()&&plan.can_apply===true&&!(plan.blockers||[]).length;
 showModal('Review firewall maintenance',`<form id="firewall-activation-review-form" class="firewall-maintenance-form"><div class="modal-body">${errorSlot}<p class="firewall-maintenance-note">${h(firewallMaintenanceOperations[plan.operation]||'Endpoint maintenance')} can change live access even when ordinary policy enforcement is monitor-only. ${plan.operation==='activate_allow_all'?'Default allow permits otherwise unmatched inbound traffic from any source to any local port. Existing explicit denies still apply.':plan.operation==='deactivate_existing'?'Stopping firewalld removes its active filtering and prevents it starting at boot.':'The existing firewall rules can block access to applications.'} ${agentFirewallServiceOperations.has(plan.operation)?'The agent checks its outbound control connection. The check does not verify inbound reachability.':'Management health checks cover the controller and protected SSH paths.'}</p><p>Expires ${h(timestamp(plan.expires_at))}. No second administrator is required.</p>${!(plan.targets||[]).length?(plan.blockers||[]).map(text=>`<p class="form-error">${h(firewallMaintenanceReason(text))}</p>`).join(''):''}${(plan.targets||[]).map(target=>`<article class="firewall-maintenance-target"><h3>${h(target.hostname||target.server_id)}</h3>${firewallActivationFactsHTML(target.assessment||{},plan.operation)}<p class="help-text">Exact native baseline: ${h(target.baseline_digest)}</p>${(target.blockers||[]).map(text=>`<p class="form-error">${h(firewallMaintenanceReason(text))}</p>`).join('')}</article>`).join('')}${canApply?`<div class="field"><label>Type the exact phrase<code class="platform-confirmation-phrase">${h(plan.challenge)}</code><input id="firewall-activation-phrase" name="confirmation_phrase" autocomplete="off"></label></div><label class="host-check"><input id="firewall-activation-ack" name="acknowledge_downtime" type="checkbox">${plan.operation==='activate_allow_all'?'I understand this start allows otherwise unmatched inbound traffic to any local port.':plan.operation==='deactivate_existing'?'I understand that stopping and disabling firewalld removes its host traffic filtering.':'I understand that this firewall change can interrupt access.'}</label><p class="help-text">Acknowledgement starts unchecked for every review and push attempt. The independent watchdog restores the exact previous configuration and service activity when recovery is provable. An unverified rollback is an error, never a success.</p>`:''}</div><div class="modal-footer"><button class="button secondary" type="button" data-action="close-modal">Close</button>${canApply?'<button class="button danger" type="submit" disabled>Apply reviewed maintenance</button>':canWrite()?'<button class="button secondary" type="button" data-action="firewall-activation-open">Return to assessment</button>':''}</div></form>`,'FROZEN ENDPOINTS · AUTHENTICATED HEALTH · INDEPENDENT ROLLBACK');
}
function firewallActivationReviewUsable(plan,phrase,ack){return canWrite()&&state.firewallActivationReviewOwner===firewallActivationIdentity()&&plan?.status==='preview'&&plan.can_apply===true&&!(plan.blockers||[]).length&&!!plan.digest&&!!plan.confirmation_nonce&&Date.parse(plan.expires_at)>Date.now()&&phrase===plan.challenge&&ack===true;}
function firewallActivationInput(event){if(event.target.form?.id==='firewall-activation-form'){renderFirewallAssessment(event.target.form);return true;}if(!['firewall-activation-phrase','firewall-activation-ack'].includes(event.target.id))return false;const form=$('#firewall-activation-review-form');if(form)$('button[type="submit"]',form).disabled=!firewallActivationReviewUsable(state.firewallActivationReview,$('#firewall-activation-phrase').value,$('#firewall-activation-ack').checked);return true;}
async function firewallActivationAction(button){
 const action=button.dataset.action;if(!action?.startsWith('firewall-activation-'))return false;
 if(action==='firewall-activation-open'){showFirewallActivationForm(button.dataset.id||'',button.dataset.operation||'');return true;}
 if(action==='firewall-activation-refresh'){await loadFirewallActivation();return true;}
 if(action==='firewall-activation-previous'||action==='firewall-activation-next'){state.firewallActivationOffset=Math.max(0,num(state.firewallActivationOffset)+(action.endsWith('next')?50:-50));await loadFirewallActivation();return true;}
 const owner=firewallActivationIdentity();button.disabled=true;
 let assessmentForm=null;
 try{
  if(action==='firewall-activation-assess'){
   if(!canWrite())return true;
   const form=$('#firewall-activation-form'),selection=firewallActivationSelection(form);
   assessmentForm=form;state.firewallActivationAssessment=null;renderFirewallAssessment(form);
   const response=await api('/firewall-activation/assess',{method:'POST',body:selection});
   if(owner!==firewallActivationIdentity()||!$('#modal').open||$('#firewall-activation-form')!==form)return true;
   state.firewallActivationAssessment={owner,form,key:firewallAssessmentKey(selection),jobs:response.items||[],ready:false,message:'<p class="help-text">Waiting for the agent to report its assessment.</p>'};
   renderFirewallAssessment(form);
   toast('Read-only endpoint assessment requested.');
   await refreshFirewallActivationAssessment();
  }else if(action==='firewall-activation-inspect'){
   const page=await api('/firewall-activation/query',{method:'POST',body:{server_ids:[button.dataset.id],limit:1,details:true}});if(owner!==firewallActivationIdentity())return true;const item=page.items?.[0];if(item)showModal('Endpoint firewall details',`<div class="modal-body"><h3>${h(item.hostname||item.server_id)}</h3>${firewallActivationReceiptHTML(item)}${item.receipt?.assessment?firewallActivationFactsHTML(item.receipt.assessment,item.receipt.target_operation):'<p class="help-text">Request an assessment to check the endpoint’s firewall.</p>'}</div><div class="modal-footer"><button class="button secondary" data-action="close-modal">Close</button>${canWrite()&&(item.ufw_active||['migrate_ufw','prepare_egress','enable_native_counters'].includes(item.receipt?.target_operation))?'<button type="button" class="button secondary" data-action="endpoint-configuration" data-id="'+h(item.server_id)+'">Configure protected SSH access</button>':''}</div>`,'ENDPOINT FIREWALL SERVICE');
  }
 }catch(error){if(owner===firewallActivationIdentity()&&(!assessmentForm||$('#modal').open&&$('#firewall-activation-form')===assessmentForm))showFirewallActivationError(error,assessmentForm);}finally{button.disabled=false;}return true;
}
async function firewallActivationSubmit(event){
 const form=event.target;if(!['firewall-activation-form','firewall-activation-review-form'].includes(form.id))return false;event.preventDefault();if(!canWrite())return true;
 const owner=firewallActivationIdentity(),submit=$('button[type="submit"]',form);if(submit?.disabled)return true;if(submit)submit.disabled=true;
 try{
  if(form.id==='firewall-activation-form'){
   const assessment=currentFirewallAssessment(form);
   if(!assessment?.ready||assessment.expires<=Date.now())throw new Error('Request a fresh assessment and wait for the agent to report readiness.');
   const plan=await api('/firewall-activation/preview',{method:'POST',body:firewallActivationSelection(form)});
   if(owner!==firewallActivationIdentity()||!$('#modal').open||$('#firewall-activation-form')!==form)return true;
   showFirewallActivationReview(plan);
  }else{
   const plan=state.firewallActivationReview,phrase=String(new FormData(form).get('confirmation_phrase')||''),ack=$('#firewall-activation-ack');const acknowledged=ack.checked;ack.checked=false;
   if(!firewallActivationReviewUsable(plan,phrase,acknowledged))throw new Error('Refresh the exact review, type its phrase and manually acknowledge downtime.');
   await api('/firewall-activation/'+encodeURIComponent(plan.id)+'/confirm',{method:'POST',body:{digest:plan.digest,confirmation_nonce:plan.confirmation_nonce,confirmation_phrase:phrase,acknowledge_downtime:true}});
   if(owner!==firewallActivationIdentity()||!$('#modal').open||$('#firewall-activation-review-form')!==form||state.firewallActivationReview!==plan||state.firewallActivationReviewOwner!==owner)return true;state.firewallActivationReview=null;closeModal();toast('Maintenance intent assigned. Wait for authenticated endpoint completion or rollback receipts; queued is not applied.');await loadFirewallActivation();
  }
 }catch(error){if(owner===firewallActivationIdentity()&&$('#modal').open&&$('#'+form.id)===form)showFirewallActivationError(error,form);}finally{if(submit&&form.id==='firewall-activation-form'&&$('#modal').open&&$('#firewall-activation-form')===form)renderFirewallAssessment(form);}return true;
}
