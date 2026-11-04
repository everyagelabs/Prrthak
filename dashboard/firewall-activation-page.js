'use strict';

const firewallMaintenanceOperations={activate_existing:'Activate existing firewalld configuration',migrate_ufw:'Assess and migrate supported UFW rules',prepare_egress:'Prepare empty outbound policy template',enable_native_counters:'Enable native firewalld counters'};
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
  const operation=item.ufw_active?'migrate_ufw':'activate_existing';
  const action=item.ufw_active?'Review UFW migration':service.label==='Stopped'?'Start firewalld':'Assess firewalld';
  return `<tr><td><strong>${h(item.hostname||item.server_id)}</strong><small>${h((item.ips||[]).join(', '))}</small></td><td>${badge(service.label,service.tone)}${item.ufw_active?'<small>UFW is active</small>':''}</td><td>${firewallActivationReceiptHTML(item)}</td><td><div class="inline-actions">${canWrite()&&(service.label!=='Running'||item.ufw_active)?`<button type="button" class="button secondary small" data-action="firewall-activation-open" data-id="${h(item.server_id)}" data-operation="${operation}">${action}</button>`:''}<button type="button" class="text-button" data-action="firewall-activation-inspect" data-id="${h(item.server_id)}">Details</button></div></td></tr>`;
 }).join('');
 return `<section class="card firewall-services"><div class="section-line"><h2>Endpoint firewall services</h2><div class="inline-actions"><button type="button" class="button secondary small" data-action="firewall-activation-refresh">Refresh status</button>${canWrite()?'<button type="button" class="button secondary small" data-action="firewall-activation-open">Firewall maintenance</button>':''}</div></div><p class="platform-intro">See which agents report firewalld running. To start it, request an assessment and review the existing rules and protected management paths.</p><p class="help-text">A service start can change live access even when ordinary policy enforcement is monitor-only. The agent uses authenticated health checks and an independent endpoint rollback watchdog.</p>${state.firewallActivationError?`<p class="form-error">${h(state.firewallActivationError)}</p>`:''}<div class="table-scroll"><table><thead><tr><th>Endpoint</th><th>firewalld</th><th>Last maintenance result</th><th>Action</th></tr></thead><tbody>${rows||'<tr><td colspan="4">Endpoint firewall status will appear after the first agent report.</td></tr>'}</tbody></table></div><div class="table-footer"><span>${page.total?num(page.offset)+1:0}–${num(page.offset)+(page.items||[]).length} of ${num(page.total)} endpoints</span><button class="text-button" data-action="firewall-activation-previous" ${page.offset?'':'disabled'}>Previous</button><button class="text-button" data-action="firewall-activation-next" ${page.has_more?'':'disabled'}>Next</button></div><details class="firewall-service-help"><summary>Service maintenance details</summary><p class="help-text">UFW is preserved during assessment. A migration requires a separate review. Custom hooks, profiles, NAT and common stock UFW configurations can be unsupported.</p></details></section>`;
}
function firewallActivationReceiptHTML(item){
 const receipt=item.receipt,job=item.job,current=receipt&&job&&receipt.id===job.id&&receipt.plan_digest===job.plan_digest;
 return receipt?`<strong>${h(current?'This job: ':'Previous job: ')}${h(receipt.status)}</strong><small>${h(timestamp(receipt.checked_at))}</small><small>${h(receipt.error||'')}</small>${current?'':'<small>Does not confirm the current request.</small>'}`:'<span class="help-text">No matching endpoint receipt; application is unverified.</span>';
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
 showModal(operation==='activate_existing'?'Start firewalld':'Firewall service maintenance',`<form id="firewall-activation-form"><div class="modal-body">${errorSlot}<p class="inline-notice warning">This is separate live maintenance authority, including on monitor-only endpoints. Start/reload can interrupt access. No service or policy changes occur during assessment.</p><div class="field"><label>Operation<select name="operation">${Object.entries(firewallMaintenanceOperations).map(([key,label])=>`<option value="${key}" ${key===operation?'selected':''}>${h(label)}</option>`).join('')}</select></label></div><fieldset><legend>Explicit endpoints · at most 20 per review</legend><div class="host-checklist">${servers.map(server=>`<label class="host-check"><input name="server_ids" type="checkbox" value="${h(server.id)}" ${server.id===id?'checked':''}>${h(server.hostname||server.id)} <small>${h((server.ips||[]).join(', '))}</small></label>`).join('')||'<p>No endpoints loaded in this workspace.</p>'}</div></fieldset><fieldset><legend>Saved groups · freeze current members</legend><div class="host-checklist">${groups.map(group=>`<label class="host-check"><input name="group_ids" type="checkbox" value="${h(group.id)}">${h(group.name)}</label>`).join('')||'<p>No saved groups loaded.</p>'}</div></fieldset><div id="firewall-assessment-status" aria-live="polite"><p class="help-text">Request an assessment to check the selected endpoints.</p></div></div><div class="modal-footer"><button class="button secondary" type="button" data-action="close-modal">Close</button><button class="button secondary" type="button" data-action="firewall-activation-assess">Request fresh assessment</button><button class="button primary" type="submit" disabled>Review activation</button></div></form>`,'NO AUTOMATIC ACTIVATION · GUI CONFIGURATION');
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
  const byEndpoint=new Map((response.items||[]).map(item=>[item.server_id,item]));
  const lines=result.jobs.map(job=>{
   const item=byEndpoint.get(job.server_id),receipt=item?.receipt;
   const matches=receipt?.id===job.id&&receipt?.plan_digest===job.plan_digest;
   const deadline=matches?Date.parse(receipt.checked_at)+180000:0;
   const passed=matches&&receipt.status==='assessed'&&deadline>Date.now();
   if(passed)expires=Math.min(expires,deadline);
   else ready=false;
   const detail=passed?'Ready to review':matches?(receipt.error||(receipt.status==='assessed'?'Assessment expired. Request a fresh assessment.':`Assessment ${receipt.status}. Open endpoint details for the reason.`)):item?.job?.id&&item.job.id!==job.id?'Assessment replaced. Request a fresh assessment.':'Waiting for the agent to report its assessment.';
   return `<li><strong>${h(item?.hostname||job.server_id)}</strong> · ${h(detail)}</li>`;
  });
  result.ready=ready;result.expires=expires;
  result.message=`<ul class="firewall-assessment-list">${lines.join('')}</ul>`;
 }catch(error){result.ready=false;result.message=`<p class="form-error">${h(error.message)}</p>`;}
 finally{result.loading=false;if($('#modal').open&&$('#firewall-activation-form')===result.form)renderFirewallAssessment(result.form);}
}
function firewallActivationFactsHTML(facts={}){
 return `<p>firewalld: ${facts.firewalld_active?'active':'inactive / unknown'} (${h(facts.firewalld_enabled||'unknown')}) · UFW: ${facts.ufw_active?'active':'inactive / absent / unknown'} · ${h(facts.version||'unknown version')} / ${h(facts.backend||'unknown backend')}</p><p><strong>Protected actual SSH listeners:</strong> ${h((facts.ssh_ports||[]).join(', ')||'Unverified')}<br><strong>Restricted management sources:</strong> ${h((facts.management_sources||[]).join(', ')||'Unverified')}<br><strong>Agent-reported interface IPs:</strong> ${h((facts.ips||[]).join(', ')||'Unverified')}</p><details><summary>Discovered services / exact numeric translation</summary><p>Listeners: ${h((facts.discovered_ports||[]).map(row=>row.port+'/'+row.protocol).join(', ')||'None reported')}</p><div class="table-scroll"><table><thead><tr><th>Order / family</th><th>Source</th><th>Port</th><th>Action</th></tr></thead><tbody>${(facts.translated_rules||[]).map(row=>`<tr><td>${num(row.priority)} / ${h(row.family)}</td><td>${h(row.source)}</td><td>${num(row.port)}/${h(row.protocol)}</td><td>${h(row.action)}</td></tr>`).join('')||'<tr><td colspan="4">No numeric UFW rules translated for this operation.</td></tr>'}</tbody></table></div></details>${(facts.blockers||[]).map(text=>`<p class="form-error">${h(text)}</p>`).join('')}${(facts.notes||[]).map(text=>`<p class="help-text">${h(text)}</p>`).join('')}`;
}
function showFirewallActivationReview(plan){
 state.firewallActivationReview=plan;state.firewallActivationReviewOwner=firewallActivationIdentity();
 const canApply=canWrite()&&plan.can_apply===true&&!(plan.blockers||[]).length;
 showModal('Review firewall maintenance',`<form id="firewall-activation-review-form"><div class="modal-body">${errorSlot}<p class="inline-notice warning">${h(firewallMaintenanceOperations[plan.operation]||'Endpoint maintenance')} can change live access even when ordinary policy enforcement is monitor-only. Discovered business ports can be blocked. SSH/controller health does not prove every application dependency.</p><p>Expires ${h(timestamp(plan.expires_at))}. No second administrator is required.</p>${!(plan.targets||[]).length?(plan.blockers||[]).map(text=>`<p class="form-error">${h(text)}</p>`).join(''):''}${(plan.targets||[]).map(target=>`<article><h3>${h(target.hostname||target.server_id)}</h3>${firewallActivationFactsHTML(target.assessment||{})}<p class="help-text">Exact native baseline: ${h(target.baseline_digest)}</p>${(target.blockers||[]).map(text=>`<p class="form-error">${h(text)}</p>`).join('')}</article>`).join('')}${canApply?`<div class="field"><label>Type the exact phrase<code class="platform-confirmation-phrase">${h(plan.challenge)}</code><input id="firewall-activation-phrase" name="confirmation_phrase" autocomplete="off"></label></div><label class="host-check"><input id="firewall-activation-ack" name="acknowledge_downtime" type="checkbox">I understand this exact service start / reviewed reload can cause downtime.</label><p class="help-text">Acknowledgement starts unchecked for every review and push attempt. The independent watchdog restores the exact previous configuration and service activity when recovery is provable. An unverified rollback is an error, never a success.</p>`:''}</div><div class="modal-footer"><button class="button secondary" type="button" data-action="close-modal">Close</button>${canApply?'<button class="button danger" type="submit" disabled>Apply reviewed maintenance</button>':canWrite()?'<button class="button secondary" type="button" data-action="firewall-activation-open">Return to assessment</button>':''}</div></form>`,'FROZEN ENDPOINTS · AUTHENTICATED HEALTH · INDEPENDENT ROLLBACK');
}
function firewallActivationReviewUsable(plan,phrase,ack){return canWrite()&&state.firewallActivationReviewOwner===firewallActivationIdentity()&&plan?.status==='preview'&&plan.can_apply===true&&!(plan.blockers||[]).length&&!!plan.digest&&!!plan.confirmation_nonce&&Date.parse(plan.expires_at)>Date.now()&&phrase===plan.challenge&&ack===true;}
function firewallActivationInput(event){if(event.target.form?.id==='firewall-activation-form'){renderFirewallAssessment(event.target.form);return true;}if(!['firewall-activation-phrase','firewall-activation-ack'].includes(event.target.id))return false;const form=$('#firewall-activation-review-form');if(form)$('button[type="submit"]',form).disabled=!firewallActivationReviewUsable(state.firewallActivationReview,$('#firewall-activation-phrase').value,$('#firewall-activation-ack').checked);return true;}
async function firewallActivationAction(button){
 const action=button.dataset.action;if(!action?.startsWith('firewall-activation-'))return false;
 if(action==='firewall-activation-open'){showFirewallActivationForm(button.dataset.id||'',button.dataset.operation||'');return true;}
 if(action==='firewall-activation-refresh'){await loadFirewallActivation();return true;}
 if(action==='firewall-activation-previous'||action==='firewall-activation-next'){state.firewallActivationOffset=Math.max(0,num(state.firewallActivationOffset)+(action.endsWith('next')?50:-50));await loadFirewallActivation();return true;}
 const owner=firewallActivationIdentity();button.disabled=true;
 try{
  if(action==='firewall-activation-assess'){
   if(!canWrite())return true;
   const form=$('#firewall-activation-form'),selection=firewallActivationSelection(form);
   const response=await api('/firewall-activation/assess',{method:'POST',body:selection});
   if(owner!==firewallActivationIdentity()||!$('#modal').open||$('#firewall-activation-form')!==form)return true;
   state.firewallActivationAssessment={owner,form,key:firewallAssessmentKey(selection),jobs:response.items||[],ready:false,message:'<p class="help-text">Waiting for the agent to report its assessment.</p>'};
   renderFirewallAssessment(form);
   toast('Read-only endpoint assessment requested.');
   await refreshFirewallActivationAssessment();
  }else if(action==='firewall-activation-inspect'){
   const page=await api('/firewall-activation/query',{method:'POST',body:{server_ids:[button.dataset.id],limit:1,details:true}});if(owner!==firewallActivationIdentity())return true;const item=page.items?.[0];if(item)showModal('Endpoint firewall details',`<div class="modal-body"><h3>${h(item.hostname||item.server_id)}</h3>${firewallActivationReceiptHTML(item)}${item.receipt?.assessment?firewallActivationFactsHTML(item.receipt.assessment):'<p class="help-text">Request an assessment to check the endpoint’s firewall and protected SSH access.</p>'}</div><div class="modal-footer"><button class="button secondary" data-action="close-modal">Close</button>${canWrite()?'<button type="button" class="button secondary" data-action="endpoint-configuration" data-id="'+h(item.server_id)+'">Configure protected SSH access</button>':''}</div>`,'ENDPOINT FIREWALL SERVICE');
  }
 }catch(error){if(owner===firewallActivationIdentity())formError(new Error([error.message,...(error.payload?.blockers||[])].join(' ')));}finally{button.disabled=false;}return true;
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
   if(owner!==firewallActivationIdentity())return true;state.firewallActivationReview=null;closeModal();toast('Maintenance intent assigned. Wait for authenticated endpoint completion or rollback receipts; queued is not applied.');await loadFirewallActivation();
  }
 }catch(error){if(owner===firewallActivationIdentity())formError(new Error([error.message,...(error.payload?.blockers||[])].join(' ')));}finally{if(submit&&form.id==='firewall-activation-form')submit.disabled=false;}return true;
}
