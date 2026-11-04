'use strict';

const endpointRenewalLabels = {
  scheduled: 'Scheduled',
  pending: 'Waiting for agent',
  issued: 'Awaiting confirmation',
  confirmed: 'Confirmed by agent',
  expired: 'Expired',
  superseded: 'Superseded'
};
function platformEndpointRenewalCanSchedule(data) {
  return canManagePlatform() && state.authType === 'session' && !state.platformEndpointCertificatesError && data?.renewal_available === true &&
    data.renewal_eligible > 0 && data.renewal_rollout?.status !== 'running';
}
function platformEndpointRenewalHTML(data) {
  if (!canManagePlatform() || typeof data.renewal_available !== 'boolean') return '';
  const rollout = data.renewal_rollout;
  const pending = num(rollout?.counts?.scheduled) + num(rollout?.counts?.pending) + num(rollout?.counts?.issued);
  const label = {running: 'Renewal in progress', complete: 'Renewal ended', expired: 'Renewal window expired'}[rollout?.status];
  return `<div class="section-line">
    <div><h3>Bulk certificate renewal</h3><p class="help-text">${data.renewal_available ? `${format(data.renewal_eligible)} eligible endpoints · No agent restart` : 'Renewal is unavailable on this controller.'}</p></div>
    <button class="button secondary small" type="button" data-action="platform-endpoint-renewal-preview" ${platformEndpointRenewalCanSchedule(data) ? '' : 'disabled'}>Review renewal</button>
  </div>${label ? `<div class="inline-notice"><strong>${label}</strong> · ${format(rollout.counts?.confirmed)} confirmed of ${format(rollout.target_count)} · ${format(pending)} waiting · ${format(rollout.counts?.expired)} expired · ${format(rollout.counts?.superseded)} superseded</div>` : ''}`;
}
function platformEndpointRenewalReviewReady(review, phrase) {
  const plan = review?.plan;
  return canManagePlatform() && state.authType === 'session' && review?.owner === accessIdentityKey() &&
    platformUI.reviewReady({...plan,can_apply:plan?.can_apply !== false},state.role) &&
    !!plan.confirmation_nonce && plan.target_count > 0 && platformUI.exactPhrase(plan,phrase);
}
async function platformEndpointRenewalPreview(button) {
  if (!platformEndpointRenewalCanSchedule(state.platformEndpointCertificates) || button.disabled) return;
  const owner = accessIdentityKey();
  const current = () => button.isConnected !== false && state.view === 'settings' &&
    state.platformTab === 'certificates' && canManagePlatform() && owner === accessIdentityKey();
  button.disabled = true;
  try {
    const plan = await api('/platform/endpoint-certificates/renewal-preview',{method:'POST',body:{}});
    if (!current() || $('#modal').open) return;
    state.endpointRenewalReview = {plan,owner};
    showModal('Review bulk certificate renewal',`<form id="platform-endpoint-renewal-form" data-id="${h(plan.id)}"><div class="modal-body">${errorSlot}
      <p><strong>${format(plan.target_count)} eligible endpoints</strong> · ${format(plan.skipped_count)} skipped</p>
      <p class="help-text">Up to ${format(plan.batch_size)} endpoints per ${format(plan.interval_seconds)} seconds. The agent verifies the new certificate and reports confirmation without restarting.</p>
      ${(plan.blockers || []).map(reason=>`<p class="form-error">${h(reason)}</p>`).join('')}
      <div class="field"><label for="endpoint-renewal-phrase">Type the exact confirmation phrase</label><code class="platform-confirmation-phrase">${h(plan.confirmation_phrase)}</code><input id="endpoint-renewal-phrase" name="confirmation_phrase" autocomplete="off" spellcheck="false"></div>
      <p class="help-text">Review expires ${h(timestamp(plan.expires_at))}.</p>
    </div><div class="modal-footer"><button type="button" class="button secondary" data-action="close-modal">Cancel</button><button type="submit" class="button primary" disabled>Schedule renewal</button></div></form>`,'ENDPOINT CERTIFICATES');
  } catch (error) {
    if (current()) toast(error.message,true);
  } finally {
    button.disabled = false;
  }
}
async function platformEndpointRenewalSubmit(event) {
  event.preventDefault();
  if (!canManagePlatform() || state.endpointRenewalApplying) return;
  const form = event.target, review = state.endpointRenewalReview;
  const phrase = String(new FormData(form).get('confirmation_phrase') || '');
  if (form.dataset.id !== review?.plan?.id || !platformEndpointRenewalReviewReady(review,phrase)) {
    platformHAError(form,new Error('Open a fresh renewal review and type its exact confirmation phrase.'));
    return;
  }
  const button = $('button[type="submit"]',form), plan = review.plan;
  const current = () => form.isConnected !== false && state.endpointRenewalReview === review &&
    review.owner === accessIdentityKey() && canManagePlatform();
  state.endpointRenewalApplying = true;
  button.disabled = true;
  try {
    await api('/platform/endpoint-certificates/renewal-apply',{method:'POST',body:{
      preview_id:plan.id,digest:plan.digest,confirmation_nonce:plan.confirmation_nonce,confirmation_phrase:phrase
    }});
    if (!current()) return;
    state.endpointRenewalReview = null;
    closeModal();
    toast('Renewal scheduled. Watch for agent confirmations.');
    await loadEndpointCertificates();
  } catch (error) {
    if (current()) {
      platformHAError(form,error);
      if (error.status === 409) state.endpointRenewalReview = null;
    }
  } finally {
    state.endpointRenewalApplying = false;
    button.disabled = !platformEndpointRenewalReviewReady(state.endpointRenewalReview,phrase);
  }
}
function platformInternalCertificatesHTML(){
  const data=state.platformInternalCertificates || {},nodes=data.nodes || [],operation=data.local_operation,runtime=data.local_runtime;
  return `<section class="card platform-panel"><div class="section-line"><h2>Internal appliance identities</h2><button class="text-button" data-action="platform-internal-certificates-refresh">Refresh internal status</button></div>${state.platformInternalCertificatesError?`<p class="inline-notice warning">${h(state.platformInternalCertificatesError)}</p>`:''}<p class="platform-intro">Same-CA, same-key leaf renewal uses a ${num(data.leaf_lifetime_days || 90)}-day lifetime and a ${num(data.renew_before_days || 30)}-day renewal window. Staged certificates remain separate from verified runtime identities.</p><div class="inline-notice warning">Suspension blocks future synchronization, renewal and web routing. It does not revoke database credentials or CA material already held by that controller. Secure decommission requires fenced offline recovery and rotation of the internal CA and all shared secrets.</div><div class="table-scroll"><table><thead><tr><th>Controller / site</th><th>Certificate expiry</th><th>Membership</th><th>Runtime verification</th><th>Actions</th></tr></thead><tbody>${nodes.map(node=>{const info=node.certificate || {},expired=Number.isFinite(Date.parse(info.not_after))&&Date.parse(info.not_after)<=Date.now(),suspended=['suspended','revoked','decommissioning','decommissioned'].includes(node.state),verified=!suspended&&!expired&&node.applied?.runtime_verified===true&&node.applied?.fingerprint===info.fingerprint;return `<tr><td><strong>${h(node.id)}</strong><small>${h(node.site || 'Site not reported')} · controller address ${h(node.ip || 'Not reported')}</small></td><td>${h(timestamp(info.not_after))}<small>${Number.isInteger(node.days_remaining)?node.days_remaining+' days remaining':'Validity not reported'}${node.renewal_due?' · Renewal due':''}</small></td><td>${badge(node.state?humanize(node.state):'Not reported',suspended?'warning':'neutral')}<small>Renewal ${node.renewal_allowed===true?'permitted':node.renewal_allowed===false?'blocked':'not reported'}</small></td><td>${badge(suspended?'Suspended · credentials may remain valid':expired?'Expired':verified?'Exact identity verified':node.applied?'Staged or verification pending':'Not reported',verified?'':suspended||expired?'warning':'neutral')}</td><td>${canManagePlatform()&&node.decommission_gate?.can_suspend===true?`<button class="text-button danger-text" data-action="platform-internal-suspend" data-id="${h(node.id)}">Review suspension</button>`:'—'}<details><summary>Decommission requirements</summary>${(node.decommission_gate?.blockers || []).map(reason=>`<p class="help-text">${h(reason)}</p>`).join('')}</details></td></tr>`;}).join('') || '<tr><td colspan="5">No registered internal appliance identities have been reported.</td></tr>'}</tbody></table></div><dl class="detail-grid"><div><dt>Local runtime phase</dt><dd>${h(runtime?.phase || runtime?.status || 'Not reported')}</dd></div><div><dt>Local renewal operation</dt><dd>${h(operation?.phase || 'No operation reported')}</dd></div></dl>${data.error||operation?.error?`<p class="form-error">${h(data.error || operation.error)}</p>`:''}</section>`;
}
function platformEndpointCertificatesHTML(){
  const data=state.platformEndpointCertificates || {},trust=state.platformPolicyTrust,keys=Object.keys(trust?.keys || {}),items=data.items || [];
  const newestByEndpoint = new Map(items.map(row=>[row.server_id,row]));
  return `<section class="card platform-panel"><div class="section-line"><h2>Endpoint certificate identities</h2><button class="text-button" data-action="platform-endpoint-certificates-refresh">Refresh identities</button></div>${state.platformEndpointCertificatesError?`<p class="inline-notice warning">${h(state.platformEndpointCertificatesError)}</p>`:''}<p class="platform-intro">Renewal window: ${num(data.renewal_window_days ?? 30)} days before expiry. Previous-credential overlap: ${num(data.old_certificate_overlap_hours ?? 24)} hours. Revocation blocks endpoint authentication at the controller; existing endpoint firewall rules remain in force.</p>${platformEndpointRenewalHTML(data)}<div class="table-scroll"><table><thead><tr><th>Server</th><th>Identity</th><th>Expires</th><th>Status</th><th>Actions</th></tr></thead><tbody>${items.map(row=>{const expired=Number.isFinite(Date.parse(row.not_after))&&Date.parse(row.not_after)<=Date.now(),label=row.status==='revoked'?'Revoked':expired?'Expired':row.status==='retiring'?'Retiring':row.status==='active'?'Active':'Not reported';return `<tr><td><strong>${h(row.hostname || row.server_id)}</strong></td><td><code class="endpoint-certificate-fingerprint">${h(row.fingerprint_sha256)}</code><small>Serial ${h(row.serial_number)}</small></td><td>${h(timestamp(row.not_after))}</td><td>${badge(label,label==='Revoked'||label==='Expired'?'danger':label==='Retiring'?'warning':label==='Active'?'':'neutral')}${newestByEndpoint.get(row.server_id)===row && endpointRenewalLabels[row.renewal_status]?`<small>${h(endpointRenewalLabels[row.renewal_status])}${row.renewal_status==='scheduled'?' · '+h(timestamp(row.renewal_not_before)):''}</small>`:''}</td><td>${canManagePlatform()?`<div class="platform-backup-actions">${row.status!=='revoked'?`<button class="text-button danger-text" data-action="platform-endpoint-revoke" data-id="${h(row.server_id)}">Review host revocation</button>`:''}<button class="text-button" data-action="platform-endpoint-recovery" data-id="${h(row.server_id)}">Issue recovery token</button></div>`:'—'}</td></tr>`;}).join('') || '<tr><td colspan="5">No endpoint certificate identities have been registered.</td></tr>'}</tbody></table></div></section><section class="card platform-panel"><div class="section-line"><h2>Policy signing trust</h2><button class="button secondary small" data-action="platform-policy-trust-download" ${!trust||!keys.length?'disabled':''}>Download public trust JSON</button></div><p class="help-text">Pin this public trust document during agent setup. The transport CA and policy-signing authority serve separate purposes. Private signing keys are never returned.</p>${state.platformPolicyTrustError?`<p class="inline-notice warning">${h(state.platformPolicyTrustError)}</p>`:''}<dl class="detail-grid"><div><dt>Trust deployment</dt><dd>${h(trust?.deployment_id || 'Not reported')}</dd></div></dl>${keys.map(id=>`<article class="policy-trust-key"><strong>Signing key ${h(id)}</strong><small>SHA-256 public-key fingerprint</small><code>${h(state.platformPolicyTrustFingerprints?.[id] || 'Fingerprint computation unavailable')}</code></article>`).join('') || '<p class="help-text">Policy signing trust is not available.</p>'}</section>`;
}
async function loadEndpointCertificates(redraw=true){
  if(!canManagePlatform())return;
  const results=await Promise.allSettled([api('/platform/endpoint-certificates'),api('/platform/policy-signing-trust'),api('/platform/internal-certificates')]);
  if(results[2].status==='fulfilled'){state.platformInternalCertificates=results[2].value;state.platformInternalCertificatesError='';}else state.platformInternalCertificatesError='Internal identity status is unavailable: '+results[2].reason.message;
  if(results[0].status==='fulfilled'){state.platformEndpointCertificates=results[0].value;state.platformEndpointCertificatesError='';}else state.platformEndpointCertificatesError='Endpoint identities are unavailable: '+results[0].reason.message;
  if(results[1].status==='fulfilled'){state.platformPolicyTrust=results[1].value;state.platformPolicyTrustError='';state.platformPolicyTrustFingerprints={};for(const [id,key] of Object.entries(results[1].value.keys || {})){try{const bytes=Uint8Array.from(atob(key.replace(/-/g,'+').replace(/_/g,'/')),char=>char.charCodeAt(0)),hash=await globalThis.crypto.subtle.digest('SHA-256',bytes);state.platformPolicyTrustFingerprints[id]=Array.from(new Uint8Array(hash),byte=>byte.toString(16).padStart(2,'0')).join('');}catch{}}}else state.platformPolicyTrustError='Policy signing trust is unavailable: '+results[1].reason.message;
  if(redraw&&state.view==='settings'&&!platformHasDraft()&&!$('#modal').open&&!document.activeElement?.matches('input,select,textarea'))render();
}
function endpointRevocationReady(plan,phrase){return canManagePlatform()&&platformUI.reviewReady({...plan,can_apply:true},state.role)&&!!plan.confirmation_nonce&&platformUI.exactPhrase(plan,phrase);}
function platformEndpointCertificateInput(event){if(event.target.id==='endpoint-renewal-phrase'){const form=$('#platform-endpoint-renewal-form');if(form)$('button[type="submit"]',form).disabled=state.endpointRenewalApplying||!platformEndpointRenewalReviewReady(state.endpointRenewalReview,event.target.value);return true;}if(event.target.id==='internal-suspend-phrase'){$('button[type="submit"]',$('#platform-internal-suspend-form')).disabled=!internalSuspensionReady(state.internalSuspensionReview,event.target.value);return true;}if(event.target.id!=='endpoint-revoke-phrase')return false;$('button[type="submit"]',$('#platform-endpoint-revoke-form')).disabled=!endpointRevocationReady(state.endpointRevocationReview,event.target.value);return true;}
function internalSuspensionReady(plan,phrase){return canManagePlatform()&&platformUI.reviewReady(plan,state.role)&&!!plan.confirmation_nonce&&platformUI.exactPhrase(plan,phrase);}
async function platformInternalSuspendSubmit(event){
  event.preventDefault();if(!canManagePlatform())return;const form=event.target,button=$('button[type="submit"]',form);button.disabled=true;try{const plan=state.internalSuspensionReview,phrase=String(new FormData(form).get('confirmation_phrase') || '');if(!internalSuspensionReady(plan,phrase))throw new Error('Use a fresh unblocked suspension review and its exact phrase.');const result=await api('/platform/internal-certificates/suspend-apply',{method:'POST',body:{preview_id:plan.id,digest:plan.digest,confirmation_nonce:plan.confirmation_nonce,confirmation_phrase:phrase}});state.internalSuspensionReview=null;closeModal();await loadEndpointCertificates();toast(result.state==='suspended'?'Controller synchronization and renewal suspended. Existing runtime credentials are not revoked.':'Suspension requested. Refresh the reported membership state.');}catch(error){platformHAError(form,error);if(error.status===409)state.internalSuspensionReview=null;}finally{button.disabled=false;}
}
async function platformEndpointCertificateSubmit(event){
  event.preventDefault();if(!canManagePlatform())return;const form=event.target,button=$('button[type="submit"]',form);button.disabled=true;try{const plan=state.endpointRevocationReview,phrase=String(new FormData(form).get('confirmation_phrase') || '');if(!endpointRevocationReady(plan,phrase))throw new Error('Use a fresh exact endpoint-identity review and confirmation phrase.');const result=await api('/platform/endpoint-certificates/revoke-apply',{method:'POST',body:{preview_id:plan.id,digest:plan.digest,confirmation_nonce:plan.confirmation_nonce,confirmation_phrase:phrase}});state.endpointRevocationReview=null;closeModal();await loadEndpointCertificates();toast(result.status==='revoked'?'The reviewed endpoint identities were revoked.':'Revocation requested. Refresh identity status to verify the result.');}catch(error){platformHAError(form,error);if(error.status===409)state.endpointRevocationReview=null;}finally{button.disabled=false;}
}
async function platformEndpointCertificateAction(button){
  if(!canManagePlatform())return;const {action,id}=button.dataset;
  if(action==='platform-endpoint-renewal-preview')return platformEndpointRenewalPreview(button);
  if(action==='platform-endpoint-certificates-refresh')return loadEndpointCertificates();
  if(action==='platform-internal-certificates-refresh')return loadEndpointCertificates();
  if(action==='platform-internal-suspend'){try{const plan=await api('/platform/internal-certificates/suspend-preview',{method:'POST',body:{node_id:id,expected_revision:state.platformInternalCertificates?.revision}});state.internalSuspensionReview=plan;const node=plan.summary?.node || {};showModal('Review controller suspension',`<form id="platform-internal-suspend-form"><div class="modal-body">${errorSlot}<div class="inline-notice warning">${h(plan.summary?.warning || 'This blocks synchronization and renewal. It does not revoke runtime database credentials or copied CA secrets.')}</div><p><strong>${h(node.id)}</strong> · ${h(node.site)} · ${h(node.ip)}</p><p>Runtime database credentials are not revoked. This does not remove the database voter or complete decommissioning.</p>${(plan.blockers || []).map(reason=>`<p class="form-error">${h(reason)}</p>`).join('')}<div class="field"><label for="internal-suspend-phrase">Type the exact confirmation phrase</label><code class="platform-confirmation-phrase">${h(plan.confirmation_phrase)}</code><input id="internal-suspend-phrase" name="confirmation_phrase" autocomplete="off"></div></div><div class="modal-footer"><button type="button" class="button secondary" data-action="close-modal">Cancel</button><button type="submit" class="button danger" disabled>Suspend sync and renewal</button></div></form>`,'SUSPENSION · NOT RUNTIME REVOCATION');}catch(error){formError(error);}return;}
  if(action==='platform-policy-trust-download'){const trust=state.platformPolicyTrust;if(!trust?.deployment_id||!Object.keys(trust.keys || {}).length)return;const url=URL.createObjectURL(new Blob([JSON.stringify(trust,null,2)+'\n'],{type:'application/json'})),link=document.createElement('a');link.href=url;link.download='prthak-policy-trust.json';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);return;}
  if(action==='platform-endpoint-revoke'){try{const plan=await api('/platform/endpoint-certificates/revoke-preview',{method:'POST',body:{server_id:id}});state.endpointRevocationReview=plan;showModal('Review endpoint certificate revocation',`<form id="platform-endpoint-revoke-form"><div class="modal-body">${errorSlot}<p class="inline-notice warning">${h(plan.message)}</p><p>Endpoint: <strong>${h((state.platformEndpointCertificates?.items || []).find(row=>row.server_id===id)?.hostname || id)}</strong></p><p>${num(plan.certificate_ids?.length)} registered identities are in this exact review. A changed identity set requires another review.</p><div class="field"><label for="endpoint-revoke-phrase">Type the exact confirmation phrase</label><code class="platform-confirmation-phrase">${h(plan.confirmation_phrase)}</code><input id="endpoint-revoke-phrase" name="confirmation_phrase" autocomplete="off"></div><p class="help-text">Review expires ${h(timestamp(plan.expires_at))}.</p></div><div class="modal-footer"><button type="button" class="button secondary" data-action="close-modal">Cancel</button><button type="submit" class="button danger" disabled>Revoke reviewed endpoint identities</button></div></form>`,'ENDPOINT IDENTITY REVIEW');}catch(error){formError(error);}return;}
  if(action==='platform-endpoint-recovery'){button.disabled=true;try{const result=await api('/platform/endpoint-certificates/recovery-token',{method:'POST',body:{server_id:id}});showModal('One-time endpoint recovery token',`<div class="modal-body">${errorSlot}<p class="inline-notice warning">Shown once. Keep this token private and give it only to the operator recovering this endpoint. It expires ${h(timestamp(result.expires_at))}.</p><p>Endpoint ${h(result.server_id)}. A recovery token does not itself revoke existing credentials; revoke compromised identities first.</p><div class="field"><label for="endpoint-recovery-token">One-time recovery token</label><textarea id="endpoint-recovery-token" readonly rows="3" autocomplete="off" spellcheck="false">${h(result.token)}</textarea></div></div><div class="modal-footer"><button class="button secondary" data-action="close-modal">Close and hide token</button></div>`,'PRIVATE ENDPOINT RECOVERY');}catch(error){formError(error);}finally{button.disabled=false;}}
}
