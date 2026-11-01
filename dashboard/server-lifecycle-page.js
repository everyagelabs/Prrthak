'use strict';

async function loadServerReservations() {
  if(state.reservationsLoading)return;state.reservationsLoading=true;
  try{const value=await api('/server-reservations');state.reservations=value.items || [];state.reservationsLoaded=true;state.reservationsError='';}
  catch(error){state.reservationsError=error.message;state.reservations=[];}
  finally{state.reservationsLoading=false;if(state.view==='servers'&&!$('#modal').open)render();}
}
function serverReservationsHTML() {
  const items=state.reservations || [];
  return `<section class="card reservation-list"><div class="card-header"><div><h2 class="card-title">Pending enrollment</h2><p class="card-subtitle">Planned servers appear in active inventory only after certificate enrollment and discovery.</p></div><button class="button secondary small" data-action="reservation-refresh">${icon('refresh')}Refresh</button></div>${state.reservationsError?`<div class="inline-notice warning">${h(state.reservationsError)}</div>`:''}<div class="table-scroll"><table><thead><tr><th>Planned hostname</th><th>Planned addresses · unverified</th><th>Registration</th><th></th></tr></thead><tbody>${items.map(item=>`<tr><td><strong>${h(item.hostname)}</strong><small>Added ${h(timestamp(item.created_at))}</small></td><td><code>${h((item.planned_ips || item.ips || []).join(', ') || 'Discovered after installation')}</code><small>Planned addresses do not enter source-policy membership.</small></td><td>${badge('Waiting for agent','neutral')}</td><td>${canWrite()?`<div class="server-lifecycle-actions"><button class="text-button" data-action="reservation-token" data-id="${h(item.id)}">Generate enrollment token</button><button class="text-button danger-text" data-action="server-lifecycle-delete-review" data-id="${h(item.id)}">Retire registration</button></div>`:''}</td></tr>`).join('') || `<tr><td colspan="4">${state.reservationsLoading?'Loading planned servers…':'No pending server registrations. Install an agent for automatic discovery, or add a planned server first.'}</td></tr>`}</tbody></table></div></section>`;
}
function showServerReservation() {
  if(!canWrite())return;
  showModal('Add a server',`<form id="server-reservation-form"><div class="modal-body">${errorSlot}<div class="inline-notice">Create a planned registration, then install the agent with a token bound to it. The agent must report this exact hostname. Inventory and source-policy membership begin after enrollment.</div><div class="field"><label for="reservation-hostname">Expected hostname</label><input id="reservation-hostname" name="hostname" required maxlength="253" placeholder="billing-api-21" autocomplete="off"></div><div class="field"><label for="reservation-addresses">Planned IP addresses (optional)</label><input id="reservation-addresses" name="ips" placeholder="10.241.1.21, 2001:db8::21" autocomplete="off"><small>Comma-separated numeric IPv4/IPv6 addresses. These are planning information, not verified endpoint ownership.</small></div><p class="help-text">Tags and DC assignments stay in the dashboard. You can prepare central CSV/subnet rules before installation or assign the enrolled server afterward.</p></div>${modalFooter('Add pending server')}</form>`,'SERVER ONBOARDING');
}
async function reservationSubmit(event) {
  event.preventDefault();if(!canWrite())return;const form=event.target,submit=$('button[type="submit"]',form);submit.disabled=true;
  try{const values=new FormData(form),body={hostname:String(values.get('hostname') || '').trim(),ips:String(values.get('ips') || '').split(',').map(value=>value.trim()).filter(Boolean)};if(!body.hostname)throw new Error('Enter the hostname the agent will discover.');const result=await api('/servers',{method:'POST',body});closeModal();await loadServerReservations();toast('Server added to pending enrollment.');showReservationToken(result.id);}
  catch(error){formError(error);}finally{submit.disabled=false;}
}
function showReservationToken(id) {
  if(!canWrite())return;const item=state.reservations.find(value=>value.id===id);if(!item)return;
  showModal('Enroll '+item.hostname,`<div class="modal-body">${errorSlot}<div class="inline-notice">This single-use token is bound to the planned server <strong>${h(item.hostname)}</strong>. Install it only on that server. Its discovered hostname must match.</div><p class="help-text">Generate the token immediately before installation. Save it in a root-owned file with mode 0600 and supply the trusted controller CA. No business tags or DC values are sent by the agent.</p><button class="button primary" data-action="reservation-token-generate" data-id="${h(id)}">Generate bound enrollment token</button><div id="reservation-token-result"></div></div>`,'SECURE SERVER BOOTSTRAP');
}
function serverDeleteCanConfirm(plan) {
  return plan?.can_delete===true&&!!plan.id&&!!plan.confirmation_nonce&&!(plan.blockers || []).length&&!!plan.expires_at&&new Date(plan.expires_at)>new Date();
}
function serverDeleteImpactHTML(impact) {
  if(!impact)return '';
  if(typeof impact==='string')return `<div class="inline-notice">${h(impact)}</div>`;
  return `<details class="server-retirement-impact" open><summary>Reviewed impact</summary><dl>${Object.entries(impact).map(([key,value])=>`<dt>${h(humanize(key))}</dt><dd>${h(Array.isArray(value)?value.map(item=>typeof item==='object'?metadataNoteText(item):item).join(', ') || 'None':typeof value==='object'&&value!==null?JSON.stringify(value):value)}</dd>`).join('')}</dl></details>`;
}
function showServerDelete(plan,id) {
  if(!canWrite())return;state.serverDeletePlan={plan,server_id:id};
  const server=plan.server || plan.before || state.data?.servers.find(item=>item.id===id) || state.reservations.find(item=>item.id===id) || {},blockers=plan.blockers || [],warnings=plan.warnings || [],valid=serverDeleteCanConfirm(plan);
  showModal('Review server retirement',`<div class="modal-body">${errorSlot}<div class="inline-notice warning">Retire this endpoint identity from Prṛthak. Endpoint firewall rules need a separately approved cleanup before retirement. Resolve every blocker shown below.</div><dl class="server-lifecycle-summary"><dt>Server</dt><dd>${h(server.hostname || serverName(id))}</dd><dt>Endpoint identity</dt><dd><code>${h(id)}</code></dd><dt>${plan.kind==='reservation'?'Planned / unverified':'Agent-reported'} addresses</dt><dd>${h((plan.kind==='reservation'?(server.planned_ips || server.ips || []):(server.ips || [])).join(', ') || 'Not reported')}</dd></dl>${blockers.length?`<div class="form-error">This server cannot be retired yet.</div><ul class="server-retirement-blockers">${blockers.map(item=>`<li>${h(metadataNoteText(item))}</li>`).join('')}</ul>`:'<p class="help-text">The controller will revoke this endpoint registration, recalculate affected membership and preserve historical audit records. The reviewed state is checked again before retirement.</p>'}${warnings.length?`<ul class="server-retirement-warnings">${warnings.map(item=>`<li>${h(metadataNoteText(item))}</li>`).join('')}</ul>`:''}${serverDeleteImpactHTML(plan.impact)}${plan.expires_at?`<p class="help-text">Review expires ${h(timestamp(plan.expires_at))}.</p>`:'<div class="form-error">This review is incomplete. Refresh the review before retiring the server.</div>'}</div><div class="modal-footer"><button class="button secondary" data-action="close-modal">Cancel</button><button class="button secondary" data-action="server-lifecycle-delete-review" data-id="${h(id)}">Refresh review</button><button class="button danger" data-action="server-lifecycle-delete-confirm" ${!valid?'disabled':''}>Retire server registration</button></div>`,'REVIEWED ENDPOINT RETIREMENT');
}
async function serverLifecycleAction(button) {
  const {action,id}=button.dataset;
  if(action==='reservation-refresh')return loadServerReservations();
  if(!canWrite())return;
  if(action==='reservation-new')return showServerReservation();
  if(action==='reservation-token')return showReservationToken(id);
  if(action==='reservation-token-generate'){
    const item=state.reservations.find(value=>value.id===id);if(!item)return;
    button.disabled=true;try{const value=await api('/enrollment-tokens',{method:'POST',body:{name:'Enroll '+item.hostname,server_id:id}});$('#reservation-token-result').innerHTML=`<p class="help-text">Single use · expires ${h(timestamp(value.expires_at))}</p><div class="token-box"><code>${h(value.token)}</code></div><small class="help-text">Keep this token private. Pass it through a protected file or provisioning secret.</small>`;}catch(error){formError(error);}finally{button.disabled=false;}return;
  }
  if(action==='server-lifecycle-delete-review'){
    button.disabled=true;try{showServerDelete(await api('/servers/'+encodeURIComponent(id)+'/delete-preview',{method:'POST',body:{}}),id);}catch(error){toast(error.message,true);}finally{button.disabled=false;}return;
  }
  if(action==='server-lifecycle-delete-confirm'){
    const current=state.serverDeletePlan;if(!serverDeleteCanConfirm(current?.plan)){formError(new Error('This review has expired or is incomplete. Refresh it before retiring this server.'));return;}
    button.disabled=true;try{await api('/servers/'+encodeURIComponent(current.server_id)+'/delete-confirm',{method:'POST',body:{plan_id:current.plan.id,confirmation_nonce:current.plan.confirmation_nonce}});state.serverDeletePlan=null;metadataSelection().delete(current.server_id);closeModal();closeDrawer();await load();toast('Server registration retired.');}catch(error){formError(error);}finally{button.disabled=false;}
  }
}
