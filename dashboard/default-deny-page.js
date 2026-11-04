'use strict';

const defaultDenyAcknowledgement='I understand unapproved inbound connections will be blocked and this can cause downtime.';
const defaultDenyState={page:null,loading:false,error:'',sequence:0,offset:0,review:null,reviewSequence:0,targetIndex:0,submitting:false};

function defaultDenyMayWrite(){return canWrite()&&!state.data?.meta?.demo;}
function defaultDenyTone(status){return ['error','rollback_failed','blocked','conflict'].includes(status)?'danger':['applied','enforced'].includes(status)?'healthy':status==='review_required'?'warning':'neutral';}
function defaultDenyStatusLabel(status){return ({not_enabled:'Not enabled',removal_pending:'Removal pending · cleanup unverified',review_required:'Fresh downtime review required',pending:'Pending endpoint application',queued:'Queued · not yet applied',applied:'Applied · endpoint report',enforced:'Last reported enforced',disabled:'Disabled · no active fallback reported',rolled_back:'Rolled back · last-good retained',rollback_failed:'Rollback unverified',blocked:'Blocked',error:'Error',unverified:'No verified receipt'})[status]||status||'No verified receipt';}
function defaultDenyRedraw(){if(state.view==='policies'&&state.policyTab==='default-deny'&&!$('#modal')?.open)managedRedraw();}
function defaultDenyHTML(showFilters=true){
 const page=defaultDenyState.scope===defaultDenyScope().key?defaultDenyState.page:null,items=page?.items||[];
 return `${showFilters?filterBarHTML('default-deny'):''}<section class="card"><div class="section-line"><h2>Whole-server default deny<span>Separate, explicitly acknowledged pushes</span></h2><div class="inline-actions"><button class="button secondary small" data-action="default-deny-refresh">Refresh status</button><button class="button danger small" data-action="default-deny-new" ${!canWrite()?'disabled':''}>Review server ingress</button></div></div><p class="platform-intro">Block inbound connections except the exact allowed source/port matrix and verified management paths in your review. Ordinary policy saves do not activate this feature. Each new deny-bearing bundle needs a fresh, manually checked downtime acknowledgement; until then an already protected endpoint retains its last-good bundle.</p><div class="inline-notice warning"><strong>Fallback action: REJECT.</strong> Applies to new inbound connections; established sessions are preserved. Existing sessions are not terminated and conntrack is not flushed. This can interrupt applications. Review IPv4 and IPv6, actual SSH ports, controller paths and every required inbound service. Groups freeze their current members; future members require another review and push. Endpoint capability, explicit local opt-in and rollback checks still apply.</div>${state.data?.meta?.demo?'<p class="inline-notice">Demo mode can inspect the controls. Preparing a real preview and pushing changes require an authenticated Admin.</p>':''}${defaultDenyState.error?`<p class="form-error" role="alert">${h(defaultDenyState.error)}</p>`:''}<div class="table-scroll"><table><thead><tr><th>Endpoint</th><th>Requested ingress state</th><th>Delivery / last verified outcome</th><th>Version / blockers</th><th>Actions</th></tr></thead><tbody>${items.map(row=>defaultDenyRowHTML(row)).join('')||`<tr><td colspan="5">${defaultDenyState.loading?'Loading endpoint ingress status…':page?'No whole-server default-deny records on this page. Unlisted hosts are not implicitly protected.':'Ingress status has not loaded.'}</td></tr>`}</tbody></table></div><div class="table-footer"><span>${page?`${items.length?num(page.offset)+1:0}–${items.length?num(page.offset)+items.length:0} of ${num(page.total)} endpoint records`:'Status not loaded'}</span><div><button class="text-button" data-action="default-deny-page" data-offset="${Math.max(0,num(page?.offset)-20)}" ${!page||num(page.offset)===0?'disabled':''}>Previous</button><button class="text-button" data-action="default-deny-page" data-offset="${num(page?.offset)+20}" ${!page?.has_more?'disabled':''}>Next</button></div></div></section>`;
}
function defaultDenyRowHTML(row){
 const outcome=row.last_outcome||{},status=['error','rolled_back','rollback_failed','blocked'].includes(row.status)?row.status:row.removal_pending?'removal_pending':row.status||'unverified';
 return `<tr><td><button class="text-button" data-action="default-deny-server" data-id="${h(row.server_id)}">${h(row.hostname||row.server_id)}</button><small>${h(row.server_id)}</small></td><td>${row.status==='not_enabled'?'No whole-server default-deny intent':row.desired_enabled===true?'Whole-server default deny requested':row.desired_enabled===false?'Disable requested':'No intent reported'}<small>Intent is not an applied receipt${row.removal_pending?'<br>Owned fallback cleanup is still pending.':''}</small>${row.active_verified===true?'<small>Last authenticated receipt reported an active fallback; this is not a live kernel probe.</small>':row.active===true?'<small>Earlier active fallback reported; its current state is unverified.</small>':''}</td><td>${badge(defaultDenyStatusLabel(status),defaultDenyTone(status))}${outcome.status?`<small><strong>${outcome.is_current===true?'Current push receipt':outcome.is_current===false?'Previous push receipt · does not verify this push':'Last recorded receipt'}</strong><br>Managed outcome ${h(outcome.status)} · v${h(outcome.version??'unreported')}<br>${h(outcome.rollout_id||'')}<br>${h(timestamp(outcome.updated_at))}</small>`:''}<small>${h(outcome.error||outcome.rollback_reason||row.error||'')}</small></td><td>Desired ${h(row.desired_version??'unreported')}<small>Reported applied ${h(row.applied_version??'unreported')} · last-good ${h(row.last_good_version??outcome.last_good_version??'unreported')}</small>${row.capable===false?'<small class="danger-text">Upgrade required: host_default_deny_v1 capability.</small>':''}${row.local_optin===false?'<small class="danger-text">Local allow_host_default_deny opt-in is off. Enabling requires a signed configuration kit; removing an existing fallback remains reviewable.</small>':''}<small>Allowed application services: ${num(row.allowed_service_count)} · protected SSH ${h((row.protected_ssh_ports||[]).join(', ')||'not reported')}</small>${(row.blockers||[]).map(reason=>`<small class="danger-text">${h(reason)}</small>`).join('')}</td><td>${canWrite()&&row.local_optin===false?'<button class="text-button" data-action="endpoint-configuration">Configure local opt-in</button> ':''}<button class="text-button" data-action="default-deny-host-review" data-id="${h(row.server_id)}" ${!canWrite()?'disabled':''}>Fresh ingress review</button></td></tr>`;
}
function defaultDenyShowSelection(serverId=''){
 if(!canWrite()||defaultDenyState.submitting)return;
 defaultDenyState.review=null;defaultDenyState.reviewSequence++;
 const servers=filteredServers(),groups=state.data?.groups||[];
 const choices=serverId?(state.data?.servers||[]).filter(server=>server.id===serverId):servers;
 showModal('Whole-server default deny',`<form id="default-deny-selection-form"><div class="modal-body">${errorSlot}<p>Choose exact endpoints or groups. The next step freezes current membership and shows the proposed allowed sources, ports and protected management paths.</p><div class="field"><label for="default-deny-operation">Requested operation</label><select id="default-deny-operation" name="operation"><option value="enable">Enable / update whole-server default deny</option><option value="disable">Disable owned whole-server default deny</option></select></div><fieldset><legend>Explicit endpoints · current workspace scope</legend><p class="help-text">${choices.length} endpoints available. No endpoint is selected automatically.${serverId?' Select this endpoint to review it.':''}</p><div class="host-checklist">${choices.map(server=>`<label class="host-check"><input type="checkbox" name="server_ids" value="${h(server.id)}">${h(server.hostname)} <small>${h((server.ips||[]).join(', '))}</small></label>`).join('')||'<p>No endpoints in the current scope.</p>'}</div></fieldset><fieldset><legend>Saved groups · current membership only</legend><div class="host-checklist">${groups.map(group=>`<label class="host-check"><input type="checkbox" name="group_ids" value="${h(group.id)}">${h(group.name)} <small>${h(group.type||'')}</small></label>`).join('')||'<p>No saved groups.</p>'}</div></fieldset><p class="help-text">Selecting a group never opts future members in automatically. A policy, source, tag or membership change cannot reuse this push acknowledgement.</p></div><div class="modal-footer"><button type="button" class="button secondary" data-action="close-modal">Cancel</button><button type="submit" class="button primary">Preview exact ingress change</button></div></form>`,'SELECTED ENDPOINTS · INBOUND ONLY');
}
function defaultDenyMatrixHTML(target){
 if(!target)return '<p class="form-error">No exact endpoint matrix is available.</p>';
 const services=target.services||[];
 return `<h3>${h(target.hostname||target.server_id)}</h3><dl class="detail-grid"><div><dt>Endpoint identity</dt><dd>${h(target.server_id)}</dd></div><div><dt>Frozen reported IPs</dt><dd>${h((target.ips||[]).join(', ')||'Not reported')}</dd></div><div><dt>Endpoint ingress revision</dt><dd>${h(target.revision??'Not reported')}</dd></div><div><dt>Current base → proposed bundle</dt><dd>${h(target.base_version??'Not reported')} → ${h(target.version??'Not reported')}</dd></div><div><dt>Bundle digest</dt><dd class="mono">${h(target.digest||'Not reported')}</dd></div><div><dt>Protection digest</dt><dd class="mono">${h(target.protection?.digest||target.protection_digest||'Not reported')}</dd></div></dl><h4>Allowed source / port matrix</h4><p class="help-text">Only enforcing grants are allowed here. Monitor-only policy rows do not open access under whole-server default deny. Verified management paths are listed separately.</p><div class="table-scroll"><table><thead><tr><th>Port / protocol</th><th>Exact approved sources</th></tr></thead><tbody>${services.map(service=>`<tr><td>${num(service.port)}/${h(service.protocol)}</td><td>${Array.isArray(service.sources)?`<details><summary>${service.sources.length} source scope${service.sources.length===1?'':'s'} · expand exact list</summary><pre class="detail-json">${h(service.sources.join('\n'))}</pre></details>`:'<span class="danger-text">Sources not supplied · incomplete review</span>'}</td></tr>`).join('')||'<tr><td colspan="2">No application-port grants in this snapshot. Review protected paths below.</td></tr>'}</tbody></table></div><h4>Protected management / controller paths</h4><p class="help-text"><strong>host-inbound-control-v1:</strong> preserves loopback and established connections, explicitly protected SSH management sources, ICMP/ICMPv6 network control, and DHCP client replies to UDP 68/546. These exceptions are separate from application grants. Unsupported forwarding/NAT, foreign direct rules or custom policies and multiple active zones block this adapter.</p><pre class="detail-json">${h(JSON.stringify(target.protection||{},null,2))}</pre>${(target.blockers||[]).length?`<div class="inline-notice warning"><strong>Endpoint cannot apply yet</strong><ul>${target.blockers.map(reason=>`<li>${h(reason)}</li>`).join('')}</ul></div>`:''}`;
}

function defaultDenyScope(){
 const scope=managedRolloutScope();
 return {key:scope.key,server_ids:scope.ids,search:''};
}
async function loadDefaultDeny({force=false,offset}={}){
 const scope=defaultDenyScope();
 if(defaultDenyState.loading&&!force&&defaultDenyState.requestedScope===scope.key)return;
 const start=offset===undefined?(defaultDenyState.scope===scope.key?defaultDenyState.offset:0):offset;
 if(!Number.isSafeInteger(start)||start<0)return;
 const sequence=++defaultDenyState.sequence;
 Object.assign(defaultDenyState,{loading:true,error:'',requestedScope:scope.key});
 try{
  const result=await api('/host-default-deny/query',{method:'POST',body:{limit:20,offset:start,...(scope.server_ids===null?{}:{server_ids:scope.server_ids}),search:scope.search}});
  if(sequence!==defaultDenyState.sequence||scope.key!==defaultDenyScope().key)return;
  if(!Array.isArray(result.items)||result.items.length>20||result.limit!==20||result.offset!==start||!Number.isSafeInteger(result.total)||result.total<0)throw new Error('Ingress status returned an invalid page. Refresh to retry.');
  Object.assign(defaultDenyState,{page:result,scope:scope.key,offset:start});
 }catch(error){if(sequence===defaultDenyState.sequence)defaultDenyState.error=error.message;}
 finally{if(sequence===defaultDenyState.sequence){defaultDenyState.loading=false;defaultDenyInvalidateReview();defaultDenyRedraw();}}
}
function defaultDenyModalActive(title){return $('#modal')?.open&&$('#modal-title')?.textContent===title;}
function defaultDenyClose(){defaultDenyState.review=null;defaultDenyState.reviewSequence++;defaultDenyResetAcknowledgement();}
function defaultDenyTargets(plan){return plan?.preview?.targets;}
function defaultDenyReviewProblem(plan){
 if(!defaultDenyMayWrite())return state.data?.meta?.demo?'Demo mode cannot push whole-server default deny.':'An authorized Admin is required.';
 if(!plan||plan.summary_only===true||plan.sources_omitted===true||plan.preview?.summary_only===true)return 'Open a fresh exact ingress preview.';
 if(!['enable','disable'].includes(plan.action)||!plan.id||!Number.isSafeInteger(plan.revision)||plan.revision<1||!/^[a-f0-9]{64}$/.test(plan.digest||'')||typeof plan.confirmation_nonce!=='string'||!plan.confirmation_nonce)return 'The review is missing exact revision, digest or nonce bindings.';
 if(!Number.isFinite(Date.parse(plan.expires_at))||Date.parse(plan.expires_at)<=Date.now())return 'The review expired or has no valid expiry. Preview again.';
 if(plan.can_apply!==true||(plan.blockers||[]).length||['queued','confirmed','applied','disabled','cancelled','invalidated','expired','revoked'].includes(plan.status))return 'This review cannot be pushed. Resolve its blockers and create a fresh preview.';
 const targets=defaultDenyTargets(plan);
 if(!Array.isArray(targets)||!targets.length||targets.length>5000||!Array.isArray(plan.server_ids)||plan.server_ids.length!==targets.length||new Set(plan.server_ids).size!==targets.length)return 'The exact frozen endpoint scope is incomplete.';
 const ids=new Set(),allowedIds=new Set(plan.server_ids),currentServers=new Map((state.data?.servers||[]).map(server=>[server.id,server]));
 for(const target of targets){
  if(!target||typeof target.server_id!=='string'||ids.has(target.server_id)||!allowedIds.has(target.server_id)||target.summary_only===true||target.sources_omitted===true||!Number.isSafeInteger(target.version)||target.version<0||!Number.isSafeInteger(target.base_version)||target.base_version<0||!/^[a-f0-9]{64}$/.test(target.digest||'')||!target.protection||!/^[a-f0-9]{64}$/.test(target.protection?.digest||target.protection_digest||'')||typeof target.protection!=='object'||Array.isArray(target.protection)||(target.blockers||[]).length||!Array.isArray(target.services))return 'An endpoint has incomplete bindings, protection, blockers or allowed services.';
  ids.add(target.server_id);
  const current=currentServers.get(target.server_id);
  if(Number.isSafeInteger(current?.desired_version)&&current.desired_version!==target.base_version)return 'The endpoint base policy version changed. Create a fresh preview and acknowledge it again.';
  if(current?.protection?.digest&&current.protection.digest!==(target.protection.digest||target.protection_digest))return 'The endpoint protection changed. Create a fresh preview and acknowledge it again.';
  const configurationDigest=current?.configuration_state?.digest||current?.configuration_state?.config_digest;
  if(configurationDigest&&target.configuration_digest&&configurationDigest!==target.configuration_digest)return 'The endpoint configuration changed. Create a fresh preview and acknowledge it again.';
  if(target.services.some(service=>!Number.isSafeInteger(service.port)||service.port<1||service.port>65535||!['tcp','udp'].includes(service.protocol)||!Array.isArray(service.sources)||service.sources.some(source=>typeof source!=='string'||!source)))return 'An endpoint is missing its exact allowed source/port matrix.';
 }
 return defaultDenyState.review===plan&&defaultDenyState.reviewStaleReason||'';
}
function defaultDenyContext(plan){
 const servers=new Map((state.data?.servers||[]).map(server=>[server.id,server]));
 const endpoints=(plan.server_ids||[]).map(id=>{const server=servers.get(id);const status=(defaultDenyState.page?.items||[]).find(row=>row.server_id===id),versions=[server?.desired_version,status?.desired_version].filter(Number.isSafeInteger);return [id,versions.length?Math.max(...versions):null,server?.protection?.digest??null,server?.configuration_state?.digest??server?.configuration_state?.config_digest??null];});
 const groups=(plan.group_ids||[]).map(id=>{const group=(state.data?.groups||[]).find(item=>item.id===id);return [id,group?.revision??null,group&&typeof F?.groupMembers==='function'?F.groupMembers(group,state.data.servers).map(server=>server.id).sort():group?.server_ids??null];});
 return JSON.stringify({endpoints,groups});
}
function defaultDenyResetAcknowledgement(reason=''){
 const input=$('#default-deny-ack'),form=$('#default-deny-review-form');
 if(input){input.checked=false;input.disabled=!!reason;}
 if(form){const button=$('button[type="submit"]',form);if(button)button.disabled=true;}
 const warning=$('#default-deny-review-warning');if(warning){warning.textContent=reason;warning.hidden=!reason;}
}
function defaultDenyInvalidateReview(){
 const plan=defaultDenyState.review;if(!plan)return;
 if(defaultDenyContext(plan)!==defaultDenyState.reviewContext)defaultDenyState.reviewStaleReason='Endpoint policy, configuration, protection or group membership changed. Create a fresh preview and acknowledge it again.';
 const reason=defaultDenyReviewProblem(plan);if(reason)defaultDenyResetAcknowledgement(reason);
}
function defaultDenyShowReview(plan,index=0){
 const previous=defaultDenyState.review,sameReview=previous?.id===plan.id&&previous?.digest===plan.digest&&previous?.revision===plan.revision,context=defaultDenyState.reviewContext,staleReason=defaultDenyState.reviewStaleReason;
 defaultDenyState.review=plan;defaultDenyState.targetIndex=index;defaultDenyState.reviewStaleReason=sameReview?staleReason||'':'';defaultDenyState.reviewContext=sameReview?context:defaultDenyContext(plan);
 if(sameReview&&context!==defaultDenyContext(plan))defaultDenyState.reviewStaleReason='Endpoint policy, configuration, protection or group membership changed. Create a fresh preview and acknowledge it again.';
 const targets=defaultDenyTargets(plan)||[],target=targets[index],problem=defaultDenyReviewProblem(plan);
 showModal('Review whole-server default deny',`<form id="default-deny-review-form" data-id="${h(plan.id)}" data-digest="${h(plan.digest)}" data-revision="${num(plan.revision)}"><div class="modal-body">${errorSlot}<div class="inline-notice warning"><strong>${plan.action==='disable'?'Disable the owned whole-server fallback':'Enable / refresh whole-server default deny'}</strong><p>${h(defaultDenyAcknowledgement)}</p></div><dl class="detail-grid"><div><dt>Frozen scope</dt><dd>${targets.length} endpoints · ${(plan.group_ids||[]).length} selected groups</dd></div><div><dt>Exact review revision</dt><dd>${num(plan.revision)}</dd></div><div><dt>Review expires</dt><dd>${h(timestamp(plan.expires_at))}</dd></div><div><dt>Review digest</dt><dd class="mono">${h(plan.digest)}</dd></div></dl><p class="help-text">${plan.action==='disable'?'Disabling removes only the owned global fallback and uses the last applied allowed matrix. It does not silently publish other pending edits.':'Only enforcing source/port grants are allowed. Monitor-only rows do not permit inbound access. New policy/tag/source changes require a fresh acknowledged deny-bearing bundle.'} Stop active automatic learning and remove existing learning-owned grants with an authenticated cleanup receipt before enabling. Imported and learned live changes are held while whole-server default deny is enabled; observe-only collection remains available.</p>${(plan.blockers||[]).length?`<ul class="form-error">${plan.blockers.map(reason=>`<li>${h(typeof reason==='string'?reason:JSON.stringify(reason))}</li>`).join('')}</ul>`:''}<div class="field"><label for="default-deny-target">Inspect each frozen endpoint</label><select id="default-deny-target">${targets.map((item,position)=>`<option value="${position}" ${position===index?'selected':''}>${h(item.hostname||item.server_id)} · ${h(item.server_id)}</option>`).join('')}</select></div>${defaultDenyMatrixHTML(target)}<p class="inline-notice warning"><strong>Fallback action: REJECT, not silent DROP.</strong> Applies to new inbound connections; established sessions are preserved. Existing unauthorized long-lived sessions are not terminated; conntrack is not flushed.</p><p class="help-text">Protection includes the frozen SSH/controller and network-control profile. Review any DHCP/ICMP exceptions shown above. This is inbound-only; application policy saves remain separate, and queued intent is not verified kernel application.</p><p id="default-deny-review-warning" class="form-error" role="alert" ${problem?'':'hidden'}>${h(problem)}</p><label class="host-check"><input id="default-deny-ack" name="acknowledge_downtime" type="checkbox" ${problem?'disabled':''}>${h(defaultDenyAcknowledgement)}</label><p class="help-text">The checkbox starts unchecked for every preview and push attempt. No second administrator is required.</p></div><div class="modal-footer"><button type="button" class="button secondary" data-action="close-modal">Cancel</button><button type="button" class="button secondary" data-action="default-deny-reload" data-id="${h(plan.id)}">Reload exact review</button><button type="submit" class="button danger" disabled>Push reviewed ingress change</button></div></form>`,'EXACT ENDPOINTS · MANUAL DOWNTIME ACKNOWLEDGEMENT');
 defaultDenyResetAcknowledgement(problem);
}
function defaultDenyChange(event){
 if(event.target.id==='default-deny-target'){const index=Number(event.target.value),plan=defaultDenyState.review;if(plan&&Number.isSafeInteger(index)&&index>=0&&index<defaultDenyTargets(plan).length){defaultDenyInvalidateReview();if(!defaultDenyState.reviewStaleReason)defaultDenyShowReview(plan,index);}return true;}
 if(event.target.id!=='default-deny-ack')return false;
 defaultDenyInvalidateReview();const form=$('#default-deny-review-form'),button=form&&$('button[type="submit"]',form);
 if(button)button.disabled=event.target.checked!==true||!!defaultDenyReviewProblem(defaultDenyState.review)||defaultDenyState.submitting;
 return true;
}
async function defaultDenyAction(button){
 const {action,id}=button.dataset;
 if(action==='default-deny-server')return openServer(id);
 if(action==='default-deny-refresh')return loadDefaultDeny({force:true});
 if(action==='default-deny-page')return loadDefaultDeny({force:true,offset:Number(button.dataset.offset)});
 if(!canWrite())return;
 if(action==='default-deny-new'||action==='default-deny-host-review')return defaultDenyShowSelection(action==='default-deny-host-review'?id:'');
 if(action==='default-deny-reload'){
  const serial=++defaultDenyState.reviewSequence;defaultDenyResetAcknowledgement('Reloading the exact review; acknowledge it again when ready.');
  try{const plan=await api('/host-default-deny/'+encodeURIComponent(id));if(serial===defaultDenyState.reviewSequence&&defaultDenyModalActive('Review whole-server default deny'))defaultDenyShowReview(plan);}
  catch(error){if(serial===defaultDenyState.reviewSequence){defaultDenyState.reviewStaleReason=error.message;defaultDenyResetAcknowledgement(error.message);}}
 }
}
async function defaultDenySubmit(event){
 event.preventDefault();if(!canWrite())return;const form=event.target,values=new FormData(form),button=$('button[type="submit"]',form);if(button)button.disabled=true;
 try{
  if(form.id==='default-deny-selection-form'){
   const action=String(values.get('operation')||''),server_ids=[...new Set(values.getAll('server_ids').map(String))],group_ids=[...new Set(values.getAll('group_ids').map(String))];
   if(!['enable','disable'].includes(action)||!server_ids.length&&!group_ids.length||server_ids.length>5000||group_ids.length>5000)throw new Error('Choose an operation and at least one explicit endpoint or group.');
   const sequence=++defaultDenyState.reviewSequence;defaultDenyState.review=null;
   const plan=await api('/host-default-deny/preview',{method:'POST',body:{action,server_ids,group_ids}});
   if(sequence===defaultDenyState.reviewSequence&&defaultDenyModalActive('Whole-server default deny'))defaultDenyShowReview(plan);
  }else{
   defaultDenyInvalidateReview();const plan=defaultDenyState.review,problem=defaultDenyReviewProblem(plan),ack=$('#default-deny-ack');
   if(problem)throw new Error(problem);
   if(defaultDenyState.submitting||plan.id!==form.dataset.id||plan.digest!==form.dataset.digest||String(plan.revision)!==form.dataset.revision||ack?.checked!==true||values.get('acknowledge_downtime')!=='on')throw new Error('Use the current exact review and manually check its downtime acknowledgement before each push.');
   const body={digest:plan.digest,expected_revision:plan.revision,confirmation_nonce:plan.confirmation_nonce,acknowledge_downtime:true};
   defaultDenyState.submitting=true;defaultDenyState.review=null;defaultDenyState.reviewSequence++;defaultDenyResetAcknowledgement('Push requested. Verify endpoint receipts; this review cannot be reused.');
   const result=await api('/host-default-deny/'+encodeURIComponent(plan.id)+'/confirm',{method:'POST',body});
   if(defaultDenyModalActive('Review whole-server default deny'))closeModal();if(typeof policyDeploymentsPublished==='function')policyDeploymentsPublished(result);toast('Ingress push queued. Verify each endpoint outcome; queued does not mean applied.');await loadDefaultDeny({force:true});
  }
 }catch(error){if(defaultDenyModalActive(form.id==='default-deny-review-form'?'Review whole-server default deny':'Whole-server default deny'))formError(error);else toast(error.message,true);if(form.id==='default-deny-review-form')defaultDenyResetAcknowledgement(defaultDenyState.review?error.message:'Push outcome is unverified. Refresh status and create a fresh review before retrying.');}
 finally{defaultDenyState.submitting=false;if(button&&form.id==='default-deny-selection-form'&&defaultDenyModalActive('Whole-server default deny'))button.disabled=false;}
}
