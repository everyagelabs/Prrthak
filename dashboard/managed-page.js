'use strict';

function managedCanConfirm(plan) {
  return !!plan&&plan.summary_only!==true&&M.canConfirm(plan,state.role)&&globalThis.PrthakApprovals.canAct(plan,{role:state.role,authType:state.authType,userId:state.user?.id,tenantId:state.user?.tenant_id});
}
function managedApprovalHTML(plan) {
  const actor=plan.approval?.requester?.display_name || plan.approval?.requester?.actor || plan.created_by || 'Not recorded';
  return `<div class="inline-notice"><strong>Admin change.</strong> ${h(actor)}. ${h(globalThis.PrthakApprovals.explain(plan))}</div>`;
}
function managedLabHTML() {
  return `<div class="managed-lab-notice">${icon('info')}<span><strong>Policy delivery and endpoint status.</strong> Admin saves publish affected intent automatically. Endpoints apply it only with their local opt-in, current protection checks and rollback support. Imported deny/restrictive changes, restrictive learned removal and destructive recovery retain their explicit same-actor confirmation steps. Whole-server default deny is a separate opt-in; every new deny-bearing bundle needs its own downtime acknowledgement. Agent outcomes show actual application.</span></div>`;
}
function managedBadge(status) { return badge(M.label(status),M.tone(status)); }
function policyWorkspaceHTML() {
  const tab=['policies','rollouts','default-deny'].includes(state.policyTab)?state.policyTab:'policies',tabs=[['policies','access-policy-tab','Access policies'],['rollouts','managed-rollout-tab','Changes & history'],['default-deny','default-deny-tab','Whole-server default deny']];
  return `<div class="policy-workspace-tabs" role="tablist" aria-label="Policy workspace">${tabs.map(([key,id,label])=>`<button role="tab" id="${id}" aria-selected="${tab===key}" tabindex="${tab===key?0:-1}" aria-controls="policy-workspace-panel" data-action="managed-workspace-tab" data-tab="${key}">${label}</button>`).join('')}<span>Admin save → delivery → agent verification</span></div><div id="policy-workspace-panel" role="tabpanel" aria-labelledby="${tabs.find(([key])=>key===tab)[1]}">${managedLabHTML()}${tab==='default-deny'?defaultDenyHTML():tab==='rollouts'?managedRolloutsHTML():policyCardsHTML()}</div>`;
}
function managedVisibleRollouts() {
  if(state.managedPagination?.remote)return state.managedScope===managedRolloutScope().key?(state.managedRollouts || []):[];
  const ids=new Set(filteredServers().map(server=>server.id));
  return (state.managedRollouts || []).filter(plan=>(plan.server_ids || []).some(id=>ids.has(id)));
}
function managedRolloutScope() {
  const scoped=F.count(state.filters || F.empty())>0 || !!state.search || !!state.flowServer&&state.flowServer!=='all';
  const ids=scoped?[...new Set(filteredServers().map(server=>server.id))].sort():null;
  return {ids,key:JSON.stringify({ids,filters:state.filters,search:state.search || '',server:state.flowServer || 'all'})};
}
function managedRedraw() {
  if(typeof policyCatalogueRedraw==='function')return policyCatalogueRedraw();
  const drafts=['#service-filter-input','#custom-tag-filter-input'].map(selector=>[selector,$(selector)?.value || '']),active=document.activeElement,id=active?.id,start=active?.selectionStart,end=active?.selectionEnd;
  if(typeof renderPreservingFilterFocus==='function')renderPreservingFilterFocus();else render();
  for(const [selector,value] of drafts){const input=$(selector);if(input)input.value=value;}
  const input=id?document.getElementById?.(id):null;input?.focus();if(Number.isInteger(start)&&input?.setSelectionRange)input.setSelectionRange(start,end ?? start);
}
function managedPaginationHTML(meta,action,id='',extra='') {
  if(!meta)return '';
  const count=meta.items?.length || 0,offset=meta.offset || 0,limit=meta.limit || 20;
  return `<div class="recommendation-pagination"><span>${count?offset+1:0}–${offset+count} of ${format(meta.total)} matching records</span><div><button class="button secondary small" data-action="${action}" data-id="${h(id)}" data-offset="${Math.max(0,offset-limit)}" ${extra} ${!offset?'disabled':''}>Previous</button><button class="button secondary small" data-action="${action}" data-id="${h(id)}" data-offset="${offset+limit}" ${extra} ${!meta.has_more?'disabled':''}>Next</button></div></div>`;
}
function managedNavigationPage(value,offset,limit=20) {
  if(!value || !Array.isArray(value.items) || value.items.length>limit || value.limit!==limit || value.offset!==offset || !Number.isSafeInteger(value.total) || value.total<0)throw new Error('The controller did not return a bounded managed history page.');
  return value;
}
function managedRememberHistory(cache,id,value) {
  delete cache[id];cache[id]=value;while(Object.keys(cache).length>8)delete cache[Object.keys(cache)[0]];
}
async function refreshManagedRollouts({force=false,offset}={}) {
  if(state.policyTab==='default-deny')return loadDefaultDeny({force,offset});
  const scope=managedRolloutScope();
  if (state.managedLoading && !force && state.managedRequestedScope===scope.key) return;
  const selectedOffset=offset===undefined?(state.managedScope===scope.key?state.managedPagination?.offset || 0:0):offset;
  if(!Number.isSafeInteger(selectedOffset)||selectedOffset<0)return;
  const sequence=(state.managedRequestSequence || 0)+1;state.managedRequestSequence=sequence;state.managedRequestedScope=scope.key;
  state.managedLoading=true;state.managedError='';
  try {
    const requests=[api('/policy-rollouts/query',{method:'POST',body:{limit:20,offset:selectedOffset,server_ids:scope.ids}})];
    if(typeof loadLearningApprovals==='function')requests.push(loadLearningApprovals(false));
    const results=await Promise.allSettled(requests);
    if(results[0].status==='rejected')throw results[0].reason;
    if(results[1]?.status==='rejected')state.learningApprovalError=results[1].reason.message;
    if(sequence!==state.managedRequestSequence || managedRolloutScope().key!==scope.key)return;
    const result=results[0].value;
    if(!Array.isArray(result.items)||result.items.length>20||!Number.isSafeInteger(result.total)||result.total<0||result.limit!==20||result.offset!==selectedOffset)throw new Error('The controller did not return a bounded rollout page.');
    state.managedRollouts=result.items;state.managedPagination={...result,remote:true};state.managedScope=scope.key;state.managedError='';
  } catch(error) { if(sequence===state.managedRequestSequence && managedRolloutScope().key===scope.key)state.managedError=error.message; }
  finally {
    if(sequence===state.managedRequestSequence){state.managedLoading=false;if(state.view==='policies' && !$('#modal').open)managedRedraw();}
  }
}
function managedRolloutsHTML() {
  const scope=managedRolloutScope();
  if((state.managedPagination?.remote || state.managedRollouts===undefined)&&state.managedRequestedScope!==scope.key&&!state.managedScheduled){state.managedScheduled=true;Promise.resolve().then(()=>{state.managedScheduled=false;refreshManagedRollouts();});}
  const plans=managedVisibleRollouts();
  return `${filterBarHTML('rollouts')}<div class="managed-section-actions"><div><h2>Policy changes and delivery</h2><p>Each review freezes complete endpoint bundles, including services outside a port filter.</p></div><div><button class="button secondary small" data-action="managed-refresh-rollouts">${icon('refresh')}Refresh</button><button class="button primary small" data-action="managed-new-rollout" ${!['admin','super_admin'].includes(state.role)?'disabled':''}>${icon('plus')}Apply current bundles</button></div></div>${state.managedError?`<div class="managed-error" role="alert">Managed rollout data unavailable: ${h(state.managedError)}. Access policies remain readable. <button class="text-button" data-action="managed-refresh-rollouts">Retry</button></div>`:''}${state.managedRollouts===undefined&&!state.managedError?'<div class="loading-state"><div class="spinner"></div><p>Loading managed rollout history.</p></div>':`<section class="card"><div class="table-scroll"><table class="managed-table"><thead><tr><th>Rollout</th><th>Scope</th><th>Review / delivery state</th><th>Agent outcomes</th><th>Created</th><th></th></tr></thead><tbody>${plans.map(plan=>{const counts=M.resultCounts(plan);return `<tr><td><strong>${h(plan.name || 'Managed rollout')}</strong><small>${h(plan.id)}</small></td><td>${format(plan.target_count ?? plan.server_ids?.length)} endpoint${(plan.target_count ?? plan.server_ids?.length)===1?'':'s'}<small>Complete immutable bundles</small></td><td>${managedBadge(plan.status)}<small>${num(plan.confirmation_count)} / ${plan.requires_double_confirmation?2:1} confirmations</small></td><td>${Object.entries(counts).map(([status,count])=>`${format(count)} ${h(M.label(status))}`).join('<br>') || '<span class="host-os">No agent outcome yet</span>'}</td><td>${h(timestamp(plan.created_at))}<small>${h(plan.created_by || 'Actor not supplied')}</small></td><td><button class="text-button" data-action="managed-open-rollout" data-id="${h(plan.id)}">Review & status</button></td></tr>`;}).join('') || `<tr><td colspan="6"><div class="managed-empty">${state.managedLoading?'Loading matching managed rollouts…':'No managed rollouts match this scope. Admin saves publish eligible changes automatically.'}</div></td></tr>`}</tbody></table></div>${managedPaginationHTML(state.managedScope===scope.key?state.managedPagination:null,'managed-rollouts-page')}</section>`}${!['admin','super_admin'].includes(state.role)?'<p class="help-text">Only an administrator can authorize live managed policy changes.</p>':''}<p class="help-text">Admin actions are audited. Delivery, local endpoint verification and actual application are separate states.</p>`;
}
async function managedPolicyHistory(id,offset=0) {
  if(!Number.isSafeInteger(offset)||offset<0)return;
  const sequence=(state.managedHistorySequence || 0)+1;state.managedHistorySequence=sequence;state.activeManagedRestore=null;
  showModal('Policy version history','<div class="modal-body"><div class="loading-state"><div class="spinner"></div><p>Loading immutable revisions.</p></div></div>','IMMUTABLE POLICY HISTORY');
  state.activePolicyHistory=id;
  try {
    const result=managedNavigationPage(await api(`/policies/${encodeURIComponent(id)}/revisions?limit=20&offset=${offset}`),offset);
    if(state.activePolicyHistory!==id || state.managedHistorySequence!==sequence)return;
    state.policyHistories ||= {};managedRememberHistory(state.policyHistories,id,M.orderedHistory(result.items));
    state.policyHistoryPages ||= {};managedRememberHistory(state.policyHistoryPages,id,result);
    if(state.activePolicyHistory===id)managedRenderPolicyHistory(id);
  } catch(error) {
    if(state.activePolicyHistory!==id || state.managedHistorySequence!==sequence)return;
    showModal('Policy version history',`<div class="modal-body"><div class="managed-error" role="alert">${h(error.message)}</div><button class="button secondary" data-action="managed-policy-history" data-id="${h(id)}">Retry history</button></div>`,'IMMUTABLE POLICY HISTORY');
  }
}
function managedRevisionOptions(items,selected) {
  return items.map(item=>`<option value="${M.revision(item)}" ${M.revision(item)===selected?'selected':''}>Revision ${M.revision(item)} · ${h(timestamp(item.recorded_at || item.updated_at || item.created_at))}</option>`).join('');
}
function managedRenderPolicyHistory(id) {
  const items=state.policyHistories?.[id] || [],current=state.data.policies.find(policy=>policy.id===id),newest=M.revision(items[0]),previous=M.revision(items[1] || items[0]);
  showModal(current?.name || M.policy(items[0]).name || 'Policy version history',`<div class="modal-body">${errorSlot}<div class="inline-notice">Revisions are immutable. Restoring an earlier configuration creates a new revision and publishes updated intent to eligible endpoints.</div>${items.length>1?`<div class="managed-history-selects"><div class="field"><label for="policy-compare-from">Compare from</label><select id="policy-compare-from">${managedRevisionOptions(items,previous)}</select></div><div class="field"><label for="policy-compare-to">Compare to</label><select id="policy-compare-to">${managedRevisionOptions(items,newest)}</select></div><button class="button secondary" data-action="managed-compare-policy" data-id="${h(id)}">Compare revisions</button></div>`:''}<div id="policy-revision-comparison"></div>${items.map(item=>{const rev=M.revision(item);return `<article class="managed-history-row"><div><strong>Revision ${rev}${rev===num(current?.revision)?' · current intent':''}</strong><small>${h(timestamp(item.recorded_at || item.updated_at || item.created_at))} · ${h(item.actor || item.created_by || 'Actor not supplied')}</small><small>${h(item.reason || item.change_reason || 'Policy configuration recorded')}${item.restored_from_revision?` · Restored from revision ${num(item.restored_from_revision)}`:''}</small>${item.digest?`<code class="managed-digest">${h(item.digest)}</code>`:''}</div><div class="managed-history-actions"><button class="text-button" data-action="managed-view-revision" data-id="${h(id)}" data-revision="${rev}">View</button><button class="text-button" data-action="managed-restore-review" data-id="${h(id)}" data-revision="${rev}" ${!['admin','super_admin'].includes(state.role)?'disabled':''}>Review restore</button></div></article>`;}).join('') || '<div class="managed-empty">No immutable revisions have been recorded for this policy.</div>'}${managedPaginationHTML(state.policyHistoryPages?.[id],'managed-history-page',id)}</div><div class="modal-footer"><button class="button secondary" data-action="close-modal">Close</button><button class="button secondary" data-action="managed-policy-history" data-id="${h(id)}">${icon('refresh')}Refresh history</button></div>`,'IMMUTABLE POLICY HISTORY');
}
function managedPolicyDiffHTML(before,after,from,to) {
  const changes=M.compare(before,after);
  return `<div class="managed-change-fields">${changes.map(change=>`<span>${h(humanize(change.field))}</span>`).join('') || '<span>No configuration differences</span>'}</div><div class="managed-diff"><section><h3>${h(from)}</h3><pre>${h(JSON.stringify(M.policyConfiguration(before),null,2))}</pre></section><section><h3>${h(to)}</h3><pre>${h(JSON.stringify(M.policyConfiguration(after),null,2))}</pre></section></div>`;
}
async function managedComparePolicy(id) {
  const from=num($('#policy-compare-from').value),to=num($('#policy-compare-to').value);
  try {
    const result=await api(`/policies/${encodeURIComponent(id)}/diff?from=${from}&to=${to}`);
    M.exactPolicy(result.before,id,from);M.exactPolicy(result.after,id,to);
    if(state.activePolicyHistory!==id)return;
    $('#policy-revision-comparison').innerHTML=managedPolicyDiffHTML(result.before,result.after,`Revision ${from}`,`Revision ${to}`);
  }catch(error){formError(error);}
}
async function managedRestoreReview(id,revision) {
  if(!['admin','super_admin'].includes(state.role))return;
  state.activeManagedRestore=null;const sequence=(state.managedRestoreSequence || 0)+1;state.managedRestoreSequence=sequence;
  try {
    const [record,result]=await Promise.all([api(`/policies/${encodeURIComponent(id)}/revisions/${revision}`),api(`/policies/${encodeURIComponent(id)}/revisions?limit=1&offset=0`)]);
    M.exactPolicy(record,id,revision);managedNavigationPage(result,0,1);const latest=M.revision(result.items?.[0]);if(!latest)throw new Error('The latest immutable revision is unavailable.');
    const before=latest===revision?record:await api(`/policies/${encodeURIComponent(id)}/revisions/${latest}`);M.exactPolicy(before,id,latest);
    if(state.managedRestoreSequence!==sequence)return;
    state.activeManagedRestore={id,revision,record,before};
    showModal('Review policy restore',`<form id="managed-restore-form" data-id="${h(id)}" data-revision="${revision}"><div class="modal-body">${errorSlot}<div class="inline-notice warning">Restore revision ${revision} as a <strong>new revision</strong>. Existing history stays intact. The saved revision is published to eligible endpoints; actual endpoint results remain separate.</div>${M.policy(record).mode==='monitor'?'<div class="managed-next-step">This revision requests monitoring. For an endpoint with previously enforced Prṛthak rules, removal requires an explicit, twice-confirmed “Remove Prṛthak-managed rules” rollout. Existing legacy firewall policy resumes; this does not empty or globally open the endpoint firewall.</div>':''}${managedPolicyDiffHTML(before,record,`Latest recorded revision ${M.revision(before)}`,`Restore configuration from revision ${revision}`)}<div class="field"><label for="managed-restore-reason">Reason for restore</label><textarea id="managed-restore-reason" name="reason" rows="3" minlength="3" maxlength="1000" required placeholder="Explain the change and reference any incident or review."></textarea></div><p class="help-text">After restore, review each new endpoint bundle and its management protection in a separate managed rollout.</p></div>${modalFooter('Create restored revision')}</form>`,'RESTORE AS NEW REVISION');
  }catch(error){formError(error);toast(error.message,true);}
}
function managedNewRollout() {
  if(!['admin','super_admin'].includes(state.role))return;
  const servers=filteredServers();
  showModal('Apply managed policies',`<form id="managed-rollout-form"><div class="modal-body">${errorSlot}<div class="inline-notice">Submitting applies each selected server’s complete current policy bundle and can change its live firewall rules. One current Admin performs this action; the agent checks SSH/controller protection and rollback readiness. No endpoint is selected automatically. Use the dedicated downtime acknowledgement for whole-server default deny.</div><div class="field"><label for="managed-rollout-name">Rollout name</label><input id="managed-rollout-name" name="name" required maxlength="120" placeholder="Lab · billing access revision"></div><div class="field"><div class="field-label">Current filtered scope · ${format(servers.length)} endpoint${servers.length===1?'':'s'}</div><div class="host-checklist">${servers.map(server=>{const protection=M.protection(server);return `<label class="host-check"><input type="checkbox" name="server_ids" value="${h(server.id)}">${h(server.hostname)}<span>Desired v${num(server.desired_version)} · ${protection.ready===true?'Protection reported ready':'Protection requires review'}</span></label>`;}).join('') || '<p class="help-text" style="padding:13px">No endpoints match the current scope. Broaden the filters.</p>'}</div><small>Port filters select endpoints; authorization covers every service in their compiled bundle. Ordinary tag and address changes resolve through the saved policy intent and safety checks. Whole-server default-deny changes require a fresh acknowledged push.</small></div>${managedLabHTML()}</div>${modalFooter('Apply selected policies')}</form>`,'ADMIN ACTION · LIVE FIREWALL CHANGE');
}
function managedStageHTML(status) {
  const stages=[['pending_approval','Review'],['staging','Runtime staging'],['runtime_healthchecking','Health check'],['committing','Permanent commit'],['enforced','Agent verified']];
  const current=stages.findIndex(([key])=>key===status);
  return `<div class="managed-stage-strip" aria-label="Managed enforcement stages">${stages.map(([key,label],index)=>`<span class="${index===current?'active':current>index?'done':''}">${label}</span>`).join('')}</div>`;
}
function managedProtectionHTML(protection={}) {
  const ready=protection.ready===true;
  return `<div class="managed-review-heading"><strong>SSH & controller protection</strong>${badge(ready?'Reported ready':'Configuration incomplete',ready?'':'warning')}</div><dl class="managed-protection-list"><div><dt>Approved management sources</dt><dd>${h(protection.management_sources?.join(', ') || 'Not reported')}</dd></div><div><dt>Protected SSH ports</dt><dd>${h(protection.ssh_ports?.map(port=>`${port}/tcp`).join(', ') || 'Not reported')}</dd></div><div><dt>Controller origin / same-mTLS witness</dt><dd>${h(protection.controller_origin || protection.controller_url || 'Not reported')}</dd></div><div><dt>Managed zone</dt><dd>${h(protection.zone || protection.capabilities?.zone || 'Not reported')}</dd></div></dl>${protection.blockers?.length?`<div class="managed-next-step"><strong>Reported blockers</strong><ul>${protection.blockers.map(reason=>`<li>${h(reason)}</li>`).join('')}</ul></div>`:''}${!ready?'<div class="managed-next-step">Configure approved management-source CIDRs, actual SSH ports and the management vantage on the agent/controller. Wait for a fresh ready protection report, then create a new rollout review. The agent blocks enforcement without fresh SSH-path evidence.</div>':''}${protection.capabilities?`<details class="managed-full-configuration"><summary>Reported protection capabilities</summary><pre class="detail-json">${h(JSON.stringify(protection.capabilities,null,2))}</pre></details>`:''}<code class="managed-digest">Protection digest: ${h(protection.digest || 'Not reported')}</code>`;
}
function managedBoundAccessHTML(bundle) {
  if(!bundle)return '<small>Inspect the immutable bundle to review its complete service and source configuration.</small>';
  const services=bundle.services || [];
  return `<div class="managed-bound-services">${services.slice(0,12).map(service=>`<div><strong>${num(service.port)}/${h(service.protocol)}</strong><span>${h(service.mode || bundle.mode || 'Mode not reported')}</span><small>Allowed sources: ${service.sources?.length?h(service.sources.slice(0,8).join(', ')):'None'}${service.sources?.length>8?` · +${format(service.sources.length-8)} more in frozen bundle`:''}</small></div>`).join('') || '<small>No desired managed services in this bundle.</small>'}${services.length>12?`<small>+${format(services.length-12)} additional services. Inspect the complete frozen bundle.</small>`:''}</div>`;
}
function managedShowRollout(plan) {
  M.exactRollout(plan,plan?.id);
  state.activeManagedRollout=plan;
  const targets=M.bindings(plan),isSecond=M.secondConfirmation(plan),eligible=managedCanConfirm(plan),modifiable=['draft','awaiting_second_confirmation','queued'].includes(plan.status),blockers=M.blockers(plan);
  showModal(plan.name || 'Managed rollout review',`<div class="modal-body">${errorSlot}<div class="managed-review-heading"><strong>Exact-bundle authorization</strong>${managedBadge(plan.status)}</div>${managedApprovalHTML(plan)}<div class="inline-notice warning">Confirming this review authorizes only the listed bundle versions, bundle digests and management-protection digests. Any later change needs a new review. An approval or download is not proof of enforcement.</div><dl class="managed-summary"><div><dt>Frozen endpoint scope</dt><dd>${format(plan.server_ids?.length)} endpoint${plan.server_ids?.length===1?'':'s'}</dd></div><div><dt>Confirmation steps</dt><dd>${num(plan.confirmation_count)} / ${plan.requires_double_confirmation?2:1}</dd></div><div><dt>Authorization expiry</dt><dd>${h(timestamp(plan.expires_at))}</dd></div></dl>${!M.hasBindings(plan)?'<div class="managed-error">The review has incomplete endpoint version, bundle or protection bindings. Authorization is disabled until the agent reports the required configuration. Refresh or create a new review.</div>':''}${blockers.length?`<div class="managed-next-step"><strong>Configuration must be completed</strong><ul>${blockers.map(reason=>`<li>${h(reason)}</li>`).join('')}</ul></div>`:''}${M.isExpired(plan)?'<div class="managed-error">This authorization has expired. Completed outcomes remain recorded below; create a fresh review for further delivery.</div>':''}<div class="managed-target-list">${targets.map(target=>{const report=plan.results?.[target.server_id],details=(plan.preview?.targets || []).find(value=>value.server_id===target.server_id)||{};return `<article class="managed-target"><div><strong>${h(target.hostname || serverName(target.server_id))} · v${target.version || 'Not reported'}</strong>${managedBadge(report?M.outcomeState({...report,intent:report.intent || target.intent}):plan.status==='queued'?'pending':['draft','awaiting_second_confirmation'].includes(plan.status)?'pending_approval':plan.status)}</div><code class="managed-digest">Bundle: ${h(target.digest || 'Not reported')}<br>Protection: ${h(target.protection_digest || 'Not reported')}</code><small>Intent: <strong>${target.intent==='remove_managed_rules'?'Remove Prṛthak-managed rules':'Apply managed source policy'}</strong></small>${target.intent==='remove_managed_rules'?'<small>Only Prṛthak-owned access rules are removed. Existing legacy firewall policy resumes; other local rules remain.</small>':''}${managedBoundAccessHTML(details.bundle || target.bundle)}<small>Protection: ${h(details.protection_status || target.protection_status || 'See endpoint evidence')}</small>${details.protection?`<details class="managed-full-configuration"><summary>Frozen management protection</summary>${managedProtectionHTML(details.protection)}</details>`:''}${report?`<div class="managed-result-message">${h(report.message || report.error || 'No outcome message supplied')}${report.rollback_reason?`<br><strong>Rollback:</strong> ${h(report.rollback_reason)}`:''}</div>${managedStageHTML(report.status)}`:''}<button class="text-button" data-action="managed-view-bound-bundle" data-id="${h(target.server_id)}" data-version="${target.version}">Inspect frozen bundle</button></article>`;}).join('')}</div>${isSecond?`<div class="firewall-challenge"><label class="field-label" for="managed-confirmation-challenge">Final confirmation · type the exact phrase</label><code>${h(plan.confirmation_phrase)}</code><input id="managed-confirmation-challenge" aria-label="Managed rollout confirmation phrase" autocomplete="off" spellcheck="false" placeholder="Type the phrase displayed above"><small class="help-text">Use the same Admin account for both explicit confirmations.</small></div>`:''}<p class="help-text">The endpoint stages runtime rules, checks protected management paths, commits permanent rules and reads back the result. Only the agent can report enforcement. Failure may produce a rolled-back result; inspect its reason. Authorization expiry or cancellation does not undo a completed deployment.</p><div class="managed-page-meta"><span>${h(plan.created_by || 'Actor not supplied')} · ${h(timestamp(plan.created_at))}</span><span>Plan digest: ${h(plan.plan_digest || 'Not reported')}</span></div></div><div class="modal-footer"><button class="button secondary" data-action="close-modal">Close</button><button class="button secondary" data-action="managed-refresh-rollout" data-id="${h(plan.id)}">Refresh status</button>${['admin','super_admin'].includes(state.role)&&modifiable?`<button class="button secondary" data-action="managed-cancel-rollout" data-id="${h(plan.id)}">Cancel authorization</button>`:''}${['draft','awaiting_second_confirmation'].includes(plan.status)?`<button class="button danger" data-action="managed-confirm-rollout" ${!eligible?'disabled':''}>${isSecond?'Final confirmation (2 of 2)':plan.requires_double_confirmation?'Confirm change (1 of 2)':'Apply exact bundles'}</button>`:''}</div>`,'REVIEWED MANAGED ENFORCEMENT');
  if(isSecond)$('#managed-confirmation-challenge')?.focus?.();
}
async function managedLoadRollout(id) { const sequence=(state.managedDetailSequence || 0)+1;state.managedDetailSequence=sequence;const response=await api(`/policy-rollouts/${encodeURIComponent(id)}`),plan=M.exactRollout(response.plan || response,id);if(state.managedDetailSequence===sequence)managedShowRollout(plan); }
async function managedBundleHistory(id,offset=0) {
  if(!Number.isSafeInteger(offset)||offset<0)return;
  const sequence=(state.managedBundleSequence || 0)+1;state.managedBundleSequence=sequence;
  state.managedBundleLoading=id;
  try {
    const [result,detail]=await Promise.all([api(`/servers/${encodeURIComponent(id)}/policy-history?limit=20&offset=${offset}`),api(`/servers/${encodeURIComponent(id)}`)]);
    if(state.managedBundleSequence!==sequence)return;
    managedNavigationPage(result,offset);
    state.bundleHistories ||= {};managedRememberHistory(state.bundleHistories,id,result.items);
    state.bundleHistoryPages ||= {};managedRememberHistory(state.bundleHistoryPages,id,result);
    state.bundleOutcomes ||= {};state.bundleOutcomes[id]=result.outcomes || [];
    state.bundleHistoryErrors ||= {};delete state.bundleHistoryErrors[id];
    if(state.detail===id && state.drawerTab==='managed')renderServerDrawer(detail.server || detail);
  }catch(error){state.bundleHistoryErrors ||= {};state.bundleHistoryErrors[id]=error.message;if(state.detail===id&&state.detailData)renderServerDrawer(state.detailData);}
  finally{if(state.managedBundleSequence===sequence)state.managedBundleLoading=null;}
}
function managedEndpointHTML(server) {
  const report=server.managed_enforcement || {},status=M.serverState(server),history=state.bundleHistories?.[server.id],error=state.bundleHistoryErrors?.[server.id],protection=M.protection(server),outcomes=[...(state.bundleOutcomes?.[server.id] || []),...(history || []).flatMap(item=>item.outcomes || [])];
  return `<div class="managed-review-heading"><strong>Managed policy status</strong>${managedBadge(status)}</div>${managedStageHTML(report.status)}<dl class="managed-summary"><div><dt>Desired bundle</dt><dd>v${num(server.desired_version)}</dd></div><div><dt>Agent-applied version</dt><dd>${num(server.applied_version)?'v'+num(server.applied_version):'Not applied'}</dd></div><div><dt>Last agent outcome</dt><dd>${h(M.label(M.outcomeState(report)))}</dd></div></dl>${report.version?`<p class="help-text">Last outcome refers to bundle v${num(report.version)}${num(report.version)!==num(server.desired_version)?'; the new desired bundle needs its own authorization':''}. Reported ${h(timestamp(report.updated_at))}.</p>`:''}${report.error||report.rollback_reason?`<div class="managed-error"><strong>${report.rollback_reason?'Rollback reason':'Agent error'}</strong><br>${h(report.rollback_reason || report.error)}</div>`:''}${report.approval_id?`<button class="text-button" data-action="managed-open-rollout" data-id="${h(report.approval_id)}">Inspect linked authorization</button>`:''}${status==='preview'?'<div class="managed-next-step">This endpoint remains in preview. Complete the protection configuration and lab validation before enabling its local enforcement opt-in and authorizing an exact bundle.</div>':''}${managedProtectionHTML(protection)}<div class="detail-heading">Immutable bundle history<button class="text-button" data-action="managed-refresh-bundles" data-id="${h(server.id)}">Refresh evidence</button></div>${error?`<div class="managed-error">${h(error)}</div>`:''}${history===undefined?'<p class="help-text">Loading compiled bundle history.</p>':history.length?history.map(record=>{const bundle=record.bundle || record;return `<article class="managed-history-row"><div><strong>Bundle v${num(bundle.version)}</strong><small>${h(timestamp(record.recorded_at || record.created_at || bundle.generated_at))} · ${h(record.reason || 'Compiled access intent')}</small><code class="managed-digest">${h(bundle.digest || 'Digest not reported')}</code><small>${record.outcomes?.length?record.outcomes.map(outcome=>h(M.label(M.outcomeState(outcome)))).join(' · '):'No linked agent outcome supplied'}${record.outcome_total?` · Latest of ${format(record.outcome_total)} report${record.outcome_total===1?'':'s'}`:''}</small></div><div class="managed-history-actions"><button class="text-button" data-action="managed-view-bound-bundle" data-id="${h(server.id)}" data-version="${num(bundle.version)}">Inspect</button>${record.outcome_total?`<button class="text-button" data-action="managed-view-outcomes" data-id="${h(server.id)}" data-version="${num(bundle.version)}">Outcome history</button>`:''}</div></article>`;}).join(''):'<div class="managed-empty">No compiled bundles have been recorded.</div>'}${managedPaginationHTML(state.bundleHistoryPages?.[server.id],'managed-bundles-page',server.id)}${outcomes.length?`<div class="detail-heading">Latest linked outcomes on this history page</div>${outcomes.slice(0,20).map(outcome=>`<div class="managed-history-row"><div><strong>v${num(outcome.version)} · ${h(M.label(M.outcomeState(outcome)))}</strong><small>${h(timestamp(outcome.updated_at || outcome.completed_at))}</small><p class="managed-result-message">${h(outcome.rollback_reason || outcome.error || outcome.message || '')}</p></div></div>`).join('')}`:''}<p class="help-text">Bundle versions describe immutable intent. Only a matching agent-applied version and successful enforcement report establish a completed rollout.</p>`;
}
async function managedInspectBundle(id,version) {
  const record=M.exactBundle(await api(`/servers/${encodeURIComponent(id)}/policy-history/${version}`),id,version),bundle=record.bundle || record;
  showModal(`${serverName(id)} · bundle v${version}`,`<div class="modal-body"><div class="inline-notice">Immutable compiled intent. Inspecting or downloading a bundle does not authorize it or mark it applied.</div><code class="managed-digest">Bundle digest: ${h(bundle.digest || 'Not reported')}</code>${record.reason?`<p class="help-text">${h(record.reason)}</p>`:''}<pre class="detail-json">${h(JSON.stringify(bundle,null,2))}</pre></div><div class="modal-footer"><button class="button secondary" data-action="close-modal">Close</button>${state.activeManagedRollout?`<button class="button secondary" data-action="managed-open-rollout" data-id="${h(state.activeManagedRollout.id)}">Back to rollout review</button>`:''}</div>`,'IMMUTABLE ENDPOINT BUNDLE');
}
async function managedOutcomeHistory(id,version,offset=0) {
  const result=managedNavigationPage(await api(`/servers/${encodeURIComponent(id)}/policy-history/${version}/outcomes?limit=20&offset=${offset}`),offset);
  if(result.server_id!==id || result.version!==version || result.items.some(value=>value.server_id!==id||value.version!==version))throw new Error('Exact agent outcome identity mismatch.');
  showModal(`${serverName(id)} · v${version} outcome history`,`<div class="modal-body"><div class="inline-notice">Agent-reported telemetry. These records do not authorize any policy or live firewall change.</div>${result.items.map(value=>`<article class="managed-history-row"><div><strong>${h(M.label(M.outcomeState(value)))}</strong><small>${h(timestamp(value.updated_at || value.created_at))}</small><pre class="detail-json">${h(JSON.stringify(value,null,2))}</pre></div></article>`).join('') || '<p class="help-text">No recorded agent outcome for this bundle.</p>'}${managedPaginationHTML(result,'managed-view-outcomes',id,`data-version="${version}"`)}</div><div class="modal-footer"><button class="button secondary" data-action="close-modal">Close</button></div>`,'BOUNDED AGENT TELEMETRY');
}
async function managedAction(button) {
  const action=button.dataset.action,id=button.dataset.id;
  if(action==='managed-workspace-tab'){if(!['policies','rollouts','default-deny'].includes(button.dataset.tab))return;state.policyTab=button.dataset.tab;try{sessionStorage.setItem('prithak-policy-tab',state.policyTab);}catch{}render();if(['rollouts','default-deny'].includes(state.policyTab))await refreshManagedRollouts();return;}
  if(action==='managed-new-rollout')return managedNewRollout();
  if(action==='managed-policy-history')return managedPolicyHistory(id);
  if(action==='managed-history-page')return managedPolicyHistory(id,num(button.dataset.offset));
  if(action==='managed-rollouts-page')return refreshManagedRollouts({force:true,offset:num(button.dataset.offset)});
  if(action==='managed-bundles-page')return managedBundleHistory(id,num(button.dataset.offset));
  if(action==='managed-compare-policy')return managedComparePolicy(id);
  if(action==='managed-restore-review')return managedRestoreReview(id,num(button.dataset.revision));
  if(action==='managed-view-revision'){
    try{const number=num(button.dataset.revision),record=M.exactPolicy(await api(`/policies/${encodeURIComponent(id)}/revisions/${number}`),id,number);showModal(`Policy revision ${number}`,`<div class="modal-body"><div class="inline-notice">Immutable configuration. No live change is made.</div><pre class="detail-json">${h(JSON.stringify(record,null,2))}</pre></div><div class="modal-footer"><button class="button secondary" data-action="managed-policy-history" data-id="${h(id)}">Back to history</button></div>`,'IMMUTABLE POLICY REVISION');}catch(error){formError(error);}return;
  }
  if(action==='managed-drawer-tab'){state.drawerTab='managed';renderServerDrawer(state.detailData);await managedBundleHistory(state.detail);return;}
  if(action==='managed-refresh-bundles')return managedBundleHistory(id);
  button.disabled=true;
  try {
    if(action==='managed-view-bound-bundle')return await managedInspectBundle(id,num(button.dataset.version));
    if(action==='managed-view-outcomes')return await managedOutcomeHistory(id,num(button.dataset.version),num(button.dataset.offset));
    if(action==='managed-refresh-rollouts')return await refreshManagedRollouts({force:true});
    if(action==='managed-open-rollout'||action==='managed-refresh-rollout')return await managedLoadRollout(id);
    if(action==='managed-cancel-rollout'){if(!['admin','super_admin'].includes(state.role))return;const plan=await api(`/policy-rollouts/${encodeURIComponent(id)}/cancel`,{method:'POST',body:{}});managedShowRollout(plan.plan || plan);await refreshManagedRollouts();return;}
    if(action==='managed-confirm-rollout'){
      const plan=state.activeManagedRollout;
      if(!managedCanConfirm(plan))throw new Error('This exact change cannot be applied. Check the Admin identity, bindings, blockers and expiry.');
      const typed=$('#managed-confirmation-challenge')?.value || '',response=await api(`/policy-rollouts/${encodeURIComponent(plan.id)}`),fresh=M.exactRollout(response.plan || response,plan.id);
      if(state.activeManagedRollout!==plan)throw new Error('The active review changed while refreshing. Review it again.');
      if(fresh.plan_digest!==plan.plan_digest||fresh.confirmation_nonce!==plan.confirmation_nonce||fresh.status!==plan.status||!managedCanConfirm(fresh)){managedShowRollout(fresh);throw new Error('The exact review changed. Review the current bindings and confirmation step again.');}
      const body=M.confirmationBody(fresh,typed);
      const result=await api(`/policy-rollouts/${encodeURIComponent(plan.id)}/confirm`,{method:'POST',body});managedShowRollout(result.plan || result);if(typeof policyDeploymentsPublished==='function')policyDeploymentsPublished(result);await refreshManagedRollouts();
    }
  }catch(error){if(error.payload?.plan)managedShowRollout(error.payload.plan);formError(error);}
  finally{button.disabled=false;}
}
async function managedSubmit(event) {
  event.preventDefault();const form=event.target,submit=$('button[type="submit"]',form),data=new FormData(form);submit.disabled=true;
  try {
    if(form.id==='managed-rollout-form'){
      if(!['admin','super_admin'].includes(state.role))throw new Error('Administrator access is required.');
      const server_ids=data.getAll('server_ids');if(!server_ids.length)throw new Error('Select the exact endpoints to apply.');
      const plan=await api('/policy-rollouts',{method:'POST',body:{name:String(data.get('name')).trim(),server_ids}});managedShowRollout(plan.plan || plan);if(typeof policyDeploymentsPublished==='function')policyDeploymentsPublished(plan);await refreshManagedRollouts();return;
    }
    if(form.id==='managed-restore-form'){
      if(!['admin','super_admin'].includes(state.role))throw new Error('Administrator access is required to restore a historical revision.');
      const reviewed=state.activeManagedRestore;if(!reviewed||reviewed.id!==form.dataset.id||reviewed.revision!==num(form.dataset.revision))throw new Error('Open and review the exact immutable revision before restoring it.');
      M.exactPolicy(reviewed.record,reviewed.id,reviewed.revision);M.exactPolicy(reviewed.before,reviewed.id);
      const reason=String(data.get('reason') || '').trim();if(reason.length<3)throw new Error('Enter a reason for restoring this revision.');
      const result=await api(`/policies/${encodeURIComponent(form.dataset.id)}/rollback`,{method:'POST',body:{revision:num(form.dataset.revision),reason}});
      state.activeManagedRestore=null;if(typeof policyDeploymentsPublished==='function')policyDeploymentsPublished(result.policy || result);toast(`Restored as new revision ${num((result.policy || result).revision)}. Eligible endpoints receive the saved intent; verify their actual results.`);await load();await managedPolicyHistory(form.dataset.id);
    }
  }catch(error){formError(error);}
  finally{submit.disabled=false;}
}
