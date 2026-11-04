'use strict';

const agentUpgradeRoute = '/platform/agent-upgrades';
const agentUpgradeCapability = 'agent_pull_upgrade_v1';
const agentUpgradeProgress = new Set(['queued', 'staging', 'upgrading', 'active', 'scheduled']);
const agentUpgradePageSize = 100;
const agentUpgradeState = {
  generation: 0, index: null, selected: '', detail: null, review: null,
  reviewPage: 0, outcomePage: 0,
  error: '', detailError: '', detailRequest: 0, detailLoading: false,
  loading: false, scheduling: false, timer: undefined,
};

function platformClearAgentUpgradeState(){
  clearTimeout(agentUpgradeState.timer);
  Object.assign(agentUpgradeState, {
    generation: agentUpgradeState.generation + 1, index: null, selected: '', detail: null, review: null,
    reviewPage: 0, outcomePage: 0,
    error: '', detailError: '', detailRequest: 0, detailLoading: false,
    loading: false, scheduling: false, timer: undefined,
  });
}

function platformAgentUpgradeAllowed(){
  return canManagePlatform() && state.authType === 'session' && !state.passwordChangeRequired;
}

function platformAgentUpgradeOnPage(){
  return state.view === 'settings' && state.platformTab === 'agent-upgrades';
}

function agentUpgradeStatus(status){
  const values = {
    queued: ['Queued', 'neutral'], staging: ['Staging', 'neutral'], upgrading: ['Upgrading', 'warning'],
    active: ['In progress', 'warning'], scheduled: ['Scheduled', 'neutral'], applied: ['Applied', ''],
    completed: ['Completed', ''], blocked: ['Blocked', 'warning'], rolled_back: ['Rolled back', 'danger'],
    error: ['Error', 'danger'], expired: ['Expired', 'neutral'], revoked: ['Revoked', 'warning'],
  };
  return Object.hasOwn(values, status) ? values[status] : ['Not reported', 'neutral'];
}

function agentUpgradeBadge(status){
  return badge(...agentUpgradeStatus(status));
}

function agentUpgradeOutcomeCounts(outcomes = {}){
  const counts = Object.entries(outcomes).filter(([, count]) => Number.isSafeInteger(count) && count > 0);
  return counts.map(([status, count]) => `${format(count)} ${agentUpgradeStatus(status)[0].toLowerCase()}`).join(' · ');
}

function agentUpgradeOutcomeRows(targets){
  return targets.map(target => `<tr>
    <td><strong>${h(target.hostname || target.server_id)}</strong><small>${h(target.server_id)}</small></td>
    <td>${h(target.architecture || 'Not reported')}</td>
    <td>${h(target.previous_version || 'Not reported')}</td>
    <td>${h(target.reported_version || '—')}</td>
    <td>${agentUpgradeBadge(target.status)}</td>
    <td>${h(target.error || target.message || target.reason || '—')}</td>
    <td>${h(timestamp(target.updated_at || target.reported_at))}</td>
  </tr>`).join('');
}

function agentUpgradePagination(total, page, action){
  if (total <= agentUpgradePageSize) return '';
  const start = page * agentUpgradePageSize;
  const end = Math.min(start + agentUpgradePageSize, total);
  return `<div class="table-footer"><span role="status">Showing ${format(start + 1)}–${format(end)} of ${format(total)} endpoints</span><div class="toolbar-group">
    <button type="button" class="button secondary small" data-action="${action}" data-step="-1" ${page ? '' : 'disabled'}>Previous</button>
    <button type="button" class="button secondary small" data-action="${action}" data-step="1" ${end < total ? '' : 'disabled'}>Next</button>
  </div></div>`;
}

function platformAgentUpgradeHistoryHTML(){
  const {index, detail, selected, loading, error, detailError, detailLoading} = agentUpgradeState;
  if (!platformAgentUpgradeAllowed()) return '';
  const rollouts = (index?.rollouts || []).filter(rollout => Object.keys(rollout.outcomes || {}).length > 0);
  const targets = detail?.id === selected ? detail.targets || [] : [];
  const outcomeStart = agentUpgradeState.outcomePage * agentUpgradePageSize;
  return `${error ? `<p class="inline-notice warning" role="alert">${h(error)}</p>` : ''}
    ${rollouts.length ? `<div class="table-scroll"><table>
      <thead><tr><th>Version</th><th>Scheduled</th><th>Status</th><th>Endpoints</th><th>Outcomes</th><th>Details</th></tr></thead>
      <tbody>${rollouts.map(rollout => `<tr>
        <td><strong>${h(rollout.version)}</strong></td><td>${h(timestamp(rollout.confirmed_at))}</td>
        <td>${agentUpgradeBadge(rollout.status)}</td><td>${format(rollout.target_count)}</td>
        <td>${h(agentUpgradeOutcomeCounts(rollout.outcomes) || 'Waiting for agent reports')}</td>
        <td><button type="button" class="text-button" data-action="platform-agent-upgrades-detail" data-id="${h(rollout.id)}" aria-pressed="${selected === rollout.id}">View outcomes</button></td>
      </tr>`).join('')}</tbody></table></div>` : `<p class="help-text">${loading ? 'Loading upgrade history…' : 'No agent upgrades have been scheduled.'}</p>`}
    ${selected ? `<section aria-labelledby="agent-upgrade-outcomes-title">
      <div class="section-line"><h3 id="agent-upgrade-outcomes-title">Endpoint outcomes${detail?.id === selected ? ` · ${h(detail.version)}` : ''}</h3></div>
      ${detailError ? `<p class="inline-notice warning" role="alert">${h(detailError)}</p>` : ''}
      ${targets.length ? `<div class="table-scroll"><table>
        <thead><tr><th>Endpoint</th><th>Architecture</th><th>Previous version</th><th>Reported version</th><th>Status</th><th>Agent report</th><th>Updated</th></tr></thead>
        <tbody>${agentUpgradeOutcomeRows(targets.slice(outcomeStart, outcomeStart + agentUpgradePageSize))}</tbody></table></div>
        ${agentUpgradePagination(targets.length, agentUpgradeState.outcomePage, 'platform-agent-upgrades-outcome-page')}` : `<p class="help-text">${detailLoading ? 'Loading endpoint outcomes…' : 'No endpoint outcomes are available yet.'}</p>`}
    </section>` : ''}`;
}

function platformAgentUpgradesHTML(){
  const {index, loading, error} = agentUpgradeState;
  const allowed = platformAgentUpgradeAllowed();
  const releases = index?.releases || [];
  const ready = allowed && index?.capability === agentUpgradeCapability && releases.length > 0;
  const notice = !allowed ? 'Sign in as a Super Admin on an installed HTTPS controller to schedule an agent upgrade.'
    : !index && !error ? 'Checking signed agent packages…'
    : index?.capability !== agentUpgradeCapability ? 'Agent upgrades are unavailable on this controller.'
    : !releases.length ? 'This controller has no verified agent packages available for upgrade.' : '';
  return `<section class="card platform-panel">
    <div class="section-line"><h2>Agent upgrades</h2><button type="button" class="button secondary small" data-action="platform-agent-upgrades-refresh" ${!allowed || loading ? 'disabled' : ''}>${icon('refresh')}Refresh</button></div>
    <p class="platform-intro">Choose a signed version and a target scope. Agents begin only after a Super Admin schedules the reviewed rollout.</p>
    ${notice ? `<p class="inline-notice" role="status">${h(notice)}</p>` : ''}
    ${ready ? `<form id="platform-agent-upgrade-scope-form">
      <div id="agent-upgrade-scope-error" class="form-error" role="alert" hidden></div>
      <div class="field-row">
        <div class="field"><label for="agent-upgrade-version">Signed agent version</label><select id="agent-upgrade-version" name="version" required>
          ${releases.map(release => `<option value="${h(release.version)}">${h(release.version)} · ${h(Object.keys(release.architectures || {}).join(', '))}</option>`).join('')}
        </select></div>
        <div class="field"><label for="agent-upgrade-scope">Target by</label><select id="agent-upgrade-scope" name="scope">
          <option value="endpoints">Selected endpoints</option><option value="tags">Tags</option><option value="location">Saved location or DC</option>
        </select></div>
      </div>
      <div data-agent-upgrade-scope="endpoints">${endpointPickerHTML('agent-upgrade-endpoints', 'upgrade_endpoint_ids', state.data?.servers || [])}</div>
      <div class="field" data-agent-upgrade-scope="tags" hidden><label for="agent-upgrade-tags">Target tags</label><input id="agent-upgrade-tags" name="tags" maxlength="1024" placeholder="application=billing, environment=production"><small>Endpoints must match every tag.</small></div>
      <div class="field" data-agent-upgrade-scope="location" hidden><label for="agent-upgrade-location">Saved location or DC</label><select id="agent-upgrade-location" name="location_id">${savedLocationOptions()}</select></div>
      <button class="button secondary" type="submit">Review target endpoints</button>
    </form>` : ''}
  </section>
  <section class="card platform-panel" aria-labelledby="agent-upgrade-history-title">
    <div class="section-line"><h2 id="agent-upgrade-history-title">Upgrade history</h2></div>
    <div id="agent-upgrade-history">${platformAgentUpgradeHistoryHTML()}</div>
  </section>`;
}

function agentUpgradeScopePayload(form){
  const fields = new FormData(form);
  const version = String(fields.get('version') || '');
  if (!(agentUpgradeState.index?.releases || []).some(release => release.version === version)) throw new Error('Choose an available signed agent version.');
  switch (fields.get('scope')) {
    case 'endpoints': {
      const server_ids = [...new Set(fields.getAll('upgrade_endpoint_ids').map(String))];
      if (!server_ids.length) throw new Error('Select at least one enrolled endpoint.');
      return {version, server_ids};
    }
    case 'tags': {
      const selector = parseTags(String(fields.get('tags') || ''));
      if (!Object.keys(selector).length) throw new Error('Enter at least one target tag.');
      return {version, selector};
    }
    case 'location': {
      const locationId = String(fields.get('location_id') || '');
      if (!(state.data?.locations || []).some(location => location.id === locationId)) throw new Error('Choose a saved location or DC.');
      return {version, selector: {location_id: locationId}};
    }
    default: throw new Error('Choose a valid target scope.');
  }
}

function platformAgentUpgradeScopeChange(event){
  if (event.target.id !== 'agent-upgrade-scope') return false;
  const form = event.target.closest('form');
  for (const field of $$('[data-agent-upgrade-scope]', form)) field.hidden = field.dataset.agentUpgradeScope !== event.target.value;
  return true;
}

function agentUpgradeReviewReady(plan){
  return platformAgentUpgradeAllowed() && platformUI.reviewReady(plan, state.role) &&
    Array.isArray(plan.targets) && plan.targets.length > 0 && plan.targets.length === plan.target_count;
}

function agentUpgradeReviewedEndpoints(plan){
  const targets = plan.targets || [];
  const exclusions = plan.exclusions || [];
  const start = agentUpgradeState.reviewPage * agentUpgradePageSize;
  const rows = [...targets, ...exclusions].slice(start, start + agentUpgradePageSize);
  if (!rows.length) return '<p class="help-text">No endpoints matched this scope.</p>';
  return `<div class="table-scroll"><table><thead><tr><th>Endpoint</th><th>Current version</th><th>Architecture</th><th>Eligibility</th></tr></thead>
    <tbody>${rows.map(target => `<tr><td><strong>${h(target.hostname || target.server_id)}</strong><small>${h(target.server_id)}</small></td><td>${h(target.previous_version || 'Not reported')}</td><td>${h(target.architecture || 'Not reported')}</td><td>${target.reason ? `${badge('Excluded', 'warning')}<small>${h(target.reason)}</small>` : badge('Eligible')}</td></tr>`).join('')}</tbody></table></div>
    ${agentUpgradePagination(targets.length + exclusions.length, agentUpgradeState.reviewPage, 'platform-agent-upgrades-review-page')}`;
}

function showAgentUpgradeReview(plan){
  agentUpgradeState.review = plan;
  agentUpgradeState.reviewPage = 0;
  const targets = plan.targets || [];
  const excluded = plan.exclusions?.length || 0;
  const ready = agentUpgradeReviewReady(plan);
  showModal('Review agent upgrade', `<form id="platform-agent-upgrade-confirm-form" data-id="${h(plan.id || '')}">
    <div class="modal-body">${errorSlot}
      <p>Signed version <strong>${h(plan.version)}</strong> will be offered to <strong>${format(targets.length)} eligible endpoint${targets.length === 1 ? '' : 's'}</strong> when they next poll. Each agent reports its result after attempting the upgrade.</p>
      ${(plan.blockers || []).map(blocker => `<p class="inline-notice warning" role="alert">${h(blocker)}</p>`).join('')}
      ${excluded ? `<p class="help-text">${format(excluded)} excluded endpoint${excluded === 1 ? '' : 's'}.</p>` : ''}
      <div id="agent-upgrade-reviewed-endpoints">${agentUpgradeReviewedEndpoints(plan)}</div>
      ${ready ? `<p class="help-text">This review expires ${h(timestamp(plan.expires_at))}. Scheduling authorizes the listed agents to attempt the upgrade.</p>` : ''}
    </div>
    <div class="modal-footer"><button type="button" class="button secondary" data-action="close-modal">Close</button>${ready ? '<button type="submit" class="button primary">Schedule upgrade</button>' : ''}</div>
  </form>`, 'EXACT ENDPOINT REVIEW');
}

function agentUpgradePoll(){
  clearTimeout(agentUpgradeState.timer);
  if (!platformAgentUpgradeAllowed() || !platformAgentUpgradeOnPage() || document.hidden) return;
  if ((agentUpgradeState.index?.rollouts || []).some(rollout => agentUpgradeProgress.has(rollout.status))) {
    agentUpgradeState.timer = setTimeout(loadPlatformAgentUpgrades, 5000);
  }
}

function refreshAgentUpgradeHistory(){
  if (!platformAgentUpgradeOnPage()) return;
  const history = $('#agent-upgrade-history');
  if (history) history.innerHTML = platformAgentUpgradeHistoryHTML();
}

async function loadAgentUpgradeDetail(id){
  if (!id) return;
  const generation = agentUpgradeState.generation;
  const request = ++agentUpgradeState.detailRequest;
  const current = () => generation === agentUpgradeState.generation && request === agentUpgradeState.detailRequest && id === agentUpgradeState.selected;
  agentUpgradeState.detailLoading = true;
  agentUpgradeState.detailError = '';
  try {
    const detail = await api(`${agentUpgradeRoute}/${encodeURIComponent(id)}`);
    if (current()) agentUpgradeState.detail = detail;
  } catch(error) {
    if (current()) agentUpgradeState.detailError = error.message;
  } finally {
    if (current()) agentUpgradeState.detailLoading = false;
  }
}

async function loadPlatformAgentUpgrades(redraw = true){
  if (!platformAgentUpgradeAllowed() || agentUpgradeState.loading) return;
  const generation = agentUpgradeState.generation;
  agentUpgradeState.loading = true;
  try {
    const index = await api(agentUpgradeRoute);
    if (generation !== agentUpgradeState.generation) return;
    if (typeof index?.capability !== 'string' || !Array.isArray(index.releases) || !Array.isArray(index.rollouts)) {
      throw new Error('The controller did not return a complete agent upgrade status.');
    }
    agentUpgradeState.index = index;
    agentUpgradeState.error = '';
    if (!agentUpgradeState.detailLoading) await loadAgentUpgradeDetail(agentUpgradeState.selected);
  } catch(error) {
    if (generation === agentUpgradeState.generation) agentUpgradeState.error = error.message;
  } finally {
    if (generation === agentUpgradeState.generation) {
      agentUpgradeState.loading = false;
      if (redraw && platformAgentUpgradeOnPage()) {
        if (platformHasDraft() || $('#modal').open || document.activeElement?.matches('input,select,textarea')) {
          refreshAgentUpgradeHistory();
        } else render();
      }
      agentUpgradePoll();
    }
  }
}

async function platformAgentUpgradeSubmit(event){
  event.preventDefault();
  if (!platformAgentUpgradeAllowed() || !platformAgentUpgradeOnPage()) return;
  const form = event.target;
  const button = $('button[type="submit"]', form);
  const generation = agentUpgradeState.generation;
  if (form.id === 'platform-agent-upgrade-scope-form') {
    if (button.disabled || agentUpgradeState.index?.capability !== agentUpgradeCapability) return;
    const errorElement = $('#agent-upgrade-scope-error', form);
    button.disabled = true;
    errorElement.hidden = true;
    try {
      const body = agentUpgradeScopePayload(form);
      const plan = await api(`${agentUpgradeRoute}/preview`, {method: 'POST', body});
      if (generation !== agentUpgradeState.generation || !platformAgentUpgradeOnPage() || $('#platform-agent-upgrade-scope-form') !== form || $('#modal').open) return;
      if (JSON.stringify(body) !== JSON.stringify(agentUpgradeScopePayload(form))) return;
      if (plan.version !== body.version || !Array.isArray(plan.targets) || !Array.isArray(plan.exclusions)) {
        throw new Error('The controller returned an incomplete endpoint review.');
      }
      showAgentUpgradeReview(plan);
    } catch(error) {
      if (generation === agentUpgradeState.generation) {
        errorElement.textContent = error.message;
        errorElement.hidden = false;
      }
    } finally { button.disabled = false; }
    return;
  }
  const plan = agentUpgradeState.review;
  if (agentUpgradeState.scheduling || !$('#modal').open || form.dataset.id !== plan?.id) return;
  if (!agentUpgradeReviewReady(plan)) {
    formError(new Error('Review the endpoints again before scheduling.'));
    return;
  }
  agentUpgradeState.scheduling = true;
  button.disabled = true;
  try {
    const detail = await api(`${agentUpgradeRoute}/${encodeURIComponent(plan.id)}/confirm`, {
      method: 'POST', body: {digest: plan.digest},
    });
    if (generation !== agentUpgradeState.generation) return;
    agentUpgradeState.selected = detail.id;
    agentUpgradeState.outcomePage = 0;
    agentUpgradeState.detail = detail;
    agentUpgradeState.review = null;
    if ($('#platform-agent-upgrade-confirm-form') === form) closeModal();
    toast('Agent upgrade scheduled. Endpoints report their outcomes as they poll.');
    await loadPlatformAgentUpgrades();
  } catch(error) {
    if (generation === agentUpgradeState.generation && $('#platform-agent-upgrade-confirm-form') === form) formError(error);
  } finally {
    if (generation === agentUpgradeState.generation) {
      agentUpgradeState.scheduling = false;
      button.disabled = !agentUpgradeReviewReady(plan);
    }
  }
}

async function platformAgentUpgradeAction(button){
  if (!platformAgentUpgradeAllowed()) return;
  const {action, id, step} = button.dataset;
  if (action === 'platform-agent-upgrades-review-page' || action === 'platform-agent-upgrades-outcome-page') {
    if (step !== '-1' && step !== '1') return;
    const reviewing = action === 'platform-agent-upgrades-review-page';
    const plan = reviewing ? agentUpgradeState.review : agentUpgradeState.detail;
    const page = reviewing ? 'reviewPage' : 'outcomePage';
    const total = (plan?.targets?.length || 0) + (reviewing ? plan?.exclusions?.length || 0 : 0);
    const next = agentUpgradeState[page] + Number(step);
    if (next < 0 || next * agentUpgradePageSize >= total) return;
    agentUpgradeState[page] = next;
    if (reviewing) $('#agent-upgrade-reviewed-endpoints').innerHTML = agentUpgradeReviewedEndpoints(plan);
    else refreshAgentUpgradeHistory();
    const selector = `[data-action="${action}"]`;
    ($(selector + `[data-step="${step}"]:not(:disabled)`) || $(selector + ':not(:disabled)'))?.focus();
    return;
  }
  if (action === 'platform-agent-upgrades-detail') {
    agentUpgradeState.selected = id;
    agentUpgradeState.outcomePage = 0;
    agentUpgradeState.detail = null;
    const loading = loadAgentUpgradeDetail(id);
    refreshAgentUpgradeHistory();
    await loading;
    refreshAgentUpgradeHistory();
    return;
  }
  return loadPlatformAgentUpgrades();
}
