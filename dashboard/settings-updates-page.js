'use strict';

let platformUpdateTimer;
let platformUpdateGeneration = 0;
const platformUpdateChunkLimit = 1024 * 1024;
const platformUpdateRetryDelays = [1000, 2000, 4000];

function platformClearUpdateState() {
  clearTimeout(platformUpdateTimer);
  platformUpdateGeneration++;
  state.platformUpdates = null;
  state.platformUpdatesError = '';
  state.platformUpdatesLoading = false;
  state.platformUpdateBusy = false;
  state.platformUpdateReviewId = null;
  if (state.platformDraftForm?.id === 'platform-update-upload-form') platformClearDraft(state.platformDraftForm);
}

function platformUpdateSessionReady() {
  return canManagePlatform() && state.authType === 'session' && !!state.user?.id &&
    !!state.csrfToken && !state.passwordChangeRequired && state.platformInfo?.runtime?.demo !== true;
}

function platformUpdateReady() {
  return platformUpdateSessionReady() && state.platformUpdates?.available === true &&
    !state.platformUpdatesError && !state.platformUpdateBusy;
}

function platformUpdateCanUpload() {
  const record = state.platformUpdates?.update;
  return platformUpdateReady() && (!record || record.status === 'uploading' && record.can_cancel === true ||
    ['applied', 'rolled_back', 'failed'].includes(record.status));
}

function platformUpdateNotice() {
  if (!platformUpdateSessionReady()) {
    return 'Sign in with a Super Admin account on the installed controller to manage updates.';
  }
  if (!state.platformUpdates && !state.platformUpdatesError) return 'Checking update support on this controller…';
  if (state.platformUpdates?.available !== true) {
    return 'Install an updater-enabled standalone RHEL 9/10 x86_64 appliance release once to enable browser updates.';
  }
  return '';
}

function platformUpdateProgressLabel(record) {
  return `${platformUI.bytes(record.offset)} of ${platformUI.bytes(record.size)} uploaded`;
}

function platformUpdateUploadLabel(record) {
  return record?.status === 'uploading' ? 'Resume upload and check package' : 'Upload and check package';
}

function platformUpdateProgressHTML(record) {
  if (!record) return '<p class="help-text">No update has been reported.</p>';
  const verified = record.result?.phase === 'committed' && record.result?.verified === true;
  const restored = record.result?.phase === 'rolled_back' && record.result?.rolled_back === true;
  const label = ({
    uploading: 'Uploading',
    reviewing: 'Checking the package',
    ready: 'Ready for review',
    applying: 'Installation in progress',
    applied: verified ? 'Update verified' : 'Update verification unavailable',
    rolled_back: restored ? 'Previous controller restored' : 'Rollback verification unavailable',
    failed: 'Update failed'
  })[record.status] || 'Update status unavailable';
  const tone = record.status === 'applied' && verified ? '' :
    ['failed', 'rolled_back'].includes(record.status) ? 'warning' : 'neutral';
  const review = record.review || {};
  return `<article class="platform-operation-result">
    <div class="section-line"><h3>Last reported update</h3>${badge(label, tone)}</div>
    <dl class="detail-grid">
      <div><dt>Package</dt><dd>${h(record.name || 'Not reported')}</dd></div>
      <div><dt>Target version</dt><dd>${h(review.version || record.version || 'Not reported')}</dd></div>
      <div><dt>Reported stage</dt><dd>${h(record.result?.phase ? humanize(record.result.phase) : label)}</dd></div>
      ${record.failure_step ? `<div><dt>Failure step</dt><dd>${h(record.failure_step)}</dd></div>` : ''}
      ${record.recovery_step ? `<div><dt>Recovery step</dt><dd>${h(record.recovery_step)}</dd></div>` : ''}
    </dl>
    ${record.status === 'uploading' ? `<progress id="platform-update-transfer" max="${h(record.size)}" value="${h(record.offset)}" aria-label="Controller package uploaded"></progress>
      <p id="platform-update-transfer-label" class="help-text">${h(platformUpdateProgressLabel(record))}</p>` : ''}
    ${record.status === 'applying' ? '<p class="help-text">The controller can briefly disconnect while it restarts. Wait for verified installation or rollback.</p>' : ''}
    ${record.error ? `<p class="form-error" role="alert">${h(record.error)}</p>` : ''}
    <div class="platform-form-actions">
      ${record.status === 'ready' || record.status === 'applying' && record.can_retry === true ? `<button type="button" class="button secondary" data-action="platform-update-open-review" ${!platformUpdateReady() || !record.confirmation_phrase ? 'disabled' : ''}>${record.status === 'ready' ? 'Review controller update' : 'Resume installation request'}</button>` : ''}
      ${record.status === 'reviewing' && record.can_retry === true ? `<button type="button" class="button secondary" data-action="platform-update-retry-review" ${!platformUpdateReady() ? 'disabled' : ''}>Resume package check</button>` : ''}
      ${record.can_cancel === true ? `<button type="button" class="text-button" data-action="platform-update-cancel" ${!platformUpdateReady() ? 'disabled' : ''}>${['applied', 'rolled_back', 'failed'].includes(record.status) ? 'Clear update record' : 'Cancel staged update'}</button>` : ''}
    </div>
  </article>`;
}

function platformUpdatesHTML() {
  const status = state.platformUpdates || {};
  const notice = platformUpdateNotice();
  const disabled = platformUpdateCanUpload() ? '' : 'disabled';
  return `<section class="card platform-panel">
    <div class="section-line">
      <h2>Controller updates<span>Offline appliance</span></h2>
      <button type="button" class="text-button" data-action="platform-update-refresh" ${!platformUpdateSessionReady() || state.platformUpdateBusy ? 'disabled' : ''}>${icon('refresh')}Refresh update status</button>
    </div>
    <p class="platform-intro">Upload a signed offline controller package and its detached signature. Review the package before restarting this controller with the bundled images.</p>
    <p class="help-text">The update uses the existing Docker installation. Changes to RHEL host packages require the host installer.</p>
    ${notice ? `<div class="inline-notice">${h(notice)}</div>` : ''}
    ${(status.blockers || []).map(reason => `<p class="help-text">${h(reason)}</p>`).join('')}
    ${state.platformUpdatesError ? `<p class="inline-notice warning" role="alert">${h(state.platformUpdatesError)}</p>` : ''}
    <div id="platform-update-record">${platformUpdateProgressHTML(status.update)}</div>
    <form id="platform-update-upload-form">
      <div id="platform-update-upload-error" class="form-error" role="alert" hidden></div>
      <div class="field">
        <label for="platform-update-archive">Offline controller package (.tar.gz)</label>
        <input id="platform-update-archive" name="archive" type="file" accept=".tar.gz,application/gzip" required ${disabled}>
        ${status.max_bytes ? `<small>Maximum package size ${h(platformUI.bytes(status.max_bytes))}.</small>` : ''}
      </div>
      <div class="field">
        <label for="platform-update-signature">Detached release signature (.signature.json)</label>
        <input id="platform-update-signature" name="signature" type="file" accept=".json,application/json" required ${disabled}>
      </div>
      <button type="submit" class="button primary" ${disabled}>${platformUpdateUploadLabel(status.update)}</button>
    </form>
  </section>`;
}

function platformUpdateOnPage() {
  return state.view === 'settings' && state.platformTab === 'updates';
}

function platformUpdateSchedule() {
  clearTimeout(platformUpdateTimer);
  if (platformUpdateOnPage() && !document.hidden && platformUpdateSessionReady() &&
      ['reviewing', 'applying'].includes(state.platformUpdates?.update?.status)) {
    platformUpdateTimer = setTimeout(loadPlatformUpdates, 3500);
  }
}

async function loadPlatformUpdates(redraw = true) {
  if (!platformUpdateSessionReady() || state.platformUpdatesLoading || state.platformUpdateBusy) return;
  const generation = platformUpdateGeneration;
  state.platformUpdatesLoading = true;
  try {
    const response = await api('/platform/updates', {cache: 'no-store'});
    if (generation !== platformUpdateGeneration) return;
    if (typeof response?.available !== 'boolean' || !Array.isArray(response.blockers)) {
      throw new Error('The update manager did not return a complete status.');
    }
    state.platformUpdates = response;
    state.platformUpdatesError = '';
  } catch (error) {
    if (generation !== platformUpdateGeneration) return;
    state.platformUpdatesError = error.status === 404 ?
      'This controller needs the one-time installer upgrade to support browser updates.' :
      'Update status is unavailable. Reconnect to the controller and refresh to verify the outcome.';
  } finally {
    if (generation === platformUpdateGeneration) {
      state.platformUpdatesLoading = false;
      platformUpdateSchedule();
      if (redraw && platformUpdateOnPage() && !$('#modal').open) {
        if (platformHasDraft()) platformUpdateDrawRecord(state.platformUpdates?.update);
        else render();
      }
    }
  }
}

function platformUpdateRecordPath(id) {
  if (typeof id !== 'string' || !/^[a-z0-9-]{1,64}$/i.test(id)) {
    throw new Error('The update manager did not return a valid upload identity.');
  }
  return '/platform/updates/' + encodeURIComponent(id);
}

function platformUpdateDrawRecord(record) {
  if (platformUpdateOnPage()) {
    const panel = $('#platform-update-record');
    if (panel) panel.innerHTML = platformUpdateProgressHTML(record);
  }
}

function platformUpdateSetRecord(record) {
  state.platformUpdates = {...state.platformUpdates, update: record};
  platformUpdateDrawRecord(record);
}

function platformUpdateReviewable(record) {
  return !!record?.confirmation_phrase &&
    (record.status === 'ready' && Date.parse(record.review?.expires_at) > Date.now() ||
      record.status === 'applying' && record.can_retry === true);
}

function platformUpdateShowReview(record) {
  if (!platformUpdateReady() || !platformUpdateReviewable(record)) return;
  state.platformUpdateReviewId = record.id;
  const review = record.review || {};
  const retry = record.status === 'applying';
  showModal(retry ? 'Resume controller update' : 'Review controller update', `<form id="platform-update-review-form">
    <div class="modal-body">${errorSlot}
      <p class="inline-notice warning">${retry ? 'Resume the existing installation request and follow its reported outcome.' : 'The update restarts this controller. Follow the operation in Updates to verify installation or rollback.'}</p>
      <dl class="detail-grid">
        <div><dt>Package</dt><dd>${h(record.name)}</dd></div>
        <div><dt>Target version</dt><dd>${h(review.version || record.version || 'Not reported')}</dd></div>
        <div><dt>Verified package SHA-256</dt><dd><code>${h(review.sha256 || 'Not reported')}</code></dd></div>
        <div><dt>Review expiry</dt><dd>${h(timestamp(review.expires_at))}</dd></div>
      </dl>
      <div class="field">
        <label for="platform-update-phrase">Type the exact confirmation phrase</label>
        <code class="platform-confirmation-phrase">${h(record.confirmation_phrase)}</code>
        <input id="platform-update-phrase" name="confirmation" autocomplete="off" spellcheck="false" required>
      </div>
    </div>
    <div class="modal-footer">
      <button type="button" class="button secondary" data-action="close-modal">Close</button>
      <button type="submit" class="button danger" disabled>${retry ? 'Resume installation request' : 'Install update and restart'}</button>
    </div>
  </form>`, 'CONTROLLER UPDATE');
}

function platformUpdateCanApply(record, phrase) {
  return platformUpdateReady() && platformUpdateReviewable(record) && record.id === state.platformUpdateReviewId &&
    platformUI.exactPhrase(record, phrase);
}

function platformUpdateInput(event) {
  if (event.target.id !== 'platform-update-phrase') return false;
  const form = $('#platform-update-review-form');
  if (form) $('button[type="submit"]', form).disabled = !platformUpdateCanApply(state.platformUpdates?.update, event.target.value);
  return true;
}

function platformUpdateRetryable(error) {
  if (error.status) return [408, 429, 500, 502, 503, 504].includes(error.status);
  return ['AbortError', 'TimeoutError', 'TypeError'].includes(error.name);
}

async function platformUploadUpdate(values, generation) {
  const archive = values.get('archive');
  const signatureFile = values.get('signature');
  const {max_bytes, chunk_bytes} = state.platformUpdates;
  if (!archive?.name?.endsWith('.tar.gz') || !Number.isSafeInteger(archive.size) ||
      !Number.isSafeInteger(max_bytes) || archive.size < 1 || archive.size > max_bytes ||
      !Number.isSafeInteger(chunk_bytes) || chunk_bytes < 1 || chunk_bytes > 4 * 1024 * 1024) {
    throw new Error('Select an offline .tar.gz package within the supported size limit.');
  }
  if (!signatureFile?.name?.endsWith('.signature.json') || !Number.isSafeInteger(signatureFile.size) ||
      signatureFile.size < 1 || signatureFile.size > 16 * 1024) {
    throw new Error('Select the matching detached .signature.json file.');
  }
  let signature;
  try { signature = JSON.parse(await signatureFile.text()); }
  catch { throw new Error('The detached signature file is not valid JSON.'); }
  if (!signature || typeof signature !== 'object' || Array.isArray(signature)) {
    throw new Error('The detached signature file is not a valid release signature.');
  }
  if (generation !== platformUpdateGeneration) return;
  let record = await api('/platform/updates/upload', {
    method: 'POST', body: {name: archive.name, size: archive.size, signature}
  });
  if (generation !== platformUpdateGeneration) return;
  const path = platformUpdateRecordPath(record?.id);
  if (record.status !== 'uploading' || record.name !== archive.name || record.size !== archive.size ||
      !Number.isSafeInteger(record.offset) || record.offset < 0 || record.offset > archive.size) {
    throw new Error('The update manager did not return a valid upload position.');
  }
  platformUpdateSetRecord(record);
  const chunkSize = Math.min(chunk_bytes, platformUpdateChunkLimit);
  while (record.offset < archive.size) {
    const offset = record.offset;
    const end = Math.min(offset + chunkSize, archive.size);
    const chunk = archive.slice(offset, end);
    let next;
    for (let attempts = 0; generation === platformUpdateGeneration; attempts++) {
      try {
        // The controller accepts an exact byte-for-byte replay at this offset.
        next = await api(path + '/chunks/' + offset, {method: 'PUT', rawBody: chunk});
        break;
      } catch (error) {
        if (generation !== platformUpdateGeneration) return;
        if (!platformUpdateRetryable(error)) throw error;
        const delay = platformUpdateRetryDelays[attempts];
        if (delay === undefined) {
          throw new Error('Upload paused. Resume with the same package and signature.');
        }
        const label = platformUpdateOnPage() && $('#platform-update-transfer-label');
        if (label) label.textContent = `${platformUpdateProgressLabel(record)} · Retrying…`;
        await new Promise(resolve => setTimeout(resolve, error.status === 429 ? Math.max(2000, delay) : delay));
      }
    }
    if (generation !== platformUpdateGeneration) return;
    if (next?.id !== record.id || next.status !== 'uploading' || next.name !== archive.name ||
        next.offset !== end || next.size !== archive.size) {
      throw new Error('The upload position changed. Refresh status and resume with the same files.');
    }
    record = next;
    platformUpdateSetRecord(record);
  }
  const result = await api(path + '/review', {method: 'POST', body: {}});
  if (generation === platformUpdateGeneration && result?.id === record.id) platformUpdateSetRecord(result);
}

async function platformUpdateSubmit(event) {
  event.preventDefault();
  const form = event.target;
  const uploading = form.id === 'platform-update-upload-form';
  const values = new FormData(form);
  const record = state.platformUpdates?.update;
  const phrase = uploading ? '' : String(values.get('confirmation') || '');
  if (uploading ? !platformUpdateCanUpload() : !platformUpdateCanApply(record, phrase)) return;
  const generation = platformUpdateGeneration;
  const button = $('button[type="submit"]', form);
  const fileInputs = uploading ? $$('input[type="file"]', form) : [];
  button.disabled = true;
  for (const input of fileInputs) input.disabled = true;
  state.platformUpdateBusy = true;
  if (uploading) {
    platformMarkDraft(form);
    const error = $('#platform-update-upload-error');
    if (error) error.hidden = true;
  }
  let completed = false;
  try {
    if (uploading) await platformUploadUpdate(values, generation);
    else {
      const result = await api(platformUpdateRecordPath(record.id) + '/apply', {method: 'POST', body: {confirmation: phrase}});
      if (generation === platformUpdateGeneration && result?.id === record.id) platformUpdateSetRecord(result);
    }
    if (generation !== platformUpdateGeneration) return;
    completed = true;
    if (uploading) platformClearDraft(form);
    else closeModal();
  } catch (error) {
    if (generation !== platformUpdateGeneration) return;
    if (!uploading && (!error.status || error.status >= 500)) {
      state.platformUpdateReviewId = null;
      platformHAError(form, new Error('The request outcome is unknown. Close this review and refresh update status before retrying.'));
    } else platformHAError(form, error);
  } finally {
    if (generation === platformUpdateGeneration) {
      state.platformUpdateBusy = false;
      await loadPlatformUpdates();
      if (generation !== platformUpdateGeneration) return;
      button.disabled = uploading ? !platformUpdateCanUpload() : completed || !platformUpdateCanApply(state.platformUpdates?.update, phrase);
      if (uploading) button.textContent = platformUpdateUploadLabel(state.platformUpdates?.update);
      for (const input of fileInputs) input.disabled = !platformUpdateCanUpload();
    }
  }
}

async function platformUpdateAction(button) {
  if (!platformUpdateSessionReady()) return;
  if (button.dataset.action === 'platform-update-refresh') return loadPlatformUpdates();
  const record = state.platformUpdates?.update;
  if (button.dataset.action === 'platform-update-open-review') return platformUpdateShowReview(record);
  const cancel = button.dataset.action === 'platform-update-cancel' && record?.can_cancel === true;
  const retry = button.dataset.action === 'platform-update-retry-review' && record?.status === 'reviewing' && record.can_retry === true;
  if (!platformUpdateReady() || !(cancel || retry)) return;
  const generation = platformUpdateGeneration;
  state.platformUpdateBusy = true;
  button.disabled = true;
  try {
    const path = platformUpdateRecordPath(record.id);
    if (cancel) await api(path, {method: 'DELETE'});
    else await api(path + '/review', {method: 'POST', body: {}});
    if (generation === platformUpdateGeneration) platformClearDraft($('#platform-update-upload-form'));
  } catch (error) {
    if (generation === platformUpdateGeneration) toast(error.message, true);
  } finally {
    if (generation === platformUpdateGeneration) {
      state.platformUpdateBusy = false;
      button.disabled = false;
      await loadPlatformUpdates();
    }
  }
}
