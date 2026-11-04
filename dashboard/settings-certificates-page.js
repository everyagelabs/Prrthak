'use strict';

function platformCertificateUploadIdentity(){
  return JSON.stringify([state.authType||'',state.user?.id||state.user?.oid||state.user?.sub||'',state.role||'',state.token||'']);
}
function platformClearCertificateUpload(){
  state.platformP12ReadSequence=(state.platformP12ReadSequence||0)+1;
  state.platformP12Base64='';state.platformP12Owner='';state.platformP12Loading=false;
  const reader=state.platformP12Reader;state.platformP12Reader=null;
  if(reader?.readyState===1){try{reader.abort();}catch(_){/* A completed reader needs no cancellation. */}}
}

function platformCertificateDetailsHTML(certificate={}){
  return `<dl class="detail-grid"><div><dt>Subject</dt><dd>${h(certificate.subject || 'Not reported')}</dd></div><div><dt>Issuer</dt><dd>${h(certificate.issuer || 'Not reported')}</dd></div><div><dt>Expires</dt><dd>${h(timestamp(certificate.not_after || certificate.expires_at))}</dd></div><div><dt>DNS / IP names</dt><dd>${h((certificate.sans || []).join(', ') || 'Not reported')}</dd></div></dl>${certificate.fingerprint || certificate.fingerprint_sha256?`<p class="help-text">SHA-256 fingerprint</p><code class="platform-certificate-fingerprint">${h(certificate.fingerprint_sha256 || certificate.fingerprint)}</code>`:''}`;
}
function platformCertificateSubjectDefault(value) {
  const label = String(value || '').trim();
  if (/[\p{C}\p{Z}]/u.test(label.replaceAll(' ', ''))) return '';
  return new TextEncoder().encode(label).length <= 64 ? label : '';
}
function platformCertificateGenerationFields(info, certificate, mode) {
  const {cluster = {}, identity = {}} = state.platformAppliance || {};
  let savedHostname = '';
  try {
    const origin = new URL(cluster.origin);
    if (origin.protocol === 'https:') savedHostname = origin.hostname.replace(/^\[|\]$/g, '');
  } catch {}
  const hostname = savedHostname || info.hostname || identity.ip || '';
  const commonName = platformCertificateSubjectDefault(savedHostname ? hostname : certificate.common_name || hostname);
  const organization = platformCertificateSubjectDefault(cluster.name) || certificate.organization || '';
  const unit = platformCertificateSubjectDefault(identity.site) || certificate.organizational_unit || '';
  const additionalNames = [...new Set([info.hostname, identity.ip, ...(certificate.sans || [])])]
    .filter(name => name && name.toLowerCase() !== hostname.toLowerCase()).slice(0, 100);
  const issuerHelp = info.generation_issuer === 'existing_local_issuer'
    ? 'The configured local CA signs the replacement and supplies the issuer name.'
    : info.generation_issuer === 'literal_self_signed'
      ? 'Clients need to trust the new self-signed certificate.'
      : 'The review shows the signing authority and client trust changes.';
  return `<div id="certificate-self-signed-fields" ${mode !== 'self_signed' ? 'hidden' : ''}>
    <p class="help-text">${hostname ? `Generate for <strong>${h(hostname)}</strong>${cluster.name ? ' · ' + h(cluster.name) : ''}${identity.site ? ' · ' + h(identity.site) : ''}.` : 'Enter the controller’s HTTPS address.'} ${issuerHelp}</p>
    <details id="certificate-identity-details" ${hostname ? '' : 'open'}>
      <summary>Certificate names and addresses</summary>
    <div class="field-row">
      <div class="field"><label for="certificate-common-name">Subject common name (CN)</label>
        <input id="certificate-common-name" name="subject_common_name" value="${h(commonName)}" maxlength="64" placeholder="prthak.example.com">
      </div>
      <div class="field"><label for="certificate-hostname">Controller HTTPS hostname or IP</label>
        <input id="certificate-hostname" name="hostname" value="${h(hostname)}" maxlength="253" placeholder="prthak.example.com">
      </div>
    </div>
    <div class="field-row">
      <div class="field"><label for="certificate-organization">Organization (O, optional)</label>
        <input id="certificate-organization" name="subject_organization" value="${h(organization)}" maxlength="64">
      </div>
      <div class="field"><label for="certificate-organizational-unit">Organizational unit (OU, optional)</label>
        <input id="certificate-organizational-unit" name="subject_organizational_unit" value="${h(unit)}" maxlength="64">
      </div>
    </div>
    <div class="field"><label for="certificate-sans">Additional DNS names and IP addresses</label>
      <textarea id="certificate-sans" name="sans" rows="3" placeholder="controller-noida.example.com, 10.241.10.11">${h(additionalNames.join('\n'))}</textarea>
      <small>Separate addresses with commas or new lines.</small>
    </div>
    </details>
  </div>`;
}

function platformCertificatesHTML() {
  const info = state.platformCertificates || {};
  const certificate = info.current || info.certificate || {};
  const mode = state.platformCertificateMode || 'pem';
  return `<section class="card platform-panel">
    <div class="section-line">
      <h2>Controller HTTPS certificate</h2>
      <button type="button" class="text-button" data-action="platform-certificate-refresh">Reload details</button>
    </div>
    ${state.platformCertificatesError ? `<div class="inline-notice warning">${h(state.platformCertificatesError)}</div>` : ''}
    ${(info.warnings || []).map(warning => `<p class="inline-notice warning">${h(warning)}</p>`).join('')}
    ${platformCertificateDetailsHTML(certificate)}
    <p class="help-text">A replacement takes effect after restart and verification.</p>
  </section>
  <section class="card platform-panel">
    <h2>Replace the certificate</h2>
    <form id="platform-certificate-form">
      <div id="platform-certificate-error" class="form-error" role="alert" hidden></div>
      <div class="field">
        <label for="platform-certificate-mode">Certificate source</label>
        <select id="platform-certificate-mode" name="mode">
          <option value="ca_signed" ${mode !== 'self_signed' ? 'selected' : ''}>Import CA-signed certificate</option>
          <option value="self_signed" ${mode === 'self_signed' ? 'selected' : ''}>Generate self-signed certificate</option>
        </select>
      </div>
      <div id="certificate-ca-signed-fields" ${mode === 'self_signed' ? 'hidden' : ''}>
        <div class="field">
          <label for="platform-certificate-format">File format</label>
          <select id="platform-certificate-format" name="format">
            <option value="pem" ${mode !== 'pkcs12' ? 'selected' : ''}>PEM</option>
            <option value="pkcs12" ${mode === 'pkcs12' ? 'selected' : ''}>PKCS#12 (.p12 / .pfx)</option>
          </select>
        </div>
      <div id="certificate-pem-fields" ${mode !== 'pem' ? 'hidden' : ''}>
        <div class="field">
          <label for="certificate-pem">PEM certificate / chain</label>
          <textarea id="certificate-pem" name="certificate_pem" rows="5" spellcheck="false" autocomplete="off"></textarea>
        </div>
        <div class="field">
          <label for="certificate-key-pem">PEM private key</label>
          <textarea id="certificate-key-pem" name="private_key_pem" class="appliance-masked-secret" rows="4" spellcheck="false" autocomplete="off"></textarea>
        </div>
        <div class="field">
          <label for="certificate-key-password">PEM key password (if encrypted)</label>
          <input id="certificate-key-password" name="key_password" type="password" autocomplete="off">
        </div>
      </div>
      <div id="certificate-pkcs12-fields" ${mode !== 'pkcs12' ? 'hidden' : ''}>
        <div class="field">
          <label for="certificate-pkcs12-file">PKCS#12 file</label>
          <input id="certificate-pkcs12-file" type="file" accept=".p12,.pfx,application/x-pkcs12">
          <small id="certificate-file-status">Choose a .p12 or .pfx file, or paste base64 below. Maximum 2 MiB.</small>
        </div>
        <details>
          <summary>Paste base64 instead of uploading a file</summary>
          <div class="field">
            <label for="certificate-pkcs12-base64">PKCS#12 base64</label>
            <textarea id="certificate-pkcs12-base64" name="pkcs12_base64" rows="4" class="appliance-masked-secret" autocomplete="off" spellcheck="false"></textarea>
          </div>
        </details>
        <div class="field">
          <label for="certificate-pkcs12-password">PKCS#12 password</label>
          <input id="certificate-pkcs12-password" type="password" name="password" autocomplete="off">
        </div>
      </div>
      </div>
      ${platformCertificateGenerationFields(info, certificate, mode)}
      <div class="platform-form-actions">
        <button class="button secondary" type="submit">Review certificate</button>
      </div>
    </form>
  </section><details class="card platform-panel"><summary>Endpoint and cluster certificates</summary>${platformEndpointCertificatesHTML()}${platformInternalCertificatesHTML()}</details>`;
}
async function loadPlatformCertificates() {
  if (!canManagePlatform()) return;
  await Promise.all([
    loadEndpointCertificates(false),
    loadPlatformAppliance(),
    api('/platform/certificates').then(info => {
      state.platformCertificates = info;
      state.platformCertificatesError = '';
    }, error => {
      state.platformCertificatesError = 'Certificate status is unavailable: ' + error.message;
    })
  ]);
  if (state.view === 'settings' && !platformHasDraft() && !$('#modal').open && !document.activeElement?.matches('input,select,textarea')) render();
}
function platformSetCertificateMode(mode) {
  platformClearCertificateUpload();
  state.platformCertificateMode = mode;
  $('#platform-certificate-mode').value = mode === 'self_signed' ? mode : 'ca_signed';
  if (mode !== 'self_signed') $('#platform-certificate-format').value = mode;
  $('#certificate-pkcs12-file').value = '';
  $('#certificate-file-status').textContent = 'Choose a .p12 or .pfx file, or paste base64 below. Maximum 2 MiB.';
  $('#certificate-ca-signed-fields').hidden = mode === 'self_signed';
  $('#certificate-pem-fields').hidden = mode !== 'pem';
  $('#certificate-pkcs12-fields').hidden = mode !== 'pkcs12';
  $('#certificate-self-signed-fields').hidden = mode !== 'self_signed';
}
function platformCertificateChange(event){
  if(event.target.id==='platform-certificate-mode'){
    platformSetCertificateMode(event.target.value==='self_signed'?'self_signed':$('#platform-certificate-format').value || 'pem');return true;
  }
  if(event.target.id==='platform-certificate-format'){platformSetCertificateMode(event.target.value);return true;}
  if(event.target.id==='certificate-pkcs12-file'){
    platformClearCertificateUpload();const file=event.target.files?.[0];if(!file){$('#certificate-file-status').textContent='Choose a .p12 or .pfx file, or paste base64 below. Maximum 2 MiB.';return true;}if(file.size>2*1024*1024){$('#certificate-file-status').textContent='Choose a PKCS#12 file no larger than 2 MiB.';return true;}
    const reader=new FileReader(),sequence=state.platformP12ReadSequence,owner=platformCertificateUploadIdentity();state.platformP12Reader=reader;state.platformP12Loading=true;$('#certificate-file-status').textContent='Reading '+file.name+'…';
    const current=()=>state.platformP12Reader===reader&&state.platformP12ReadSequence===sequence&&owner===platformCertificateUploadIdentity()&&canManagePlatform();
    reader.onload=()=>{if(!current())return;state.platformP12Reader=null;state.platformP12Loading=false;state.platformP12Owner=owner;state.platformP12Base64=String(reader.result || '').split(',')[1] || '';$('#certificate-file-status').textContent=file.name+' loaded locally for the next review request.';};
    reader.onerror=reader.onabort=()=>{if(!current())return;platformClearCertificateUpload();$('#certificate-file-status').textContent='The file could not be read. Choose it again.';};
    try{reader.readAsDataURL(file);}catch(_){if(current()){platformClearCertificateUpload();$('#certificate-file-status').textContent='The file could not be read. Choose it again.';}}return true;
  }
  return false;
}
async function platformCertificateSubmit(event){
  event.preventDefault();if(!canManagePlatform())return;const form=event.target,button=$('button[type="submit"]',form);button.disabled=true;
  const owner = platformCertificateUploadIdentity();
  const sequence = state.platformP12ReadSequence || 0;
  const isCurrent = () => form.isConnected !== false && owner === platformCertificateUploadIdentity() &&
    sequence === (state.platformP12ReadSequence || 0) && canManagePlatform();
  try{
    const values=new FormData(form),source=String(values.get('mode') || 'ca_signed');
    const mode=source==='ca_signed'?String(values.get('format') || 'pem'):source,body={mode};
    if(mode==='pem'){body.certificate_pem=String(values.get('certificate_pem') || '').trim();body.private_key_pem=String(values.get('private_key_pem') || '').trim();if(values.get('key_password'))body.key_password=String(values.get('key_password'));if(!body.certificate_pem||!body.private_key_pem)throw new Error('Provide the PEM certificate and its matching private key.');}
    else if(mode==='pkcs12'){const pasted=String(values.get('pkcs12_base64')||'').trim();if(!pasted&&state.platformP12Loading)throw new Error('Wait for the selected PKCS#12 file to finish reading.');if(!pasted&&state.platformP12Base64&&state.platformP12Owner!==platformCertificateUploadIdentity()){platformClearCertificateUpload();throw new Error('Choose the PKCS#12 file again after signing in.');}body.pkcs12_base64=pasted||state.platformP12Base64||'';body.password=String(values.get('password') || '');if(!body.pkcs12_base64)throw new Error('Upload a PKCS#12 file or paste its base64 content.');}
    else if (mode === 'self_signed') {
      body.hostname = String(values.get('hostname') || '').trim();
      if (!body.hostname) throw new Error('Enter the controller HTTPS hostname or IP for the generated certificate.');
      body.sans = String(values.get('sans') || '').split(/[,\s]+/).filter(Boolean);
      for (const field of ['subject_common_name', 'subject_organization', 'subject_organizational_unit']) {
        const value = String(values.get(field) || '').trim();
        if (value) body[field] = value;
      }
    }
    else throw new Error('Choose PEM, PKCS#12 or self-signed certificate material.');
    const plan = await api('/platform/certificates/preview', {method: 'POST', body});
    if (!isCurrent()) return;
    platformClearCertificateUpload();
    const fileInput = $('#certificate-pkcs12-file', form);
    if (fileInput) fileInput.value = '';
    for (const input of $$('textarea:not([name="sans"]),input[type="password"]', form)) input.value = '';
    platformShowApplianceReview(plan, 'certificates');
  } catch (error) {
    if (form.isConnected !== false && owner === platformCertificateUploadIdentity() && canManagePlatform()) platformHAError(form, error);
  } finally {
    button.disabled = false;
  }
}
