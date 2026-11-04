'use strict';

const trafficCountUnits=['connections','packets','log_records','sample_minutes'];

function captureEvidence(row={}) {
  const known={accepted_connection:{label:'Accepted transport connection',unit:'connections',backend:'conntrack'},denied_packet:{label:'Denied packet',unit:'packets',backend:'nflog'}};
  if(row.count_unit==='sample_minutes'){
    const evidence=known[row.capture_kind];
    return {label:evidence?`${evidence.label} · sampled`:'Sampled communication',unit:'sample_minutes',backend:evidence?.backend || 'unknown'};
  }
  return known[row.capture_kind] || {label:'Legacy sampled log',unit:'log_records',backend:'journal'};
}
function captureUnitLabel(unit){return {connections:'connections',packets:'denied packets',log_records:'legacy log records',sample_minutes:'communication samples'}[unit] || 'legacy log records';}
function captureEvidenceHTML(row={}){const info=captureEvidence(row);return `${h(info.label)}<small>${h(info.backend)} · ${h(row.address_family || (String(row.source_ip || '').includes(':')?'ipv6':'ipv4'))}</small>`;}
function captureCountHTML(row={}){return `${format(row.count)}<small>${h(captureUnitLabel(captureEvidence(row).unit))}</small>`;}
function trafficCollectionFields(){return '<div class="field"><label class="host-check"><input type="checkbox" name="traffic_hit_count">Count traffic hits</label><small>Off by default. Record up to one communication sample per source and destination service per minute. Turn on for observed hit counts and rates.</small></div>';}
function trafficCollectionMode(values){return values.get('traffic_hit_count')==='on'?'hits':'sampled';}
function captureKindFields(){return `<input type="hidden" name="capture_scope_version" value="1"><div class="field"><div class="field-label">Capture evidence</div><label class="host-check"><input type="checkbox" name="observation_kinds" value="accepted_connection" checked>Accepted transport connections · conntrack</label><label class="host-check"><input type="checkbox" name="observation_kinds" value="denied_packet" checked>Denied packets · terminal NFLOG</label><small>Counts use separate units. New scopes require traffic_capture_v1. Historical scopes retain legacy sampled logs. Unsupported backends, IPv6 support, losses and gaps appear in endpoint receipts; this is not a complete traffic ledger or application-success proof.</small></div>`;}
function captureKindsPayload(values){const selected=values.getAll('observation_kinds');if(!selected.length&&String(values.get('capture_scope_version') || '')!=='1')return undefined;if(!selected.length||selected.some(kind=>!['accepted_connection','denied_packet'].includes(kind)))throw new Error('Select accepted connections, denied packets, or both.');return [...new Set(selected)].sort();}
const conntrackCaptureLimit = 'Conntrack startup/dump races, untracked flows and event loss cannot establish a complete connection ledger.';

function captureReasonKey(reason) {
  return String(reason || '').trim().toLowerCase().replace(/^(conntrack|nflog):\s*/, '').replace(/\.$/, '');
}

function captureCoverageHTML(coverage={}) {
  const backends = Array.isArray(coverage.capture_backends) ? coverage.capture_backends.slice(0, 3) : [];
  const gaps = Array.isArray(coverage.capture_gaps) ? coverage.capture_gaps.slice(0, 16) : [];
  const reasonKeys = new Set(backends.map(row => captureReasonKey(row.error)));
  const issues = [];
  if (coverage.rate_limited === true) issues.push('Capture rate limiting was reported.');
  if (num(coverage.dropped_events) > 0) issues.push(`Dropped events reported: ${format(coverage.dropped_events)}.`);
  for (const reason of [coverage.error, ...gaps]) {
    const key = captureReasonKey(reason);
    if (!key || reasonKeys.has(key) || reason === conntrackCaptureLimit) continue;
    reasonKeys.add(key);
    issues.push(reason);
  }
  const backendLabels = {conntrack: 'Conntrack', nflog: 'NFLOG', journal: 'Journal'};
  const backendEvidence = {conntrack: 'Accepted connections', nflog: 'Denied packets'};
  const statusLabels = {active: 'Active', unsupported: 'Unavailable', error: 'Error', off: 'Off'};
  const family = value => value === true ? 'supported' : value === false ? 'unavailable' : 'not reported';
  const reports = backends.map(row => `<li class="capture-backend">
    <div class="capture-backend-heading"><strong>${h(backendLabels[row.backend] || row.backend)}</strong>${backendEvidence[row.backend] ? `<span>${h(backendEvidence[row.backend])}</span>` : ''}<span class="capture-backend-status" data-active="${row.status === 'active'}">${h(statusLabels[row.status] || row.status || 'Unknown')}</span></div>
    <div class="capture-backend-metrics"><span>IPv4 ${family(row.ipv4)}</span><span>IPv6 ${family(row.ipv6)}</span><span>Reported lost events ${Number.isInteger(row.lost_events) && row.lost_events >= 0 ? format(row.lost_events) : 'unknown'}</span></div>
    ${row.error ? `<p class="capture-backend-error">${h(row.error)}</p>` : ''}
  </li>`).join('');
  return `<div class="capture-coverage">
    ${reports ? `<ul class="capture-backend-list">${reports}</ul>` : '<p class="help-text">Capture backend and loss are unknown.</p>'}
    ${issues.length ? `<ul class="capture-coverage-issues">${issues.map(reason => `<li>${h(reason)}</li>`).join('')}</ul>` : ''}
    ${gaps.includes(conntrackCaptureLimit) ? '<p class="capture-coverage-limit"><strong>General Conntrack limit.</strong> Connections can be missed during startup or when the kernel does not track a flow. Reported lost events count measured losses.</p>' : ''}
    <p class="capture-coverage-limit">Capture covers observed events. Application success requires a separate check.</p>
  </div>`;
}
function captureCoverageLimited(coverage={}){return !!coverage.error||coverage.rate_limited===true||num(coverage.dropped_events)>0||!!coverage.capture_gaps?.length||!coverage.capture_backends?.length||coverage.capture_backends.some(row=>row.status!=='active'||row.ipv4!==true||row.ipv6!==true||!Number.isInteger(row.lost_events)||row.lost_events>0);}
function trafficCaptureStatusHTML(page){
  const hosts=filteredServers().filter(server=>server.learning_coverage),issues=hosts.filter(server=>captureCoverageLimited(server.learning_coverage));
  const label=!hosts.length?'No reports yet':issues.length?'Limited':'Reported';
  const samples=issues.length?issues:hosts;
  const reports = samples.slice(0, 3).map(server => `<section class="traffic-coverage-endpoint">
    <div class="traffic-coverage-endpoint-heading"><strong>${h(server.hostname)}</strong>${server.learning_coverage.session_id ? `<span>Session ${h(server.learning_coverage.session_id)}</span>` : ''}</div>
    ${captureCoverageHTML(server.learning_coverage)}
  </section>`).join('');
  return `<details class="traffic-coverage ${!hosts.length||issues.length?'limited':''}" ${state.trafficCoverageOpen?'open':''}><summary>Capture coverage <strong>${label}</strong></summary>
    <div class="traffic-coverage-details">
      <p>Capture gaps can reduce counts.</p>
      ${reports}
      ${samples.length>3 ? `<p>See endpoint details for ${format(samples.length-3)} more capture reports.</p>` : ''}
      ${page ? `<p>${h(page.coverage || 'The table and export use all matching observations. The charts use the current page.')}</p>` : ''}
    </div>
  </details>`;
}
function learningHosts(scope,serverId) { return scope==='all'||serverId?state.data.servers:filteredServers(); }
function endpointPickerAddress(value){
  if(/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value)&&value.split('.').every(part=>Number(part)<=255))return value.split('.').map(Number).join('.');
  if(value.includes(':')&&/^[0-9a-f:.]+$/i.test(value)){try{return new URL(`https://[${value}]`).hostname;}catch{}}
  return '';
}
function endpointPickerMatches(servers,search='',location=''){
  const query=search.trim().toLowerCase(),exactAddress=endpointPickerAddress(query);
  return servers.filter(server=>{
    if(location&&server.location_id!==location)return false;
    const ips=server.ips || [];
    if(exactAddress)return ips.some(ip=>endpointPickerAddress(ip)===exactAddress);
    if(query.includes('='))return Object.entries(server.tags || {}).some(([key,value])=>`${key}=${value}`.toLowerCase()===query);
    return !query||[server.hostname,...ips].some(value=>String(value || '').toLowerCase().includes(query));
  });
}
function endpointPickerRows(name,servers,selected){
  const visible=servers.slice(0,100),visibleIds=new Set(visible.map(server=>server.id)),chosen=new Set(selected);
  const statusLabels = {healthy: 'Healthy', warning: 'Warning', offline: 'Offline', upgrade: 'Agent upgrade required'};
  const rows = visible.map(server => {
    const needsUpgrade = name === 'server_ids' && !(server.capabilities || []).includes('traffic_capture_v1');
    const status = needsUpgrade ? 'upgrade' : server.status;
    const label = Object.hasOwn(statusLabels, status) ? statusLabels[status] : 'Unknown';
    return `<label class="endpoint-picker-row">
      <input type="checkbox" name="${h(name)}" value="${h(server.id)}" ${chosen.has(server.id) ? 'checked' : ''}>
      <span class="endpoint-picker-identity">
        <strong>${h(server.hostname || server.id)}</strong>
        <small>${h((server.ips || []).join(', ') || 'Address unavailable')}</small>
      </span>
      <span class="endpoint-picker-status" data-status="${h(status)}">${label}</span>
    </label>`;
  }).join('');
  const hidden=[...chosen].filter(id=>!visibleIds.has(id)).map(id=>`<input type="hidden" name="${h(name)}" value="${h(id)}">`).join('');
  return (rows||'<p class="endpoint-picker-empty">No enrolled endpoints match.</p>')+hidden;
}
function endpointPickerHTML(id,name,servers,selected=[],{location=false,bulk=false}={}){
  const chosen = new Set(selected);
  return `<fieldset class="field endpoint-picker" id="${h(id)}" data-endpoint-picker data-field-name="${h(name)}">
    <legend>Enrolled endpoints</legend>
    <div class="field"><label for="${h(id)}-search">Find by IP address, hostname${location?' or tag (key=value)':''}</label>
      <input type="search" id="${h(id)}-search" data-endpoint-search placeholder="${location?'IP, hostname or application=billing':'IP address or hostname'}" autocomplete="off"></div>
    ${location?`<div class="field"><label for="${h(id)}-location">Saved location</label><select id="${h(id)}-location" data-endpoint-location>${savedLocationOptions('',true)}</select></div>`:''}
    <div class="endpoint-picker-toolbar">
      <span data-endpoint-count aria-live="polite">${format(chosen.size)} selected · ${format(servers.length)} matching${servers.length>100?' · first 100 shown':''}</span>
      <div class="endpoint-picker-actions" role="group" aria-label="Endpoint selection">
        ${bulk ? `<button type="button" class="button secondary small" data-action="endpoint-picker-select" ${servers.every(server => chosen.has(server.id)) ? 'disabled' : ''}>Select all matching</button>` : ''}
        <button type="button" class="button secondary small" data-action="endpoint-picker-clear" ${chosen.size ? '' : 'disabled'}>Clear selection</button>
      </div>
    </div>
    <div class="host-checklist" data-endpoint-results>${endpointPickerRows(name,servers,selected)}</div>
  </fieldset>`;
}
function endpointPickerRefresh(picker,action=''){
  const form=picker.closest('form'),name=picker.dataset.fieldName;
  const servers=form.id==='learning-form'?learningHosts($('[name="scope"]',form).value,form.dataset.serverId):state.data.servers;
  const matches=endpointPickerMatches(servers,$('[data-endpoint-search]',picker).value,$('[data-endpoint-location]',picker)?.value);
  const selected = new Set(action === 'clear' ? [] : new FormData(form).getAll(name));
  if (action === 'select') for (const server of matches) selected.add(server.id);
  $('[data-endpoint-count]',picker).textContent=`${format(selected.size)} selected · ${format(matches.length)} matching${matches.length>100?' · first 100 shown':''}`;
  const select = $('[data-action="endpoint-picker-select"]', picker);
  if (select) select.disabled = matches.every(server => selected.has(server.id));
  $('[data-action="endpoint-picker-clear"]', picker).disabled = !selected.size;
  if(action!=='count')$('[data-endpoint-results]',picker).innerHTML=endpointPickerRows(name,matches,selected);
  if(form.id==='learning-form'&&['count','select','clear'].includes(action))refreshLearningPreview();
  if(form.id==='policy-form')updatePolicyTargets();
}
function endpointPickerAction(button){
  const picker=button.closest('[data-endpoint-picker]');
  if(picker)endpointPickerRefresh(picker,button.dataset.action==='endpoint-picker-select'?'select':'clear');
}
function endpointPickerInput(target){
  const picker=target.closest?.('[data-endpoint-picker]');
  if(!picker)return false;
  if(target.matches('[data-endpoint-search],[data-endpoint-location]'))endpointPickerRefresh(picker);
  else if(target.name===picker.dataset.fieldName)endpointPickerRefresh(picker,'count');
  else return false;
  return true;
}
function showLearning(serverId,{purpose=''}={}) {
  if(!canWrite())return;
  const scope=serverId?'all':'filtered',matching=filteredServers(),discover=purpose==='traffic',automatic=purpose==='automatic';
  showModal(discover?'Discover traffic':automatic?'Discover policy':'Start a learning session',`<form id="learning-form" data-server-id="${h(serverId || '')}"><div class="modal-body">${errorSlot}<div class="inline-notice">${discover?'Collect inbound connection metadata from selected endpoints for a fixed period. Agents freshly discover network listeners and record source IPs, ports and timestamps. Access rules are unchanged.':automatic?'Automatically allow observed sources on eligible, unprotected network services. Review the selected endpoints, ports and capture kinds before starting.':'Observe inbound sources temporarily. Each selected agent runs a fresh service scan and freezes its own network listener ports. Loopback-only listeners are excluded.'}</div><div class="field"><label for="learning-scope">Endpoint scope</label><select id="learning-scope" name="scope"><option value="filtered" ${scope==='filtered'?'selected':''}>Current filters · ${matching.length} matching endpoints</option><option value="all" ${scope==='all'?'selected':''}>Entire fleet · ${state.data.servers.length} endpoints</option></select><small>Choose endpoints explicitly below. Opening this dialog does not select the entire scope.</small></div>${endpointPickerHTML('learning-endpoints','server_ids',learningHosts(scope,serverId),serverId?[serverId]:[],{location:true,bulk:true})}<div class="field"><label for="learning-mode">Services to observe</label><select id="learning-mode" name="selection_mode"><option value="discovered" selected>Auto-detect running services</option>${discover||automatic?'':'<option value="manual">Choose exact ports manually</option>'}</select><small>Requires learning discovery support (agent 0.3.0 or later). Offline agents start when they reconnect.</small></div><section id="learning-auto-fields"><label class="host-check learning-port-filter-toggle"><input type="checkbox" id="learning-port-filter-enabled" name="port_filter_enabled">Limit learning to selected ports</label><div id="learning-port-filter-fields" hidden><div class="field"><label for="learning-filter-service-group">Copy ports from a service group (optional)</label><select id="learning-filter-service-group" name="filter_service_group" disabled><option value="">Enter selected ports below</option>${(state.data.service_groups || []).map(group=>`<option value="${h(group.id)}">${h(group.name)} · r${num(group.revision)}</option>`).join('')}</select></div><div class="field"><label for="learning-port-filter">Only learn these exact ports</label><input id="learning-port-filter" name="port_filter" value="" placeholder="443/tcp" disabled><small>Enter 1–100 exact port/protocol pairs, separated by commas. Each server is freshly scanned; only matching network listeners are learned. Other discovered services remain visible in inventory.</small></div></div><div class="learning-preview-heading"><h3>Selected server listener preview</h3><button class="text-button" type="button" data-action="learning-refresh-preview">Refresh cached preview</button></div><p class="help-text">Cached inventory only. Without a port limit, all freshly discovered network listeners are learned. A fresh scan is requested when you start learning. Each host's scope is frozen separately after its scan.</p><div id="learning-preview" aria-live="polite"><p class="help-text">Select endpoints to preview their cached network listeners.</p></div></section><div id="learning-manual-fields" hidden><div class="field"><label for="learning-service-group">Use a service group (optional)</label><select id="learning-service-group" name="manual_service_group"><option value="">Enter ports below</option>${(state.data.service_groups || []).map(group=>`<option value="${h(group.id)}">${h(group.name)} · r${num(group.revision)}</option>`).join('')}</select><small>Copies this revision's exact ports into the session. Later catalogue edits do not change a running session.</small></div><div class="field"><label for="learning-ports">Exact ports to observe</label><input id="learning-ports" name="ports" value="" placeholder="8443/tcp, 53/udp"><small>Applies the same explicitly selected ports to all checked endpoints. Enter 1–100 TCP or UDP port/protocol pairs.</small></div></div>${captureKindFields()}${discover?trafficCollectionFields():''}${discover?'<input type="hidden" name="purpose" value="traffic"><input type="hidden" name="policy_action" value="observe">':automatic?'<input type="hidden" name="policy_action" value="auto_allow">':`<div class="field"><label for="learning-policy-action">Policy behavior</label><select id="learning-policy-action" name="policy_action"><option value="observe" selected>Observe and recommend · review before applying</option><option value="auto_allow">Auto-allow observed sources on the services they hit</option></select><small>Observe mode keeps access policies unchanged. Automatic allowances create visible learned policies and add exact source IP allowances while this session runs.</small></div>`}<div id="learning-auto-allow-confirmation" ${automatic?'':'hidden'}><div class="inline-notice warning">Automatic allowances include the selected observation kinds. Denied first-hits and scanners can become allowed sources when denied-packet capture is selected; observing them is not proof of trust. Requires automatic service discovery, agent 0.4.0 with automatic allowance support, and endpoint enforcement and learning allowances enabled. Incomplete endpoint guards are shown as blocked. An agent verification report is required before an allowance is shown as applied.</div><label class="host-check"><input type="checkbox" id="learning-auto-allow-confirmed" name="auto_allow_confirmed" ${automatic?'required':''}>Automatically allow observed source IPs on the ports they hit; this can include unwanted clients</label></div><div class="field-row"><div class="field"><label for="learning-duration">Duration</label><input id="learning-duration" name="duration" type="number" min="1" max="${discover?720:168}" value="1" required></div><div class="field"><label for="learning-unit">Unit</label><select id="learning-unit" name="unit"><option value="3600">Hours</option><option value="60">Minutes</option><option value="86400">Days</option></select></div></div><small class="help-text">Choose 1 minute to ${discover?'30':'7'} days. Agents stop collection at expiry.</small></div>${modalFooter(discover?'Start traffic discovery':automatic?'Start automatic allowances':'Start learning')}</form>`,discover?'METADATA ONLY':'TEMPORARY COLLECTION');
  if(serverId)refreshLearningPreview();
}
let learningPreviewSequence=0;
async function refreshLearningPreview() {
  const form=$('#learning-form');if(!form||!canWrite())return;const selected=new FormData(form).getAll('server_ids'),sequence=++learningPreviewSequence,identity=accessIdentityKey();
  if(!selected.length){$('#learning-preview').innerHTML='<p class="help-text">Select endpoints to preview their cached network listeners.</p>';return;}
  $('#learning-preview').innerHTML='<p class="help-text">Loading cached network listener preview…</p>';
  try {
    const values=new FormData(form),purpose=values.get('purpose'),port_filter=String(values.get('selection_mode') || 'discovered')==='discovered'?learningPortFilter(values):[];
    const mode=purpose==='traffic'?trafficCollectionMode(values):null;
    const result=await api('/learning/preview',{method:'POST',body:{server_ids:selected.slice(0,50),...(mode?{purpose,traffic_collection_mode:mode}:{}),...(port_filter.length?{port_filter}:{})}});
    if(sequence!==learningPreviewSequence||$('#learning-form')!==form||identity!==accessIdentityKey())return;
    $('#learning-preview').innerHTML=`${port_filter.length?`<div class="inline-notice">Only ${portList(port_filter)} will be learned or automatically allowed. Each selected server must have a matching network listener after its fresh scan.</div>`:'<p class="help-text">Scope: all freshly discovered network listeners on each selected server.</p>'}<p class="help-text">${h(result.message || 'Cached preview. Start learning requests a fresh scan on every selected endpoint.')}</p>${selected.length>50?'<p class="help-text">Cached listeners are shown for the first 50 selected endpoints. The session will include the full selection.</p>':''}<div class="learning-host-previews">${(result.servers || []).map(server=>{const ports=(server.ports || []).filter(port=>!port_filter.length||port_filter.some(selected=>selected.port===port.port&&selected.protocol===port.protocol)),unsupported=server.supported===false||(mode==='sampled'&&server.sampling_supported===false);return `<article class="learning-host-preview"><div><strong>${h(server.hostname || server.server_id)}</strong>${badge(unsupported?'Upgrade agent':server.offline?'Offline · awaiting connection':'Fresh scan pending',unsupported||server.offline?'warning':'neutral')}</div><div class="service-pills">${serviceGroupPortsHTML(ports) || `<span class="help-text">${port_filter.length?'No selected network listeners in cached inventory':'No cached network listeners'}</span>`}</div><small>Cached preview · ${ports.length} distinct ${port_filter.length?'selected ':''}network services · Last discovery: ${h(timestamp(server.last_discovery_at))}${server.synthetic?' · Synthetic demo':''}</small></article>`;}).join('')}</div>`;
  }catch(error){if(sequence===learningPreviewSequence&&$('#learning-form')===form&&identity===accessIdentityKey())$('#learning-preview').innerHTML=`<p class="form-error">${h(error.message)}</p>`;}
}
function learningPortFilter(values) {
  if(!['on','true',true].includes(values.get('port_filter_enabled')))return [];
  let ports;try{ports=parsePorts(String(values.get('port_filter') || ''));}catch{throw new Error('Enter exact port/protocol pairs for the learning limit, such as 443/tcp. Ranges are not supported.');}
  if(!ports.length||ports.length>100)throw new Error('Enter between 1 and 100 exact ports for the learning limit, such as 443/tcp.');
  return ports;
}
function updateLearningPortFilterFields() {
  const enabled=$('#learning-port-filter-enabled')?.checked===true,automatic=$('#learning-mode')?.value!=='manual';
  $('#learning-port-filter-fields').hidden=!enabled;$('#learning-port-filter').required=enabled&&automatic;$('#learning-port-filter').disabled=!enabled||!automatic;$('#learning-filter-service-group').disabled=!enabled||!automatic;
}
function learningChange(event) {
  if(event.target.name==='traffic_hit_count'){refreshLearningPreview();return true;}
  if(event.target.id==='learning-unit'){const form=$('#learning-form'),maxDays=$('[name="purpose"]',form)?.value==='traffic'?30:7;$('#learning-duration').max=String(maxDays*86400/Number(event.target.value));return true;}
  if(event.target.id==='learning-port-filter-enabled'){updateLearningPortFilterFields();refreshLearningPreview();return true;}
  if(event.target.id==='learning-port-filter'){refreshLearningPreview();return true;}
  if(event.target.id==='learning-filter-service-group'){const group=serviceGroupById(event.target.value);$('#learning-port-filter').value=group?portList(group.ports):'';refreshLearningPreview();return true;}
  if(event.target.id==='learning-policy-action'){const automatic=event.target.value==='auto_allow';$('#learning-auto-allow-confirmation').hidden=!automatic;$('#learning-auto-allow-confirmed').required=automatic;if(automatic){$('#learning-mode').value='discovered';$('#learning-auto-fields').hidden=false;$('#learning-manual-fields').hidden=true;$('#learning-ports').required=false;updateLearningPortFilterFields();}return true;}
  if(event.target.id==='learning-scope'){endpointPickerRefresh($('#learning-endpoints'),'clear');return true;}
  if(event.target.id==='learning-mode'){const manual=event.target.value==='manual';if(manual&&$('#learning-policy-action')?.value==='auto_allow'){event.target.value='discovered';toast('Automatic allowances require automatic per-server service discovery.',true);return true;}$('#learning-manual-fields').hidden=!manual;$('#learning-auto-fields').hidden=manual;$('#learning-ports').required=manual;updateLearningPortFilterFields();return true;}
  if(event.target.id==='learning-service-group'){const group=serviceGroupById(event.target.value);$('#learning-ports').value=group?portList(group.ports):'';return true;}
  return false;
}
function learningPayload(values) {
  const server_ids=values.getAll('server_ids');if(!server_ids.length)throw new Error('Select at least one endpoint.');
  const selection_mode=String(values.get('selection_mode') || 'discovered'),duration_seconds=Number(values.get('duration'))*Number(values.get('unit'));
  const purpose=String(values.get('purpose') || ''),discover=purpose==='traffic';
  const policy_action=String(values.get('policy_action') || 'observe');
  if(!Number.isInteger(duration_seconds)||duration_seconds<60||duration_seconds>(discover?2592000:604800))throw new Error(`Choose a duration between 1 minute and ${discover?'30':'7'} days.`);
  if(!['observe','auto_allow'].includes(policy_action))throw new Error('Choose observe and recommend or automatic allowances.');
  if(discover&&(selection_mode!=='discovered'||policy_action!=='observe'))throw new Error('Traffic discovery only observes freshly discovered network listeners.');
  const body={server_ids,selection_mode,duration_seconds,policy_action,...(discover?{purpose}:{})},kinds=captureKindsPayload(values);if(kinds)body.observation_kinds=kinds;
  if(discover)body.traffic_collection_mode=trafficCollectionMode(values);
  if(policy_action==='auto_allow'){if(selection_mode!=='discovered')throw new Error('Automatic allowances require automatic per-server service discovery.');if(!['on','true',true].includes(values.get('auto_allow_confirmed')))throw new Error('Confirm that automatic allowances can include unwanted clients.');body.auto_allow_confirmed=true;}
  if(selection_mode==='manual'){body.ports=parsePorts(String(values.get('ports') || ''));if(!body.ports.length||body.ports.length>100)throw new Error('Enter between 1 and 100 exact ports to observe.');}
  else if(selection_mode==='discovered'){const port_filter=learningPortFilter(values);if(port_filter.length)body.port_filter=port_filter;}
  else throw new Error('Choose automatic discovery or manual ports.');
  return body;
}
async function learningSubmit(event) {
  event.preventDefault();const form=event.target,submit=$('button[type="submit"]',form),identity=accessIdentityKey();submit.disabled=true;
  try {
    if(!canWrite())throw new Error('Read Only access cannot start learning.');const body=learningPayload(new FormData(form));
    {const unsupported=state.data.servers.filter(server=>body.server_ids.includes(server.id)&&!(server.capabilities || []).includes('traffic_capture_v1'));if(unsupported.length)throw new Error('New capture scopes require agent upgrade to traffic_capture_v1: '+unsupported.map(server=>server.hostname).join(', '));}
    if(body.traffic_collection_mode==='sampled'){
      const unsupported=state.data.servers.filter(server=>body.server_ids.includes(server.id)&&!(server.capabilities || []).includes('traffic_minute_sampling_v1'));
      if(unsupported.length)throw new Error('Communication sampling requires updated agents: '+unsupported.slice(0,20).map(server=>server.hostname).join(', '));
    }
    if(body.duration_seconds>604800){
      const unsupported=state.data.servers.filter(server=>body.server_ids.includes(server.id)&&!(server.capabilities || []).includes('traffic_discovery_30d_v1'));
      if(unsupported.length)throw new Error('Traffic discovery longer than seven days requires updated agents: '+unsupported.slice(0,20).map(server=>server.hostname).join(', '));
    }
    if(body.selection_mode==='discovered'){const unsupported=state.data.servers.filter(server=>body.server_ids.includes(server.id)&&!(server.capabilities || []).includes('learning_discovery_v1'));if(unsupported.length)throw new Error('Upgrade agents to 0.3.0 or later, or choose manual ports: '+unsupported.map(server=>server.hostname).join(', '));}
    if(body.policy_action==='auto_allow'){const unsupported=state.data.servers.filter(server=>body.server_ids.includes(server.id)&&!(server.capabilities || []).includes('learning_auto_allow_v1'));if(unsupported.length)throw new Error('Automatic allowances require agent 0.4.0 with learning_auto_allow_v1 support: '+unsupported.map(server=>server.hostname).join(', '));}
    await api('/learning',{method:'POST',body});
    if(identity!==accessIdentityKey()||$('#learning-form')!==form)return;
    if(body.purpose==='traffic')state.learningHistoryPurpose='traffic';
    closeModal();await load();
    if(body.purpose==='traffic'&&state.view==='traffic'&&state.trafficLearningSessionsOpen)await loadTrafficLearningHistory({quiet:true});
    toast(body.purpose==='traffic'?'Traffic discovery requested. Collection starts after each endpoint reports its fresh listener scan.':body.policy_action==='auto_allow'?'Automatic source allowances enabled for this session. Learned policies appear as observations arrive; endpoint guards determine application.':body.selection_mode==='discovered'?'Fresh discovery requested on selected endpoints. Collection waits for each server’s own scan.':'Manual learning requested. Collection starts when each agent syncs.');
  }catch(error){if(identity===accessIdentityKey()&&$('#learning-form')===form)formError(error);}finally{submit.disabled=false;}
}
function learningHostSessionHTML(session,server,assigned=true) {
  const automatic=session.selection_mode==='discovered',result=session.discovery_results?.[server.id] || {},pending=session.discovery_pending_server_ids?.includes(server.id),ports=automatic?session.server_ports?.[server.id] || []:session.ports || [],offline=server.status==='offline',capabilities=server.capabilities || [];
  const unsupported=(automatic&&!capabilities.includes('learning_discovery_v1'))||(session.traffic_collection_mode==='sampled'&&!capabilities.includes('traffic_minute_sampling_v1'));
  const noListenersLabel=session.port_filter?.length?'No selected network listeners':'No network listeners';
  const label=!assigned?(automatic&&result.status==='ready'?'Ended · snapshot ready':automatic&&result.status==='no_listeners'?'Ended · '+noListenersLabel.toLowerCase():automatic&&pending?'Ended · discovery incomplete':'Ended'):unsupported?'Upgrade agent':offline?'Offline':result.status==='error'?'Discovery error':pending?'Fresh discovery pending':automatic&&result.status==='no_listeners'?noListenersLabel:F.isCollecting(server)?'Collecting':automatic&&result.status==='ready'?'Ready · awaiting collector':'Awaiting agent';
  return `<div class="learning-session-host"><strong>${h(server.hostname)}</strong><span>${h(label)}</span><small>${portList(ports) || (pending?'Ports freeze after fresh scan':'No ports selected')}${result.error?' · '+h(result.error):''}${result.discovered_at?' · Scanned '+h(timestamp(result.discovered_at)):''}</small></div>`;
}
function learningPageCache(){
  const identity=accessIdentityKey();
  if(state.learningSessionIdentity!==identity){
    state.learningSessionIdentity=identity;
    state.learningSessionPages=new Map();
  }
  return state.learningSessionPages;
}
function learningPageKey(serverId,purpose=''){return serverId?'server:'+serverId:purpose?'fleet:'+purpose:'fleet';}
function learningSetPage(key,page){const cache=learningPageCache();cache.delete(key);cache.set(key,page);for(const candidate of [...cache.keys()]){if(cache.size<=6)break;if(candidate!=='fleet'&&candidate!==key)cache.delete(candidate);}}
function learningPageRecord(items,meta){
  if(!Array.isArray(items)||!meta||!Number.isInteger(meta.total)||meta.total<0||!Number.isInteger(meta.offset)||meta.offset<0||!Number.isInteger(meta.limit)||meta.limit<1||meta.limit>20||items.length>20)throw new Error('The controller did not return a complete bounded session page.');
  return {...meta,items,remote:true,loading:false,error:''};
}
function learningReceiveOverview(result){
  if(!result.learning_session_pagination)return;const cache=learningPageCache(),current=cache.get('fleet');
  if(!current||!current.offset&&!current.loading)learningSetPage('fleet',learningPageRecord(result.learning_sessions || [],result.learning_session_pagination));
}
function learningReceiveServer(server){
  if(!server?.learning_session_pagination)return;const key=learningPageKey(server.id),cache=learningPageCache(),current=cache.get(key);
  if(!current)learningSetPage(key,learningPageRecord(server.learning_sessions || [],server.learning_session_pagination));
}
function learningSessionPage(serverId,purpose=''){
  const cached=learningPageCache().get(learningPageKey(serverId,purpose));if(cached)return cached;
  if(purpose)return {items:[],total:null,offset:0,limit:6,remote:true,unloaded:true,error:''};
  const items=(state.data?.learning_sessions || []).filter(session=>!serverId||session.server_ids?.includes(serverId)).sort((a,b)=>(date(b.starts_at)||0)-(date(a.starts_at)||0));
  const remote=!!state.data?.learning_session_pagination;
  return {items:remote&&serverId?[]:items,total:remote&&serverId?null:items.length,offset:0,limit:6,has_more:false,remote,unloaded:remote&&!!serverId,error:''};
}
const trafficLearningHistoryLimit=20;
function trafficLearningHistoryPage(purpose=state.learningHistoryPurpose || ''){
  return learningPageCache().get('traffic-history:'+purpose) || {items:[],unloaded:true};
}
function loadTrafficLearningHistory({quiet=false}={}){
  const purpose=state.learningHistoryPurpose || '';
  if(!trafficLearningHistoryPage(purpose).loading)return loadLearningSessionPage(undefined,0,purpose,{quiet,traffic:true});
}
let learningSessionRequestSequence=0;
async function loadLearningSessionPage(serverId,offset=0,purpose='',{quiet=false,traffic=false}={}){
  if(!Number.isSafeInteger(offset)||offset<0)return;const key=traffic?'traffic-history:'+purpose:learningPageKey(serverId,purpose),cache=learningPageCache(),previous=traffic?trafficLearningHistoryPage(purpose):learningSessionPage(serverId,purpose),sequence=++learningSessionRequestSequence;
  learningSetPage(key,{...previous,loading:true,error:'',sequence});if(!quiet)learningRedraw(serverId);
  try{const response=await api('/learning?limit='+(traffic?trafficLearningHistoryLimit:6)+'&offset='+offset+(serverId?'&server_id='+encodeURIComponent(serverId):'')+(purpose?'&purpose='+encodeURIComponent(purpose):''));if(learningPageCache()!==cache||cache.get(key)?.sequence!==sequence)return;learningSetPage(key,learningPageRecord(response.items,response));}
  catch(error){if(learningPageCache()===cache&&cache.get(key)?.sequence===sequence)learningSetPage(key,{...previous,loading:false,error:'Session history unavailable: '+error.message});}
  learningRedraw(serverId);
}
function learningRedraw(serverId){
  if(serverId){
    if(state.detail===serverId&&state.detailData)renderServerDrawer(state.detailData);
    return;
  }
  if(!['overview','traffic'].includes(state.view)||$('#modal').open)return;
  const active=document.activeElement,restoreFocus=['traffic-history-purpose','traffic-learning-sessions-toggle'].includes(active?.id);
  if(!restoreFocus&&active?.matches('input,select,textarea'))return;
  render();
  if(restoreFocus)document.getElementById(active.id)?.focus();
}
function learningSessionPaginationHTML(page,serverId,purpose=''){
  const count=page.remote?page.items.length:Math.min(page.items.length,state.learningSessionLimit || 6),total=page.total,offset=page.offset || 0;
  return `<div class="recommendation-pagination"><span>${total===null?'Session history not loaded':`Loaded ${format(count)} · ${count?offset+1:0}–${count?offset+count:0} of ${format(total)} sessions`}${page.loading?' · Loading…':''}</span><div>${page.unloaded?`<button class="button secondary small" data-action="learning-session-page" data-server-id="${h(serverId || '')}" data-purpose="${h(purpose)}" data-offset="0">Load session history</button>`:page.remote?`<button class="button secondary small" data-action="learning-session-page" data-server-id="${h(serverId || '')}" data-purpose="${h(purpose)}" data-offset="${Math.max(0,offset-page.limit)}" ${!offset||page.loading?'disabled':''}>Previous sessions</button><button class="button secondary small" data-action="learning-session-page" data-server-id="${h(serverId || '')}" data-purpose="${h(purpose)}" data-offset="${offset+page.limit}" ${!page.has_more||page.loading?'disabled':''}>Next sessions</button>`:''}</div></div>${page.error?`<p class="form-error">${h(page.error)}</p>`:''}`;
}
function learningSessionCardHTML(session,serverId){
  const start=num(date(session.starts_at)?.getTime()),end=num(date(session.expires_at)?.getTime()),assigned=['active','learning'].includes(session.status)&&start<=Date.now()&&end>Date.now(),membership=new Set(session.server_ids || []),hosts=state.data.servers.filter(server=>membership.has(server.id)),pending=num(session.discovery_pending_count ?? session.discovery_pending_server_ids?.length),errors=num(session.discovery_error_count ?? Object.values(session.discovery_results || {}).filter(result=>result.status==='error').length),empty=num(session.discovery_no_listeners_count),hostCount=num(session.server_count ?? membership.size),summary=session.summary_only===true,collecting=hosts.filter(F.isCollecting).length,noListeners=summary?hostCount>0&&empty===hostCount:hosts.length&&hosts.every(server=>session.discovery_results?.[server.id]?.status==='no_listeners'),status=assigned?(errors?'Discovery error':pending?'Discovery pending':noListeners?(session.port_filter?.length?'No selected network listeners':'No network listeners'):summary?'Active assignment · inspect hosts':collecting?'Learning':'Awaiting agents'):humanize(session.status || 'Complete'),percent=Math.max(0,Math.min(100,(Date.now()-start)/Math.max(1,end-start)*100));
  const discover=session.purpose==='traffic';
  const scope=summary?`<p class="help-text">${pending?`${pending} awaiting fresh discovery · `:''}${errors?`${errors} discovery errors · `:''}Frozen ports and per-host state load separately.</p><button class="text-button" data-action="learning-host-scope" data-id="${h(session.id)}" data-server-id="${h(serverId || '')}">View endpoint scope and status</button>`:`<details class="learning-session-hosts"><summary>View each endpoint's scope and status</summary>${hosts.slice(0,50).map(server=>learningHostSessionHTML(session,server,assigned)).join('')}${hosts.length>50?'<p class="help-text">First 50 loaded endpoints shown.</p>':''}</details>`;
  return `<article class="learning-card ${assigned?'':'finished'}"><div class="learning-top"><div class="learning-name">${h(discover?'Traffic discovery · '+sessionTitle(session):sessionTitle(session))}</div>${badge(status,errors?'warning':assigned?'learning':'neutral')}</div><div class="learning-details">${session.selection_mode==='discovered'?(session.port_filter?.length?'Automatic · only '+portList(session.port_filter):'Automatic · all network listeners per host'):'Manual · '+portList(session.ports)} · ${format(hostCount)} endpoints${assigned&&!summary?` · ${collecting} confirmed collecting`:''}</div><p class="help-text learning-policy-behavior">${discover?(session.traffic_collection_mode==='sampled'?'Sampled communication · one per source and service per minute':'Observed hit counts'):session.policy_action==='auto_allow'?'Auto-allow observed sources · see learned policy application reports':'Observe and recommend · access changes require review'}</p>${initialLearningApprovalHTML(session)}${scope}<div class="learning-evidence-actions"><button class="text-button" data-action="recommendation-open" data-id="${h(session.id)}" data-purpose="${discover?'traffic':''}" data-server-id="${h(discover&&serverId?serverId:'')}">${discover?'View traffic observations':'Review observed access'}</button><button class="text-button" data-action="recommendation-export" data-id="${h(session.id)}" data-server-id="${h(serverId || '')}">Export ${serverId?'endpoint ':''}CSV</button></div><div class="learning-progress"><span style="width:${percent.toFixed(1)}%"></span></div><div class="learning-bottom"><span>${assigned?`${Math.ceil(Math.max(0,end-Date.now())/60000)}m remaining`:`Ended ${timestamp(session.stopped_at || session.ended_at || session.expires_at)}`}</span>${assigned&&canWrite()?`<button class="text-button" data-action="stop-learning" data-id="${h(session.id)}">Stop learning</button>`:'<span>History retained</span>'}</div></article>`;
}
function trafficLearningHistoryHTML(){
  const purpose=state.learningHistoryPurpose || '',page=trafficLearningHistoryPage(purpose);
  const scopeIds=new Set(filteredServers().map(server=>server.id));
  const sessions=page.items.slice(0,trafficLearningHistoryLimit).filter(session=>session.server_ids?.some(id=>scopeIds.has(id)));
  return `<div class="field"><label for="traffic-history-purpose">Session type</label><select id="traffic-history-purpose"><option value="">All collection sessions</option><option value="traffic" ${purpose==='traffic'?'selected':''}>Traffic discovery only</option></select></div>
    <p class="help-text">Latest ${trafficLearningHistoryLimit} sessions, live and ended. Endpoint filters apply to this list.</p>
    ${page.error?`<p class="form-error" role="alert">${h(page.error)}</p><button class="text-button" type="button" data-action="traffic-learning-refresh">Retry</button>`:''}
    ${sessions.length?`<div class="learning-grid">${sessions.map(session=>learningSessionCardHTML(session)).join('')}</div>`:page.loading||page.unloaded&&!page.error?'<p class="help-text">Loading sessions…</p>':page.error?'':'<p class="help-text">No matching sessions in recent history.</p>'}`;
}
function learningHTML(){
  const open=state.trafficLearningSessionsOpen===true;
  return `<div class="section-line"><button id="traffic-learning-sessions-toggle" type="button" class="button secondary small" data-action="traffic-learning-sessions" aria-expanded="${open}" aria-controls="traffic-learning-sessions">${icon('learning')} Learning sessions</button></div>
    <section id="traffic-learning-sessions" aria-label="Learning sessions" ${open?'':'hidden'}>${open?trafficLearningHistoryHTML():''}</section>`;
}
function serverLearningSessionsHTML(server){
  const page=learningSessionPage(server.id),items=page.remote?page.items:page.items.slice(0,6);
  return `${learningSessionPaginationHTML(page,server.id)}${items.length?`<div class="learning-grid">${items.map(session=>learningSessionCardHTML(session,server.id)).join('')}</div>`:page.unloaded?'': '<p class="help-text">No learning sessions on this endpoint history page.</p>'}`;
}
let learningHostRequestSequence=0;
async function showLearningHostScope(sessionId,offset,serverId){
  const session=[...learningPageCache().values()].flatMap(page=>page.items || []).find(item=>item.id===sessionId)||(state.data.learning_sessions || []).find(item=>item.id===sessionId),sequence=++learningHostRequestSequence;
  if(offset===undefined){const position=serverId?session?.server_ids?.indexOf(serverId):-1;offset=position>=0?Math.floor(position/50)*50:0;}
  if(!Number.isSafeInteger(offset)||offset<0)return;
  state.learningHostView={sessionId,serverId,session,offset,sequence};showModal('Learning endpoint scope',`<div class="modal-body"><p class="help-text">Loading the exact frozen host scope…</p></div><div class="modal-footer"><button class="button secondary" data-action="close-modal">Close</button></div>`,'PAGED FROZEN SCOPE');
  try{const page=await api('/learning/'+encodeURIComponent(sessionId)+'/hosts?limit=50&offset='+offset);if(state.learningHostView?.sequence!==sequence||!$('#modal').open||$('#modal-title').textContent!=='Learning endpoint scope')return;if(page.session_id!==sessionId||!Array.isArray(page.items)||page.items.length>100||!Number.isInteger(page.total)||page.total<0||page.total>20000||!Number.isInteger(page.offset)||page.offset<0||!Number.isInteger(page.limit)||page.limit<1||page.limit>100||page.items.length>page.limit)throw new Error('The controller did not return a bounded host-scope page.');
    showModal('Learning endpoint scope',`<div class="modal-body"><p class="help-text">${h(sessionTitle(session || {}))} · Exact per-host frozen ports. This is discovery scope, not proof that traffic was collected or firewall allowances applied.</p>${page.items.map(row=>{const ready=row.status==='ready',pending=row.pending||row.status==='pending',empty=row.status==='no_listeners',label=pending?'Fresh discovery pending':row.status==='error'?'Discovery error':empty?(session?.port_filter?.length?'No selected network listeners':'No network listeners'):ready?'Frozen snapshot ready':row.status==='manual'?'Manual scope':'Snapshot not reported';return `<article class="learning-session-host"><strong>${h(serverName(row.server_id))}${row.server_id===serverId?' · Selected endpoint':''}</strong><span>${h(label)}</span><small>${h(portList(row.ports || []) || (pending?'Ports freeze after fresh scan':empty?'No matching listeners were frozen':'Frozen ports not reported'))}${row.error?' · '+h(row.error):''}${row.discovered_at?' · Scanned '+h(timestamp(row.discovered_at)):''}</small><button class="text-button" data-action="recommendation-export" data-id="${h(sessionId)}" data-server-id="${h(row.server_id)}">Export endpoint CSV</button></article>`;}).join('')||'<p class="help-text">No endpoints on this scope page.</p>'}<div class="recommendation-pagination"><span>Loaded ${page.items.length} · ${page.items.length?page.offset+1:0}–${page.items.length?page.offset+page.items.length:0} of ${format(page.total)} endpoints</span><div><button class="button secondary small" data-action="learning-host-page" data-id="${h(sessionId)}" data-server-id="${h(serverId || '')}" data-offset="${Math.max(0,page.offset-page.limit)}" ${!page.offset?'disabled':''}>Previous endpoints</button><button class="button secondary small" data-action="learning-host-page" data-id="${h(sessionId)}" data-server-id="${h(serverId || '')}" data-offset="${page.offset+page.limit}" ${!page.has_more?'disabled':''}>Next endpoints</button></div></div></div><div class="modal-footer"><button class="button secondary" data-action="close-modal">Close</button></div>`,'PAGED FROZEN SCOPE');
  }catch(error){if(state.learningHostView?.sequence!==sequence||!$('#modal').open||$('#modal-title').textContent!=='Learning endpoint scope')return;showModal('Learning endpoint scope',`<div class="modal-body"><p class="form-error">${h(error.message)}</p><p class="help-text">No empty or successful host scope was inferred from this failure.</p></div><div class="modal-footer"><button class="button secondary" data-action="close-modal">Close</button><button class="button secondary" data-action="learning-host-page" data-id="${h(sessionId)}" data-server-id="${h(serverId || '')}" data-offset="${offset}">Retry scope page</button></div>`,'SCOPE UNAVAILABLE');}
}
async function learningHistoryAction(button){
  const action=button.dataset.action,serverId=button.dataset.serverId || undefined;
  if(action==='traffic-learning-sessions'){
    if(state.view!=='traffic')return true;
    const open=state.trafficLearningSessionsOpen=!state.trafficLearningSessionsOpen;
    render();
    $('#traffic-learning-sessions-toggle')?.focus();
    if(open)await loadTrafficLearningHistory({quiet:true});
    return true;
  }
  if(action==='traffic-learning-refresh'){
    if(state.view==='traffic'&&state.trafficLearningSessionsOpen)await loadTrafficLearningHistory();
    return true;
  }
  if(action==='learning-session-page'){await loadLearningSessionPage(serverId,Number(button.dataset.offset),button.dataset.purpose || '');return true;}
  if(action==='learning-host-scope'){await showLearningHostScope(button.dataset.id,undefined,serverId);return true;}
  if(action==='learning-host-page'){await showLearningHostScope(button.dataset.id,Number(button.dataset.offset),serverId);return true;}
  return false;
}
