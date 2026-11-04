'use strict';

function appliance(){return state.platformAppliance || {};}
function controllerDisplayNameSettings() {
  return state.platformInfo?.runtime?.controller_id ? state.platformInfo.runtime : state.data?.meta || {};
}

function showControllerDisplayName() {
  const settings = controllerDisplayNameSettings();
  if (!canManagePlatform() || !settings.controller_id) return;
  showModal('Controller display name', `<form id="platform-controller-name-form" data-controller-id="${h(settings.controller_id)}">
    <div class="modal-body">${errorSlot}
      <div class="field">
        <label for="platform-controller-name">Display name</label>
        <input id="platform-controller-name" name="display_name" value="${h(settings.controller_display_name || '')}" maxlength="64" placeholder="Primary controller" autofocus>
        <small>This label appears in the workspace for this controller. Leave it blank to use the default.</small>
      </div>
    </div>
    ${modalFooter('Save display name')}
  </form>`, 'PLATFORM SETTINGS');
}

async function saveControllerDisplayName(event) {
  event.preventDefault();
  if (!canManagePlatform()) return;
  const form = event.target;
  const button = $('button[type="submit"]', form);
  const controllerId = form.dataset.controllerId;
  button.disabled = true;
  try {
    const result = await api('/platform/controller-name', {
      method: 'PUT',
      body: {controller_id: controllerId, display_name: String(new FormData(form).get('display_name') || '')}
    });
    if (state.platformInfo?.runtime?.controller_id === result.controller_id) {
      state.platformInfo.runtime.controller_display_name = result.display_name;
    }
    if (state.data?.meta?.controller_id === result.controller_id) {
      state.data.meta.controller_display_name = result.display_name;
    }
    if ($('#platform-controller-name-form') === form) closeModal();
    if (state.data) renderChrome();
    toast('Controller display name saved.');
  } catch (error) {
    if ($('#platform-controller-name-form') === form) formError(error);
    else toast(error.message, true);
  } finally {
    button.disabled = false;
  }
}

function applianceOperational(){return canManagePlatform()&&appliance().installed===true&&appliance().manager_available!==false&&state.platformInfo?.runtime?.demo!==true;}
function applianceDisabledNotice(){return applianceOperational()?'':`<div class="inline-notice">${state.platformInfo?.runtime?.demo===true?'Demo mode shows settings and reported health. Real cluster joining, storage moves and service restarts are disabled.':appliance().installed===true&&appliance().manager_available===false?(appliance().error || 'The installed appliance manager is unavailable. Service and storage operations remain blocked.'):'Managed operations require the appliance package and its node manager on this controller. Installation state has not been verified.'}</div>`;}
function applianceReplicationRotationHTML(){
  const cluster=appliance().cluster || {},rotation=cluster.replication_rotation;
  if(!rotation)return cluster.replication_password_pending===true?'<p class="inline-notice">The saved replication credential is pending setup. Its activation has not been confirmed.</p>':'';
  const phase=rotation.phase || 'unknown',voters=Array.isArray(rotation.voters)?rotation.voters:[],labels={prepare:'Prepare credentials','change-role':'Change database role',reload:'Reload replication',verify:'Verify every voter',finalize:'Finalize credentials',abort:'Cancellation requested',aborted:'Cancelled',completed:'Completed'},ackPhase=phase==='completed'?'finalize':phase==='aborted'?'abort':phase,acks=rotation.acks?.[ackPhase] || {},required=phase==='change-role'?1:Math.max(3,voters.length),expected=phase==='change-role'?[rotation.primary_id].filter(Boolean):voters.map(voter=>voter.id),ackCount=expected.filter(id=>typeof acks[id]==='string'&&acks[id]).length,completed=phase==='completed',aborted=phase==='aborted',cancelRequested=phase==='abort',canCancel=canManagePlatform()&&rotation.can_abort===true&&!cancelRequested&&!completed&&!aborted;
  return `<section class="appliance-replication-rotation" aria-label="Replication password rotation"><div class="section-line"><h3>Replication password rotation</h3>${badge(labels[phase] || humanize(phase),completed?'':aborted?'neutral':'warning')}</div><p class="help-text">${completed?'The controller reports the new replication password active after verification.':aborted?'Cancellation completed. The previous replication credential was retained.':cancelRequested?'Cancellation is requested. It is complete only after every voter acknowledges cleanup.':'The new credential is pending. Activation has not been confirmed across all voters.'}</p><div class="appliance-rotation-progress"><progress max="${required}" value="${Math.min(required,ackCount)}" aria-label="${h(labels[ackPhase] || humanize(ackPhase))} acknowledgements"></progress><span>${ackCount} of ${required} ${phase==='change-role'?'primary':'voters'} acknowledged ${h(labels[ackPhase] || humanize(ackPhase))}</span><small>${h(timestamp(rotation.updated_at || rotation.completed_at))}</small></div>${Object.entries(rotation.errors || {}).map(([id,error])=>`<p class="form-error">${h(voters.find(voter=>voter.id===id)?.site || id)}: ${h(typeof error==='string'?error:'Voter verification is pending')}</p>`).join('')}${canCancel?`<button type="button" class="text-button danger-text" data-action="platform-appliance-replication-abort" ${appliance().installed!==true||state.platformInfo?.runtime?.demo===true?'disabled':''}>Cancel pending rotation</button>`:!completed&&!aborted&&!cancelRequested&&rotation.role_change_intent===true?'<p class="help-text">The database role change has begun. This rotation must recover forward; cancellation is unavailable.</p>':''}</section>`;
}
function applianceRoutingHTML(){
  const routing=appliance().routing || {};
  const pools=(routing.pools || []).map(pool=>Array.isArray(pool)?{site:pool[1],health:'unknown'}:pool);
  return `<section class="card platform-panel"><div class="section-line"><h2>Site routing</h2>${badge(routing.failover_state?humanize(routing.failover_state):'Not reported','neutral')}</div>
    ${pools.length?`<div class="appliance-route-pools">${pools.map(pool=>`<article><strong>${h(pool.site)}-local pool</strong><span>${h(pool.url?platformUI.connectionLabel(pool.url):'Pool address not reported')}</span>${platformHealthBadge(pool.health)}${pool.role?`<small>${h(humanize(pool.role))}</small>`:''}</article>`).join('')}</div>`:'<p class="help-text">No site routing pools have been reported.</p>'}
  </section>`;
}
function platformApplianceOverviewHTML(){
  const info=appliance(),identity=info.identity || {},platformCluster=state.platformInfo?.cluster || {};
  const cluster=info.cluster || {},nodes=cluster.nodes || platformCluster.nodes || [],runtime=state.platformInfo?.runtime || {};
  const display=controllerDisplayNameSettings(),controllerId=identity.id || runtime.controller_id || platformCluster.controller_id;
  const node=nodes.find(member=>member.id===controllerId);
  const mode=runtime.demo===true?'Demo':runtime.ha===true?'High availability':runtime.ha===false?'Standalone':platformCluster.mode?humanize(platformCluster.mode):'Not reported';
  const clusterState=cluster.configured===true?(cluster.name || 'Connected'):cluster.settings_saved===true?'Settings saved':cluster.configured===false?'Not connected':'Not reported';
  const nodeDetails=[identity.site || runtime.site || platformCluster.site,identity.ip,node?.role?humanize(node.role):''].filter(Boolean);
  const blockers=(info.blockers || []).filter(reason=>typeof reason==='string'&&reason);
  const services=info.services || [];
  return `${state.platformApplianceError?`<div class="inline-notice warning">${h(state.platformApplianceError)}</div>`:''}
    <div class="platform-overview-cards">
      <article class="card platform-metric"><span>This controller</span><strong>${h(display.controller_display_name || controllerId || 'Not reported')}</strong><p>${nodeDetails.map(h).join(' · ') || 'Site and role not reported'}</p></article>
      <article class="card platform-metric"><span>Deployment mode</span><strong>${h(mode)}</strong><p>${h(({sqlite:'SQLite',postgresql:'PostgreSQL'})[runtime.storage] || 'Database not reported')}</p>${info.data_root?`<p>Data location <code class="appliance-data-root">${h(info.data_root)}</code></p>`:''}</article>
      <article class="card platform-metric"><span>Cluster</span><strong>${h(clusterState)}</strong><p>${h(cluster.replication_state?`Replication: ${humanize(cluster.replication_state)}`:'Replication state not reported')}</p></article>
    </div>
    ${blockers.length?`<section class="card platform-panel"><h2>Needs attention</h2><ul>${blockers.map(reason=>`<li>${h(reason)}</li>`).join('')}</ul></section>`:''}
    <section class="card platform-panel"><div class="section-line"><h2>Controller nodes<span>${nodes.length} reported</span></h2><button class="text-button" data-action="platform-refresh">Refresh health</button></div>
      <div class="table-scroll"><table><thead><tr><th>Controller</th><th>Site</th><th>Reported health</th><th>Last heartbeat</th></tr></thead>
      <tbody>${nodes.map(node=>`<tr><td><strong>${h(node.id || node.name)}</strong></td><td>${h(node.site || 'Not reported')}</td><td>${platformHealthBadge(node.health ?? node.ready ?? node.status ?? node.state)}</td><td>${h(timestamp(node.last_seen))}</td></tr>`).join('') || '<tr><td colspan="4">No controller health has been reported.</td></tr>'}</tbody></table></div>
    </section>
    ${services.length||info.installed===true?`<section class="card platform-panel"><h2>Appliance service health</h2><dl class="detail-grid">${services.map(service=>`<div><dt>${h(service.name || service.id)}</dt><dd>${applianceServiceBadge(service)}</dd></div>`).join('')}${info.installed===true?`<div><dt>Appliance node manager</dt><dd>${applianceManagerBadge(info)}</dd></div>`:''}</dl></section>`:''}
    ${!canManagePlatform()?'<div class="inline-notice">Your role can view platform health. Super Admins manage platform settings.</div>':''}`;
}
function platformApplianceClusterHTML(){
  const info=appliance(),identity=info.identity || {},cluster=info.cluster || {},routing=info.routing || {},join=state.platformApplianceClusterMode==='join';
  return `${applianceDisabledNotice()}<section class="card platform-panel"><div class="platform-panel-heading"><span class="platform-feature-icon">${icon('cloud')}</span><div><h2>Cluster</h2><p>The same appliance package runs the controller and database stack at each site. Add management controllers through the same join workflow.</p></div></div><div class="platform-choice-tabs"><button class="button ${!join?'primary':'secondary'} small" data-action="platform-appliance-create">Cluster settings</button><button class="button ${join?'primary':'secondary'} small" data-action="platform-appliance-connect">Join an existing cluster</button></div>${join?`<form id="platform-appliance-join-form"><div id="platform-appliance-join-error" class="form-error" role="alert" hidden></div><p class="platform-intro">Connect this installed controller${identity.id?' '+h(identity.id):''}${identity.site?' in '+h(identity.site):''} to an existing cluster. Its identity comes from this installation.</p><div class="field"><label for="appliance-peer-url">Existing controller IP or HTTPS origin</label><input id="appliance-peer-url" name="peer_url" required placeholder="https://controller-noida.example.com:8787"></div><div class="field"><label for="appliance-join-password">Shared cluster password</label><input id="appliance-join-password" name="cluster_password" type="password" required autocomplete="off"><small>Use the cluster password configured on the existing cluster. It is used for this request and is not stored in browser storage.</small></div><button class="button primary" type="submit" ${!applianceOperational()?'disabled':''}>Review connection</button></form>`:`<form id="platform-appliance-config-form" data-revision="${num(info.revision)}"><div id="platform-appliance-config-error" class="form-error" role="alert" hidden></div><div class="field-row"><div class="field"><label for="appliance-cluster-name">Cluster name</label><input id="appliance-cluster-name" name="cluster_name" value="${h(cluster.name || '')}" required maxlength="120" placeholder="Prithak production"></div><div class="field"><label for="appliance-site">This site</label><input id="appliance-site" name="site" value="${h(identity.site || '')}" required maxlength="100" placeholder="Noida"></div></div><div class="field-row"><div class="field"><label for="appliance-node-ip">This controller's management IP</label><input id="appliance-node-ip" name="node_ip" value="${h(identity.ip || '')}" required placeholder="10.241.10.11"></div><div class="field"><label for="appliance-origin">Cluster HTTPS origin</label><input id="appliance-origin" name="controller_origin" value="${h(cluster.origin || '')}" required placeholder="https://prthak.example.com"></div></div><div class="field-row"><div class="field"><label for="appliance-cluster-password">Shared cluster password ${cluster.cluster_password_configured?'· configured':''}</label><input id="appliance-cluster-password" name="cluster_password" type="password" autocomplete="new-password" placeholder="${cluster.cluster_password_configured?'Leave blank to keep the current password':'Set a shared cluster password'}"><small>Use the same password when joining another controller. Existing passwords are never returned.</small></div><div class="field"><label for="appliance-replication-password">Replication password ${cluster.replication_password_configured?'· configured':''}</label><input id="appliance-replication-password" name="replication_password" type="password" minlength="32" maxlength="128" autocomplete="new-password" placeholder="${cluster.replication_password_configured?'Leave blank to keep the current password':'Generate automatically when blank'}"><small>Use 32–128 printable ASCII characters. Initially blank generates a private password; afterward blank preserves it.</small></div></div>${applianceReplicationRotationHTML()}<details class="appliance-routing-fields"><summary>Advanced: site routing and host fencing</summary><label class="host-check"><input id="appliance-watchdog-approved" name="watchdog_approved" type="checkbox" ${info.watchdog_approved===true||cluster.watchdog_approved===true?'checked':''}>Enable approved host fencing for automatic failover</label><p class="help-text">Host fencing can restart a database host. Automatic failover requires the native <code>/dev/watchdog0</code> device and an approved fencing configuration.</p><div class="field"><label for="appliance-preferred-url">Local controller pool URL</label><input id="appliance-preferred-url" name="preferred_controller_url" value="${h(routing.preferred_controller_url || '')}" placeholder="https://noida-prthak.example.com"></div><div class="field"><label for="appliance-fallback-url">Other-site fallback pool URL</label><input id="appliance-fallback-url" name="fallback_controller_url" value="${h(routing.fallback_controller_url || '')}" placeholder="https://pune-prthak.example.com"></div><p class="help-text">Configure the load balancer to use the local pool first and the other site only when local health checks fail.</p></details><div class="platform-form-actions"><button class="button primary" type="submit" ${!state.platformAppliance?'disabled':''}>${cluster.configured===true||cluster.settings_saved===true?'Save cluster settings':'Create cluster settings'}</button><span class="help-text">Automatic database stack setup waits for three site voters and approved host fencing. Saved settings are separate from actual replication and service health.</span></div></form>`}</section>${applianceRoutingHTML()}<div class="platform-form-actions">${platformOperationHistoryLinkHTML()}</div>`;
}
function platformApplianceStorageHTML(){
  const info=appliance();return `${applianceDisabledNotice()}<section class="card platform-panel"><div class="platform-panel-heading"><span class="platform-feature-icon">${icon('services')}</span><div><h2>Storage location</h2><p>Change the appliance data path through a reviewed migration.</p></div></div><dl class="detail-grid"><div><dt>Current data path</dt><dd><code>${h(info.data_root || 'Not reported')}</code></dd></div></dl><form id="platform-appliance-storage-form"><div id="platform-appliance-storage-error" class="form-error" role="alert" hidden></div><div class="field"><label for="appliance-data-root">New data mount path</label><input id="appliance-data-root" name="data_root" value="" required placeholder="/srv/prthak-data"><small>Choose an absolute path on a mounted volume. The review reports migration checks, service interruption and any blockers before changes start.</small></div><button class="button secondary" type="submit" ${!applianceOperational()?'disabled':''}>Review storage migration</button></form></section>`;
}
function applianceServiceUnused(service){
  return service.enabled===false&&['database','etcd'].includes(service.id);
}
function applianceServiceBadge(service){
  const unused=applianceServiceUnused(service);
  const running=['active','running'].includes(service.state);
  const stopped=['stopped','exited'].includes(service.state);
  const inactive=unused&&stopped;
  const label=inactive?'Not used on this node':humanize(service.state || 'Not reported');
  const unexpected=(unused&&running)||(service.enabled===true&&stopped);
  const failed=unexpected||['failed','dead'].includes(service.state);
  return badge(label,failed?'danger':running?'':'neutral');
}
function applianceManagerBadge(info){
  return info.manager_available===true?badge('Reachable'):info.manager_available===false?badge('Unreachable','danger'):badge('Not reported','neutral');
}
function applianceServiceRowHTML(service){
  const unused=applianceServiceUnused(service);
  const enabled=unused?'HA database voters only':service.enabled===true?'Enabled':service.enabled===false?'Disabled':'Not reported';
  const disabled=applianceOperational()?'':'disabled';
  const actions=unused?'&mdash;':`<div class="platform-backup-actions"><button class="text-button" data-action="platform-appliance-service-review" data-id="${h(service.id)}" data-service-action="restart" ${service.can_restart===true?disabled:'disabled'}>Restart</button>${service.can_stop===true?`<button class="text-button danger-text" data-action="platform-appliance-service-review" data-id="${h(service.id)}" data-service-action="stop" ${disabled}>Stop</button>`:''}</div>`;
  return `<tr><td><strong>${h(service.name || service.id)}</strong></td><td>${applianceServiceBadge(service)}</td><td>${enabled}</td><td>${actions}</td></tr>`;
}
function platformApplianceServicesHTML(){
  const info=appliance(),services=info.services || [];
  const runtime=state.platformInfo?.runtime;
  const storageNote=runtime?.ha===false&&runtime.storage==='sqlite'&&services.some(applianceServiceUnused)?'<p class="help-text">This standalone controller stores its data in SQLite. PostgreSQL with Patroni and etcd run on database voters in a high-availability deployment.</p>':'';
  const managerRow=info.installed===true?`<tr><td><strong>Appliance node manager</strong><br><small>prthak-appliance-manager.service</small></td><td>${applianceManagerBadge(info)}</td><td>Host systemd</td><td>&mdash;</td></tr>`:'';
  return `${platformApplicationPortHTML()}${applianceDisabledNotice()}<section class="card platform-panel"><div class="section-line"><h2>Appliance services</h2><div class="toolbar-group">${platformOperationHistoryLinkHTML()}<button class="text-button" data-action="platform-refresh">Refresh health</button></div></div><p class="platform-intro">Review a service action before it runs. A controller restart can briefly disconnect the dashboard.</p>${storageNote}<div class="table-scroll"><table><thead><tr><th>Service</th><th>Reported state</th><th>Configuration</th><th>Actions</th></tr></thead><tbody>${managerRow}${services.map(applianceServiceRowHTML).join('') || '<tr><td colspan="4">No managed service state has been reported by this appliance.</td></tr>'}</tbody></table></div></section>`;
}
function platformBackupScheduleHTML(){
  const schedule=state.platformBackupSchedule,loaded=!!schedule,s=schedule || {},frequency=s.frequency || 'daily';
  return `<section class="card platform-panel appliance-schedule"><div class="section-line"><h2>Automatic backups</h2><button class="text-button" data-action="platform-backup-schedule-refresh">Refresh schedule</button></div>${state.platformBackupScheduleError?`<div class="inline-notice warning">${h(state.platformBackupScheduleError)}</div>`:''}<form id="platform-backup-schedule-form" data-revision="${num(s.revision)}"><div id="platform-backup-schedule-error" class="form-error" role="alert" hidden></div><label class="host-check"><input id="backup-schedule-enabled" name="enabled" type="checkbox" ${s.enabled===true?'checked':''}>Enable scheduled backups</label><div class="field-row"><div class="field"><label for="backup-schedule-frequency">Frequency</label><select id="backup-schedule-frequency" name="frequency"><option value="daily" ${frequency==='daily'?'selected':''}>Daily</option><option value="weekly" ${frequency==='weekly'?'selected':''}>Weekly</option><option value="interval" ${frequency==='interval'?'selected':''}>Every few hours</option></select></div><div class="field" id="backup-schedule-time-field" ${frequency==='interval'?'hidden':''}><label for="backup-schedule-time">Time</label><input id="backup-schedule-time" name="time" type="time" value="${h(s.time || '02:00')}" required></div><div class="field"><label for="backup-schedule-timezone">Timezone</label><input id="backup-schedule-timezone" name="timezone" value="${h(s.timezone || 'Asia/Kolkata')}" required placeholder="Asia/Kolkata"></div></div><div class="field" id="backup-schedule-weekday-field" ${frequency!=='weekly'?'hidden':''}><label for="backup-schedule-weekday">Weekday</label><select id="backup-schedule-weekday" name="weekday">${['Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday'].map((day,index)=>`<option value="${index}" ${Number(s.weekday || 0)===index?'selected':''}>${day}</option>`).join('')}</select></div><div class="field" id="backup-schedule-interval-field" ${frequency!=='interval'?'hidden':''}><label for="backup-schedule-interval">Interval in hours</label><input id="backup-schedule-interval" name="interval_hours" type="number" min="1" max="168" value="${num(s.interval_hours || 24)}" required></div><div class="field"><label for="backup-schedule-retention">Backups to retain</label><input id="backup-schedule-retention" name="retention_count" type="number" min="1" max="365" value="${num(s.retention_count || 7)}" required><small>The scheduler applies retention to scheduled backup history. Review the latest run and errors below.</small></div><button class="button primary" type="submit" ${!loaded?'disabled':''}>Save backup schedule</button></form><dl class="detail-grid appliance-schedule-status"><div><dt>Next run</dt><dd>${h(timestamp(s.next_run_at))}</dd></div><div><dt>Last successful run</dt><dd>${h(timestamp(s.last_success_at))}</dd></div><div><dt>Last run</dt><dd>${h(timestamp(s.last_run_at))}</dd></div><div><dt>Latest status</dt><dd>${h(s.running===true?'Running':s.last_status?humanize(s.last_status):'Not reported')}</dd></div><div><dt>Schedule revision</dt><dd>${loaded?'r'+num(s.revision):'Not loaded'}</dd></div></dl>${s.last_error?`<p class="form-error">${h(s.last_error)}</p>`:''}${s.retention_error?`<p class="inline-notice warning">${h(s.retention_error)}</p>`:''}<p class="help-text">Scheduled archives and retention are local to the controller's backup storage.</p></section>`;
}
async function loadPlatformAppliance(){
  if(!canManagePlatform())return;try{state.platformAppliance=await api('/platform/appliance');state.platformApplianceError='';}catch(error){state.platformApplianceError='Appliance state is unavailable: '+error.message;}
}
async function loadPlatformBackupSchedule(redraw=true){
  if(!canManagePlatform())return;try{state.platformBackupSchedule=await api('/platform/backup-schedule');state.platformBackupScheduleError='';}catch(error){state.platformBackupScheduleError='Backup schedule is unavailable: '+error.message;}if(redraw&&state.view==='settings'&&!platformHasDraft()&&!$('#modal').open&&!document.activeElement?.matches('input,select,textarea'))render();
}
function platformApplianceInput(event){
  if(event.target.id==='appliance-review-phrase'){const form=$('#platform-appliance-review-form');if(form)$('button[type="submit"]',form).disabled=!applianceReviewUsable(state.platformApplianceReview,event.target.value);return true;}return false;
}
function platformApplianceChange(event){
  if(event.target.id!=='backup-schedule-frequency')return false;const value=event.target.value;$('#backup-schedule-time-field').hidden=value==='interval';$('#backup-schedule-weekday-field').hidden=value!=='weekly';$('#backup-schedule-interval-field').hidden=value!=='interval';return true;
}
function applianceReviewUsable(review,phrase){return (review?.kind==='certificates'?canManagePlatform()&&state.platformInfo?.runtime?.demo!==true:applianceOperational())&&!!review&&platformUI.reviewReady({...review.plan,can_apply:review.plan.can_apply===undefined?true:review.plan.can_apply},state.role)&&!!review.plan.confirmation_nonce&&platformUI.exactPhrase(review.plan,phrase);}
function platformShowApplianceReview(plan,kind){
  state.platformApplianceReview={plan,kind};const summary=plan.summary || {},labels={join:'Connect to the existing cluster',storage:'Migrate the appliance data path',services:'Run the reviewed service action',certificates:'Review HTTPS certificate activation'};
  const fields=[['peer_url','Existing controller'],['service','Service'],['action','Action'],['current_data_root','Current data path'],['data_root','New data path'],['node_id','Controller'],['site','Site']];
  showModal(labels[kind] || 'Review appliance change',`<form id="platform-appliance-review-form"><div class="modal-body">${errorSlot}<div class="inline-notice warning">Review the exact change. Services may restart and the dashboard may temporarily disconnect. Queued work is separate from a verified result.</div><dl class="detail-grid">${fields.filter(([key])=>typeof summary[key]==='string').map(([key,label])=>`<div><dt>${label}</dt><dd>${h(key==='peer_url'?platformUI.connectionLabel(summary[key]):summary[key])}</dd></div>`).join('')}<div><dt>Review expiry</dt><dd>${h(timestamp(plan.expires_at))}</dd></div></dl>${summary.node?`<p class="help-text">This controller: ${h(summary.node.id || '')} · ${h(summary.node.site || '')} · ${h(summary.node.ip || '')}</p>`:''}${summary.message?`<p class="help-text">${h(summary.message)}</p>`:''}${summary.trust_verified===false?'<div class="inline-notice warning">Peer certificate trust has not been verified. Compare the full fingerprint with the existing cluster administrator through a trusted channel before confirming.</div>':''}${summary.certificate?platformCertificateDetailsHTML(summary.certificate):kind==='certificates'?platformCertificateDetailsHTML(summary):''}${(plan.blockers || []).map(reason=>`<p class="form-error">${h(reason)}</p>`).join('')}${(plan.warnings || []).map(reason=>`<p class="inline-notice warning">${h(reason)}</p>`).join('')}<div class="field"><label for="appliance-review-phrase">Type the exact confirmation phrase</label><code class="platform-confirmation-phrase">${h(plan.confirmation_phrase)}</code><input id="appliance-review-phrase" name="confirmation_phrase" autocomplete="off" spellcheck="false"></div></div><div class="modal-footer"><button type="button" class="button secondary" data-action="close-modal">Cancel</button><button type="submit" class="button danger" disabled>Apply reviewed change</button></div></form>`,'APPLIANCE CHANGE REVIEW');
}
function platformSchedulePayload(form){
  const values=new FormData(form),frequency=String(values.get('frequency') || ''),time=String(values.get('time') || ''),timezone=String(values.get('timezone') || '').trim(),weekday=Number(values.get('weekday')),interval_hours=Number(values.get('interval_hours')),retention_count=Number(values.get('retention_count'));
  if(!['daily','weekly','interval'].includes(frequency))throw new Error('Choose daily, weekly or an hourly interval.');if(!/^([01]\d|2[0-3]):[0-5]\d$/.test(time))throw new Error('Choose a valid 24-hour backup time.');try{new Intl.DateTimeFormat('en',{timeZone:timezone});}catch{throw new Error('Enter a valid IANA timezone, such as Asia/Kolkata.');}
  if(!Number.isInteger(weekday)||weekday<0||weekday>6)throw new Error('Choose a valid weekday.');if(!Number.isInteger(interval_hours)||interval_hours<1||interval_hours>168)throw new Error('Backup intervals must be 1–168 hours.');if(!Number.isInteger(retention_count)||retention_count<1||retention_count>365)throw new Error('Retain between 1 and 365 scheduled backups.');
  return {expected_revision:Number(form.dataset.revision),enabled:['on','true',true].includes(values.get('enabled')),frequency,time,timezone,weekday,interval_hours,retention_count};
}
async function platformApplianceSubmit(event){
  event.preventDefault();if(!canManagePlatform())return;const form=event.target,button=$('button[type="submit"]',form);button.disabled=true;
  try{
    const values=new FormData(form),get=key=>String(values.get(key) || '').trim();
    if(form.id==='platform-backup-schedule-form'){await api('/platform/backup-schedule',{method:'POST',body:platformSchedulePayload(form)});platformClearDraft(form);await loadPlatformBackupSchedule();toast('Backup schedule saved. The next run and outcome come from the scheduler.');return;}
    if(form.id==='platform-appliance-config-form'){const body={expected_revision:Number(form.dataset.revision),cluster_name:get('cluster_name'),site:get('site'),node_ip:get('node_ip'),controller_origin:get('controller_origin'),preferred_controller_url:get('preferred_controller_url'),fallback_controller_url:get('fallback_controller_url'),watchdog_approved:['on','true',true].includes(values.get('watchdog_approved'))};for(const key of ['cluster_password','replication_password']){const secret=String(values.get(key) || '');if(secret){if(key==='replication_password'&&!/^([\x20-\x7E]{32,128})$/.test(secret))throw new Error('Replication passwords must contain 32–128 printable ASCII characters.');body[key]=secret;}}await api('/platform/appliance/config',{method:'POST',body});platformClearDraft(form);$$('input[type="password"]',form).forEach(input=>input.value='');await loadPlatformSettings();toast('Cluster settings saved. Review actual replication and service status separately.');return;}
    if(form.id!=='platform-appliance-review-form'&&!applianceOperational())throw new Error('This operation requires an installed production appliance manager.');
    if(form.id==='platform-appliance-join-form'){const password=String(values.get('cluster_password') || '');if(!password)throw new Error('Enter the shared cluster password.');const plan=await api('/platform/appliance/join/preview',{method:'POST',body:{peer_url:get('peer_url'),cluster_password:password}});$('#appliance-join-password').value='';platformShowApplianceReview(plan,'join');return;}
    if(form.id==='platform-appliance-storage-form'){const data_root=get('data_root');if(!data_root.startsWith('/'))throw new Error('Enter an absolute path on the mounted data volume.');const plan=await api('/platform/appliance/storage/review',{method:'POST',body:{data_root}});platformShowApplianceReview(plan,'storage');return;}
    if(form.id==='platform-appliance-review-form'){const review=state.platformApplianceReview,phrase=String(values.get('confirmation_phrase') || '');if(!applianceReviewUsable(review,phrase))throw new Error('Use a fresh, unblocked review and type the exact confirmation phrase.');const plan=review.plan,job=await api(review.kind==='certificates'?'/platform/certificates/apply':'/platform/appliance/'+review.kind+'/apply',{method:'POST',body:{preview_id:plan.id,digest:plan.digest,confirmation_nonce:plan.confirmation_nonce,confirmation_phrase:phrase}});state.platformApplianceReview=null;state.platformRuntimePending=true;closeModal();platformTrackJob(job);toast('Reviewed appliance operation queued. Wait for its verified result.');}
  }catch(error){platformHAError(form,error);if(error.status===409)state.platformApplianceReview=null;}finally{button.disabled=false;}
}
async function platformApplianceAction(button){
  if(!canManagePlatform())return;const {action,id}=button.dataset;
  if(action==='platform-appliance-controller-name')return showControllerDisplayName();
  if(action==='platform-appliance-replication-abort'){
    const rotation=appliance().cluster?.replication_rotation;if(appliance().installed!==true||state.platformInfo?.runtime?.demo===true||rotation?.can_abort!==true||rotation.phase==='abort')return;
    button.disabled=true;try{const result=await api('/platform/appliance/replication/abort',{method:'POST',body:{}});state.platformAppliance.cluster.replication_rotation=result;render();toast(result?.phase==='aborted'?'Replication rotation cancellation completed.':'Cancellation requested. Wait for every voter to acknowledge cleanup.');}catch(error){formError(error);if(error.status===409)await loadPlatformSettings();}finally{button.disabled=false;}return;
  }
  if(action==='platform-appliance-create'||action==='platform-appliance-connect'){platformClearDraft();state.platformTab='cluster';state.platformApplianceClusterMode=action==='platform-appliance-connect'?'join':'settings';render();return;}
  if(action==='platform-backup-schedule-refresh')return loadPlatformBackupSchedule();
  if(action==='platform-appliance-service-review'){
    try{const service=(appliance().services || []).find(service=>service.id===id),operation=button.dataset.serviceAction;if(!applianceOperational()||!service||applianceServiceUnused(service)||!['restart','stop'].includes(operation)||(operation==='restart'&&service.can_restart!==true)||(operation==='stop'&&service.can_stop!==true))throw new Error('This fixed service action is not available on the installed appliance.');const plan=await api('/platform/appliance/services/review',{method:'POST',body:{service:id,action:operation}});platformShowApplianceReview(plan,'services');}catch(error){formError(error);}
  }
}
