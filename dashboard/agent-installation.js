'use strict';

let agentInstallationEpoch=0,agentInstallationDraft=0;
let agentFleetProfiles=[],agentFleetProfileTotal=0,agentFleetProfileOffset=0,agentFleetProfileLoading=false,agentFleetProfileError='',agentFleetListSequence=0;
const agentFleetProfileLimit=20;
function agentInstallationIdentity(){
  return JSON.stringify([state.authConfig?.mode||'',state.authConfig?.tenant_id||'',state.authConfig?.client_id||'',state.authType||'',state.role||'',state.user?.tenant_id||'',state.user?.id||state.user?.oid||state.user?.sub||'',state.token||'']);
}
function clearAgentInstallation(){
  agentInstallationEpoch++;agentInstallationDraft++;agentFleetListSequence++;agentFleetProfiles=[];agentFleetProfileTotal=0;agentFleetProfileOffset=0;agentFleetProfileLoading=false;agentFleetProfileError='';
}
function agentInstallationModalChanged(content){if(!String(content).includes('id="agent-installation-form"'))clearAgentInstallation();}
function agentInstallationCurrent(epoch,identity){return epoch===agentInstallationEpoch&&identity===agentInstallationIdentity()&&canWrite()&&state.authConfig?.mode!=='demo'&&$('#modal')?.open===true;}
function agentInstallationOrigin(){
  const candidates=[state.authConfig?.agent_channels?.controller_url,state.platformAppliance?.cluster?.origin,state.authConfig?.redirect_uri,globalThis.location?.origin];
  for(const value of candidates){try{const parsed=new URL(value);if(parsed.protocol==='https:'&&!parsed.username&&!parsed.password)return parsed.origin;}catch{}}
  return '';
}
function agentInstallationChannelsHTML(){const channels=state.authConfig?.agent_channels||{};return `<div class="field-row"><div class="field"><label for="agent-install-control-url">Control HTTPS origin</label><input id="agent-install-control-url" name="control_url" type="url" value="${h(channels.control_url||'')}" placeholder="Blank uses combined controller origin"><small>Policy, protection and certificate renewal.</small></div><div class="field"><label for="agent-install-discovery-url">Discovery HTTPS origin</label><input id="agent-install-discovery-url" name="discovery_url" type="url" value="${h(channels.discovery_url||'')}" placeholder="Blank uses combined controller origin"><small>Enrollment, discovery reports and traffic evidence.</small></div></div>`;}
function agentInstallationCommand(){return 'sudo ./scripts/install-agent-auto.sh --setup-file /root/prthak-agent-setup.json';}
function agentInstallationDownload(architecture){
  const arch=architecture==='arm64'?'arm64':'amd64';
  const version=state.authConfig?.agent_downloads?.[arch];
  if(typeof version!=='string'||!/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(version))return null;
  return {filename:`prthak-agent-${version}-linux-${arch}.tar.gz`,route:'/agent-installation/releases/'+arch};
}
function agentInstallationArchive(architecture){return agentInstallationDownload(architecture)?.filename||'the signed agent archive';}
function agentInstallationAssetHTML(item,asset,label,style){
  const path=item.route+'/'+asset,filename=item.filename+(asset==='signature'?'.signature.json':'');
  if(state.authConfig?.mode==='tokens')return `<button type="button" class="${style}" data-agent-release-asset="${asset}">${label}</button>`;
  return `<a class="${style}" href="/api/v1${h(path)}" download="${h(filename)}">${label}</a>`;
}
function agentInstallationLinksHTML(architecture){
  const item=agentInstallationDownload(architecture);
  if(!item)return '<small>The signed agent package for this CPU is unavailable on this controller.</small>';
  return `<small>${h(item.filename)}</small>${agentInstallationAssetHTML(item,'signature','Download archive signature','text-button')}`;
}
function agentInstallationArchiveActionHTML(architecture){
  const item=agentInstallationDownload(architecture);
  return item?agentInstallationAssetHTML(item,'archive','Download agent (.tar.gz)','button secondary'):'<button type="button" class="button secondary" disabled>Download agent (.tar.gz)</button>';
}
async function downloadTokenAgentAsset(button){
  const asset=button.dataset.agentReleaseAsset;
  if(state.authConfig?.mode!=='tokens'||!state.user||!['archive','signature'].includes(asset))return;
  const item=agentInstallationDownload($('#agent-install-architecture')?.value);
  if(!item)return;
  const epoch=agentInstallationEpoch,identity=agentInstallationIdentity();
  button.disabled=true;
  try{
    const blob=await api(item.route+'/'+asset,{cache:'no-store',download:true});
    if(epoch!==agentInstallationEpoch||identity!==agentInstallationIdentity())return;
    const url=URL.createObjectURL(blob),link=document.createElement('a');
    try{link.href=url;link.download=item.filename+(asset==='signature'?'.signature.json':'');link.click();}
    finally{setTimeout(()=>URL.revokeObjectURL(url),1000);}
  }catch(error){if(epoch===agentInstallationEpoch&&identity===agentInstallationIdentity())formError(error);}
  finally{button.disabled=false;}
}
function agentInstallationScopeHTML(mode){
  if(mode==='individual')return `<div class="field"><label for="agent-install-hostname">Expected hostname (optional)</label><input id="agent-install-hostname" name="expected_hostname" maxlength="253" autocomplete="off" placeholder="billing-server-01"><small>This optional one-use setup expires after 15 minutes. Its credential enrolls one endpoint.</small></div>`;
  return `<div class="field-row"><div class="field"><label for="agent-install-profile-name">Enrollment profile name</label><input id="agent-install-profile-name" name="name" maxlength="120" value="Server fleet" required autocomplete="off" placeholder="Production server rollout"></div><div class="field"><label for="agent-install-profile-validity">Allow new enrollment for</label><select id="agent-install-profile-validity" name="validity_hours"><option value="1">1 hour</option><option value="24" selected>24 hours</option><option value="168">7 days</option><option value="720">30 days</option></select></div></div><p class="help-text">Reuse the same private setup file on any number of servers before expiry. Each server generates its own private key and certificate automatically. No hostname list, CSV or per-server download is required.</p>`;
}
function agentInstallationSetupHelp(mode){return mode==='individual'?'Transfer this one-use setup file privately as root-owned mode 0600 to /root/prthak-agent-setup.json. Generate a fresh file for another endpoint.':'Transfer the same reusable setup file privately as root-owned mode 0600 to /root/prthak-agent-setup.json on every server. It contains an enrollment key, so distribute it only through your approved private deployment channel.';}
function agentInstallationPreparationHTML(){
  return `<div class="field"><label>Automatic OS dependency installation</label><p class="help-text">The same installer detects RHEL or Ubuntu and installs missing required packages from the server's approved repositories after validating the setup and signed release. Existing firewall service activity is preserved. This does not activate firewalld, disable UFW or authorize firewall access changes.</p><label class="host-check"><input id="agent-install-ufw-assess" name="assess_ufw" type="checkbox">Assess UFW and export migration data</label><small>Optional private UFW configuration/status export for review. UFW stays active; this does not activate firewalld or apply a migration. UFW assessment is off by default.</small></div>`;
}
function agentInstallationManagementHTML(){
  return `<div class="field"><label for="agent-install-management-sources">Pinned management source IPs / CIDRs (optional)</label><textarea id="agent-install-management-sources" name="management_sources" rows="2" maxlength="13000" placeholder="10.90.0.10/32, 10.91.0.0/24, 2001:db8:90::10/128"></textarea><small>Enter up to100 restricted sources used by your SSH bastion and controller management probe. Use canonical networks; /0 is forbidden. These are local safety pins, not access-policy grants. They do not enable enforcement. Configure the controller's management probe in Settings before reviewed source-bank activation. Leaving this blank permits inventory; protected maintenance stays blocked until pins are configured.</small></div>`;
}
function showAgentInstallation(){
  clearAgentInstallation();const allowed=canWrite(),demo=state.authConfig?.mode==='demo';
  showModal('Install endpoint agents',`<form id="agent-installation-form"><div class="modal-body">${errorSlot}<div class="inline-notice">RHEL/Rocky/Alma/Oracle Linux 8/9 and Ubuntu 22.04/24.04/26.04 · native systemd agent · outbound HTTPS</div><p class="platform-intro">Download the agent archive and private setup JSON below. Reuse the archive on servers with the same CPU architecture and the fleet setup JSON on all servers in its enrollment window. No agent JSON or environment-file editing is required.</p>${demo?'<p class="inline-notice warning">This is a local preview. Real setup files require an installed HTTPS controller and its trusted certificate identity.</p>':''}<div class="field"><label for="agent-install-mode">Setup type</label><select id="agent-install-mode" name="setup_mode"><option value="fleet" selected>Fleet setup · reusable</option><option value="individual">Individual setup · one use</option></select></div><div id="agent-install-scope-fields">${agentInstallationScopeHTML('fleet')}</div><p class="help-text">Linux family is detected automatically on the server: RHEL/Rocky/Alma/Oracle Linux 8/9 or Ubuntu 22.04/24.04/26.04. The same binary is used on RHEL and Ubuntu for the same CPU.</p><div class="field"><label for="agent-install-architecture">CPU architecture</label><select id="agent-install-architecture" name="architecture"><option value="amd64">x86_64 / AMD64</option><option value="arm64">aarch64 / ARM64</option></select><div class="inline-actions" id="agent-install-download-links">${agentInstallationLinksHTML('amd64')}</div></div><div class="field"><label for="agent-install-controller">Controller HTTPS origin</label><input id="agent-install-controller" name="controller_url" type="url" value="${h(agentInstallationOrigin())}" required placeholder="https://prthak.example.internal"><small>Use the trusted dashboard/load-balancer origin, including its port when required.</small></div>${agentInstallationChannelsHTML()}${agentInstallationManagementHTML()}<div class="field"><label for="agent-install-ca">Public HTTPS CA chain (when required)</label><input id="agent-install-ca" name="controller_ca" type="file" accept=".pem,.crt,.cer"><small>Use an independently approved public CA chain if the web certificate uses a different issuer. Never upload a private key.</small></div><div class="field-row"><div class="field"><label for="agent-install-control">Control polling (seconds)</label><input id="agent-install-control" name="interval_seconds" type="number" min="5" max="3600" value="30" required></div><div class="field"><label for="agent-install-discovery">Full inventory fallback (seconds)</label><input id="agent-install-discovery" name="discovery_interval_seconds" type="number" min="60" max="86400" value="900" required></div></div>${agentInstallationPreparationHTML()}<p class="help-text">Supported native agents check listeners every 5 seconds and report changes promptly. The interval above controls the periodic full inventory/firewall fallback; unsupported kernel checks use that fallback.</p><p class="help-text">Initial setup is monitor-only. Enforcement, automatic learned access and traffic instrumentation remain disabled. Central polling profiles can override these intervals. The enrollment key grants no dashboard or firewall-policy authority.</p><p class="help-text">Enrollment is identity-only. Assign tags and DC centrally after discovery, through subnet mappings, or by importing IP profiles.</p><ol class="setup-steps"><li>Stage and independently verify <code id="agent-install-archive">${agentInstallationArchive('amd64')}</code> and its detached signature. Extract the signed release into a protected directory on each server.</li><li id="agent-install-file-help">${agentInstallationSetupHelp('fleet')}</li><li>From the extracted release directory run:</li></ol><code id="agent-install-command" class="setup-code">${h(agentInstallationCommand())}</code><p class="help-text">Your deployment tool can run the same installer across the fleet. The installer validates this setup, detects the OS, installs missing required dependencies, and starts seg-agent. UFW assessment produces a private review export; switching firewall managers remains a separate reviewed operation. Servers appear automatically after their first authenticated report.</p><div id="agent-installation-result" role="status" aria-live="polite"></div><div class="section-line"><h3>Fleet enrollment keys</h3><button type="button" class="text-button" data-action="agent-fleet-refresh" ${!allowed||demo?'disabled':''}>Refresh</button></div><p class="help-text">Keys can be downloaded only when created. Revoking a key stops new enrollment; existing enrolled servers keep their own certificates and remain connected.</p><div id="agent-fleet-profiles">${demo?'Native fleet enrollment is unavailable in this synthetic preview.':allowed?'Loading enrollment profiles…':'Admin or Super Admin access is required to manage enrollment profiles.'}</div><p><button type="button" class="button secondary" data-action="endpoint-configuration">Configure an enrolled endpoint</button></p>${!allowed?'<p class="inline-notice">Admin or Super Admin access is required to download an endpoint setup file.</p>':''}</div><div class="modal-footer"><button type="button" class="button secondary" data-action="close-modal">Close</button><span id="agent-install-archive-action">${agentInstallationArchiveActionHTML('amd64')}</span><button type="submit" class="button primary" ${!allowed||demo?'disabled':''}>Download private setup JSON</button></div></form>`,'FLEET AGENT INSTALLATION');
  if(allowed&&!demo)loadAgentFleetProfiles();
}
function agentInstallationChange(event){
  if(!String(event.target.id||'').startsWith('agent-install-'))return false;
  agentInstallationDraft++;
  if(event.target.id==='agent-install-mode'){
    const mode=event.target.value==='individual'?'individual':'fleet';
    $('#agent-install-scope-fields').innerHTML=agentInstallationScopeHTML(mode);
    $('#agent-install-file-help').textContent=agentInstallationSetupHelp(mode);
    $('#agent-installation-result').innerHTML='';
  }
  if(event.target.id==='agent-install-architecture'){
    $('#agent-install-command').textContent=agentInstallationCommand();
    $('#agent-install-archive').textContent=agentInstallationArchive($('#agent-install-architecture').value);
    $('#agent-install-download-links').innerHTML=agentInstallationLinksHTML($('#agent-install-architecture').value);
    $('#agent-install-archive-action').innerHTML=agentInstallationArchiveActionHTML($('#agent-install-architecture').value);
  }
  const button=$('button[type="submit"]',$('#agent-installation-form'));if(button)button.disabled=!canWrite()||state.authConfig?.mode==='demo';
  return true;
}
function agentInstallationMode(form){const value=String(new FormData(form).get('setup_mode')||'fleet');if(!['fleet','individual'].includes(value))throw new Error('Choose fleet or individual setup.');return value;}
function agentInstallationManagementSources(raw){
  if(typeof raw!=='string'||raw.length>13000)throw new Error('Use at most100 restricted management IPs or canonical CIDRs.');
  const values=raw.trim()?raw.trim().split(/[\s,]+/):[];
  if(values.length>100||values.some(value=>value.length>128||value.includes(':')&&value.includes('.')||!/^([0-9a-fA-F:.]+)(?:\/([1-9]\d{0,2}))?$/.test(value)||value.includes('/')&&Number(value.split('/')[1])>(value.includes(':')?128:32)))throw new Error('Use restricted native management IPs/CIDRs; /0, mapped IPv6 and scope identifiers are unsupported.');
  return [...new Set(values.map(value=>value.includes('/')?value:value+(value.includes(':')?'/128':'/32')))].sort();
}
function agentInstallationPayload(form){
  const values=new FormData(form),get=key=>String(values.get(key)||'').trim(),mode=agentInstallationMode(form);
  const family='auto',architecture=get('architecture'),expected_hostname=get('expected_hostname'),controller_url=get('controller_url');
  if(!['amd64','arm64'].includes(architecture))throw new Error('Choose the endpoint CPU architecture. The installer detects its Linux family.');
  if(mode==='individual'&&expected_hostname&&(!/^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/.test(expected_hostname)||expected_hostname.includes('..')))throw new Error('Enter the exact valid endpoint hostname, or leave it blank.');
  let origin;try{const parsed=new URL(controller_url);if(parsed.protocol!=='https:'||parsed.username||parsed.password||parsed.search||parsed.hash||!['','/'].includes(parsed.pathname))throw new Error();origin=parsed.origin;}catch{throw new Error('Use an HTTPS controller origin without a path, credentials, query or fragment.');}
  const integer=(key,min,max)=>{const value=get(key);if(!/^\d+$/.test(value)||!Number.isSafeInteger(Number(value))||Number(value)<min||Number(value)>max)throw new Error('Use a whole-number value within the displayed range.');return Number(value);};
  const channel=key=>{const value=get(key);if(!value)return '';try{const parsed=new URL(value);if(parsed.protocol!=='https:'||parsed.username||parsed.password||parsed.search||parsed.hash||!['','/'].includes(parsed.pathname))throw new Error();return parsed.origin;}catch{throw new Error('Channel URLs must be trusted HTTPS origins.');}};
  const channels={};for(const key of ['control_url','discovery_url']){const value=channel(key);if(value)channels[key]=value;}
  const scope=mode==='individual'?{expected_hostname}:{name:get('name'),validity_hours:integer('validity_hours',1,720)};
  if(mode==='fleet'&&(!scope.name||scope.name.length>120||/[\x00-\x1f\x7f]/.test(scope.name)))throw new Error('Enter an enrollment profile name of 1–120 characters.');
  const selected=key=>{const value=values.get(key);if(value!==null&&value!=='on')throw new Error('Endpoint preparation must be selected with its checkbox.');return value==='on';};
  const assessUfw=selected('assess_ufw');
  const managementSources=agentInstallationManagementSources(get('management_sources'));
  return {family,architecture,...scope,controller_url:origin,...channels,interval_seconds:integer('interval_seconds',5,3600),discovery_interval_seconds:integer('discovery_interval_seconds',60,86400),...(managementSources.length?{management_sources:managementSources}:{}),installation_options:{install_dependencies:true,ufw_action:assessUfw?'assess':'preserve'}};
}
function agentFleetPublicProfile(profile){
  if(!profile||typeof profile.id!=='string'||!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(profile.id))throw new Error('The controller returned an invalid enrollment profile.');
  return {id:profile.id,name:String(profile.name||'Enrollment profile').slice(0,120),status:['active','expired','revoked'].includes(profile.status)?profile.status:'unknown',expires_at:typeof profile.expires_at==='string'?profile.expires_at:'',enrollment_count:Number.isSafeInteger(profile.enrollment_count)&&profile.enrollment_count>=0?profile.enrollment_count:0};
}
function renderAgentFleetProfiles(){
  const container=$('#agent-fleet-profiles');if(!container)return;
  if(agentFleetProfileError){container.innerHTML=`<p class="inline-notice warning">${h(agentFleetProfileError)}</p>`;return;}
  const start=agentFleetProfiles.length?agentFleetProfileOffset+1:0,end=agentFleetProfiles.length?agentFleetProfileOffset+agentFleetProfiles.length:0;
  container.innerHTML=(agentFleetProfiles.map(profile=>`<article class="inline-notice"><strong>${h(profile.name)}</strong><p>${h(profile.status)} · ${profile.enrollment_count} enrolled · expires ${h(timestamp(profile.expires_at))}</p>${profile.status==='active'?`<button type="button" class="button secondary small" data-action="agent-fleet-revoke" data-id="${h(profile.id)}" ${agentFleetProfileLoading?'disabled':''}>Revoke enrollment key</button>`:''}</article>`).join('')||`<p class="help-text">${agentFleetProfileLoading?'Loading enrollment profiles…':'No fleet enrollment profiles on this page.'}</p>`)+`<div class="toolbar-group"><span>${start}–${end} of ${agentFleetProfileTotal} profiles</span><button type="button" class="text-button" data-action="agent-fleet-previous" ${agentFleetProfileLoading||agentFleetProfileOffset===0?'disabled':''}>Previous</button><button type="button" class="text-button" data-action="agent-fleet-next" ${agentFleetProfileLoading||end>=agentFleetProfileTotal?'disabled':''}>Next</button></div>`;
}
async function loadAgentFleetProfiles(offset=agentFleetProfileOffset){
  if(!canWrite()||state.authConfig?.mode==='demo')return;
  const epoch=agentInstallationEpoch,identity=agentInstallationIdentity(),sequence=++agentFleetListSequence;
  agentFleetProfileLoading=true;agentFleetProfileError='';renderAgentFleetProfiles();
  try{
    const result=await api('/agent-installation/fleet-profiles?limit='+agentFleetProfileLimit+'&offset='+offset,{cache:'no-store'});
    if(!agentInstallationCurrent(epoch,identity)||sequence!==agentFleetListSequence)return;
    if(!Array.isArray(result.items)||!Number.isSafeInteger(result.total)||result.total<0||result.items.length>agentFleetProfileLimit)throw new Error('The controller returned an invalid enrollment profile page.');
    agentFleetProfiles=result.items.map(agentFleetPublicProfile);agentFleetProfileTotal=result.total;agentFleetProfileOffset=offset;
  }catch(error){if(agentInstallationCurrent(epoch,identity)&&sequence===agentFleetListSequence)agentFleetProfileError='Enrollment profiles could not be loaded. Refresh to try again.';}
  finally{if(agentInstallationCurrent(epoch,identity)&&sequence===agentFleetListSequence){agentFleetProfileLoading=false;renderAgentFleetProfiles();}}
}
async function agentFleetAction(button){
  if(!canWrite()||state.authConfig?.mode==='demo'||button.disabled)return;
  const action=button.dataset.action;
  if(action==='agent-fleet-refresh')return loadAgentFleetProfiles();
  if(action==='agent-fleet-previous')return loadAgentFleetProfiles(Math.max(0,agentFleetProfileOffset-agentFleetProfileLimit));
  if(action==='agent-fleet-next'){if(agentFleetProfileOffset+agentFleetProfileLimit<agentFleetProfileTotal)return loadAgentFleetProfiles(agentFleetProfileOffset+agentFleetProfileLimit);return;}
  if(action!=='agent-fleet-revoke')return;
  const profile=agentFleetProfiles.find(item=>item.id===button.dataset.id&&item.status==='active');if(!profile)return;
  const epoch=agentInstallationEpoch,identity=agentInstallationIdentity();button.disabled=true;agentFleetListSequence++;agentFleetProfileLoading=false;
  try{
    const response=await api('/agent-installation/fleet-profiles/'+encodeURIComponent(profile.id)+'/revoke',{method:'POST',cache:'no-store',body:{}});
    if(!agentInstallationCurrent(epoch,identity))return;
    const updated=agentFleetPublicProfile(response);if(updated.id!==profile.id||updated.status!=='revoked')throw new Error('The controller did not confirm enrollment-key revocation.');
    agentFleetListSequence++;agentFleetProfileLoading=false;
    agentFleetProfiles=agentFleetProfiles.map(item=>item.id===updated.id?updated:item);renderAgentFleetProfiles();toast('Enrollment key revoked. Existing enrolled servers remain connected.');
  }catch(error){if(agentInstallationCurrent(epoch,identity))formError(error);}
  finally{if(agentInstallationCurrent(epoch,identity))button.disabled=false;}
}
function validateAgentInstallationKit(kit,mode,profile,installationOptions,managementSources=[]){
  const expected=installationOptions?3:mode==='fleet'?2:1;
  if(kit?.schema_version!==expected||typeof kit.enrollment_token!=='string'||!kit.enrollment_token||!Number.isFinite(Date.parse(kit.expires_at))||Date.parse(kit.expires_at)<=Date.now())throw new Error('The controller did not return a fresh setup file. Generate another file.');
  if(installationOptions){
    const actual=kit.installation_options;
    if(!actual||Object.keys(actual).length!==2||actual.install_dependencies!==installationOptions.install_dependencies||actual.ufw_action!==installationOptions.ufw_action)throw new Error('The controller changed the selected preparation options. Review and download a new setup.');
  }else if(Object.hasOwn(kit,'installation_options'))throw new Error('The controller returned preparation that was not selected.');
  if(mode==='fleet'){
    const publicProfile=agentFleetPublicProfile(profile);
    if(kit.enrollment_profile_id!==publicProfile.id||kit.expected_hostname||publicProfile.status!=='active'||publicProfile.expires_at!==kit.expires_at)throw new Error('The controller returned an inconsistent fleet setup file.');
  }else if(Object.hasOwn(kit,'enrollment_profile_id'))throw new Error('The controller returned fleet identity data for individual setup.');
  if(!kit.config||['enforce','allow_firewall_changes','learning_auto_allow','unexpected_port_monitor_enabled'].some(key=>kit.config[key]!==false)||['allow_host_default_deny','allow_single_admin_pilot'].some(key=>kit.config[key]===true))throw new Error('The controller returned a setup file outside the monitor-only setup defaults.');
  const actual=kit.config.management_sources??[];
  if(!Array.isArray(actual)||actual.length>100||actual.some(value=>typeof value!=='string')||JSON.stringify([...actual].sort())!==JSON.stringify([...managementSources].sort()))throw new Error('The controller changed the reviewed management source pins. Review and download a new setup.');
}
async function agentInstallationSubmit(event){
  event.preventDefault();if(!canWrite()||state.authConfig?.mode==='demo')return;
  const form=event.target,button=$('button[type="submit"]',form),epoch=agentInstallationEpoch,draft=agentInstallationDraft,identity=agentInstallationIdentity();if(button.disabled)return;button.disabled=true;
  const current=()=>agentInstallationCurrent(epoch,identity)&&draft===agentInstallationDraft&&form.isConnected!==false;
  try{
    const mode=agentInstallationMode(form),payload=agentInstallationPayload(form),caFile=$('#agent-install-ca').files?.[0];
    if(caFile){
      if(caFile.size>128*1024)throw new Error('The public HTTPS CA chain must be at most 128 KiB.');
      const pem=await caFile.text();if(!current()||$('#agent-install-ca').files?.[0]!==caFile)return;
      if(pem.length>128*1024||!pem.includes('-----BEGIN CERTIFICATE-----')||/PRIVATE KEY|PKCS12/i.test(pem))throw new Error('Upload a PEM public certificate chain without any private key.');
      payload.controller_ca_pem=pem;
    }
    if(!current())return;
    const response=await api(mode==='fleet'?'/agent-installation/fleet-profiles':'/agent-installation/kit',{method:'POST',cache:'no-store',body:payload});
    if(!current())return;
    const kit=mode==='fleet'?response?.kit:response;validateAgentInstallationKit(kit,mode,response?.profile,payload.installation_options,payload.management_sources||[]);
    const blob=new Blob([JSON.stringify(kit,null,2)+'\n'],{type:'application/json'}),url=URL.createObjectURL(blob),link=document.createElement('a');
    try{link.href=url;link.download='prthak-agent-setup.json';link.click();}finally{setTimeout(()=>URL.revokeObjectURL(url),1000);}
    $('#agent-installation-result').innerHTML=`<div class="inline-notice">Private setup file downloaded. Expires ${h(timestamp(kit.expires_at))}. ${mode==='fleet'?'Reuse this file on any number of servers before expiry. Each server creates its own identity. Keep the shared enrollment key private.':'Use it for one endpoint; generate a different file for the next server.'}</div>`;
    toast(mode==='fleet'?'Reusable fleet setup file downloaded.':'Private endpoint setup file downloaded.');
    if(mode==='fleet')await loadAgentFleetProfiles(0);
  }catch(error){if(current())formError(error);}finally{if(current())button.disabled=false;}
}
document.addEventListener('click',event=>{const button=event.target.closest?.('[data-agent-release-asset]');if(button)downloadTokenAgentAsset(button);});
document.addEventListener('click',event=>{const button=event.target.closest?.('[data-action^="agent-fleet-"]');if(button){event.preventDefault();agentFleetAction(button);}});
document.addEventListener('input',event=>{if(String(event.target.id||'').startsWith('agent-install-')&&event.target.id!=='agent-install-mode')agentInstallationChange(event);});

let endpointConfigurationReviews=[];
const endpointConfigurationFlags=['enforce','allow_firewall_changes','learning_auto_allow','unexpected_port_monitor_enabled','allow_host_default_deny'];
const endpointConfigurationFlagLabels=['Managed policy enforcement','Supported imported-rule changes','Automatic learned access (requires enforcement and an enabled learning session)','Unexpected-port log instrumentation','Whole-server default-deny opt-in (does not enable it; a separate acknowledged push is required)'];
function endpointConfigurationServers(){return (state.data?.servers||[]).filter(server=>server.configuration_state&&server.capabilities?.includes('endpoint_configuration_v1'));}
function endpointConfigurationFields(server){
  const current=server.configuration_state,urls=['controller_url','control_url','discovery_url'];
  return `<div class="inline-notice">An Admin creates the exact signed configuration kit. Root must apply it locally on this endpoint before its security opt-ins or URLs change. Existing identity/signing trust stay pinned. Turning off an opt-in retains committed firewall rules; remove those through their reviewed workflow first.</div>${urls.map(key=>`<div class="field"><label for="endpoint-${key}">${h(key.replaceAll('_',' '))}</label><input id="endpoint-${key}" name="${key}" type="url" value="${h(current[key]||'')}" ${key==='controller_url'?'required':''}><small>${key==='controller_url'?'Public management origin.':'Blank retains combined management-origin fallback.'}</small></div>`).join('')}<div class="field"><label>Local security opt-ins</label>${endpointConfigurationFlags.map((key,index)=>`<label class="host-check"><input type="checkbox" name="${key}" ${current[key]===true?'checked':''}>${h(endpointConfigurationFlagLabels[index])}</label>`).join('')}</div><p class="help-text">Whole-server default deny additionally requires the host_default_deny_v1 agent capability. Upgrade older endpoints first. This local opt-in alone does not block other ports; review and push the exact ingress bundle under Policies.</p><div class="field"><label for="endpoint-management-sources">Protected management source IPs / CIDRs</label><textarea id="endpoint-management-sources" name="management_sources" rows="2" placeholder="10.90.0.0/24">${h((current.management_sources||[]).join('\n'))}</textarea><small>Explicit trusted administration sources. Unrestricted /0 protection is refused.</small></div><div class="field-row"><div class="field"><label for="endpoint-ssh-ports">Actual SSH ports</label><input id="endpoint-ssh-ports" name="protected_ssh_ports" value="${h((current.protected_ssh_ports||[]).join(', '))}" placeholder="22, 2022"><small>Include every discovered SSH listener.</small></div><div class="field"><label for="endpoint-zone">Firewalld zone</label><input id="endpoint-zone" name="zone" value="${h(current.zone||'')}" maxlength="100" placeholder="public"></div></div><div class="field"><label for="endpoint-transition-ca">Optional replacement public HTTPS CA bundle</label><input id="endpoint-transition-ca" name="controller_ca" type="file" accept=".pem,.crt,.cer"><small>Empty preserves current trust. For CA rotation stage an approved old+new public CA bundle before switching certificates. Endpoint issuer and assignment signing keys remain unchanged.</small></div><label class="host-check"><input type="checkbox" name="retain_old_origin">I confirm old and proposed origins remain reachable for the same deployment throughout migration.</label><p class="help-text">Both control origins must accept the existing mTLS identity. Physical DNS/LB/alias setup is external. A 90-second independent timer restores previous config/trust unless the new daemon reports this exact configuration.</p>`;
}
async function showEndpointConfiguration(id=''){
  if(!canWrite())return;
  try{
    endpointConfigurationReviews=(await api('/agent-installation/configuration')).items||[];
    const servers=endpointConfigurationServers();
    showModal('Review endpoint configuration',`<form id="endpoint-configuration-form"><div class="modal-body">${errorSlot}<div class="field"><label for="endpoint-config-server">Enrolled endpoint</label><select id="endpoint-config-server" name="server_id" required><option value="">Choose a fresh endpoint</option>${servers.map(server=>`<option value="${h(server.id)}" ${server.id===id?'selected':''}>${h(server.hostname)} · ${h((server.ips||[]).join(', '))}</option>`).join('')}</select><small>Upgrade/report endpoint_configuration_v1 first if a server is missing.</small></div><div id="endpoint-config-fields">${servers.some(server=>server.id===id)?endpointConfigurationFields(servers.find(server=>server.id===id)):''}</div><div class="section-line"><h3>Immutable configuration reviews</h3></div>${endpointConfigurationReviews.map(plan=>`<article class="inline-notice"><strong>${h(plan.scope.hostname)}</strong> · ${h(plan.status)}<p class="mono">${h(plan.id)}</p><p>Expires ${h(timestamp(plan.expires_at))}</p><button type="button" class="button secondary small" data-action="endpoint-configuration-review" data-id="${h(plan.id)}">Open exact review</button></article>`).join('')||'<p class="help-text">No configuration reviews.</p>'}</div><div class="modal-footer"><button type="button" class="button secondary" data-action="close-modal">Close</button><button type="submit" class="button primary" ${!servers.length?'disabled':''}>Create signed configuration kit</button></div></form>`,'SIGNED ENDPOINT CONFIGURATION');
  }catch(error){toast(error.message||'Could not load configuration reviews.');}
}
function endpointConfigurationPayload(form){
  const data=new FormData(form),get=key=>String(data.get(key)||'').trim();
  const settings={};for(const key of ['controller_url','control_url','discovery_url'])settings[key]=get(key);
  for(const key of endpointConfigurationFlags)settings[key]=data.get(key)==='on';
  settings.management_sources=get('management_sources').split(/[\s,]+/).filter(Boolean);
  const ports=get('protected_ssh_ports').split(/[\s,]+/).filter(Boolean);
  if(ports.some(value=>!/^\d+$/.test(value)||Number(value)<1||Number(value)>65535)||new Set(ports.map(Number)).size!==ports.length)throw new Error('Choose distinct actual SSH ports 1-65535.');
  settings.protected_ssh_ports=ports.map(Number);settings.zone=get('zone');
  return {server_id:get('server_id'),settings,controller_ca_pem:'',retain_old_origin:Boolean(data.get('retain_old_origin'))};
}
function showEndpointConfigurationReview(plan){
  const stage=plan.approval?.stage,active=plan.status!=='revoked'&&Date.parse(plan.expires_at)>Date.now(),ready=active&&stage==='approved';
  showModal('Signed endpoint configuration',`<div class="modal-body">${errorSlot}<p><strong>${h(plan.scope.hostname)}</strong> · ${h(plan.status)} · expires ${h(timestamp(plan.expires_at))}</p><p>Admin: ${h(plan.approval?.requester?.display_name||plan.approval?.requester?.user_id||'Unavailable')}.</p><pre class="detail-json">${h(JSON.stringify(plan.scope,null,2))}</pre><p class="help-text">Creating this kit does not change the running daemon. Root must apply it locally; existing endpoint identity, management protection and rollback remain in effect.</p>${ready?`<button type="button" class="button primary" data-action="endpoint-configuration-download" data-id="${h(plan.id)}">Download signed configuration kit</button><p>Transfer as root-owned 0600 to /root/prthak-endpoint-configuration.json, then run the verified automatic installer:</p><code class="setup-code">sudo ./scripts/install-agent-auto.sh --configuration-file /root/prthak-endpoint-configuration.json</code>`:active?'<p class="inline-notice warning">This historical review cannot create a new kit. Create a fresh endpoint configuration.</p>':''}${active?`<p><button type="button" class="button secondary small" data-action="endpoint-configuration-revoke" data-id="${h(plan.id)}">Revoke uncommitted configuration kit</button></p>`:''}</div><div class="modal-footer"><button type="button" class="button secondary" data-action="endpoint-configuration">Back to configuration</button></div>`,'EXACT SIGNED SCOPE');
}
async function endpointConfigurationAction(button){
  const action=button.dataset.action,id=button.dataset.id;
  if(!canWrite())return;
  if(action==='endpoint-configuration'){await showEndpointConfiguration(id);return;}
  if(action==='endpoint-configuration-review'){const plan=endpointConfigurationReviews.find(item=>item.id===id);if(plan)showEndpointConfigurationReview(plan);return;}
  try{
    if(action==='endpoint-configuration-revoke'){await api('/agent-installation/configuration/'+encodeURIComponent(id)+'/revoke',{method:'POST',body:{}});toast('Configuration authority revoked; committed state requires a new reviewed change.');await showEndpointConfiguration();}
    if(action==='endpoint-configuration-download'){
      const kit=await api('/agent-installation/configuration/'+encodeURIComponent(id)+'/kit',{method:'POST',cache:'no-store',body:{}});
      if(kit?.schema_version!==1||kit.manifest?.kind!=='prthak-endpoint-configuration-v1'||kit.manifest?.approval?.stage!=='approved'||!kit.signature)throw new Error('The controller did not return exact Admin-authorized configuration.');
      const url=URL.createObjectURL(new Blob([JSON.stringify(kit,null,2)+'\n'],{type:'application/json'})),link=document.createElement('a');try{link.href=url;link.download='prthak-endpoint-configuration.json';link.click();}finally{setTimeout(()=>URL.revokeObjectURL(url),1000);}toast('Signed data-only configuration kit downloaded. Apply it on its exact endpoint before expiry.');
    }
  }catch(error){toast(error.message||'Configuration action failed.');}
}
document.addEventListener('click',event=>{const button=event.target.closest?.('[data-action^="endpoint-configuration"]');if(button){event.preventDefault();endpointConfigurationAction(button);}});
document.addEventListener('change',event=>{if(event.target.id==='endpoint-config-server'){const server=endpointConfigurationServers().find(item=>item.id===event.target.value);$('#endpoint-config-fields').innerHTML=server?endpointConfigurationFields(server):'';}});
async function endpointConfigurationSubmit(event){
  const form=event.target;if(form.id!=='endpoint-configuration-form')return;event.preventDefault();event.stopImmediatePropagation?.();if(!canWrite())return;
  const button=$('button[type="submit"]',form);if(button)button.disabled=true;
  try{
    let plan;
    if(form.id==='endpoint-configuration-form'){
      const payload=endpointConfigurationPayload(form),file=$('#endpoint-transition-ca')?.files?.[0];
      if(file){if(file.size>128*1024)throw new Error('Public CA bundle must be at most 128 KiB.');payload.controller_ca_pem=await file.text();if(/PRIVATE KEY|PKCS12/i.test(payload.controller_ca_pem))throw new Error('Public CA certificates only.');}
      plan=await api('/agent-installation/configuration/preview',{method:'POST',body:payload});
    }
    endpointConfigurationReviews=[plan,...endpointConfigurationReviews.filter(item=>item.id!==plan.id)];showEndpointConfigurationReview(plan);
  }catch(error){formError(error);}finally{if(button)button.disabled=false;}
}
document.addEventListener('submit',endpointConfigurationSubmit);
