'use strict';

const accessRoles = ['read_only','admin','super_admin'];
function accessRole(value) { return accessRoles.includes(value)?value:'read_only'; }
function accessRoleLabel(value) { return ({read_only:'Read Only',admin:'Admin',super_admin:'Super Admin'})[accessRole(value)]; }
function canManageUsers() { return state.role==='super_admin'; }
function clearDashboardIdentity() {
  if(typeof platformClearCertificateUpload==='function')platformClearCertificateUpload();
  if(typeof clearAgentInstallation==='function')clearAgentInstallation();
  state.role='read_only';state.user=null;state.authType=null;state.csrfToken='';state.token='';
  state.accessUsers=[];state.accessLoaded=false;state.accessError='';state.serverDeletePlan=null;sessionStorage.removeItem('segment-token');
}
function applyDashboardIdentity(auth) {
  const previousIdentity=typeof platformCertificateUploadIdentity==='function'?platformCertificateUploadIdentity():null;
  const previousAgentIdentity=typeof agentInstallationIdentity==='function'?agentInstallationIdentity():null;
  const demo=auth.demo===true&&state.authConfig?.mode==='demo';
  state.role=demo?'super_admin':accessRole(auth.role);
  state.user=auth.user || null;state.authType=demo?'demo':auth.auth_type || (state.token&&state.authConfig?.mode==='tokens'?'token':null);
  state.csrfToken=typeof auth.csrf_token==='string'?auth.csrf_token:'';state.authError='';
  if(previousIdentity!==null&&previousIdentity!==platformCertificateUploadIdentity())platformClearCertificateUpload();
  if(previousAgentIdentity!==null&&previousAgentIdentity!==agentInstallationIdentity())clearAgentInstallation();
  if(!canManageUsers()){state.accessUsers=[];state.accessLoaded=false;state.accessError='';}
}
function microsoftMark() { return '<svg class="microsoft-mark" viewBox="0 0 20 20" aria-hidden="true"><path fill="#f25022" d="M1 1h8v8H1z"/><path fill="#7fba00" d="M11 1h8v8h-8z"/><path fill="#00a4ef" d="M1 11h8v8H1z"/><path fill="#ffb900" d="M11 11h8v8h-8z"/></svg>'; }
function showDashboardLogin() {
  const config=state.authConfig,entra=config?.mode==='entra',tokens=config?.mode==='tokens';
  let content;
  if(entra){
    content=`<div class="modal-body auth-signin-panel">${errorSlot}<div class="auth-emblem">${icon('access')}</div><h3>Your organisation. Your approved access.</h3><p>Sign in with Microsoft Entra ID using your organisation account. A Super Admin must grant your Prṛthak access first.</p>${state.authError?`<div class="form-error">${h(state.authError)}</div>`:''}${config.configured?`<button class="button microsoft-signin" data-action="auth-entra-login">${microsoftMark()}Sign in with Microsoft</button>`:'<div class="inline-notice warning">Microsoft Entra sign-in is not configured. Ask the deployment administrator to complete the tenant, application and callback configuration.</div>'}<div class="auth-role-chips"><span>Read Only</span><span>Admin</span><span>Super Admin</span></div><small>Your password and MFA are handled by Microsoft Entra ID. Prṛthak does not collect your directory password.</small></div>`;
  }else if(tokens){
    content=`<form id="login-form"><div class="modal-body">${errorSlot}<div class="inline-notice">Role-token authentication is enabled on this controller. Microsoft Entra sign-in must be configured separately.</div><p class="help-text">Enter a controller-issued role token. It is kept only in this browser tab.</p><div class="field"><label for="login-token">Access token</label><input id="login-token" name="token" type="password" autocomplete="off" required autofocus></div></div><div class="modal-footer"><button class="button primary" type="submit">Connect workspace</button></div></form>`;
  }else{
    content=`<div class="modal-body auth-signin-panel">${errorSlot}<div class="inline-notice warning">${h(state.authError || 'The controller authentication configuration is unavailable.')}</div><button class="button secondary" data-action="auth-retry">Retry sign-in configuration</button></div>`;
  }
  showModal('Sign in to Prṛthak',content,'SECURE WORKSPACE ACCESS');
}
async function dashboardLogout() {
  try {
    if(state.authType==='session')await api('/auth/logout',{method:'POST',body:{}});
  }catch(error){toast('Sign-out failed: '+error.message,true);return;}
  clearDashboardIdentity();state.data=null;state.lastSync=null;closeDrawer();renderChrome();
  $('#view-content').innerHTML=emptyHTML('Signed out','Sign in to view your infrastructure.','access');showLogin();
}
function accessConnectionHTML() {
  const config=state.authConfig || {},demo=config.mode==='demo',configured=!!config.configured;
  return `<section class="card access-connection"><div><span class="access-provider-icon">${microsoftMark()}</span><div><h2>Microsoft Entra ID</h2><p>${demo?'Synthetic demo workspace. No Microsoft directory connection is claimed.':configured?'Organisation sign-in is configured. Only approved users can enter this workspace.':'Entra sign-in is not configured on this controller.'}</p>${config.tenant_id?`<small>Tenant ID: <code>${h(config.tenant_id)}</code></small>`:''}</div></div>${badge(demo?'Demo':configured?'Configured':'Setup required',demo?'neutral':configured?'':'warning')}</section>`;
}
function accessHTML() {
  if(!canManageUsers())return emptyHTML('Super Admin access required','Only Super Admins can view or manage workspace users and role assignments.','access');
  const users=state.accessUsers || [],counts=Object.fromEntries(accessRoles.map(role=>[role,users.filter(user=>user.enabled!==false&&user.role===role).length]));
  return `${accessConnectionHTML()}<div class="access-role-grid">${accessRoles.map(role=>`<article class="card access-role-card"><span>${accessRoleLabel(role)}</span><strong>${format(counts[role])}</strong><p>${role==='read_only'?'View servers, policies, traffic and alerts.':role==='admin'?'Add, edit and delete infrastructure and policies.':'All Admin permissions, plus exclusive user and role management.'}</p></article>`).join('')}</div><div class="inline-notice">An Entra account establishes identity. A Super Admin grants application access and chooses one role. Directory groups, email addresses and token role claims do not grant Prṛthak access automatically.</div><div class="section-line"><h2>Approved workspace users<span>${format(users.length)} users</span></h2><div class="toolbar-group"><button class="button secondary small" data-action="access-refresh">${icon('refresh')}Refresh</button><button class="button primary small" data-action="access-user-new" ${!state.authConfig?.configured?'disabled':''}>${icon('plus')}Add Entra user</button></div></div>${state.accessError?`<div class="inline-notice warning" role="alert">${h(state.accessError)}</div>`:''}<section class="card"><div class="table-scroll"><table class="access-user-table"><thead><tr><th>User</th><th>Role</th><th>Access</th><th>Last sign-in</th><th></th></tr></thead><tbody>${users.map(user=>`<tr><td><strong>${h(user.display_name || user.email || 'Entra user')}${user.id===state.user?.id?' <span class="access-self">You</span>':''}</strong>${user.email?`<small>${h(user.email)}</small>`:''}<small>Object ID: <code>${h(user.object_id || '')}</code></small></td><td><span class="access-role-badge ${h(accessRole(user.role))}">${accessRoleLabel(user.role)}</span></td><td>${badge(user.enabled===false?'Disabled':'Enabled',user.enabled===false?'neutral':'')}</td><td>${h(timestamp(user.last_login_at || user.last_login))}<small>Microsoft Entra ID</small></td><td><div class="access-user-actions"><button class="text-button" data-action="access-user-edit" data-id="${h(user.id)}">Edit access</button><button class="text-button" data-action="access-user-revoke-review" data-id="${h(user.id)}">Revoke sessions</button></div></td></tr>`).join('') || `<tr><td colspan="5">${state.accessLoading?'Loading approved users…':'No users have been provisioned. Configure Entra and the initial Super Admin before granting access.'}</td></tr>`}</tbody></table></div></section><p class="help-text access-policy-note">Adding a user grants access to Prṛthak for an existing Entra identity; it does not create a Microsoft directory account. Disabling a user or changing their role takes effect on subsequent requests. Agent certificate authentication is managed separately.</p>`;
}
async function loadAccessUsers() {
  if(!canManageUsers() || state.accessLoading)return;
  state.accessLoading=true;
  try {const result=await api('/access/users');state.accessUsers=result.items || [];state.accessLoaded=true;state.accessError='';}
  catch(error){state.accessError=error.message;state.accessUsers=[];state.accessLoaded=false;}
  finally{state.accessLoading=false;if(state.view==='access'&&!$('#modal').open)render();}
}
function accessUserForm(id) {
  if(!canManageUsers())return;
  const user=id?(state.accessUsers || []).find(item=>item.id===id):null;if(id&&!user)return;
  const self=user?.id===state.user?.id;
  showModal(user?'Edit workspace access':'Add an existing Entra user',`<form id="access-user-form" data-id="${h(user?.id || '')}"><div class="modal-body">${errorSlot}<div class="inline-notice">Only Super Admins create or change workspace access. Use the immutable Object ID from the configured Entra tenant. Email is display information.</div><div class="field"><label for="access-object-id">Entra Object ID</label><input id="access-object-id" name="object_id" value="${h(user?.object_id || '')}" ${user?'readonly':'required'} placeholder="00000000-0000-0000-0000-000000000000"><small>Find this user's Object ID in Microsoft Entra ID → Users. Existing identity bindings cannot be changed.</small></div>${user?.tenant_id?`<p class="help-text">Tenant: <code>${h(user.tenant_id)}</code></p>`:''}<div class="field"><label for="access-display-name">Display name</label><input id="access-display-name" name="display_name" value="${h(user?.display_name || '')}" maxlength="200" autocomplete="off"></div><div class="field"><label for="access-email">Email (display only)</label><input id="access-email" name="email" value="${h(user?.email || '')}" type="email" maxlength="254" autocomplete="off"></div><div class="field"><label for="access-role">Workspace role</label><select id="access-role" name="role" ${self?'disabled':''}>${accessRoles.map(role=>`<option value="${role}" ${role===(user?.role || 'read_only')?'selected':''}>${accessRoleLabel(role)}</option>`).join('')}</select></div>${user?`<div class="field"><label for="access-enabled">Account access</label><select id="access-enabled" name="enabled" ${self?'disabled':''}><option value="true" ${user.enabled!==false?'selected':''}>Enabled</option><option value="false" ${user.enabled===false?'selected':''}>Disabled</option></select></div>`:''}${self?'<div class="inline-notice">Your own role and enabled status cannot be changed here. Ask another Super Admin to review that change.</div>':''}<p class="help-text">Read Only can view. Admin can manage infrastructure. Super Admin alone can grant or change any user's role. Existing sessions are checked against current access on each request.</p></div>${modalFooter(user?'Save access':'Grant workspace access')}</form>`,'SUPER ADMIN USER MANAGEMENT');
}
async function accessSubmit(event) {
  event.preventDefault();if(!canManageUsers())return;
  const form=event.target,submit=$('button[type="submit"]',form);submit.disabled=true;
  try {
    const values=new FormData(form),id=form.dataset.id,user=id?state.accessUsers.find(item=>item.id===id):null,self=user?.id===state.user?.id;
    const body={display_name:String(values.get('display_name') || '').trim(),email:String(values.get('email') || '').trim()};
    if(!self){body.role=String(values.get('role') || 'read_only');if(!accessRoles.includes(body.role))throw new Error('Choose one of the three workspace roles.');if(id)body.enabled=values.get('enabled')!=='false';}
    if(!id){body.object_id=String(values.get('object_id') || '').trim();if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(body.object_id))throw new Error('Enter the immutable Entra Object ID as a GUID.');}
    await api('/access/users'+(id?'/'+encodeURIComponent(id):''),{method:id?'PATCH':'POST',body});closeModal();await loadAccessUsers();toast(id?'Workspace access updated.':'Entra user access granted.');
  }catch(error){formError(error);}finally{submit.disabled=false;}
}
async function accessAction(button) {
  const {action,id}=button.dataset;
  if(action==='auth-entra-login'){if(state.authConfig?.mode==='entra'&&state.authConfig.configured)location.assign('/api/v1/auth/login');return;}
  if(action==='auth-retry'){state.authError='';try{state.authConfig=await api('/auth/config');showLogin();}catch(error){state.authError=error.message;showLogin();}return;}
  if(!canManageUsers())return;
  if(action==='access-refresh')return loadAccessUsers();
  if(action==='access-user-new')return accessUserForm();
  if(action==='access-user-edit')return accessUserForm(id);
  if(action==='access-user-revoke-review'){
    const user=state.accessUsers.find(item=>item.id===id);if(!user)return;
    showModal('Revoke active sessions?',`<div class="modal-body">${errorSlot}<p>Sign out all active Prṛthak sessions for <strong>${h(user.display_name || user.email || user.object_id)}</strong>.</p><p class="help-text">The account remains ${user.enabled===false?'disabled':'enabled'}. An enabled user can sign in again with Microsoft Entra ID.</p></div><div class="modal-footer"><button class="button secondary" data-action="close-modal">Cancel</button><button class="button danger" data-action="access-user-revoke-confirm" data-id="${h(id)}">Revoke sessions</button></div>`,'SESSION CONTROL');return;
  }
  if(action==='access-user-revoke-confirm'){
    button.disabled=true;try{await api('/access/users/'+encodeURIComponent(id)+'/revoke-sessions',{method:'POST',body:{}});if(id===state.user?.id){clearDashboardIdentity();state.data=null;closeModal();closeDrawer();renderChrome();$('#view-content').innerHTML=emptyHTML('Signed out','Your active sessions have been revoked. Sign in again to continue.','access');showLogin();}else{closeModal();await loadAccessUsers();toast('Active sessions revoked.');}}catch(error){formError(error);}finally{button.disabled=false;}
  }
}
