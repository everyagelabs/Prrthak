(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.PrithakManaged = api;
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';
  const states = {
    preview:['Preview only','neutral'], pending_approval:['Pending delivery','warning'], draft:['Draft review','neutral'],
    awaiting_second_confirmation:['Second confirmation required','warning'], queued:['Authorized · awaiting agent','warning'],
    pending:['Pending agent','warning'], staging:['Staging runtime rules','learning'],
    runtime_healthchecking:['Checking runtime health','learning'], runtime_health_checking:['Checking runtime health','learning'],
    healthchecking:['Checking runtime health','learning'], committing:['Committing permanent rules','learning'],
    enforced:['Enforced · agent verified',''], applied:['Applied · agent reported',''],
    rolled_back:['Rolled back','warning'], removed:['Managed rules removed · verified','neutral'], error:['Failed','danger'], failed:['Failed','danger'], conflict:['Snapshot conflict','danger'],
    completed:['Completed','neutral'], completed_with_errors:['Completed with errors','danger'], cancelled:['Cancelled','neutral'],
    expired:['Expired','neutral'], invalidated:['Bindings changed','danger'], synced:['Current · reported',''], unknown:['Not reported','neutral']
  };
  const editable = ['draft','awaiting_second_confirmation'];
  const str = value => String(value ?? '');
  function label(value) { return (states[value] || [str(value).replaceAll('_',' ') || 'Not reported'])[0]; }
  function tone(value) { return (states[value] || states.unknown)[1]; }
  function policy(record={}) { return record.policy || record.configuration || record; }
  function normalized(value) {
    if (Array.isArray(value)) return value.map(normalized).sort((a,b)=>JSON.stringify(a).localeCompare(JSON.stringify(b)));
    if (value && typeof value==='object') return Object.fromEntries(Object.keys(value).sort().map(key=>[key,normalized(value[key])]));
    return value;
  }
  function policyConfiguration(record={}) {
    const value=policy(record);
    if(record.summary_only===true || value.summary_only===true) throw new Error('Load the exact immutable policy revision before reviewing its configuration.');
    return {name:value.name || '',mode:value.mode || 'monitor',selector:normalized(value.selector || {}),group_ids:normalized(value.group_ids || []),services:normalized(value.services || [])};
  }
  function exactPolicy(record,id,number) {
    const value=policy(record || {});
    if(!record || record.summary_only===true || value.summary_only===true || value.sources_omitted===true || value.id!==id || !Number.isInteger(Number(value.revision)) || Number(value.revision)<=0 || (number!==undefined && Number(value.revision)!==Number(number)) || !Array.isArray(value.services) || value.services.some(service=>!service||service.sources_omitted===true||!Array.isArray(service.sources)))throw new Error('Exact policy revision identity or configuration is unavailable. Refresh the review.');
    return record;
  }
  function exactRollout(plan,id) {
    if(!plan || plan.summary_only===true || plan.id!==id || !Array.isArray(plan.server_ids) || !plan.server_ids.length || !plan.bindings || !Array.isArray(plan.preview?.targets || plan.targets))throw new Error('Load the exact frozen managed review before continuing.');
    return plan;
  }
  function exactBundle(record,id,number) {
    const value=record?.bundle || record;
    if(!record || record.summary_only===true || value?.summary_only===true || value?.server_id!==id || Number(value?.version)!==Number(number) || !Array.isArray(value?.services))throw new Error('Exact endpoint bundle identity or configuration is unavailable.');
    return record;
  }
  function compare(before={},after={}) {
    const a=policyConfiguration(before), b=policyConfiguration(after);
    return Object.keys(a).filter(key=>JSON.stringify(a[key])!==JSON.stringify(b[key])).map(field=>({field,before:a[field],after:b[field]}));
  }
  function revision(record={}) { return Number(record.revision ?? policy(record).revision) || 0; }
  function orderedHistory(items=[]) { return [...items].sort((a,b)=>revision(b)-revision(a)); }
  function bindings(plan={}) {
    const values=Array.isArray(plan.targets)?plan.targets:Array.isArray(plan.preview?.targets)?plan.preview.targets:[];
    const indexed=new Map(values.map(value=>[value.server_id || value.id,value]));
    return (plan.server_ids || []).map(server_id=>{
      const binding=plan.bindings?.[server_id] || plan.bundles?.[server_id] || indexed.get(server_id) || {};
      return {...indexed.get(server_id),...binding,server_id,version:Number(binding.version ?? binding.desired_version)||0,digest:str(binding.digest || binding.bundle_digest),protection_digest:str(binding.protection_digest || binding.protected_config_digest)};
    });
  }
  function hasBindings(plan) { const targets=bindings(plan); return targets.length>0 && targets.every(target=>Number.isInteger(target.version) && target.version>0 && /^[a-f0-9]{64}$/i.test(target.digest) && /^[a-f0-9]{64}$/i.test(target.protection_digest)); }
  function isExpired(plan,now=Date.now()) { const expiry=Date.parse(plan.expires_at);return Number.isFinite(expiry)&&expiry<=now; }
  function blockers(plan={}) { return [...(plan.blockers || []),...(plan.preview?.targets || []).flatMap(target=>target.blockers || [])]; }
  function canConfirm(plan,role,now=Date.now()) { return !!plan && plan.summary_only!==true && ['admin','super_admin'].includes(role) && editable.includes(plan.status) && Number(plan.confirmation_count)===(plan.status==='draft'?0:1) && !isExpired(plan,now) && !!plan.confirmation_nonce && hasBindings(plan) && blockers(plan).length===0; }
  function secondConfirmation(plan) { return plan.status==='awaiting_second_confirmation'; }
  function confirmationBody(plan,typed='') {
    if(plan.summary_only===true)throw new Error('Load the exact frozen managed review before confirming it.');
    if (!plan.confirmation_nonce) throw new Error('The review has no current confirmation nonce. Refresh the plan.');
    const body={confirmation_nonce:plan.confirmation_nonce};
    if (secondConfirmation(plan)) {
      if (!plan.confirmation_phrase || typed!==plan.confirmation_phrase) throw new Error('Type the exact displayed confirmation phrase to authorize these bundles.');
      body.challenge=typed;
    }
    return body;
  }
  function outcomeState(report={}) { return report.status==='enforced' && report.intent==='remove_managed_rules'?'removed':report.status || 'unknown'; }
  function resultCounts(plan={}) { if(plan.summary_only===true)return {...plan.result_counts};const counts={};Object.entries(plan.results || {}).forEach(([id,result])=>{const target=(plan.preview?.targets || []).find(item=>item.server_id===id);const status=outcomeState({...result,intent:result.intent || target?.intent});counts[status]=(counts[status] || 0)+1;});return counts; }
  function protection(server={}) { const value=server.protection || server.managed_protection || server.management_protection || server.managed_enforcement?.protection || {};return {...value,digest:value.digest || server.protection_digest || '',blockers:value.blockers || value.blocking_reasons || []}; }
  function serverState(server={}) {
    const report=server.managed_enforcement || {};
    if (['enforced','applied'].includes(report.status) && Number(report.version)>0 && Number(server.desired_version)>0 && Number(report.version)!==Number(server.desired_version)) return 'pending_approval';
    return server.managed_policy_status || (report.status?outcomeState(report):server.apply_status) || 'unknown';
  }
  return {label,tone,policy,policyConfiguration,exactPolicy,exactRollout,exactBundle,compare,revision,orderedHistory,bindings,hasBindings,blockers,isExpired,canConfirm,secondConfirmation,confirmationBody,resultCounts,outcomeState,protection,serverState};
}));
