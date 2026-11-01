(function(root,factory){const api=factory();if(typeof module==='object'&&module.exports)module.exports=api;else root.PrthakApprovals=api;}(typeof globalThis!=='undefined'?globalThis:this,function(){
  'use strict';
  function contextActor(context={}){return context.authType==='session'?'entra:'+context.userId:context.userId;}
  function canAct(plan={},context={}){
    if(!['admin','super_admin'].includes(context.role)||plan.summary_only===true||!['draft','reviewed','awaiting_second_confirmation'].includes(plan.status)||![0,1].includes(Number(plan.confirmation_count)))return false;
    const expiry=Date.parse(plan.expires_at);if(!Number.isFinite(expiry)||expiry<=Date.now())return false;
    const approval=plan.approval,actor=approval?.requester;if(!actor||!plan.confirmation_nonce)return false;
    if(approval.mode==='lab_only')return ['demo','token'].includes(context.authType)&&actor.actor===contextActor(context);
    return approval.mode==='single_admin'&&context.authType==='session'&&!!context.userId&&context.userId===actor.user_id&&context.tenantId===actor.tenant_id;
  }
  function explain(plan={}){
    if(!plan.approval)return 'Create a fresh exact change review before applying.';
    if(plan.approval.stage==='approved')return 'Admin action recorded. Endpoint verification and its actual result determine whether the change is applied.';
    if(!['single_admin','lab_only'].includes(plan.approval.mode))return 'Historical change record. Create a fresh review to make a new change.';
    if(Number(plan.confirmation_count)===1)return 'Final confirmation for this destructive or restrictive change. Recheck its exact scope and type the displayed phrase using the same Admin account.';
    return plan.requires_double_confirmation===true?'This destructive or restrictive change requires two explicit confirmations by the same Admin.':'Apply this exact reviewed change. Local endpoint opt-ins, management protections and rollback remain in effect.';
  }
  function phaseLabel(plan={}){
    if(plan.approval?.stage==='approved'||plan.status==='applied')return 'Admin action recorded';
    if(!['single_admin','lab_only'].includes(plan.approval?.mode))return 'Historical change';
    return Number(plan.confirmation_count)===1?'Final confirmation required':'Ready to apply';
  }
  function confirmationBody(plan,extra={},typed=''){
    if(!plan?.confirmation_nonce)throw new Error('Refresh the current change nonce.');
    const body={...extra,preview_id:plan.id,confirmation_nonce:plan.confirmation_nonce};
    if(plan.digest)body.digest=plan.digest;
    if(Number(plan.confirmation_count)===1||typed){if(!plan.confirmation_phrase||typed!==plan.confirmation_phrase)throw new Error('Type the exact displayed confirmation phrase.');body.challenge=typed;}
    return body;
  }
  return {canAct,explain,phaseLabel,confirmationBody};
}));
