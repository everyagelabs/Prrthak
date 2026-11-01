(function(root,factory){
  const api=factory();
  if(typeof module==='object'&&module.exports)module.exports=api;
  else root.PrithakPlatform=api;
}(typeof globalThis!=='undefined'?globalThis:this,function(){
  'use strict';
  const tabs=[['overview','Overview'],['setup','Setup'],['cluster','Cluster'],['storage','Storage'],['backups','Backups'],['recovery','Recovery'],['services','Services'],['certificates','Certificates'],['agents','Agent polling'],['notifications','Notifications']];
  function canConfigure(role){return role==='super_admin';}
  function tab(value){return tabs.some(([key])=>key===value)||['demo','database','controllers'].includes(value)?value:'overview';}
  function connectionLabel(value){
    if(typeof value!=='string'||!value.trim())return 'Not configured';
    try{const parsed=new URL(value);if(!['postgres:','postgresql:','https:','http:'].includes(parsed.protocol))return 'Configured endpoint';return `${parsed.protocol}//${parsed.hostname}${parsed.port?':'+parsed.port:''}${parsed.pathname==='/'?'':parsed.pathname}`;}
    catch{return 'Configured endpoint';}
  }
  function health(value){return value===true||['healthy','ready','available','passed'].includes(value)?'healthy':value===false||['unhealthy','not_ready','unavailable','failed','error'].includes(value)?'unavailable':'unknown';}
  function reviewReady(plan,role,now=Date.now()){
    return canConfigure(role)&&!!plan&&typeof plan.id==='string'&&!!plan.id&&/^[a-f0-9]{64}$/i.test(plan.digest || '')&&Number.isFinite(Date.parse(plan.expires_at))&&Date.parse(plan.expires_at)>now&&plan.can_apply===true&&!(plan.blockers || []).length;
  }
  function exactPhrase(plan,typed){return typeof plan?.confirmation_phrase==='string'&&!!plan.confirmation_phrase&&typed===plan.confirmation_phrase;}
  function bytes(value){const size=Number(value);if(!Number.isFinite(size)||size<0)return 'Not reported';if(size<1024)return `${size} B`;if(size<1024*1024)return `${(size/1024).toFixed(1)} KB`;if(size<1024*1024*1024)return `${(size/1024/1024).toFixed(1)} MB`;return `${(size/1024/1024/1024).toFixed(1)} GB`;}
  return {tabs,canConfigure,tab,connectionLabel,health,reviewReady,exactPhrase,bytes};
}));
