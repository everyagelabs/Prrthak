(function (root, factory) {
  const api = factory(typeof module === 'object' && module.exports ? require('./filters.js') : root.PSegraFilters);
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.PrithakFirewall = api;
}(typeof globalThis !== 'undefined' ? globalThis : this, function (F) {
  'use strict';
  const string = value => typeof value === 'string' ? value : value == null ? '' : JSON.stringify(value);
  const kind = rule => String(rule.kind || '').replace(/-/g,'_');
  function action(rule) {
    if (rule.action) return String(rule.action).toLowerCase();
    if (['service','port'].includes(kind(rule))) return 'accept';
    const value = string(rule.value);
    if (/target/.test(kind(rule)) && /^(ACCEPT|DROP|REJECT)$/i.test(value)) return value.toLowerCase();
    return value.replace(/"[^"\\]*(?:\\.[^"\\]*)*"|'[^'\\]*(?:\\.[^'\\]*)*'/g,'""').match(/(?:^|\s)(accept|reject|drop)(?=\s|$)/i)?.[1]?.toLowerCase() || 'configured';
  }
  function risks(rule) {
    if (Array.isArray(rule.risk)) return rule.risk.map(String);
    if (rule.risk && typeof rule.risk==='object') return Object.entries(rule.risk).filter(([,value])=>value).map(([key])=>key);
    return rule.risk ? [String(rule.risk)] : [];
  }
  function highRisk(rule) { return risks(rule).some(risk=>/^(high|critical|any[_ -]?any|trusted|allow[_ -]?all)$/i.test(risk)) || (/target/.test(kind(rule))&&action(rule)==='accept'); }
  function anySource(rule) {
    if (['service','port','forward_port'].includes(kind(rule)) || /target/.test(kind(rule))) return true;
    if (kind(rule)==='rich_rule') {const raw=string(rule.value);if(/\bsource\s+address=["'](?:0\.0\.0\.0\/0|::\/0)["']/i.test(raw))return true;return !/\bsource\s+(?:not\s+)?(?:address|ipset|mac)=/i.test(raw);}
    if(kind(rule)==='direct'){const match=string(rule.value).match(/(?:^|\s)-s\s+(\S+)/);return !match||['0.0.0.0/0','::/0'].includes(match[1]);}
    return risks(rule).some(risk=>/any[_ -]?source|any[_ -]?any/i.test(risk));
  }
  function editable(rule) { return rule.editable===true && ['service','port','rich_rule','target','direct','forward_port'].includes(kind(rule)); }
  function removable(rule) { return editable(rule) && kind(rule)!=='target'; }
  function zoneLabel(rule) { return kind(rule)==='direct'?'Host INPUT · all zones':rule.zone||'Zone not reported'; }
  function editHint(rule) {
    return ({port:'Use a firewalld port or range with protocol, such as 8443/tcp.',service:'Use an existing firewalld service name. Its definition determines the actual ports.',target:'Choose ACCEPT, DROP, REJECT or default. Only the permanent target changes; runtime remains unchanged. No global reload is performed.',direct:'Supported INPUT filter only: ipv4|ipv6 filter INPUT priority [-s numeric-CIDR] -p tcp|udp [ -m tcp|udp ] --dport port-or-range -j ACCEPT|DROP|REJECT. Other chains, tables and arguments are blocked.',forward_port:'Local redirect only: port=8080:proto=tcp:toport=8443:toaddr=. Remote address routing remains read only.'})[kind(rule)] || 'Enter one supported firewalld rich rule. The controller validates it; unsupported syntax remains read only.';
  }
  function readOnlyReason(rule) { return rule.readonly_reason || rule.unsupported_reason || rule.reason || 'This imported rule type is inventory-only. Review it with the existing firewall management process.'; }
  function definition(snapshot, name) { return snapshot?.service_definitions?.[name] || snapshot?.services?.[name] || null; }
  function normalizePorts(values) {
    return (Array.isArray(values)?values:[]).map(value=>{
      if (typeof value==='string') {const match=value.match(/^(\d+(?:-\d+)?)\/(tcp|udp)$/i);return match?{port:match[1],protocol:match[2].toLowerCase()}:null;}
      if (Array.isArray(value)) return {port:String(value[0]),protocol:String(value[1]).toLowerCase()};
      if (value&&typeof value==='object') return {port:String(value.port??value.portid??''),protocol:String(value.protocol||'').toLowerCase()};
      return null;
    }).filter(value=>value && /^\d+(?:-\d+)?$/.test(value.port) && ['tcp','udp'].includes(value.protocol));
  }
  function ports(rule, snapshot) {
    const declared=normalizePorts(rule.ports);
    if (kind(rule)==='port') return normalizePorts([string(rule.value)]);
    if (kind(rule)==='service') {const found=definition(snapshot,string(rule.value));return normalizePorts(found?.ports || found || declared);}
    if (declared.length) return declared;
    if(kind(rule)==='direct'){const raw=string(rule.value),port=raw.match(/(?:^|\s)--dport\s+(\d+(?:[-:]\d+)?)(?:\s|$)/),protocol=raw.match(/(?:^|\s)-p\s+(tcp|udp)(?:\s|$)/);return port&&protocol?normalizePorts([`${port[1].replace(':','-')}/${protocol[1]}`]):[];}
    if(kind(rule)==='forward_port'){const match=string(rule.value).match(/^port=(\d+(?:-\d+)?):proto=(tcp|udp):/);return match?normalizePorts([`${match[1]}/${match[2]}`]):[];}
    if (kind(rule)==='rich_rule') {
      const raw=string(rule.value), match=raw.match(/\bport\s+port=["']([^"']+)["']\s+protocol=["'](tcp|udp)["']/i);
      if (match) return normalizePorts([`${match[1]}/${match[2]}`]);
      const service=raw.match(/\bservice\s+name=["']([^"']+)["']/i);
      if (service) {const found=definition(snapshot,service[1]);return normalizePorts(found?.ports||found);}
    }
    return [];
  }
  function coversAllPorts(rule) {
    return /target/.test(kind(rule)) || (kind(rule)==='rich_rule'&&!/\b(?:port\s+port|service\s+name|protocol\s+value|source-port\s+port)=?/i.test(string(rule.value)) && ['accept','drop','reject'].includes(action(rule)));
  }
  function matchesPorts(rule, selections, snapshot) {
    if (!selections?.length || coversAllPorts(rule)) return true;
    return ports(rule,snapshot).some(port=>selections.some(selection=>{const [selected,protocol]=selection.split('/');const [low,high]=port.port.split('-').map(Number);return Number(selected)>=low&&Number(selected)<=(high||low)&&(!protocol||protocol===port.protocol);}));
  }
  function actualRules(rule,snapshot) {return (snapshot?.rules||[]).filter(item=>{const same=rule.rule_key?item.logical_key===rule.rule_key:rule.logical_key?item.logical_key===rule.logical_key:kind(item)===kind(rule)&&string(item.value)===string(rule.value)&&(!rule.zone||item.zone===rule.zone);return same&&(!rule.scope||item.scope===rule.scope);});}
  function scopedRules(rules, servers, snapshots, filters, search='', serverId='all') {
    const byId=new Map(servers.map(server=>[server.id,server])),snapshotById=new Map((snapshots||[]).map(item=>[item.server_id,item.snapshot]));
    return (rules||[]).map(rule=>{
      const directSearch=!!search&&JSON.stringify([rule.zone,rule.kind,rule.value,rule.action,rule.risk]).toLowerCase().includes(search.toLowerCase());
      const matching=(rule.server_ids||[]).filter(id=>{const server=byId.get(id),snapshot=snapshotById.get(id),rows=actualRules(rule,snapshot);return server&&(serverId==='all'||serverId===id)&&F.matchServer(server,filters,{ignorePorts:true,search:directSearch?'':search})&&(rows.length?rows.some(item=>matchesPorts(item,filters.ports,snapshot)):matchesPorts(rule,filters.ports,snapshot));});
      let canEdit=rule.editable===true,reason=rule.reason||'';
      if(matching.length&&matching.every(id=>snapshotById.has(id)&&actualRules(rule,snapshotById.get(id)).length)){
        canEdit=matching.every(id=>{const snapshot=snapshotById.get(id),rows=actualRules(rule,snapshot).filter(item=>kind(rule)!=='target'||item.scope==='permanent');return snapshot.status==='ok'&&!snapshot.stale&&rows.length>0&&rows.every(item=>item.editable===true);});
        if(canEdit)reason='';else reason=matching.flatMap(id=>actualRules(rule,snapshotById.get(id))).find(item=>item.editable!==true)?.reason||'One or more selected endpoint snapshots are incomplete or stale.';
      }
      const crossScopeMismatch=!!filters.ports?.length&&matching.some(id=>actualRules(rule,snapshotById.get(id)).some(item=>!matchesPorts(item,filters.ports,snapshotById.get(id))));
      if(crossScopeMismatch){canEdit=false;reason='Different service ports are reported across configuration scopes. Clear the port filter and review the scope-specific definitions before preparing a shared change.';}
      return {...rule,editable:canEdit,...(kind(rule)==='target'?{editable_scopes:canEdit?['permanent']:[]}:{}),reason,matching_server_ids:matching,matching_host_count:matching.length};
    }).filter(rule=>rule.matching_host_count>0);
  }
  function scopedPlans(plans, servers, snapshots, filters, search='', serverId='all') {
    const byId=new Map(servers.map(server=>[server.id,server])),snapshotsById=new Map((snapshots||[]).map(item=>[item.server_id,item.snapshot]));
    return (plans||[]).map(plan=>{const preview=[...(plan.preview?.before||[]),...(plan.preview?.after||[])],direct=!!search&&JSON.stringify([plan.name,preview]).toLowerCase().includes(search.toLowerCase());const matching=(plan.server_ids||[]).filter(id=>{const server=byId.get(id);if(!server||(serverId!=='all'&&id!==serverId)||!F.matchServer(server,filters,{ignorePorts:true,search:direct?'':search}))return false;if(!filters.ports?.length)return true;return preview.filter(row=>row.server_id===id).some(row=>{const snapshot=snapshotsById.get(id),actual=actualRules(row,snapshot);return actual.length?actual.some(item=>matchesPorts(item,filters.ports,snapshot)):matchesPorts(row,filters.ports,snapshot);});});return {...plan,matching_server_ids:matching,matching_host_count:matching.length};}).filter(plan=>plan.matching_host_count>0);
  }
  function resultLabel(result={}) {return ({draft:'Draft only',not_reported:'No acknowledgement',expired:'Expired',invalidated:'Snapshot invalidated',awaiting_second_confirmation:'Final confirmation required',applied:'Applied',preview:'Preview only',failed:'Failed',error:'Failed',conflict:'Conflict',pending:'Pending agent',queued:'Queued',cancelled:'Cancelled',skipped:'Skipped'})[result.status] || string(result.status || 'Pending agent');}
  function restrictive(rule, operation, newValue) {
    if (operation==='remove') return ['accept','allow'].includes(action(rule));
    return ['drop','reject','deny'].includes(action({...rule,value:newValue,action:undefined}));
  }
  return {kind,action,risks,highRisk,anySource,editable,removable,zoneLabel,editHint,readOnlyReason,definition,ports,matchesPorts,actualRules,scopedRules,scopedPlans,resultLabel,restrictive,string};
}));
