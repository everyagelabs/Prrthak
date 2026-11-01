(function (root, factory) {
  const api=factory();
  if(typeof module==='object'&&module.exports)module.exports=api;
  else root.PrithakRecommendations=api;
}(typeof globalThis!=='undefined'?globalThis:this,function () {
  'use strict';
  function validRow(row) {
    return !!row&&typeof row.id==='string'&&!!row.id&&typeof row.server_id==='string'&&!!row.server_id&&typeof row.source_ip==='string'&&!!row.source_ip&&Number.isInteger(row.port)&&row.port>=1&&row.port<=65535&&['tcp','udp'].includes(row.protocol);
  }
  function selectedRows(rows,ids) {
    const wanted=new Set(ids),byId=new Map(rows.filter(validRow).map(row=>[row.id,row]));
    if(!wanted.size)throw new Error('Select at least one observed source and service row.');
    if([...wanted].some(id=>!byId.has(id)))throw new Error('The observed access selection changed. Refresh the evidence and select rows again.');
    return [...wanted].map(id=>byId.get(id));
  }
  function servicesByServer(rows) {
    const hosts=new Map();
    for(const row of rows){
      if(!validRow(row))throw new Error('Observed access contains an invalid exact server, source or service.');
      if(!hosts.has(row.server_id))hosts.set(row.server_id,new Map());
      const services=hosts.get(row.server_id),key=`${row.port}/${row.protocol}`;
      if(!services.has(key))services.set(key,{port:row.port,protocol:row.protocol,sources:new Set(),row_ids:new Set()});
      services.get(key).sources.add(row.source_ip);services.get(key).row_ids.add(row.id);
    }
    return [...hosts].sort(([a],[b])=>a.localeCompare(b)).map(([server_id,services])=>({server_id,services:[...services.values()].sort((a,b)=>a.port-b.port||a.protocol.localeCompare(b.protocol)).map(service=>({...service,sources:[...service.sources].sort(),row_ids:[...service.row_ids].sort()}))}));
  }
  function csvCell(value) {
    let text=String(value ?? '');
    // Spreadsheet applications interpret these leading characters as formulas.
    if(/^[=+\-@\t\r]/.test(text))text="'"+text;
    return '"'+text.replace(/"/g,'""')+'"';
  }
  function evidenceCSV(rows) {
    const columns=['server_id','hostname','source_ip','port','protocol','count','first_seen','last_seen','verdicts'];
    return [columns,...rows.map(row=>columns.map(column=>Array.isArray(row[column])?row[column].join(' | '):row[column]))].map(values=>values.map(csvCell).join(',')).join('\r\n')+'\r\n';
  }
  function targetIds(type,serverIds=[],groupIds=[]) {
    if(!['servers','groups'].includes(type))throw new Error('Choose selected servers or saved server groups.');
    const selected=[...new Set(type==='servers'?serverIds:groupIds)].filter(id=>typeof id==='string'&&id);
    if(!selected.length)throw new Error(type==='servers'?'Select at least one target server.':'Select at least one target server group.');
    return {server_ids:type==='servers'?selected:[],group_ids:type==='groups'?selected:[]};
  }
  return {validRow,selectedRows,servicesByServer,evidenceCSV,targetIds};
}));
