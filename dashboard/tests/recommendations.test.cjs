const test=require('node:test');
const assert=require('node:assert/strict');
const R=require('../recommendations.js');
const row=(id,server_id,port,source_ip,protocol='tcp')=>({id,server_id,hostname:server_id,port,protocol,source_ip,count:2});
test('recommendation summaries preserve every exact destination, protocol and allowed source association',()=>{
 const data=[row('a-web','a',8080,'192.0.2.1'),row('a-ssh','a',2022,'192.0.2.2'),row('b-db','b',5432,'192.0.2.3'),row('a-udp','a',8080,'192.0.2.4','udp'),row('a-web2','a',8080,'192.0.2.1')];
 const result=R.servicesByServer(data);
 assert.deepEqual(result,[{server_id:'a',services:[{port:2022,protocol:'tcp',sources:['192.0.2.2'],row_ids:['a-ssh']},{port:8080,protocol:'tcp',sources:['192.0.2.1'],row_ids:['a-web','a-web2']},{port:8080,protocol:'udp',sources:['192.0.2.4'],row_ids:['a-udp']}]},{server_id:'b',services:[{port:5432,protocol:'tcp',sources:['192.0.2.3'],row_ids:['b-db']}]}]);
 assert.equal(result[1].services.some(service=>service.port===8080),false);
 assert.deepEqual(data[0],row('a-web','a',8080,'192.0.2.1'),'input evidence stays immutable');
});
test('evidence selection fails for unknown or invalid rows rather than silently broadening scope',()=>{
 const rows=[row('valid','a',443,'192.0.2.1'),row('bad','a',0,'192.0.2.1')];
 assert.deepEqual(R.selectedRows(rows,['valid','valid']),[rows[0]]);
 assert.throws(()=>R.selectedRows(rows,[]),/Select at least/);
 assert.throws(()=>R.selectedRows(rows,['valid','unknown']),/selection changed/);
 assert.throws(()=>R.selectedRows(rows,['bad']),/selection changed/);
 assert.throws(()=>R.servicesByServer([rows[1]]),/invalid exact/);
});
test('target choices keep explicit server IDs and group IDs separate and never infer the fleet',()=>{
 assert.deepEqual(R.targetIds('servers',['a','a','b'],['database-group']),{server_ids:['a','b'],group_ids:[]});
 assert.deepEqual(R.targetIds('groups',['a'],['database-group','database-group']),{server_ids:[],group_ids:['database-group']});
 assert.throws(()=>R.targetIds('servers',[],['database-group']),/target server/);
 assert.throws(()=>R.targetIds('groups',['a'],[]),/target server group/);
 assert.throws(()=>R.targetIds('all',['a'],['database-group']),/Choose selected/);
});
test('CSV export preserves exact observations and safely quotes spreadsheet formula-like metadata',()=>{
 const rows=[{...row('x','a',8443,'2001:db8::1'),hostname:'=SUM(1,2)',first_seen:'2026-10-30T10:00:00Z',last_seen:'2026-10-30T10:05:00Z',verdicts:['allowed','denied']},{...row('y','b',5432,'192.0.2.3'),hostname:'db "primary"\nMumbai'}];
 const csv=R.evidenceCSV(rows);
 assert.match(csv,/"'\=SUM\(1,2\)"/);assert.match(csv,/"db ""primary""\nMumbai"/);
 assert.match(csv,/"2001:db8::1","8443","tcp","2"/);assert.match(csv,/"allowed \| denied"/);
 assert.ok(csv.endsWith('\r\n'));assert.equal(rows[0].hostname,'=SUM(1,2)');
});
