const assert = require('node:assert/strict');
const test = require('node:test');
const F = require('../filters.js');
const L=require('../locations.js');
L.setCatalog([{id:'loc-hyd',name:'Hyderabad',type:'datacenter'},{id:'loc-mum',name:'Mumbai',type:'datacenter'}]);
const servers = [
  {id:'billing-1',hostname:'billing-api-01',os:'ubuntu',status:'healthy',tags:{application:'billing',dc:'Hyderabad',network_zone:'production',criticality:'high',owner:'finance'},listeners:[{port:8443,protocol:'tcp'}],desired_version:2,applied_version:2,apply_status:'synced',collector_status:'learning'},
  {id:'billing-2',hostname:'billing-api-02',os:'rhel',status:'warning',tags:{application:'billing',dc:'Mumbai',network_zone:'production',criticality:'high',owner:'finance'},listeners:[{port:22,protocol:'tcp'}],desired_version:2,applied_version:1,apply_status:'preview',collector_status:'off',collector_desired_status:'learning'},
  {id:'web-1',hostname:'web-01',os:'rhel',status:'healthy',tags:{application:'payments',dc:'Hyderabad',network_zone:'production',criticality:'medium',owner:'platform'},listeners:[{port:8443,protocol:'udp'}],desired_version:3,applied_version:3,apply_status:'synced',collector_status:'learning',learning_stop_pending:true},
  {id:'stale-1',hostname:'stale',os:'rhel',status:'offline',tags:{application:'billing',dc:'Hyderabad'},listeners:[{port:8443,protocol:'tcp'}],collector_status:'learning'}
];
servers.forEach((server,index)=>{server.location_id=['loc-hyd','loc-mum','loc-hyd','loc-hyd'][index];server.location=L.find(server.location_id);});
test('AND across application + service + DC; OR for values in the same category',()=>{
  const filters=F.empty();filters.application=['billing'];filters.dc=['Hyderabad'];filters.ports=['8443/tcp'];
  assert.deepEqual(servers.filter(server=>F.matchServer(server,filters)).map(server=>server.id),['billing-1','stale-1']);
  filters.status=['healthy'];assert.deepEqual(servers.filter(server=>F.matchServer(server,filters)).map(server=>server.id),['billing-1']);
  filters.application.push('payments');filters.ports=['8443'];assert.deepEqual(servers.filter(server=>F.matchServer(server,filters)).map(server=>server.id),['billing-1','web-1']);
});
test('custom tag values are OR within key, AND across keys and free text',()=>{
  const filters=F.empty();F.addCustom(filters,'owner=finance, owner=platform, network_zone=production');filters.os=['ubuntu'];
  assert.equal(F.matchServer(servers[0],filters,{search:'billing-api'}),true);assert.equal(F.matchServer(servers[0],filters,{search:'web-01'}),false);assert.equal(F.matchServer(servers[2],filters),false);
  assert.deepEqual(filters.custom.owner,['finance','platform']);assert.deepEqual(filters.network_zone,['production']);assert.equal(F.count(filters),4);
});
test('ports validate range, optional protocol and duplicates',()=>{
  assert.deepEqual(F.parsePorts('8443, 53/UDP, 08443, 80/tcp'),['8443','53/udp','80/tcp']);
  for(const text of ['0','65536','22/sctp','80,','x','-1','1.5'])assert.throws(()=>F.parsePorts(text));
  assert.equal(F.matchesPorts(8443,'udp',['8443']),true);assert.equal(F.matchesPorts(8443,'udp',['8443/tcp']),false);
});
test('historical flows use flow service, not current listener, and destination tags',()=>{
  const filters=F.empty();filters.application=['billing'];filters.ports=['8443/tcp'];
  const historical={server_id:'billing-2',source_ip:'192.0.2.4',port:8443,protocol:'tcp',verdict:'observed'};
  assert.equal(F.matchServer(servers[1],filters),false);assert.equal(F.matchFlow(historical,servers[1],filters),true);assert.equal(F.matchFlow({...historical,port:22},servers[1],filters),false);assert.equal(F.matchFlow(historical,servers[1],filters,'192.0.2.4'),true);
});
test('KPI drilldowns produce exactly the scoped current and confirmed-learning rows',()=>{
  const filters=F.empty();filters.dc=['Hyderabad'];
  const alerts=[{server_id:'billing-1',status:'open'},{server_id:'billing-1',status:'acknowledged'},{server_id:'billing-1',status:'resolved'},{server_id:'billing-2',status:'open'}];
  const summary=F.summarize(servers,alerts,filters);
  assert.equal(summary.servers.length,3);assert.equal(summary.current.length,2);assert.equal(summary.collecting.length,2);assert.equal(summary.alerts.length,2);
  assert.deepEqual(servers.filter(server=>F.matchServer(server,F.drilldown(filters,'current'))).map(server=>server.id),summary.current.map(server=>server.id));
  assert.deepEqual(servers.filter(server=>F.matchServer(server,F.drilldown(filters,'learning'))).map(server=>server.id),summary.collecting.map(server=>server.id));
  assert.equal(F.learningStatus(servers[1]),'assigned');assert.equal(F.learningStatus(servers[2]),'stop_pending');assert.equal(F.learningStatus(servers[3]),'unknown');
  assert.deepEqual(filters.policy_status,[]);
});

test('drilldowns cannot broaden an existing conflicting selection',()=>{
  const filters=F.empty();filters.policy_status=['preview'];filters.learning=['assigned'];filters.dc=['Hyderabad'];
  const summary=F.summarize(servers,[],filters);assert.equal(summary.current.length,0);assert.equal(summary.collecting.length,0);
  assert.equal(servers.filter(server=>F.matchServer(server,F.drilldown(filters,'current'))).length,0);assert.equal(servers.filter(server=>F.matchServer(server,F.drilldown(filters,'learning'))).length,0);
});

test('one group policy resolves dynamic membership, includes future tagged hosts, and deduplicates groups',()=>{
  const dynamic={id:'billing',type:'dynamic',selector:{application:'billing'}};
  const staticGroup={id:'saved',type:'static',server_ids:['billing-1','web-1']};
  const policy={selector:{},group_ids:['billing','saved']};
  assert.deepEqual(F.policyTargets(policy,servers,[dynamic,staticGroup]).map(server=>server.id),['billing-1','billing-2','web-1','stale-1']);
  const future={...servers[0],id:'future-billing',hostname:'future'};
  assert.equal(F.policyTargets(policy,[...servers,future],[dynamic,staticGroup]).some(server=>server.id==='future-billing'),true);
  assert.equal(F.groupMembers(staticGroup,[...servers,future]).length,2);
  assert.equal(F.policyTargets({selector:{owner:'finance'},group_ids:[]},servers,[]).length,2);
});
test('only exact nonempty single-value tag scopes are suggested as dynamic groups',()=>{
  const filters=F.empty();assert.equal(F.scopeSelector(filters),null);filters.application=['billing'];filters.custom.owner=['finance'];
  assert.deepEqual(F.scopeSelector(filters),{application:'billing',owner:'finance'});filters.ports=['8443'];assert.equal(F.scopeSelector(filters),null);filters.ports=[];filters.dc=['Mumbai','Hyderabad'];assert.equal(F.scopeSelector(filters),null);filters.dc=[];assert.equal(F.scopeSelector(filters,'billing'),null);assert.equal(F.scopeSelector(filters,'','billing-1'),null);
});
test('application and static group filters stay ANDed with location and service scope',()=>{
  F.setGroups([{id:'billing-live',type:'dynamic',selector:{application:'billing'}},{id:'selected',type:'static',server_ids:['billing-1','web-1']}]);
  const filters=F.empty();filters.groups=['billing-live'];filters.locations=['location:loc-hyd'];filters.ports=['8443/tcp'];
  assert.deepEqual(servers.filter(server=>F.matchServer(server,filters)).map(server=>server.id),['billing-1','stale-1']);
  filters.groups=['selected'];assert.deepEqual(servers.filter(server=>F.matchServer(server,filters)).map(server=>server.id),['billing-1']);
  filters.groups=['billing-live','selected'];assert.deepEqual(servers.filter(server=>F.matchServer(server,filters)).map(server=>server.id),['billing-1','stale-1']);
  assert.equal(F.scopeSelector(filters),null,'saving a group intersection cannot discard its membership constraint');
});
test('dynamic application group browsing includes future members and refreshed static membership',()=>{
  const group={id:'billing-live',type:'dynamic',selector:{application:'billing'}};F.setGroups([group]);
  const filters=F.empty();filters.groups=['billing-live'];
  const future={...servers[0],id:'new-billing'};assert.equal(F.matchServer(future,filters),true);
  assert.equal(F.matchServer({...future,tags:{application:'platform'}},filters),false);
  F.setGroups([{id:'billing-live',type:'static',server_ids:['web-1']}]);
  assert.equal(F.matchServer(servers[0],filters),false);assert.equal(F.matchServer(servers[2],filters),true);
});
test('deleted, unknown and malformed empty dynamic groups never broaden a saved scope',()=>{
  F.setGroups([{id:'empty',type:'dynamic',selector:{}},{id:'none',type:'static',server_ids:[]}]);
  for(const id of ['empty','none','missing']){const filters=F.empty();filters.groups=[id];assert.equal(servers.filter(server=>F.matchServer(server,filters)).length,0);}
  assert.deepEqual(F.groupMembers({type:'dynamic',selector:{}},servers),[]);
  const filters=F.empty();filters.groups=['none'];F.setGroups([]);assert.equal(F.matchServer(servers[0],filters),false);
});
test('port-scoped alert counts exclude known SSH22 while retaining matching-service and host-wide alerts',()=>{
  const filters=F.empty();filters.application=['billing'];filters.ports=['8443/tcp'];
  const alerts=[{id:'ssh',server_id:'billing-1',status:'open',details:{port:22,protocol:'tcp'}},{id:'billing',server_id:'billing-1',status:'open',details:{port:8443,protocol:'tcp'}},{id:'host',server_id:'billing-1',status:'open',details:{}},{id:'udp',server_id:'billing-1',status:'open',details:{port:8443,protocol:'udp'}}];
  const summary=F.summarize(servers,alerts,filters);const byId=new Map(summary.servers.map(server=>[server.id,server]));
  const page=alerts.filter(alert=>F.unresolved(alert)&&F.matchAlert(alert,byId.get(alert.server_id),filters));
  assert.deepEqual(summary.alerts.map(alert=>alert.id),['billing','host']);assert.deepEqual(page,summary.alerts);
});
test('policy service filtering follows configured service ports rather than present listeners',()=>{
  const filters=F.empty();filters.application=['billing'];filters.ports=['8443/tcp'];
  const ssh={name:'Management',selector:{},services:[{port:22,protocol:'tcp'}]};
  const billing={name:'Billing',selector:{application:'billing'},services:[{port:8443,protocol:'tcp'},{port:22,protocol:'tcp'}]};
  assert.equal(F.policyScope(ssh,servers,[],filters).matches,false);const scope=F.policyScope(billing,servers,[],filters);
  assert.equal(scope.matches,true);assert.deepEqual(scope.services,[{port:8443,protocol:'tcp'}]);assert.equal(scope.targets.some(server=>server.id==='billing-2'),true);
});
test('scan alerts with a known port list honor service filters while unknown host-wide events remain',()=>{
 const filters=F.empty();filters.application=['billing'];filters.ports=['8443/tcp'];assert.equal(F.matchAlert({details:{ports:[22,23],protocol:'tcp'}},servers[0],filters),false);assert.equal(F.matchAlert({details:{ports:[22,8443],protocol:'tcp'}},servers[0],filters),true);assert.equal(F.matchAlert({details:{}},servers[0],filters),true);
});


test('grouped policy ports come from frozen snapshots and preserve each row own sources',()=>{
 const groupRow={service_group_id:'app',service_group_snapshot:{id:'app',name:'Web ports',revision:3,ports:[{port:443,protocol:'tcp'},{port:8443,protocol:'tcp'}]},sources:['192.0.2.0/24'],source_group_ids:['lb','bastion'],source_selector:{role:'client'}};
 const singleRow={port:5432,protocol:'tcp',sources:['198.51.100.0/24'],source_group_ids:['database-clients']};
 const flattened=F.flattenServices([groupRow,singleRow]);
 assert.deepEqual(flattened.map(item=>[item.port,item.protocol,item.sources,item.source_group_ids]),[[443,'tcp',['192.0.2.0/24'],['lb','bastion']],[8443,'tcp',['192.0.2.0/24'],['lb','bastion']],[5432,'tcp',['198.51.100.0/24'],['database-clients']]]);
 assert.equal(groupRow.port,undefined,'flattening does not mutate the original grouped policy row');
 assert.equal(F.flattenServices([{service_group_id:'missing',port:22,protocol:'tcp'}]).length,0,'missing snapshots cannot invent group ports');
 const filters=F.empty();filters.ports=['8443/tcp'];const policy={name:'Group policy',selector:{application:'billing'},services:[groupRow,singleRow]};
 const scope=F.policyScope(policy,servers,[],filters);assert.equal(scope.matches,true);assert.equal(scope.services.length,1);assert.equal(scope.services[0].port,8443);assert.deepEqual(scope.services[0].source_group_ids,['lb','bastion']);
 filters.ports=['8443/udp'];assert.equal(F.policyScope(policy,servers,[],filters).matches,false);
 filters.ports=['5432'];assert.deepEqual(F.policyScope(policy,servers,[],filters).services[0].sources,['198.51.100.0/24']);
});
test('fresh discovery pending and failed hosts are never counted as confirmed collecting',()=>{
 for(const [status,expected] of [['pending','discovering'],['error','discovery_error']]){
  const host={status:'healthy',collector_status:'learning',collector_desired_status:'off',learning_discovery_pending:true,learning_discovery_status:status};
  assert.equal(F.learningStatus(host),expected);assert.equal(F.isCollecting(host),false);
 }
 assert.equal(F.learningStatus({status:'healthy',collector_status:'off',learning_discovery_status:'no_listeners'}),'no_listeners');
 assert.equal(F.learningStatus({status:'offline',collector_status:'learning',learning_discovery_pending:true}),'unknown');
});
