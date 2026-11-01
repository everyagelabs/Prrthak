const test=require('node:test');const assert=require('node:assert/strict');const L=require('../locations.js');const F=require('../filters.js');
const catalog=[
 {id:'loc-mumbai',name:'Mumbai',location:'Mumbai facility A',type:'datacenter',aliases:['Mumbai legacy']},
 {id:'loc-hyd',name:'Hyderabad',location:'Hyderabad',type:'datacenter'},
 {id:'loc-blr',name:'Bengaluru',location:'Bengaluru',type:'datacenter'},
 {id:'loc-aws',name:'AWS India primary',location:'India',type:'cloud',provider:'aws',region:'ap-south-1'},
 {id:'loc-aws-secondary',name:'AWS India secondary',location:'India',type:'cloud',provider:'aws',region:'ap-south-1'}
];
const fixtures=[
 {id:'dc1',location_id:'loc-mumbai',tags:{dc:'Must not create a DC',application:'billing'},listeners:[{port:8443,protocol:'tcp'}]},
 {id:'dc2',location_id:'loc-hyd',tags:{application:'billing'},listeners:[{port:8443,protocol:'tcp'}]},
 {id:'dc3',location_id:'loc-blr',tags:{application:'payments'},listeners:[]},
 {id:'aws',location_id:'loc-aws',tags:{cloud_provider:'gcp',region:'Wrong custom region',account:'123',application:'billing'},listeners:[{port:8443,protocol:'tcp'}]},
 {id:'unknown',ips:['54.1.2.3'],tags:{dc:'Mumbai',location_type:'cloud',application:'billing'},listeners:[]}
];
test.beforeEach(()=>L.setCatalog(catalog));
test('three saved DCs and an assigned cloud location stay distinct; tags and IPs never infer assignment',()=>{
 const places=L.all(fixtures);assert.equal(places.filter(location=>location.kind==='datacenter').length,3);assert.equal(places.filter(location=>location.kind==='cloud').length,1);assert.equal(L.of(fixtures[4]).kind,'unknown');assert.equal(L.of(fixtures[3]).label,'AWS India primary');assert.equal(L.of(fixtures[3]).provider,'aws');assert.equal(L.of({tags:{dc:'Mumbai'}}).label,'Unassigned location');assert.equal(L.catalog().length,5);
});
test('saved location selections are OR within locations and AND with application and port scope',()=>{
 const filters=F.empty();filters.locations=['location:loc-mumbai','location:loc-aws'];filters.application=['billing'];filters.ports=['8443/tcp'];assert.deepEqual(fixtures.filter(server=>F.matchServer(server,filters)).map(server=>server.id),['dc1','aws']);assert.equal(F.count(filters),4);assert.equal(F.scopeSelector(filters),null);
});
test('a single location scope becomes a stable-ID dynamic selector independent of custom cloud tags',()=>{
 const filters=F.empty();filters.locations=['location:loc-aws'];assert.deepEqual(F.scopeSelector(filters),{location_id:'loc-aws'});assert.deepEqual(F.scopeSelector(filters,'','all',fixtures),{location_id:'loc-aws'});assert.equal(L.of({...fixtures[3],tags:{account:'other'}}).key,L.of(fixtures[3]).key);assert.notEqual(L.of({...fixtures[3],location_id:'loc-aws-secondary'}).key,L.of(fixtures[3]).key);
});
test('renaming a catalogue entry keeps location filters, groups and policies stable and preserves explicit aliases',()=>{
 const selected='location:loc-mumbai',policy={selector:{location_id:'loc-mumbai'},group_ids:[]};L.setCatalog(catalog.map(record=>record.id==='loc-mumbai'?{...record,name:'Mumbai primary DC',aliases:['Mumbai','Mumbai legacy']}:record));assert.equal(L.matchesKey(fixtures[0],selected),true);assert.equal(L.describe(selected),'Mumbai primary DC');assert.deepEqual(F.policyTargets(policy,fixtures,[]).map(server=>server.id),['dc1']);assert.deepEqual(F.groupMembers({type:'dynamic',selector:{dc:'Mumbai'}},fixtures).map(server=>server.id),['dc1']);assert.equal(L.matchesKey(fixtures[4],selected),false);
});
test('unassigned legacy tags remain migration hints; unknown and ambiguous aliases fail closed',()=>{
 assert.equal(L.matchesSelector(fixtures[4],{dc:'Mumbai'}),false);const filters=F.empty();filters.dc=['A nonexistent DC'];assert.equal(F.matchServer(fixtures[4],filters),false);filters.locations=['unknown'];assert.equal(F.matchServer(fixtures[4],filters),false);filters.dc=[];assert.equal(F.matchServer(fixtures[4],filters),true);
 L.setCatalog([...catalog,{id:'duplicate-alias',name:'Different DC',type:'datacenter',aliases:['Mumbai legacy']}]);assert.equal(L.find('Mumbai legacy'),null);assert.equal(L.matchesSelector(fixtures[0],{dc:'Mumbai legacy'}),false);assert.equal(L.matchesKey(fixtures[4],JSON.stringify({dc:'Missing'})),false);
});
test('location aliases cannot be written as custom tags; arbitrary other tags remain independent',()=>{
 for(const key of ['dc','DC','dc_id','data-center','data_centre','location','location_id','LOCATION-TYPE'])assert.throws(()=>L.assertCustomTags({[key]:'somewhere'}),/reserved/);
 assert.deepEqual(L.assertCustomTags({application:'billing',owner:'finance',cloud_provider:'other',region:'custom',account:'one'}),{application:'billing',owner:'finance',cloud_provider:'other',region:'custom',account:'one'});assert.throws(()=>F.addCustom(F.empty(),'dc=Mumbai'),/Location filter/);assert.deepEqual(L.customTags({dc:'Mumbai',owner:'finance'}),{owner:'finance'});
});
test('empty saved locations are available for assignment but do not invent topology members',()=>{
 assert.equal(L.all(fixtures).some(location=>location.id==='loc-aws-secondary'),false);const empty=L.all(fixtures,true).find(location=>location.id==='loc-aws-secondary');assert.equal(empty.members.length,0);assert.equal(L.catalog().some(record=>record.id==='loc-aws-secondary'),true);
});
