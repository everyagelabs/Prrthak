const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');

function collect(rows){
 const context={state:{data:{service_groups:[{id:'web'}]}},L:{withLocation:(tags)=>tags},parseTags:text=>Object.fromEntries(text.split(',').filter(Boolean).map(x=>x.split('='))),
  $:(selector,row)=>({value:row[selector.match(/name="(.*?)"/)[1]]||''}),
  $$:(selector,row)=>selector==='.rule-row'?rows:(row.groups||[]).map(value=>({value}))};
 vm.createContext(context);vm.runInContext(fs.readFileSync(path.join(__dirname,'..','service-groups-page.js'),'utf8'),context);
 return JSON.parse(JSON.stringify(context.collectPolicyServices({})));
}
const row={rule_type:'port',rule_port:'443',rule_protocol:'tcp',rule_sources:'192.0.2.1,192.0.2.2',rule_selector:'application=billing,owner=finance',groups:['clients-a','clients-b']};
test('identical policy rows are skipped regardless of source or selector ordering',()=>{
 assert.equal(collect([row,{...row,rule_sources:'192.0.2.2,192.0.2.1,192.0.2.1',rule_selector:'owner=finance,application=billing',groups:['clients-b','clients-a']}]).length,1);
});
test('same port with different source intent remains additive without a duplicate blocker',()=>{
 const result=collect([row,{...row,rule_sources:'198.51.100.1'},{...row,rule_protocol:'udp'}]);
 assert.equal(result.length,3);assert.equal(result[1].sources[0],'198.51.100.1');assert.equal(result[2].protocol,'udp');
});
test('overlapping named-group and direct-port rows reach the compiler for semantic merging',()=>{
 assert.equal(collect([row,{...row,rule_type:'group',rule_service_group:'web'}]).length,2);
});
