const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
function environment(overrides={}){
 const shown=[],calls=[],errors=[],elements=new Map([['#modal',{open:true}]]),state={role:'read_only',data:{servers:[]}},escape=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
 const context={canWrite:()=>state.role==='admin'||state.role==='super_admin',console,state,URLSearchParams,BigInt,Date,Map,Set,String,Number,JSON,Array,Math,h:escape,format:String,timestamp:String,serverName:id=>id,showModal:(title,html)=>{shown.push({title,html});elements.get('#modal').open=true;},formError:error=>errors.push(error.message),$:selector=>elements.get(selector),api:async(path,options)=>{calls.push({path,options});return {server_id:'host',status:'unavailable',reason:'Counters disabled',items:[],has_more:false,total:0};},...overrides};
 vm.createContext(context);vm.runInContext(fs.readFileSync(require.resolve('../firewall-counters-page.js'),'utf8'),context);return {context,state,shown,calls,errors,elements};
}
test('native uint64 counters retain precision and unavailable counters are never rendered as zero',()=>{
 const e=environment();assert.equal(e.context.firewallCounterNumber('18446744073709551615'),'18,446,744,073,709,551,615');assert.equal(e.context.firewallCounterNumber('0'),'0');
 for(const value of [null,undefined,'-1','1.5','001','18446744073709551616',0])assert.equal(e.context.firewallCounterNumber(value),'Unavailable');
});
test('rule expressions and names escape HTML, keep packet/byte units and explain reset baseline',()=>{
 const e=environment(),html=e.context.firewallCounterPageHTML('host',{status:'partial',backend:'nftables',items:[{chain:'<script>secret</script>',table:'firewalld',family:'inet',kind:'base',basis:'kernel_rule',action:'accept',packets:null,bytes:null,expression:'<img src=x onerror=alert(1)>',reason:'Disabled <unsafe>',delta_status:'reset',reset_detected:true}],total:1,reason:'NftablesCounters=no',sample_interval_seconds:900,stale:true});
 assert.doesNotMatch(html,/<script>|<img/);assert.match(html,/&lt;script&gt;/);assert.match(html,/Counter reset/);assert.match(html,/Packets/);assert.match(html,/Bytes/);assert.match(html,/not connection counts/);assert.match(html,/sample is stale/);assert.match(html,/Unavailable/);assert.match(html,/NftablesCounters=no/);
});
test('five thousand endpoints use fifty-row picker pages and exact per-host reads',async()=>{
 const e=environment();e.state.data.servers=Array.from({length:5000},(_,n)=>({id:'h'+n,hostname:'host'+String(n).padStart(4,'0'),ips:['192.0.2.1']}));e.context.firewallCounterPicker();
 assert.equal((e.shown.at(-1).html.match(/data-action="firewall-counters-open"/g)||[]).length,50);assert.match(e.shown.at(-1).html,/5000 matching servers/);assert.equal(e.calls.length,0);
 await e.context.firewallCounterAction({dataset:{action:'firewall-counters-picker-page',offset:'50'}});assert.match(e.shown.at(-1).html,/host0050/);assert.doesNotMatch(e.shown.at(-1).html,/host0000/);
});
test('Read Only fetches native counters with GET only and never mutates a firewall',async()=>{
 const e=environment();await e.context.firewallCounterOpen('host');assert.equal(e.calls.length,1);assert.equal(e.calls[0].options,undefined);assert.match(e.calls[0].path,/^\/servers\/host\/firewall-counters\?/);assert.match(e.shown.at(-1).html,/Counters disabled/);assert.doesNotMatch(e.shown.at(-1).html,/Apply|Reload firewalld/);
});
test('responses for a previous endpoint and responses after closing cannot replace current views',async()=>{
 const pending=[],e=environment({api:path=>new Promise(resolve=>pending.push({path,resolve}))});const first=e.context.firewallCounterOpen('first'),second=e.context.firewallCounterOpen('second');pending[1].resolve({server_id:'second',items:[],status:'unavailable'});await second;const count=e.shown.length;pending[0].resolve({server_id:'first',items:[],status:'unavailable'});await first;assert.equal(e.shown.length,count);
 const third=e.context.firewallCounterOpen('third');e.elements.get('#modal').open=false;const closed=e.shown.length;pending[2].resolve({server_id:'third',items:[],status:'unavailable'});await third;assert.equal(e.shown.length,closed);
});
test('invalid endpoint pages fail without displaying another server counts',async()=>{
 const e=environment({api:async()=>({server_id:'another-host',items:[]})});await e.context.firewallCounterOpen('host');assert.match(e.errors[0],/invalid native counter page/);assert.equal(e.shown.length,1);
});
