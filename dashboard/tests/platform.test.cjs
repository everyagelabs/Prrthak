const test=require('node:test');
const assert=require('node:assert/strict');
const P=require('../platform.js');
test('platform privileges remain exclusive to Super Admin while all tabs have stable fallbacks',()=>{
 for(const role of ['admin','read_only','operator','viewer','Super Admin',undefined])assert.equal(P.canConfigure(role),false);
 assert.equal(P.canConfigure('super_admin'),true);assert.equal(P.tab('database'),'database');assert.equal(P.tab('unexpected'),'overview');assert.equal(P.tabs.length,14);assert.equal(P.tab('updates'),'updates');assert.equal(P.tab('agent-upgrades'),'agent-upgrades');assert.equal(P.tab('approvals'),'overview');
});
test('connection summaries never display usernames, passwords or query secrets',()=>{
 assert.equal(P.connectionLabel('postgresql://operator:private-password@database.example.test:5432/inventory?sslpassword=hidden'),'postgresql://database.example.test:5432/inventory');
 assert.equal(P.connectionLabel('https://user:private@controller.example.test:8443/readyz?token=hidden'),'https://controller.example.test:8443/readyz');
 assert.equal(P.connectionLabel('password=unparseable-secret'),'Configured endpoint');assert.equal(P.connectionLabel(''),'Not configured');
});
test('review readiness needs explicit server permission, immutable digest, fresh expiry and Super Admin',()=>{
 const now=Date.now(),plan={id:'review-1',digest:'a'.repeat(64),can_apply:true,expires_at:new Date(now+60000).toISOString(),blockers:[]};assert.equal(P.reviewReady(plan,'super_admin',now),true);
 for(const changes of [{can_apply:false},{can_apply:undefined},{digest:''},{id:''},{expires_at:null},{expires_at:new Date(now-1).toISOString()},{blockers:['Database test failed']}])assert.equal(P.reviewReady({...plan,...changes},'super_admin',now),false);
 assert.equal(P.reviewReady(plan,'admin',now),false);assert.equal(P.reviewReady(plan,'read_only',now),false);
});
test('destructive confirmation phrases match exactly and unreported health never appears healthy',()=>{
 const plan={confirmation_phrase:'DELETE DEMO DATA'};assert.equal(P.exactPhrase(plan,'DELETE DEMO DATA'),true);assert.equal(P.exactPhrase(plan,'delete demo data'),false);assert.equal(P.exactPhrase({},''),false);assert.equal(P.health(undefined),'unknown');assert.equal(P.health('pending'),'unknown');assert.equal(P.health(false),'unavailable');assert.equal(P.health('ready'),'healthy');
});
