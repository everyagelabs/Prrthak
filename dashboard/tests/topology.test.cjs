'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
require('../topology.js');
const now = Date.parse('2026-10-30T10:00:00Z');
const stamp = seconds => new Date(now - seconds * 1000).toISOString();
const server = (id, dc = 'DC-1', extra = {}) => ({id, hostname:id, tags:{dc}, location_id:dc?'loc-'+dc:null,location:dc?{id:'loc-'+dc,name:dc,type:'datacenter'}:null, ips:[id === 'web' ? '10.1.0.2' : '10.1.0.1'], status:'healthy', last_seen:stamp(10), listeners:[{port:22, protocol:'tcp'}], ...extra});
const source = server('source');
const target = server('web', 'DC-2', {collector_status:'learning'});
const session = {id:'session-now', status:'active', server_ids:['web'], starts_at:stamp(300), expires_at:new Date(now + 300000).toISOString()};
const flow = {server_id:'web', session_id:session.id, source_ip:'10.1.0.1', port:80, protocol:'tcp', verdict:'observed', count:4, last_seen:stamp(20)};
const render = values => globalThis.PSegraTopology.render({servers:[source, target], flows:[], alerts:[], learningSessions:[session], now, ...values});

test('inventory never fabricates communication paths or traffic events', () => {
  const html = render({});
  assert.equal((html.match(/class="pseg-edge /g) || []).length, 0);
  assert.match(html, /No captured flows in this view/);
  assert.match(html, /Heartbeat received/);
  assert.doesNotMatch(html, /packets\/s|connections\/s|Live packets/i);
});
test('recent supplied observed flows connect managed source to target', () => {
  const html = render({flows:[flow]});
  assert.match(html, /class="pseg-edge is-current"/);
  assert.match(html, /source → web/);
  assert.match(html, /pseg-edge-pulse/);
  assert.doesNotMatch(html, /External \/ other sources<\/text>/);
});
test('one observed link retains separate connection, packet and historical log units', () => {
  const html=render({flows:[{...flow,capture_kind:'accepted_connection',verdict:'allowed',count:2},{...flow,capture_kind:'denied_packet',verdict:'denied',count:500},{...flow,count:7}]});
  assert.match(html,/2 transport connections \/ 500 denied packets \/ 7 legacy log records/);
  assert.doesNotMatch(html,/509 observed events|509 transport connections/);
});
test('historical flows are static and labeled last observed', () => {
  const html = render({flows:[{...flow,last_seen:stamp(600)}]});
  assert.match(html, /pseg-edge is-historical/);
  assert.doesNotMatch(html, /class="pseg-edge-pulse"/);
  assert.match(html, /Last observed 10m ago/);
});
test('ended learning, stale heartbeat, and another session cannot imply live capture', () => {
  for (const values of [{learningSessions:[]}, {servers:[source,{...target,last_seen:stamp(300)}]}, {flows:[{...flow,session_id:'old-session'}]}]) {
    const html = render({flows:[flow], ...values});
    assert.match(html, /pseg-edge is-historical/);
    assert.doesNotMatch(html, /class="pseg-edge-pulse"/);
  }
});
test('unresolved sources aggregate, ambiguous IP ownership is not attributed', () => {
  const html = render({servers:[source,server('shared'),target],flows:[flow,{...flow,source_ip:'203.0.113.15'}]});
  assert.match(html, /External \/ other sources/);
  assert.match(html, /2 observed source IPs/);
  assert.equal((html.match(/class="pseg-edge /g) || []).length, 1);
});
test('labels, IDs, and event messages cannot inject markup', () => {
  const malicious = '<img src=x onerror=alert(1)>';
  const html = render({servers:[server('" onclick="bad',malicious,{hostname:malicious})],alerts:[{created_at:stamp(4),message:malicious,kind:'service_down'}]});
  assert.doesNotMatch(html, /<img|data-server-id="" onclick=/);
  assert.match(html, /&lt;img/);
  assert.match(html, /&quot; onclick=&quot;bad/);
});
test('large fleets stay bounded and expose real host/DC overflow totals', () => {
  const servers = Array.from({length:140}, (_, i) => server(`host-${i}`,`DC-${i % 7}`,{ips:[`10.1.0.${i + 1}`]}));
  const html = render({servers});
  assert.equal((html.match(/class="pseg-dc"/g) || []).length, 6);
  assert.equal((html.match(/class="pseg-node /g) || []).length, 48);
  assert.match(html, /\+12 endpoints/);
  assert.match(html, /\+1 location · 20 endpoints outside canvas/);
});
test('demo state is visibly identified and unknown targets create no nodes', () => {
  const html = render({servers:[{...source,synthetic:true}],flows:[flow]});
  assert.match(html, /pseg-synthetic-label">SYNTHETIC/);
  assert.equal((html.match(/class="pseg-node /g) || []).length, 1);
  assert.equal((html.match(/class="pseg-edge /g) || []).length, 0);
});
test('physical DC and cloud region cards identify their types and expose factual health totals',()=>{
const html=render({servers:[server('dc-node','legacy',{location_id:'loc-mumbai',location:{id:'loc-mumbai',name:'Mumbai',type:'datacenter'},tags:{dc:'Untrusted different name'}}),server('cloud-node','',{location_id:'loc-aws',location:{id:'loc-aws',name:'AWS · ap-south-1',type:'cloud',provider:'aws',region:'ap-south-1'},tags:{dc:'Must not create a data centre'}})],flows:[],alerts:[]});assert.match(html,/data-location-type="datacenter"/);assert.match(html,/data-location-type="cloud"/);assert.match(html,/1 data centre · 1 cloud region/);assert.match(html,/AWS · ap-south-1/);assert.match(html,/1\/1 healthy/);assert.match(html,/0 open alerts · 1 host/);assert.doesNotMatch(html,/class="pseg-edge /);
});
test('missing session identity cannot animate a flow as current collection',()=>{
const legacy={...flow};delete legacy.session_id;const html=render({flows:[legacy]});assert.match(html,/pseg-edge is-historical/);assert.doesNotMatch(html,/class="pseg-edge-pulse"/);
});
test('configured control interval uses its reported heartbeat timeout instead of fixed three-minute staleness',()=>{
const configured=server('slow-control','DC-1',{control_interval_seconds:300,heartbeat_timeout_seconds:900,last_seen:stamp(200)});
const healthy=render({servers:[configured],learningSessions:[]});assert.match(healthy,/class="pseg-node is-healthy/);assert.doesNotMatch(healthy,/class="pseg-node is-offline/);
const stale=render({servers:[{...configured,last_seen:stamp(901)}],learningSessions:[]});assert.match(stale,/class="pseg-node is-offline/);
});

test('fresh discovery pending or incomplete excludes ghost collector acknowledgements from animation and counts',()=>{
 for(const state of [
  {learning_discovery_pending:true,learning_discovery_status:'pending'},
  {learning_discovery_pending:true,learning_discovery_status:'error'},
  {learning_discovery_pending:false,learning_discovery_status:'pending'},
  {learning_discovery_pending:false,learning_discovery_status:'no_listeners'},
  {learning_discovery_pending:false,learning_discovery_status:'unsupported'}
 ]) {
  const html=render({servers:[source,{...target,collector_status:'learning',collector_desired_status:'off',...state}],flows:[flow],learningSessions:[{...session,selection_mode:'discovered',discovery_pending_server_ids:['web'],server_ports:{web:[]}}]});
  assert.match(html,/pseg-edge is-historical/);assert.doesNotMatch(html,/class="pseg-edge-pulse"/);assert.doesNotMatch(html,/endpoint[s]? collecting flows|is-learning|collecting observed traffic/);assert.match(html,/Historical flow observations/);
 }
});
test('topology ownership never treats a connection, forwarded or planned address as agent-reported inventory',()=>{
 const unreported={...source,ips:[],peer_ip:'10.1.0.1',remote_ip:'10.1.0.1',forwarded_for:'10.1.0.1',planned_ips:['10.1.0.1']};let html=render({servers:[unreported,target],flows:[flow]});assert.match(html,/External \/ other source/);assert.doesNotMatch(html,/<title>source → web/);
 html=render({servers:[{...unreported,ips:['10.1.0.1']} ,target],flows:[flow]});assert.match(html,/<title>source → web/);
});
