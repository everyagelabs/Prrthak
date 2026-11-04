'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
require('../topology.js');
const now = Date.parse('2026-10-30T10:00:00Z');
const stamp = seconds => new Date(now - seconds * 1000).toISOString();
const server = (id, dc = 'DC-1', extra = {}) => ({
  id, hostname:id, location_id:dc?'loc-'+dc:null,
  location:dc?{id:'loc-'+dc,name:dc,type:'datacenter',country_code:'IN',latitude:19+(Number(dc.split('-').at(-1))||0),longitude:77}:null,
  ips:[id === 'web' ? '10.1.0.2' : '10.1.0.1'], status:'healthy', last_seen:stamp(10), ...extra
});
const source = server('source');
const target = server('web', 'DC-2', {collector_status:'learning'});
const session = {id:'session-now', status:'active', server_ids:['web'], starts_at:stamp(300), expires_at:stamp(-300)};
const flow = {server_id:'web', session_id:session.id, source_ip:'10.1.0.1', port:80, protocol:'tcp', verdict:'observed', count:4, last_seen:stamp(20)};
const render = values => globalThis.PSegraTopology.render({servers:[source,target], flows:[], learningSessions:[session], now, ...values});

test('inventory without observations creates site markers but no links', () => {
  const html = render({});
  assert.match(html,/class="pseg-map" viewBox="0 0 760 425"/);
  assert.match(html,/class="pseg-site-button".*data-location-key="location:loc-DC-1"/);
  assert.match(html,/No observed links/);
  assert.match(html,/pseg-site-pulse/);
  assert.doesNotMatch(html,/class="pseg-edge |Recent activity|packets\/s|connections\/s|Live packets/i);
  assert.match(render({servers:[]}),/No endpoints match this scope/);
});

test('countries are selectable and only matching geographic sites get map pins', () => {
  const india = server('delhi','IN',{location:{id:'loc-IN',name:'Noida facility',location:'Noida, India',type:'datacenter'}});
  const australia = server('sydney','AU',{location:{id:'loc-AU',name:'Sydney facility',location:'Sydney, Australia',type:'datacenter'}});
  const html = render({servers:[india,australia],country:'AU'});
  assert.match(html,/aria-label="Infrastructure in Australia"/);
  assert.match(html,/class="pseg-country-shape"/);
  assert.match(html,/<option value="AU" selected>Australia/);
  assert.match(html,/<option value="IN">India/);
  assert.match(html,/data-location-key="location:loc-AU"/);
  assert.doesNotMatch(html,/data-location-key="location:loc-IN"/);
  assert.match(render({servers:[india,australia],country:'IN'}),/aria-label="Infrastructure in India"/);
});

test('a saved country can show its outline before the site has a pin', () => {
  const facility = server('dc','NL',{location:{id:'loc-NL',name:'DC 17',type:'datacenter',country_code:'NL'}});
  const html = render({servers:[facility]});
  assert.match(html,/aria-label="Infrastructure in Netherlands"/);
  assert.match(html,/Needs map coordinates/);
  assert.doesNotMatch(html,/class="pseg-site-point/);
  facility.location.latitude = 52.3702;
  facility.location.longitude = 4.8952;
  assert.match(render({servers:[facility]}),/class="pseg-site-point/);
});

test('AWS map pins use a known region or consistent regional hostnames', () => {
  const aws = server('aws','AWS',{location:{id:'loc-AWS',name:'AWS',type:'cloud',provider:'aws'}});
  const generic = render({servers:[aws]});
  assert.match(generic,/Unmapped sites/);
  assert.doesNotMatch(generic,/class="pseg-site-point/);
  const regional = {...aws,hostname:'ip-10-0-0-10.ap-south-1.compute.internal'};
  assert.match(render({servers:[regional]}),/aria-label="Infrastructure in India"/);
  const mixed = [regional,{...aws,id:'other',hostname:'ip-10-0-0-11.ap-southeast-2.compute.internal'}];
  assert.match(render({servers:mixed}),/Unmapped sites/);
  assert.match(render({servers:[regional],inventory:mixed}),/Unmapped sites/);
  assert.match(render({servers:[{...regional,location:{...aws.location,region:'ap-southeast-2'}}]}),/aria-label="Infrastructure in Australia"/);
});
test('recent observations connect managed source and destination sites', () => {
  const html = render({flows:[flow]});
  assert.match(html,/class="pseg-edge is-current"/);
  assert.match(html,/DC-1 → DC-2/);
  assert.match(html,/pseg-edge-pulse/);
  assert.doesNotMatch(html,/External \/ other sources/);
});
test('one observed link retains separate connection, packet, historical log and sample units', () => {
  const html=render({flows:[
    {...flow,capture_kind:'accepted_connection',verdict:'allowed',count:2},
    {...flow,capture_kind:'denied_packet',verdict:'denied',count:500},
    {...flow,count:7},{...flow,capture_kind:'accepted_connection',count_unit:'sample_minutes',count:3}
  ]});
  assert.match(html,/2 transport connections \/ 500 denied packets \/ 7 legacy log records \/ 3 communication samples/);
  assert.match(html,/>1 observed link</);
});
test('historical observations show a static link and last-observed timestamp', () => {
  const html = render({flows:[{...flow,last_seen:stamp(600)}]});
  assert.match(html,/pseg-edge is-historical/);
  assert.doesNotMatch(html,/class="pseg-edge-pulse"/);
  assert.match(html,/2026-10-30T09:50:00.000Z/);
});
test('ended, missing and mismatched sessions or stale endpoints cannot imply live capture', () => {
  for (const values of [
    {learningSessions:[]}, {servers:[source,{...target,last_seen:stamp(300)}]},
    {flows:[{...flow,session_id:'old-session'}]}, {flows:[{...flow,session_id:undefined}]}
  ]) {
    const html = render({flows:[flow],...values});
    assert.match(html,/pseg-edge is-historical/);
    assert.doesNotMatch(html,/class="pseg-edge-pulse"/);
  }
});
test('unresolved sources aggregate and ambiguous IP ownership outside scope is not attributed', () => {
  const html = render({inventory:[source,server('shared','Other site'),target],flows:[flow,{...flow,source_ip:'203.0.113.15'}]});
  assert.match(html,/External \/ other sources/);
  assert.match(html,/2 observed source IPs/);
  assert.equal((html.match(/class="pseg-edge /g) || []).length,1);
});
test('location labels and keys cannot inject markup', () => {
  const html = render({servers:[server('bad','" onclick="bad',{
    location:{id:'loc-" onclick="bad',type:'datacenter',name:'<img src=x onerror=alert(1)>'}
  })]});
  assert.doesNotMatch(html,/<img|data-location-key="location:loc-" onclick=/);
  assert.match(html,/&lt;img/);
  assert.match(html,/&quot; onclick=&quot;bad/);
});
test('large fleets render at most six map sites and disclose the off-map remainder', () => {
  const servers = Array.from({length:140}, (_, i) => server('host-'+i,'DC-'+i%7));
  const html = render({servers});
  assert.equal((html.match(/class="pseg-site"/g) || []).length,6);
  assert.match(html,/7 data centres/);
  assert.match(html,/Additional sites in India/);
  assert.match(PSegraTopology.healthHTML(servers,now),/140 of 140 endpoints reporting/);
});
test('demo observations are visibly identified and unknown targets produce no links', () => {
  const html = render({servers:[{...source,synthetic:true}],flows:[flow]});
  assert.match(html,/Synthetic observations/);
  assert.equal((html.match(/class="pseg-site"/g) || []).length,1);
  assert.doesNotMatch(html,/class="pseg-edge /);
});
test('physical DCs and cloud regions use their assigned location type and factual health totals',()=>{
  const servers=[source,server('cloud-node','',{location_id:'loc-aws',location:{id:'loc-aws',name:'AWS · ap-south-1',type:'cloud'}})];
  const html=render({servers});
  assert.match(html,/data-location-type="datacenter"/);
  assert.match(html,/data-location-type="cloud"/);
  assert.match(html,/1 data centre · 1 cloud region/);
  assert.match(html,/AWS · ap-south-1/);
  assert.match(html,/1\/1 healthy/);
});
test('site health uses the configured heartbeat timeout',()=>{
  const configured=server('slow-control','DC-1',{heartbeat_timeout_seconds:900,last_seen:stamp(200)});
  const healthy=render({servers:[configured]});
  assert.match(healthy,/pseg-health-dot is-healthy/);
  assert.doesNotMatch(healthy,/pseg-health-dot is-offline/);
  assert.doesNotMatch(healthy,/pseg-site-pulse/);
  const stale={...configured,last_seen:stamp(901)};
  assert.match(render({servers:[stale]}),/pseg-health-dot is-offline/);
  assert.match(PSegraTopology.healthHTML([stale],now),/0 of 1 endpoint reporting/);
});
test('discovery pending or incomplete does not animate unconfirmed collection',()=>{
  for(const state of [
    {learning_discovery_pending:true},
    {learning_discovery_status:'pending'},
    {learning_discovery_status:'error'},
    {learning_discovery_status:'no_listeners'},
    {learning_discovery_status:'unsupported'}
  ]) {
    const html=render({servers:[source,{...target,...state}],flows:[flow]});
    assert.match(html,/pseg-edge is-historical/);
    assert.doesNotMatch(html,/class="pseg-edge-pulse"/);
  }
});
test('map ownership uses agent-reported IPs rather than connection or planned addresses',()=>{
  const unreported={...source,ips:[],peer_ip:'10.1.0.1',remote_ip:'10.1.0.1',forwarded_for:'10.1.0.1',planned_ips:['10.1.0.1']};
  assert.match(render({servers:[unreported,target],flows:[flow]}),/External \/ other sources → DC-2/);
  assert.match(render({servers:[{...unreported,ips:['10.1.0.1']},target],flows:[flow]}),/<title>DC-1 → DC-2/);
});
