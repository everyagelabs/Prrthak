const assert = require('node:assert/strict');
const fs = require('node:fs');
const test = require('node:test');
const vm = require('node:vm');
const services = require('../services.js');

test('listener order follows displayed service identity before numeric ports without mutating reports', () => {
  const listeners = Object.freeze([
    Object.freeze({service:'Zebra',port:1,protocol:'tcp'}),
    Object.freeze({process:'sshd',port:2022,protocol:'tcp'}),
    Object.freeze({service:'alpha',port:100,protocol:'tcp'}),
    Object.freeze({service:'Alpha',port:9,protocol:'tcp'}),
    Object.freeze({service:'unknown',process:'/usr/sbin/nginx',port:80,protocol:'tcp'}),
    Object.freeze({port:443,protocol:'tcp'}),
  ]);
  const sorted = services.sortedListeners(listeners);
  assert.deepEqual(sorted.map(services.label), [
    'Alpha · 9/tcp', 'alpha · 100/tcp', 'nginx · 80/tcp', 'SSH · 2022/tcp',
    'Unknown service · 443/tcp', 'Zebra · 1/tcp',
  ]);
  assert.equal(sorted[0], listeners[3]);
  assert.equal(listeners[0].service, 'Zebra');
  assert.notEqual(sorted, listeners);
  assert.deepEqual(services.sortedListeners(), []);
});

test('equal service names use port, protocol, binding and application for deterministic ordering', () => {
  const listeners = [
    {id:'udp',service:'alpha',port:80,protocol:'udp',address:'10.0.0.1',application:'A'},
    {id:'second-address',service:'ALPHA',port:80,protocol:'tcp',address:'10.0.0.2',application:'A'},
    {id:'second-app',service:'alpha',port:80,protocol:'tcp',address:'10.0.0.1',application:'Z'},
    {id:'first',service:'Alpha',port:80,protocol:'tcp',address:'10.0.0.1',application:'A'},
    {id:'second-port',service:'alpha',port:443,protocol:'tcp',address:'10.0.0.1',application:'A'},
  ];
  const expected = ['first','second-app','second-address','udp','second-port'];
  assert.deepEqual(services.sortedListeners(listeners).map(row=>row.id), expected);
  assert.deepEqual(services.sortedListeners([...listeners].reverse()).map(row=>row.id), expected);
});

test('discovered service catalogue and pickers remain alphabetical while preserving unique endpoint counts', () => {
  const servers = [
    {id:'one',listeners:[{service:'zookeeper',port:2181,protocol:'tcp'},
      {service:'HTTPS',port:443,protocol:'tcp',application:'Web'},
      {service:'API',port:8443,protocol:'tcp',application:'Billing'},
      {service:'API',port:8443,protocol:'tcp',application:'Billing',address:'::'}]},
    {id:'two',listeners:[{service:'HTTPS',port:443,protocol:'tcp',application:'Web'},
      {process:'sshd',port:22,protocol:'tcp'}]},
  ];
  const catalogue = services.catalogue(servers);
  assert.deepEqual(catalogue.map(row=>[row.service,row.port,row.endpointCount]), [
    ['API',8443,1],['HTTPS',443,2],['SSH',22,1],['zookeeper',2181,1],
  ]);
  assert.deepEqual(services.catalogue([...servers].reverse()), catalogue);
  assert.equal(servers[0].listeners[0].service, 'zookeeper');
});

test('server inventory previews alphabetically before selecting its first three listener chips', () => {
  const listeners = [
    {service:'Zebra',port:1,protocol:'tcp'}, {service:'Charlie',port:3,protocol:'tcp'},
    {service:'Alpha',port:9,protocol:'tcp'}, {service:'Bravo',port:2,protocol:'tcp'},
  ];
  const server = {id:'node',hostname:'node',tags:{},listeners};
  const source = fs.readFileSync(require.resolve('../app.js'),'utf8');
  const fn = source.slice(source.indexOf('function serverRows('),source.indexOf('\nfunction inventoryHTML'));
  const context = {state:{view:'servers',filters:{},search:'',flowServer:'all'},filteredServers:()=>[server],
    D:services,JSON,Math,h:String,icon:()=>'',num:Number,metadataSelectionCell:()=>'',
    listenerChip:listener=>`<span>${services.label(listener)}</span>`,riskyPortBadge:()=>'',riskyServerBadge:()=>'',
    serverLocationHTML:()=>'',tagsHTML:()=>'',serverHealth:()=>'',networkControlStatusHTML:()=>'',policyBadge:()=>'',
    L:{customTags:()=>({})}};
  vm.createContext(context);
  vm.runInContext(fn, context);
  const {html} = context.serverRows();
  assert.ok(html.indexOf('Alpha · 9/tcp') < html.indexOf('Bravo · 2/tcp'));
  assert.ok(html.indexOf('Bravo · 2/tcp') < html.indexOf('Charlie · 3/tcp'));
  assert.doesNotMatch(html, /Zebra/);
  assert.match(html, />\+1</);
  assert.equal(listeners[0].service, 'Zebra');
});
