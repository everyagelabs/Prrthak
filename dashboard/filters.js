(function (root, factory) {
  const api = factory(typeof module === 'object' && module.exports ? require('./locations.js') : root.PrithakLocations);
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.PSegraFilters = api;
}(typeof globalThis !== 'undefined' ? globalThis : this, function (L) {
  'use strict';
  const tagCategories = ['application', 'dc', 'network_zone', 'criticality'];
  const categories = [...tagCategories, 'os', 'status', 'policy_status', 'learning', 'locations', 'groups'];
  let registeredGroups = new Map();
  let staticMembers = new Map();
  function setGroups(groups = []) {
    registeredGroups = new Map(groups.filter(group => group && typeof group.id === 'string').map(group => [group.id, group]));
    staticMembers = new Map([...registeredGroups].filter(([,group]) => group.type === 'static').map(([id,group]) => [id, new Set(group.server_ids || group.member_ids || [])]));
  }
  function groupById(id) { return registeredGroups.get(id); }
  function belongsToGroup(server, group) {
    if (!group) return false;
    if (group.type === 'dynamic') return Object.keys(group.selector || {}).length > 0 && L.matchesSelector(server, group.selector);
    if (group.type === 'static') return registeredGroups.get(group.id) === group ? staticMembers.get(group.id)?.has(server.id) === true : (group.server_ids || group.member_ids || []).includes(server.id);
    return false;
  }
  function empty() { return {...Object.fromEntries(categories.map(key => [key, []])), ports: [], custom: {}}; }
  function parsePorts(text) {
    const result = [];
    if (!String(text).trim()) return result;
    for (const entry of String(text).split(',')) {
      const match = entry.trim().match(/^(\d{1,5})(?:\/(tcp|udp))?$/i);
      if (!match || Number(match[1]) < 1 || Number(match[1]) > 65535) throw new Error('Use a port from 1–65535, optionally followed by /tcp or /udp. Separate values with commas.');
      const value = String(Number(match[1])) + (match[2] ? '/' + match[2].toLowerCase() : '');
      if (!result.includes(value)) result.push(value);
    }
    return result;
  }
  function parseTags(text) {
    const result = {};
    if (!String(text).trim()) return result;
    for (const entry of String(text).split(',')) {
      const eq = entry.indexOf('=');
      const key = entry.slice(0, eq).trim(), value = entry.slice(eq + 1).trim();
      if (eq < 1 || !/^[A-Za-z][A-Za-z0-9_.-]{0,63}$/.test(key) || !value || value.length > 128) throw new Error('Use tag key=value pairs separated by commas, for example owner=finance, environment=production.');
      if (!result[key]) result[key] = [];
      if (!result[key].includes(value)) result[key].push(value);
    }
    return result;
  }
  function addCustom(filters, text) {
    for (const [key, values] of Object.entries(parseTags(text))) {
      if(L.isReserved(key))throw new Error('Choose a saved location from the Location filter instead of using a reserved location tag.');
      if (!tagCategories.includes(key) && !Object.hasOwn(filters.custom, key)) filters.custom[key] = [];
      const target = tagCategories.includes(key) ? filters[key] : filters.custom[key];
      for (const value of values) if (!target.includes(value)) target.push(value);
    }
    return filters;
  }
  function policyStatus(server) {
    const report=server.managed_enforcement || {}, status=report.status || server.apply_status;
    if (['error','failed'].includes(status)) return 'error';
    if (status==='rolled_back') return 'rolled_back';
    if(status==='enforced' && report.intent==='remove_managed_rules' && Number(report.version)===Number(server.desired_version))return 'removed';
    if (['preview','pending_approval','staging','runtime_healthchecking','committing'].includes(status)) return status;
    if (['enforced','applied'].includes(report.status) && Number(report.version)>0 && Number(report.version)!==Number(server.desired_version)) return 'pending_approval';
    if (Number(server.desired_version)>0 && Number(server.desired_version)===Number(server.applied_version)) return 'current';
    return 'pending';
  }
  function learningStatus(server) {
    if (server.status === 'offline' || server.collector_status_stale || server.collector_state === 'unknown') return 'unknown';
    if (server.learning_discovery_pending) return server.learning_discovery_status === 'error' ? 'discovery_error' : 'discovering';
    if (server.learning_discovery_status === 'no_listeners') return 'no_listeners';
    if (server.collector_status === 'learning') return server.learning_stop_pending ? 'stop_pending' : 'collecting';
    if (server.collector_desired_status === 'learning') return 'assigned';
    return server.collector_status === 'off' ? 'off' : 'unknown';
  }
  function isCollecting(server) { return ['collecting', 'stop_pending'].includes(learningStatus(server)); }
  function matchesPorts(port, protocol, selections) {
    return !selections.length || selections.some(selection => {
      const [selectedPort, selectedProtocol] = selection.split('/');
      return Number(port) === Number(selectedPort) && (!selectedProtocol || selectedProtocol === String(protocol).toLowerCase());
    });
  }
  function matchServer(server, filters, options = {}) {
    if (filters.groups?.length && !filters.groups.some(id => belongsToGroup(server, groupById(id)))) return false;
    if (filters.locations?.length && !filters.locations.some(key=>L.matchesKey(server,key))) return false;
    for (const category of tagCategories) if (filters[category]?.length) {if(category==='dc'){if(!filters.dc.some(value=>value===''?!server.location_id:!!L.find(value)&&L.find(value).id===server.location_id))return false;}else if(!filters[category].includes(String(server.tags?.[category] ?? '')))return false;}
    const derived = {os: String(server.os || ''), status: String(server.status || ''), policy_status: policyStatus(server), learning: learningStatus(server)};
    for (const key of ['os', 'status', 'policy_status', 'learning']) if (filters[key]?.length && !filters[key].includes(derived[key])) return false;
    for (const [key, values] of Object.entries(filters.custom || {})) if (values.length && !values.some(value=>L.matchesSelector(server,{[key]:value}))) return false;
    if (!options.ignorePorts && filters.ports?.length && !(server.listeners || []).some(listener => matchesPorts(listener.port, listener.protocol, filters.ports))) return false;
    if (options.search) {
      const haystack = JSON.stringify([server.hostname, server.ips, server.tags, server.os, server.os_version, server.listeners]).toLowerCase();
      if (!haystack.includes(String(options.search).toLowerCase())) return false;
    }
    return true;
  }
  function matchFlow(flow, server, filters, search = '') {
    if (!server || !matchServer(server, filters, {ignorePorts: true})) return false;
    if (!matchesPorts(flow.port, flow.protocol, filters.ports || [])) return false;
    if (search) {
      const haystack = JSON.stringify([flow.source_ip, flow.port, flow.protocol, flow.verdict, server.hostname, server.ips, server.tags, server.os]).toLowerCase();
      if (!haystack.includes(String(search).toLowerCase())) return false;
    }
    return true;
  }
  function count(filters) {
    return categories.reduce((sum, key) => sum + (filters[key]?.length || 0), 0) + (filters.ports?.length || 0) + Object.values(filters.custom || {}).reduce((sum, values) => sum + values.length, 0);
  }
  function matchAlert(alert, server, filters, search = '') {
    if (!server || !matchServer(server, filters, {ignorePorts:true})) return false;
    if(search&&!JSON.stringify([server.hostname,server.ips,server.tags,server.os,server.listeners,alert.message,alert.details]).toLowerCase().includes(String(search).toLowerCase()))return false;
    const details = alert.details?.listener || alert.details?.service_details || alert.details || alert.detail;
    const port = Number(details?.port), protocol = details?.protocol;
    if (filters.ports?.length && Array.isArray(details?.ports)) {const known=details.ports.map(Number).filter(value=>Number.isInteger(value)&&value>=1&&value<=65535);if(known.length)return known.some(value=>filters.ports.some(selection=>{const [selectedPort,selectedProtocol]=selection.split('/');return Number(selectedPort)===value&&(!selectedProtocol||!protocol||selectedProtocol===protocol);}));}
    if (filters.ports?.length && Number.isInteger(port) && port >= 1 && port <= 65535) {
      return filters.ports.some(selection => {const [selectedPort, selectedProtocol] = selection.split('/');return Number(selectedPort) === port && (!selectedProtocol || !protocol || selectedProtocol === protocol);});
    }
    return !filters.ports?.length||(server.listeners||[]).some(listener=>matchesPorts(listener.port,listener.protocol,filters.ports));
  }
  function servicePorts(service = {}) {
    const ports = service.service_group_id ? service.service_group_snapshot?.ports || [] : [service];
    return ports.filter(item => Number.isInteger(Number(item.port)) && Number(item.port) >= 1 && Number(item.port) <= 65535 && ['tcp','udp'].includes(item.protocol)).map(item => ({port:Number(item.port),protocol:item.protocol}));
  }
  function flattenServices(services = []) { return services.flatMap(service => servicePorts(service).map(port => ({...service,...port}))); }
  function policyScope(policy, servers, groups, filters, search = '', serverId = 'all') {
    const services = flattenServices(policy.services || []).filter(service => matchesPorts(service.port, service.protocol, filters.ports || []));
    const policyNameMatches = !!search && String(policy.name || '').toLowerCase().includes(search.toLowerCase());
    const targets = policyTargets(policy, servers, groups).filter(server => (serverId === 'all' || server.id === serverId) && matchServer(server, filters, {ignorePorts:true,search:policyNameMatches?'':search}));
    const metadataScope = categories.some(key => filters[key]?.length) || Object.values(filters.custom || {}).some(values=>values.length) || serverId !== 'all';
    return {services,targets,matches:services.length > 0 && (!metadataScope || targets.length > 0) && (!search || policyNameMatches || targets.length > 0)};
  }
  function unresolved(alert) { return !alert.resolved_at && alert.status !== 'resolved'; }
  function summarize(servers, alerts, filters, search = '') {
    const matching = servers.filter(server => matchServer(server, filters, {search}));
    const matchingById = new Map(matching.map(server => [server.id, server]));
    return {servers: matching, current: matching.filter(server => policyStatus(server) === 'current'), collecting: matching.filter(isCollecting), assigned: matching.filter(server => learningStatus(server) === 'assigned'), alerts: alerts.filter(alert => unresolved(alert) && matchAlert(alert, matchingById.get(alert.server_id), filters, search))};
  }
  function drilldown(filters, scope) {
    const result = JSON.parse(JSON.stringify(filters));
    const constrain = (key, values) => {const intersection = result[key].length ? result[key].filter(value => values.includes(value)) : values; result[key] = intersection.length ? intersection : ['__no_match__'];};
    if (scope === 'current') constrain('policy_status', ['current']);
    if (scope === 'learning') constrain('learning', ['collecting', 'stop_pending']);
    if (scope === 'healthy') constrain('status', ['healthy']);
    return result;
  }
  function groupMembers(group, servers) {
    if (group?.type === 'static') { const ids = new Set(group.server_ids || group.member_ids || []); return servers.filter(server => ids.has(server.id)); }
    return servers.filter(server => belongsToGroup(server, group));
  }
  function policyTargets(policy, servers, groups) {
    if (policy.endpoint_ids?.length) {
      const ids = new Set(policy.endpoint_ids);
      return servers.filter(server => ids.has(server.id));
    }
    if (policy.group_ids?.length) {
      const ids = new Set(groups.filter(group => policy.group_ids.includes(group.id)).flatMap(group => groupMembers(group, servers).map(server => server.id)));
      return servers.filter(server => ids.has(server.id));
    }
    return servers.filter(server => L.matchesSelector(server,policy.selector || {}));
  }
  function scopeSelector(filters, search = '', serverId = 'all', servers = null) {
    if (search || serverId !== 'all' || filters.groups?.length || filters.ports.length || ['os','status','policy_status','learning'].some(key => filters[key].length)) return null;
    const selector = {};
    if (filters.locations?.length) {if (filters.locations.length > 1) return null; const selected = L.selectorFromKey(filters.locations[0]); if (!selected) return null; Object.assign(selector, selected);}
    for (const category of tagCategories) { if (filters[category].length > 1) return null; if (filters[category].length) {const key=category==='dc'?'location_id':category,value=category==='dc'?L.find(filters[category][0])?.id:filters[category][0];if(!value || (selector[key] && selector[key]!==value))return null;selector[key]=value;} }
    for (const [key, values] of Object.entries(filters.custom)) { if (values.length > 1) return null; if (values.length) {if (selector[key] && selector[key] !== values[0]) return null; selector[key] = values[0];} }
    if (Array.isArray(servers) && Object.keys(selector).length) {const expected=new Set(servers.filter(server=>matchServer(server,filters)).map(server=>server.id));const candidate=servers.filter(server=>L.matchesSelector(server,selector));if(candidate.length!==expected.size||candidate.some(server=>!expected.has(server.id)))return null;}
    return Object.keys(selector).length ? selector : null;
  }
  return {empty, categories, tagCategories, setGroups, groupById, parsePorts, parseTags, addCustom, policyStatus, learningStatus, isCollecting, matchesPorts, servicePorts, flattenServices, matchServer, matchFlow, matchAlert, policyScope, count, unresolved, summarize, drilldown, groupMembers, policyTargets, scopeSelector};
}));
