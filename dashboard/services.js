(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.PrithakServices = api;
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';
  function value(input) { return typeof input === 'string' ? input.trim() : ''; }
  function known(input) { return input && !/^(unknown(?: service| application)?|n\/a|none)$/i.test(input); }
  function name(listener = {}) {
    const identity = [listener.service, listener.process, listener.systemd_unit].map(value).join(' ');
    if (/(?:^|[\s/"(])(?:sshd|openssh)(?:[.@\s/"-]|$)/i.test(identity)) return 'SSH';
    const reported = value(listener.service);
    if (known(reported)) return reported;
    const process = value(listener.process);
    if (known(process)) return process.split('/').pop();
    const unit = value(listener.systemd_unit).replace(/\.service$/, '');
    return known(unit) ? unit : 'Unknown service';
  }
  function label(listener = {}) { return `${name(listener)} · ${Number(listener.port) || '—'}/${value(listener.protocol) || 'tcp'}`; }
  function application(listener = {}) {
    return value(listener.application) || value(listener.process) || value(listener.systemd_unit).replace(/\.service$/, '') || 'Application not reported';
  }
  function textOrder(a, b) { return a === b ? 0 : a < b ? -1 : 1; }
  function portOrder(listener) {
    const port = Number(listener.port);
    return Number.isInteger(port) && port >= 1 && port <= 65535 ? port : 65536;
  }
  function listenerOrder(a, b) {
    return textOrder(name(a).toLowerCase(), name(b).toLowerCase()) || portOrder(a) - portOrder(b)
      || textOrder((value(a.protocol) || 'tcp').toLowerCase(), (value(b.protocol) || 'tcp').toLowerCase())
      || textOrder(value(a.address).toLowerCase(), value(b.address).toLowerCase())
      || textOrder(application(a).toLowerCase(), application(b).toLowerCase())
      || textOrder(name(a), name(b)) || textOrder(value(a.protocol), value(b.protocol))
      || textOrder(value(a.address), value(b.address)) || textOrder(application(a), application(b))
      || textOrder(value(a.process), value(b.process)) || textOrder(value(a.systemd_unit), value(b.systemd_unit))
      || (Number(a.pid) || 0) - (Number(b.pid) || 0);
  }
  function sortedListeners(listeners = []) { return [...listeners].sort(listenerOrder); }
  function catalogue(servers) {
    const rows = new Map();
    for (const server of servers) {
      for (const listener of server.listeners || []) {
        const port = Number(listener.port);
        const protocol = value(listener.protocol).toLowerCase();
        if (!Number.isInteger(port) || port < 1 || port > 65535 || !['tcp','udp'].includes(protocol)) continue;
        const service = name(listener), app = application(listener);
        const key = JSON.stringify([port, protocol, service.toLowerCase(), app.toLowerCase()]);
        if (!rows.has(key)) rows.set(key, {port, protocol, service, application:app, endpoints:new Set()});
        rows.get(key).endpoints.add(server.id);
      }
    }
    return sortedListeners([...rows.values()].map(({endpoints, ...row}) => ({...row, endpointCount:endpoints.size})));
  }
  return {name, label, application, sortedListeners, catalogue};
}));
