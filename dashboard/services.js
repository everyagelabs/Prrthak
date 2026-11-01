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
  return {name, label, application};
}));
