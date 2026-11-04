(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.PrithakRoutes = api;
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';
  const pages = ['overview', 'servers', 'locations', 'services', 'firewall', 'policies', 'network-control', 'traffic', 'risk', 'alerts', 'activity', 'settings', 'access'];
  function href(view) { return '/' + (pages.includes(view) ? view : 'overview'); }
  function viewFromPath(pathname) {
    const name = String(pathname || '/').replace(/^\/+|\/+$/g, '');
    return pages.includes(name) ? name : 'overview';
  }
  function legacyDestination(pathname, hash, search = '') {
    const view = String(hash || '').replace(/^#/, '');
    return pages.includes(view) ? href(view) + search : null;
  }
  return {pages, href, viewFromPath, legacyDestination};
}));
