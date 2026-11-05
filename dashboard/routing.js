(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.PrithakRoutes = api;
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';
  const pages = ['overview', 'servers', 'tags', 'locations', 'services', 'firewall', 'policies', 'traffic', 'risk', 'alerts', 'activity', 'settings', 'access'];
  const advancedPoliciesHref = '/policies?section=advanced';
  function href(view) { return '/' + (pages.includes(view) ? view : 'overview'); }
  function viewFromPath(pathname) {
    const name = String(pathname || '/').replace(/^\/+|\/+$/g, '');
    if (name === 'network-control') return 'policies';
    return pages.includes(name) ? name : 'overview';
  }
  function advancedPolicies(pathname, search) {
    const path = String(pathname || '').replace(/\/$/, '');
    const query = new URLSearchParams(search);
    return path === '/network-control' ||
      (path === '/policies' && query.get('section') === 'advanced') ||
      (path === '/login' && query.get('next') === 'network-control');
  }
  function legacyDestination(pathname, hash, search = '') {
    const view = String(hash || '').replace(/^#/, '');
    if (view === 'network-control') {
      const query = new URLSearchParams(search);
      query.set('section', 'advanced');
      return '/policies?' + query;
    }
    return pages.includes(view) ? href(view) + search : null;
  }
  return {pages, href, viewFromPath, advancedPolicies, advancedPoliciesHref, legacyDestination};
}));
