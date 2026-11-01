const assert = require('node:assert/strict');
const test = require('node:test');
const routes = require('../routing.js');
const services = require('../services.js');

test('each section has a distinct direct URL and refresh resolves only that section', () => {
  for (const page of routes.pages) {
    assert.equal(routes.href(page), `/${page}`);
    assert.equal(routes.viewFromPath(`/${page}`), page);
    assert.equal(routes.viewFromPath(`/${page}/`), page);
  }
  assert.equal(routes.viewFromPath('/'), 'overview');
  assert.equal(routes.href('untrusted'), '/overview');
});
test('legacy hash bookmarks migrate to section paths without losing query strings', () => {
  assert.equal(routes.legacyDestination('/', '#servers'), '/servers');
  assert.equal(routes.legacyDestination('/overview', '#traffic', '?window=3600'), '/traffic?window=3600');
  assert.equal(routes.legacyDestination('/', '#untrusted'), null);
});
test('service identity comes from process or unit and works on a nonstandard SSH port', () => {
  assert.equal(services.label({port:2022,protocol:'tcp',process:'sshd'}), 'SSH · 2022/tcp');
  assert.equal(services.label({port:2222,protocol:'tcp',systemd_unit:'sshd.service'}), 'SSH · 2222/tcp');
  assert.equal(services.label({port:80,protocol:'tcp'}), 'Unknown service · 80/tcp');
  assert.equal(services.label({port:22,protocol:'udp',process:'custom-app'}), 'custom-app · 22/udp');
  assert.equal(services.name({port:80,process:'nginx'}), 'nginx');
  assert.equal(services.application({application:'Payments API',process:'java'}), 'Payments API');
});
