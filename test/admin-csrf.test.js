'use strict';
/** Admin console unsafe routes must carry CSRF protection. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const server = fs.readFileSync(path.join(root, 'server.js'), 'utf8');
const dashboard = fs.readFileSync(path.join(root, 'public', 'index.html'), 'utf8');

test('admin write routes include csrf middleware', () => {
  assert.match(server, /const adminWrite = \[auth\.requireAuth,\s*auth\.requireCsrf\]/);
  for (const route of [
    "app.post('/api/logout', ...adminWrite",
    "app.post('/api/queries/:id/reveal', ...adminWrite",
    "app.post('/api/queries/:id/approve', ...adminWrite",
    "app.post('/api/queries/:id/deny', ...adminWrite",
    "app.put('/api/policy/apply-template', ...adminWrite",
    "app.put('/api/policy', ...adminWrite",
  ]) {
    assert.ok(server.includes(route), route);
  }
});

test('dashboard fetches and sends csrf token on unsafe admin requests', () => {
  assert.match(dashboard, /async function loadCsrf\(\)/);
  assert.match(dashboard, /api\('\/api\/csrf'\)/);
  assert.match(dashboard, /headers\.set\('x-csrf-token', csrfToken\)/);
  assert.match(dashboard, /await loadCsrf\(\)/);
});
