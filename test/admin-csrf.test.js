'use strict';
/** Admin console unsafe routes must carry CSRF protection. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const server = fs.readFileSync(path.join(root, 'server.js'), 'utf8');
const dashboard = fs.readFileSync(path.join(root, 'public', 'dashboard.js'), 'utf8');

test('admin write routes include csrf middleware', () => {
  assert.match(server, /const adminWrite = \[auth\.requireAuth,\s*auth\.requireCsrf\]/);
  assert.match(server, /app\.post\(\s*'\/api\/queries\/:id\/reveal',\s*\.\.\.adminWrite,\s*validation\.validateBody\(validation\.revealSchema\),\s*requireRevealPassword,/);
  for (const route of [
    "app.post('/api/logout', ...adminWrite",
    "app.post('/api/queries/:id/approve', ...adminWrite",
    "app.post('/api/queries/:id/deny', ...adminWrite",
    "app.post('/api/retention/purge', ...adminWrite",
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

test('dashboard requires masked password confirmation before raw reveal', () => {
  assert.match(dashboard, /function askRevealPassword\(\)/);
  assert.match(dashboard, /type="password"/);
  assert.match(dashboard, /body: JSON\.stringify\(\{ password \}\)/);
  assert.match(dashboard, /allowAuthError: true/);
  assert.match(dashboard, /Password confirmation failed\./);
  assert.doesNotMatch(dashboard, /\/reveal`, \{ method: 'POST' \}\)/);
});

test('dashboard exposes retention settings and manual purge control', () => {
  assert.match(dashboard, /id="pol_retention"/);
  assert.match(dashboard, /rawRetentionDays: Number\(\$\(\'#pol_retention\'\)\.value\)/);
  assert.match(dashboard, /id="runRetentionPurge"/);
  assert.match(dashboard, /api\('\/api\/retention\/purge', \{ method: 'POST' \}\)/);
});
