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
  assert.match(server, /const sessionWrite = \[auth\.requireAuth,\s*auth\.requireCsrf\]/);
  assert.match(server, /const adminWrite = \[auth\.requireAuth,\s*auth\.requireCsrf,\s*auth\.requireRole\('security_admin'\)\]/);
  assert.match(server, /app\.post\(\s*'\/api\/queries\/:id\/reveal',\s*\.\.\.adminWrite,\s*validation\.validateBody\(validation\.revealSchema\),\s*requireRevealPassword,/);
  assert.match(server, /app\.post\(\s*'\/api\/queries\/:id\/approve',\s*\.\.\.adminWrite,\s*validation\.validateBody\(validation\.approveSchema\),\s*requireApprovePassword,/);
  for (const route of [
    "app.post('/api/queries/:id/deny', ...adminWrite",
    "app.post('/api/retention/purge', ...adminWrite",
    "app.put('/api/policy/apply-template', ...adminWrite",
    "app.put('/api/policy', ...adminWrite",
  ]) {
    assert.ok(server.includes(route), route);
  }
  assert.ok(server.includes("app.post('/api/logout', ...sessionWrite"), 'logout remains available to any authenticated session');
});

test('dashboard fetches and sends csrf token on unsafe admin requests', () => {
  assert.match(dashboard, /async function loadCsrf\(\)/);
  assert.match(dashboard, /api\('\/api\/csrf'\)/);
  assert.match(dashboard, /headers\.set\('x-csrf-token', csrfToken\)/);
  assert.match(dashboard, /await loadCsrf\(\)/);
});

test('dashboard requires masked password confirmation before raw reveal', () => {
  assert.match(dashboard, /function askStepUpPassword/);
  assert.match(dashboard, /function askRevealPassword\(\)/);
  assert.match(dashboard, /type="password"/);
  assert.match(dashboard, /body: JSON\.stringify\(\{ password \}\)/);
  assert.match(dashboard, /allowAuthError: true/);
  assert.match(dashboard, /Password confirmation failed\./);
  assert.doesNotMatch(dashboard, /\/reveal`, \{ method: 'POST' \}\)/);
});

test('dashboard requires password confirmation before approving release', () => {
  assert.match(dashboard, /function askApprovePassword\(\)/);
  assert.match(dashboard, /const password = act === 'approve' \? await askApprovePassword\(\) : ''/);
  assert.match(dashboard, /JSON\.stringify\(act === 'approve' \? \{ note, password \} : \{ note \}\)/);
});

test('dashboard exposes retention settings and manual purge control', () => {
  assert.match(dashboard, /id="pol_retention"/);
  assert.match(dashboard, /rawRetentionDays: Number\(\$\(\'#pol_retention\'\)\.value\)/);
  assert.match(dashboard, /id="runRetentionPurge"/);
  assert.match(dashboard, /api\('\/api\/retention\/purge', \{ method: 'POST' \}\)/);
});

test('dashboard renders auditors as read-only users', () => {
  assert.match(dashboard, /let currentRole = 'auditor'/);
  assert.match(dashboard, /function normalizeRole\(role\)/);
  assert.match(dashboard, /function canAdminWrite\(\)/);
  assert.match(dashboard, /currentRole = normalizeRole\(me\.role\)/);
  assert.match(dashboard, /\$\('#who'\)\.textContent = `\$\{me\.user\} \/ \$\{roleLabel\(currentRole\)\}`/);
  assert.match(dashboard, /Read-only auditor view/);
  assert.match(dashboard, /if \(!canAdminWrite\(\)\)/);
});
