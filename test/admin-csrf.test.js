'use strict';
/** Admin console unsafe routes must carry CSRF protection. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const server = fs.readFileSync(path.join(root, 'server/app.js'), 'utf8');
const loginHtml = fs.readFileSync(path.join(root, 'server', 'public', 'login.html'), 'utf8');
const loginJs = fs.readFileSync(path.join(root, 'server', 'public', 'login.js'), 'utf8');

test('admin write routes include csrf middleware', () => {
  assert.match(server, /const sessionWrite = \[auth\.requireAuth,\s*auth\.requireCsrf\]/);
  assert.match(server, /const adminRead = \[auth\.requireAuth,\s*auth\.requireRole\(roles\.SECURITY_ADMIN\)\]/);
  assert.match(server, /const adminWrite = \[auth\.requireAuth,\s*auth\.requireCsrf,\s*auth\.requireRole\(roles\.SECURITY_ADMIN\),\s*requireWritableSharedLicense\]/);
  assert.match(server, /const decisionWrite = \[auth\.requireAuth,\s*auth\.requireCsrf,\s*auth\.requireRole\(roles\.SECURITY_ADMIN,\s*roles\.APPROVER\)\]/);
  assert.match(server, /app\.post\(\s*'\/api\/queries\/:id\/reveal',\s*\.\.\.adminWrite,\s*validation\.validateBody\(validation\.revealSchema\),\s*requireRevealPassword,/);
  assert.match(server, /app\.post\(\s*'\/api\/queries\/:id\/approve',\s*\.\.\.decisionWrite,\s*validation\.validateBody\(validation\.approveSchema\),\s*requireDecisionAccess,\s*requireApprovePassword,/);
  for (const route of [
    "app.post('/api/queries/:id/deny', ...decisionWrite",
    "app.post('/api/retention/purge', ...adminWrite",
    "app.post('/api/destinations/review', ...adminWrite",
    "app.post('/api/policy/impact', ...adminWrite",
    "app.put('/api/policy/apply-template', ...adminWrite",
    "app.put('/api/policy', ...adminWrite",
  ]) {
    assert.ok(server.includes(route), route);
  }
  assert.ok(server.includes("app.post('/api/logout', ...sessionWrite"), 'logout remains available to any authenticated session');
  assert.ok(server.includes("app.get('/api/billing/seats', ...adminRead"), 'billing seat identities remain Security Admin only');
  assert.ok(server.includes("app.get('/api/metrics', ...adminRead"), 'ops metrics remain Security Admin only');
});

test('login page discovers optional OIDC without exposing secrets', () => {
  assert.match(server, /app\.get\('\/api\/login-options'/);
  assert.match(server, /oidc\.publicOptions\(\)/);
  assert.match(loginHtml, /id="oidc" hidden/);
  assert.match(loginJs, /fetch\('\/api\/login-options', \{ redirect: 'error' \}\)/);
  assert.match(loginJs, /location\.href = body\.oidc\.startUrl/);
  assert.doesNotMatch(loginJs, /OIDC_CLIENT_SECRET|client_secret/i);
});

test('login alerts expose accessible live feedback', () => {
  assert.match(loginHtml, /aria-describedby="err"/);
  assert.match(loginHtml, /id="err" role="alert" aria-live="polite"/);
  assert.match(loginJs, /function showError\(message, fields = \[\]\)/);
  assert.match(loginJs, /function setInvalidFields\(fields = \[\]\)/);
  assert.match(loginJs, /setAttribute\('aria-invalid'/);
});
