'use strict';
/** Admin console unsafe routes must carry CSRF protection. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const server = fs.readFileSync(path.join(root, 'server/app.js'), 'utf8');
const index = fs.readFileSync(path.join(root, 'server', 'public', 'index.html'), 'utf8');
const dashboard = fs.readFileSync(path.join(root, 'server', 'public', 'dashboard.js'), 'utf8');

test('admin write routes include csrf middleware', () => {
  assert.match(server, /const sessionWrite = \[auth\.requireAuth,\s*auth\.requireCsrf\]/);
  assert.match(server, /const adminWrite = \[auth\.requireAuth,\s*auth\.requireCsrf,\s*auth\.requireRole\('security_admin'\)\]/);
  assert.match(server, /app\.post\(\s*'\/api\/queries\/:id\/reveal',\s*\.\.\.adminWrite,\s*validation\.validateBody\(validation\.revealSchema\),\s*requireRevealPassword,/);
  assert.match(server, /app\.post\(\s*'\/api\/queries\/:id\/approve',\s*\.\.\.adminWrite,\s*validation\.validateBody\(validation\.approveSchema\),\s*requireApprovePassword,/);
  for (const route of [
    "app.post('/api/queries/:id/deny', ...adminWrite",
    "app.post('/api/retention/purge', ...adminWrite",
    "app.post('/api/destinations/review', ...adminWrite",
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
  assert.match(dashboard, /function askDestinationReviewReason/);
  assert.match(dashboard, /body: JSON\.stringify\(\{ destination, decision, reason \}\)/);
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
  assert.match(dashboard, /id="pol_desktop_destination"/);
  assert.match(dashboard, /desktopCollectorDestination: \(\$\(\'#pol_desktop_destination\'\)\.value \|\| ''\)\.trim\(\)/);
  assert.match(dashboard, /id="pol_block_unapproved_ai"/);
  assert.match(dashboard, /blockUnapprovedAiDestinations: \$\('#pol_block_unapproved_ai'\)\.checked/);
  assert.match(dashboard, /id="pol_required_sensors"/);
  assert.match(dashboard, /requiredSensors: parsePolicyList\(\$\(\'#pol_required_sensors\'\)\.value\)/);
  assert.match(dashboard, /id="pol_desired_sensor_versions"/);
  assert.match(dashboard, /desiredSensorVersions: parsePolicyMap\(\$\(\'#pol_desired_sensor_versions\'\)\.value\)/);
  assert.match(dashboard, /const separator = trimmed\.includes\('='\) \? trimmed\.indexOf\('='\) : trimmed\.search\(\/\\s\/\)/);
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

test('dashboard filters approval queue by workflow state, category, and destination', () => {
  assert.match(index, /id="queueCategoryFilter"/);
  assert.match(index, /id="queueDestinationFilter"/);
  assert.match(index, /Approval queue metadata filters/);
  assert.match(dashboard, /let queueCategoryFilter = 'all'/);
  assert.match(dashboard, /let queueDestinationFilter = 'all'/);
  assert.match(dashboard, /function queueCategoryLabels\(q = \{\}\)/);
  assert.match(dashboard, /function queueMetadataMatches\(q\)/);
  assert.match(dashboard, /currentQueue\.filter\(queueMetadataMatches\)\.filter\(matchesSearch\)/);
  assert.match(dashboard, /e\.target\.matches\('#queueCategoryFilter'\)/);
  assert.match(dashboard, /e\.target\.matches\('#queueDestinationFilter'\)/);
});
