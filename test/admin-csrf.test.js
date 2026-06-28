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
const loginHtml = fs.readFileSync(path.join(root, 'server', 'public', 'login.html'), 'utf8');
const loginJs = fs.readFileSync(path.join(root, 'server', 'public', 'login.js'), 'utf8');

test('admin write routes include csrf middleware', () => {
  assert.match(server, /const sessionWrite = \[auth\.requireAuth,\s*auth\.requireCsrf\]/);
  assert.match(server, /const adminWrite = \[auth\.requireAuth,\s*auth\.requireCsrf,\s*auth\.requireRole\(roles\.SECURITY_ADMIN\)\]/);
  assert.match(server, /const decisionWrite = \[auth\.requireAuth,\s*auth\.requireCsrf,\s*auth\.requireRole\(roles\.SECURITY_ADMIN,\s*roles\.APPROVER\)\]/);
  assert.match(server, /app\.post\(\s*'\/api\/queries\/:id\/reveal',\s*\.\.\.adminWrite,\s*validation\.validateBody\(validation\.revealSchema\),\s*requireRevealPassword,/);
  assert.match(server, /app\.post\(\s*'\/api\/queries\/:id\/approve',\s*\.\.\.decisionWrite,\s*validation\.validateBody\(validation\.approveSchema\),\s*requireDecisionAccess,\s*requireApprovePassword,/);
  for (const route of [
    "app.post('/api/queries/:id/deny', ...decisionWrite",
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

test('login page discovers optional OIDC without exposing secrets', () => {
  assert.match(server, /app\.get\('\/api\/login-options'/);
  assert.match(server, /oidc\.publicOptions\(\)/);
  assert.match(loginHtml, /id="oidc" hidden/);
  assert.match(loginJs, /fetch\('\/api\/login-options'\)/);
  assert.match(loginJs, /location\.href = body\.oidc\.startUrl/);
  assert.doesNotMatch(loginJs, /OIDC_CLIENT_SECRET|client_secret/i);
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
  assert.match(dashboard, /function canDecide\(q = \{\}\)/);
  assert.match(dashboard, /function canReveal\(q = \{\}\)/);
});

test('dashboard exposes retention settings and manual purge control', () => {
  assert.match(dashboard, /id="pol_retention"/);
  assert.match(dashboard, /rawRetentionDays: Number\(\$\(\'#pol_retention\'\)\.value\)/);
  assert.match(dashboard, /id="pol_desktop_destination"/);
  assert.match(dashboard, /desktopCollectorDestination: \(\$\(\'#pol_desktop_destination\'\)\.value \|\| ''\)\.trim\(\)/);
  assert.match(dashboard, /id="pol_block_unapproved_ai"/);
  assert.match(dashboard, /blockUnapprovedAiDestinations: \$\('#pol_block_unapproved_ai'\)\.checked/);
  assert.match(dashboard, /id="pol_response_scan_mode"/);
  assert.match(dashboard, /responseScanMode: \$\('#pol_response_scan_mode'\)\.value/);
  assert.match(dashboard, /id="pol_blocked_browser_actions"/);
  assert.match(dashboard, /const blockedBrowserActions = parsePolicyJsonArray\(\$\(\'#pol_blocked_browser_actions\'\)\.value, 'Browser action controls'\)/);
  assert.match(dashboard, /blockedBrowserActions,/);
  assert.match(dashboard, /id="pol_required_sensors"/);
  assert.match(dashboard, /requiredSensors: parsePolicyList\(\$\(\'#pol_required_sensors\'\)\.value\)/);
  assert.match(dashboard, /id="pol_desired_sensor_versions"/);
  assert.match(dashboard, /desiredSensorVersions: parsePolicyMap\(\$\(\'#pol_desired_sensor_versions\'\)\.value\)/);
  assert.match(dashboard, /const separator = trimmed\.includes\('='\) \? trimmed\.indexOf\('='\) : trimmed\.search\(\/\\s\/\)/);
  assert.match(dashboard, /id="runRetentionPurge"/);
  assert.match(dashboard, /api\('\/api\/retention\/purge', \{ method: 'POST' \}\)/);
});

test('dashboard exposes scoped policy and exception editors', () => {
  assert.match(index, /policy-advanced-grid/);
  assert.match(index, /policy-builder-grid/);
  assert.match(dashboard, /function shortPolicyValue/);
  assert.match(dashboard, /function policyMatcherSummary/);
  assert.match(dashboard, /function exceptionLifecycleSummary/);
  assert.match(dashboard, /function appendGuidedScopeRule/);
  assert.match(dashboard, /function appendGuidedExceptionRule/);
  assert.match(dashboard, /id="scopeRuleBuilder"/);
  assert.match(dashboard, /id="exceptionRuleBuilder"/);
  assert.match(dashboard, /id="addScopeRule"/);
  assert.match(dashboard, /id="addExceptionRule"/);
  assert.match(dashboard, /id="exception_builder_owner_group"/);
  assert.match(dashboard, /id="exception_builder_reviewer_role"/);
  assert.match(dashboard, /id="exception_builder_review_hours"/);
  assert.match(dashboard, /const now = Date\.now\(\)/);
  assert.match(dashboard, /expiresAt: new Date\(now \+ hours \* 60 \* 60 \* 1000\)\.toISOString\(\)/);
  assert.match(dashboard, /rule\.reviewAfter = new Date\(now \+ reviewHours \* 60 \* 60 \* 1000\)\.toISOString\(\)/);
  assert.match(dashboard, /ownerGroup/);
  assert.match(dashboard, /reviewerRole/);
  assert.match(dashboard, /reviewAfter/);
  assert.match(dashboard, /id="pol_policy_scopes"/);
  assert.match(dashboard, /id="pol_policy_exceptions"/);
  assert.match(dashboard, /addPolicyRuleToTextarea\('#pol_policy_scopes', rule, 'Scoped enforcement rules'\)/);
  assert.match(dashboard, /addPolicyRuleToTextarea\('#pol_policy_exceptions', rule, 'Time-bound exceptions'\)/);
  assert.match(dashboard, /const policyScopes = parsePolicyJsonArray\(\$\(\'#pol_policy_scopes\'\)\.value, 'Scoped enforcement rules'\)/);
  assert.match(dashboard, /const policyExceptions = parsePolicyJsonArray\(\$\(\'#pol_policy_exceptions\'\)\.value, 'Time-bound exceptions'\)/);
  assert.match(dashboard, /policyScopes,/);
  assert.match(dashboard, /policyExceptions,/);
  assert.match(dashboard, /no scoped rules/);
  assert.match(dashboard, /no exceptions/);
});

test('dashboard renders auditors as read-only users', () => {
  assert.match(dashboard, /let currentRole = 'auditor'/);
  assert.match(dashboard, /function normalizeRole\(role\)/);
  assert.match(dashboard, /function canAdminWrite\(\)/);
  assert.match(dashboard, /function queueDecisionLabel\(q = \{\}\)/);
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
