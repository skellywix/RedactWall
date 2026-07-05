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
  assert.match(server, /const adminRead = \[auth\.requireAuth,\s*auth\.requireRole\(roles\.SECURITY_ADMIN\)\]/);
  assert.match(server, /const adminWrite = \[auth\.requireAuth,\s*auth\.requireCsrf,\s*auth\.requireRole\(roles\.SECURITY_ADMIN\),\s*license\.requireWritable\]/);
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

test('dashboard fetches and sends csrf token on unsafe admin requests', () => {
  assert.match(dashboard, /async function loadCsrf\(\)/);
  assert.match(dashboard, /api\('\/api\/csrf'\)/);
  assert.match(dashboard, /headers\.set\('x-csrf-token', csrfToken\)/);
  assert.match(dashboard, /await loadCsrf\(\)/);
  assert.match(dashboard, /function askDestinationReviewReason/);
  assert.match(dashboard, /body: JSON\.stringify\(\{ destination, decision, reason \}\)/);
});

test('dashboard policy status clears only the latest transient message', () => {
  assert.match(dashboard, /let policyStatusTimer = null/);
  assert.match(dashboard, /function setPolicyStatus\(message, clearAfterMs = 0\)/);
  assert.match(dashboard, /clearTimeout\(policyStatusTimer\)/);
  assert.match(dashboard, /if \(status\.textContent === message\) status\.textContent = ''/);
  assert.match(dashboard, /setPolicyStatus\('Saved', 4000\)/);
  assert.doesNotMatch(dashboard, /\$\('#polSaved'\)\.textContent = 'Saved';\s*setTimeout/);
});

test('login page discovers optional OIDC without exposing secrets', () => {
  assert.match(server, /app\.get\('\/api\/login-options'/);
  assert.match(server, /oidc\.publicOptions\(\)/);
  assert.match(loginHtml, /id="oidc" hidden/);
  assert.match(loginJs, /fetch\('\/api\/login-options'\)/);
  assert.match(loginJs, /location\.href = body\.oidc\.startUrl/);
  assert.doesNotMatch(loginJs, /OIDC_CLIENT_SECRET|client_secret/i);
});

test('login and dashboard alerts expose accessible live feedback', () => {
  assert.match(loginHtml, /aria-describedby="err"/);
  assert.match(loginHtml, /id="err" role="alert" aria-live="polite"/);
  assert.match(loginJs, /function showError\(message, fields = \[\]\)/);
  assert.match(loginJs, /function setInvalidFields\(fields = \[\]\)/);
  assert.match(loginJs, /setAttribute\('aria-invalid'/);
  assert.match(index, /id="banner" role="alert" aria-live="polite"/);
});

test('dashboard requires masked password confirmation before raw reveal', () => {
  assert.match(dashboard, /function uniqueDialogId\(prefix\)/);
  assert.match(dashboard, /dialog\.setAttribute\('aria-labelledby', titleId\)/);
  assert.match(dashboard, /dialog\.setAttribute\('aria-describedby', descriptionId\)/);
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
  assert.match(dashboard, /function samePrincipal\(left, right\)/);
  assert.match(dashboard, /samePrincipal\(q\.assignedUser, currentUser\)/);
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
  assert.match(dashboard, /canAdminWrite\(\) \? api\('\/api\/billing\/seats'\) : Promise\.resolve\(null\)/);
});

test('dashboard exposes queue filter selection state to assistive technology', () => {
  assert.match(index, /data-queue-filter="all" type="button" aria-pressed="true"/);
  assert.match(index, /data-queue-filter="mine" type="button" aria-pressed="false"/);
  assert.match(dashboard, /button\.setAttribute\('aria-pressed', String\(active\)\)/);
});

test('dashboard exposes selected queue rows and incident details accessibly', () => {
  assert.match(index, /id="queueList" class="queue-list" role="list" aria-label="Pending approval prompts"/);
  assert.match(index, /id="incidentDetail" class="incident-detail" role="region" aria-live="polite" aria-label="Selected incident details"/);
  assert.match(dashboard, /const isSelected = selected === q\.id/);
  assert.match(dashboard, /role="listitem"/);
  assert.match(dashboard, /aria-current="true"/);
  assert.match(dashboard, /aria-controls="incidentDetail"/);
  assert.match(dashboard, /aria-label="\$\{escapeHtml\(rowLabel\)\}"/);
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

test('dashboard recovers approval queue from a stalled pending fetch', () => {
  assert.match(dashboard, /async function dashboardJsonWithTimeout/);
  assert.match(dashboard, /new AbortController\(\)/);
  assert.match(dashboard, /controller\.abort\(\)/);
  assert.match(dashboard, /async function pendingQueueRows/);
  assert.match(dashboard, /\/api\/queries\?status=pending/);
  assert.match(dashboard, /currentActivity\.filter\(\(q\) => q\.status === 'pending'\)/);
  assert.match(dashboard, /\/api\/queries\?limit=200/);
  assert.match(dashboard, /currentQueue = await pendingQueueRows\(\)/);
});

test('dashboard exposes compact queue viewing controls', () => {
  assert.match(index, /id="toggleQueueDensity"/);
  assert.match(index, /queue-density-compact/);
  assert.match(dashboard, /function applyQueueDensity/);
  assert.match(dashboard, /promptwall\.queueDensity/);
  assert.match(dashboard, /aria-pressed/);
});

test('dashboard global search filters audit table rows', () => {
  assert.match(index, /id="globalSearch"/);
  assert.match(index, /id="auditRows"/);
  assert.match(dashboard, /let currentAuditEntries = \[\]/);
  assert.match(dashboard, /function auditText\(entry = \{\}\)/);
  assert.match(dashboard, /function matchesAudit\(entry\)/);
  assert.match(dashboard, /renderAuditRows\(currentAuditEntries\)/);
  assert.match(dashboard, /currentAuditEntries = d\.entries/);
  assert.match(dashboard, /function filteredAuditEntries\(entries\)/);
  assert.match(dashboard, /matchesAudit\(a\)\)/);
});

test('dashboard paginates activity lineage and audit tables', () => {
  assert.match(index, /id="activityPager"/);
  assert.match(index, /id="lineageUsersPager"/);
  assert.match(index, /id="auditPager"/);
  assert.match(dashboard, /let activityPageSize = 10/);
  assert.match(dashboard, /const LINEAGE_PAGE_SIZE = 10/);
  assert.match(dashboard, /let auditPageSize = 10/);
  assert.match(dashboard, /function paginatedRows\(rows, page, pageSize\)/);
  assert.match(dashboard, /function renderTablePager\(selector/);
  assert.match(dashboard, /data-pager-target/);
  assert.match(dashboard, /resetTablePages\(\)/);
});
