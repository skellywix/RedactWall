'use strict';
/** Dashboard frontend/backend linkage stays aligned for rendered controls and API contracts. */
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

process.env.ADMIN_PASSWORD = 'unit-pass';
process.env.SENTINEL_SECRET = 'unit-secret-stable';
process.env.SENTINEL_DATA_KEY = 'unit-data-key-stable';
process.env.INGEST_API_KEY = 'unit-ingest-key';
process.env.SENTINEL_DB_PATH = path.join(os.tmpdir(), 'ps-dashboard-linkage-test-' + crypto.randomBytes(6).toString('hex') + '.db');
process.env.SENTINEL_POLICY_PATH = path.join(os.tmpdir(), 'ps-dashboard-linkage-policy-' + crypto.randomBytes(6).toString('hex') + '.json');

fs.copyFileSync(path.join(__dirname, '..', 'config', 'policy.json'), process.env.SENTINEL_POLICY_PATH);

const app = require('../server/app');
const db = require('../server/db');
const dataCrypto = require('../server/crypto');
const { listen } = require('./support/listen');

function readProjectFile(...parts) {
  return fs.readFileSync(path.join(__dirname, '..', ...parts), 'utf8');
}

function close(server) {
  return new Promise((resolve) => server.close(resolve));
}

async function withServer(fn) {
  const server = await listen(app);
  try {
    return await fn(server.address().port);
  } finally {
    await close(server);
  }
}

async function jsonFetch(port, apiPath, { method = 'POST', body, headers = {} } = {}) {
  return fetch(`http://127.0.0.1:${port}${apiPath}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...headers,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

async function login(port) {
  const res = await jsonFetch(port, '/api/login', {
    body: { user: 'admin', password: 'unit-pass' },
  });
  assert.strictEqual(res.status, 200);
  const cookie = (res.headers.get('set-cookie') || '').split(';')[0];
  assert.match(cookie, /^promptwall_session=/);

  const csrfRes = await jsonFetch(port, '/api/csrf', {
    method: 'GET',
    headers: { cookie },
  });
  assert.strictEqual(csrfRes.status, 200);
  const { csrfToken } = await csrfRes.json();
  assert.match(csrfToken, /^[A-Za-z0-9_-]+$/);
  return { cookie, csrfToken };
}

async function createHeldPrompt(port, suffix, destination = 'chatgpt.com') {
  const res = await jsonFetch(port, '/api/v1/gate', {
    headers: { 'x-api-key': 'unit-ingest-key' },
    body: {
      prompt: `Dashboard linkage QA member SSN 524-71-${suffix} before submission.`,
      user: `qa-${suffix}@example.test`,
      destination,
      source: 'browser_extension',
      channel: 'submit',
      orgId: 'qa-org',
    },
  });
  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.status, 'pending');
  assert.match(body.id, /^q_/);
  return body;
}

async function recordHeartbeat(port) {
  const res = await jsonFetch(port, '/api/v1/heartbeat', {
    headers: { 'x-api-key': 'unit-ingest-key' },
    body: {
      user: 'tech@example.test',
      orgId: 'qa-org',
      source: 'endpoint_agent',
      destination: 'endpoint-install',
      sensor: { name: 'endpoint_agent', version: '0.3.0', platform: 'win32' },
      checks: [
        { id: 'endpoint_env_file', ok: true, detail: 'found' },
        { id: 'handoff_secret', ok: false, detail: 'missing 32-plus character handoff secret' },
      ],
    },
  });
  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.status, 'sensor_heartbeat');
  return body;
}

function routePattern(route) {
  return route
    .replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    .replace(/:id/g, "[^'\"`]+");
}

function assertRoute(serverSource, method, route) {
  assert.match(
    serverSource,
    new RegExp(`app\\.${method}\\(\\s*['"\`]${routePattern(route)}['"\`]`),
    `${method.toUpperCase()} ${route} is missing from server/app.js`,
  );
}

function assertHtmlId(source, id, fileLabel) {
  assert.match(source, new RegExp(`id=["']${id}["']`), `${fileLabel} is missing #${id}`);
}

function assertRenderedId(source, id) {
  assert.match(source, new RegExp(`id=["']${id}["']|#${id}\\b`), `dashboard.js does not render or reference #${id}`);
}

test('dashboard static controls, generated policy controls, and API routes stay wired', () => {
  const index = readProjectFile('server', 'public', 'index.html');
  const loginHtml = readProjectFile('server', 'public', 'login.html');
  const loginJs = readProjectFile('server', 'public', 'login.js');
  const dashboard = readProjectFile('server', 'public', 'dashboard.js');
  const server = readProjectFile('server', 'app.js');

  [
    'qBadge',
    'globalSearch',
    'logout',
    'banner',
    'stats',
    'queueCategoryFilter',
    'queueDestinationFilter',
    'queueList',
    'incidentDetail',
    'topEntities',
    'refreshQueue',
    'activityRows',
    'activityPager',
    'refreshCoverage',
    'coverageScore',
    'coveragePosture',
    'sensorMix',
    'fleetRows',
    'endpointAiToolRows',
    'governedRows',
    'shadowRows',
    'identityProvider',
    'identityTenant',
    'refreshIdentity',
    'identitySummary',
    'identityScimRows',
    'identityOidcRows',
    'identityEnvRows',
    'identityRoleRows',
    'identityValidation',
    'refreshLineage',
    'lineageSummary',
    'lineageUsers',
    'lineageUsersPager',
    'lineageDestinations',
    'lineageDestinationsPager',
    'lineageSensors',
    'lineageSensorsPager',
    'lineageCategories',
    'lineageCategoriesPager',
    'lineageChannels',
    'lineageChannelsPager',
    'lineageDecisions',
    'lineageDecisionsPager',
    'exportEvidence',
    'exportStatus',
    'integrity',
    'auditRows',
    'auditPager',
    'configurationStatus',
    'policyBox',
    'liveTxt',
    'who',
  ].forEach((id) => assertHtmlId(index, id, 'index.html'));

  ['f', 'user', 'password', 'otp', 'oidc', 'err'].forEach((id) => {
    assertHtmlId(loginHtml, id, 'login.html');
    assert.match(loginJs, new RegExp(`\\b${id}\\b|['"]${id}['"]|#${id}\\b`), `login.js does not reference #${id}`);
  });

  [
    'discardPolicy',
    'testConfiguration',
    'savePolicy',
    'polSaved',
    'pol_sev',
    'pol_risk',
    'pol_retention',
    'pol_desktop_destination',
    'pol_block_unapproved_ai',
    'pol_response_scan_mode',
    'pol_governed_destinations',
    'pol_allowed_destinations',
    'pol_blocked_destinations',
    'pol_blocked_file_upload_destinations',
    'pol_blocked_browser_actions',
    'pol_required_sensors',
    'pol_desired_sensor_versions',
    'pol_approval_routing_rules',
    'scope_builder_id',
    'scope_builder_groups',
    'scope_builder_users',
    'scope_builder_destinations',
    'scope_builder_categories',
    'scope_builder_detectors',
    'scope_builder_mode',
    'scope_builder_severity',
    'scope_builder_risk',
    'scope_builder_reason',
    'addScopeRule',
    'exception_builder_id',
    'exception_builder_groups',
    'exception_builder_users',
    'exception_builder_destinations',
    'exception_builder_categories',
    'exception_builder_detectors',
    'exception_builder_hours',
    'exception_builder_owner_group',
    'exception_builder_reviewer_role',
    'exception_builder_review_hours',
    'exception_builder_reason',
    'addExceptionRule',
    'pol_policy_scopes',
    'pol_policy_exceptions',
    'runRetentionPurge',
  ].forEach((id) => assertRenderedId(dashboard, id));

  [
    ['get', '/api/login-options'],
    ['post', '/api/login'],
    ['get', '/api/csrf'],
    ['post', '/api/logout'],
    ['get', '/api/me'],
    ['get', '/api/queries'],
    ['get', '/api/queries/:id'],
    ['post', '/api/queries/:id/reveal'],
    ['post', '/api/queries/:id/approve'],
    ['post', '/api/queries/:id/deny'],
    ['get', '/api/stats'],
    ['get', '/api/billing/seats'],
    ['get', '/api/preflight'],
    ['post', '/api/retention/purge'],
    ['get', '/api/coverage'],
    ['get', '/api/lineage'],
    ['get', '/api/destinations/review'],
    ['post', '/api/destinations/review'],
    ['get', '/api/policy/templates'],
    ['put', '/api/policy/apply-template'],
    ['get', '/api/audit'],
    ['get', '/api/export/evidence'],
    ['get', '/api/policy'],
    ['put', '/api/policy'],
  ].forEach(([method, route]) => assertRoute(server, method, route));

  [
    '/api/csrf',
    '/api/me',
    '/api/stats',
    '/api/billing/seats',
    '/api/queries?status=pending',
    '/api/queries?limit=200',
    '/api/destinations/review',
    '/api/coverage',
    '/api/identity/setup-guide',
    '/api/lineage?limit=1000',
    '/api/audit',
    '/api/export/evidence?queryLimit=1000&auditLimit=1000',
    '/api/policy',
    '/api/policy/templates',
    '/api/preflight',
    '/api/retention/purge',
    '/api/policy/apply-template',
    '/api/logout',
  ].forEach((endpoint) => {
    assert.ok(dashboard.includes(endpoint), `dashboard.js no longer calls ${endpoint}`);
  });
});

test('dashboard-backed API actions accept the payloads built by forms and buttons', async () => withServer(async (port) => {
  const loginOptions = await jsonFetch(port, '/api/login-options', { method: 'GET' });
  assert.strictEqual(loginOptions.status, 200);

  const { cookie, csrfToken } = await login(port);
  const headers = { cookie, 'x-csrf-token': csrfToken };

  const reveal = await createHeldPrompt(port, '9043', 'chatgpt.com');
  const approve = await createHeldPrompt(port, '9044', 'claude.ai');
  const deny = await createHeldPrompt(port, '9045', 'gemini.google.com');
  await recordHeartbeat(port);

  for (const apiPath of [
    '/api/me',
    '/api/stats',
    '/api/billing/seats',
    '/api/preflight',
    '/api/coverage',
    '/api/lineage?limit=1000',
    '/api/identity/setup-guide?provider=okta&tenantId=acme.okta.com',
    '/api/audit',
    '/api/policy',
    '/api/policy/templates',
  ]) {
    const res = await jsonFetch(port, apiPath, { method: 'GET', headers: { cookie } });
    assert.strictEqual(res.status, 200, `${apiPath} should be reachable from dashboard session`);
  }

  const queue = await jsonFetch(port, '/api/queries?status=pending', { method: 'GET', headers: { cookie } });
  assert.strictEqual(queue.status, 200);
  const queued = await queue.json();
  assert.ok(queued.length >= 3);
  const revealQueueRow = queued.find((row) => row.id === reveal.id);
  assert.ok(revealQueueRow);
  assert.strictEqual(revealQueueRow.rawRetained, true);
  assert.strictEqual(revealQueueRow._rawPrompt, undefined);

  const detail = await jsonFetch(port, `/api/queries/${reveal.id}`, { method: 'GET', headers: { cookie } });
  assert.strictEqual(detail.status, 200);
  const detailBody = await detail.json();
  assert.strictEqual(detailBody.rawRetained, true);
  assert.strictEqual(detailBody._rawPrompt, undefined);

  const revealRes = await jsonFetch(port, `/api/queries/${reveal.id}/reveal`, {
    headers,
    body: { password: 'unit-pass' },
  });
  assert.strictEqual(revealRes.status, 200);
  const revealBody = await revealRes.json();
  assert.match(revealBody.rawPrompt, /524-71-9043/);
  assert.strictEqual(revealBody.rawRetained, true);
  assert.strictEqual(revealBody.rawDiffersFromRedacted, true);

  const retainedPreview = 'Debug this deploy script. Here is the AWS key [SECRET_KEY] and secret we use.';
  const retainedPreviewRow = db.createQuery({
    status: 'pending',
    user: 'redacted-api@example.test',
    destination: 'claude.ai',
    source: 'api',
    channel: 'submit',
    redactedPrompt: retainedPreview,
    findings: [{ type: 'SECRET_KEY', severity: 4, score: 0.95, masked: 'AK***EF' }],
    categories: [],
    entityCounts: { SECRET_KEY: 1 },
    riskScore: 30,
    maxSeverity: 4,
    maxSeverityLabel: 'critical',
    reasons: ['client-redacted test fixture'],
    _rawPrompt: dataCrypto.seal(retainedPreview),
  });
  assert.ok(retainedPreviewRow._rawPrompt);
  const retainedPreviewRevealRes = await jsonFetch(port, `/api/queries/${retainedPreviewRow.id}/reveal`, {
    headers,
    body: { password: 'unit-pass' },
  });
  assert.strictEqual(retainedPreviewRevealRes.status, 200);
  const retainedPreviewReveal = await retainedPreviewRevealRes.json();
  assert.strictEqual(retainedPreviewReveal.rawPrompt, retainedPreview);
  assert.strictEqual(retainedPreviewReveal.rawRetained, true);
  assert.strictEqual(retainedPreviewReveal.rawDiffersFromRedacted, false);

  const approveRes = await jsonFetch(port, `/api/queries/${approve.id}/approve`, {
    headers,
    body: { note: 'dashboard linkage approve', password: 'unit-pass' },
  });
  assert.strictEqual(approveRes.status, 200);
  assert.strictEqual((await approveRes.json()).status, 'approved');

  const denyRes = await jsonFetch(port, `/api/queries/${deny.id}/deny`, {
    headers,
    body: { note: 'dashboard linkage deny' },
  });
  assert.strictEqual(denyRes.status, 200);
  assert.strictEqual((await denyRes.json()).status, 'denied');

  const policyRes = await jsonFetch(port, '/api/policy', { method: 'GET', headers: { cookie } });
  assert.strictEqual(policyRes.status, 200);
  const p = await policyRes.json();
  const savePayload = {
    enforcementMode: p.enforcementMode,
    blockMinSeverity: p.blockMinSeverity,
    blockRiskScore: p.blockRiskScore,
    rawRetentionDays: p.rawRetentionDays ?? 30,
    desktopCollectorDestination: p.desktopCollectorDestination || 'Desktop AI',
    requiredSensors: p.requiredSensors || ['browser_extension', 'endpoint_agent', 'mcp_guard'],
    desiredSensorVersions: p.desiredSensorVersions || {},
    approvalRoutingRules: p.approvalRoutingRules || [],
    policyScopes: p.policyScopes || [],
    policyExceptions: p.policyExceptions || [],
    governedDestinations: p.governedDestinations || [],
    allowedDestinations: p.allowedDestinations || [],
    blockedDestinations: p.blockedDestinations || [],
    blockedFileUploadDestinations: p.blockedFileUploadDestinations || [],
    blockedBrowserActions: p.blockedBrowserActions || [],
    blockUnapprovedAiDestinations: p.blockUnapprovedAiDestinations !== false,
    responseScanMode: p.responseScanMode || 'flag',
  };
  const savePolicy = await jsonFetch(port, '/api/policy', {
    method: 'PUT',
    headers,
    body: savePayload,
  });
  assert.strictEqual(savePolicy.status, 200);

  const templates = await jsonFetch(port, '/api/policy/templates', { method: 'GET', headers: { cookie } });
  assert.strictEqual(templates.status, 200);
  const templateList = await templates.json();
  assert.ok(templateList.some((item) => item.id === 'baseline'));
  const applyTemplate = await jsonFetch(port, '/api/policy/apply-template', {
    method: 'PUT',
    headers,
    body: { id: 'baseline' },
  });
  assert.strictEqual(applyTemplate.status, 200);

  const destinationReview = await jsonFetch(port, '/api/destinations/review', {
    headers,
    body: { destination: 'example-ai.test', decision: 'block', reason: 'dashboard_linkage_test' },
  });
  assert.strictEqual(destinationReview.status, 200);
  assert.strictEqual((await destinationReview.json()).decision, 'block');

  const purge = await jsonFetch(port, '/api/retention/purge', { headers });
  assert.strictEqual(purge.status, 200);
  assert.strictEqual(typeof (await purge.json()).purged, 'number');

  const evidence = await jsonFetch(port, '/api/export/evidence?queryLimit=1000&auditLimit=1000', {
    method: 'GET',
    headers: { cookie },
  });
  assert.strictEqual(evidence.status, 200);
  const evidenceBody = await evidence.json();
  assert.ok(Array.isArray(evidenceBody.queries));
  assert.ok(evidenceBody.auditIntegrity && evidenceBody.auditIntegrity.ok);

  const logout = await jsonFetch(port, '/api/logout', { headers });
  assert.strictEqual(logout.status, 200);
}));

test.after(() => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { fs.unlinkSync(process.env.SENTINEL_DB_PATH + suffix); } catch {}
  }
  try { fs.unlinkSync(process.env.SENTINEL_POLICY_PATH); } catch {}
});
