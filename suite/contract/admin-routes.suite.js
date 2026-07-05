'use strict';
/**
 * Contract: every documented admin API route (README.md route table) rejects
 * anonymous callers and keeps its documented top-level response shape.
 */
const test = require('node:test');
const assert = require('node:assert');

const support = require('../support/app');
support.bootEnv();
const app = support.requireApp();

function hasKeys(body, keys) {
  for (const key of keys) assert.ok(key in body, `missing top-level key "${key}" in ${JSON.stringify(Object.keys(body))}`);
}

const GET_ROUTES = [
  ['/api/csrf', (b) => assert.strictEqual(typeof b.csrfToken, 'string')],
  ['/api/me', (b) => hasKeys(b, ['user', 'role', 'authProvider', 'defaultPassword'])],
  ['/api/queries', (b) => assert.ok(Array.isArray(b))],
  ['/api/queries?status=pending', (b) => assert.ok(Array.isArray(b))],
  ['/api/stats', (b) => hasKeys(b, ['total', 'pending', 'approved', 'denied', 'allowed', 'todayBlocked', 'topEntities'])],
  ['/api/billing/seats', (b) => hasKeys(b, ['saasMode', 'seatLimit', 'seatLimitValid', 'seatsUsed'])],
  ['/api/metrics', (b) => hasKeys(b, ['uptimeSec', 'auditOk', 'auditCount', 'ts'])],
  ['/api/preflight', (b) => hasKeys(b, ['production', 'ready', 'level', 'checks'])],
  ['/api/identity/setup-guide?provider=entra&tenantId=contoso.onmicrosoft.com',
    (b) => hasKeys(b, ['provider', 'scim', 'oidc', 'env', 'roleGroups'])],
  ['/api/risk', (b) => assert.ok(Array.isArray(b.users))],
  ['/api/coverage', (b) => hasKeys(b, ['generatedAt', 'score', 'totals', 'sensors', 'fleet'])],
  ['/api/posture', (b) => hasKeys(b, ['generatedAt', 'summary', 'metrics', 'objectives'])],
  ['/api/lineage', (b) => hasKeys(b, ['limit', 'lineage'])],
  ['/api/destinations/review', (b) => hasKeys(b, ['destinations', 'coverage'])],
  ['/api/policy/templates', (b) => {
    assert.ok(Array.isArray(b) && b.length > 0);
    hasKeys(b[0], ['id', 'label', 'policy']);
  }],
  ['/api/audit', (b) => {
    hasKeys(b, ['entries', 'integrity', 'retention']);
    assert.ok(Array.isArray(b.entries));
    assert.strictEqual(b.integrity.ok, true);
  }],
  ['/api/export/evidence', (b) => hasKeys(b, ['schemaVersion', 'generatedAt', 'policy', 'stats', 'auditIntegrity', 'coverage'])],
  ['/api/policy', (b) => {
    hasKeys(b, ['enforcementMode', 'blockMinSeverity', 'blockRiskScore', 'alwaysBlock', 'rawRetentionDays']);
    assert.ok(Array.isArray(b.alwaysBlock));
  }],
  ['/api/compliance', (b) => assert.ok(b.controlMappings)],
  ['/api/insights', (b) => hasKeys(b, ['generatedAt', 'windowDays', 'totals', 'decisions'])],
  ['/api/catalog', (b) => assert.ok(Array.isArray(b.apps))],
  ['/api/fleet', (b) => hasKeys(b, ['trackedSensors', 'users', 'gapCount'])],
];

const WRITE_ROUTES = [
  ['POST', '/api/logout'],
  ['POST', '/api/retention/purge'],
  ['POST', '/api/policy/impact'],
  ['PUT', '/api/policy'],
  ['PUT', '/api/policy/apply-template'],
  ['POST', '/api/queries/q_nope/approve'],
  ['POST', '/api/queries/q_nope/deny'],
  ['POST', '/api/queries/q_nope/reveal'],
  ['POST', '/api/queries/bulk-decision'],
  ['POST', '/api/receipts/verify'],
  ['POST', '/api/destinations/review'],
  ['POST', '/api/tickets/sync'],
  ['POST', '/api/posture/notify'],
];

test('admin GET routes require a session and keep their top-level shape', async () => support.withServer(app, async (port) => {
  const held = await support.seedHeldPrompt(port, { suffix: '9001' });
  for (const [route] of GET_ROUTES) {
    const anon = await support.request(port, route);
    assert.strictEqual(anon.status, 401, `expected 401 unauthenticated for ${route}`);
    assert.deepStrictEqual(await anon.json(), { error: 'unauthenticated' }, route);
  }
  const admin = await support.login(port, 'admin');
  for (const [route, check] of GET_ROUTES) {
    const res = await support.request(port, route, { headers: { cookie: admin.cookie } });
    assert.strictEqual(res.status, 200, `expected 200 for ${route}, got ${res.status}`);
    check(await res.json());
  }
  const one = await support.request(port, `/api/queries/${held.id}`, { headers: { cookie: admin.cookie } });
  assert.strictEqual(one.status, 200);
  const row = await one.json();
  assert.strictEqual(row.id, held.id);
  hasKeys(row, ['status', 'user', 'destination', 'findings', 'redactedPrompt']);
  assert.ok(!('_rawPrompt' in row) && !('_tokenVault' in row), 'sealed fields must never be serialized');
}));

test('admin write routes reject anonymous callers before validation runs', async () => support.withServer(app, async (port) => {
  for (const [method, route] of WRITE_ROUTES) {
    const res = await support.request(port, route, { method, body: {} });
    assert.strictEqual(res.status, 401, `expected 401 unauthenticated for ${method} ${route}`);
  }
}));

test('unknown query ids return 404 for authenticated admins, not a crash', async () => support.withServer(app, async (port) => {
  const admin = await support.login(port, 'admin');
  const res = await support.request(port, '/api/queries/q_does_not_exist', { headers: { cookie: admin.cookie } });
  assert.strictEqual(res.status, 404);
  assert.deepStrictEqual(await res.json(), { error: 'not found' });
}));
