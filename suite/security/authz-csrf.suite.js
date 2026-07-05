'use strict';
/**
 * Security: role and CSRF boundaries on the approval queue.
 * - approver cannot decide items routed to security_admin or assigned to
 *   another approver (IDOR via /api/queries/:id/approve|deny)
 * - auditor sessions can never perform CSRF-protected writes
 * - a valid session without x-csrf-token is rejected on unsafe routes
 */
const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');

const support = require('../support/app');
support.bootEnv({
  policy: {
    enforcementMode: 'block',
    blockMinSeverity: 2,
    blockRiskScore: 20,
    storeRawForApproval: true,
    rawRetentionDays: 30,
    approvalRoutingRules: [{
      id: 'engineering_source_code',
      categories: ['SOURCE_CODE'],
      assignedGroup: 'engineering',
      assignedRole: 'approver',
      slaMinutes: 90,
      reason: 'engineering_review',
    }],
  },
});
const app = support.requireApp();
const Database = require(path.join(support.ROOT, 'node_modules', 'better-sqlite3'));

function assignQueryUser(queryId, assignedUser) {
  const db = new Database(process.env.REDACTWALL_DB_PATH);
  try {
    const row = db.prepare('SELECT data FROM queries WHERE id = ?').get(queryId);
    const data = JSON.parse(row.data);
    data.assignedUser = assignedUser;
    db.prepare('UPDATE queries SET data = ? WHERE id = ?').run(JSON.stringify(data), queryId);
  } finally {
    db.close();
  }
}

async function seedSourceCodePrompt(port) {
  const res = await support.gate(port, {
    prompt: 'function calculateLimit(tier) { return tier === "gold" ? 5000 : 1000; }',
    user: 'engineer@example.test',
    destination: 'chatgpt.com',
    source: 'browser_extension',
    channel: 'submit',
    clientCategories: [{ category: 'SOURCE_CODE', score: 0.94 }],
  });
  const body = await res.json();
  assert.strictEqual(body.status, 'pending');
  return body;
}

test('approver cannot decide items routed to security_admin (IDOR)', async () => support.withServer(app, async (port) => {
  const adminItem = await support.seedHeldPrompt(port, { suffix: '8801' });
  const approver = await support.login(port, 'approver');
  const headers = { cookie: approver.cookie, 'x-csrf-token': approver.csrfToken };

  const approve = await support.request(port, `/api/queries/${adminItem.id}/approve`, {
    method: 'POST', headers, body: { note: 'idor attempt', password: approver.password },
  });
  assert.strictEqual(approve.status, 403);
  const deny = await support.request(port, `/api/queries/${adminItem.id}/deny`, {
    method: 'POST', headers, body: { note: 'idor attempt' },
  });
  assert.strictEqual(deny.status, 403);

  const bulk = await support.request(port, '/api/queries/bulk-decision', {
    method: 'POST', headers, body: { ids: [adminItem.id], action: 'deny' },
  });
  assert.strictEqual(bulk.status, 200);
  assert.deepStrictEqual((await bulk.json()).results[0], {
    id: adminItem.id, outcome: 'skipped', reason: 'not yours to decide',
  });

  const admin = await support.login(port, 'admin');
  const still = await support.request(port, `/api/queries/${adminItem.id}`, { headers: { cookie: admin.cookie } });
  assert.strictEqual((await still.json()).status, 'pending', 'item stays untouched after IDOR attempts');
}));

test('approver cannot decide an item assigned to a different approver', async () => support.withServer(app, async (port) => {
  const item = await seedSourceCodePrompt(port);
  assignQueryUser(item.id, 'someone-else@example.test');
  const approver = await support.login(port, 'approver');
  const deny = await support.request(port, `/api/queries/${item.id}/deny`, {
    method: 'POST',
    headers: { cookie: approver.cookie, 'x-csrf-token': approver.csrfToken },
    body: { note: 'not my item' },
  });
  assert.strictEqual(deny.status, 403);
}));

test('auditor sessions are rejected on every CSRF-protected write', async () => support.withServer(app, async (port) => {
  const held = await support.seedHeldPrompt(port, { suffix: '8802' });
  const auditor = await support.login(port, 'auditor');
  const headers = { cookie: auditor.cookie, 'x-csrf-token': auditor.csrfToken };
  const writes = [
    ['POST', `/api/queries/${held.id}/approve`, { note: 'x', password: auditor.password }],
    ['POST', `/api/queries/${held.id}/deny`, { note: 'x' }],
    ['POST', `/api/queries/${held.id}/reveal`, { password: auditor.password }],
    ['POST', '/api/queries/bulk-decision', { ids: [held.id], action: 'deny' }],
    ['POST', '/api/retention/purge', undefined],
    ['POST', '/api/policy/impact', { blockRiskScore: 10 }],
    ['PUT', '/api/policy', { rawRetentionDays: 7 }],
    ['PUT', '/api/policy/apply-template', { id: 'baseline' }],
    ['POST', '/api/destinations/review', { destination: 'chatgpt.com', decision: 'block' }],
    ['POST', '/api/tickets/sync', undefined],
  ];
  for (const [method, route, body] of writes) {
    const res = await support.request(port, route, { method, headers, body });
    assert.strictEqual(res.status, 403, `auditor must get 403 on ${method} ${route}, got ${res.status}`);
  }
}));

test('a valid admin session without the CSRF token is rejected on unsafe routes', async () => support.withServer(app, async (port) => {
  const held = await support.seedHeldPrompt(port, { suffix: '8803' });
  const admin = await support.login(port, 'admin');
  const noToken = { cookie: admin.cookie };
  for (const [method, route, body] of [
    ['PUT', '/api/policy', { blockRiskScore: 25 }],
    ['POST', `/api/queries/${held.id}/deny`, { note: 'x' }],
    ['POST', '/api/logout', undefined],
  ]) {
    const res = await support.request(port, route, { method, headers: noToken, body });
    assert.strictEqual(res.status, 403, `expected 403 without csrf on ${method} ${route}`);
    assert.deepStrictEqual(await res.json(), { error: 'invalid csrf token' });
  }
  const wrong = await support.request(port, `/api/queries/${held.id}/deny`, {
    method: 'POST', headers: { ...noToken, 'x-csrf-token': admin.csrfToken + 'x' }, body: { note: 'x' },
  });
  assert.strictEqual(wrong.status, 403, 'a tampered csrf token is rejected');
}));
