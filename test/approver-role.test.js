'use strict';
/** Approvers can decide assigned items without gaining Security Admin powers. */
const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');

process.env.ADMIN_PASSWORD = 'unit-pass';
process.env.APPROVER_USER = 'approver';
process.env.APPROVER_PASSWORD = 'approver-pass';
process.env.SENTINEL_SECRET = 'unit-secret-stable';
process.env.SENTINEL_DATA_KEY = 'unit-data-key-stable';
process.env.INGEST_API_KEY = 'unit-ingest-key';
process.env.SENTINEL_DB_PATH = path.join(os.tmpdir(), 'ps-approver-role-test-' + crypto.randomBytes(6).toString('hex') + '.db');
process.env.SENTINEL_POLICY_PATH = path.join(os.tmpdir(), 'ps-approver-role-policy-' + crypto.randomBytes(6).toString('hex') + '.json');

fs.writeFileSync(process.env.SENTINEL_POLICY_PATH, JSON.stringify({
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
}, null, 2));

const app = require('../server/app');
const { listen } = require('./support/listen');
const db = require('../server/db');
const policy = require('../server/policy');


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

async function login(port, user, password) {
  const res = await jsonFetch(port, '/api/login', {
    body: { user, password },
  });
  assert.strictEqual(res.status, 200);
  const body = await res.json();
  const cookie = (res.headers.get('set-cookie') || '').split(';')[0];
  const csrfRes = await fetch(`http://127.0.0.1:${port}/api/csrf`, { headers: { cookie } });
  assert.strictEqual(csrfRes.status, 200);
  const csrf = await csrfRes.json();
  return { cookie, csrfToken: csrf.csrfToken, body };
}

async function createHeldPrompt(port, prompt, destination = 'chatgpt.com', extra = {}) {
  const res = await jsonFetch(port, '/api/v1/gate', {
    headers: { 'x-api-key': 'unit-ingest-key' },
    body: {
      prompt,
      user: 'engineer@example.test',
      destination,
      source: 'browser_extension',
      channel: 'submit',
      ...extra,
    },
  });
  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.status, 'pending');
  return body;
}

test('approver can decide assigned items but cannot reveal, edit policy, or decide security-admin items', async () => withServer(async (port) => {
  const rawCode = 'function calculateLimit(memberTier) { return memberTier === "gold" ? 5000 : 1000; }';
  const rawSsn = 'Please review member SSN 524-71-9043 before release.';
  const assigned = await createHeldPrompt(port, rawCode, 'chatgpt.com', {
    clientCategories: [{ category: 'SOURCE_CODE', score: 0.94 }],
  });
  const security = await createHeldPrompt(port, rawSsn, 'claude.ai');

  assert.strictEqual(db.getQuery(assigned.id).assignedRole, 'approver');
  assert.strictEqual(db.getQuery(security.id).assignedRole, 'security_admin');

  const approver = await login(port, 'approver', 'approver-pass');
  assert.deepStrictEqual(approver.body, { ok: true, user: 'approver', role: 'approver' });

  const me = await fetch(`http://127.0.0.1:${port}/api/me`, { headers: { cookie: approver.cookie } });
  assert.strictEqual(me.status, 200);
  assert.strictEqual((await me.json()).role, 'approver');

  const queue = await fetch(`http://127.0.0.1:${port}/api/queries?status=pending`, { headers: { cookie: approver.cookie } });
  assert.strictEqual(queue.status, 200);
  const queueText = await queue.text();
  assert.ok(queueText.includes(assigned.id));
  assert.ok(queueText.includes(security.id));
  assert.ok(!queueText.includes(rawCode));
  assert.ok(!queueText.includes(rawSsn));

  for (const [apiPath, body, method = 'POST'] of [
    ['/api/queries/' + assigned.id + '/reveal', { password: 'approver-pass' }],
    ['/api/retention/purge', undefined],
    ['/api/policy', { rawRetentionDays: 7 }, 'PUT'],
    ['/api/destinations/review', { destination: 'poe.com', decision: 'allow', reason: 'unit_test' }],
  ]) {
    const res = await jsonFetch(port, apiPath, {
      method,
      headers: { cookie: approver.cookie, 'x-csrf-token': approver.csrfToken },
      body,
    });
    assert.strictEqual(res.status, 403, apiPath);
  }

  const blocked = await jsonFetch(port, `/api/queries/${security.id}/approve`, {
    headers: { cookie: approver.cookie, 'x-csrf-token': approver.csrfToken },
    body: { note: 'not my security item', password: 'approver-pass' },
  });
  assert.strictEqual(blocked.status, 403);
  assert.strictEqual(db.getQuery(security.id).status, 'pending');

  const approved = await jsonFetch(port, `/api/queries/${assigned.id}/approve`, {
    headers: { cookie: approver.cookie, 'x-csrf-token': approver.csrfToken },
    body: { note: 'Assigned engineering review approved', password: 'approver-pass' },
  });
  assert.strictEqual(approved.status, 200);
  const approvedBody = await approved.json();
  assert.strictEqual(approvedBody.status, 'approved');
  assert.strictEqual(approvedBody.decidedBy, 'approver');
  assert.strictEqual(db.getQuery(assigned.id).status, 'approved');
  assert.strictEqual(policy.loadPolicy().rawRetentionDays, 30);
  assert.strictEqual(db.verifyAuditChain().ok, true);
}));

test.after(() => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { fs.unlinkSync(process.env.SENTINEL_DB_PATH + suffix); } catch {}
  }
  try { fs.unlinkSync(process.env.SENTINEL_POLICY_PATH); } catch {}
});
