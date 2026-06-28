'use strict';
/** Held approvals should carry sanitized owner/SLA routing metadata. */
const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');

process.env.ADMIN_PASSWORD = 'unit-pass';
process.env.SENTINEL_SECRET = 'unit-secret-stable';
process.env.SENTINEL_DATA_KEY = 'unit-data-key-stable';
process.env.INGEST_API_KEY = 'unit-ingest-key';
process.env.SENTINEL_DB_PATH = path.join(os.tmpdir(), 'ps-approval-routing-test-' + crypto.randomBytes(6).toString('hex') + '.db');
process.env.SENTINEL_POLICY_PATH = path.join(os.tmpdir(), 'ps-approval-routing-policy-' + crypto.randomBytes(6).toString('hex') + '.json');

fs.writeFileSync(process.env.SENTINEL_POLICY_PATH, JSON.stringify({
  enforcementMode: 'block',
  blockMinSeverity: 2,
  blockRiskScore: 20,
  storeRawForApproval: true,
  rawRetentionDays: 30,
}, null, 2));

const app = require('../server/app');
const db = require('../server/db');

function listen(appUnderTest) {
  return new Promise((resolve, reject) => {
    const server = appUnderTest.listen(0, '127.0.0.1', () => resolve(server));
    server.on('error', reject);
  });
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
  const csrfRes = await fetch(`http://127.0.0.1:${port}/api/csrf`, { headers: { cookie } });
  assert.strictEqual(csrfRes.status, 200);
  const csrf = await csrfRes.json();
  return { cookie, csrfToken: csrf.csrfToken };
}

test('gate stores and exposes approval routing without prompt content', async () => withServer(async (port) => {
  const rawCode = 'function leak(){ const token = process.env.CORE_BANKING_TOKEN; return token; }';
  const gate = await jsonFetch(port, '/api/v1/gate', {
    headers: { 'x-api-key': 'unit-ingest-key' },
    body: {
      prompt: rawCode,
      user: 'developer@example.test',
      destination: 'chatgpt.com',
      source: 'browser_extension',
      channel: 'submit',
    },
  });
  assert.strictEqual(gate.status, 200);
  const body = await gate.json();
  assert.strictEqual(body.status, 'pending');

  const stored = db.getQuery(body.id);
  assert.strictEqual(stored.assignedRole, 'security_admin');
  assert.strictEqual(stored.assignedGroup, 'security');
  assert.match(stored.workflowReason, /SOURCE_CODE/);
  assert.match(stored.slaDueAt, /^\d{4}-\d{2}-\d{2}T/);
  assert.strictEqual(stored.notificationStatus, 'not_configured');
  assert.ok(!JSON.stringify({
    assignedRole: stored.assignedRole,
    assignedGroup: stored.assignedGroup,
    workflowReason: stored.workflowReason,
    slaDueAt: stored.slaDueAt,
    notificationStatus: stored.notificationStatus,
  }).includes(rawCode));

  const { cookie } = await login(port);
  const queueRes = await jsonFetch(port, '/api/queries?status=pending', {
    method: 'GET',
    headers: { cookie },
  });
  assert.strictEqual(queueRes.status, 200);
  const queue = await queueRes.json();
  const queued = queue.find((row) => row.id === body.id);
  assert.ok(queued);
  assert.strictEqual(queued.assignedGroup, 'security');
  assert.strictEqual(queued._rawPrompt, undefined);
  assert.ok(!JSON.stringify(queued).includes(rawCode));

  const evidenceRes = await jsonFetch(port, '/api/export/evidence?queryLimit=50&auditLimit=50', {
    method: 'GET',
    headers: { cookie },
  });
  assert.strictEqual(evidenceRes.status, 200);
  const pack = await evidenceRes.json();
  const exported = pack.queries.find((row) => row.id === body.id);
  assert.ok(exported);
  assert.strictEqual(exported.workflow.assignedGroup, 'security');
  assert.strictEqual(exported.workflow.assignedRole, 'security_admin');
  assert.ok(!JSON.stringify(exported).includes(rawCode));
}));

test.after(() => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { fs.unlinkSync(process.env.SENTINEL_DB_PATH + suffix); } catch {}
  }
  try { fs.unlinkSync(process.env.SENTINEL_POLICY_PATH); } catch {}
});
