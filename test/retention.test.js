'use strict';
/** Raw approval-data retention purge API. */
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
process.env.SENTINEL_DB_PATH = path.join(os.tmpdir(), 'ps-retention-test-' + crypto.randomBytes(6).toString('hex') + '.db');
process.env.SENTINEL_POLICY_PATH = path.join(os.tmpdir(), 'ps-retention-policy-' + crypto.randomBytes(6).toString('hex') + '.json');

fs.writeFileSync(process.env.SENTINEL_POLICY_PATH, JSON.stringify({
  enforcementMode: 'block',
  blockMinSeverity: 2,
  blockRiskScore: 20,
  storeRawForApproval: true,
  rawRetentionDays: 30,
}, null, 2));

const app = require('../server');
const db = require('../src/db');
const policy = require('../src/policy');

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

test('admin purge endpoint removes finalized retained raw data and keeps pending review data', async () => withServer(async (port) => {
  const createdAt = '2026-01-01T00:00:00.000Z';
  const approved = db.createQuery({
    createdAt,
    status: 'approved',
    user: 'analyst@example.test',
    redactedPrompt: '[REDACTED: US_SSN]',
    _rawPrompt: 'sealed-old-raw',
  });
  const redacted = db.createQuery({
    createdAt,
    status: 'redacted',
    user: 'analyst@example.test',
    tokenizedPrompt: 'Member [[US_SSN_1]]',
    _tokenVault: 'sealed-old-vault',
  });
  const pending = db.createQuery({
    createdAt,
    status: 'pending',
    user: 'analyst@example.test',
    redactedPrompt: '[REDACTED: US_SSN]',
    _rawPrompt: 'sealed-pending-raw',
  });
  db.appendAudit({ action: 'APPROVED', queryId: approved.id, actor: 'admin' });
  db.appendAudit({ action: 'REDACTED', queryId: redacted.id, actor: 'sensor' });
  db.appendAudit({ action: 'BLOCKED', queryId: pending.id, actor: 'sensor' });

  const noAuth = await jsonFetch(port, '/api/retention/purge');
  assert.strictEqual(noAuth.status, 401);

  const { cookie, csrfToken } = await login(port);
  const res = await jsonFetch(port, '/api/retention/purge', {
    headers: { cookie, 'x-csrf-token': csrfToken },
  });
  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.rawRetentionDays, 30);
  assert.strictEqual(body.purged, 2);
  assert.deepStrictEqual(body.records.map((r) => r.id).sort(), [approved.id, redacted.id].sort());
  assert.ok(!JSON.stringify(body).includes('sealed-old-raw'));
  assert.ok(!JSON.stringify(body).includes('sealed-old-vault'));

  assert.strictEqual(db.getQuery(approved.id)._rawPrompt, undefined);
  assert.strictEqual(db.getQuery(redacted.id)._tokenVault, undefined);
  assert.strictEqual(db.getQuery(pending.id)._rawPrompt, 'sealed-pending-raw');
  assert.deepStrictEqual(db.getQuery(approved.id).retentionPurgedFields, ['rawPrompt']);
  assert.deepStrictEqual(db.getQuery(redacted.id).retentionPurgedFields, ['tokenVault']);
  assert.strictEqual(db.listAudit(10).filter((a) => a.action === 'RETENTION_PURGED').length, 2);
  assert.strictEqual(db.verifyAuditChain().ok, true);
}));

test('admin policy can update the raw retention window', async () => withServer(async (port) => {
  const { cookie, csrfToken } = await login(port);
  const res = await jsonFetch(port, '/api/policy', {
    method: 'PUT',
    headers: { cookie, 'x-csrf-token': csrfToken },
    body: { rawRetentionDays: 14 },
  });
  assert.strictEqual(res.status, 200);
  assert.strictEqual((await res.json()).rawRetentionDays, 14);
  assert.strictEqual(policy.rawRetentionDays(policy.loadPolicy()), 14);
}));

test('purged approval reveal falls back to redacted prompt without the secret', async () => withServer(async (port) => {
  const { cookie, csrfToken } = await login(port);
  const policyRes = await jsonFetch(port, '/api/policy', {
    method: 'PUT',
    headers: { cookie, 'x-csrf-token': csrfToken },
    body: { rawRetentionDays: 0 },
  });
  assert.strictEqual(policyRes.status, 200);

  const secret = '524-71-9043';
  const gate = await jsonFetch(port, '/api/v1/gate', {
    headers: { 'x-api-key': 'unit-ingest-key' },
    body: {
      prompt: 'Please review this member SSN ' + secret + ' before submission.',
      user: 'analyst@example.test',
      destination: 'chatgpt.com',
      source: 'api',
      channel: 'submit',
    },
  });
  assert.strictEqual(gate.status, 200);
  const gated = await gate.json();
  assert.strictEqual(gated.status, 'pending');

  const approve = await jsonFetch(port, `/api/queries/${gated.id}/approve`, {
    headers: { cookie, 'x-csrf-token': csrfToken },
    body: { note: 'Synthetic approval for retention test', password: 'unit-pass' },
  });
  assert.strictEqual(approve.status, 200);

  const beforeReveal = await jsonFetch(port, `/api/queries/${gated.id}/reveal`, {
    headers: { cookie, 'x-csrf-token': csrfToken },
    body: { password: 'unit-pass' },
  });
  assert.strictEqual(beforeReveal.status, 200);
  const beforeBody = await beforeReveal.json();
  assert.strictEqual(beforeBody.rawRetained, true);
  assert.ok(beforeBody.rawPrompt.includes(secret));

  const purge = await jsonFetch(port, '/api/retention/purge', {
    headers: { cookie, 'x-csrf-token': csrfToken },
  });
  assert.strictEqual(purge.status, 200);
  assert.strictEqual((await purge.json()).purged, 1);

  const afterReveal = await jsonFetch(port, `/api/queries/${gated.id}/reveal`, {
    headers: { cookie, 'x-csrf-token': csrfToken },
    body: { password: 'unit-pass' },
  });
  assert.strictEqual(afterReveal.status, 200);
  const afterBody = await afterReveal.json();
  assert.strictEqual(afterBody.rawRetained, false);
  assert.ok(!afterBody.rawPrompt.includes(secret));
  assert.strictEqual(db.getQuery(gated.id)._rawPrompt, undefined);
  assert.strictEqual(db.verifyAuditChain().ok, true);
}));

test.after(() => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { fs.unlinkSync(process.env.SENTINEL_DB_PATH + suffix); } catch {}
  }
  try { fs.unlinkSync(process.env.SENTINEL_POLICY_PATH); } catch {}
});
