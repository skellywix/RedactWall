'use strict';
/** Read-only auditor access for examiner evidence review. */
const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');

process.env.ADMIN_PASSWORD = 'unit-pass';
process.env.AUDITOR_USER = 'auditor';
process.env.AUDITOR_PASSWORD = 'auditor-pass';
process.env.SENTINEL_SECRET = 'unit-secret-stable';
process.env.SENTINEL_DATA_KEY = 'unit-data-key-stable';
process.env.INGEST_API_KEY = 'unit-ingest-key';
process.env.SENTINEL_DB_PATH = path.join(os.tmpdir(), 'ps-auditor-role-test-' + crypto.randomBytes(6).toString('hex') + '.db');
process.env.SENTINEL_POLICY_PATH = path.join(os.tmpdir(), 'ps-auditor-role-policy-' + crypto.randomBytes(6).toString('hex') + '.json');

fs.writeFileSync(process.env.SENTINEL_POLICY_PATH, JSON.stringify({
  enforcementMode: 'block',
  blockMinSeverity: 2,
  blockRiskScore: 20,
  storeRawForApproval: true,
  rawRetentionDays: 30,
}, null, 2));

const app = require('../server/app');
const db = require('../server/db');
const policy = require('../server/policy');

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

async function createHeldPrompt(port, secret) {
  const res = await jsonFetch(port, '/api/v1/gate', {
    headers: { 'x-api-key': 'unit-ingest-key' },
    body: {
      prompt: 'Please review this member SSN ' + secret + ' before submission.',
      user: 'analyst@example.test',
      destination: 'chatgpt.com',
      source: 'browser_extension',
      channel: 'submit',
    },
  });
  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.status, 'pending');
  return body;
}

test('auditor can inspect evidence but cannot reveal, decide, purge, or edit policy', async () => withServer(async (port) => {
  const secret = '524-71-9043';
  const held = await createHeldPrompt(port, secret);
  const auditor = await login(port, 'auditor', 'auditor-pass');
  assert.deepStrictEqual(auditor.body, { ok: true, user: 'auditor', role: 'auditor' });

  const me = await fetch(`http://127.0.0.1:${port}/api/me`, { headers: { cookie: auditor.cookie } });
  assert.strictEqual(me.status, 200);
  assert.strictEqual((await me.json()).role, 'auditor');

  const queries = await fetch(`http://127.0.0.1:${port}/api/queries?status=pending`, { headers: { cookie: auditor.cookie } });
  assert.strictEqual(queries.status, 200);
  const queryRows = await queries.json();
  assert.ok(queryRows.some((q) => q.id === held.id));
  assert.ok(!JSON.stringify(queryRows).includes(secret));

  for (const apiPath of [
    `/api/queries/${held.id}`,
    '/api/stats',
    '/api/preflight',
    '/api/audit',
    '/api/export/evidence',
    '/api/policy',
    '/api/policy/templates',
  ]) {
    const res = await fetch(`http://127.0.0.1:${port}${apiPath}`, { headers: { cookie: auditor.cookie } });
    assert.strictEqual(res.status, 200, apiPath);
    const text = await res.text();
    assert.ok(!text.includes(secret), apiPath);
  }

  const templates = await fetch(`http://127.0.0.1:${port}/api/policy/templates`, { headers: { cookie: auditor.cookie } });
  const templateId = (await templates.json())[0].id;
  const forbidden = [
    ['/api/queries/' + held.id + '/reveal', { password: 'auditor-pass' }],
    ['/api/queries/' + held.id + '/approve', { note: 'auditor attempt', password: 'auditor-pass' }],
    ['/api/queries/' + held.id + '/deny', { note: 'auditor attempt' }],
    ['/api/retention/purge', undefined],
    ['/api/policy', { rawRetentionDays: 7 }, 'PUT'],
    ['/api/policy/apply-template', { id: templateId }, 'PUT'],
  ];
  for (const [apiPath, body, method = 'POST'] of forbidden) {
    const res = await jsonFetch(port, apiPath, {
      method,
      headers: { cookie: auditor.cookie, 'x-csrf-token': auditor.csrfToken },
      body,
    });
    assert.strictEqual(res.status, 403, apiPath);
  }

  const logout = await jsonFetch(port, '/api/logout', {
    headers: { cookie: auditor.cookie, 'x-csrf-token': auditor.csrfToken },
  });
  assert.strictEqual(logout.status, 200);
  assert.strictEqual(db.getQuery(held.id).status, 'pending');
  assert.strictEqual(policy.loadPolicy().rawRetentionDays, 30);

  const admin = await login(port, 'admin', 'unit-pass');
  assert.strictEqual(admin.body.role, 'security_admin');
  const approve = await jsonFetch(port, `/api/queries/${held.id}/approve`, {
    headers: { cookie: admin.cookie, 'x-csrf-token': admin.csrfToken },
    body: { note: 'Synthetic approval after auditor review', password: 'unit-pass' },
  });
  assert.strictEqual(approve.status, 200);
  assert.strictEqual((await approve.json()).status, 'approved');
  assert.strictEqual(db.getQuery(held.id).status, 'approved');
  assert.strictEqual(db.verifyAuditChain().ok, true);
}));

test.after(() => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { fs.unlinkSync(process.env.SENTINEL_DB_PATH + suffix); } catch {}
  }
  try { fs.unlinkSync(process.env.SENTINEL_POLICY_PATH); } catch {}
});
