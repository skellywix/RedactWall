'use strict';
/** Raw prompt reveal requires password step-up. */
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
process.env.SENTINEL_DB_PATH = path.join(os.tmpdir(), 'ps-reveal-stepup-test-' + crypto.randomBytes(6).toString('hex') + '.db');
process.env.SENTINEL_POLICY_PATH = path.join(os.tmpdir(), 'ps-reveal-stepup-policy-' + crypto.randomBytes(6).toString('hex') + '.json');

fs.writeFileSync(process.env.SENTINEL_POLICY_PATH, JSON.stringify({
  enforcementMode: 'block',
  blockMinSeverity: 2,
  blockRiskScore: 20,
  storeRawForApproval: true,
  rawRetentionDays: 30,
}, null, 2));

const app = require('../server');
const db = require('../src/db');

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

async function createHeldPrompt(port, secret) {
  const res = await jsonFetch(port, '/api/v1/gate', {
    headers: { 'x-api-key': 'unit-ingest-key' },
    body: {
      prompt: 'Please review this member SSN ' + secret + ' before submission.',
      user: 'analyst@example.test',
      destination: 'chatgpt.com',
      source: 'api',
      channel: 'submit',
    },
  });
  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.status, 'pending');
  return body;
}

test('raw reveal requires password confirmation and audits failures', async () => withServer(async (port) => {
  const secret = '524-71-9043';
  const held = await createHeldPrompt(port, secret);
  const { cookie, csrfToken } = await login(port);

  const missing = await jsonFetch(port, `/api/queries/${held.id}/reveal`, {
    headers: { cookie, 'x-csrf-token': csrfToken },
  });
  assert.strictEqual(missing.status, 400);
  assert.deepStrictEqual(await missing.json(), {
    error: 'invalid request body',
    fields: ['password'],
  });

  const wrong = await jsonFetch(port, `/api/queries/${held.id}/reveal`, {
    headers: { cookie, 'x-csrf-token': csrfToken },
    body: { password: 'wrong-password' },
  });
  assert.strictEqual(wrong.status, 401);
  assert.ok(!JSON.stringify(await wrong.json()).includes(secret));
  assert.strictEqual(db.listAudit(20).filter((a) => a.action === 'REVEAL_FAILED').length, 1);

  const ok = await jsonFetch(port, `/api/queries/${held.id}/reveal`, {
    headers: { cookie, 'x-csrf-token': csrfToken },
    body: { password: 'unit-pass' },
  });
  assert.strictEqual(ok.status, 200);
  const body = await ok.json();
  assert.strictEqual(body.rawRetained, true);
  assert.ok(body.rawPrompt.includes(secret));
  assert.strictEqual(db.listAudit(20).filter((a) => a.action === 'REVEAL_RAW').length, 1);
  assert.strictEqual(db.verifyAuditChain().ok, true);

  for (let i = 0; i < 7; i += 1) {
    const failed = await jsonFetch(port, `/api/queries/${held.id}/reveal`, {
      headers: { cookie, 'x-csrf-token': csrfToken },
      body: { password: 'still-wrong' },
    });
    assert.strictEqual(failed.status, 401);
  }
  const locked = await jsonFetch(port, `/api/queries/${held.id}/reveal`, {
    headers: { cookie, 'x-csrf-token': csrfToken },
    body: { password: 'still-wrong' },
  });
  assert.strictEqual(locked.status, 429);
  assert.ok(!JSON.stringify(await locked.json()).includes(secret));
  assert.strictEqual(db.listAudit(20).filter((a) => a.action === 'REVEAL_LOCKED').length, 1);
}));

test.after(() => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { fs.unlinkSync(process.env.SENTINEL_DB_PATH + suffix); } catch {}
  }
  try { fs.unlinkSync(process.env.SENTINEL_POLICY_PATH); } catch {}
});
