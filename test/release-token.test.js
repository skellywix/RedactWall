'use strict';
/** Release polling must be scoped to the sensor request that created the hold. */
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
process.env.SENTINEL_DB_PATH = path.join(os.tmpdir(), 'ps-release-token-test-' + crypto.randomBytes(6).toString('hex') + '.db');
process.env.SENTINEL_POLICY_PATH = path.join(os.tmpdir(), 'ps-release-token-policy-' + crypto.randomBytes(6).toString('hex') + '.json');

fs.writeFileSync(process.env.SENTINEL_POLICY_PATH, JSON.stringify({
  enforcementMode: 'block',
  blockMinSeverity: 2,
  blockRiskScore: 20,
  storeRawForApproval: true,
  rawRetentionDays: 30,
}, null, 2));

const app = require('../server/app');
const db = require('../server/db');
const releaseTokens = require('../server/release-token');

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

test('held prompt status polling requires the matching release token', async () => withServer(async (port) => {
  const gate = await jsonFetch(port, '/api/v1/gate', {
    headers: { 'x-api-key': 'unit-ingest-key' },
    body: {
      prompt: 'Please review this synthetic member SSN 524-71-9043 before submission.',
      user: 'analyst@example.test',
      destination: 'chatgpt.com',
      source: 'proxy',
      channel: 'submit',
    },
  });
  assert.strictEqual(gate.status, 200);
  const held = await gate.json();
  assert.strictEqual(held.status, 'pending');
  assert.match(held.releaseToken, /^[A-Za-z0-9_-]{32,}$/);

  const stored = db.getQuery(held.id);
  assert.ok(stored._releaseTokenHash);
  assert.ok(!JSON.stringify(stored).includes(held.releaseToken));

  const statusUrl = `http://127.0.0.1:${port}/api/v1/status/${held.id}`;
  const noToken = await fetch(statusUrl, { headers: { 'x-api-key': 'unit-ingest-key' } });
  assert.strictEqual(noToken.status, 401);
  assert.deepStrictEqual(await noToken.json(), { error: 'invalid release token' });

  const wrongToken = await fetch(statusUrl, {
    headers: { 'x-api-key': 'unit-ingest-key', 'x-release-token': 'not-the-release-token' },
  });
  assert.strictEqual(wrongToken.status, 401);

  const queryToken = await fetch(`${statusUrl}?releaseToken=${encodeURIComponent(held.releaseToken)}`, {
    headers: { 'x-api-key': 'unit-ingest-key' },
  });
  assert.strictEqual(queryToken.status, 401);

  const pending = await fetch(statusUrl, {
    headers: { 'x-api-key': 'unit-ingest-key', 'x-release-token': held.releaseToken },
  });
  assert.strictEqual(pending.status, 200);
  assert.deepStrictEqual(await pending.json(), { id: held.id, status: 'pending', released: false });

  const { cookie, csrfToken } = await login(port);
  const approve = await jsonFetch(port, `/api/queries/${held.id}/approve`, {
    headers: { cookie, 'x-csrf-token': csrfToken },
    body: { note: 'Synthetic approval for release-token test', password: 'unit-pass' },
  });
  assert.strictEqual(approve.status, 200);

  const released = await fetch(statusUrl, {
    headers: { 'x-api-key': 'unit-ingest-key', 'x-release-token': held.releaseToken },
  });
  assert.strictEqual(released.status, 200);
  assert.deepStrictEqual(await released.json(), { id: held.id, status: 'approved', released: true });

  const publicQuery = await fetch(`http://127.0.0.1:${port}/api/queries/${held.id}`, {
    headers: { cookie },
  });
  assert.strictEqual(publicQuery.status, 200);
  assert.ok(!JSON.stringify(await publicQuery.json()).includes('_releaseTokenHash'));

  const evidence = await fetch(`http://127.0.0.1:${port}/api/export/evidence`, {
    headers: { cookie },
  });
  assert.strictEqual(evidence.status, 200);
  const evidenceWire = JSON.stringify(await evidence.json());
  assert.ok(!evidenceWire.includes('_releaseTokenHash'));
  assert.ok(!evidenceWire.includes(held.releaseToken));
}));

test('held file scan returns a release token for approval polling', async () => withServer(async (port) => {
  const res = await jsonFetch(port, '/api/v1/scan-file', {
    headers: { 'x-api-key': 'unit-ingest-key' },
    body: {
      filename: 'member-note.txt',
      contentBase64: Buffer.from('Synthetic member SSN 524-71-9043 in a file.').toString('base64'),
      user: 'endpoint@example.test',
      destination: 'desktop-ai-app',
      source: 'endpoint_agent',
      channel: 'file_upload',
    },
  });
  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.status, 'pending');
  assert.match(body.releaseToken, /^[A-Za-z0-9_-]{32,}$/);
  assert.ok(!JSON.stringify(db.getQuery(body.id)).includes(body.releaseToken));
}));

test('release token helper verifies hashes and fails closed on malformed stored hashes', () => {
  const issued = releaseTokens.issueReleaseToken();
  assert.strictEqual(releaseTokens.verifyReleaseToken({ _releaseTokenHash: issued.hash }, issued.token), true);
  assert.strictEqual(releaseTokens.verifyReleaseToken({ _releaseTokenHash: issued.hash }, 'wrong'), false);
  assert.strictEqual(releaseTokens.verifyReleaseToken({ _releaseTokenHash: 'not-hex' }, issued.token), false);
  assert.strictEqual(releaseTokens.verifyReleaseToken({ _releaseTokenHash: 'a'.repeat(63) }, issued.token), false);
  assert.strictEqual(releaseTokens.verifyReleaseToken({ status: 'allowed' }, ''), true);
});

test.after(() => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { fs.unlinkSync(process.env.SENTINEL_DB_PATH + suffix); } catch {}
  }
  try { fs.unlinkSync(process.env.SENTINEL_POLICY_PATH); } catch {}
});
