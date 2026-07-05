'use strict';
/** Backend list APIs clamp hostile limit parameters before touching storage. */
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

process.env.ADMIN_PASSWORD = 'unit-pass';
process.env.REDACTWALL_SECRET = 'unit-secret-stable';
process.env.REDACTWALL_DATA_KEY = 'unit-data-key-stable';
process.env.INGEST_API_KEY = 'unit-ingest-key';
process.env.REDACTWALL_DB_PATH = path.join(os.tmpdir(), 'ps-api-limits-test-' + crypto.randomBytes(6).toString('hex') + '.db');
process.env.REDACTWALL_POLICY_PATH = path.join(os.tmpdir(), 'ps-api-limits-policy-' + crypto.randomBytes(6).toString('hex') + '.json');

fs.copyFileSync(path.join(__dirname, '..', 'config', 'policy.json'), process.env.REDACTWALL_POLICY_PATH);

const app = require('../server/app');
const { listen, loopbackHttpFetch } = require('./support/listen');

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
  return loopbackHttpFetch(`http://127.0.0.1:${port}${apiPath}`, {
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
  assert.match(cookie, /^redactwall_session=/);
  return { cookie };
}

async function createHeldPrompt(port, suffix) {
  const res = await jsonFetch(port, '/api/v1/gate', {
    headers: { 'x-api-key': 'unit-ingest-key' },
    body: {
      prompt: `Backend API limit contract SSN 524-71-${suffix}.`,
      user: `api-limit-${suffix}@example.test`,
      destination: 'chatgpt.com',
      source: 'api',
      channel: 'submit',
      orgId: 'qa-org',
    },
  });
  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.status, 'pending');
  return body;
}

test('list and export APIs clamp invalid and oversized limits', async () => withServer(async (port) => {
  for (const suffix of ['9401', '9402', '9403']) await createHeldPrompt(port, suffix);
  const { cookie } = await login(port);
  const authHeaders = { cookie };

  const oneQuery = await jsonFetch(port, '/api/queries?limit=1', { method: 'GET', headers: authHeaders });
  assert.strictEqual(oneQuery.status, 200);
  assert.strictEqual((await oneQuery.json()).length, 1);

  const negativeQuery = await jsonFetch(port, '/api/queries?limit=-20', { method: 'GET', headers: authHeaders });
  assert.strictEqual(negativeQuery.status, 200);
  assert.strictEqual((await negativeQuery.json()).length, 1);

  const blankQuery = await jsonFetch(port, '/api/queries?limit=', { method: 'GET', headers: authHeaders });
  assert.strictEqual(blankQuery.status, 200);
  assert.ok((await blankQuery.json()).length >= 3);

  const nonFiniteQuery = await jsonFetch(port, '/api/queries?limit=Infinity', { method: 'GET', headers: authHeaders });
  assert.strictEqual(nonFiniteQuery.status, 200);
  assert.ok((await nonFiniteQuery.json()).length >= 3);

  const cappedLineage = await jsonFetch(port, '/api/lineage?limit=999999', { method: 'GET', headers: authHeaders });
  assert.strictEqual(cappedLineage.status, 200);
  assert.strictEqual((await cappedLineage.json()).limit, 5000);

  const fallbackLineage = await jsonFetch(port, '/api/lineage?limit=Infinity', { method: 'GET', headers: authHeaders });
  assert.strictEqual(fallbackLineage.status, 200);
  assert.strictEqual((await fallbackLineage.json()).limit, 1000);

  const negativeExport = await jsonFetch(port, '/api/export/evidence?queryLimit=-20&auditLimit=999999', {
    method: 'GET',
    headers: authHeaders,
  });
  assert.strictEqual(negativeExport.status, 200);
  const negativePack = await negativeExport.json();
  assert.strictEqual(negativePack.scope.queryLimit, 1);
  assert.strictEqual(negativePack.scope.auditLimit, 5000);

  const fallbackExport = await jsonFetch(port, '/api/export/evidence?queryLimit=Infinity&auditLimit=NaN', {
    method: 'GET',
    headers: authHeaders,
  });
  assert.strictEqual(fallbackExport.status, 200);
  const fallbackPack = await fallbackExport.json();
  assert.strictEqual(fallbackPack.scope.queryLimit, 500);
  assert.strictEqual(fallbackPack.scope.auditLimit, 500);

  const audit = await jsonFetch(port, '/api/audit?limit=Infinity', { method: 'GET', headers: authHeaders });
  assert.strictEqual(audit.status, 200);
  const auditBody = await audit.json();
  assert.ok(Array.isArray(auditBody.entries));
  assert.ok(auditBody.integrity.ok);
}));

test.after(() => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { fs.unlinkSync(process.env.REDACTWALL_DB_PATH + suffix); } catch {}
  }
  try { fs.unlinkSync(process.env.REDACTWALL_POLICY_PATH); } catch {}
});
