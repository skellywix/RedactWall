'use strict';
/** Sensor ingest authentication: constant-time check plus invalid-key throttle. */
const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');

process.env.ADMIN_PASSWORD = 'unit-pass';
process.env.REDACTWALL_SECRET = 'unit-secret-stable';
process.env.REDACTWALL_DATA_KEY = 'unit-data-key-stable';
process.env.INGEST_API_KEY = 'unit-ingest-key';
process.env.INGEST_AUTH_MAX_FAILURES = '3';
process.env.INGEST_AUTH_WINDOW_MS = '60000';
process.env.INGEST_AUTH_LOCK_MS = '60000';
process.env.REDACTWALL_DB_PATH = path.join(os.tmpdir(), 'ps-ingest-auth-test-' + crypto.randomBytes(6).toString('hex') + '.db');

const app = require('../server/app');
const { listen } = require('./support/listen');


function close(server) {
  return new Promise((resolve) => server.close(resolve));
}

async function gate(port, key) {
  const headers = { 'Content-Type': 'application/json' };
  if (key !== undefined) headers['x-api-key'] = key;
  return fetch(`http://127.0.0.1:${port}/api/v1/gate`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ prompt: 'Draft a lobby announcement.' }),
  });
}

test('invalid ingest keys are sanitized and throttled without blocking a valid key', async (t) => {
  const server = await listen(app);
  t.after(() => close(server));
  const { port } = server.address();
  const wrongKey = 'wrong-key-should-not-echo';

  let res = await gate(port, wrongKey);
  assert.strictEqual(res.status, 401);
  let body = await res.json();
  assert.deepStrictEqual(body, { error: 'invalid ingest key' });
  assert.ok(!JSON.stringify(body).includes(wrongKey));

  res = await gate(port, wrongKey);
  assert.strictEqual(res.status, 401);

  res = await gate(port, wrongKey);
  assert.strictEqual(res.status, 429);
  body = await res.json();
  assert.strictEqual(body.error, 'too many ingest key attempts');
  assert.ok(body.retryMs > 0);
  assert.ok(!JSON.stringify(body).includes(wrongKey));

  res = await gate(port, 'unit-ingest-key');
  assert.strictEqual(res.status, 200);
  body = await res.json();
  assert.strictEqual(body.decision, 'allow');
});

test.after(() => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { fs.unlinkSync(process.env.REDACTWALL_DB_PATH + suffix); } catch {}
  }
});
