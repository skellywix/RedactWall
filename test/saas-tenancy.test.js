'use strict';
const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const fs = require('node:fs');

process.env.SENTINEL_DB_PATH = path.join(os.tmpdir(), 'ps-saas-test-' + crypto.randomBytes(6).toString('hex') + '.db');
process.env.SENTINEL_POLICY_PATH = path.join(os.tmpdir(), 'ps-saas-policy-' + crypto.randomBytes(6).toString('hex') + '.json');
process.env.INGEST_API_KEY = 'unit-saas-ingest-key';
process.env.ADMIN_PASSWORD = 'unit-pass';
process.env.SENTINEL_SECRET = 'unit-saas-secret-stable-value-32';
process.env.SENTINEL_DATA_KEY = 'unit-saas-data-key-stable-value-32';
process.env.SENTINEL_SAAS_MODE = 'true';
process.env.SENTINEL_TENANT_ID = 'cu-acme';
process.env.SENTINEL_SEAT_LIMIT = '1';
fs.writeFileSync(process.env.SENTINEL_POLICY_PATH, JSON.stringify({
  scanner: { maxFileBytes: 1024 },
}));

const app = require('../server/app');
const { listen } = require('./support/listen');
const db = require('../server/db');


async function postGate(port, body) {
  const res = await fetch(`http://127.0.0.1:${port}/api/v1/gate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.INGEST_API_KEY },
    body: JSON.stringify({
      prompt: 'ordinary business note',
      destination: 'chat.openai.com',
      source: 'browser_extension',
      channel: 'submit',
      ...body,
    }),
  });
  return { res, body: await res.json() };
}

async function postFile(port, body) {
  const res = await fetch(`http://127.0.0.1:${port}/api/v1/scan-file`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.INGEST_API_KEY },
    body: JSON.stringify({
      filename: 'note.txt',
      contentBase64: Buffer.from('ordinary business note').toString('base64'),
      destination: 'desktop-ai',
      source: 'endpoint_agent',
      channel: 'file_upload',
      ...body,
    }),
  });
  return { res, body: await res.json() };
}

async function postScanFile(port, body) {
  const res = await fetch(`http://127.0.0.1:${port}/api/v1/scan-file`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.INGEST_API_KEY },
    body: JSON.stringify({
      filename: 'oversized.txt',
      contentBase64: Buffer.alloc(2048).toString('base64'),
      destination: 'chat.openai.com',
      source: 'browser_extension',
      channel: 'file_upload',
      ...body,
    }),
  });
  return { res, body: await res.json() };
}

async function login(port) {
  const res = await fetch(`http://127.0.0.1:${port}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ user: 'admin', password: 'unit-pass' }),
  });
  assert.strictEqual(res.status, 200);
  return res.headers.get('set-cookie').split(';')[0];
}

test('SaaS mode enforces tenant identity and paid seat limit', async (t) => {
  const server = await listen(app);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const { port } = server.address();

  const missingTenant = await postGate(port, { user: 'analyst@example.test' });
  assert.strictEqual(missingTenant.res.status, 400);
  assert.strictEqual(missingTenant.body.status, 'tenant_context_required');

  const first = await postGate(port, { orgId: 'cu-acme', user: 'analyst@example.test' });
  assert.strictEqual(first.res.status, 200);
  assert.strictEqual(first.body.decision, 'allow');

  const knownAgain = await postGate(port, { orgId: 'cu-acme', user: 'analyst@example.test' });
  assert.strictEqual(knownAgain.res.status, 200);
  assert.strictEqual(knownAgain.body.decision, 'allow');

  const knownFile = await postFile(port, { orgId: 'cu-acme', user: 'analyst@example.test' });
  assert.strictEqual(knownFile.res.status, 200);
  assert.strictEqual(knownFile.body.decision, 'allow');

  const otherTenant = await postGate(port, { orgId: 'other-cu', user: 'analyst@example.test' });
  assert.strictEqual(otherTenant.res.status, 403);
  assert.strictEqual(otherTenant.body.status, 'tenant_mismatch');

  const otherTenantFile = await postScanFile(port, { orgId: 'other-cu', user: 'analyst@example.test' });
  assert.strictEqual(otherTenantFile.res.status, 403);
  assert.strictEqual(otherTenantFile.body.status, 'tenant_mismatch');

  const secondUser = await postGate(port, { orgId: 'cu-acme', user: 'second@example.test' });
  assert.strictEqual(secondUser.res.status, 402);
  assert.strictEqual(secondUser.body.status, 'seat_limit_blocked');
  assert.strictEqual(secondUser.body.seatLimit, 1);
  assert.strictEqual(secondUser.body.seatsUsed, 1);

  const secondFileUser = await postFile(port, { orgId: 'cu-acme', user: 'file-user@example.test' });
  assert.strictEqual(secondFileUser.res.status, 402);
  assert.strictEqual(secondFileUser.body.status, 'seat_limit_blocked');

  const cookie = await login(port);
  const seatsRes = await fetch(`http://127.0.0.1:${port}/api/billing/seats`, {
    headers: { Cookie: cookie },
  });
  assert.strictEqual(seatsRes.status, 200);
  const seats = await seatsRes.json();
  assert.strictEqual(seats.tenantId, 'cu-acme');
  assert.strictEqual(seats.seatLimit, 1);
  assert.strictEqual(seats.seatsUsed, 1);
  assert.deepStrictEqual(seats.users.map((u) => u.user), ['analyst@example.test']);
  assert.strictEqual(db.verifyAuditChain().ok, true);
});
