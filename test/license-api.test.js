'use strict';
/**
 * License gating must degrade ONLY the admin console config writes — never the
 * security function. With a past-grace license: /api/v1/gate still blocks,
 * approve/deny still work, audit/evidence export still work, PUT /api/policy is
 * 403 license_readonly, and installing a fresh license clears readonly.
 */
const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');

const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
const PUB = publicKey.export({ type: 'spki', format: 'pem' }).toString();

process.env.ADMIN_PASSWORD = 'unit-pass';
process.env.SENTINEL_SECRET = 'unit-secret-stable';
process.env.INGEST_API_KEY = 'unit-ingest-key';
process.env.SENTINEL_LICENSE_PUBLIC_KEY = PUB;
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pw-license-api-'));
process.env.SENTINEL_DB_PATH = path.join(tmp, 'test.db');
process.env.SENTINEL_LICENSE_PATH = path.join(tmp, 'promptwall.lic');
process.env.SENTINEL_POLICY_PATH = path.join(tmp, 'policy.json');
fs.writeFileSync(process.env.SENTINEL_POLICY_PATH, JSON.stringify({ enforcementMode: 'block', blockMinSeverity: 2, blockRiskScore: 20 }));

const app = require('../server/app');
const db = require('../server/db');
const license = require('../server/license');
const { listen } = require('./support/listen');

test.after(() => { try { db._db.close(); } catch {} fs.rmSync(tmp, { recursive: true, force: true }); });

function signLicense(over = {}) {
  const payload = { customer: 'Test CU', customerId: 'cu-1', plan: 'standard', seats: 50, features: [], issued: '2026-01-01T00:00:00Z', expires: '2027-01-01T00:00:00Z', graceDays: 30, ...over };
  const b64 = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64');
  const sig = crypto.sign(null, Buffer.from(b64, 'utf8'), privateKey).toString('base64');
  return `${b64}.${sig}`;
}

async function jsonFetch(port, apiPath, { method = 'POST', body, headers = {} } = {}) {
  return fetch(`http://127.0.0.1:${port}${apiPath}`, { method, headers: { 'Content-Type': 'application/json', ...headers }, body: body === undefined ? undefined : JSON.stringify(body) });
}

async function login(port) {
  const res = await jsonFetch(port, '/api/login', { body: { user: 'admin', password: 'unit-pass' } });
  assert.strictEqual(res.status, 200);
  const cookie = (res.headers.get('set-cookie') || '').split(';')[0];
  const csrf = await (await fetch(`http://127.0.0.1:${port}/api/csrf`, { headers: { cookie } })).json();
  return { cookie, csrfToken: csrf.csrfToken };
}

test('past-grace license makes config read-only but never disables the security function', async (t) => {
  // Put the module into readonly with a past-grace license.
  license.refresh({ readFile: () => signLicense({ expires: '2026-01-01T00:00:00Z' }), now: Date.now(), appendAudit: (r) => db.appendAudit(r) });
  assert.strictEqual(license.status().state, 'readonly');
  t.after(() => license.refresh({ readFile: () => { throw new Error('none'); } }));

  const server = await listen(app);
  t.after(() => new Promise((r) => server.close(r)));
  const { port } = server.address();
  const { cookie, csrfToken } = await login(port);

  // 1) Detection/enforcement still runs and blocks a hard-stop.
  const gate = await jsonFetch(port, '/api/v1/gate', { headers: { 'x-api-key': 'unit-ingest-key' }, body: { prompt: 'member SSN 123-45-6789', user: 'u@cu.org', destination: 'chatgpt.com' } });
  assert.strictEqual(gate.status, 200);
  assert.strictEqual((await gate.json()).decision, 'block');

  // 2) Audit + evidence export still work (auditRead, no requireWritable).
  assert.strictEqual((await fetch(`http://127.0.0.1:${port}/api/audit`, { headers: { cookie } })).status, 200);
  assert.strictEqual((await fetch(`http://127.0.0.1:${port}/api/export/evidence`, { headers: { cookie } })).status, 200);

  // 3) Config write is blocked with license_readonly.
  const put = await jsonFetch(port, '/api/policy', { method: 'PUT', headers: { cookie, 'x-csrf-token': csrfToken }, body: { enforcementMode: 'warn' } });
  assert.strictEqual(put.status, 403);
  assert.strictEqual((await put.json()).error, 'license_readonly');

  // 4) Installing a fresh valid license clears readonly (the install route is never gated).
  const install = await jsonFetch(port, '/api/billing/license', { headers: { cookie, 'x-csrf-token': csrfToken }, body: { license: signLicense() } });
  assert.strictEqual(install.status, 200);
  assert.strictEqual((await install.json()).state, 'active');
  assert.strictEqual(license.status().state, 'active');

  // 5) Now a config write succeeds.
  const put2 = await jsonFetch(port, '/api/policy', { method: 'PUT', headers: { cookie, 'x-csrf-token': csrfToken }, body: { enforcementMode: 'warn' } });
  assert.strictEqual(put2.status, 200);

  // 6) No raw license text leaks into audit entries.
  const audit = await (await fetch(`http://127.0.0.1:${port}/api/audit`, { headers: { cookie } })).json();
  assert.ok(!JSON.stringify(audit).includes('.'.repeat(0) + signLicense().slice(0, 30)), 'no raw license material in audit');
});

test('invalid license install is rejected with a reason and audited', async (t) => {
  const server = await listen(app);
  t.after(() => new Promise((r) => server.close(r)));
  const { port } = server.address();
  const { cookie, csrfToken } = await login(port);
  const res = await jsonFetch(port, '/api/billing/license', { headers: { cookie, 'x-csrf-token': csrfToken }, body: { license: 'garbage.garbage' } });
  assert.strictEqual(res.status, 400);
  assert.strictEqual((await res.json()).error, 'invalid_license');
});
