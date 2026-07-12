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
process.env.REDACTWALL_SECRET = 'unit-secret-stable';
process.env.INGEST_API_KEY = 'unit-ingest-key';
process.env.REDACTWALL_LICENSE_PUBLIC_KEY = PUB;
process.env.REDACTWALL_LICENSE_CUSTOMER_ID = 'cu-1';
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pw-license-api-'));
const licenseDir = path.join(tmp, 'license');
require('../server/private-path').withPrivateDirectoryMutationLockSync(licenseDir, () => {}, {
  fs,
  directory: true,
  label: 'test license directory',
  ownerLabel: 'test license directory',
  lockTimeoutMs: 60_000,
  lockTimeoutMaximumMs: 60_000,
});
process.env.REDACTWALL_DB_PATH = path.join(tmp, 'test.db');
process.env.REDACTWALL_LICENSE_PATH = path.join(licenseDir, 'redactwall.lic');
process.env.REDACTWALL_POLICY_PATH = path.join(tmp, 'policy.json');
fs.writeFileSync(process.env.REDACTWALL_POLICY_PATH, JSON.stringify({ enforcementMode: 'block', blockMinSeverity: 2, blockRiskScore: 20 }));

const app = require('../server/app');
const db = require('../server/db');
const license = require('../server/license');
const vendorLink = require('../server/vendor-link');
const { opaqueReference } = require('../server/audit-reference');
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

  // Seat and renewal state are configuration too; only license installation is
  // exempt from readonly so an operator can recover the deployment.
  for (const [apiPath, body] of [
    ['/api/admin/license/seats/assign', { userKey: 'member@example.test', reason: 'readonly assignment must not persist' }],
    ['/api/admin/license/seats/release', { userKey: 'member@example.test', reason: 'readonly release must not persist' }],
    ['/api/admin/license/renewal-request', { requestedSeats: 60, note: 'readonly renewal must not persist' }],
  ]) {
    const blocked = await jsonFetch(port, apiPath, {
      headers: { cookie, 'x-csrf-token': csrfToken },
      body,
    });
    assert.strictEqual(blocked.status, 403, apiPath);
    assert.strictEqual((await blocked.json()).error, 'license_readonly', apiPath);
  }

  // 4) Installing a fresh valid license clears readonly (the install route is never gated).
  const install = await jsonFetch(port, '/api/admin/license/install', {
    headers: { cookie, 'x-csrf-token': csrfToken },
    body: { license: signLicense(), reason: 'restore licensed administration' },
  });
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

test('license file and in-memory state roll back when immutable install audit fails', async (t) => {
  const previous = signLicense({ seats: 41 });
  const candidate = signLicense({ seats: 99 });
  const exactPreviousBytes = Buffer.from(`${previous}\r\n \t`, 'utf8');
  fs.writeFileSync(process.env.REDACTWALL_LICENSE_PATH, exactPreviousBytes);
  license.refresh();
  assert.strictEqual(license.publicStatus().seats, 41);

  const server = await listen(app);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const { port } = server.address();
  const { cookie, csrfToken } = await login(port);
  db._db.exec(`
    CREATE TRIGGER fail_license_install_audit
    BEFORE INSERT ON audit
    WHEN NEW.action = 'LICENSE_INSTALLED'
    BEGIN
      SELECT RAISE(ABORT, 'synthetic license audit failure');
    END;
  `);
  t.after(() => db._db.exec('DROP TRIGGER IF EXISTS fail_license_install_audit'));

  const response = await jsonFetch(port, '/api/admin/license/install', {
    headers: { cookie, 'x-csrf-token': csrfToken },
    body: { license: candidate, reason: 'prove rollback on audit outage' },
  });
  assert.strictEqual(response.status, 500);
  assert.deepStrictEqual(await response.json(), { error: 'internal_error' });
  assert.deepStrictEqual(fs.readFileSync(process.env.REDACTWALL_LICENSE_PATH), exactPreviousBytes);
  assert.strictEqual(license.verifyLicenseText(fs.readFileSync(process.env.REDACTWALL_LICENSE_PATH, 'utf8')).payload.seats, 41);
  assert.strictEqual(license.publicStatus().seats, 41);
  assert.ok(!db.listAudit(100).some((entry) => entry.action === 'LICENSE_INSTALLED' && /seats=99/.test(entry.detail || '')));
});

test('vendor revocation fail-closed-blocks ingest but never disables evidence export', async (t) => {
  license.refresh({ readFile: () => signLicense(), now: Date.now() });
  license.applyVendorVerdict(true, { appendAudit: (r) => db.appendAudit(r) });
  t.after(() => license.applyVendorVerdict(false));
  assert.strictEqual(license.status().state, 'revoked');
  assert.strictEqual(license.publicStatus().reason, 'vendor_revoked');

  const server = await listen(app);
  t.after(() => new Promise((r) => server.close(r)));
  const { port } = server.address();
  const { cookie, csrfToken } = await login(port);

  // 1) EVERY sensor ingest path is fail-closed-blocked with a DISTINCT status
  //    (not an outage) — gate, scan-file, scan-response, heartbeat, discovery,
  //    and token rehydration.
  const key = { 'x-api-key': 'unit-ingest-key' };
  const revokedTenant = 'revoked-tenant';
  const nativeGateBody = {
    prompt: 'anything at all',
    user: 'u@cu.org',
    destination: 'chatgpt.com',
    orgId: revokedTenant,
    source: 'endpoint_agent',
    channel: 'file_upload',
    sensor: { name: 'endpoint_agent', version: '1.0.0', platform: 'test' },
    idempotency: { scope: 'native_handoff_v1', key: 'e'.repeat(64) },
  };
  const gate = await jsonFetch(port, '/api/v1/gate', { headers: key, body: nativeGateBody });
  assert.strictEqual(gate.status, 403);
  const gateBody = await gate.json();
  assert.strictEqual(gateBody.decision, 'block');
  assert.strictEqual(gateBody.status, 'license_revoked');
  assert.match(gateBody.id, /^q_/);
  const gateRetry = await jsonFetch(port, '/api/v1/gate', { headers: key, body: nativeGateBody });
  assert.strictEqual(gateRetry.status, 200);
  const gateRetryBody = await gateRetry.json();
  assert.strictEqual(gateRetryBody.id, gateBody.id);
  assert.strictEqual(gateRetryBody.status, 'license_revoked');
  assert.strictEqual(gateRetryBody.idempotentReplay, true);
  assert.strictEqual(db.listAudit(500).filter((entry) => entry.queryId === gateBody.id).length, 1);

  const scanFile = await jsonFetch(port, '/api/v1/scan-file', { headers: key, body: { filename: 'x.txt', contentBase64: Buffer.from('hi').toString('base64'), user: 'u@cu.org' } });
  assert.strictEqual(scanFile.status, 403);
  assert.strictEqual((await scanFile.json()).status, 'license_revoked');

  const scanResp = await jsonFetch(port, '/api/v1/scan-response', { headers: key, body: { text: 'model reply', user: 'u@cu.org' } });
  assert.strictEqual(scanResp.status, 403);

  const hb = await jsonFetch(port, '/api/v1/heartbeat', { headers: key, body: { user: 'u@cu.org', checks: [] } });
  assert.strictEqual(hb.status, 403);

  const disc = await jsonFetch(port, '/api/v1/discovery', { headers: key, body: { sightings: [{ destination: 'chatgpt.com' }] } });
  assert.strictEqual(disc.status, 403);

  const rehydrate = await jsonFetch(port, '/api/v1/rehydrate', { headers: { ...key, 'x-release-token': 'x' }, body: { id: 'nonexistent', text: 't' } });
  assert.strictEqual(rehydrate.status, 403);
  assert.strictEqual((await rehydrate.json()).status, 'license_revoked');

  // 2) Config writes are blocked with license_revoked.
  const put = await jsonFetch(port, '/api/policy', { method: 'PUT', headers: { cookie, 'x-csrf-token': csrfToken }, body: { enforcementMode: 'warn' } });
  assert.strictEqual(put.status, 403);
  assert.strictEqual((await put.json()).error, 'license_revoked');

  // 3) Evidence export STILL works — data protection is never disabled.
  assert.strictEqual((await fetch(`http://127.0.0.1:${port}/api/export/evidence`, { headers: { cookie } })).status, 200);

  // 4) A signed 'active' verdict clears the kill-switch and ingest resumes.
  license.applyVendorVerdict(false, { appendAudit: (r) => db.appendAudit(r) });
  const gate2 = await jsonFetch(port, '/api/v1/gate', { headers: { 'x-api-key': 'unit-ingest-key' }, body: { prompt: 'benign text', user: 'u@cu.org', destination: 'chatgpt.com' } });
  assert.strictEqual(gate2.status, 200);

  // 5) The revocation is recorded prompt-free in the audit chain.
  const audit = await (await fetch(`http://127.0.0.1:${port}/api/audit`, { headers: { cookie } })).json();
  const auditWire = JSON.stringify(audit);
  assert.ok(auditWire.includes('LICENSE_REVOKED_BLOCK'));
  assert.match(auditWire, /tenantRef=tenant_[A-Za-z0-9_-]{24}/);
  assert.ok(!auditWire.includes(revokedTenant), 'audit detail stores only an opaque tenant reference');
  assert.strictEqual(db.verifyAuditChain().ok, true);
});

test('the next authorization request adopts a newer revocation committed by another replica', async (t) => {
  const previousUrl = process.env.REDACTWALL_LICENSE_SERVER_URL;
  const previousToken = process.env.REDACTWALL_LICENSE_SERVER_TOKEN;
  process.env.REDACTWALL_LICENSE_SERVER_URL = 'https://license.example.test/heartbeat';
  process.env.REDACTWALL_LICENSE_SERVER_TOKEN = 'rwls_replica_request_test_0123456789abcdef';
  license.refresh({ readFile: () => signLicense(), now: Date.now() });
  license.applyVendorVerdict(false);
  license.setVendorStale(false);
  vendorLink._internal.reset();
  t.after(() => {
    if (previousUrl === undefined) delete process.env.REDACTWALL_LICENSE_SERVER_URL;
    else process.env.REDACTWALL_LICENSE_SERVER_URL = previousUrl;
    if (previousToken === undefined) delete process.env.REDACTWALL_LICENSE_SERVER_TOKEN;
    else process.env.REDACTWALL_LICENSE_SERVER_TOKEN = previousToken;
    license.applyVendorVerdict(false);
    license.setVendorStale(false);
    vendorLink._internal.reset();
  });

  const issuedAt = Date.now();
  const customerId = 'cu-1';
  const customerRef = opaqueReference('license', customerId);
  const state = { customerId, customerRef, issuedAt, contactAt: issuedAt, status: 'revoked' };
  const committed = db.applyVendorHeartbeat({
    ...state,
    audits: [{
      action: 'VENDOR_HEARTBEAT_OK',
      actor: 'vendor',
      detail: JSON.stringify({ customerRef, issuedAt, contactAt: issuedAt, status: 'revoked' }),
    }],
  });
  assert.strictEqual(committed.applied, true);
  assert.strictEqual(license.isRevoked(), false, 'replica B is still locally active before its next request');

  const server = await listen(app);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const { port } = server.address();
  const gate = await jsonFetch(port, '/api/v1/gate', {
    headers: { 'x-api-key': 'unit-ingest-key' },
    body: { prompt: 'benign text', user: 'replica-b@cu.test', destination: 'chatgpt.com' },
  });
  assert.strictEqual(gate.status, 403);
  assert.strictEqual((await gate.json()).status, 'license_revoked');
  assert.strictEqual(license.publicStatus().reason, 'vendor_revoked');
});

test('boot restore failure is fail-closed before the first ingest', async (t) => {
  const previousUrl = process.env.REDACTWALL_LICENSE_SERVER_URL;
  const originalReader = db.lastVendorHeartbeat;
  process.env.REDACTWALL_LICENSE_SERVER_URL = 'https://license.example.test/heartbeat';
  license.refresh({ readFile: () => signLicense(), now: Date.now() });
  license.applyVendorVerdict(false);
  license.setVendorStale(false);
  db.lastVendorHeartbeat = () => { throw new Error('synthetic shared-state read failure'); };
  app._internal.runVendorRestore();
  assert.strictEqual(license.isRevoked(), true);
  assert.strictEqual(license.publicStatus().reason, 'vendor_unreachable');
  t.after(() => {
    db.lastVendorHeartbeat = originalReader;
    if (previousUrl === undefined) delete process.env.REDACTWALL_LICENSE_SERVER_URL;
    else process.env.REDACTWALL_LICENSE_SERVER_URL = previousUrl;
    license.applyVendorVerdict(false);
    license.setVendorStale(false);
  });

  const server = await listen(app);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const { port } = server.address();
  const gate = await jsonFetch(port, '/api/v1/gate', {
    headers: { 'x-api-key': 'unit-ingest-key' },
    body: { prompt: 'benign text', user: 'restore-failure@cu.test', destination: 'chatgpt.com' },
  });
  assert.strictEqual(gate.status, 403);
  assert.strictEqual((await gate.json()).status, 'license_revoked');
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

test('license install rejects missing and mismatched customer bindings', async (t) => {
  const server = await listen(app);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const { port } = server.address();
  const { cookie, csrfToken } = await login(port);

  for (const [customerId, reason] of [
    [undefined, 'customer_id_missing'],
    ['billing@example.test', 'customer_id_invalid'],
    ['cu-other', 'customer_mismatch'],
  ]) {
    const res = await jsonFetch(port, '/api/billing/license', {
      headers: { cookie, 'x-csrf-token': csrfToken },
      body: { license: signLicense({ customerId }) },
    });
    assert.strictEqual(res.status, 400, String(customerId));
    const body = await res.json();
    assert.strictEqual(body.error, 'invalid_license');
    assert.strictEqual(body.reason, reason);
  }

  const bindingKeys = [
    'REDACTWALL_LICENSE_CUSTOMER_ID',
    'PROMPTWALL_LICENSE_CUSTOMER_ID',
    'SENTINEL_LICENSE_CUSTOMER_ID',
    'REDACTWALL_TENANT_ID',
    'PROMPTWALL_TENANT_ID',
    'SENTINEL_TENANT_ID',
  ];
  const priorBindings = new Map(bindingKeys.map((key) => [key, process.env[key]]));
  try {
    for (const key of bindingKeys) delete process.env[key];
    const res = await jsonFetch(port, '/api/billing/license', {
      headers: { cookie, 'x-csrf-token': csrfToken },
      body: { license: signLicense() },
    });
    assert.strictEqual(res.status, 400);
    assert.deepStrictEqual(await res.json(), {
      error: 'invalid_license',
      reason: 'customer_binding_missing',
    });
  } finally {
    for (const [key, value] of priorBindings) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
});
