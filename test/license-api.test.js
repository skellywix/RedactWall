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
delete process.env.REDACTWALL_LICENSE_MANAGED_EXTERNALLY;
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

  // 4) Installing a fresh valid license clears readonly unless the deployment
  // explicitly delegates license mutation to an external durable workflow.
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

test('externally managed deployments expose their source of truth and reject both in-app license installers', async (t) => {
  const originalBytes = fs.existsSync(process.env.REDACTWALL_LICENSE_PATH)
    ? fs.readFileSync(process.env.REDACTWALL_LICENSE_PATH)
    : null;
  const parkedLicense = `${process.env.REDACTWALL_LICENSE_PATH}.managed-readiness-test`;
  fs.writeFileSync(process.env.REDACTWALL_LICENSE_PATH, signLicense());
  license.refresh();
  process.env.REDACTWALL_LICENSE_MANAGED_EXTERNALLY = 'true';
  t.after(() => {
    if (fs.existsSync(parkedLicense)) fs.rmSync(parkedLicense, { force: true });
    if (originalBytes === null) fs.rmSync(process.env.REDACTWALL_LICENSE_PATH, { force: true });
    else fs.writeFileSync(process.env.REDACTWALL_LICENSE_PATH, originalBytes);
    delete process.env.REDACTWALL_LICENSE_MANAGED_EXTERNALLY;
    license.refresh();
  });
  const beforeBytes = fs.existsSync(process.env.REDACTWALL_LICENSE_PATH)
    ? fs.readFileSync(process.env.REDACTWALL_LICENSE_PATH)
    : null;
  const beforeStatus = license.status();

  const server = await listen(app);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const { port } = server.address();
  const { cookie, csrfToken } = await login(port);
  const status = await (await fetch(`http://127.0.0.1:${port}/api/billing/license`, { headers: { cookie } })).json();
  assert.strictEqual(status.managedExternally, true);

  for (const [apiPath, body] of [
    ['/api/admin/license/install', { license: signLicense({ seats: 60 }), reason: 'must use immutable AWS secret version' }],
    ['/api/billing/license', { license: signLicense({ seats: 60 }) }],
  ]) {
    const response = await jsonFetch(port, apiPath, {
      headers: { cookie, 'x-csrf-token': csrfToken },
      body,
    });
    assert.strictEqual(response.status, 409, apiPath);
    assert.strictEqual((await response.json()).error, 'license_managed_externally', apiPath);
  }
  const afterBytes = fs.existsSync(process.env.REDACTWALL_LICENSE_PATH)
    ? fs.readFileSync(process.env.REDACTWALL_LICENSE_PATH)
    : null;
  assert.deepStrictEqual(afterBytes, beforeBytes);
  assert.deepStrictEqual(license.status(), beforeStatus);

  assert.ok(beforeBytes, 'managed-license readiness regression requires an installed license');
  fs.renameSync(process.env.REDACTWALL_LICENSE_PATH, parkedLicense);
  const missingReady = await fetch(`http://127.0.0.1:${port}/readyz`);
  assert.strictEqual(missingReady.status, 503);
  const missingStatus = await (await fetch(`http://127.0.0.1:${port}/api/billing/license`, { headers: { cookie } })).json();
  assert.strictEqual(missingStatus.state, 'readonly');
  assert.match(missingStatus.reason, /^managed_license_/);
  assert.strictEqual(license.entitled('ncua_readiness'), false);
  fs.renameSync(parkedLicense, process.env.REDACTWALL_LICENSE_PATH);
  license.refresh();
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

test('historical vendor-license rows cannot authorize or revoke offline decisions', (t) => {
  const customerId = 'cu-inert-vendor-row';
  const row = db._db.prepare(`
    INSERT INTO vendor_license_state ("customerId", "issuedAt", "contactAt", status)
    VALUES (?, ?, ?, ?)
    ON CONFLICT("customerId") DO UPDATE SET
      "issuedAt" = excluded."issuedAt", "contactAt" = excluded."contactAt", status = excluded.status
  `);
  t.after(() => {
    db._db.prepare('DELETE FROM vendor_license_state WHERE "customerId" = ?').run(customerId);
    license.refresh({ readFile: () => { throw new Error('none'); } });
  });

  license.refresh({ readFile: () => { throw new Error('none'); }, now: Date.now() });
  assert.strictEqual(license.status().state, 'unlicensed');
  row.run(customerId, 1, 1, 'active');
  assert.strictEqual(license.status().state, 'unlicensed', 'an old active row grants nothing');

  license.refresh({ readFile: () => signLicense(), now: Date.now() });
  assert.strictEqual(license.status().state, 'active');
  row.run(customerId, 2, 2, 'revoked');
  assert.strictEqual(license.status().state, 'active', 'an old revoked row cannot override the signed file');
  assert.strictEqual(db.applyVendorHeartbeat, undefined);
  assert.strictEqual(db.lastVendorHeartbeat, undefined);
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
