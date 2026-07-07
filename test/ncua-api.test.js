'use strict';
/** NCUA Readiness route: auth, entitlement gating, and examiner-pack export. */
const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');

process.env.ADMIN_PASSWORD = 'unit-pass';
process.env.AUDITOR_USER = 'auditor';
process.env.AUDITOR_PASSWORD = 'auditor-pass';
process.env.REDACTWALL_SECRET = 'unit-secret-stable';
process.env.REDACTWALL_DATA_KEY = 'unit-data-key-stable';
process.env.INGEST_API_KEY = 'unit-ingest-key';
process.env.REDACTWALL_DB_PATH = path.join(os.tmpdir(), 'ps-ncua-api-test-' + crypto.randomBytes(6).toString('hex') + '.db');
process.env.REDACTWALL_POLICY_PATH = path.join(os.tmpdir(), 'ps-ncua-api-policy-' + crypto.randomBytes(6).toString('hex') + '.json');

fs.writeFileSync(process.env.REDACTWALL_POLICY_PATH, JSON.stringify({
  enforcementMode: 'block',
  blockMinSeverity: 2,
  blockRiskScore: 20,
}, null, 2));

const app = require('../server/app');
const { listen } = require('./support/listen');
const license = require('../server/license');

const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
const PUB = publicKey.export({ type: 'spki', format: 'pem' }).toString();

function signLicense(payload) {
  const b64 = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64');
  const sig = crypto.sign(null, Buffer.from(b64, 'utf8'), privateKey).toString('base64');
  return `${b64}.${sig}`;
}

function setLicense(payload) {
  license.refresh({
    publicKeyPem: PUB,
    readFile: () => {
      if (!payload) throw new Error('missing');
      return signLicense(payload);
    },
  });
}

const STANDARD_NO_ADDON = {
  customer: 'Test CU', customerId: 'cu-1', plan: 'standard', seats: 50,
  features: [], issued: '2026-01-01T00:00:00Z', expires: '2027-01-01T00:00:00Z',
};

function close(server) {
  return new Promise((resolve) => server.close(resolve));
}

async function withServer(fn) {
  const server = await listen(app);
  try {
    return await fn(server.address().port);
  } finally {
    await close(server);
    setLicense(null); // back to demo mode for whatever runs next
  }
}

async function login(port, user, password) {
  const res = await fetch(`http://127.0.0.1:${port}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ user, password }),
  });
  assert.strictEqual(res.status, 200);
  return (res.headers.get('set-cookie') || '').split(';')[0];
}

test('ncua readiness requires an authenticated console session', async () => {
  await withServer(async (port) => {
    const res = await fetch(`http://127.0.0.1:${port}/api/ncua/readiness`);
    assert.strictEqual(res.status, 401);
  });
});

test('ncua readiness returns the full report in demo mode for admin and auditor', async () => {
  await withServer(async (port) => {
    setLicense(null); // unlicensed = demo mode = entitled
    for (const [user, password] of [['admin', 'unit-pass'], ['auditor', 'auditor-pass']]) {
      const cookie = await login(port, user, password);
      const res = await fetch(`http://127.0.0.1:${port}/api/ncua/readiness`, { headers: { cookie } });
      assert.strictEqual(res.status, 200);
      const body = await res.json();
      assert.strictEqual(body.entitled, true);
      assert.strictEqual(body.report.profile, 'federal_credit_union');
      assert.ok(Number.isFinite(body.report.score));
      assert.ok(Array.isArray(body.report.controls));
      assert.ok(body.report.panels.audit.verified);
      const wire = JSON.stringify(body);
      assert.ok(!wire.includes('"salt"'));
      assert.ok(!wire.includes('"notes"'));
    }
  });
});

test('licensed install without the add-on gets entitled=false and no report', async () => {
  await withServer(async (port) => {
    setLicense(STANDARD_NO_ADDON);
    const cookie = await login(port, 'admin', 'unit-pass');
    const res = await fetch(`http://127.0.0.1:${port}/api/ncua/readiness`, { headers: { cookie } });
    assert.strictEqual(res.status, 200);
    assert.deepStrictEqual(await res.json(), { entitled: false, report: null });

    setLicense({ ...STANDARD_NO_ADDON, features: ['ncua_readiness'] });
    const granted = await fetch(`http://127.0.0.1:${port}/api/ncua/readiness`, { headers: { cookie } });
    const body = await granted.json();
    assert.strictEqual(body.entitled, true);
    assert.strictEqual(body.report.profile, 'federal_credit_union');
  });
});

test('examiner-profile export stamps schemaVersion 3; default export stays 2', async () => {
  await withServer(async (port) => {
    const cookie = await login(port, 'auditor', 'auditor-pass');
    const profiled = await fetch(
      `http://127.0.0.1:${port}/api/export/evidence?examinerProfile=federal_credit_union`,
      { headers: { cookie } },
    );
    assert.strictEqual(profiled.status, 200);
    const pack = await profiled.json();
    assert.strictEqual(pack.schemaVersion, 3);
    assert.strictEqual(pack.scope.examinerProfile, 'federal_credit_union');
    assert.strictEqual(pack.scope.rawPromptBodiesIncluded, false);
    assert.strictEqual(pack.ncuaReadiness.profile, 'federal_credit_union');

    const plain = await fetch(`http://127.0.0.1:${port}/api/export/evidence`, { headers: { cookie } });
    const plainPack = await plain.json();
    assert.strictEqual(plainPack.schemaVersion, 2);
    assert.strictEqual(plainPack.scope.examinerProfile, undefined);
    assert.strictEqual(plainPack.ncuaReadiness, undefined);
  });
});
