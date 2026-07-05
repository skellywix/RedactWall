'use strict';
/**
 * Offline Ed25519 license verification (server/license.js). Uses a throwaway
 * keypair injected via the publicKeyPem param, so no repo keypair is needed.
 */
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const license = require('../server/license');

const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
const PUB = publicKey.export({ type: 'spki', format: 'pem' }).toString();

function sign(payload) {
  const b64 = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64');
  const sig = crypto.sign(null, Buffer.from(b64, 'utf8'), privateKey).toString('base64');
  return `${b64}.${sig}`;
}

const base = { customer: 'Test CU', customerId: 'cu-1', plan: 'standard', seats: 50, features: [], issued: '2026-01-01T00:00:00Z', expires: '2027-01-01T00:00:00Z', graceDays: 30 };
const NOW = Date.parse('2026-07-05T00:00:00Z');

test('verifies a well-formed license', () => {
  const v = license.verifyLicenseText(sign(base), { publicKeyPem: PUB, now: NOW });
  assert.strictEqual(v.ok, true);
  assert.strictEqual(v.payload.customer, 'Test CU');
});

test('rejects tampering, wrong key, malformed, and missing without throwing', () => {
  const good = sign(base);
  assert.strictEqual(license.verifyLicenseText(good.slice(0, 10) + 'X' + good.slice(11), { publicKeyPem: PUB, now: NOW }).reason, 'bad_signature');
  const otherPub = crypto.generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' }).toString();
  assert.strictEqual(license.verifyLicenseText(good, { publicKeyPem: otherPub, now: NOW }).reason, 'bad_signature');
  assert.strictEqual(license.verifyLicenseText('not-a-license', { publicKeyPem: PUB }).reason, 'malformed');
  assert.strictEqual(license.verifyLicenseText('', { publicKeyPem: PUB }).reason, 'missing');
  assert.strictEqual(license.verifyLicenseText('garbage.garbage', { publicKeyPem: PUB }).reason, 'bad_signature');
});

test('rejects bad payloads (unknown plan, no seats, unparseable expiry)', () => {
  assert.strictEqual(license.verifyLicenseText(sign({ ...base, plan: 'ultra' }), { publicKeyPem: PUB, now: NOW }).reason, 'bad_payload');
  assert.strictEqual(license.verifyLicenseText(sign({ ...base, seats: 0 }), { publicKeyPem: PUB, now: NOW }).reason, 'bad_payload');
  assert.strictEqual(license.verifyLicenseText(sign({ ...base, expires: 'never' }), { publicKeyPem: PUB, now: NOW }).reason, 'bad_payload');
});

test('state machine: active / grace / readonly with graceDays default', () => {
  assert.strictEqual(license.evaluate(base, NOW), 'active');
  const expired = { ...base, expires: '2026-07-01T00:00:00Z', graceDays: 30 };
  assert.strictEqual(license.evaluate(expired, NOW), 'grace'); // 4 days after expiry, within 30
  const pastGrace = { ...base, expires: '2026-05-01T00:00:00Z', graceDays: 30 };
  assert.strictEqual(license.evaluate(pastGrace, NOW), 'readonly');
  // Missing payload / unparseable expiry -> unlicensed (never gates).
  assert.strictEqual(license.evaluate(null, NOW), 'unlicensed');
  assert.strictEqual(license.evaluate({ ...base, expires: 'x' }, NOW), 'unlicensed');
  // Default grace is 30 days when unspecified.
  assert.strictEqual(license.DEFAULT_GRACE_DAYS, 30);
});

test('loadStatus reads a file and refresh audits state transitions', () => {
  const text = sign(base);
  const audits = [];
  const deps = { readFile: () => text, publicKeyPem: PUB, now: NOW, appendAudit: (r) => audits.push(r) };
  const s = license.loadStatus(NOW, deps);
  assert.strictEqual(s.state, 'active');
  license.refresh({ ...deps });
  // The first refresh from the module's default 'unlicensed' should audit a transition.
  assert.ok(audits.some((a) => a.action === 'LICENSE_STATE_CHANGED'));
});

test('requireWritable gates config writes but exempts /api/queries/ and license install', () => {
  // Force readonly by installing a past-grace license into the module cache.
  const pastGrace = sign({ ...base, expires: '2026-05-01T00:00:00Z', graceDays: 30 });
  license.refresh({ readFile: () => pastGrace, publicKeyPem: PUB, now: NOW });
  assert.strictEqual(license.status().state, 'readonly');

  const run = (path, method = 'PUT') => {
    let code = null; let body = null; let nexted = false;
    license.requireWritable({ path, method }, { status: (c) => { code = c; return { json: (b) => { body = b; } }; } }, () => { nexted = true; });
    return { code, body, nexted };
  };
  assert.strictEqual(run('/api/policy').code, 403, 'policy write blocked in readonly');
  assert.strictEqual(run('/api/policy').body.error, 'license_readonly');
  assert.strictEqual(run('/api/queries/q1/reveal', 'POST').nexted, true, 'reveal passes (approval workflow)');
  assert.strictEqual(run('/api/billing/license', 'POST').nexted, true, 'license install always passes');

  // Restore to unlicensed so other tests are unaffected.
  license.refresh({ readFile: () => { throw new Error('none'); }, now: NOW });
  assert.strictEqual(license.status().state, 'unlicensed');
});
