'use strict';
/**
 * Connected-mode license heartbeat (server/vendor-link.js). Opt-in egress:
 * dormant without an HTTPS server URL; applies ONLY signature-verified,
 * customer-bound verdicts; never changes state on an unreachable/forged reply;
 * carries seat counts and license ids only — no prompts or member data.
 */
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');

const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
const PUB = publicKey.export({ type: 'spki', format: 'pem' }).toString();
const { privateKey: attackerKey } = crypto.generateKeyPairSync('ed25519');

process.env.REDACTWALL_LICENSE_PUBLIC_KEY = PUB;
const license = require('../server/license');
const vendorLink = require('../server/vendor-link');

function signLicense(over = {}) {
  const payload = { customer: 'CU', customerId: 'cu-42', plan: 'enterprise', seats: 50, features: [], issued: '2026-01-01T00:00:00Z', expires: '2027-01-01T00:00:00Z', ...over };
  const b64 = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64');
  return `${b64}.${crypto.sign(null, Buffer.from(b64, 'utf8'), privateKey).toString('base64')}`;
}
function signVerdict(payload, key = privateKey) {
  const b64 = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64');
  return `${b64}.${crypto.sign(null, Buffer.from(b64, 'utf8'), key).toString('base64')}`;
}
function fetchReturning(text, ok = true, status = 200) {
  return async () => ({ ok, status, text: async () => text });
}
const CFG = { enabled: true, url: 'https://vendor.example.com/hb', timeoutMs: 8000 };

test.beforeEach(() => {
  license.refresh({ publicKeyPem: PUB, now: Date.parse('2026-07-08T00:00:00Z'), readFile: () => signLicense() });
  license.applyVendorVerdict(false);
});
test.after(() => license.applyVendorVerdict(false));

test('opt-in gating: disabled without a URL, http rejected, https enabled', () => {
  assert.strictEqual(vendorLink.enabled({}), false);
  assert.strictEqual(vendorLink.enabled({ REDACTWALL_LICENSE_SERVER_URL: 'http://plain.example.com' }), false);
  assert.strictEqual(vendorLink.enabled({ REDACTWALL_LICENSE_SERVER_URL: 'https://169.254.169.254/hb' }), false); // metadata blocked
  assert.strictEqual(vendorLink.enabled({ REDACTWALL_LICENSE_SERVER_URL: 'https://vendor.example.com/hb' }), true);
});

test('heartbeat body is prompt-free: seat counts and license ids only', () => {
  const body = vendorLink._internal.heartbeatBody({ seatReport: { seatsUsed: 12, seatLimit: 50, users: [{ user: 'roster@cu.test' }] }, version: '0.3.0', now: '2026-07-08T00:00:00Z' });
  assert.deepStrictEqual(body, { customerId: 'cu-42', plan: 'enterprise', seatsUsed: 12, seatLimit: 50, version: '0.3.0', sentAt: '2026-07-08T00:00:00Z' });
  assert.ok(!JSON.stringify(body).includes('roster@cu.test'));
});

test('a signed revoked verdict trips the kill-switch; a signed active verdict clears it', async () => {
  let r = await vendorLink.heartbeat({ settings: CFG, publicKeyPem: PUB, seatReport: { seatsUsed: 1 }, fetchImpl: fetchReturning(signVerdict({ status: 'revoked', customerId: 'cu-42' })) });
  assert.deepStrictEqual(r, { ok: true, verdict: { status: 'revoked' } });
  assert.strictEqual(license.isRevoked(), true);

  r = await vendorLink.heartbeat({ settings: CFG, publicKeyPem: PUB, seatReport: { seatsUsed: 1 }, fetchImpl: fetchReturning(signVerdict({ status: 'active', customerId: 'cu-42' })) });
  assert.deepStrictEqual(r, { ok: true, verdict: { status: 'active' } });
  assert.strictEqual(license.isRevoked(), false);
});

test('a forged, cross-customer, or unreachable verdict never changes state', async () => {
  const cases = [
    ['bad_verdict', fetchReturning(signVerdict({ status: 'revoked', customerId: 'cu-42' }, attackerKey))],
    ['customer_mismatch', fetchReturning(signVerdict({ status: 'revoked', customerId: 'cu-OTHER' }))],
    ['bad_verdict', fetchReturning('not-even-a-token')],
    ['http_500', fetchReturning('', false, 500)],
    ['unreachable', async () => { throw new Error('network down'); }],
  ];
  for (const [reason, fetchImpl] of cases) {
    const r = await vendorLink.heartbeat({ settings: CFG, publicKeyPem: PUB, seatReport: {}, fetchImpl });
    assert.strictEqual(r.ok, false);
    assert.strictEqual(r.reason, reason);
    assert.strictEqual(license.isRevoked(), false, `state must not change on ${reason}`);
  }
});

test('a revocation cannot be lifted by a forged active verdict', async () => {
  await vendorLink.heartbeat({ settings: CFG, publicKeyPem: PUB, seatReport: {}, fetchImpl: fetchReturning(signVerdict({ status: 'revoked', customerId: 'cu-42' })) });
  assert.strictEqual(license.isRevoked(), true);
  const forged = await vendorLink.heartbeat({ settings: CFG, publicKeyPem: PUB, seatReport: {}, fetchImpl: fetchReturning(signVerdict({ status: 'active', customerId: 'cu-42' }, attackerKey)) });
  assert.strictEqual(forged.ok, false);
  assert.strictEqual(license.isRevoked(), true); // still revoked
});

test('disabled link is a no-op', async () => {
  const r = await vendorLink.heartbeat({ settings: { enabled: false } });
  assert.deepStrictEqual(r, { ok: false, reason: 'disabled' });
});
