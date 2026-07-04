'use strict';
/** Signed, versioned, expiring sensor policy bundles — Ed25519, verify with the
 *  public key, fail closed on tamper or staleness. */
const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');

process.env.SENTINEL_DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'pw-bundle-'));
test.after(() => fs.rmSync(process.env.SENTINEL_DATA_DIR, { recursive: true, force: true }));

const pb = require('../server/policy-bundle');

const POLICY = { enforcementMode: 'block', alwaysBlock: ['US_SSN', 'CREDIT_CARD'], blockRiskScore: 25 };

test('a fresh bundle verifies with the published public key', () => {
  const bundle = pb.buildBundle(POLICY);
  const result = pb.verifyBundle(bundle, pb.publicKeyPem());
  assert.deepStrictEqual(result, { ok: true });
  assert.strictEqual(bundle.version, pb.BUNDLE_VERSION);
  assert.ok(bundle.expiresAt > bundle.issuedAt);
});

test('a tampered policy fails verification (fail closed)', () => {
  const bundle = pb.buildBundle(POLICY);
  const tampered = { ...bundle, policy: { ...POLICY, alwaysBlock: [] } };
  assert.strictEqual(pb.verifyBundle(tampered, pb.publicKeyPem()).ok, false);
});

test('a tampered signature fails verification', () => {
  const bundle = pb.buildBundle(POLICY);
  const bad = { ...bundle, signature: Buffer.from('not-a-real-signature').toString('base64') };
  assert.strictEqual(pb.verifyBundle(bad, pb.publicKeyPem()).ok, false);
});

test('an expired bundle is rejected as stale', () => {
  const bundle = pb.buildBundle(POLICY, { now: '2020-01-01T00:00:00Z', ttlMs: 1000 });
  const result = pb.verifyBundle(bundle, pb.publicKeyPem());
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.reason, 'expired');
  assert.strictEqual(pb.isFresh(bundle), false);
});

test('the wrong public key does not verify a real bundle', () => {
  const bundle = pb.buildBundle(POLICY);
  const other = crypto.generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' }).toString();
  assert.strictEqual(pb.verifyBundle(bundle, other).ok, false);
});

test('a version mismatch is rejected', () => {
  const bundle = pb.buildBundle(POLICY);
  assert.strictEqual(pb.verifyBundle({ ...bundle, version: 99 }, pb.publicKeyPem()).reason, 'version_mismatch');
});

test('a malformed bundle returns {ok:false} and never throws (fail closed)', () => {
  const bundle = pb.buildBundle(POLICY);
  for (const bad of [{ ...bundle, policy: undefined }, { version: pb.BUNDLE_VERSION, signature: 'x' }, {}, null, 'nope']) {
    let result;
    assert.doesNotThrow(() => { result = pb.verifyBundle(bad, pb.publicKeyPem()); });
    assert.strictEqual(result.ok, false);
  }
});
