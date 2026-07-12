'use strict';
/** Signed, versioned, expiring sensor policy bundles — Ed25519, verify with the
 *  public key, fail closed on tamper or staleness. */
const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');

process.env.REDACTWALL_DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'pw-bundle-'));
test.after(() => fs.rmSync(process.env.REDACTWALL_DATA_DIR, { recursive: true, force: true }));

const pb = require('../server/policy-bundle');

const POLICY = { enforcementMode: 'block', alwaysBlock: ['US_SSN', 'CREDIT_CARD'], blockRiskScore: 25 };
const WINDOWS_O_TEMPORARY = 0x40;

test('a fresh bundle verifies with the published public key', () => {
  const bundle = pb.buildBundle(POLICY);
  const result = pb.verifyBundle(bundle, pb.publicKeyPem());
  assert.deepStrictEqual(result, { ok: true });
  assert.strictEqual(bundle.version, pb.BUNDLE_VERSION);
  assert.ok(bundle.expiresAt > bundle.issuedAt);
});

test('published policy ordering survives Chrome-style storage normalization', () => {
  const policy = {
    zeta: { second: true, first: false },
    alpha: [{ zebra: 1, aardvark: 2 }],
    versionMap: { 10: 'ten', 2: 'two' },
    enforcementMode: 'block',
  };
  const bundle = pb.buildBundle(policy);
  const chromeStored = JSON.parse(JSON.stringify(bundle, (_key, value) => {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return value;
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, value[key]]));
  }));
  assert.strictEqual(JSON.stringify(bundle.policy), pb.canonicalPolicyJson(policy));
  assert.deepStrictEqual(pb.verifyBundle(chromeStored, pb.publicKeyPem()), { ok: true });
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

test('policy key publication rolls back instead of leaving an nlink=2 target when source cleanup fails', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-policy-key-source-cleanup-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const file = path.join(root, 'private', '.policy-bundle-key.pem');
  let staged = '';
  let denied = false;
  const fsImpl = {
    ...fs,
    linkSync(source, destination) {
      if (path.resolve(destination) === path.resolve(file) && !staged) {
        staged = path.resolve(source);
      }
      return fs.linkSync(source, destination);
    },
    openSync(target, flags, mode) {
      if (!denied && staged && path.resolve(target) === staged
          && typeof flags === 'number' && (flags & WINDOWS_O_TEMPORARY) === WINDOWS_O_TEMPORARY) {
        denied = true;
        const error = new Error('synthetic policy key staging unlink EIO');
        error.code = 'EIO';
        throw error;
      }
      return fs.openSync(target, flags, mode);
    },
    unlinkSync(target) {
      if (!denied && staged && path.resolve(target) === staged) {
        denied = true;
        const error = new Error('synthetic policy key staging unlink EIO');
        error.code = 'EIO';
        throw error;
      }
      return fs.unlinkSync(target);
    },
  };

  assert.throws(
    () => pb.loadOrCreateKeypair({ keyFile: file, fs: fsImpl }),
    (error) => error?.code === 'POLICY_SIGNING_KEY_UNAVAILABLE',
  );
  assert.strictEqual(denied, true);
  assert.strictEqual(fs.existsSync(file), false, 'unverified multi-link target is rolled back');
  if (fs.existsSync(path.dirname(file))) {
    for (const entry of fs.readdirSync(path.dirname(file))) {
      const stat = fs.lstatSync(path.join(path.dirname(file), entry), { bigint: true });
      if (stat.isFile()) assert.strictEqual(stat.nlink, 1n);
    }
  }
});

test('policy key failure cleanup preserves a replacement at the staging pathname', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-policy-key-stage-replacement-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const file = path.join(root, 'private', '.policy-bundle-key.pem');
  const replacement = Buffer.from('replacement-policy-staging-bytes');
  let staged = '';
  const fsImpl = {
    ...fs,
    linkSync(source, destination) {
      if (path.resolve(destination) === path.resolve(file) && !staged) {
        staged = path.resolve(source);
        fs.renameSync(source, `${source}.retained-original`);
        fs.writeFileSync(source, replacement, { mode: 0o600 });
        const error = new Error('synthetic policy key publication collision');
        error.code = 'EIO';
        throw error;
      }
      return fs.linkSync(source, destination);
    },
  };

  assert.throws(
    () => pb.loadOrCreateKeypair({ keyFile: file, fs: fsImpl }),
    (error) => error?.code === 'POLICY_SIGNING_KEY_UNAVAILABLE',
  );
  assert.ok(staged);
  assert.strictEqual(fs.existsSync(file), false);
  assert.deepStrictEqual(fs.readFileSync(staged), replacement);
});
