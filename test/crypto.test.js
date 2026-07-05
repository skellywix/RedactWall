'use strict';
/**
 * At-rest encryption for retained raw prompts (server/crypto.js).
 * Run via: node --test
 */
const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const os = require('node:os');
const { execFileSync } = require('node:child_process');

// Key must be set before requiring the module (it reads env at load time).
process.env.REDACTWALL_DATA_KEY = process.env.REDACTWALL_DATA_KEY || 'unit-test-stable-key';
const dataCrypto = require('../server/crypto');

const root = path.join(__dirname, '..');

// The module derives keys from env at require time, so rotation scenarios run
// in child processes with explicit key env (same pattern as db-migration tests).
function childEnv(overrides = {}) {
  return {
    ...process.env,
    REDACTWALL_ENV_PATH: path.join(os.tmpdir(), 'ps-crypto-test-missing.env'),
    REDACTWALL_SECRET: '',
    REDACTWALL_DATA_KEY: '',
    REDACTWALL_DATA_KEY_PREVIOUS: '',
    REDACTWALL_SECRET: '',
    REDACTWALL_DATA_KEY: '',
    REDACTWALL_DATA_KEY_PREVIOUS: '',
    ...overrides,
  };
}

function runCrypto(script, env, args = []) {
  return execFileSync(process.execPath, ['-e', script, ...args], {
    cwd: root,
    encoding: 'utf8',
    env: childEnv(env),
  });
}

function sealWithKeys(env, plaintext) {
  return runCrypto("const c = require('./server/crypto'); process.stdout.write(c.seal(process.argv[1]));", env, [plaintext]);
}

function inspectWithKeys(env, token) {
  const script = `
    const c = require('./server/crypto');
    const token = process.argv[1];
    const opened = c.open(token);
    process.stdout.write(JSON.stringify({
      opened,
      needsReseal: c.needsReseal(token),
      status: c.rotationStatus(),
      resealed: c.needsReseal(token) ? c.seal(opened) : null,
    }));
  `;
  return JSON.parse(runCrypto(script, env, [token]));
}

test('round-trips plaintext', () => {
  const pt = 'Member SSN 524-71-9043, card 4111 1111 1111 1111';
  const sealed = dataCrypto.seal(pt);
  assert.ok(dataCrypto.isSealed(sealed), 'output is a sealed token');
  assert.strictEqual(dataCrypto.open(sealed), pt, 'decrypts back to the original');
});

test('ciphertext does not leak the plaintext', () => {
  const sealed = dataCrypto.seal('SSN 524-71-9043');
  assert.ok(!sealed.includes('524-71-9043'), 'no cleartext in the stored token');
});

test('tampering is detected (auth tag)', () => {
  const sealed = dataCrypto.seal('sensitive');
  const tampered = sealed.slice(0, -3) + 'AAA';
  assert.strictEqual(dataCrypto.open(tampered), null, 'tampered ciphertext returns null, not garbage');
});

test('non-sealed input passes through open() unchanged (legacy rows)', () => {
  assert.strictEqual(dataCrypto.open('plain redacted text'), 'plain redacted text');
});

test('without a previous key nothing needs resealing and status reflects it', () => {
  assert.deepStrictEqual(dataCrypto.rotationStatus(), { enabled: true, previousKeyConfigured: false });
  assert.strictEqual(dataCrypto.needsReseal(dataCrypto.seal('sensitive')), false, 'current-key token');
  assert.strictEqual(dataCrypto.needsReseal('plain redacted text'), false, 'non-sealed value');
});

test('previous-key fallback opens old tokens and needsReseal flags them', () => {
  const pt = 'Member SSN 524-71-9043';
  const oldToken = sealWithKeys({ REDACTWALL_DATA_KEY: 'old-key-A' }, pt);

  const midRotation = inspectWithKeys({ REDACTWALL_DATA_KEY: 'new-key-B', REDACTWALL_DATA_KEY_PREVIOUS: 'old-key-A' }, oldToken);
  assert.strictEqual(midRotation.opened, pt, 'old token opens via previous-key fallback');
  assert.strictEqual(midRotation.needsReseal, true, 'old token is flagged for resealing');
  assert.deepStrictEqual(midRotation.status, { enabled: true, previousKeyConfigured: true });
  assert.ok(midRotation.resealed && midRotation.resealed !== oldToken, 'reseal produces a fresh token');

  const afterRotation = inspectWithKeys({ REDACTWALL_DATA_KEY: 'new-key-B', REDACTWALL_DATA_KEY_PREVIOUS: 'old-key-A' }, midRotation.resealed);
  assert.strictEqual(afterRotation.opened, pt, 'resealed token opens with the current key');
  assert.strictEqual(afterRotation.needsReseal, false, 'resealed token no longer needs resealing');
});

test('after the previous key is retired only current-key tokens open', () => {
  const pt = 'card 4111 1111 1111 1111';
  const oldToken = sealWithKeys({ REDACTWALL_DATA_KEY: 'old-key-A' }, pt);
  const resealed = inspectWithKeys({ REDACTWALL_DATA_KEY: 'new-key-B', REDACTWALL_DATA_KEY_PREVIOUS: 'old-key-A' }, oldToken).resealed;

  const newKeyOnly = { REDACTWALL_DATA_KEY: 'new-key-B' };
  assert.strictEqual(inspectWithKeys(newKeyOnly, resealed).opened, pt, 'resealed token survives retiring the old key');
  assert.strictEqual(inspectWithKeys(newKeyOnly, oldToken).opened, null, 'unrotated token is unreadable once the old key is gone');
});

test('wrong current and previous keys both return null, never garbage', () => {
  const oldToken = sealWithKeys({ REDACTWALL_DATA_KEY: 'old-key-A' }, 'sensitive');
  const result = inspectWithKeys({ REDACTWALL_DATA_KEY: 'wrong-key-C', REDACTWALL_DATA_KEY_PREVIOUS: 'wrong-key-D' }, oldToken);
  assert.strictEqual(result.opened, null);
  assert.strictEqual(result.needsReseal, false, 'unreadable tokens are not reseal candidates');
});

test('with no key configured encryption stays off (rotation change is inert)', () => {
  const sealedElsewhere = sealWithKeys({ REDACTWALL_DATA_KEY: 'old-key-A' }, 'sensitive');
  const script = `
    const c = require('./server/crypto');
    process.stdout.write(JSON.stringify({
      enabled: c.ENABLED,
      seal: c.seal('x'),
      openSealed: c.open(process.argv[1]),
      passThrough: c.open('plain text'),
      status: c.rotationStatus(),
    }));
  `;
  const result = JSON.parse(runCrypto(script, {}, [sealedElsewhere]));
  assert.deepStrictEqual(result, {
    enabled: false,
    seal: null,
    openSealed: null,
    passThrough: 'plain text',
    status: { enabled: false, previousKeyConfigured: false },
  });
});
