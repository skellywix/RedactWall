'use strict';
/**
 * At-rest encryption for retained raw prompts (src/crypto.js).
 * Run via: node --test
 */
const test = require('node:test');
const assert = require('node:assert');

// Key must be set before requiring the module (it reads env at load time).
process.env.SENTINEL_DATA_KEY = process.env.SENTINEL_DATA_KEY || 'unit-test-stable-key';
const dataCrypto = require('../src/crypto');

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
