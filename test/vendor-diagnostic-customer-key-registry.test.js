'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const test = require('node:test');
const {
  createCustomerDeletionIntentKeyRegistry,
  deletionIntentSigningInput,
} = require('../server/vendor-diagnostic-customer-key-registry');

const NOW = Date.parse('2026-07-13T12:00:00.000Z');
const DOMAIN = 'redactwall.customer-diagnostic-deletion-intent.v1';
const DEPLOYMENT_A = 'dep_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const DEPLOYMENT_B = 'dep_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const LEGACY_DEPLOYMENT = 'deployment_registry_a';

function keyRecord(pair, keyId, validFrom, verifyUntil) {
  const record = {
    keyId,
    publicKey: pair.publicKey.export({ format: 'pem', type: 'spki' }),
    validFrom: new Date(validFrom).toISOString(),
  };
  if (verifyUntil !== undefined) record.verifyUntil = new Date(verifyUntil).toISOString();
  return record;
}

function signature(pair, keyId, message) {
  return crypto.sign(
    null, deletionIntentSigningInput(DOMAIN, keyId, message), pair.privateKey,
  ).toString('base64');
}

test('customer deletion key registry is verify-only, scope-bound, and rotation-aware', () => {
  let nowMs = NOW;
  const current = crypto.generateKeyPairSync('ed25519');
  const old = crypto.generateKeyPairSync('ed25519');
  const other = crypto.generateKeyPairSync('ed25519');
  const registry = createCustomerDeletionIntentKeyRegistry({
    now: () => nowMs,
    entries: [{
      customerId: 'cu-registry-a',
      deploymentId: DEPLOYMENT_A,
      current: keyRecord(current, 'delete-a-current', NOW - 60_000),
      verifyOnly: [keyRecord(old, 'delete-a-old', NOW - 120_000, NOW + 60_000)],
    }, {
      customerId: 'cu-registry-b',
      deploymentId: DEPLOYMENT_B,
      current: keyRecord(other, 'delete-b-current', NOW - 60_000),
      verifyOnly: [],
    }],
  });
  assert.equal(typeof registry.sign, 'undefined');
  assert.equal(registry.manifestDigest.length, 64);
  const message = '{"intent":"prompt-free"}';
  const request = {
    customerId: 'cu-registry-a',
    deploymentId: DEPLOYMENT_A,
    domain: DOMAIN,
    issuedAt: new Date(NOW).toISOString(),
    keyId: 'delete-a-current',
    message,
    signature: signature(current, 'delete-a-current', message),
  };
  assert.equal(registry.verify(request), true);
  assert.equal(registry.verify({ ...request, deploymentId: DEPLOYMENT_B }), false);
  assert.equal(registry.verify({
    ...request,
    keyId: 'delete-a-old',
    signature: signature(old, 'delete-a-old', message),
  }), true);
  nowMs = NOW + 60_001;
  assert.equal(registry.verify({
    ...request,
    keyId: 'delete-a-old',
    signature: signature(old, 'delete-a-old', message),
  }), false);
});

test('customer deletion key registry rejects public-key reuse across scopes', () => {
  const pair = crypto.generateKeyPairSync('ed25519');
  assert.throws(() => createCustomerDeletionIntentKeyRegistry({ entries: [{
    customerId: 'cu-registry-a',
    deploymentId: DEPLOYMENT_A,
    current: keyRecord(pair, 'delete-a-current', NOW),
    verifyOnly: [],
  }, {
    customerId: 'cu-registry-b',
    deploymentId: DEPLOYMENT_B,
    current: keyRecord(pair, 'delete-b-current', NOW),
    verifyOnly: [],
  }] }), (error) => error.code === 'key_identity_reused');
});

test('customer deletion key registry rejects every private-key representation', () => {
  const pair = crypto.generateKeyPairSync('ed25519');
  const privatePem = pair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const privateDer = pair.privateKey.export({ type: 'pkcs8', format: 'der' });
  for (const publicKey of [
    privatePem,
    { key: privateDer, format: 'der', type: 'pkcs8' },
    pair.privateKey,
  ]) {
    assert.throws(() => createCustomerDeletionIntentKeyRegistry({ entries: [{
      customerId: 'cu-registry-a',
      deploymentId: DEPLOYMENT_A,
      current: {
        ...keyRecord(pair, 'delete-a-current', NOW),
        publicKey,
      },
      verifyOnly: [],
    }] }), (error) => error.code === 'registry_invalid');
  }
});

test('customer deletion key registry rejects legacy broad deployment ids before persistence', () => {
  const pair = crypto.generateKeyPairSync('ed25519');
  assert.throws(() => createCustomerDeletionIntentKeyRegistry({ entries: [{
    customerId: 'cu-registry-a',
    deploymentId: LEGACY_DEPLOYMENT,
    current: keyRecord(pair, 'delete-a-current', NOW),
    verifyOnly: [],
  }] }), (error) => error.code === 'registry_invalid');
});

test('customer deletion key registry keeps exact sibling deployment scopes distinct', () => {
  const first = crypto.generateKeyPairSync('ed25519');
  const sibling = crypto.generateKeyPairSync('ed25519');
  const registry = createCustomerDeletionIntentKeyRegistry({ entries: [{
    customerId: 'cu-registry-a',
    deploymentId: DEPLOYMENT_A,
    current: keyRecord(first, 'delete-a-current', NOW),
    verifyOnly: [],
  }, {
    customerId: 'cu-registry-a',
    deploymentId: DEPLOYMENT_B,
    current: keyRecord(sibling, 'delete-b-current', NOW),
    verifyOnly: [],
  }] });
  const message = '{"intent":"prompt-free"}';
  const request = {
    customerId: 'cu-registry-a',
    deploymentId: DEPLOYMENT_A,
    domain: DOMAIN,
    issuedAt: new Date(NOW).toISOString(),
    keyId: 'delete-a-current',
    message,
    signature: signature(first, 'delete-a-current', message),
  };
  assert.equal(registry.verify(request), true);
  assert.equal(registry.verify({ ...request, deploymentId: DEPLOYMENT_B }), false);
});
