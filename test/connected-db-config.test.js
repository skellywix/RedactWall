'use strict';

const crypto = require('node:crypto');
const test = require('node:test');
const assert = require('node:assert/strict');
const config = require('../server/connected-license-config');
const entitlementState = require('../server/connected-entitlement-state');

const entitlement = crypto.generateKeyPairSync('ed25519');
const entitlementNext = crypto.generateKeyPairSync('ed25519');
const verdict = crypto.generateKeyPairSync('ed25519');
const offline = crypto.generateKeyPairSync('ed25519');
const pem = (value, type = 'spki') => value.export({ type, format: 'pem' }).toString();
const b64 = (value) => value.export({ type: 'spki', format: 'der' }).toString('base64');
const keyId = (value) => `rw-entitlement-${config.publicKeyFingerprint(value)}`;
const CURRENT_KEY_ID = keyId(entitlement.publicKey);
const NEXT_KEY_ID = keyId(entitlementNext.publicKey);
const env = {
  REDACTWALL_TENANT_ID: 'customer_config',
  REDACTWALL_CONNECTED_DEPLOYMENT_ID: 'dep_0123456789abcdef0123456789abcdef',
  REDACTWALL_LICENSE_VERDICT_PUBLIC_KEY: pem(verdict.publicKey),
  REDACTWALL_LICENSE_PUBLIC_KEY: pem(offline.publicKey),
};

function clearEntitlementConfig() {
  for (const name of [
    'REDACTWALL_ENTITLEMENT_PUBLIC_KEY', 'REDACTWALL_ENTITLEMENT_PUBLIC_KEY_B64',
    'REDACTWALL_ENTITLEMENT_KEY_ID', 'REDACTWALL_ENTITLEMENT_NEXT_PUBLIC_KEY',
    'REDACTWALL_ENTITLEMENT_NEXT_PUBLIC_KEY_B64', 'REDACTWALL_ENTITLEMENT_NEXT_KEY_ID',
  ]) delete env[name];
}

function setCurrent() {
  env.REDACTWALL_ENTITLEMENT_PUBLIC_KEY = pem(entitlement.publicKey);
  env.REDACTWALL_ENTITLEMENT_KEY_ID = CURRENT_KEY_ID;
}

test('connected entitlement current key and explicit key ID are an inseparable pair', () => {
  clearEntitlementConfig();
  env.REDACTWALL_ENTITLEMENT_PUBLIC_KEY = pem(entitlement.publicKey);
  assert.throws(
    () => config.connectedVerificationKeys(env),
    (error) => error && error.code === 'CONNECTED_ENTITLEMENT_CURRENT_KEY_PAIR_REQUIRED',
  );
  clearEntitlementConfig();
  env.REDACTWALL_ENTITLEMENT_KEY_ID = CURRENT_KEY_ID;
  assert.throws(
    () => config.connectedVerificationKeys(env),
    (error) => error && error.code === 'CONNECTED_ENTITLEMENT_CURRENT_KEY_PAIR_REQUIRED',
  );
  setCurrent();
  assert.deepEqual(
    Object.keys(config.connectedVerificationKeys(env).publicKeys),
    [CURRENT_KEY_ID],
  );
});

test('next entitlement key is optional only as a complete explicit key-ID pair', () => {
  clearEntitlementConfig();
  setCurrent();
  env.REDACTWALL_ENTITLEMENT_NEXT_PUBLIC_KEY = pem(entitlementNext.publicKey);
  assert.throws(
    () => config.connectedVerificationKeys(env),
    (error) => error && error.code === 'CONNECTED_ENTITLEMENT_NEXT_KEY_PAIR_REQUIRED',
  );
  delete env.REDACTWALL_ENTITLEMENT_NEXT_PUBLIC_KEY;
  env.REDACTWALL_ENTITLEMENT_NEXT_KEY_ID = NEXT_KEY_ID;
  assert.throws(
    () => config.connectedVerificationKeys(env),
    (error) => error && error.code === 'CONNECTED_ENTITLEMENT_NEXT_KEY_PAIR_REQUIRED',
  );
  env.REDACTWALL_ENTITLEMENT_NEXT_PUBLIC_KEY = pem(entitlementNext.publicKey);
  const keys = config.connectedVerificationKeys(env).publicKeys;
  assert.deepEqual(Object.keys(keys), [CURRENT_KEY_ID, NEXT_KEY_ID]);
});

test('private key material is never accepted or fingerprinted as a customer trust pin', () => {
  clearEntitlementConfig();
  env.REDACTWALL_ENTITLEMENT_PUBLIC_KEY = pem(entitlement.privateKey, 'pkcs8');
  env.REDACTWALL_ENTITLEMENT_KEY_ID = CURRENT_KEY_ID;
  assert.throws(
    () => config.connectedVerificationKeys(env),
    (error) => error && error.code === 'CONNECTED_PUBLIC_KEY_INVALID',
  );
  assert.equal(config.publicKeyFingerprint(entitlement.privateKey), '');
  assert.equal(config.publicKeyFingerprint(pem(entitlement.privateKey, 'pkcs8')), '');
});

test('entitlement key IDs are explicit SPKI-bound entropy identifiers', () => {
  clearEntitlementConfig();
  env.REDACTWALL_ENTITLEMENT_PUBLIC_KEY = pem(entitlement.publicKey);
  env.REDACTWALL_ENTITLEMENT_KEY_ID = 'unscoped-current-key';
  assert.throws(
    () => config.connectedVerificationKeys(env),
    (error) => error && error.code === 'CONNECTED_ENTITLEMENT_KEY_ID_INVALID',
  );
  env.REDACTWALL_ENTITLEMENT_KEY_ID = `rw-entitlement-${'a'.repeat(65)}`;
  assert.throws(
    () => config.connectedVerificationKeys(env),
    (error) => error && error.code === 'CONNECTED_ENTITLEMENT_KEY_ID_INVALID',
  );
});

test('current, next, offline, and verdict trust pins are pairwise separated', () => {
  clearEntitlementConfig();
  setCurrent();
  env.REDACTWALL_ENTITLEMENT_NEXT_PUBLIC_KEY = pem(entitlement.publicKey);
  env.REDACTWALL_ENTITLEMENT_NEXT_KEY_ID = CURRENT_KEY_ID;
  assert.throws(
    () => config.connectedVerificationKeys(env),
    (error) => error && error.code === 'CONNECTED_ENTITLEMENT_KEY_ID_DUPLICATE',
  );
  clearEntitlementConfig();
  env.REDACTWALL_ENTITLEMENT_PUBLIC_KEY = pem(offline.publicKey);
  env.REDACTWALL_ENTITLEMENT_KEY_ID = keyId(offline.publicKey);
  assert.throws(
    () => config.connectedVerificationKeys(env),
    (error) => error && error.code === 'CONNECTED_ENTITLEMENT_KEY_IDENTITY_REUSED',
  );
  const previousNextVerdict = env.REDACTWALL_LICENSE_VERDICT_NEXT_PUBLIC_KEY;
  clearEntitlementConfig();
  env.REDACTWALL_LICENSE_VERDICT_NEXT_PUBLIC_KEY = pem(entitlement.publicKey);
  setCurrent();
  try {
    assert.throws(
      () => config.connectedVerificationKeys(env),
      (error) => error && error.code === 'CONNECTED_ENTITLEMENT_KEY_IDENTITY_REUSED',
    );
  } finally {
    if (previousNextVerdict === undefined) delete env.REDACTWALL_LICENSE_VERDICT_NEXT_PUBLIC_KEY;
    else env.REDACTWALL_LICENSE_VERDICT_NEXT_PUBLIC_KEY = previousNextVerdict;
  }
});

test('optional and dual-source key configuration fails closed', () => {
  clearEntitlementConfig();
  setCurrent();
  env.REDACTWALL_ENTITLEMENT_NEXT_PUBLIC_KEY = 'not a public key';
  assert.throws(
    () => config.connectedVerificationKeys(env),
    (error) => error && error.code === 'CONNECTED_PUBLIC_KEY_INVALID',
  );
  delete env.REDACTWALL_ENTITLEMENT_NEXT_PUBLIC_KEY;
  env.REDACTWALL_ENTITLEMENT_PUBLIC_KEY_B64 = b64(entitlementNext.publicKey);
  assert.throws(
    () => config.connectedVerificationKeys(env),
    (error) => error && error.code === 'CONNECTED_PUBLIC_KEY_SOURCE_CONFLICT',
  );
  env.REDACTWALL_ENTITLEMENT_PUBLIC_KEY_B64 = b64(entitlement.publicKey);
  assert.deepEqual(Object.keys(config.connectedVerificationKeys(env).publicKeys), [CURRENT_KEY_ID]);
});

test('legacy license customer ID cannot supply the connected deployment scope', () => {
  const tenantId = env.REDACTWALL_TENANT_ID;
  delete env.REDACTWALL_TENANT_ID;
  env.REDACTWALL_LICENSE_CUSTOMER_ID = 'legacy_customer';
  try {
    assert.throws(
      () => config.connectedScopeFromEnv(env, entitlementState.initialState),
      (error) => error && error.code === 'CONNECTED_ENTITLEMENT_SCOPE_REQUIRED',
    );
  } finally {
    env.REDACTWALL_TENANT_ID = tenantId;
    delete env.REDACTWALL_LICENSE_CUSTOMER_ID;
  }
});

test('connected deployment scope requires the frozen dep plus 32-hex form', () => {
  const deploymentId = env.REDACTWALL_CONNECTED_DEPLOYMENT_ID;
  env.REDACTWALL_CONNECTED_DEPLOYMENT_ID = 'deployment_config_001';
  try {
    assert.throws(
      () => config.connectedScopeFromEnv(env, entitlementState.initialState),
      (error) => error && error.code === 'CONNECTED_ENTITLEMENT_SCOPE_REQUIRED',
    );
  } finally {
    env.REDACTWALL_CONNECTED_DEPLOYMENT_ID = deploymentId;
  }
});
