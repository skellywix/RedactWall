'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const verifier = require('../server/policy-control-verifier');
const vendorProtocol = require('../server/vendor-policy-protocol');
const { CUSTOMER_POLICY_PACKAGE_BOUNDARY } = require('../server/connected-policy-store');

const POLICY_KEY_ID = 'rw-policy-current';
const DIGEST_A = 'a'.repeat(64);
const DIGEST_B = 'b'.repeat(64);
const DIGEST_C = 'c'.repeat(64);

function fingerprint(key) {
  return crypto.createHash('sha256')
    .update(key.export({ type: 'spki', format: 'der' }))
    .digest('hex');
}

function policyPayload() {
  return {
    schemaVersion: verifier.POLICY_CONTROL_SCHEMA_VERSION,
    kind: verifier.GLOBAL_POLICY_KIND,
    globalReleaseId: '3d594650-3436-4c5d-8f25-5acdc49cfe99',
    globalVersion: 1,
    previousGlobalVersion: 0,
    rollbackOfGlobalVersion: null,
    historyEpoch: 1,
    keyEpoch: 1,
    approvalAttestationDigest: DIGEST_A,
    bundleDigest: DIGEST_B,
    mandatoryControlsDigest: DIGEST_C,
    issuedAt: '2026-07-13T12:00:00.000Z',
  };
}

function policyTrust(publicKey, registryKey = publicKey) {
  const identity = fingerprint(registryKey);
  const registry = {
    assertPublicKey(purpose, keyId, candidateIdentity) {
      assert.equal(purpose, 'policy');
      assert.equal(keyId, POLICY_KEY_ID);
      assert.equal(candidateIdentity, identity);
    },
    assertHistoricalPublicKey(purpose, keyId, candidateIdentity) {
      this.assertPublicKey(purpose, keyId, candidateIdentity);
    },
    verificationPublicKey(purpose, keyId) {
      assert.equal(purpose, 'policy');
      assert.equal(keyId, POLICY_KEY_ID);
      return new Map([[POLICY_KEY_ID, registryKey]]);
    },
  };
  return {
    currentEpoch: 1,
    forbiddenPublicKeyFingerprints: [],
    keyEpochs: { [POLICY_KEY_ID]: { validFromEpoch: 1, retireAfterEpoch: null } },
    offlineKeyFingerprint: 'f'.repeat(64),
    publicKeys: { [POLICY_KEY_ID]: publicKey },
    authorityRegistry: registry,
  };
}

test('vendor facade retains the original policy protocol API', () => {
  assert.deepEqual(Object.keys(vendorProtocol), [
    'GLOBAL_POLICY_KIND',
    'GLOBAL_POLICY_SIGNATURE_DOMAIN',
    'OWNER_APPROVAL_KIND',
    'OWNER_APPROVAL_SIGNATURE_DOMAIN',
    'POLICY_CONTROL_SCHEMA_VERSION',
    'assertGlobalPolicyPayload',
    'assertOwnerApprovalPayload',
    'assertPolicyDeliveryBinding',
    'createPolicyControlEnvelope',
    'digestCanonical',
    'policyDeliveryDigest',
    'policyGlobalArtifactDigest',
    'policyGlobalSigningInput',
    'signGlobalPolicyRelease',
    'signOwnerApproval',
    'verifyGlobalPolicyRelease',
    'verifyPersistedGlobalPolicyRelease',
    'verifyPersistedOwnerApproval',
    'verifyOwnerApproval',
  ]);
});

test('customer verifier accepts a valid release and rejects a changed signature', () => {
  const keys = crypto.generateKeyPairSync('ed25519');
  const artifact = vendorProtocol.signGlobalPolicyRelease(policyPayload(), {
    keyEpoch: 1,
    keyId: POLICY_KEY_ID,
    privateKey: keys.privateKey,
  });
  const trust = policyTrust(keys.publicKey);
  const verified = verifier.verifyGlobalPolicyRelease(artifact, trust);
  assert.equal(verified.keyId, POLICY_KEY_ID);
  assert.equal(verified.artifactDigest, verifier.policyGlobalArtifactDigest(artifact));
  assert.equal(verifier.verifyPersistedGlobalPolicyRelease(artifact, trust).artifactDigest,
    verified.artifactDigest);

  const changed = {
    ...artifact,
    signature: `${artifact.signature[0] === 'A' ? 'B' : 'A'}${artifact.signature.slice(1)}`,
  };
  assert.throws(
    () => verifier.verifyGlobalPolicyRelease(changed, trust),
    (error) => error && error.code === 'policy_global_signature_invalid',
  );
});

test('customer verifier explicitly rejects private trust pins', () => {
  const keys = crypto.generateKeyPairSync('ed25519');
  const artifact = vendorProtocol.signGlobalPolicyRelease(policyPayload(), {
    keyEpoch: 1,
    keyId: POLICY_KEY_ID,
    privateKey: keys.privateKey,
  });
  for (const privatePin of [
    keys.privateKey,
    keys.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    { key: keys.privateKey.export({ type: 'pkcs8', format: 'der' }), format: 'der', type: 'pkcs8' },
  ]) {
    assert.throws(
      () => verifier.verifyGlobalPolicyRelease(artifact, policyTrust(privatePin, keys.publicKey)),
      (error) => error && error.code === 'policy_private_trust_pin_rejected',
    );
  }
});

test('customer verifier and package boundary contain no vendor signing capability', () => {
  const verifierSource = fs.readFileSync(
    path.join(__dirname, '..', 'server', 'policy-control-verifier.js'),
    'utf8',
  );
  const customerStateSource = fs.readFileSync(
    path.join(__dirname, '..', 'server', 'connected-policy-state.js'),
    'utf8',
  );
  assert.doesNotMatch(verifierSource, /crypto\.sign\s*\(/);
  assert.doesNotMatch(verifierSource, /createPrivateKey\s*\(/);
  assert.doesNotMatch(verifierSource, /function\s+sign(?:GlobalPolicyRelease|OwnerApproval)\b/);
  assert.doesNotMatch(verifierSource, /vendor-policy-protocol|vendor-signed-artifact/);
  assert.match(customerStateSource, /require\('\.\/policy-control-verifier'\)/);
  assert.doesNotMatch(customerStateSource, /require\('\.\/vendor-policy-protocol'\)/);
  assert.equal(CUSTOMER_POLICY_PACKAGE_BOUNDARY.includes.includes('policy-control-verifier'), true);
  assert.equal(CUSTOMER_POLICY_PACKAGE_BOUNDARY.includes.includes('vendor-policy-protocol'), false);
  assert.equal(CUSTOMER_POLICY_PACKAGE_BOUNDARY.excludes.includes('vendor-policy-protocol'), true);
});
