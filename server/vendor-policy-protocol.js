'use strict';

const crypto = require('node:crypto');
const protocol = require('./vendor-control-protocol');
const verifier = require('./policy-control-verifier');

function signGlobalPolicyRelease(payload, signingSlot) {
  const checked = verifier.assertGlobalPolicyPayload(payload);
  assertSigningSlot(signingSlot, checked.keyEpoch, 'policy_signing_slot_invalid');
  const signingInput = verifier.policyGlobalSigningInput(checked, signingSlot.keyId);
  const privateKey = privateEd25519(signingSlot.privateKey, 'policy_signing_slot_invalid');
  const artifact = {
    keyId: signingSlot.keyId,
    payload: checked,
    signature: crypto.sign(
      null,
      signingInput,
      privateKey,
    ).toString('base64'),
  };
  verifier.policyGlobalArtifactDigest(artifact);
  return deepFreeze(clone(artifact));
}

function signOwnerApproval(payload, signingSlot) {
  const checked = verifier.assertOwnerApprovalPayload(payload);
  assertSigningSlot(signingSlot, checked.keyEpoch, 'owner_approval_signing_slot_invalid');
  const signingInput = verifier.ownerApprovalSigningInput(checked, signingSlot.keyId);
  const privateKey = privateEd25519(signingSlot.privateKey, 'owner_approval_signing_slot_invalid');
  const artifact = {
    keyId: signingSlot.keyId,
    payload: checked,
    signature: crypto.sign(
      null,
      signingInput,
      privateKey,
    ).toString('base64'),
  };
  return deepFreeze(clone(artifact));
}

function assertSigningSlot(value, keyEpoch, code) {
  if (!plainRecord(value)
      || Object.keys(value).sort().join(',') !== 'keyEpoch,keyId,privateKey'
      || value.keyEpoch !== keyEpoch) throw fault(code);
}

function privateEd25519(value, code) {
  let key;
  try { key = value instanceof crypto.KeyObject ? value : crypto.createPrivateKey(value); }
  catch { throw fault(code); }
  if (key.type !== 'private' || key.asymmetricKeyType !== 'ed25519') throw fault(code);
  return key;
}

function plainRecord(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function clone(value) {
  return JSON.parse(protocol.canonicalJson(value));
}

function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const item of Object.values(value)) deepFreeze(item);
  return value;
}

function fault(code) {
  const error = new Error('vendor policy protocol rejected');
  error.code = code;
  return error;
}

module.exports = {
  GLOBAL_POLICY_KIND: verifier.GLOBAL_POLICY_KIND,
  GLOBAL_POLICY_SIGNATURE_DOMAIN: verifier.GLOBAL_POLICY_SIGNATURE_DOMAIN,
  OWNER_APPROVAL_KIND: verifier.OWNER_APPROVAL_KIND,
  OWNER_APPROVAL_SIGNATURE_DOMAIN: verifier.OWNER_APPROVAL_SIGNATURE_DOMAIN,
  POLICY_CONTROL_SCHEMA_VERSION: verifier.POLICY_CONTROL_SCHEMA_VERSION,
  assertGlobalPolicyPayload: verifier.assertGlobalPolicyPayload,
  assertOwnerApprovalPayload: verifier.assertOwnerApprovalPayload,
  assertPolicyDeliveryBinding: verifier.assertPolicyDeliveryBinding,
  createPolicyControlEnvelope: verifier.createPolicyControlEnvelope,
  digestCanonical: verifier.digestCanonical,
  policyDeliveryDigest: verifier.policyDeliveryDigest,
  policyGlobalArtifactDigest: verifier.policyGlobalArtifactDigest,
  policyGlobalSigningInput: verifier.policyGlobalSigningInput,
  signGlobalPolicyRelease,
  signOwnerApproval,
  verifyGlobalPolicyRelease: verifier.verifyGlobalPolicyRelease,
  verifyPersistedGlobalPolicyRelease: verifier.verifyPersistedGlobalPolicyRelease,
  verifyPersistedOwnerApproval: verifier.verifyPersistedOwnerApproval,
  verifyOwnerApproval: verifier.verifyOwnerApproval,
};
