'use strict';

const crypto = require('node:crypto');
const verifier = require('./audit-support-control-verifier');

const KEY_ID_RE = /^rw-audit-request-[a-z0-9][a-z0-9_.-]{0,77}$/;

function signAuditSupportRequest(rawPayload, signingSlot) {
  return signArtifact(
    verifier.assertAuditSupportRequest(rawPayload),
    signingSlot,
    verifier.REQUEST_SIGNATURE_DOMAIN,
  );
}

function signAuditSupportCancellation(rawPayload, signingSlot) {
  return signArtifact(
    verifier.assertAuditSupportCancellation(rawPayload),
    signingSlot,
    verifier.CANCELLATION_SIGNATURE_DOMAIN,
  );
}

function signArtifact(payload, signingSlot, domain) {
  const slot = checkedSigningSlot(signingSlot);
  return deepFreeze({
    keyId: slot.keyId,
    payload,
    signature: crypto.sign(
      null,
      verifier.signingInput(payload, slot.keyId, domain),
      slot.privateKey,
    ).toString('base64'),
  });
}

function checkedSigningSlot(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).sort().join(',') !== 'keyId,privateKey'
      || !KEY_ID_RE.test(String(value.keyId || ''))) {
    throw artifactError('audit_support_signing_slot_invalid');
  }
  let privateKey;
  try {
    privateKey = value.privateKey instanceof crypto.KeyObject
      ? value.privateKey : crypto.createPrivateKey(value.privateKey);
  } catch { throw artifactError('audit_support_signing_slot_invalid'); }
  if (privateKey.type !== 'private' || privateKey.asymmetricKeyType !== 'ed25519') {
    throw artifactError('audit_support_signing_slot_invalid');
  }
  return { keyId: value.keyId, privateKey };
}

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.values(value).forEach(deepFreeze);
    Object.freeze(value);
  }
  return value;
}

function artifactError(code) {
  const error = new Error('audit support control artifact rejected');
  error.code = code;
  return error;
}

module.exports = {
  CANCELLATION_KIND: verifier.CANCELLATION_KIND,
  CANCELLATION_SIGNATURE_DOMAIN: verifier.CANCELLATION_SIGNATURE_DOMAIN,
  REQUEST_SIGNATURE_DOMAIN: verifier.REQUEST_SIGNATURE_DOMAIN,
  assertAuditSupportCancellation: verifier.assertAuditSupportCancellation,
  assertAuditSupportRequest: verifier.assertAuditSupportRequest,
  payloadDigest: verifier.payloadDigest,
  signAuditSupportCancellation,
  signAuditSupportRequest,
  signingInput: verifier.signingInput,
  verifyAuditSupportCancellation: verifier.verifyAuditSupportCancellation,
  verifyAuditSupportRequest: verifier.verifyAuditSupportRequest,
};
