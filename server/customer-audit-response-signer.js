'use strict';

const crypto = require('node:crypto');
const protocol = require('./vendor-control-protocol');
const { isDeploymentId } = require('./deployment-identity');

const CUSTOMER_AUDIT_RESPONSE_SIGNATURE_DOMAIN = 'redactwall.customer-audit-response.v1';
const RESPONSE_KIND = protocol.CHANNEL_KINDS.AUDIT_RESPONSE;
const MAX_RESPONSE_BYTES = 1024 * 1024;
const KEY_ID_RE = /^rw-customer-audit-response-[a-z0-9][a-z0-9_.-]{0,55}$/;
const CUSTOMER_ID_RE = /^[a-z0-9][a-z0-9_-]{1,62}$/;
const SHA256_RE = /^[a-f0-9]{64}$/;
const LOCAL_AUDIT_REF_RE = /^local_audit_[A-Za-z0-9_-]{20,86}$/;
const RESPONSE_KEYS = Object.freeze([
  'customerId', 'decision', 'deploymentId', 'kind', 'localApprovalRef', 'messageId',
  'reasonCode', 'requestDigest', 'requestId', 'requestVersion', 'respondedAt',
  'schemaVersion', 'status', 'summaries',
]);
const SIGNER_BRAND = Symbol('customer-audit-response-signer');

function createCustomerAuditResponseSigner(options = {}) {
  assertReferenceRuntime();
  const input = exactObject(options, [
    'customerId', 'deploymentId', 'keyId', 'privateKey',
  ], 'customer_response_signer_invalid');
  checkedScope(input);
  const keyId = checkedKeyId(input.keyId);
  const privateKey = privateEd25519(input.privateKey);
  const fingerprint = keyFingerprint(crypto.createPublicKey(privateKey));
  const signer = {
    customerId: input.customerId,
    deploymentId: input.deploymentId,
    keyId,
    fingerprint,
    sign(payload) {
      const checked = assertCustomerAuditResponsePayload(payload);
      if (checked.customerId !== input.customerId
          || checked.deploymentId !== input.deploymentId) {
        throw responseError('customer_response_scope_mismatch');
      }
      return deepFreeze({
        keyId,
        payload: checked,
        signature: crypto.sign(
          null, customerAuditResponseSigningInput(checked, keyId), privateKey,
        ).toString('base64'),
      });
    },
  };
  Object.defineProperty(signer, SIGNER_BRAND, { value: true });
  return Object.freeze(signer);
}

function isCustomerAuditResponseSigner(value) {
  return Boolean(value && value[SIGNER_BRAND] === true);
}

function assertCustomerAuditResponsePayload(raw) {
  const value = boundedSnapshot(raw, 'customer_response_payload_invalid');
  if (!exactKeys(value, RESPONSE_KEYS)
      || !SHA256_RE.test(String(value.requestDigest || ''))
      || !LOCAL_AUDIT_REF_RE.test(String(value.localApprovalRef || ''))
      || !['approved', 'denied', 'expired', 'revoked'].includes(value.decision)) {
    throw responseError('customer_response_payload_invalid');
  }
  const shared = { ...value };
  delete shared.decision;
  delete shared.localApprovalRef;
  delete shared.requestDigest;
  let checked;
  try { checked = protocol.assertChannel(shared, RESPONSE_KIND); }
  catch { throw responseError('customer_response_payload_invalid'); }
  assertDecisionBinding(value);
  return deepFreeze({
    ...checked,
    requestDigest: value.requestDigest,
    decision: value.decision,
    localApprovalRef: value.localApprovalRef,
  });
}

function customerAuditResponseSigningInput(payload, keyId) {
  const checked = assertCustomerAuditResponsePayload(payload);
  const normalized = checkedKeyId(keyId);
  return Buffer.from(
    `${CUSTOMER_AUDIT_RESPONSE_SIGNATURE_DOMAIN}\0${normalized}\0${protocol.canonicalJson(checked)}`,
    'utf8',
  );
}

function assertDecisionBinding(value) {
  const bindings = {
    approved: ['completed', 'completed'],
    denied: ['denied', 'customer_denied'],
    expired: ['expired', 'request_expired'],
    revoked: ['revoked', 'customer_revoked'],
  };
  const [status, reason] = bindings[value.decision];
  if (value.status !== status || value.reasonCode !== reason) {
    throw responseError('customer_response_decision_mismatch');
  }
}

function checkedScope(value) {
  if (!CUSTOMER_ID_RE.test(String(value.customerId || ''))
      || !isDeploymentId(value.deploymentId)) {
    throw responseError('customer_response_scope_invalid');
  }
  return { customerId: value.customerId, deploymentId: value.deploymentId };
}

function checkedKeyId(value) {
  if (!KEY_ID_RE.test(String(value || ''))) throw responseError('customer_response_key_id_invalid');
  return value;
}

function privateEd25519(value) {
  let key;
  try { key = value instanceof crypto.KeyObject ? value : crypto.createPrivateKey(value); }
  catch { throw responseError('customer_response_private_key_invalid'); }
  if (key.type !== 'private' || key.asymmetricKeyType !== 'ed25519') {
    throw responseError('customer_response_private_key_invalid');
  }
  return key;
}

function keyFingerprint(key) {
  return crypto.createHash('sha256')
    .update(key.export({ format: 'der', type: 'spki' })).digest('hex');
}

function boundedSnapshot(value, code) {
  let serialized;
  try { serialized = JSON.stringify(value); }
  catch { throw responseError(code); }
  if (typeof serialized !== 'string' || Buffer.byteLength(serialized, 'utf8') > MAX_RESPONSE_BYTES) {
    throw responseError(code);
  }
  return JSON.parse(serialized);
}

function exactObject(value, keys, code) {
  if (!plainObject(value) || !exactKeys(value, keys)) throw responseError(code);
  return descriptorValues(value, code);
}

function descriptorValues(value, code) {
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Object.values(descriptors).some((descriptor) => descriptor.get || descriptor.set
      || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true)) {
    throw responseError(code);
  }
  return Object.fromEntries(Object.entries(descriptors).map(([key, descriptor]) => [
    key, descriptor.value,
  ]));
}

function exactKeys(value, keys) {
  return plainObject(value)
    && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
}

function plainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.values(value).forEach(deepFreeze);
    Object.freeze(value);
  }
  return value;
}

function responseError(code) {
  const error = new Error('customer audit response rejected');
  error.code = code;
  return error;
}

function assertReferenceRuntime() {
  if (process.env.NODE_ENV === 'production') {
    throw responseError('customer_response_reference_runtime_forbidden');
  }
}

module.exports = Object.freeze({
  CUSTOMER_AUDIT_RESPONSE_SIGNATURE_DOMAIN,
  assertCustomerAuditResponsePayload,
  createCustomerAuditResponseSigner,
  customerAuditResponseSigningInput,
  isCustomerAuditResponseSigner,
});
