'use strict';

const crypto = require('node:crypto');
const protocol = require('./vendor-control-protocol');
const { isDeploymentId } = require('./deployment-identity');
const {
  KEY_PURPOSES,
  normalizePublicKeys,
} = require('./vendor-signed-artifact');

const REQUEST_KIND = protocol.CHANNEL_KINDS.AUDIT_REQUEST;
const CANCELLATION_KIND = 'audit-support.cancellation.v1';
const REQUEST_SIGNATURE_DOMAIN = 'redactwall.vendor-audit-request.v2';
const CANCELLATION_SIGNATURE_DOMAIN = 'redactwall.vendor-audit-cancellation.v1';
const SHA256_RE = /^[a-f0-9]{64}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CUSTOMER_ID_RE = /^[a-z0-9][a-z0-9_-]{1,62}$/;
const KEY_ID_RE = /^rw-audit-request-[a-z0-9][a-z0-9_.-]{0,77}$/;
const MAX_ARTIFACT_BYTES = 1024 * 1024;
const MAX_REQUEST_ISSUANCE_SKEW_MS = 60 * 1000;
const MAX_REQUEST_WINDOW_MS = 24 * 60 * 60 * 1000;
const REQUEST_KEYS = Object.freeze([
  'customerId', 'deploymentId', 'expiresAt', 'fields', 'issuedAt', 'kind',
  'maxRecords', 'messageId', 'notBefore', 'purposeCode', 'requestId',
  'requestType', 'requestVersion', 'schemaVersion',
]);
const CANCELLATION_KEYS = Object.freeze([
  'customerId', 'deploymentId', 'issuedAt', 'kind', 'messageId', 'reasonCode',
  'requestDigest', 'requestId', 'requestVersion', 'schemaVersion',
]);

function verifyAuditSupportRequest(rawEnvelope, publicKeys, authorityRegistry) {
  return verifyArtifact(rawEnvelope, publicKeys, authorityRegistry,
    assertAuditSupportRequest, REQUEST_SIGNATURE_DOMAIN);
}

function verifyAuditSupportCancellation(rawEnvelope, publicKeys, authorityRegistry) {
  return verifyArtifact(rawEnvelope, publicKeys, authorityRegistry,
    assertAuditSupportCancellation, CANCELLATION_SIGNATURE_DOMAIN);
}

function assertAuditSupportRequest(rawPayload) {
  const value = boundedSnapshot(rawPayload, 'audit_support_request_invalid');
  if (!exactKeys(value, REQUEST_KEYS)) throw artifactError('audit_support_request_invalid');
  canonicalIso(value.issuedAt, 'audit_support_request_invalid');
  const shared = { ...value };
  delete shared.issuedAt;
  let checked;
  try { checked = protocol.assertChannel(shared, REQUEST_KIND); }
  catch { throw artifactError('audit_support_request_invalid'); }
  const issuedMs = Date.parse(value.issuedAt);
  const notBeforeMs = Date.parse(checked.notBefore);
  const expiresMs = Date.parse(checked.expiresAt);
  if (Math.abs(notBeforeMs - issuedMs) > MAX_REQUEST_ISSUANCE_SKEW_MS
      || expiresMs <= notBeforeMs
      || expiresMs - notBeforeMs > MAX_REQUEST_WINDOW_MS) {
    throw artifactError('audit_support_request_window_invalid');
  }
  return deepFreeze({ ...checked, issuedAt: value.issuedAt });
}

function assertAuditSupportCancellation(rawPayload) {
  const value = boundedSnapshot(rawPayload, 'audit_support_cancellation_invalid');
  if (!exactKeys(value, CANCELLATION_KEYS)
      || value.schemaVersion !== protocol.PROTOCOL_VERSION
      || value.kind !== CANCELLATION_KIND
      || value.reasonCode !== 'vendor_revoked'
      || !UUID_RE.test(String(value.messageId || ''))
      || !UUID_RE.test(String(value.requestId || ''))
      || !CUSTOMER_ID_RE.test(String(value.customerId || ''))
      || !isDeploymentId(value.deploymentId)
      || !Number.isSafeInteger(value.requestVersion) || value.requestVersion < 1
      || !SHA256_RE.test(String(value.requestDigest || ''))) {
    throw artifactError('audit_support_cancellation_invalid');
  }
  canonicalIso(value.issuedAt, 'audit_support_cancellation_invalid');
  return deepFreeze(value);
}

function verifyArtifact(rawEnvelope, publicKeys, authorityRegistry, validator, domain) {
  const envelope = boundedSnapshot(rawEnvelope, 'audit_support_artifact_invalid');
  if (!exactKeys(envelope, ['keyId', 'payload', 'signature'])
      || !KEY_ID_RE.test(String(envelope.keyId || ''))) {
    throw artifactError('audit_support_artifact_invalid');
  }
  let keys;
  try {
    keys = normalizePublicKeys(publicKeys, {
      authorityRegistry,
      purpose: KEY_PURPOSES.AUDIT_REQUEST,
      strictPurpose: true,
    });
  } catch { throw artifactError('audit_support_authority_invalid'); }
  const key = keys.get(envelope.keyId);
  if (!key) throw artifactError('unknown_signing_key');
  const payload = validator(envelope.payload);
  const signature = canonicalSignature(envelope.signature);
  if (!crypto.verify(null, signingInput(payload, envelope.keyId, domain), key, signature)) {
    throw artifactError('invalid_signature');
  }
  return deepFreeze({
    keyId: envelope.keyId,
    payload,
    payloadDigest: payloadDigest(payload, domain),
    signatureDomain: domain,
  });
}

function signingInput(payload, keyId, domain) {
  if (!KEY_ID_RE.test(String(keyId || ''))) throw artifactError('audit_support_key_id_invalid');
  return Buffer.from(`${domain}\0${keyId}\0${protocol.canonicalJson(payload)}`, 'utf8');
}

function payloadDigest(payload, domain) {
  return sha256(`${domain}\0${protocol.canonicalJson(payload)}`);
}

function canonicalSignature(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    throw artifactError('audit_support_signature_invalid');
  }
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length !== 64 || bytes.toString('base64') !== value) {
    throw artifactError('audit_support_signature_invalid');
  }
  return bytes;
}

function boundedSnapshot(value, code) {
  let serialized;
  try { serialized = JSON.stringify(value); }
  catch { throw artifactError(code); }
  if (typeof serialized !== 'string'
      || Buffer.byteLength(serialized, 'utf8') > MAX_ARTIFACT_BYTES) {
    throw artifactError(code);
  }
  return JSON.parse(serialized);
}

function exactKeys(value, keys) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
}

function canonicalIso(value, code) {
  const parsed = typeof value === 'string' ? Date.parse(value) : NaN;
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    throw artifactError(code);
  }
  return value;
}

function sha256(value) { return crypto.createHash('sha256').update(value).digest('hex'); }

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
  CANCELLATION_KIND,
  CANCELLATION_SIGNATURE_DOMAIN,
  REQUEST_SIGNATURE_DOMAIN,
  assertAuditSupportCancellation,
  assertAuditSupportRequest,
  payloadDigest,
  signingInput,
  verifyAuditSupportCancellation,
  verifyAuditSupportRequest,
};
