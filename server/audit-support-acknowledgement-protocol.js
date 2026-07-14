'use strict';

const crypto = require('node:crypto');
const protocol = require('./vendor-control-protocol');
const { isDeploymentId } = require('./deployment-identity');

const ACKNOWLEDGEMENT_DOMAIN = 'redactwall.audit-support-acknowledgement.v1';
const KEY_ID_RE = /^rw-audit-ack-[a-z0-9][a-z0-9_.-]{0,70}$/;
const CUSTOMER_ID_RE = /^[a-z0-9][a-z0-9_-]{1,62}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA256_RE = /^[a-f0-9]{64}$/;
const MAC_RE = /^[A-Za-z0-9_-]{43}$/;

function checkedRecord(raw) {
  if (!plainObject(raw) || !exactKeys(raw, [
    'customerId', 'deploymentId', 'keyId', 'secret',
  ]) || !CUSTOMER_ID_RE.test(String(raw.customerId || ''))
      || !isDeploymentId(raw.deploymentId)
      || !KEY_ID_RE.test(String(raw.keyId || ''))
      || !Buffer.isBuffer(raw.secret) || raw.secret.length !== 32) {
    throw acknowledgementError('audit_acknowledgement_configuration_invalid');
  }
  return Object.freeze({
    customerId: raw.customerId,
    deploymentId: raw.deploymentId,
    keyId: raw.keyId,
    secret: Buffer.from(raw.secret),
  });
}

function checkedReceipt(raw) {
  const value = snapshot(raw, 'audit_acknowledgement_invalid');
  const cancellation = Object.hasOwn(value, 'cancellationDigest');
  const keys = receiptCoreKeys(cancellation).concat([
    'acknowledgementKeyId', 'acknowledgementMac',
  ]);
  if (!exactKeys(value, keys) || !KEY_ID_RE.test(String(value.acknowledgementKeyId || ''))
      || !MAC_RE.test(String(value.acknowledgementMac || ''))) {
    throw acknowledgementError('audit_acknowledgement_invalid');
  }
  checkedReceiptCore(receiptCore(value));
  return value;
}

function checkedReceiptCore(raw) {
  const value = snapshot(raw, 'audit_acknowledgement_invalid');
  const cancellation = Object.hasOwn(value, 'cancellationDigest');
  if (!exactKeys(value, receiptCoreKeys(cancellation)) || value.accepted !== true
      || !SHA256_RE.test(String(value.artifactDigest || ''))
      || !CUSTOMER_ID_RE.test(String(value.customerId || ''))
      || !isDeploymentId(value.deploymentId)
      || !UUID_RE.test(String(value.messageId || ''))
      || !SHA256_RE.test(String(value.requestDigest || ''))
      || !UUID_RE.test(String(value.requestId || ''))
      || !Number.isSafeInteger(value.requestVersion) || value.requestVersion < 1
      || (cancellation && !SHA256_RE.test(String(value.cancellationDigest || '')))) {
    throw acknowledgementError('audit_acknowledgement_invalid');
  }
  canonicalIso(value.receivedAt);
  return deepFreeze(value);
}

function receiptCore(value) {
  const output = { ...value };
  delete output.acknowledgementKeyId;
  delete output.acknowledgementMac;
  return output;
}

function receiptCoreKeys(cancellation) {
  const keys = [
    'accepted', 'artifactDigest', 'customerId', 'deploymentId', 'messageId', 'receivedAt',
    'requestDigest', 'requestId', 'requestVersion',
  ];
  if (cancellation) keys.push('cancellationDigest');
  return keys;
}

function acknowledgementMac(secret, keyId, receipt) {
  return crypto.createHmac('sha256', secret)
    .update(`${ACKNOWLEDGEMENT_DOMAIN}\0${keyId}\0${protocol.canonicalJson(receipt)}`, 'utf8')
    .digest('base64url');
}

function verifyAcknowledgementMac(secret, keyId, receipt, suppliedMac) {
  const supplied = Buffer.from(suppliedMac, 'utf8');
  const trusted = Buffer.from(acknowledgementMac(secret, keyId, receipt), 'utf8');
  return supplied.length === trusted.length && crypto.timingSafeEqual(supplied, trusted);
}

function secretFingerprint(secret) {
  return crypto.createHash('sha256').update(secret).digest('hex');
}

function snapshot(value, code) {
  let serialized;
  try { serialized = JSON.stringify(value); }
  catch { throw acknowledgementError(code); }
  if (typeof serialized !== 'string' || Buffer.byteLength(serialized, 'utf8') > 16 * 1024) {
    throw acknowledgementError(code);
  }
  return JSON.parse(serialized);
}

function canonicalIso(value) {
  const parsed = typeof value === 'string' ? Date.parse(value) : NaN;
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    throw acknowledgementError('audit_acknowledgement_invalid');
  }
}

function scopeKey(customerId, deploymentId, keyId) {
  return `${customerId}\0${deploymentId}\0${keyId}`;
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

function acknowledgementError(code) {
  const error = new Error('audit support acknowledgement rejected');
  error.code = code;
  return error;
}

module.exports = Object.freeze({
  ACKNOWLEDGEMENT_DOMAIN,
  acknowledgementError,
  acknowledgementMac,
  checkedReceipt,
  checkedReceiptCore,
  checkedRecord,
  deepFreeze,
  exactKeys,
  plainObject,
  receiptCore,
  scopeKey,
  secretFingerprint,
  verifyAcknowledgementMac,
});
