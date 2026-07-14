'use strict';

const crypto = require('node:crypto');

const CUSTOMER_DIAGNOSTIC_INTEGRITY_KEY_ID = 'rw-customer-diagnostic-integrity-v1';
const ENV_NAME = 'REDACTWALL_CUSTOMER_DIAGNOSTIC_INTEGRITY_KEY';
const KEY_BYTES = 32;
const MAX_MESSAGE_BYTES = 32 * 1024;
const CHANNEL_TOKEN_NAMES = Object.freeze([
  'REDACTWALL_VENDOR_CONTROL_HEARTBEAT_TOKEN',
  'REDACTWALL_VENDOR_CONTROL_ACKNOWLEDGEMENT_TOKEN',
  'REDACTWALL_VENDOR_CONTROL_DIAGNOSTIC_TOKEN',
  'REDACTWALL_VENDOR_CONTROL_SHADOW_CANDIDATE_TOKEN',
]);
const CUSTOMER_SECRET_NAMES = Object.freeze([
  'REDACTWALL_AUDIT_KEY',
  'REDACTWALL_SECRET',
  'REDACTWALL_DATA_KEY',
  'REDACTWALL_DATA_KEY_PREVIOUS',
  'REDACTWALL_ENDPOINT_AGENT_HANDOFF_SECRET',
]);

function createCustomerDiagnosticIntegrityAuthority(options = {}) {
  const record = exactOptions(options);
  const env = plainEnvironment(record.env);
  const secretText = record.secret;
  const secret = canonicalSecret(secretText);
  rejectPrivateLike(secretText, secret);
  rejectAuthorityReuse(secretText, secret, env);
  return Object.freeze({
    sign(message) {
      const checked = checkedMessage(message);
      return Object.freeze({
        keyId: CUSTOMER_DIAGNOSTIC_INTEGRITY_KEY_ID,
        mac: crypto.createHmac('sha256', secret).update(checked, 'utf8').digest('hex'),
      });
    },
    verify(message, proof) {
      try {
        const checked = checkedMessage(message);
        const normalized = exactProof(proof);
        if (normalized.keyId !== CUSTOMER_DIAGNOSTIC_INTEGRITY_KEY_ID) return false;
        const expected = crypto.createHmac('sha256', secret)
          .update(checked, 'utf8').digest();
        const actual = Buffer.from(normalized.mac, 'hex');
        return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
      } catch { return false; }
    },
  });
}

function createCustomerDiagnosticIntegrityAuthorityFromEnvironment(env = process.env) {
  const source = plainEnvironment(env);
  return createCustomerDiagnosticIntegrityAuthority({
    secret: source[ENV_NAME],
    env: source,
  });
}

function customerDiagnosticIntegrityStatus(env = process.env) {
  const source = plainEnvironment(env);
  const consent = source.REDACTWALL_VENDOR_CONTROL_DIAGNOSTICS_ENABLED;
  const enabled = consent === true || consent === 'true';
  if (!enabled) return Object.freeze({ enabled: false, ok: true, reason: null });
  try {
    createCustomerDiagnosticIntegrityAuthorityFromEnvironment(source);
    return Object.freeze({ enabled: true, ok: true, reason: null });
  } catch (error) {
    return Object.freeze({
      enabled: true,
      ok: false,
      reason: error && error.code === 'CUSTOMER_DIAGNOSTIC_INTEGRITY_KEY_REUSED'
        ? 'authority_reused' : 'key_invalid',
    });
  }
}

function exactOptions(value) {
  const record = exactRecord(value, ['secret', 'env'], 'CUSTOMER_DIAGNOSTIC_INTEGRITY_KEY_INVALID');
  if (!Object.hasOwn(record, 'secret')) throw integrityError('CUSTOMER_DIAGNOSTIC_INTEGRITY_KEY_INVALID');
  return record;
}

function exactProof(value) {
  const record = exactRecord(value, ['keyId', 'mac'], 'CUSTOMER_DIAGNOSTIC_INTEGRITY_PROOF_INVALID');
  if (Object.keys(record).length !== 2
      || typeof record.keyId !== 'string'
      || typeof record.mac !== 'string'
      || !/^[a-f0-9]{64}$/.test(record.mac)) {
    throw integrityError('CUSTOMER_DIAGNOSTIC_INTEGRITY_PROOF_INVALID');
  }
  return record;
}

function exactRecord(value, allowedKeys, code) {
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error();
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) throw new Error();
    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => typeof key !== 'string' || !allowedKeys.includes(key))) throw new Error();
    const record = {};
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !descriptor.enumerable || descriptor.get || descriptor.set) throw new Error();
      record[key] = descriptor.value;
    }
    return record;
  } catch { throw integrityError(code); }
}

function plainEnvironment(value) {
  if (!value || typeof value !== 'object') return {};
  return value;
}

function canonicalSecret(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]{43}=$/.test(value)) {
    throw integrityError('CUSTOMER_DIAGNOSTIC_INTEGRITY_KEY_INVALID');
  }
  let bytes;
  try { bytes = Buffer.from(value, 'base64'); }
  catch { throw integrityError('CUSTOMER_DIAGNOSTIC_INTEGRITY_KEY_INVALID'); }
  if (bytes.length !== KEY_BYTES || bytes.toString('base64') !== value) {
    throw integrityError('CUSTOMER_DIAGNOSTIC_INTEGRITY_KEY_INVALID');
  }
  return bytes;
}

function rejectPrivateLike(text, secret) {
  const decoded = secret.toString('utf8');
  if (/PRIVATE KEY|OPENSSH|BEGIN [A-Z ]+KEY/i.test(text)
      || /PRIVATE KEY|OPENSSH|BEGIN [A-Z ]+KEY/i.test(decoded)) {
    throw integrityError('CUSTOMER_DIAGNOSTIC_INTEGRITY_KEY_INVALID');
  }
}

function rejectAuthorityReuse(secretText, secret, env) {
  const names = new Set([...CHANNEL_TOKEN_NAMES, ...CUSTOMER_SECRET_NAMES]);
  for (const name of Object.keys(env)) {
    if (name === ENV_NAME || /_PUBLIC_KEY(?:_B64|_PATH)?$/.test(name)) continue;
    if (/^REDACTWALL_.*(?:INTEGRITY|SIGNING|AUDIT|WITNESS|RECOVERY).*KEY/.test(name)) {
      names.add(name);
    }
  }
  for (const name of names) {
    const value = env[name];
    if (value === undefined || value === null || value === '') continue;
    if (typeof value === 'string' && value === secretText) {
      throw integrityError('CUSTOMER_DIAGNOSTIC_INTEGRITY_KEY_REUSED');
    }
    const other = comparableSecret(value);
    if (other && other.length === secret.length && crypto.timingSafeEqual(other, secret)) {
      throw integrityError('CUSTOMER_DIAGNOSTIC_INTEGRITY_KEY_REUSED');
    }
  }
}

function comparableSecret(value) {
  if (typeof value !== 'string') return null;
  if (/^[A-Za-z0-9+/]{43}=$/.test(value)) {
    const bytes = Buffer.from(value, 'base64');
    if (bytes.length === KEY_BYTES && bytes.toString('base64') === value) return bytes;
  }
  if (/^[a-fA-F0-9]{64}$/.test(value)) return Buffer.from(value, 'hex');
  const raw = Buffer.from(value, 'utf8');
  return raw.length === KEY_BYTES ? raw : null;
}

function checkedMessage(value) {
  if (typeof value !== 'string' || value.length < 1
      || Buffer.byteLength(value, 'utf8') > MAX_MESSAGE_BYTES) {
    throw integrityError('CUSTOMER_DIAGNOSTIC_INTEGRITY_MESSAGE_INVALID');
  }
  return value;
}

function integrityError(code) {
  const error = new Error('customer diagnostic integrity configuration rejected');
  error.code = code;
  return error;
}

module.exports = {
  CUSTOMER_DIAGNOSTIC_INTEGRITY_KEY_ID,
  createCustomerDiagnosticIntegrityAuthority,
  createCustomerDiagnosticIntegrityAuthorityFromEnvironment,
  customerDiagnosticIntegrityStatus,
};
