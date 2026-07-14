'use strict';

const crypto = require('node:crypto');

const VERDICT_DOMAIN = 'redactwall.connected-license-verdict.v2';
const KEY_ID_PREFIX = 'rw-online-verdict-';
const KEY_ID_RE = /^rw-online-verdict-[a-f0-9]{64}$/;
const CUSTOMER_ID_RE = /^[a-z0-9][a-z0-9_-]{1,62}$/;
const DEPLOYMENT_ID_RE = /^dep_[a-f0-9]{32}$/;
const HEX_64_RE = /^[a-f0-9]{64}$/;
const ISO_TIME_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;
const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;
const MAX_SIGNED_BYTES = 4096;
const MAX_PAYLOAD_BYTES = 2048;
const PAYLOAD_KEYS = Object.freeze([
  'kind', 'keyId', 'status', 'customerId', 'deploymentId', 'issuedAt',
  'registryGeneration', 'registryStateDigest',
]);

function verifySignedOnlineVerdict(text, keyring, options = {}) {
  const keys = normalizeKeyring(keyring, options);
  const parsed = parseSigned(text);
  const publicKey = keys.get(parsed.payload.keyId);
  if (!publicKey) throw verdictError('registry_signing_key_unknown');
  if (!crypto.verify(null, parsed.input, publicKey, parsed.signature)) {
    throw verdictError('registry_signature_invalid');
  }
  return Object.freeze({
    payload: parsed.payload,
    signatureDomain: VERDICT_DOMAIN,
    signedEnvelopeDigest: sha256(Buffer.from(text, 'utf8')),
    signingKeyId: parsed.payload.keyId,
    signingKeyFingerprint: keyFingerprint(publicKey),
  });
}

function normalizeKeyring(input, options = {}) {
  const entries = keyringEntries(input);
  if (entries.length < 1 || entries.length > 2) throw verdictError('registry_keyring_invalid');
  const forbidden = forbiddenFingerprints(options.forbiddenPublicKeyFingerprints);
  const output = new Map();
  const identities = new Set();
  for (const [rawKeyId, value] of entries) {
    const keyId = String(rawKeyId || '');
    const publicKey = checkedPublicKey(value);
    const fingerprint = keyFingerprint(publicKey);
    if (!KEY_ID_RE.test(keyId) || keyId !== `${KEY_ID_PREFIX}${fingerprint}`) {
      throw verdictError('registry_key_id_invalid');
    }
    if (identities.has(fingerprint) || forbidden.has(fingerprint)) {
      throw verdictError('registry_key_identity_reused');
    }
    identities.add(fingerprint);
    output.set(keyId, publicKey);
  }
  return output;
}

function parseSigned(text) {
  if (typeof text !== 'string' || Buffer.byteLength(text, 'utf8') > MAX_SIGNED_BYTES) {
    throw verdictError('registry_signed_verdict_invalid');
  }
  const parts = text.split('.');
  if (parts.length !== 2 || !parts.every((part) => BASE64_RE.test(part))) {
    throw verdictError('registry_signed_verdict_invalid');
  }
  const payloadBytes = canonicalBase64(parts[0], MAX_PAYLOAD_BYTES);
  const signature = canonicalBase64(parts[1], 64);
  if (signature.length !== 64) throw verdictError('registry_signature_invalid');
  let parsed;
  try { parsed = JSON.parse(payloadBytes.toString('utf8')); }
  catch { throw verdictError('registry_payload_invalid'); }
  const payload = checkedPayload(parsed);
  if (JSON.stringify(payload) !== payloadBytes.toString('utf8')) {
    throw verdictError('registry_payload_noncanonical');
  }
  return {
    payload,
    signature,
    input: Buffer.from(`${VERDICT_DOMAIN}\0${parts[0]}`, 'utf8'),
  };
}

function checkedPayload(value) {
  if (!plainRecord(value) || !exactKeys(value, PAYLOAD_KEYS)
      || value.kind !== VERDICT_DOMAIN || !KEY_ID_RE.test(String(value.keyId || ''))
      || !['active', 'revoked'].includes(value.status)
      || !CUSTOMER_ID_RE.test(String(value.customerId || ''))
      || !DEPLOYMENT_ID_RE.test(String(value.deploymentId || ''))
      || !validIsoTime(value.issuedAt)
      || !Number.isSafeInteger(value.registryGeneration) || value.registryGeneration < 1
      || !HEX_64_RE.test(String(value.registryStateDigest || ''))) {
    throw verdictError('registry_payload_invalid');
  }
  return Object.fromEntries(PAYLOAD_KEYS.map((key) => [key, value[key]]));
}

function keyIdForPublicKey(value) {
  return `${KEY_ID_PREFIX}${keyFingerprint(checkedPublicKey(value))}`;
}

function keyFingerprint(value) {
  const key = checkedPublicKey(value);
  return sha256(key.export({ type: 'spki', format: 'der' }));
}

function checkedPublicKey(value) {
  let key;
  try {
    if (value instanceof crypto.KeyObject) {
      if (value.type !== 'public') throw new Error();
      key = value;
    } else {
      if (containsPrivateKeyMaterial(value)) throw new Error();
      key = crypto.createPublicKey(value);
    }
  } catch { throw verdictError('registry_public_key_invalid'); }
  if (key.type !== 'public' || key.asymmetricKeyType !== 'ed25519') {
    throw verdictError('registry_public_key_invalid');
  }
  return key;
}

function containsPrivateKeyMaterial(value) {
  try {
    return crypto.createPrivateKey(value).type === 'private';
  } catch {
    return false;
  }
}

function keyringEntries(input) {
  if (input instanceof Map) return [...input.entries()];
  if (!plainRecord(input) || Object.getOwnPropertySymbols(input).length) {
    throw verdictError('registry_keyring_invalid');
  }
  const descriptors = Object.getOwnPropertyDescriptors(input);
  if (Object.values(descriptors).some((entry) => !entry.enumerable
      || !Object.hasOwn(entry, 'value'))) throw verdictError('registry_keyring_invalid');
  return Object.entries(input);
}

function forbiddenFingerprints(values) {
  if (values === undefined) return new Set();
  if (!Array.isArray(values) || !values.every((value) => HEX_64_RE.test(String(value || '')))) {
    throw verdictError('registry_keyring_invalid');
  }
  return new Set(values);
}

function canonicalBase64(value, maxBytes) {
  const decoded = Buffer.from(value, 'base64');
  if (!decoded.length || decoded.length > maxBytes || decoded.toString('base64') !== value) {
    throw verdictError('registry_signed_verdict_invalid');
  }
  return decoded;
}

function validIsoTime(value) {
  return typeof value === 'string' && value.length <= 40 && ISO_TIME_RE.test(value)
    && Number.isFinite(Date.parse(value));
}

function plainRecord(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value, keys) {
  return Object.keys(value).sort().join('\0') === [...keys].sort().join('\0');
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function verdictError(code) {
  const error = new Error('connected online verdict rejected');
  error.code = code;
  return error;
}

module.exports = Object.freeze({
  KEY_ID_PREFIX,
  KEY_ID_RE,
  MAX_PAYLOAD_BYTES,
  MAX_SIGNED_BYTES,
  PAYLOAD_KEYS,
  VERDICT_DOMAIN,
  keyFingerprint,
  keyIdForPublicKey,
  normalizeKeyring,
  verifySignedOnlineVerdict,
});
