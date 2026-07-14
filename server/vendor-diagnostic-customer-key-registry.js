'use strict';

const crypto = require('node:crypto');
const protocol = require('./vendor-control-protocol');
const { isDeploymentId } = require('./deployment-identity');
const { parsePublicOnlyEd25519Key } = require('./vendor-signed-artifact');

const KEY_ID_RE = /^[a-z0-9][a-z0-9_.-]{0,63}$/;
const CUSTOMER_ID_RE = /^[a-z0-9][a-z0-9_-]{1,62}$/;
const MAX_VERIFY_ONLY_KEYS = 4;
const ERROR_MESSAGE = 'vendor diagnostic customer key registry rejected';

function createCustomerDeletionIntentKeyRegistry(options = {}) {
  try { return buildRegistry(options); }
  catch (error) { throw registryError(error && error.code ? error.code : 'registry_invalid'); }
}

function buildRegistry(options) {
  if (!options || typeof options !== 'object' || Array.isArray(options)) {
    throw registryError('registry_invalid');
  }
  const descriptors = Object.getOwnPropertyDescriptors(options);
  if (!Object.hasOwn(descriptors, 'entries')
      || Object.keys(descriptors).some((key) => !['entries', 'now'].includes(key))
      || Object.values(descriptors).some((descriptor) => !Object.hasOwn(descriptor, 'value')
        || descriptor.get || descriptor.set || descriptor.enumerable !== true)) {
    throw registryError('registry_invalid');
  }
  const input = Object.fromEntries(Object.entries(descriptors).map(([key, descriptor]) => [
    key, descriptor.value,
  ]));
  const now = checkedNow(input.now);
  if (!Array.isArray(input.entries) || input.entries.length < 1 || input.entries.length > 10_000) {
    throw registryError('registry_invalid');
  }
  const scopes = new Map();
  const identities = new Set();
  const keyIds = new Set();
  for (const raw of input.entries) {
    const entry = registryEntry(raw, identities, keyIds);
    const key = scopeKey(entry);
    if (scopes.has(key)) throw registryError('scope_duplicate');
    scopes.set(key, entry);
  }
  const manifest = Object.freeze({
    schemaVersion: 1,
    recordType: 'customer_deletion_intent_key_registry',
    scopes: Object.freeze([...scopes.values()].map(publicEntry)
      .sort((left, right) => scopeKey(left).localeCompare(scopeKey(right)))),
  });
  const manifestDigest = sha256(protocol.canonicalJson(manifest));
  return Object.freeze({
    manifest() { return manifest; },
    manifestDigest,
    verify(request) {
      try {
        const candidate = verificationRequest(request);
        const entry = scopes.get(scopeKey(candidate));
        if (!entry) return false;
        const key = [entry.current, ...entry.verifyOnly]
          .find((item) => item.keyId === candidate.keyId);
        if (!key || Date.parse(candidate.issuedAt) < Date.parse(key.validFrom)
            || (key.verifyUntil !== null
              && Date.parse(candidate.issuedAt) > Date.parse(key.verifyUntil))
            || (key.verifyUntil !== null && now() > Date.parse(key.verifyUntil))) return false;
        const signature = canonicalSignature(candidate.signature);
        return crypto.verify(
          null,
          deletionIntentSigningInput(candidate.domain, candidate.keyId, candidate.message),
          key.publicKey,
          signature,
        );
      } catch { return false; }
    },
  });
}

function registryEntry(value, identities, keyIds) {
  const input = exactObject(
    value, ['current', 'customerId', 'deploymentId', 'verifyOnly'], 'registry_invalid',
  );
  checkedScope(input);
  if (!Array.isArray(input.verifyOnly) || input.verifyOnly.length > MAX_VERIFY_ONLY_KEYS) {
    throw registryError('registry_invalid');
  }
  const current = publicKeyRecord(input.current, false);
  const verifyOnly = input.verifyOnly.map((item) => publicKeyRecord(item, true));
  for (const key of [current, ...verifyOnly]) {
    if (identities.has(key.fingerprint) || keyIds.has(key.keyId)) {
      throw registryError('key_identity_reused');
    }
    identities.add(key.fingerprint);
    keyIds.add(key.keyId);
  }
  return Object.freeze({
    customerId: input.customerId,
    deploymentId: input.deploymentId,
    current,
    verifyOnly: Object.freeze(verifyOnly),
  });
}

function publicKeyRecord(value, verifyOnly) {
  const keys = verifyOnly
    ? ['keyId', 'publicKey', 'validFrom', 'verifyUntil']
    : ['keyId', 'publicKey', 'validFrom'];
  const input = exactObject(value, keys, 'registry_invalid');
  if (typeof input.keyId !== 'string' || !KEY_ID_RE.test(input.keyId)) {
    throw registryError('registry_invalid');
  }
  const validFrom = canonicalIso(input.validFrom);
  const verifyUntil = verifyOnly ? canonicalIso(input.verifyUntil) : null;
  if (verifyUntil !== null && Date.parse(verifyUntil) <= Date.parse(validFrom)) {
    throw registryError('registry_invalid');
  }
  if (typeof input.publicKey !== 'string'
      || Buffer.byteLength(input.publicKey, 'utf8') > 8 * 1024) {
    throw registryError('registry_invalid');
  }
  let key;
  try { key = parsePublicOnlyEd25519Key(input.publicKey); }
  catch { throw registryError('registry_invalid'); }
  const der = key.export({ format: 'der', type: 'spki' });
  return Object.freeze({
    keyId: input.keyId,
    publicKey: key,
    fingerprint: sha256(der),
    validFrom,
    verifyUntil,
  });
}

function publicEntry(entry) {
  const summarize = (key) => Object.freeze({
    keyId: key.keyId,
    fingerprint: key.fingerprint,
    validFrom: key.validFrom,
    verifyUntil: key.verifyUntil,
  });
  return Object.freeze({
    customerId: entry.customerId,
    deploymentId: entry.deploymentId,
    current: summarize(entry.current),
    verifyOnly: Object.freeze(entry.verifyOnly.map(summarize)),
  });
}

function verificationRequest(value) {
  const input = exactObject(value, [
    'customerId', 'deploymentId', 'domain', 'issuedAt', 'keyId', 'message', 'signature',
  ], 'verification_invalid');
  checkedScope(input);
  if (typeof input.domain !== 'string' || input.domain.length < 8 || input.domain.length > 256
      || typeof input.keyId !== 'string' || !KEY_ID_RE.test(input.keyId)
      || typeof input.message !== 'string' || Buffer.byteLength(input.message, 'utf8') > 1024 * 1024) {
    throw registryError('verification_invalid');
  }
  canonicalIso(input.issuedAt);
  return input;
}

function deletionIntentSigningInput(domain, keyId, message) {
  return Buffer.from(`${domain}\0${keyId}\0${message}`, 'utf8');
}

function canonicalSignature(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    throw registryError('verification_invalid');
  }
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length !== 64 || bytes.toString('base64') !== value) {
    throw registryError('verification_invalid');
  }
  return bytes;
}

function checkedScope(value) {
  if (typeof value.customerId !== 'string' || !CUSTOMER_ID_RE.test(value.customerId)
      || !isDeploymentId(value.deploymentId)) {
    throw registryError('registry_invalid');
  }
}

function checkedNow(value) {
  const now = value === undefined ? Date.now : value;
  if (typeof now !== 'function') throw registryError('registry_invalid');
  const probe = now();
  if (!Number.isSafeInteger(probe) || probe < 0) {
    throw registryError('registry_invalid');
  }
  return now;
}

function exactObject(value, keys, code) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.getPrototypeOf(value) !== Object.prototype
      || Object.keys(value).sort().join(',') !== [...keys].sort().join(',')) {
    throw registryError(code);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Object.values(descriptors).some((descriptor) => !Object.hasOwn(descriptor, 'value')
      || descriptor.get || descriptor.set || descriptor.enumerable !== true)) {
    throw registryError(code);
  }
  return Object.fromEntries(Object.entries(descriptors).map(([key, descriptor]) => [
    key, descriptor.value,
  ]));
}

function canonicalIso(value) {
  const parsed = typeof value === 'string' ? Date.parse(value) : NaN;
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    throw registryError('registry_invalid');
  }
  return value;
}

function scopeKey(value) { return `${value.customerId}\0${value.deploymentId}`; }
function sha256(value) { return crypto.createHash('sha256').update(value).digest('hex'); }

function registryError(code) {
  const error = new Error(ERROR_MESSAGE);
  error.code = code;
  return error;
}

module.exports = {
  createCustomerDeletionIntentKeyRegistry,
  deletionIntentSigningInput,
};
