'use strict';

const crypto = require('node:crypto');
const { types: utilTypes } = require('node:util');
const protocol = require('./vendor-control-protocol');

const KEY_ID_RE = /^[a-z0-9][a-z0-9_.-]{0,95}$/;
const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;
const SHA256_RE = /^[a-f0-9]{64}$/;
const MAX_PUBLIC_KEYS = 2;

const KEY_PURPOSES = Object.freeze({
  OFFLINE_LICENSE: 'offline_license',
  ONLINE_VERDICT: 'online_verdict',
  ENTITLEMENT: 'entitlement',
  PLATFORM_AUDIT: 'platform_audit',
  RECOVERY: 'recovery',
  DIAGNOSTIC_INTEGRITY: 'diagnostic_integrity',
  AUDIT_REQUEST: 'audit_request',
  POLICY: 'policy',
  LIFECYCLE: 'lifecycle',
  CATALOG_GLOBAL: 'catalog_global',
  CATALOG_DISTRIBUTION: 'catalog_distribution',
  OWNER_ATTESTATION: 'owner_attestation',
  WITNESS_INTEGRITY: 'witness_integrity',
  HEARTBEAT_CREDENTIAL: 'heartbeat_credential',
  ACKNOWLEDGEMENT_CREDENTIAL: 'acknowledgement_credential',
  DIAGNOSTIC_CREDENTIAL: 'diagnostic_credential',
  SHADOW_CANDIDATE_CREDENTIAL: 'shadow_candidate_credential',
  LICENSE_REGISTRY_INTEGRITY: 'license_registry_integrity',
  COMMAND_IDEMPOTENCY: 'command_idempotency',
  PAGINATION_CURSOR: 'pagination_cursor',
});

const AUTHORITY_DEFINITIONS = Object.freeze({
  [KEY_PURPOSES.OFFLINE_LICENSE]: definition('ed25519_public', 'rw-offline-license-'),
  [KEY_PURPOSES.ONLINE_VERDICT]: definition('ed25519_public', 'rw-online-verdict-'),
  [KEY_PURPOSES.ENTITLEMENT]: definition('ed25519_public', 'rw-entitlement-'),
  [KEY_PURPOSES.PLATFORM_AUDIT]: definition('hmac_secret', 'rw-platform-audit-'),
  [KEY_PURPOSES.RECOVERY]: definition('hmac_secret', 'rw-recovery-'),
  [KEY_PURPOSES.DIAGNOSTIC_INTEGRITY]: definition('hmac_secret', 'rw-diagnostic-integrity-'),
  [KEY_PURPOSES.AUDIT_REQUEST]: definition('ed25519_public', 'rw-audit-request-'),
  [KEY_PURPOSES.POLICY]: definition('ed25519_public', 'rw-policy-'),
  [KEY_PURPOSES.LIFECYCLE]: definition('hmac_secret', 'rw-lifecycle-'),
  [KEY_PURPOSES.CATALOG_GLOBAL]: definition('ed25519_public', 'rw-catalog-global-'),
  [KEY_PURPOSES.CATALOG_DISTRIBUTION]: definition('ed25519_public', 'rw-catalog-distribution-'),
  [KEY_PURPOSES.OWNER_ATTESTATION]: definition('ed25519_public', 'rw-owner-attestation-'),
  [KEY_PURPOSES.WITNESS_INTEGRITY]: definition('hmac_secret', 'rw-lifecycle-witness-'),
  [KEY_PURPOSES.HEARTBEAT_CREDENTIAL]: definition('opaque_credential', 'rw-heartbeat-credential-'),
  [KEY_PURPOSES.ACKNOWLEDGEMENT_CREDENTIAL]: definition(
    'opaque_credential', 'rw-ack-credential-',
  ),
  [KEY_PURPOSES.DIAGNOSTIC_CREDENTIAL]: definition(
    'opaque_credential', 'rw-diagnostic-credential-',
  ),
  [KEY_PURPOSES.SHADOW_CANDIDATE_CREDENTIAL]: definition(
    'opaque_credential', 'rw-shadow-candidate-credential-',
  ),
  [KEY_PURPOSES.LICENSE_REGISTRY_INTEGRITY]: definition(
    'hmac_secret', 'rw-license-registry-integrity-',
  ),
  [KEY_PURPOSES.COMMAND_IDEMPOTENCY]: definition(
    'hmac_secret', 'rw-command-idempotency-',
  ),
  [KEY_PURPOSES.PAGINATION_CURSOR]: definition(
    'hmac_secret', 'rw-pagination-cursor-',
  ),
});

const SIGNED_KIND_PURPOSES = Object.freeze({
  [protocol.CHANNEL_KINDS.ENTITLEMENT]: KEY_PURPOSES.ENTITLEMENT,
  [protocol.CHANNEL_KINDS.GLOBAL_CATALOG_RELEASE]: KEY_PURPOSES.CATALOG_GLOBAL,
  [protocol.CHANNEL_KINDS.CATALOG_DISTRIBUTION]: KEY_PURPOSES.CATALOG_DISTRIBUTION,
  [protocol.CHANNEL_KINDS.POLICY_DESIRED_STATE]: KEY_PURPOSES.POLICY,
  [protocol.CHANNEL_KINDS.AUDIT_REQUEST]: KEY_PURPOSES.AUDIT_REQUEST,
});

function definition(identityType, keyPrefix) {
  return Object.freeze({ identityType, keyPrefix });
}

/**
 * Validate the complete vendor authority manifest once at process startup.
 * Identity equality is deliberately namespaced by cryptographic type. An HMAC
 * secret digest is not represented as, or compared with, an Ed25519 public-key
 * fingerprint.
 */
function createAuthorityRegistry(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)
      || Object.keys(input).sort().join(',') !== Object.keys(AUTHORITY_DEFINITIONS).sort().join(',')) {
    throw keyError('vendor_authority_manifest_invalid');
  }
  const records = new Map();
  const identities = new Set();
  const keyIds = new Set();
  for (const purpose of Object.keys(AUTHORITY_DEFINITIONS)) {
    const value = input[purpose];
    const expected = AUTHORITY_DEFINITIONS[purpose];
    if (!value || typeof value !== 'object' || Array.isArray(value)
        || Object.keys(value).sort().join(',') !== 'identity,keyId'
        || !validPurposeKeyBinding(value.keyId, purpose, value.identity)
        || !SHA256_RE.test(String(value.identity || ''))) {
      throw keyError('vendor_authority_manifest_invalid');
    }
    if (identities.has(value.identity) || keyIds.has(value.keyId)) {
      throw keyError('vendor_key_identity_reused');
    }
    identities.add(value.identity);
    keyIds.add(value.keyId);
    records.set(purpose, Object.freeze({
      purpose,
      identityType: expected.identityType,
      keyId: value.keyId,
      identity: value.identity,
    }));
  }
  return Object.freeze({
    get(purposeValue) {
      const purpose = checkedPurpose(purposeValue);
      const record = records.get(purpose);
      return record ? { ...record } : null;
    },
    assertPublicKey(purposeValue, keyId, fingerprint) {
      const purpose = checkedPurpose(purposeValue);
      const record = records.get(purpose);
      if (!record || record.identityType !== 'ed25519_public'
          || record.keyId !== keyId || record.identity !== fingerprint) {
        throw keyError('vendor_authority_manifest_mismatch');
      }
    },
  });
}

function normalizePublicKeys(input, options = {}) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw keyError('vendor_keys_invalid');
  }
  const entries = input instanceof Map ? [...input.entries()] : Object.entries(input);
  if (!entries.length || entries.length > MAX_PUBLIC_KEYS) throw keyError('vendor_keys_invalid');
  const purpose = checkedPurpose(options.purpose);
  const strictPurpose = options.strictPurpose === true || Boolean(options.authorityRegistry);
  const forbidden = normalizeForbiddenPublicFingerprints(options);
  const output = new Map();
  const fingerprints = new Set();
  for (const [rawKeyId, value] of entries) {
    const keyId = String(rawKeyId || '');
    if (!KEY_ID_RE.test(keyId)) throw keyError('vendor_key_id_invalid');
    if (purpose && strictPurpose && !validPurposeKeyId(keyId, purpose)) {
      throw keyError('vendor_key_purpose_mismatch');
    }
    const key = parsePublicOnlyEd25519Key(value);
    const fingerprint = keyFingerprint(key);
    if (purpose === KEY_PURPOSES.ENTITLEMENT
        && keyId !== `rw-entitlement-${fingerprint}`) {
      throw keyError('vendor_key_purpose_mismatch');
    }
    if (fingerprints.has(fingerprint) || forbidden.has(fingerprint)) {
      throw keyError('vendor_key_identity_reused');
    }
    fingerprints.add(fingerprint);
    if (options.authorityRegistry) {
      if (typeof options.authorityRegistry.assertPublicKey !== 'function') {
        throw keyError('vendor_authority_manifest_invalid');
      }
      options.authorityRegistry.assertPublicKey(purpose, keyId, fingerprint);
    }
    output.set(keyId, key);
  }
  return output;
}

function containsPrivateKeyMaterial(value) {
  try {
    return crypto.createPrivateKey(value).type === 'private';
  } catch {
    return false;
  }
}

/**
 * Parse an Ed25519 verifier key without allowing Node to derive a public key
 * from private material. createPublicKey() accepts private PEM/PKCS8 inputs.
 * Snapshot every supported structured input before either crypto API sees it,
 * so a Proxy, accessor, mutable byte view, or nested private key cannot change
 * the material between the private-key probe and public-key parse.
 */
function parsePublicOnlyEd25519Key(value) {
  let key;
  try {
    const stable = stableKeyInput(value);
    if (utilTypes.isKeyObject(stable)) {
      if (stable.type !== 'public') throw new Error('private key object');
      key = stable;
    } else {
      if (containsPrivateKeyMaterial(stable)) throw new Error('private key material');
      key = crypto.createPublicKey(stable);
    }
  } catch { throw keyError('vendor_key_invalid'); }
  if (key.type !== 'public' || key.asymmetricKeyType !== 'ed25519') {
    throw keyError('vendor_key_invalid');
  }
  return key;
}

function stableKeyInput(value, seen = new Set(), depth = 0) {
  if (depth > 8 || utilTypes.isProxy(value)) throw new Error('unstable key input');
  if (utilTypes.isKeyObject(value)) {
    if (value.type !== 'public') throw new Error('private key object');
    return value;
  }
  if (utilTypes.isCryptoKey(value)) {
    const key = crypto.KeyObject.from(value);
    if (key.type !== 'public') throw new Error('private crypto key');
    return key;
  }
  if (typeof value === 'string' || value === null || value === undefined
      || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('invalid key input');
    return value;
  }
  if (Buffer.isBuffer(value)) return Buffer.from(value);
  if (ArrayBuffer.isView(value)) {
    return Buffer.from(Buffer.from(value.buffer, value.byteOffset, value.byteLength));
  }
  if (value instanceof ArrayBuffer) return Buffer.from(new Uint8Array(value));
  if (!value || typeof value !== 'object' || seen.has(value)) {
    throw new Error('invalid key input');
  }
  seen.add(value);
  if (Array.isArray(value)) {
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.some((key) => typeof key !== 'string')
        || keys.length !== value.length + 1 || !Object.hasOwn(descriptors, 'length')) {
      throw new Error('invalid key input');
    }
    return Array.from({ length: value.length }, (_, index) => {
      const descriptor = descriptors[String(index)];
      if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.get || descriptor.set) {
        throw new Error('invalid key input');
      }
      return stableKeyInput(descriptor.value, seen, depth + 1);
    });
  }
  if (Object.getPrototypeOf(value) !== Object.prototype) {
    throw new Error('invalid key input');
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  if (keys.length > 64 || keys.some((key) => typeof key !== 'string')) {
    throw new Error('invalid key input');
  }
  const snapshot = {};
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (!Object.hasOwn(descriptor, 'value') || descriptor.get || descriptor.set) {
      throw new Error('invalid key input');
    }
    snapshot[key] = stableKeyInput(descriptor.value, seen, depth + 1);
  }
  return snapshot;
}

function verifySignedArtifact(value, publicKeys, expectedKind, options = {}) {
  const artifact = stableArtifactInput(value);
  if (Object.keys(artifact).sort().join(',') !== 'keyId,payload,signature') {
    throw artifactError('invalid_schema');
  }
  if (!KEY_ID_RE.test(String(artifact.keyId || ''))) throw artifactError('invalid_schema');
  const purpose = options.purpose || expectedKind;
  const keysById = normalizePublicKeys(publicKeys, { ...options, purpose });
  const key = keysById.get(artifact.keyId);
  if (!key) throw artifactError('unknown_signing_key');
  const signature = canonicalSignature(artifact.signature);
  const payload = protocol.assertChannel(artifact.payload, expectedKind);
  if (!crypto.verify(null, protocol.signingInput(payload, artifact.keyId), key, signature)) {
    throw artifactError('invalid_signature');
  }
  return Object.freeze({
    keyId: artifact.keyId,
    payload,
    payloadDigest: protocol.payloadDigest(payload, expectedKind),
    artifactDigest: crypto.createHash('sha256').update(protocol.canonicalJson({
      keyId: artifact.keyId,
      payload,
      signature: artifact.signature,
    }), 'utf8').digest('hex'),
    signatureDomain: protocol.SIGNATURE_DOMAINS[payload.kind],
  });
}

function stableArtifactInput(value) {
  try {
    const budget = { nodes: 0 };
    const artifact = stableJsonValue(value, new Set(), budget, 0);
    if (!artifact || typeof artifact !== 'object' || Array.isArray(artifact)) throw new Error();
    return artifact;
  } catch { throw artifactError('invalid_schema'); }
}

function stableJsonValue(value, seen, budget, depth) {
  budget.nodes += 1;
  if (budget.nodes > 4096 || depth > 32 || utilTypes.isProxy(value)) throw new Error();
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error();
    return value;
  }
  if (!value || typeof value !== 'object' || seen.has(value)) throw new Error();
  seen.add(value);
  try {
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.some((key) => typeof key !== 'string')) throw new Error();
    if (Array.isArray(value)) {
      if (keys.length !== value.length + 1 || !Object.hasOwn(descriptors, 'length')) throw new Error();
      return Array.from({ length: value.length }, (_unused, index) => stableDataProperty(
        descriptors[String(index)], seen, budget, depth + 1,
      ));
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) throw new Error();
    if (keys.length > 128) throw new Error();
    return Object.fromEntries(keys.map((key) => [
      key, stableDataProperty(descriptors[key], seen, budget, depth + 1),
    ]));
  } finally {
    seen.delete(value);
  }
}

function stableDataProperty(descriptor, seen, budget, depth) {
  if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')
      || descriptor.get || descriptor.set) throw new Error();
  return stableJsonValue(descriptor.value, seen, budget, depth);
}

function checkedPurpose(value) {
  if (value === undefined || value === null || value === '') return null;
  const mapped = SIGNED_KIND_PURPOSES[value] || value;
  if (!Object.hasOwn(AUTHORITY_DEFINITIONS, mapped)) throw keyError('vendor_key_purpose_invalid');
  return mapped;
}

function validPurposeKeyId(value, purposeValue) {
  const purpose = checkedPurpose(purposeValue);
  return KEY_ID_RE.test(String(value || ''))
    && String(value).startsWith(AUTHORITY_DEFINITIONS[purpose].keyPrefix);
}

function validPurposeKeyBinding(value, purposeValue, identity) {
  const purpose = checkedPurpose(purposeValue);
  if (!validPurposeKeyId(value, purpose)) return false;
  if (purpose !== KEY_PURPOSES.ENTITLEMENT) return true;
  return SHA256_RE.test(String(identity || ''))
    && String(value) === `rw-entitlement-${identity}`;
}

function normalizeForbiddenPublicFingerprints(options) {
  const values = [];
  if (options.offlineKeyFingerprint) values.push(options.offlineKeyFingerprint);
  if (Array.isArray(options.forbiddenPublicKeyFingerprints)) {
    values.push(...options.forbiddenPublicKeyFingerprints);
  }
  if (!values.every((value) => SHA256_RE.test(String(value || '')))) {
    throw keyError('vendor_keys_invalid');
  }
  return new Set(values);
}

function keyFingerprint(keyValue) {
  const key = parsePublicOnlyEd25519Key(keyValue);
  const der = key.export({ type: 'spki', format: 'der' });
  return crypto.createHash('sha256').update(der).digest('hex');
}

function canonicalSignature(value) {
  const encoded = String(value || '');
  if (!BASE64_RE.test(encoded)) throw artifactError('invalid_signature');
  const decoded = Buffer.from(encoded, 'base64');
  if (decoded.length !== 64 || decoded.toString('base64') !== encoded) {
    throw artifactError('invalid_signature');
  }
  return decoded;
}

function keyError(code) {
  const error = new TypeError('vendor signing key configuration rejected');
  error.code = code;
  return error;
}

function artifactError(code) {
  const error = new Error('vendor control artifact rejected');
  error.code = code;
  return error;
}

module.exports = {
  AUTHORITY_DEFINITIONS,
  KEY_PURPOSES,
  MAX_PUBLIC_KEYS,
  createAuthorityRegistry,
  keyFingerprint,
  normalizePublicKeys,
  parsePublicOnlyEd25519Key,
  validPurposeKeyBinding,
  validPurposeKeyId,
  verifySignedArtifact,
};
