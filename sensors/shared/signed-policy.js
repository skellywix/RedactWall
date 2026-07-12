'use strict';
/** Pinned Ed25519 policy verification plus an atomic, bounded LKG cache. */
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { withFileMutationLockSync } = require('../../server/file-mutation-lock');
const {
  assertPrivatePath,
  securePrivatePath,
  withPrivateDirectoryMutationLockSync,
  readBoundedRegularFile,
  publishFileDurably,
} = require('../../server/private-path');

const BUNDLE_VERSION = 1;
const MAX_BUNDLE_BYTES = 512 * 1024;
const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;
const PRIVATE_INIT_LOCK_TIMEOUT_MS = 60_000;
const runtimeHighWater = new Map();

function arrayIndexKey(value) {
  if (!/^(0|[1-9]\d*)$/.test(value)) return false;
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed >= 0 && parsed < 4294967295 && String(parsed) === value;
}

function orderedPolicyKeys(value, legacyLexical = false) {
  const keys = Object.keys(value);
  if (legacyLexical) return keys.sort();
  return [
    ...keys.filter(arrayIndexKey).sort((left, right) => Number(left) - Number(right)),
    ...keys.filter((key) => !arrayIndexKey(key)).sort(),
  ];
}

function canonicalPolicyJson(value, legacyLexical = false) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((item) => canonicalPolicyJson(item, legacyLexical)).join(',')}]`;
  return `{${orderedPolicyKeys(value, legacyLexical).map((key) => (
    `${JSON.stringify(key)}:${canonicalPolicyJson(value[key], legacyLexical)}`
  )).join(',')}}`;
}

function signingInput(bundle, canonical = true, legacyLexical = false) {
  if (!bundle.policy || typeof bundle.policy !== 'object' || Array.isArray(bundle.policy)) {
    throw new TypeError('policy must be an object');
  }
  const serializedPolicy = canonical ? canonicalPolicyJson(bundle.policy, legacyLexical) : JSON.stringify(bundle.policy);
  const policyHash = crypto.createHash('sha256').update(serializedPolicy).digest('hex');
  return JSON.stringify({
    version: bundle.version,
    issuedAt: bundle.issuedAt,
    expiresAt: bundle.expiresAt,
    policyHash,
  });
}

function strictSignature(value) {
  return typeof value === 'string' && /^[A-Za-z0-9+/]{86}==$/.test(value)
    ? Buffer.from(value, 'base64')
    : null;
}

function resolvePinnedPublicKey(options = {}) {
  const env = options.env || process.env;
  let value = options.policyPublicKey || options.publicKey || env.REDACTWALL_POLICY_PUBLIC_KEY || '';
  const file = options.policyPublicKeyPath || options.publicKeyPath || env.REDACTWALL_POLICY_PUBLIC_KEY_PATH || '';
  if (!value && file) {
    value = readBoundedRegularFile(path.resolve(file), {
      fs: options.fs || fs,
      maxBytes: 16 * 1024,
      label: 'policy public-key file',
    }).toString('utf8');
  }
  value = String(value || '').replace(/\\n/g, '\n').trim();
  return value ? `${value}\n` : '';
}

function verifySignedPolicyBundle(bundle, publicKeyPem, options = {}) {
  if (!publicKeyPem) return { ok: false, reason: 'missing_pin' };
  if (!bundle || typeof bundle !== 'object' || Array.isArray(bundle)) return { ok: false, reason: 'no_bundle' };
  let encoded;
  try { encoded = Buffer.from(JSON.stringify(bundle)); } catch { return { ok: false, reason: 'malformed_bundle' }; }
  if (!encoded.length || encoded.length > (options.maxBytes || MAX_BUNDLE_BYTES)) return { ok: false, reason: 'bundle_too_large' };
  if (bundle.version !== BUNDLE_VERSION) return { ok: false, reason: 'version_mismatch' };
  if (!bundle.policy || typeof bundle.policy !== 'object' || Array.isArray(bundle.policy)) return { ok: false, reason: 'malformed_bundle' };
  const signature = strictSignature(bundle.signature);
  if (!signature) return { ok: false, reason: 'bad_signature' };
  const now = Number(options.now ?? Date.now());
  const issued = Date.parse(bundle.issuedAt);
  const expires = Date.parse(bundle.expiresAt);
  if (![now, issued, expires].every(Number.isFinite)
      || issued > now + MAX_CLOCK_SKEW_MS || expires <= issued
      || (!options.allowExpired && expires <= now)) {
    return { ok: false, reason: 'expired' };
  }
  try {
    const key = crypto.createPublicKey(publicKeyPem);
    if (key.asymmetricKeyType !== 'ed25519') return { ok: false, reason: 'bad_public_key' };
    const inputs = [...new Set([signingInput(bundle), signingInput(bundle, true, true), signingInput(bundle, false)])];
    const valid = inputs.some((input) => crypto.verify(null, Buffer.from(input), key, signature));
    return valid ? { ok: true } : { ok: false, reason: 'bad_signature' };
  } catch {
    return { ok: false, reason: 'bad_public_key' };
  }
}

function defaultCachePath(sensorId = 'sensor') {
  const safe = String(sensorId || 'sensor').toLowerCase().replace(/[^a-z0-9_-]+/g, '-').slice(0, 64) || 'sensor';
  return path.join(os.homedir(), '.redactwall', `${safe}-policy-bundle.json`);
}

function configuredCachePath(options = {}) {
  const env = options.env || process.env;
  return path.resolve(options.policyCachePath || options.cachePath
    || env.REDACTWALL_POLICY_CACHE_PATH || defaultCachePath(options.sensorId));
}

function highWaterKey(publicKey, options = {}) {
  return `${configuredCachePath(options)}:${crypto.createHash('sha256').update(publicKey).digest('hex')}`;
}

function sequenceCheck(previous, next) {
  if (!previous) return { ok: true };
  const priorIssued = Date.parse(previous.issuedAt);
  const nextIssued = Date.parse(next.issuedAt);
  if (priorIssued > nextIssued) return { ok: false, reason: 'rollback_detected' };
  if (priorIssued === nextIssued && previous.signature !== next.signature) {
    return { ok: false, reason: 'policy_sequence_conflict' };
  }
  return { ok: true };
}

function cacheSecurity(options, directory) {
  return {
    ...(options.privatePathSecurity || {}),
    fs: options.fs || fs,
    directory,
    label: 'signed policy cache',
    ownerLabel: 'signed policy cache',
  };
}

function readCacheBundle(options = {}) {
  const file = configuredCachePath(options);
  const dir = path.dirname(file);
  assertPrivatePath(dir, cacheSecurity(options, true));
  assertPrivatePath(file, cacheSecurity(options, false));
  return JSON.parse(readBoundedRegularFile(file, {
    ...cacheSecurity(options, false),
    maxBytes: options.maxBytes || MAX_BUNDLE_BYTES,
  }).toString('utf8'));
}

function readCachedSignedPolicy(options = {}) {
  let publicKey;
  try { publicKey = resolvePinnedPublicKey(options); } catch { return { ok: false, reason: 'bad_public_key' }; }
  if (!publicKey) return { ok: false, reason: 'missing_pin' };
  try {
    const bundle = readCacheBundle(options);
    const verified = verifySignedPolicyBundle(bundle, publicKey, options);
    if (!verified.ok) return verified;
    const key = highWaterKey(publicKey, options);
    const sequence = sequenceCheck(runtimeHighWater.get(key), bundle);
    if (!sequence.ok) return sequence;
    runtimeHighWater.set(key, bundle);
    return { ok: true, policy: bundle.policy, bundle, source: 'cache' };
  } catch {
    return { ok: false, reason: 'no_fresh_cache' };
  }
}

function persistSignedPolicyBundleUnlocked(bundle, options = {}) {
  const body = `${JSON.stringify(bundle)}\n`;
  if (Buffer.byteLength(body) > (options.maxBytes || MAX_BUNDLE_BYTES)) throw new Error('policy bundle too large');
  const fsImpl = options.fs || fs;
  const file = configuredCachePath(options);
  const dir = path.dirname(file);
  const temp = path.join(dir, `.${path.basename(file)}.${crypto.randomBytes(16).toString('hex')}.tmp`);
  let fd;
  let publicationStarted = false;
  try {
    fd = fsImpl.openSync(temp, 'wx', 0o600);
    fsImpl.writeFileSync(fd, body, 'utf8');
    fsImpl.fsyncSync(fd);
    fsImpl.fchmodSync(fd, 0o600);
    fsImpl.closeSync(fd);
    fd = undefined;
    securePrivatePath(temp, cacheSecurity(options, false));
    publicationStarted = true;
    publishFileDurably(temp, file, {
      ...options,
      fs: fsImpl,
      cleanupComponent: 'signed-policy-cache-publication',
    });
    return file;
  } finally {
    if (fd !== undefined) { try { fsImpl.closeSync(fd); } catch {} }
    if (!publicationStarted) try { fsImpl.unlinkSync(temp); } catch {}
  }
}

function cachedHighWater(publicKey, options = {}) {
  try {
    const bundle = readCacheBundle(options);
    const verified = verifySignedPolicyBundle(bundle, publicKey, { ...options, allowExpired: true });
    return verified.ok
      ? { ok: true, bundle }
      : { ok: false, reason: 'cache_high_water_invalid', blocksUpdate: true };
  } catch (error) {
    return error && error.code === 'ENOENT'
      ? { ok: false, reason: 'no_cache_high_water' }
      : { ok: false, reason: 'cache_high_water_invalid', blocksUpdate: true };
  }
}

function acceptSignedPolicyBundle(bundle, options = {}) {
  let publicKey;
  try { publicKey = resolvePinnedPublicKey(options); } catch { return { ok: false, reason: 'bad_public_key' }; }
  const verified = verifySignedPolicyBundle(bundle, publicKey, options);
  if (!verified.ok) return verified;
  const key = highWaterKey(publicKey, options);
  const memorySequence = sequenceCheck(runtimeHighWater.get(key), bundle);
  if (!memorySequence.ok) return memorySequence;
  let persisted = false;
  try {
    const file = configuredCachePath(options);
    const result = withPrivateDirectoryMutationLockSync(path.dirname(file), () => {
      return withFileMutationLockSync(file, () => {
        const previous = cachedHighWater(publicKey, options);
        if (previous.blocksUpdate) return previous;
        if (previous.ok) {
          const sequence = sequenceCheck(previous.bundle, bundle);
          if (!sequence.ok) return sequence;
          if (previous.bundle.signature === bundle.signature) return { ok: true, persisted: true };
        }
        try {
          persistSignedPolicyBundleUnlocked(bundle, options);
          return { ok: true, persisted: true };
        } catch {
          return { ok: false, reason: 'policy_cache_unavailable' };
        }
      }, {
        ...options,
        lockTimeoutMs: options.lockTimeoutMs ?? PRIVATE_INIT_LOCK_TIMEOUT_MS,
        lockTimeoutMaximumMs: options.lockTimeoutMaximumMs ?? PRIVATE_INIT_LOCK_TIMEOUT_MS,
        fs: options.fs || fs,
        cleanupComponent: 'signed-policy-cache-lock',
      });
    }, {
      ...options,
      ...cacheSecurity(options, true),
      lockTimeoutMs: options.lockTimeoutMs ?? PRIVATE_INIT_LOCK_TIMEOUT_MS,
      lockTimeoutMaximumMs: options.lockTimeoutMaximumMs ?? PRIVATE_INIT_LOCK_TIMEOUT_MS,
      cleanupComponent: 'signed-policy-cache-directory-lock',
    });
    if (!result.ok) return result;
    persisted = result.persisted;
  } catch {
    return { ok: false, reason: 'policy_cache_unavailable' };
  }
  runtimeHighWater.set(key, bundle);
  return { ok: true, policy: bundle.policy, bundle, source: 'current', persisted };
}

function resetForTest() {
  runtimeHighWater.clear();
}

module.exports = {
  BUNDLE_VERSION,
  MAX_BUNDLE_BYTES,
  signingInput,
  resolvePinnedPublicKey,
  verifySignedPolicyBundle,
  readCachedSignedPolicy,
  acceptSignedPolicyBundle,
  configuredCachePath,
  _resetForTest: resetForTest,
  _internal: { readCacheBundle, cachedHighWater, sequenceCheck },
};
