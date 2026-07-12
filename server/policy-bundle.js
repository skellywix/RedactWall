'use strict';
/** Durable Ed25519 signing for versioned sensor policy bundles. */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { withFileMutationLockSync } = require('./file-mutation-lock');
const {
  assertPrivatePath,
  securePrivatePath,
  readBoundedRegularFile,
  publishFileExclusiveDurably,
  removeExactPublicationFile,
  withPrivateDirectoryMutationLockSync,
} = require('./private-path');

const BUNDLE_VERSION = 1;
const DEFAULT_TTL_MS = 15 * 60 * 1000;
const MAX_KEY_BYTES = 16 * 1024;
const PRIVATE_INIT_LOCK_TIMEOUT_MS = 60_000;
let cachedKeys = null;
let cachedKeyFile = '';

function dataDir(env = process.env) {
  const configured = env.REDACTWALL_DATA_DIR || env.PROMPTWALL_DATA_DIR || env.SENTINEL_DATA_DIR;
  if (configured) return path.resolve(configured);
  return String(env.NODE_ENV || '').trim().toLowerCase() === 'production'
    ? path.resolve('/data')
    : path.join(__dirname, '..', 'data');
}

function keyFile(options = {}) {
  return path.resolve(options.keyFile || path.join(dataDir(options.env), '.policy-bundle-key.pem'));
}

function privateSecurity(options, fsImpl, directory) {
  return {
    ...(options.privatePathSecurity || {}),
    fs: fsImpl,
    directory,
    label: 'policy signing key',
    ownerLabel: 'policy signing key',
  };
}

function readPrivateKey(file, fsImpl = fs, options = {}) {
  try {
    const security = privateSecurity(options, fsImpl, false);
    if (options.harden === true) securePrivatePath(file, security);
    else assertPrivatePath(file, security);
    const pem = readBoundedRegularFile(file, {
      ...security,
      maxBytes: MAX_KEY_BYTES,
    }).toString('utf8');
    const privateKey = crypto.createPrivateKey(pem);
    if (privateKey.asymmetricKeyType !== 'ed25519') throw new Error('policy signing key is not Ed25519');
    return { privateKey, publicKey: crypto.createPublicKey(privateKey) };
  } catch (error) {
    const wrapped = new Error('policy signing key is unreadable or corrupt');
    wrapped.code = 'POLICY_SIGNING_KEY_INVALID';
    wrapped.cause = error;
    throw wrapped;
  }
}

function createPrivateKeyExclusive(file, fsImpl = fs, options = {}) {
  const dir = path.dirname(file);

  const generated = crypto.generateKeyPairSync('ed25519');
  const pem = generated.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const temp = path.join(dir, `.${path.basename(file)}.${crypto.randomBytes(16).toString('hex')}.tmp`);
  let fd;
  let stagedIdentity;
  let sourceConsumed = false;
  let publishedKeys;
  try {
    fd = fsImpl.openSync(temp, 'wx', 0o600);
    fsImpl.writeFileSync(fd, pem);
    fsImpl.fsyncSync(fd);
    fsImpl.fchmodSync(fd, 0o600);
    fsImpl.closeSync(fd);
    fd = undefined;
    securePrivatePath(temp, privateSecurity(options, fsImpl, false));
    stagedIdentity = fsImpl.lstatSync(temp, { bigint: true });
    // Hard-link publication is atomic and refuses to replace a concurrently
    // published identity. The surrounding interprocess lock serializes normal
    // initializers; this exclusive publication is the final collision guard.
    publishFileExclusiveDurably(temp, file, {
      ...options,
      fs: fsImpl,
      consumeSource: true,
      verifyPublished(publishedFile) {
        publishedKeys = readPrivateKey(publishedFile, fsImpl, options);
      },
    });
    sourceConsumed = true;
  } finally {
    if (fd !== undefined) {
      if (!stagedIdentity) try { stagedIdentity = fsImpl.fstatSync(fd, { bigint: true }); } catch {}
      try { fsImpl.closeSync(fd); } catch {}
    }
    if (!sourceConsumed && stagedIdentity) {
      try { removeExactPublicationFile(temp, stagedIdentity, { ...options, fs: fsImpl }); } catch {}
    }
  }
  return publishedKeys;
}

function loadOrCreateKeypair(options = {}) {
  const file = keyFile(options);
  const fsImpl = options.fs || fs;
  return withPrivateDirectoryMutationLockSync(path.dirname(file), () => {
    return withFileMutationLockSync(file, () => {
      try {
        fsImpl.lstatSync(file);
        return readPrivateKey(file, fsImpl, { ...options, harden: true });
      } catch (error) {
        if (!error || error.code !== 'ENOENT') throw error;
      }
      try {
        return createPrivateKeyExclusive(file, fsImpl, options);
      } catch (error) {
        if (error && error.code === 'EEXIST') return readPrivateKey(file, fsImpl, { ...options, harden: true });
        const wrapped = new Error('policy signing key could not be persisted');
        wrapped.code = 'POLICY_SIGNING_KEY_UNAVAILABLE';
        wrapped.cause = error;
        throw wrapped;
      }
    }, {
      ...options,
      lockTimeoutMs: options.lockTimeoutMs ?? PRIVATE_INIT_LOCK_TIMEOUT_MS,
      lockTimeoutMaximumMs: options.lockTimeoutMaximumMs ?? PRIVATE_INIT_LOCK_TIMEOUT_MS,
      fs: fsImpl,
    });
  }, {
    ...options,
    ...privateSecurity(options, fsImpl, true),
    lockTimeoutMs: options.lockTimeoutMs ?? PRIVATE_INIT_LOCK_TIMEOUT_MS,
    lockTimeoutMaximumMs: options.lockTimeoutMaximumMs ?? PRIVATE_INIT_LOCK_TIMEOUT_MS,
  });
}

function keys(options = {}) {
  const file = keyFile(options);
  if (options.reload || !cachedKeys || cachedKeyFile !== file) {
    cachedKeys = loadOrCreateKeypair(options);
    cachedKeyFile = file;
  }
  return cachedKeys;
}

function publicKeyPem(options = {}) {
  return keys(options).publicKey.export({ type: 'spki', format: 'pem' }).toString();
}

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

function signingInput({ version, issuedAt, expiresAt, policy }, legacyLexical = false) {
  if (!policy || typeof policy !== 'object' || Array.isArray(policy)) throw new TypeError('policy must be an object');
  const policyHash = crypto.createHash('sha256').update(canonicalPolicyJson(policy, legacyLexical)).digest('hex');
  return JSON.stringify({ version, issuedAt, expiresAt, policyHash });
}

function legacySigningInput({ version, issuedAt, expiresAt, policy }) {
  const policyHash = crypto.createHash('sha256').update(JSON.stringify(policy)).digest('hex');
  return JSON.stringify({ version, issuedAt, expiresAt, policyHash });
}

function buildBundle(policy, { now = new Date().toISOString(), ttlMs = DEFAULT_TTL_MS, ...options } = {}) {
  const issuedAt = now;
  const expiresAt = new Date(Date.parse(now) + ttlMs).toISOString();
  // Chrome storage recursively orders object properties. Publish that same
  // canonical order so existing v1 clients verify both before and after
  // persistence while upgraded clients treat key order as semantic noise.
  const canonicalPolicy = JSON.parse(canonicalPolicyJson(policy));
  const header = { version: BUNDLE_VERSION, issuedAt, expiresAt, policy: canonicalPolicy };
  const signature = crypto.sign(null, Buffer.from(signingInput(header)), keys(options).privateKey).toString('base64');
  return { ...header, signature };
}

function verifyBundle(bundle, publicKeyPemStr, { now = new Date().toISOString() } = {}) {
  if (!bundle || typeof bundle !== 'object' || Array.isArray(bundle)) return { ok: false, reason: 'no_bundle' };
  if (bundle.version !== BUNDLE_VERSION) return { ok: false, reason: 'version_mismatch' };
  if (!bundle.policy || typeof bundle.policy !== 'object' || Array.isArray(bundle.policy)) return { ok: false, reason: 'malformed_bundle' };
  if (typeof bundle.signature !== 'string' || !/^[A-Za-z0-9+/]{86}==$/.test(bundle.signature)) return { ok: false, reason: 'no_signature' };
  let pub;
  try {
    pub = crypto.createPublicKey(publicKeyPemStr);
    if (pub.asymmetricKeyType !== 'ed25519') return { ok: false, reason: 'bad_public_key' };
  } catch { return { ok: false, reason: 'bad_public_key' }; }
  let inputs;
  try { inputs = [...new Set([signingInput(bundle), signingInput(bundle, true), legacySigningInput(bundle)])]; } catch { return { ok: false, reason: 'malformed_bundle' }; }
  let valid = false;
  try {
    const signature = Buffer.from(bundle.signature, 'base64');
    valid = inputs.some((input) => crypto.verify(null, Buffer.from(input), pub, signature));
  } catch { valid = false; }
  if (!valid) return { ok: false, reason: 'bad_signature' };
  const issued = Date.parse(bundle.issuedAt);
  const exp = Date.parse(bundle.expiresAt);
  const ref = Date.parse(now);
  if (![issued, exp, ref].every(Number.isFinite) || issued > ref + 5 * 60 * 1000 || exp <= issued || exp <= ref) {
    return { ok: false, reason: 'expired' };
  }
  return { ok: true };
}

function isFresh(bundle, now = new Date().toISOString()) {
  return !!bundle && Number.isFinite(Date.parse(bundle.expiresAt)) && Date.parse(bundle.expiresAt) > Date.parse(now);
}

function signingKeyStatus(options = {}) {
  try {
    const fsImpl = options.fs || fs;
    const pair = options.initialize === false
      ? readPrivateKey(keyFile(options), fsImpl, options)
      : keys({ ...options, reload: options.reload === true });
    const persisted = readPrivateKey(keyFile(options), fsImpl, options);
    const active = pair.publicKey.export({ type: 'spki', format: 'der' });
    const stored = persisted.publicKey.export({ type: 'spki', format: 'der' });
    if (!active.equals(stored)) throw new Error('policy signing key changed after initialization');
    return { ok: !!pair.privateKey, persistent: true };
  } catch (error) {
    return { ok: false, persistent: false, reason: error && error.code || 'POLICY_SIGNING_KEY_INVALID' };
  }
}

function resetForTest() {
  cachedKeys = null;
  cachedKeyFile = '';
}

module.exports = {
  buildBundle,
  verifyBundle,
  isFresh,
  publicKeyPem,
  signingInput,
  canonicalPolicyJson,
  signingKeyStatus,
  loadOrCreateKeypair,
  keyFile,
  dataDir,
  BUNDLE_VERSION,
  DEFAULT_TTL_MS,
  get KEY_FILE() { return keyFile(); },
  _resetForTest: resetForTest,
};
