'use strict';

/**
 * Durable authentication state for the audit chain.
 *
 * The database stores the append-only entries, while this private sidecar keeps
 * the HMAC key provenance and the last verified count/head outside the database.
 * A database writer can therefore neither recompute changed entries nor delete
 * a tail without access to the independent sidecar/key boundary.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const integrity = require('./audit-integrity');
const {
  acquireFileMutationLockSync,
  releaseFileMutationLock,
  withFileMutationLockSync,
} = require('./file-mutation-lock');
const {
  windowsPrincipal,
  assertPrivatePath,
  assertPrivatePathDacl,
  securePrivatePath,
  protectInheritedPrivateFile,
  withPrivateDirectoryMutationLockSync,
  readBoundedRegularFile,
  fsyncDirectory,
  publishFileDurably,
} = require('./private-path');

const LEGACY_STATE_VERSION = 1;
const STATE_VERSION = 2;
const SCOPED_STATE_VERSION = 3;
const PENDING_VERSION = 1;
const MAX_STATE_BYTES = 8 * 1024;
const MAX_CHECKPOINT_BYTES = 4 * 1024;
const MAX_PENDING_BYTES = 8 * 1024;
const TRANSACTION_LOCK_TIMEOUT_MS = 30_000;
const INITIALIZATION_LOCK_TIMEOUT_MS = 60_000;

function sidecarSecurity(options, directory, label) {
  return {
    ...(options.privatePathSecurity || {}),
    fs: options.fs || fs,
    directory,
    label,
    ownerLabel: label,
  };
}

function resolvedAuditOptions(input) {
  const security = input.privatePathSecurity || {};
  const platform = security.platform || input.platform || process.platform;
  if (platform !== 'win32' || security.principal) return input;
  return {
    ...input,
    privatePathSecurity: {
      ...security,
      principal: windowsPrincipal(security.spawn, 'audit integrity sidecar'),
    },
  };
}

function ensurePrivateDirectory(directory, options = {}) {
  const fsImpl = options.fs || fs;
  fsImpl.mkdirSync(directory, { recursive: true, mode: 0o700 });
  securePrivatePath(directory, sidecarSecurity(options, true, 'audit integrity directory'));
  return directory;
}

function sidecarPlatform(options = {}) {
  return options.privatePathSecurity?.platform || options.platform || process.platform;
}

function requirePrivateDirectory(directory, options = {}) {
  if (sidecarPlatform(options) !== 'win32') return ensurePrivateDirectory(directory, options);
  assertPrivatePath(directory, sidecarSecurity(options, true, 'audit integrity directory'));
  return directory;
}

function withPreparedAuditDirectories(directories, callback, options = {}) {
  const byLockIdentity = new Map();
  for (const directory of directories) {
    const resolved = path.resolve(directory);
    const identity = sidecarPlatform(options) === 'win32' ? resolved.toLowerCase() : resolved;
    if (!byLockIdentity.has(identity)) byLockIdentity.set(identity, resolved);
  }
  const unique = [...byLockIdentity.entries()]
    .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
    .map(([, resolved]) => resolved);
  if (sidecarPlatform(options) !== 'win32') {
    for (const directory of unique) ensurePrivateDirectory(directory, options);
    return callback();
  }
  const lockTimeoutMs = options.initializationLockTimeoutMs
    ?? options.lockTimeoutMs
    ?? INITIALIZATION_LOCK_TIMEOUT_MS;
  function prepare(index) {
    if (index === unique.length) return callback();
    return withPrivateDirectoryMutationLockSync(unique[index], () => prepare(index + 1), {
      ...sidecarSecurity(options, true, 'audit integrity directory'),
      lockTimeoutMs,
      lockTimeoutMaximumMs: INITIALIZATION_LOCK_TIMEOUT_MS,
    });
  }
  return prepare(0);
}

function privateFileIdentity(fsImpl, file) {
  const stat = fsImpl.lstatSync(file, { bigint: true });
  if (String(stat.dev) === '0' || String(stat.ino) === '0') {
    throw new Error('audit integrity sidecar has no stable filesystem identity');
  }
  return stat;
}

function privateBirthtime(stat) {
  return stat.birthtimeNs ?? stat.birthtimeMs;
}

function samePrivateFileIdentity(left, right, platform = process.platform) {
  return String(left.dev) === String(right.dev)
    && String(left.ino) === String(right.ino)
    // NTFS preserves the replaced destination's creation timestamp even though
    // rename installs the source file ID. Device + file ID are the stable
    // handle identity on Windows; requiring birthtime rejects every atomic
    // overwrite after the first publication.
    && (platform === 'win32' || String(privateBirthtime(left)) === String(privateBirthtime(right)))
    && String(left.size) === String(right.size)
    && String(left.nlink) === '1'
    && String(right.nlink) === '1';
}

function privateDirectoryIdentity(fsImpl, directory, platform = process.platform) {
  const stat = fsImpl.lstatSync(directory, { bigint: true });
  const dev = String(stat.dev);
  const ino = String(stat.ino);
  const birthtime = String(privateBirthtime(stat));
  if (!stat.isDirectory() || stat.isSymbolicLink() || dev === '0' || ino === '0'
      || (platform === 'win32' && (birthtime === '0' || birthtime === 'undefined'))) {
    throw new Error('audit integrity directory has no stable filesystem identity');
  }
  return { dev, ino, birthtime };
}

function samePrivateDirectoryIdentity(left, right) {
  return !!left && !!right && left.dev === right.dev && left.ino === right.ino
    && left.birthtime === right.birthtime;
}

function writePrivateJsonInternal(file, value, options, trustedDirectory) {
  const fsImpl = options.fs || fs;
  const directory = trustedDirectory
    ? path.dirname(file)
    : requirePrivateDirectory(path.dirname(file), options);
  const verifyTrustedDirectory = trustedDirectory && typeof options.verifyTrustedDirectory === 'function'
    ? options.verifyTrustedDirectory
    : null;
  const temp = path.join(directory, `.${path.basename(file)}.${process.pid}.${crypto.randomBytes(12).toString('hex')}.tmp`);
  let fd;
  let publicationStarted = false;
  try {
    if (verifyTrustedDirectory) verifyTrustedDirectory(directory);
    fd = fsImpl.openSync(temp, 'wx', 0o600);
    fsImpl.writeFileSync(fd, JSON.stringify(value), 'utf8');
    fsImpl.fsyncSync(fd);
    fsImpl.fchmodSync(fd, 0o600);
    fsImpl.closeSync(fd);
    fd = undefined;
    if (trustedDirectory) {
      protectInheritedPrivateFile(temp, {
        ...sidecarSecurity(options, false, 'audit integrity sidecar'),
        verifyOwner: false,
      });
    } else {
      // Bootstrap and backup paths have not yet retained a trusted-parent
      // proof. Keep the complete owner plus reset/grant hardening contract.
      securePrivatePath(temp, sidecarSecurity(options, false, 'audit integrity sidecar'));
    }
    if (verifyTrustedDirectory) verifyTrustedDirectory(directory);
    const before = privateFileIdentity(fsImpl, temp);
    publicationStarted = true;
    publishFileDurably(temp, file, {
      ...options,
      fs: fsImpl,
      cleanupComponent: 'audit-sidecar-publication',
      verifyPublished(published) {
        const after = privateFileIdentity(fsImpl, published);
        if (!samePrivateFileIdentity(before, after, sidecarPlatform(options))) {
          throw new Error('audit integrity sidecar changed during publication');
        }
        if (verifyTrustedDirectory) verifyTrustedDirectory(directory);
        if (trustedDirectory && typeof options.verifyTrustedPublication === 'function') {
          options.verifyTrustedPublication();
        }
        if (!trustedDirectory) {
          securePrivatePath(published, sidecarSecurity(options, false, 'audit integrity sidecar'));
        }
      },
    });
    return file;
  } finally {
    if (fd !== undefined) { try { fsImpl.closeSync(fd); } catch {} }
    if (!publicationStarted) try { fsImpl.unlinkSync(temp); } catch {}
  }
}

function writePrivateJson(file, value, options = {}) {
  return writePrivateJsonInternal(file, value, options, false);
}

function sameDeviceAndFile(left, right) {
  return String(left.dev) === String(right.dev) && String(left.ino) === String(right.ino);
}

function quarantineFailedNewPrivateJson(file, stagedIdentity, options, originalError) {
  const fsImpl = options.fs || fs;
  const directory = path.dirname(file);
  const quarantine = path.join(
    directory,
    `.${path.basename(file)}.failed-new-state-${process.pid}-${crypto.randomBytes(12).toString('hex')}`,
  );
  try {
    fsImpl.renameSync(file, quarantine);
  } catch (error) {
    if (error && error.code === 'ENOENT') return;
    throw new Error('audit state publication failed; refusing unsafe cleanup', { cause: originalError || error });
  }
  let quarantined;
  try {
    quarantined = privateFileIdentity(fsImpl, quarantine);
  } catch (error) {
    throw new Error(`audit state publication failed; unverifiable quarantine retained at ${quarantine}`, {
      cause: originalError || error,
    });
  }
  if (!sameDeviceAndFile(stagedIdentity, quarantined)
      || String(stagedIdentity.size) !== String(quarantined.size)) {
    throw new Error(`audit state publication failed; changed replacement retained at ${quarantine}`, {
      cause: originalError,
    });
  }
  try {
    fsImpl.unlinkSync(quarantine);
  } catch (error) {
    throw new Error(`audit state publication failed; exact quarantine retained at ${quarantine}`, {
      cause: originalError || error,
    });
  }
  fsyncDirectory(directory, { ...options, fs: fsImpl });
}

function writeNewPrivateJson(file, value, options = {}) {
  const fsImpl = options.fs || fs;
  const directory = requirePrivateDirectory(path.dirname(file), options);
  const temp = path.join(
    directory,
    `.${path.basename(file)}.${process.pid}.${crypto.randomBytes(12).toString('hex')}.new`,
  );
  let fd;
  let linked = false;
  let stagedIdentity;
  try {
    fd = fsImpl.openSync(temp, 'wx', 0o600);
    fsImpl.writeFileSync(fd, JSON.stringify(value), 'utf8');
    fsImpl.fsyncSync(fd);
    fsImpl.fchmodSync(fd, 0o600);
    fsImpl.closeSync(fd);
    fd = undefined;
    securePrivatePath(temp, sidecarSecurity(options, false, 'audit integrity sidecar'));
    stagedIdentity = privateFileIdentity(fsImpl, temp);
    try {
      fsImpl.linkSync(temp, file);
      linked = true;
    } catch (error) {
      if (error && error.code === 'EEXIST') return false;
      throw error;
    }
    const publishedIdentity = privateFileIdentity(fsImpl, file);
    if (!sameDeviceAndFile(stagedIdentity, publishedIdentity)
        || String(stagedIdentity.size) !== String(publishedIdentity.size)) {
      throw new Error('audit integrity sidecar changed during exclusive publication');
    }
    fsImpl.unlinkSync(temp);
    securePrivatePath(file, sidecarSecurity(options, false, 'audit integrity sidecar'));
    fsyncDirectory(directory, { ...options, fs: fsImpl });
    const settledIdentity = privateFileIdentity(fsImpl, file);
    if (!samePrivateFileIdentity(stagedIdentity, settledIdentity, sidecarPlatform(options))) {
      throw new Error('audit integrity sidecar changed during exclusive publication');
    }
    return true;
  } catch (error) {
    if (linked) {
      quarantineFailedNewPrivateJson(file, stagedIdentity, options, error);
    }
    throw error;
  } finally {
    if (fd !== undefined) { try { fsImpl.closeSync(fd); } catch {} }
    try { fsImpl.unlinkSync(temp); } catch {}
  }
}

function writeTrustedPrivateJson(file, value, options = {}) {
  return writePrivateJsonInternal(file, value, options, true);
}

function parsePrivateJson(file, maxBytes, options) {
  const value = JSON.parse(readBoundedRegularFile(file, {
    ...sidecarSecurity(options, false, 'audit integrity sidecar'),
    maxBytes,
  }).toString('utf8'));
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('audit integrity sidecar is malformed');
  return value;
}

function readPrivateJson(file, maxBytes, options = {}) {
  assertPrivatePath(file, sidecarSecurity(options, false, 'audit integrity sidecar'));
  return parsePrivateJson(file, maxBytes, options);
}

function readTrustedPrivateJson(file, maxBytes, options = {}) {
  const verifyTrustedDirectory = typeof options.verifyTrustedDirectory === 'function'
    ? options.verifyTrustedDirectory
    : null;
  const directory = path.dirname(file);
  if (verifyTrustedDirectory) verifyTrustedDirectory(directory);
  try {
    return parsePrivateJson(file, maxBytes, options);
  } finally {
    if (verifyTrustedDirectory) verifyTrustedDirectory(directory);
  }
}

function configuredKey(env = process.env) {
  const source = String(env.REDACTWALL_AUDIT_KEY || env.REDACTWALL_SECRET || '');
  if (!source) return null;
  return crypto.createHash('sha256').update(`redactwall:audit-auth:v1:${source}`).digest();
}

function keyId(key) {
  return crypto.createHash('sha256').update(key).digest('hex');
}

function validDatabaseScope(value) {
  return /^[a-f0-9]{64}$/.test(String(value || ''));
}

function stateBody(key, checkpointCreated, embedded, pendingProtocol = true, databaseScope = null) {
  if (databaseScope) {
    if (!validDatabaseScope(databaseScope)) throw new TypeError('audit database scope is invalid');
    return {
      version: SCOPED_STATE_VERSION,
      keyId: keyId(key),
      checkpointCreated: checkpointCreated === true,
      pendingProtocol: pendingProtocol === true,
      databaseScope,
      ...(embedded ? { key: key.toString('base64') } : {}),
    };
  }
  if (pendingProtocol !== true) {
    return {
      version: LEGACY_STATE_VERSION,
      keyId: keyId(key),
      checkpointCreated: checkpointCreated === true,
      ...(embedded ? { key: key.toString('base64') } : {}),
    };
  }
  return {
    version: STATE_VERSION,
    keyId: keyId(key),
    checkpointCreated: checkpointCreated === true,
    pendingProtocol: true,
    ...(embedded ? { key: key.toString('base64') } : {}),
  };
}

function signedState(key, checkpointCreated, embedded, pendingProtocol = true, databaseScope = null) {
  const body = stateBody(key, checkpointCreated, embedded, pendingProtocol, databaseScope);
  return { ...body, mac: integrity.hmac(key, integrity.canonical(body)) };
}

function loadState(file, externalKey, options = {}, trustedDirectory = false) {
  const read = trustedDirectory ? readTrustedPrivateJson : readPrivateJson;
  const raw = read(file, MAX_STATE_BYTES, options);
  const embedded = typeof raw.key === 'string' && raw.key.length > 0;
  const key = externalKey || (embedded ? Buffer.from(raw.key, 'base64') : null);
  if (!key || key.length < 32) throw new Error('audit authentication key is unavailable');
  const scoped = raw.version === SCOPED_STATE_VERSION;
  const databaseScope = scoped && validDatabaseScope(raw.databaseScope) ? raw.databaseScope : null;
  const pendingProtocol = (raw.version === STATE_VERSION || scoped) && raw.pendingProtocol === true;
  if ((!pendingProtocol && raw.version !== LEGACY_STATE_VERSION && !scoped)
      || (scoped && !databaseScope)) {
    throw new Error('audit integrity state version is unsupported');
  }
  const expected = signedState(
    key,
    raw.checkpointCreated === true,
    embedded,
    pendingProtocol,
    databaseScope,
  );
  if (raw.version !== expected.version || raw.keyId !== expected.keyId || raw.key !== expected.key
      || raw.checkpointCreated !== expected.checkpointCreated
      || raw.pendingProtocol !== expected.pendingProtocol
      || raw.databaseScope !== expected.databaseScope || raw.mac !== expected.mac) {
    throw new Error('audit integrity state authentication failed');
  }
  if (externalKey && embedded) throw new Error('audit integrity state key source changed');
  return {
    key,
    embedded,
    checkpointCreated: raw.checkpointCreated === true,
    pendingProtocol,
    databaseScope,
  };
}

function createState(file, externalKey, options = {}) {
  const key = externalKey || crypto.randomBytes(32);
  const embedded = !externalKey;
  const databaseScope = options.databaseScope || null;
  // A missing state is allowed only before migration 8, when the database may
  // already contain a valid legacy hash chain without per-row MACs. Persist the
  // v1 bootstrap marker until that exact tail verifies and its checkpoint is
  // durable; markCheckpointProtocolUnlocked then irreversibly enables v2.
  const created = writeNewPrivateJson(
    file,
    signedState(key, false, embedded, false, databaseScope),
    options,
  );
  if (!created) return loadState(file, externalKey, options);
  return { key, embedded, checkpointCreated: false, pendingProtocol: false, databaseScope };
}

function pendingBody(checkpoint, entryId) {
  if (!checkpoint || !Number.isSafeInteger(checkpoint.count) || checkpoint.count <= 0
      || !Number.isSafeInteger(checkpoint.seq) || checkpoint.seq <= 0
      || !/^[a-f0-9]{64}$/i.test(String(checkpoint.head || ''))
      || typeof entryId !== 'string' || !entryId || entryId.length > 256
      || /[\u0000-\u001f\u007f]/.test(entryId)) {
    throw new TypeError('audit pending high-water is invalid');
  }
  return {
    version: PENDING_VERSION,
    count: checkpoint.count,
    seq: checkpoint.seq,
    head: checkpoint.head.toLowerCase(),
    entryId,
  };
}

function signedPending(checkpoint, entryId, key) {
  const body = pendingBody(checkpoint, entryId);
  return {
    ...body,
    mac: integrity.hmac(key, integrity.canonical({ domain: 'redactwall:audit-pending:v1', ...body })),
  };
}

function validPending(pending, key) {
  try {
    const body = pendingBody(pending, pending.entryId);
    if (pending.version !== PENDING_VERSION || typeof pending.mac !== 'string') return false;
    return crypto.timingSafeEqual(
      Buffer.from(pending.mac, 'hex'),
      Buffer.from(integrity.hmac(key, integrity.canonical({ domain: 'redactwall:audit-pending:v1', ...body })), 'hex'),
    );
  } catch {
    return false;
  }
}

function sameCheckpoint(left, right) {
  return !!left && left.version === right.version && left.count === right.count
    && left.seq === right.seq && left.head === right.head && left.mac === right.mac;
}

function openAuditAnchor(inputOptions = {}) {
  const options = resolvedAuditOptions(inputOptions);
  const env = options.env || process.env;
  const databaseScope = options.databaseScope || null;
  if (databaseScope && !validDatabaseScope(databaseScope)) {
    throw new TypeError('audit database scope is invalid');
  }
  const directory = path.resolve(options.directory);
  const statePath = path.resolve(options.statePath || path.join(directory, '.audit-integrity-state.json'));
  const scopeClaimPath = `${statePath}.database-scope-claim`;
  const checkpointPath = path.resolve(options.checkpointPath || path.join(directory, '.audit-integrity-checkpoint.json'));
  const pendingPath = path.resolve(options.pendingPath || path.join(directory, '.audit-integrity-pending.json'));
  const fsImpl = options.fs || fs;
  const externalKey = configuredKey(env);
  const externalCoordination = typeof options.withCoordinationLock === 'function';
  const sidecarDirectories = [...new Map([
    directory,
    path.dirname(statePath),
    path.dirname(scopeClaimPath),
    path.dirname(checkpointPath),
    path.dirname(pendingPath),
  ].map((item) => {
    const resolved = path.resolve(item);
    const identity = sidecarPlatform(options) === 'win32' ? resolved.toLowerCase() : resolved;
    return [identity, resolved];
  })).values()];

  let state;
  let initialization;
  let legacyBootstrapAuthorized = false;

  function loadDatabaseScopeClaim() {
    try {
      return loadState(scopeClaimPath, externalKey, options);
    } catch (error) {
      if (error && error.code === 'ENOENT') return null;
      throw error;
    }
  }

  function claimDatabaseScope() {
    const claim = signedState(
      state.key,
      state.checkpointCreated,
      state.embedded,
      state.pendingProtocol,
      databaseScope,
    );
    writeNewPrivateJson(scopeClaimPath, claim, options);
    const durable = loadDatabaseScopeClaim();
    if (!durable || durable.databaseScope !== databaseScope) {
      throw new Error('audit integrity state database scope mismatch');
    }
  }

  function bootstrapLegacyDatabase(database) {
    let checkpoint = null;
    try {
      checkpoint = readPrivateJson(checkpointPath, MAX_CHECKPOINT_BYTES, options);
    } catch (error) {
      if (!error || error.code !== 'ENOENT') throw error;
    }
    if (!checkpoint && !legacyBootstrapAuthorized) {
      throw new Error('legacy audit bootstrap failed (checkpoint-missing)');
    }
    let verifiedCheckpoint;
    const result = integrity.verifyAuditChainForDatabase(database, {
      key: state.key,
      checkpoint,
      allowCheckpointBootstrap: !checkpoint && legacyBootstrapAuthorized,
      onVerified(next) { verifiedCheckpoint = next; },
    });
    if (!result.ok || !verifiedCheckpoint) {
      throw new Error(`legacy audit bootstrap failed (${result.reason || 'chain'})`);
    }
    if (!sameCheckpoint(checkpoint, verifiedCheckpoint)) {
      writePrivateJson(checkpointPath, verifiedCheckpoint, options);
    }
    writePrivateJson(
      statePath,
      signedState(state.key, true, state.embedded, true, state.databaseScope),
      options,
    );
    state = { ...state, checkpointCreated: true, pendingProtocol: true };
    return result;
  }

  function bindDatabaseScope(database) {
    if (!databaseScope) return;
    const existingClaim = loadDatabaseScopeClaim();
    if (existingClaim && existingClaim.databaseScope !== databaseScope) {
      throw new Error('audit integrity state database scope mismatch');
    }
    if (state.databaseScope === databaseScope) return;
    if (state.databaseScope) throw new Error('audit integrity state database scope mismatch');
    let checkpoint = null;
    try {
      checkpoint = readPrivateJson(checkpointPath, MAX_CHECKPOINT_BYTES, options);
    } catch (error) {
      if (!error || error.code !== 'ENOENT') throw error;
    }
    const result = integrity.verifyAuditChainForDatabase(database, {
      key: state.key,
      checkpoint,
      allowCheckpointBootstrap: false,
    });
    if (!result.ok) {
      throw new Error(`audit database scope binding failed (${result.reason || 'chain'})`);
    }
    claimDatabaseScope();
    writePrivateJson(
      statePath,
      signedState(
        state.key,
        state.checkpointCreated,
        state.embedded,
        state.pendingProtocol,
        databaseScope,
      ),
      options,
    );
    state = { ...state, databaseScope };
  }

  const initializeAnchor = () => withPreparedAuditDirectories([
    directory,
    path.dirname(statePath),
    path.dirname(scopeClaimPath),
    path.dirname(checkpointPath),
    path.dirname(pendingPath),
  ], () => {
    const initializeUnlocked = () => {
      const bootstrapAllowed = typeof options.allowBootstrap === 'function'
        ? options.allowBootstrap() === true
        : options.allowBootstrap === true;
      try {
        state = loadState(statePath, externalKey, options);
      } catch (error) {
        if (!error || error.code !== 'ENOENT') throw error;
        if (!bootstrapAllowed) throw new Error('audit integrity state is missing after initialization');
        state = createState(statePath, externalKey, options);
      }
      if (databaseScope && state.databaseScope && state.databaseScope !== databaseScope) {
        throw new Error('audit integrity state database scope mismatch');
      }
      // Only a protocol-v1 state that has never claimed a checkpoint can
      // authorize the one-time unsigned legacy-tail bootstrap. A v2 state
      // implies that a checkpoint already existed, even if migration 8 was
      // not durably recorded, so a missing checkpoint must fail closed.
      legacyBootstrapAuthorized = bootstrapAllowed
        && state.checkpointCreated === false
        && state.pendingProtocol === false;
      if (typeof options.initialize === 'function') {
        initialization = options.initialize({ bootstrapLegacyDatabase, bindDatabaseScope });
      }
      if (databaseScope && state.databaseScope !== databaseScope) {
        throw new Error('audit database scope binding was not completed');
      }
    };
    if (externalCoordination) return initializeUnlocked();
    return withFileMutationLockSync(checkpointPath, initializeUnlocked, {
      ...options,
      fs: fsImpl,
      lockTimeoutMs: options.initializationLockTimeoutMs
        ?? options.lockTimeoutMs
        ?? INITIALIZATION_LOCK_TIMEOUT_MS,
      lockTimeoutMaximumMs: INITIALIZATION_LOCK_TIMEOUT_MS,
    });
  }, options);
  if (externalCoordination) {
    options.withCoordinationLock(initializeAnchor, { timeoutMs: INITIALIZATION_LOCK_TIMEOUT_MS });
  }
  else initializeAnchor();

  // Carry the full startup owner+DACL proof through steady-state operations by
  // binding every sidecar directory to its nonzero filesystem identity. A
  // parent-level rename can make the original directory unavailable, but it
  // cannot substitute a foreign directory without tripping these checks.
  const sidecarDirectoryProofs = new Map();
  for (const sidecarDirectory of sidecarDirectories) {
    const before = privateDirectoryIdentity(fsImpl, sidecarDirectory, sidecarPlatform(options));
    assertPrivatePath(
      sidecarDirectory,
      sidecarSecurity(options, true, 'audit integrity directory'),
    );
    const after = privateDirectoryIdentity(fsImpl, sidecarDirectory, sidecarPlatform(options));
    if (!samePrivateDirectoryIdentity(before, after)) {
      throw new Error('audit integrity directory changed during startup verification');
    }
    sidecarDirectoryProofs.set(sidecarDirectory, after);
  }

  let lastError = null;
  // A failed sidecar publication happens after the database transaction that
  // produced this authenticated tail has committed. Keep that exact high-water
  // mark in memory until it is durably published. Otherwise a repair against
  // the older on-disk checkpoint could silently accept truncation of the row
  // whose publication failed.
  let requiredCheckpoint = null;
  let preparedTransaction = null;
  let scheduled = false;
  let initialVerificationPending = true;

  function sidecarDirectoryProof(directory) {
    const resolved = path.resolve(directory);
    const identity = sidecarPlatform(options) === 'win32' ? resolved.toLowerCase() : resolved;
    for (const [sidecarDirectory, proof] of sidecarDirectoryProofs) {
      const candidate = sidecarPlatform(options) === 'win32'
        ? sidecarDirectory.toLowerCase()
        : sidecarDirectory;
      if (candidate === identity) return { directory: sidecarDirectory, proof };
    }
    throw new Error('audit integrity sidecar escaped its verified directory');
  }

  function assertBoundSidecarDirectoryUnlocked(directory) {
    const bound = sidecarDirectoryProof(directory);
    const current = privateDirectoryIdentity(fsImpl, bound.directory, sidecarPlatform(options));
    if (!samePrivateDirectoryIdentity(bound.proof, current)) {
      throw new Error('audit integrity directory identity changed');
    }
    return bound.directory;
  }

  function trustedSidecarOptions() {
    return {
      ...options,
      verifyTrustedDirectory: assertBoundSidecarDirectoryUnlocked,
      verifyTrustedPublication: assertBoundSidecarDirectoriesUnlocked,
    };
  }

  function reloadTrustedStateUnlocked() {
    const candidate = loadState(statePath, externalKey, trustedSidecarOptions(), true);
    const sameKey = Buffer.isBuffer(state.key) && Buffer.isBuffer(candidate.key)
      && state.key.length === candidate.key.length
      && crypto.timingSafeEqual(state.key, candidate.key);
    if (!sameKey || candidate.embedded !== state.embedded
        || candidate.checkpointCreated !== state.checkpointCreated
        || candidate.pendingProtocol !== state.pendingProtocol
        || candidate.databaseScope !== state.databaseScope) {
      const error = new Error('audit integrity state continuity failed');
      error.code = 'REDACTWALL_AUDIT_STATE_CONTINUITY';
      throw error;
    }
    state = candidate;
    return state;
  }

  function assertTrustedSidecarDirectoriesUnlocked() {
    for (const sidecarDirectory of sidecarDirectories) {
      assertBoundSidecarDirectoryUnlocked(sidecarDirectory);
      assertPrivatePathDacl(
        sidecarDirectory,
        sidecarSecurity(options, true, 'audit integrity directory'),
      );
      assertBoundSidecarDirectoryUnlocked(sidecarDirectory);
    }
  }

  function assertBoundSidecarDirectoriesUnlocked() {
    for (const sidecarDirectory of sidecarDirectories) {
      assertBoundSidecarDirectoryUnlocked(sidecarDirectory);
    }
  }

  function loadCheckpointUnlocked(trustedDirectory = false) {
    try {
      return trustedDirectory
        ? readTrustedPrivateJson(checkpointPath, MAX_CHECKPOINT_BYTES, trustedSidecarOptions())
        : readPrivateJson(checkpointPath, MAX_CHECKPOINT_BYTES, options);
    } catch (error) {
      if (error && error.code === 'ENOENT') return null;
      throw error;
    }
  }

  function loadPendingUnlocked(trustedDirectory = false) {
    let pending;
    try {
      pending = trustedDirectory
        ? readTrustedPrivateJson(pendingPath, MAX_PENDING_BYTES, trustedSidecarOptions())
        : readPrivateJson(pendingPath, MAX_PENDING_BYTES, options);
    } catch (error) {
      if (error && error.code === 'ENOENT') return null;
      throw error;
    }
    if (!validPending(pending, state.key)) {
      const error = new Error('audit pending high-water authentication failed');
      error.code = 'REDACTWALL_AUDIT_PENDING_AUTHENTICATION';
      throw error;
    }
    return pending;
  }

  function removePendingUnlocked(trustedDirectory = false) {
    if (!trustedDirectory) {
      assertPrivatePath(pendingPath, sidecarSecurity(options, false, 'audit integrity sidecar'));
    } else {
      assertBoundSidecarDirectoryUnlocked(path.dirname(pendingPath));
    }
    try {
      fsImpl.unlinkSync(pendingPath);
    } catch (error) {
      if (error && error.code === 'ENOENT') return;
      throw error;
    }
    fsyncDirectory(path.dirname(pendingPath), { ...options, fs: fsImpl });
    if (trustedDirectory) assertBoundSidecarDirectoryUnlocked(path.dirname(pendingPath));
  }

  function databaseCount(database) {
    const count = Number(database.prepare('SELECT COUNT(*) n FROM audit').get().n);
    return Number.isSafeInteger(count) && count >= 0 ? count : 0;
  }

  function exactHighWaterFailureUnlocked(database, highWater, entryId) {
    if (!highWater || highWater.count === 0) return null;
    const count = databaseCount(database);
    if (count < highWater.count) {
      return { ok: false, count, reason: 'checkpoint-truncated' };
    }
    const row = database.prepare('SELECT seq, entry FROM audit WHERE seq = ?').get(highWater.seq);
    let entry;
    try { entry = row && JSON.parse(row.entry); } catch { entry = null; }
    if (!row || Number(row.seq) !== highWater.seq || !entry
        || (entryId && entry.id !== entryId)
        || entry.hash !== highWater.head
        || !integrity.validAuthenticatedEntry(entry, state.key)) {
      return { ok: false, count, reason: 'checkpoint-truncated' };
    }
    return null;
  }

  function requiredTailFailureUnlocked(database) {
    return exactHighWaterFailureUnlocked(database, requiredCheckpoint, '');
  }

  function pendingTailFailureUnlocked(database, pending) {
    return exactHighWaterFailureUnlocked(database, pending, pending && pending.entryId);
  }

  function rememberRequiredCheckpoint(checkpoint) {
    if (!requiredCheckpoint || checkpoint.count >= requiredCheckpoint.count) {
      requiredCheckpoint = checkpoint;
    }
  }

  function settleRequiredCheckpoint(published) {
    if (requiredCheckpoint && published
        && published.count >= requiredCheckpoint.count
        && published.seq >= requiredCheckpoint.seq) {
      requiredCheckpoint = null;
    }
  }

  function publishCheckpointUnlocked(current, next, trustedDirectory = false) {
    if (sameCheckpoint(current, next)) {
      settleRequiredCheckpoint(current);
      return;
    }
    rememberRequiredCheckpoint(next);
    const write = trustedDirectory ? writeTrustedPrivateJson : writePrivateJson;
    write(checkpointPath, next, trustedDirectory ? trustedSidecarOptions() : options);
    settleRequiredCheckpoint(next);
  }

  function markCheckpointProtocolUnlocked(trustedDirectory = false) {
    if (state.checkpointCreated && state.pendingProtocol) return;
    const write = trustedDirectory ? writeTrustedPrivateJson : writePrivateJson;
    write(
      statePath,
      signedState(state.key, true, state.embedded, true, state.databaseScope),
      trustedDirectory ? trustedSidecarOptions() : options,
    );
    state = { ...state, checkpointCreated: true, pendingProtocol: true };
  }

  function missingPendingFailureUnlocked(database, checkpoint, pending) {
    if (pending || !state.pendingProtocol) return null;
    const count = databaseCount(database);
    const durableCount = checkpoint && Number.isSafeInteger(checkpoint.count) ? checkpoint.count : 0;
    if (count > durableCount) return { ok: false, count, reason: 'pending-missing' };
    return null;
  }

  function checkpointAuthenticationFailureUnlocked(database, checkpoint) {
    if (!checkpoint || integrity.validCheckpoint(checkpoint, state.key)) return null;
    return { ok: false, count: databaseCount(database), reason: 'checkpoint-authentication' };
  }

  function clearPendingIfCoveredUnlocked(pending, checkpoint, trustedDirectory = false) {
    if (!pending || !checkpoint) return;
    if (checkpoint.count < pending.count || checkpoint.seq < pending.seq) return;
    removePendingUnlocked(trustedDirectory);
  }

  function fullVerifyUnlocked(
    database,
    checkpoint,
    pending = loadPendingUnlocked(),
    trustedDirectory = false,
  ) {
    if (!checkpoint && state.checkpointCreated) {
      return { ok: false, count: database.prepare('SELECT COUNT(*) n FROM audit').get().n, reason: 'checkpoint-missing' };
    }
    const checkpointFailure = checkpointAuthenticationFailureUnlocked(database, checkpoint);
    if (checkpointFailure) return checkpointFailure;
    const pendingFailure = pendingTailFailureUnlocked(database, pending);
    if (pendingFailure) return pendingFailure;
    const missingPending = missingPendingFailureUnlocked(database, checkpoint, pending);
    if (missingPending) return missingPending;
    const requiredFailure = requiredTailFailureUnlocked(database);
    if (requiredFailure) return requiredFailure;
    let verifiedCheckpoint;
    const result = integrity.verifyAuditChainForDatabase(database, {
      key: state.key,
      checkpoint,
      allowCheckpointBootstrap: !checkpoint && !state.checkpointCreated && legacyBootstrapAuthorized,
      onVerified(next) { verifiedCheckpoint = next; },
    });
    if (!result.ok) return result;
    publishCheckpointUnlocked(checkpoint, verifiedCheckpoint, trustedDirectory);
    clearPendingIfCoveredUnlocked(pending, verifiedCheckpoint, trustedDirectory);
    markCheckpointProtocolUnlocked(trustedDirectory);
    if (trustedDirectory) assertBoundSidecarDirectoriesUnlocked();
    return result;
  }

  function withAnchorCoordination(callback, fileLockOptions = {}) {
    if (externalCoordination) {
      const timeoutMs = fileLockOptions.timeoutMs ?? fileLockOptions.lockTimeoutMs;
      return options.withCoordinationLock(callback, {
        ...fileLockOptions,
        ...(timeoutMs == null ? {} : { timeoutMs }),
      });
    }
    return withFileMutationLockSync(checkpointPath, callback, {
      ...options,
      ...fileLockOptions,
      fs: fsImpl,
    });
  }

  function verifyDatabase(database) {
    const firstVerification = initialVerificationPending;
    initialVerificationPending = false;
    try {
      const result = withAnchorCoordination(() => {
        assertBoundSidecarDirectoriesUnlocked();
        reloadTrustedStateUnlocked();
        const verified = fullVerifyUnlocked(
          database,
          loadCheckpointUnlocked(true),
          loadPendingUnlocked(true),
          false,
        );
        assertBoundSidecarDirectoriesUnlocked();
        return verified;
      }, {
        ...(firstVerification ? {
          lockTimeoutMs: options.initializationLockTimeoutMs
            ?? options.lockTimeoutMs
            ?? INITIALIZATION_LOCK_TIMEOUT_MS,
          lockTimeoutMaximumMs: INITIALIZATION_LOCK_TIMEOUT_MS,
        } : {}),
      });
      lastError = result.ok ? null : result;
      return result;
    } catch (error) {
      lastError = error;
      return { ok: false, count: 0, reason: 'checkpoint-unavailable' };
    }
  }

  function advanceCheckpoint(database) {
    try {
      const result = withAnchorCoordination(() => {
        assertTrustedSidecarDirectoriesUnlocked();
        reloadTrustedStateUnlocked();
        const checkpoint = loadCheckpointUnlocked(true);
        const pending = loadPendingUnlocked(true);
        const checkpointFailure = checkpointAuthenticationFailureUnlocked(database, checkpoint);
        if (checkpointFailure) return checkpointFailure;
        const pendingFailure = pendingTailFailureUnlocked(database, pending);
        if (pendingFailure) return pendingFailure;
        const missingPending = missingPendingFailureUnlocked(database, checkpoint, pending);
        if (missingPending) return missingPending;
        const requiredFailure = requiredTailFailureUnlocked(database);
        if (requiredFailure) return requiredFailure;
        if (!checkpoint) {
          return fullVerifyUnlocked(database, checkpoint, pending, true);
        }
        const count = databaseCount(database);
        if (!Number.isSafeInteger(count) || count < checkpoint.count) {
          return { ok: false, count: Number.isSafeInteger(count) ? count : 0, reason: 'checkpoint-truncated' };
        }
        const storedRows = database.prepare('SELECT seq, entry FROM audit WHERE seq > ? ORDER BY seq ASC').all(checkpoint.seq);
        if (count !== checkpoint.count + storedRows.length) {
          return fullVerifyUnlocked(database, checkpoint, pending, true);
        }
        let head = checkpoint.head;
        let seq = checkpoint.seq;
        for (const row of storedRows) {
          const entry = JSON.parse(row.entry);
          const rowSeq = Number(row.seq);
          if (!Number.isSafeInteger(rowSeq) || rowSeq <= seq || entry.prevHash !== head) {
            return { ok: false, count, brokenAt: entry.id, reason: 'chain' };
          }
          if (!integrity.validAuthenticatedEntry(entry, state.key)) {
            return { ok: false, count, brokenAt: entry.id, reason: 'entry-authentication' };
          }
          head = entry.hash;
          seq = rowSeq;
        }
        if (storedRows.length) {
          publishCheckpointUnlocked(
            checkpoint,
            integrity.createCheckpoint(count, head, state.key, seq),
            true,
          );
        } else {
          settleRequiredCheckpoint(checkpoint);
        }
        const published = storedRows.length
          ? integrity.createCheckpoint(count, head, state.key, seq)
          : checkpoint;
        clearPendingIfCoveredUnlocked(pending, published, true);
        markCheckpointProtocolUnlocked(true);
        assertBoundSidecarDirectoriesUnlocked();
        return { ok: true, count };
      });
      lastError = result.ok ? null : result;
      return result;
    } catch (error) {
      lastError = error;
      return { ok: false, count: 0, reason: 'checkpoint-unavailable' };
    }
  }

  function protocolError(message, reason = 'pending-diverged') {
    const error = new Error(message);
    error.code = 'REDACTWALL_AUDIT_PENDING_UNHEALTHY';
    error.integrity = { ok: false, count: 0, reason };
    return error;
  }

  function validatedCheckpointUnlocked(trustedDirectory = false) {
    const checkpoint = loadCheckpointUnlocked(trustedDirectory);
    if (!checkpoint) {
      if (state.checkpointCreated) throw protocolError('audit checkpoint is missing', 'checkpoint-missing');
      return null;
    }
    if (!integrity.validCheckpoint(checkpoint, state.key)) {
      throw protocolError('audit checkpoint authentication failed', 'checkpoint-authentication');
    }
    return checkpoint;
  }

  function durableHighWater(checkpoint, pending) {
    const zero = { count: 0, seq: 0, head: integrity.ZERO };
    if (!checkpoint && !pending) return zero;
    if (!checkpoint) return pending;
    if (!pending) return checkpoint;
    if (checkpoint.count === pending.count
        && (checkpoint.seq !== pending.seq || checkpoint.head !== pending.head)) {
      throw protocolError('audit checkpoint and pending high-water diverge');
    }
    return checkpoint.count >= pending.count ? checkpoint : pending;
  }

  function transactionTail(database, entries) {
    const rows = database.prepare('SELECT seq, entry FROM audit ORDER BY seq DESC LIMIT ?')
      .all(entries.length)
      .reverse();
    if (rows.length !== entries.length) {
      throw protocolError('audit transaction tail is incomplete');
    }
    let previous = null;
    for (let index = 0; index < rows.length; index += 1) {
      let stored;
      try { stored = JSON.parse(rows[index].entry); } catch { stored = null; }
      const expected = entries[index];
      const seq = Number(rows[index].seq);
      if (!stored || !expected || stored.id !== expected.id || stored.hash !== expected.hash
          || !Number.isSafeInteger(seq) || seq <= 0
          || !integrity.validAuthenticatedEntry(stored, state.key)
          || (previous && (stored.prevHash !== previous.hash || seq <= previous.seq))) {
        throw protocolError('audit transaction tail does not match its authenticated entries');
      }
      previous = { hash: stored.hash, seq };
    }
    return {
      first: entries[0],
      last: entries[entries.length - 1],
      lastSeq: Number(rows[rows.length - 1].seq),
    };
  }

  function verifyLegacyTailUnlocked(database, checkpoint) {
    let verified;
    const result = integrity.verifyAuditChainForDatabase(database, {
      key: state.key,
      checkpoint,
      allowCheckpointBootstrap: !checkpoint && !state.checkpointCreated && legacyBootstrapAuthorized,
      onVerified(next) { verified = next; },
    });
    if (!result.ok || !verified) {
      throw protocolError('legacy audit tail cannot be authenticated', result.reason || 'chain');
    }
    return verified;
  }

  function prepareTransactionCommit(database, entries) {
    if (preparedTransaction) throw new Error('an audit transaction is already prepared');
    if (!Array.isArray(entries) || !entries.length) return;
    let lock;
    let prepared = false;
    let prepareError = null;
    try {
      if (externalCoordination) {
        if (typeof options.transactionCoordinationHeld !== 'function'
            || options.transactionCoordinationHeld() !== true) {
          throw protocolError('database audit coordination is not held for transaction preparation');
        }
      } else {
        lock = acquireFileMutationLockSync(checkpointPath, {
          ...options,
          fs: fsImpl,
          lockTimeoutMs: options.transactionLockTimeoutMs
            ?? options.lockTimeoutMs
            ?? TRANSACTION_LOCK_TIMEOUT_MS,
          lockTimeoutMaximumMs: TRANSACTION_LOCK_TIMEOUT_MS,
        });
      }
      assertTrustedSidecarDirectoriesUnlocked();
      reloadTrustedStateUnlocked();
      const checkpoint = validatedCheckpointUnlocked(true);
      const previousPending = loadPendingUnlocked(true);
      const pendingFailure = pendingTailFailureUnlocked(database, previousPending);
      if (pendingFailure) {
        throw protocolError('audit pending high-water no longer exists', pendingFailure.reason);
      }

      const count = databaseCount(database);
      const priorCount = count - entries.length;
      if (!Number.isSafeInteger(priorCount) || priorCount < 0) {
        throw protocolError('audit transaction count is inconsistent');
      }
      if (checkpoint && checkpoint.count > priorCount) {
        throw protocolError('audit transaction begins behind its checkpoint', 'checkpoint-truncated');
      }
      if (previousPending && previousPending.count > priorCount) {
        throw protocolError('audit transaction begins behind its pending high-water', 'checkpoint-truncated');
      }

      let durable = durableHighWater(checkpoint, previousPending);
      const tail = transactionTail(database, entries);
      if (durable.count !== priorCount) {
        if (state.pendingProtocol) {
          throw protocolError('a committed audit tail has no durable pending high-water', 'pending-missing');
        }
        durable = verifyLegacyTailUnlocked(database, checkpoint);
        if (durable.count !== count) {
          throw protocolError('legacy audit tail count is inconsistent');
        }
      } else if (tail.first.prevHash !== durable.head) {
        throw protocolError('audit transaction does not extend the durable high-water', 'chain');
      }

      const nextCheckpoint = integrity.createCheckpoint(count, tail.last.hash, state.key, tail.lastSeq);
      const nextPending = signedPending(nextCheckpoint, tail.last.id, state.key);
      writeTrustedPrivateJson(pendingPath, nextPending, trustedSidecarOptions());
      preparedTransaction = { lock };
      prepared = true;
    } catch (error) {
      prepareError = error;
      // Healthy replicas may contend on the bounded interprocess lock. Storage,
      // cleanup, or trust failures are different: readiness must freeze until
      // the exact durable sidecars can be verified again.
      if (!error || error.code !== 'FILE_MUTATION_LOCK_TIMEOUT') lastError = error;
      throw error;
    } finally {
      if (lock && !prepared) {
        try {
          releaseFileMutationLock(lock);
        } catch (releaseError) {
          if (prepareError) {
            prepareError.lockReleaseError = releaseError;
            lastError = prepareError;
          } else {
            lastError = releaseError;
            throw releaseError;
          }
        }
      }
    }
  }

  function transactionCommitted(database) {
    const transaction = preparedTransaction;
    if (!transaction) return;
    preparedTransaction = null;
    if (transaction.lock) {
      try {
        releaseFileMutationLock(transaction.lock);
      } catch (error) {
        lastError = error;
      }
    }
    scheduleVerification(database);
  }

  function transactionCommitUncertain(database) {
    const transaction = preparedTransaction;
    if (!transaction) return;
    preparedTransaction = null;
    const uncertainty = { ok: false, count: 0, reason: 'commit-uncertain' };
    if (transaction.lock) {
      try {
        releaseFileMutationLock(transaction.lock);
      } catch (error) {
        uncertainty.cause = error;
      }
    }
    // Preserve the newly published pending high-water. Reconciliation may
    // prove that COMMIT applied and safely advance it; a missing row remains a
    // hard failure instead of being mistaken for a normal rollback.
    lastError = uncertainty;
    scheduleVerification(database);
  }

  function requireMutationReady(database) {
    if (!externalCoordination && !lastError && !requiredCheckpoint) {
      return { ok: true, count: databaseCount(database) };
    }
    const previousError = lastError;
    const result = advanceCheckpoint(database);
    if (result.ok && !requiredCheckpoint) return result;
    const error = new Error('audit checkpoint is unhealthy; mutation is frozen until the committed tail is durably verified');
    error.code = 'REDACTWALL_AUDIT_CHECKPOINT_UNHEALTHY';
    error.integrity = result.ok ? { ok: false, count: result.count, reason: 'checkpoint-pending' } : result;
    if (previousError instanceof Error) error.cause = previousError;
    throw error;
  }

  function scheduleVerification(database) {
    if (scheduled) return;
    scheduled = true;
    // Run after the current I/O batch rather than after each individual HTTP
    // callback. Every committed row is independently HMAC-authenticated, so a
    // restart can verify and advance a short tail beyond the checkpoint while
    // concurrent requests share one durable sidecar publication.
    setImmediate(() => {
      scheduled = false;
      advanceCheckpoint(database);
    });
  }

  return {
    authenticate(prevHash, body) {
      return integrity.authenticatedEntry(prevHash, body, state.key);
    },
    verifyAuthenticatedEntry(entry) {
      return integrity.validAuthenticatedEntry(entry, state.key);
    },
    verifyDatabase,
    advanceCheckpoint,
    prepareTransactionCommit,
    transactionCommitted,
    transactionCommitUncertain,
    requireMutationReady,
    scheduleVerification,
    initialization,
    status: () => ({
      ok: !lastError && !requiredCheckpoint,
      error: lastError,
      reason: lastError && lastError.reason
        ? lastError.reason
        : (lastError ? 'checkpoint-unavailable' : (requiredCheckpoint ? 'checkpoint-pending' : null)),
      statePath,
      checkpointPath,
      pendingPath,
    }),
    paths: { statePath, checkpointPath, pendingPath },
  };
}

module.exports = {
  openAuditAnchor,
  _internal: {
    TRANSACTION_LOCK_TIMEOUT_MS,
    INITIALIZATION_LOCK_TIMEOUT_MS,
    configuredKey,
    keyId,
    loadState,
    signedState,
    validDatabaseScope,
    signedPending,
    validPending,
    writePrivateJson,
    readPrivateJson,
    withPreparedAuditDirectories,
    writeNewPrivateJson,
  },
};
