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
  assertPrivatePath,
  securePrivatePath,
  withPrivateDirectoryMutationLockSync,
  readBoundedRegularFile,
  fsyncDirectory,
  publishFileDurably,
} = require('./private-path');

const LEGACY_STATE_VERSION = 1;
const STATE_VERSION = 2;
const PENDING_VERSION = 1;
const MAX_STATE_BYTES = 8 * 1024;
const MAX_CHECKPOINT_BYTES = 4 * 1024;
const MAX_PENDING_BYTES = 8 * 1024;
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
  if (sidecarPlatform(options) !== 'win32') {
    ensurePrivateDirectory(directories[0], options);
    return callback();
  }
  const byLockIdentity = new Map();
  for (const directory of directories) {
    const resolved = path.resolve(directory);
    const identity = resolved.toLowerCase();
    if (!byLockIdentity.has(identity)) byLockIdentity.set(identity, resolved);
  }
  const unique = [...byLockIdentity.entries()]
    .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
    .map(([, resolved]) => resolved);
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

function writePrivateJson(file, value, options = {}) {
  const fsImpl = options.fs || fs;
  const directory = requirePrivateDirectory(path.dirname(file), options);
  const temp = path.join(directory, `.${path.basename(file)}.${process.pid}.${crypto.randomBytes(12).toString('hex')}.tmp`);
  let fd;
  try {
    fd = fsImpl.openSync(temp, 'wx', 0o600);
    fsImpl.writeFileSync(fd, JSON.stringify(value), 'utf8');
    fsImpl.fsyncSync(fd);
    fsImpl.fchmodSync(fd, 0o600);
    fsImpl.closeSync(fd);
    fd = undefined;
    securePrivatePath(temp, sidecarSecurity(options, false, 'audit integrity sidecar'));
    publishFileDurably(temp, file, { ...options, fs: fsImpl });
    securePrivatePath(file, sidecarSecurity(options, false, 'audit integrity sidecar'));
    return file;
  } finally {
    if (fd !== undefined) { try { fsImpl.closeSync(fd); } catch {} }
    try { fsImpl.unlinkSync(temp); } catch {}
  }
}

function readPrivateJson(file, maxBytes, options = {}) {
  const fsImpl = options.fs || fs;
  assertPrivatePath(file, sidecarSecurity(options, false, 'audit integrity sidecar'));
  const value = JSON.parse(readBoundedRegularFile(file, {
    ...sidecarSecurity(options, false, 'audit integrity sidecar'),
    maxBytes,
  }).toString('utf8'));
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('audit integrity sidecar is malformed');
  return value;
}

function configuredKey(env = process.env) {
  const source = String(env.REDACTWALL_AUDIT_KEY || env.REDACTWALL_SECRET || '');
  if (!source) return null;
  return crypto.createHash('sha256').update(`redactwall:audit-auth:v1:${source}`).digest();
}

function keyId(key) {
  return crypto.createHash('sha256').update(key).digest('hex');
}

function stateBody(key, checkpointCreated, embedded, pendingProtocol = true) {
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

function signedState(key, checkpointCreated, embedded, pendingProtocol = true) {
  const body = stateBody(key, checkpointCreated, embedded, pendingProtocol);
  return { ...body, mac: integrity.hmac(key, integrity.canonical(body)) };
}

function loadState(file, externalKey, options = {}) {
  const raw = readPrivateJson(file, MAX_STATE_BYTES, options);
  const embedded = typeof raw.key === 'string' && raw.key.length > 0;
  const key = externalKey || (embedded ? Buffer.from(raw.key, 'base64') : null);
  if (!key || key.length < 32) throw new Error('audit authentication key is unavailable');
  const pendingProtocol = raw.version === STATE_VERSION && raw.pendingProtocol === true;
  if (!pendingProtocol && raw.version !== LEGACY_STATE_VERSION) {
    throw new Error('audit integrity state version is unsupported');
  }
  const expected = signedState(key, raw.checkpointCreated === true, embedded, pendingProtocol);
  if (raw.version !== expected.version || raw.keyId !== expected.keyId || raw.key !== expected.key
      || raw.checkpointCreated !== expected.checkpointCreated
      || raw.pendingProtocol !== expected.pendingProtocol || raw.mac !== expected.mac) {
    throw new Error('audit integrity state authentication failed');
  }
  if (externalKey && embedded) throw new Error('audit integrity state key source changed');
  return { key, embedded, checkpointCreated: raw.checkpointCreated === true, pendingProtocol };
}

function createState(file, externalKey, options = {}) {
  const key = externalKey || crypto.randomBytes(32);
  const embedded = !externalKey;
  writePrivateJson(file, signedState(key, false, embedded, true), options);
  return { key, embedded, checkpointCreated: false, pendingProtocol: true };
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

function openAuditAnchor(options = {}) {
  const env = options.env || process.env;
  const directory = path.resolve(options.directory);
  const statePath = path.resolve(options.statePath || path.join(directory, '.audit-integrity-state.json'));
  const checkpointPath = path.resolve(options.checkpointPath || path.join(directory, '.audit-integrity-checkpoint.json'));
  const pendingPath = path.resolve(options.pendingPath || path.join(directory, '.audit-integrity-pending.json'));
  const fsImpl = options.fs || fs;
  const externalKey = configuredKey(env);

  let state;
  let initialization;
  withPreparedAuditDirectories([
    directory,
    path.dirname(statePath),
    path.dirname(checkpointPath),
    path.dirname(pendingPath),
  ], () => {
    withFileMutationLockSync(checkpointPath, () => {
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
      if (typeof options.initialize === 'function') initialization = options.initialize();
    }, {
      ...options,
      fs: fsImpl,
      lockTimeoutMs: options.initializationLockTimeoutMs
        ?? options.lockTimeoutMs
        ?? INITIALIZATION_LOCK_TIMEOUT_MS,
      lockTimeoutMaximumMs: INITIALIZATION_LOCK_TIMEOUT_MS,
    });
  }, options);

  let lastError = null;
  // A failed sidecar publication happens after the database transaction that
  // produced this authenticated tail has committed. Keep that exact high-water
  // mark in memory until it is durably published. Otherwise a repair against
  // the older on-disk checkpoint could silently accept truncation of the row
  // whose publication failed.
  let requiredCheckpoint = null;
  let preparedTransaction = null;
  let scheduled = false;

  function loadCheckpointUnlocked() {
    try {
      return readPrivateJson(checkpointPath, MAX_CHECKPOINT_BYTES, options);
    } catch (error) {
      if (error && error.code === 'ENOENT') return null;
      throw error;
    }
  }

  function loadPendingUnlocked() {
    let pending;
    try {
      pending = readPrivateJson(pendingPath, MAX_PENDING_BYTES, options);
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

  function removePendingUnlocked() {
    try {
      assertPrivatePath(pendingPath, sidecarSecurity(options, false, 'audit integrity sidecar'));
      fsImpl.unlinkSync(pendingPath);
      fsyncDirectory(path.dirname(pendingPath), { ...options, fs: fsImpl });
    } catch (error) {
      if (!error || error.code !== 'ENOENT') throw error;
    }
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

  function publishCheckpointUnlocked(current, next) {
    if (sameCheckpoint(current, next)) {
      settleRequiredCheckpoint(current);
      return;
    }
    rememberRequiredCheckpoint(next);
    writePrivateJson(checkpointPath, next, options);
    settleRequiredCheckpoint(next);
  }

  function markCheckpointProtocolUnlocked() {
    if (state.checkpointCreated && state.pendingProtocol) return;
    writePrivateJson(statePath, signedState(state.key, true, state.embedded, true), options);
    state = { ...state, checkpointCreated: true, pendingProtocol: true };
  }

  function missingPendingFailureUnlocked(database, checkpoint, pending) {
    if (pending || !state.pendingProtocol) return null;
    const count = databaseCount(database);
    const durableCount = checkpoint && Number.isSafeInteger(checkpoint.count) ? checkpoint.count : 0;
    if (count > durableCount) return { ok: false, count, reason: 'pending-missing' };
    return null;
  }

  function clearPendingIfCoveredUnlocked(pending, checkpoint) {
    if (!pending || !checkpoint) return;
    if (checkpoint.count < pending.count || checkpoint.seq < pending.seq) return;
    removePendingUnlocked();
  }

  function fullVerifyUnlocked(database, checkpoint, pending = loadPendingUnlocked()) {
    if (!checkpoint && state.checkpointCreated) {
      return { ok: false, count: database.prepare('SELECT COUNT(*) n FROM audit').get().n, reason: 'checkpoint-missing' };
    }
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
      allowCheckpointBootstrap: !checkpoint && !state.checkpointCreated,
      onVerified(next) { verifiedCheckpoint = next; },
    });
    if (!result.ok) return result;
    publishCheckpointUnlocked(checkpoint, verifiedCheckpoint);
    clearPendingIfCoveredUnlocked(pending, verifiedCheckpoint);
    markCheckpointProtocolUnlocked();
    return result;
  }

  function verifyDatabase(database) {
    try {
      const result = withFileMutationLockSync(checkpointPath, () => {
        state = loadState(statePath, externalKey, options);
        return fullVerifyUnlocked(database, loadCheckpointUnlocked(), loadPendingUnlocked());
      }, { ...options, fs: fsImpl });
      lastError = result.ok ? null : result;
      return result;
    } catch (error) {
      lastError = error;
      return { ok: false, count: 0, reason: 'checkpoint-unavailable' };
    }
  }

  function advanceCheckpoint(database) {
    try {
      const result = withFileMutationLockSync(checkpointPath, () => {
        state = loadState(statePath, externalKey, options);
        const checkpoint = loadCheckpointUnlocked();
        const pending = loadPendingUnlocked();
        const pendingFailure = pendingTailFailureUnlocked(database, pending);
        if (pendingFailure) return pendingFailure;
        const missingPending = missingPendingFailureUnlocked(database, checkpoint, pending);
        if (missingPending) return missingPending;
        const requiredFailure = requiredTailFailureUnlocked(database);
        if (requiredFailure) return requiredFailure;
        if (!checkpoint || !Number.isSafeInteger(checkpoint.seq)
            || !integrity.validCheckpoint(checkpoint, state.key)) {
          return fullVerifyUnlocked(database, checkpoint, pending);
        }
        const count = databaseCount(database);
        if (!Number.isSafeInteger(count) || count < checkpoint.count) {
          return { ok: false, count: Number.isSafeInteger(count) ? count : 0, reason: 'checkpoint-truncated' };
        }
        const storedRows = database.prepare('SELECT seq, entry FROM audit WHERE seq > ? ORDER BY seq ASC').all(checkpoint.seq);
        if (count !== checkpoint.count + storedRows.length) {
          return fullVerifyUnlocked(database, checkpoint, pending);
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
          );
        } else {
          settleRequiredCheckpoint(checkpoint);
        }
        const published = storedRows.length
          ? integrity.createCheckpoint(count, head, state.key, seq)
          : checkpoint;
        clearPendingIfCoveredUnlocked(pending, published);
        markCheckpointProtocolUnlocked();
        return { ok: true, count };
      }, { ...options, fs: fsImpl });
      lastError = result.ok ? null : result;
      return result;
    } catch (error) {
      lastError = error;
      return { ok: false, count: 0, reason: 'checkpoint-unavailable' };
    }
  }

  function requireMutationReady(database) {
    if (!lastError && !requiredCheckpoint) return { ok: true, count: databaseCount(database) };
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
    }),
    paths: { statePath, checkpointPath },
  };
}

module.exports = {
  openAuditAnchor,
  _internal: {
    INITIALIZATION_LOCK_TIMEOUT_MS,
    configuredKey,
    keyId,
    loadState,
    signedState,
    writePrivateJson,
    readPrivateJson,
  },
};
