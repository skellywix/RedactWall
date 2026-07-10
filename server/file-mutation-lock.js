'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');
const { performance } = require('perf_hooks');

const DEFAULT_TIMEOUT_MS = 5000;
const DEFAULT_MAXIMUM_TIMEOUT_MS = 30_000;
const ABSOLUTE_MAXIMUM_TIMEOUT_MS = 60_000;
const DEFAULT_RETRY_MS = 25;
const MAX_OWNER_BYTES = 1024;
const CLEANUP_RETRIES = 6;
const CLEANUP_RETRY_MS = 5;
const OWNER_FILE_PATTERN = /^owner\.([a-f0-9]{48})\.json$/;
const LINUX_GENERATION_PATTERN = /^linux:([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}):([0-9]+)$/;
const LOCK_SLEEP = new Int32Array(new SharedArrayBuffer(4));
const PROCESS_START = String(performance.timeOrigin);
let contentionObserver = null;
const releasedOwnerTokens = new Set();

function lockPathFor(targetPath) {
  const target = path.resolve(targetPath);
  return path.join(path.dirname(target), `.${path.basename(target)}.mutation.lock`);
}

function ownerFileName(token) {
  return `owner.${token}.json`;
}

function lockTimeoutError() {
  const error = new Error('configuration mutation lock timed out');
  error.code = 'FILE_MUTATION_LOCK_TIMEOUT';
  error.statusCode = 503;
  error.publicMessage = 'configuration mutation is busy; retry';
  return error;
}

function boundedPositive(value, fallback, maximum) {
  const number = Number(value);
  if (!Number.isFinite(number) || number <= 0) return fallback;
  return Math.min(maximum, Math.max(1, Math.round(number)));
}

function normalizedProcessStart(value) {
  const number = Number(value);
  return Number.isFinite(number) && number > 0 ? String(number) : PROCESS_START;
}

function normalizedHostname(value) {
  const hostname = String(value || '');
  if (!hostname || hostname.length > 255 || /[\u0000-\u001f\u007f]/.test(hostname)) {
    throw new Error('file-mutation lock hostname is invalid');
  }
  return hostname;
}

function procStatStartTime(contents) {
  const text = String(contents || '').trim();
  const commandEnd = text.lastIndexOf(')');
  if (commandEnd < 2) return null;
  const remainingFields = text.slice(commandEnd + 1).trim().split(/\s+/);
  const startTime = remainingFields[19]; // /proc/<pid>/stat field 22.
  return typeof startTime === 'string' && /^\d+$/.test(startTime) ? startTime : null;
}

function normalizedGeneration(value) {
  if (value === null) return null;
  const match = LINUX_GENERATION_PATTERN.exec(String(value || '').toLowerCase());
  if (!match) return null;
  return `linux:${match[1]}:${match[2]}`;
}

function linuxGeneration(fsImpl = fs, platform = process.platform) {
  if (platform !== 'linux') return null;
  try {
    const bootId = String(fsImpl.readFileSync('/proc/sys/kernel/random/boot_id', 'utf8')).trim().toLowerCase();
    const startTime = procStatStartTime(fsImpl.readFileSync('/proc/1/stat', 'utf8'));
    return normalizedGeneration(`linux:${bootId}:${startTime}`);
  } catch {
    return null;
  }
}

function requestedGeneration(options, fsImpl) {
  if (Object.prototype.hasOwnProperty.call(options, 'generation')) {
    return normalizedGeneration(options.generation);
  }
  return linuxGeneration(fsImpl, options.platform || process.platform);
}

function lockOptions(options = {}) {
  const requestedPid = Number(options.pid);
  const fsImpl = options.fs || fs;
  // Routine mutations stay at the 30-second ceiling. Slow first-boot work must
  // opt into a larger ceiling explicitly, and can never exceed one minute.
  const maximumTimeoutMs = boundedPositive(
    options.lockTimeoutMaximumMs,
    DEFAULT_MAXIMUM_TIMEOUT_MS,
    ABSOLUTE_MAXIMUM_TIMEOUT_MS,
  );
  return {
    fsImpl,
    timeoutMs: boundedPositive(options.lockTimeoutMs ?? options.timeoutMs, DEFAULT_TIMEOUT_MS, maximumTimeoutMs),
    retryMs: boundedPositive(options.lockRetryMs ?? options.retryMs, DEFAULT_RETRY_MS, 250),
    now: typeof options.now === 'function' ? options.now : Date.now,
    onContention: typeof options.onLockContention === 'function'
      ? options.onLockContention
      : (contentionObserver || (() => {})),
    onBeforeReclaim: typeof options.onBeforeReclaim === 'function' ? options.onBeforeReclaim : null,
    onBeforeEmptyReclaim: typeof options.onBeforeEmptyReclaim === 'function' ? options.onBeforeEmptyReclaim : null,
    hostname: normalizedHostname(options.hostname || process.env.REDACTWALL_LOCK_HOSTNAME || os.hostname()),
    pid: Number.isInteger(requestedPid) && requestedPid > 0 ? requestedPid : process.pid,
    processStart: normalizedProcessStart(options.processStart ?? PROCESS_START),
    generation: requestedGeneration(options, fsImpl),
    processKill: typeof options.processKill === 'function' ? options.processKill : process.kill.bind(process),
    sleep: typeof options.sleep === 'function'
      ? options.sleep
      : (ms) => Atomics.wait(LOCK_SLEEP, 0, 0, ms),
  };
}

function setContentionObserverForTest(observer) {
  contentionObserver = typeof observer === 'function' ? observer : null;
}

function sameFileIdentity(left, right) {
  if (!left.isFile() || left.isSymbolicLink() || !right.isFile() || right.isSymbolicLink()) return false;
  return left.dev === right.dev && left.ino === right.ino;
}

function sameDirectoryIdentity(left, right) {
  if (!left.isDirectory() || left.isSymbolicLink() || !right.isDirectory() || right.isSymbolicLink()) return false;
  return left.dev === right.dev && left.ino === right.ino;
}

function readBoundedOwnerFile(ownerPath, before, fsImpl) {
  if (before.size <= 0 || before.size > MAX_OWNER_BYTES) throw new Error('file-mutation lock owner size is invalid');
  const noFollow = fs.constants.O_NOFOLLOW || 0;
  let fd;
  try {
    fd = fsImpl.openSync(ownerPath, fs.constants.O_RDONLY | noFollow);
    const opened = fsImpl.fstatSync(fd);
    if (opened.size !== before.size || !sameFileIdentity(before, opened)) throw new Error('file-mutation lock owner changed while opening');
    const output = Buffer.alloc(MAX_OWNER_BYTES + 1);
    let offset = 0;
    while (offset < output.length) {
      const count = fsImpl.readSync(fd, output, offset, output.length - offset, null);
      if (!count) break;
      offset += count;
    }
    const after = fsImpl.fstatSync(fd);
    if (offset > MAX_OWNER_BYTES || offset !== opened.size || after.size !== opened.size
        || after.mtimeMs !== opened.mtimeMs || after.ctimeMs !== opened.ctimeMs
        || !sameFileIdentity(opened, after)) throw new Error('file-mutation lock owner changed while reading');
    return { contents: output.subarray(0, offset).toString('utf8'), stat: after };
  } finally {
    if (fd !== undefined) fsImpl.closeSync(fd);
  }
}

function parseOwner(contents) {
  try {
    const owner = JSON.parse(contents);
    if (!owner || ![1, 2, 3].includes(owner.version) || !Number.isInteger(owner.pid) || owner.pid <= 0) return null;
    if (typeof owner.hostname !== 'string' || !owner.hostname || owner.hostname.length > 255) return null;
    if (typeof owner.token !== 'string' || !/^[a-f0-9]{48}$/.test(owner.token)) return null;
    if (owner.version >= 2 && normalizedProcessStart(owner.processStart) !== owner.processStart) return null;
    if (owner.version === 3) {
      if (!Object.prototype.hasOwnProperty.call(owner, 'generation')) return null;
      if (owner.generation !== null && normalizedGeneration(owner.generation) !== owner.generation) return null;
    }
    return owner;
  } catch {
    return null;
  }
}

function ownerDefinitelyDead(owner, options) {
  if (!owner || owner.hostname !== options.hostname) return false;
  // A release whose exact-owner unlink was temporarily denied is no longer a
  // live critical section. Remember only this process's unguessable owner
  // token so the next mutation can retry the exact cleanup without waiting for
  // process exit. A different process/boot can never inherit this proof.
  if (releasedOwnerTokens.has(owner.token)
      && owner.pid === options.pid
      && owner.processStart === options.processStart
      && owner.generation === options.generation) return true;
  // A boot plus PID-namespace generation change is conclusive only for the
  // supported singleton assigned to one stable lock hostname.
  if (owner.generation && options.generation && owner.generation !== options.generation) return true;
  if (owner.pid === options.pid && owner.processStart && owner.processStart !== options.processStart) return true;
  try {
    options.processKill(owner.pid, 0);
    return false;
  } catch (error) {
    return !!(error && error.code === 'ESRCH');
  }
}

function readOwnerSnapshot(lockPath, fsImpl) {
  const directoryStat = fsImpl.lstatSync(lockPath);
  if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink()) return null;
  const entries = fsImpl.readdirSync(lockPath);
  if (entries.length !== 1) return null;
  const match = OWNER_FILE_PATTERN.exec(entries[0]);
  if (!match) return null;
  const ownerName = entries[0];
  const ownerPath = path.join(lockPath, ownerName);
  const ownerStat = fsImpl.lstatSync(ownerPath);
  if (!ownerStat.isFile() || ownerStat.isSymbolicLink() || ownerStat.nlink !== 1) return null;
  const bounded = readBoundedOwnerFile(ownerPath, ownerStat, fsImpl);
  const contents = bounded.contents;
  const owner = parseOwner(contents);
  if (!owner || owner.token !== match[1]) return null;
  return { directoryStat, ownerStat: bounded.stat, ownerName, ownerPath, contents, owner };
}

function sameSnapshot(left, right) {
  return !!(left && right
    && left.ownerName === right.ownerName
    && left.contents === right.contents
    && sameDirectoryIdentity(left.directoryStat, right.directoryStat)
    && sameFileIdentity(left.ownerStat, right.ownerStat));
}

function reclaimDeadOwner(targetPath, options) {
  const lockPath = lockPathFor(targetPath);
  let before;
  try {
    before = readOwnerSnapshot(lockPath, options.fsImpl);
  } catch {
    return false;
  }
  if (!before || !ownerDefinitelyDead(before.owner, options)) return false;
  if (options.onBeforeReclaim) options.onBeforeReclaim({
    lockPath,
    ownerPath: before.ownerPath,
    ownerName: before.ownerName,
    owner: { ...before.owner },
  });
  try {
    const current = readOwnerSnapshot(lockPath, options.fsImpl);
    if (!sameSnapshot(before, current)) return false;
    options.fsImpl.unlinkSync(before.ownerPath);
    options.fsImpl.rmdirSync(lockPath);
    releasedOwnerTokens.delete(before.owner.token);
    return true;
  } catch {
    return false;
  }
}

function reclaimEmptyLockDirectory(targetPath, options) {
  const lockPath = lockPathFor(targetPath);
  let before;
  try {
    before = options.fsImpl.lstatSync(lockPath);
    if (!before.isDirectory() || before.isSymbolicLink() || options.fsImpl.readdirSync(lockPath).length !== 0) return false;
  } catch {
    return false;
  }
  if (options.onBeforeEmptyReclaim) options.onBeforeEmptyReclaim({ lockPath });
  try {
    const current = options.fsImpl.lstatSync(lockPath);
    if (!sameDirectoryIdentity(before, current) || options.fsImpl.readdirSync(lockPath).length !== 0) return false;
    options.fsImpl.rmdirSync(lockPath);
    return true;
  } catch {
    return false;
  }
}

function releaseFileMutationLock(lock) {
  if (!lock || lock.released) return;
  if (lock.fd !== undefined) {
    try { lock.fsImpl.closeSync(lock.fd); } catch { /* best effort */ }
    lock.fd = undefined;
  }
  const ownerToken = OWNER_FILE_PATTERN.exec(lock.ownerName || '')?.[1] || '';
  try {
    const current = readOwnerSnapshot(lock.lockPath, lock.fsImpl);
    const expected = {
      directoryStat: lock.directoryStat,
      ownerStat: lock.ownerStat,
      ownerName: lock.ownerName,
      contents: lock.contents,
    };
    if (current && !sameSnapshot(expected, current)) {
      // Our exact owner has already gone and another writer owns this path.
      // Treat our release as complete without touching the replacement.
      lock.released = true;
      if (ownerToken) releasedOwnerTokens.delete(ownerToken);
      return;
    }
    if (!current || !cleanupExactOwnerDirectory(lock.fsImpl, lock.lockPath, lock.ownerPath)) {
      throw new Error('file-mutation lock cleanup did not complete');
    }
    lock.released = true;
    if (ownerToken) releasedOwnerTokens.delete(ownerToken);
  } catch (cause) {
    let exactOwnerRemains = false;
    try {
      const remaining = readOwnerSnapshot(lock.lockPath, lock.fsImpl);
      exactOwnerRemains = !!(remaining && remaining.owner.token === ownerToken);
    } catch {}
    if (ownerToken && exactOwnerRemains) releasedOwnerTokens.add(ownerToken);
    else if (ownerToken) releasedOwnerTokens.delete(ownerToken);
    const error = new Error('file-mutation lock cleanup failed');
    error.code = 'FILE_MUTATION_LOCK_CLEANUP';
    error.cause = cause;
    throw error;
  }
}

function cleanupExactOwnerDirectory(fsImpl, directory, ownerPath) {
  for (let attempt = 0; attempt < CLEANUP_RETRIES; attempt += 1) {
    let ownerGone = false;
    try { fsImpl.unlinkSync(ownerPath); ownerGone = true; }
    catch (error) { ownerGone = !!(error && error.code === 'ENOENT'); }
    if (ownerGone) {
      try { fsImpl.rmdirSync(directory); return true; }
      catch (error) { if (error && error.code === 'ENOENT') return true; }
    }
    if (attempt + 1 < CLEANUP_RETRIES) {
      Atomics.wait(LOCK_SLEEP, 0, 0, CLEANUP_RETRY_MS);
    }
  }
  return false;
}

function existingLockCaused(error) {
  // Windows reports an existing destination directory as EPERM. The winner
  // may release before we can probe it, so classification cannot depend on a
  // second path lookup.
  return !!(error && ['EEXIST', 'ENOTEMPTY', 'EPERM', 'EACCES', 'EBUSY'].includes(error.code));
}

function fsyncDirectoryBestEffort(fsImpl, directory) {
  let fd;
  try {
    fd = fsImpl.openSync(directory, 'r');
    fsImpl.fsyncSync(fd);
  } catch { /* directory fsync is not available on every platform */
  } finally {
    if (fd !== undefined) try { fsImpl.closeSync(fd); } catch { /* best effort */ }
  }
}

function tryAcquire(targetPath, options) {
  const target = path.resolve(targetPath);
  const lockPath = lockPathFor(target);
  options.fsImpl.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
  const owner = {
    version: 3,
    pid: options.pid,
    hostname: options.hostname,
    processStart: options.processStart,
    generation: options.generation,
    token: crypto.randomBytes(24).toString('hex'),
  };
  const contents = `${JSON.stringify(owner)}\n`;
  const ownerName = ownerFileName(owner.token);
  const tempPath = `${lockPath}.${owner.token}.owner.tmp`;
  const tempOwnerPath = path.join(tempPath, ownerName);
  let fd;
  let published = false;
  try {
    options.fsImpl.mkdirSync(tempPath, { mode: 0o700 });
    fd = options.fsImpl.openSync(tempOwnerPath, 'wx', 0o600);
    options.fsImpl.writeFileSync(fd, contents, 'utf8');
    options.fsImpl.fsyncSync(fd);
    fsyncDirectoryBestEffort(options.fsImpl, tempPath);
    options.fsImpl.closeSync(fd);
    fd = undefined;
    options.fsImpl.renameSync(tempPath, lockPath);
    published = true;
    fsyncDirectoryBestEffort(options.fsImpl, path.dirname(lockPath));
    const ownerPath = path.join(lockPath, ownerName);
    fd = options.fsImpl.openSync(ownerPath, 'r');
    const ownerStat = options.fsImpl.fstatSync(fd);
    const directoryStat = options.fsImpl.lstatSync(lockPath);
    return {
      fd,
      lockPath,
      ownerPath,
      ownerName,
      ownerStat,
      directoryStat,
      contents,
      token: contents,
      fsImpl: options.fsImpl,
      released: false,
    };
  } catch (error) {
    if (fd !== undefined) try { options.fsImpl.closeSync(fd); } catch { /* best effort */ }
    const cleaned = published
      ? cleanupExactOwnerDirectory(options.fsImpl, lockPath, path.join(lockPath, ownerName))
      : cleanupExactOwnerDirectory(options.fsImpl, tempPath, tempOwnerPath);
    if (!cleaned) {
      const cleanupError = new Error('file-mutation lock cleanup failed');
      cleanupError.code = 'FILE_MUTATION_LOCK_CLEANUP';
      cleanupError.cause = error;
      throw cleanupError;
    }
    if (existingLockCaused(error)) return null;
    throw error;
  }
}

function acquireFileMutationLockSync(targetPath, options = {}) {
  const normalized = lockOptions(options);
  const deadline = normalized.now() + normalized.timeoutMs;
  for (;;) {
    const lock = tryAcquire(targetPath, normalized);
    if (lock) return lock;
    if (reclaimDeadOwner(targetPath, normalized)) continue;
    if (reclaimEmptyLockDirectory(targetPath, normalized)) continue;
    normalized.onContention();
    const remaining = deadline - normalized.now();
    if (remaining <= 0) throw lockTimeoutError();
    normalized.sleep(Math.min(normalized.retryMs, remaining));
  }
}

async function acquireFileMutationLock(targetPath, options = {}) {
  const normalized = lockOptions(options);
  const deadline = normalized.now() + normalized.timeoutMs;
  for (;;) {
    const lock = tryAcquire(targetPath, normalized);
    if (lock) return lock;
    if (reclaimDeadOwner(targetPath, normalized)) continue;
    if (reclaimEmptyLockDirectory(targetPath, normalized)) continue;
    normalized.onContention();
    const remaining = deadline - normalized.now();
    if (remaining <= 0) throw lockTimeoutError();
    await new Promise((resolve) => setTimeout(resolve, Math.min(normalized.retryMs, remaining)));
  }
}

function withFileMutationLockSync(targetPath, callback, options = {}) {
  const lock = acquireFileMutationLockSync(targetPath, options);
  let callbackError;
  try {
    const result = callback();
    if (result && typeof result.then === 'function') {
      throw new TypeError('synchronous file mutation callback returned a promise');
    }
    return result;
  } catch (error) {
    callbackError = error;
    throw error;
  } finally {
    try { releaseFileMutationLock(lock); }
    catch (cleanupError) {
      if (callbackError) callbackError.cleanupError = cleanupError;
      else throw cleanupError;
    }
  }
}

async function withFileMutationLock(targetPath, callback, options = {}) {
  const lock = await acquireFileMutationLock(targetPath, options);
  let callbackError;
  try {
    return await callback();
  } catch (error) {
    callbackError = error;
    throw error;
  } finally {
    try { releaseFileMutationLock(lock); }
    catch (cleanupError) {
      if (callbackError) callbackError.cleanupError = cleanupError;
      else throw cleanupError;
    }
  }
}

module.exports = {
  lockPathFor,
  acquireFileMutationLock,
  acquireFileMutationLockSync,
  releaseFileMutationLock,
  withFileMutationLock,
  withFileMutationLockSync,
  _setContentionObserverForTest: setContentionObserverForTest,
  _internal: {
    linuxGeneration,
    normalizedGeneration,
    ownerFileName,
    parseOwner,
    procStatStartTime,
    releasedOwnerTokenCount: () => releasedOwnerTokens.size,
  },
};
