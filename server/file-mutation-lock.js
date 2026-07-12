'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');
const { performance } = require('perf_hooks');

const DEFAULT_TIMEOUT_MS = 5000;
const DEFAULT_MAXIMUM_TIMEOUT_MS = 30_000;
const ABSOLUTE_MAXIMUM_TIMEOUT_MS = 60_000;
const WINDOWS_O_TEMPORARY = fs.constants.O_TEMPORARY || 0x40;
const DEFAULT_RETRY_MS = 25;
const MAX_OWNER_BYTES = 1024;
const MAX_OWNER_BYTES_BIGINT = BigInt(MAX_OWNER_BYTES);
const CLEANUP_RETRIES = 20;
const CLEANUP_RETRY_MS = 10;
const OWNER_FILE_PATTERN = /^owner\.([a-f0-9]{48})\.json$/;
const LINUX_GENERATION_PATTERN = /^linux:([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}):([0-9]+)$/;
const LOCK_SLEEP = new Int32Array(new SharedArrayBuffer(4));
const PROCESS_START = String(performance.timeOrigin);
let contentionObserver = null;
const releasedOwnerTokens = new Set();
const committedCleanupWarnings = [];

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
    onBeforeExactOwnerDeleteClose: typeof options.onBeforeExactOwnerDeleteClose === 'function'
      ? options.onBeforeExactOwnerDeleteClose
      : null,
    onBeforeExactDirectoryDeleteClose: typeof options.onBeforeExactDirectoryDeleteClose === 'function'
      ? options.onBeforeExactDirectoryDeleteClose
      : null,
    platform: options.platform || process.platform,
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

function committedCleanupWarning(error, options = {}, phase = 'file-mutation-lock-release') {
  const warning = {
    component: String(options.cleanupComponent || 'file-mutation-lock').slice(0, 80),
    phase,
    code: String(error && error.code || 'FILE_MUTATION_LOCK_CLEANUP').slice(0, 80),
    ...(error && error.retainedPath ? { retainedPath: String(error.retainedPath) } : {}),
  };
  committedCleanupWarnings.push(warning);
  if (committedCleanupWarnings.length > 32) committedCleanupWarnings.shift();
  if (typeof options.onCommittedCleanupWarning === 'function') {
    try { options.onCommittedCleanupWarning({ ...warning }); } catch { /* committed callback stays successful */ }
  }
  return warning;
}

function committedCleanupHealth() {
  const latest = committedCleanupWarnings[committedCleanupWarnings.length - 1] || null;
  return {
    ok: committedCleanupWarnings.length === 0,
    reason: latest ? 'durable-storage-cleanup-degraded' : null,
    count: committedCleanupWarnings.length,
    latest: latest && { component: latest.component, phase: latest.phase, code: latest.code },
  };
}

function resetCommittedCleanupHealthForTest() {
  committedCleanupWarnings.length = 0;
}

function exactLstat(fsImpl, target) {
  return fsImpl.lstatSync(target, { bigint: true });
}

function exactFstat(fsImpl, descriptor) {
  return fsImpl.fstatSync(descriptor, { bigint: true });
}

function hasStableIdentity(stat) {
  return !!stat && typeof stat.dev === 'bigint' && typeof stat.ino === 'bigint'
    && stat.dev > 0n && stat.ino > 0n;
}

function singleLinkRegularFile(stat) {
  return hasStableIdentity(stat) && typeof stat.size === 'bigint'
    && stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1n;
}

function stableDirectory(stat) {
  return hasStableIdentity(stat) && stat.isDirectory() && !stat.isSymbolicLink();
}

function sameStatTime(left, right, name) {
  const ns = `${name}Ns`;
  if (left[ns] !== undefined || right[ns] !== undefined) {
    return left[ns] !== undefined && right[ns] !== undefined && left[ns] === right[ns];
  }
  const ms = `${name}Ms`;
  return left[ms] !== undefined && right[ms] !== undefined && left[ms] === right[ms];
}

function sameFileIdentity(left, right) {
  return singleLinkRegularFile(left) && singleLinkRegularFile(right)
    && left.dev === right.dev && left.ino === right.ino;
}

function sameFileSnapshot(left, right) {
  return sameFileIdentity(left, right) && left.size === right.size
    && sameStatTime(left, right, 'mtime') && sameStatTime(left, right, 'ctime');
}

function sameDirectoryIdentity(left, right) {
  return stableDirectory(left) && stableDirectory(right)
    && left.dev === right.dev && left.ino === right.ino;
}

function readBoundedOwnerFile(ownerPath, before, fsImpl) {
  if (!singleLinkRegularFile(before) || before.size <= 0n || before.size > MAX_OWNER_BYTES_BIGINT) {
    throw new Error('file-mutation lock owner size is invalid');
  }
  const noFollow = fs.constants.O_NOFOLLOW || 0;
  let fd;
  try {
    fd = fsImpl.openSync(ownerPath, fs.constants.O_RDONLY | noFollow);
    const opened = exactFstat(fsImpl, fd);
    if (!sameFileSnapshot(before, opened)) throw new Error('file-mutation lock owner changed while opening');
    const output = Buffer.alloc(MAX_OWNER_BYTES + 1);
    let offset = 0;
    while (offset < output.length) {
      const count = fsImpl.readSync(fd, output, offset, output.length - offset, null);
      if (!count) break;
      offset += count;
    }
    const after = exactFstat(fsImpl, fd);
    if (offset > MAX_OWNER_BYTES || BigInt(offset) !== opened.size
        || !sameFileSnapshot(opened, after)) throw new Error('file-mutation lock owner changed while reading');
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
  const directoryStat = exactLstat(fsImpl, lockPath);
  if (!stableDirectory(directoryStat)) return null;
  const entries = fsImpl.readdirSync(lockPath);
  if (entries.length !== 1) return null;
  const match = OWNER_FILE_PATTERN.exec(entries[0]);
  if (!match) return null;
  const ownerName = entries[0];
  const ownerPath = path.join(lockPath, ownerName);
  const ownerStat = exactLstat(fsImpl, ownerPath);
  if (!singleLinkRegularFile(ownerStat)) return null;
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
    && sameFileSnapshot(left.ownerStat, right.ownerStat));
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
    quarantineAndRemoveOwnerDirectory(options.fsImpl, lockPath, current, options);
    releasedOwnerTokens.delete(before.owner.token);
    return true;
  } catch (cause) {
    // Another contender may have completed the same exact dead-owner reclaim
    // after our proof. A missing path means there is nothing left for this
    // process to delete; retry the exclusive acquisition instead of turning
    // normal contention into a storage failure.
    if (cause && cause.code === 'ENOENT') {
      releasedOwnerTokens.delete(before.owner.token);
      return true;
    }
    const error = new Error('file-mutation lock reclaim cleanup failed');
    error.code = 'FILE_MUTATION_LOCK_CLEANUP';
    error.cause = cause;
    if (cause && cause.retainedPath) error.retainedPath = cause.retainedPath;
    throw error;
  }
}

function reclaimEmptyLockDirectory(targetPath, options) {
  const lockPath = lockPathFor(targetPath);
  let before;
  try {
    before = exactLstat(options.fsImpl, lockPath);
    if (!stableDirectory(before) || options.fsImpl.readdirSync(lockPath).length !== 0) return false;
  } catch {
    return false;
  }
  if (options.onBeforeEmptyReclaim) options.onBeforeEmptyReclaim({ lockPath });
  const quarantine = `${lockPath}.empty-cleanup.${crypto.randomBytes(24).toString('hex')}`;
  try {
    const current = exactLstat(options.fsImpl, lockPath);
    if (!sameDirectoryIdentity(before, current) || options.fsImpl.readdirSync(lockPath).length !== 0) return false;
    options.fsImpl.renameSync(lockPath, quarantine);
    const quarantined = exactLstat(options.fsImpl, quarantine);
    if (!sameDirectoryIdentity(current, quarantined)
        || options.fsImpl.readdirSync(quarantine).length !== 0) {
      throw lockCleanupError('empty lock directory changed during cleanup quarantine', quarantine);
    }
    removeExactEmptyDirectory(options.fsImpl, quarantine, quarantined, options);
    fsyncDirectoryBestEffort(options.fsImpl, path.dirname(lockPath));
    return true;
  } catch (error) {
    if (error && error.code === 'FILE_MUTATION_LOCK_CLEANUP') throw error;
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
    const expected = {
      directoryStat: lock.directoryStat,
      ownerStat: lock.ownerStat,
      ownerName: lock.ownerName,
      contents: lock.contents,
    };
    if (lock.cleanupPath) {
      removeQuarantinedOwnerDirectory(lock.fsImpl, lock.cleanupPath, expected, lock.cleanupOptions || {});
      lock.cleanupPath = '';
      lock.released = true;
      if (ownerToken) releasedOwnerTokens.delete(ownerToken);
      return;
    }
    const current = readOwnerSnapshot(lock.lockPath, lock.fsImpl);
    if (current && !sameSnapshot(expected, current)) {
      // Our exact owner has already gone and another writer owns this path.
      // Treat our release as complete without touching the replacement.
      lock.released = true;
      if (ownerToken) releasedOwnerTokens.delete(ownerToken);
      return;
    }
    if (!current) {
      throw new Error('file-mutation lock cleanup did not complete');
    }
    quarantineAndRemoveOwnerDirectory(lock.fsImpl, lock.lockPath, current, lock.cleanupOptions || {});
    lock.released = true;
    if (ownerToken) releasedOwnerTokens.delete(ownerToken);
  } catch (cause) {
    if (cause && cause.retainedPath) lock.cleanupPath = cause.retainedPath;
    let exactOwnerRemains = false;
    try {
      const remaining = readOwnerSnapshot(lock.cleanupPath || lock.lockPath, lock.fsImpl);
      exactOwnerRemains = !!(remaining && remaining.owner.token === ownerToken);
    } catch {}
    if (ownerToken && exactOwnerRemains) releasedOwnerTokens.add(ownerToken);
    else if (ownerToken) releasedOwnerTokens.delete(ownerToken);
    const error = new Error('file-mutation lock cleanup failed');
    error.code = 'FILE_MUTATION_LOCK_CLEANUP';
    error.cause = cause;
    if (lock.cleanupPath) error.retainedPath = lock.cleanupPath;
    throw error;
  }
}

function lockCleanupError(message, retainedPath = '', cause = null) {
  const error = new Error(message);
  error.code = 'FILE_MUTATION_LOCK_CLEANUP';
  if (retainedPath) error.retainedPath = retainedPath;
  if (cause) error.cause = cause;
  return error;
}

function pathStillExists(fsImpl, target) {
  try {
    exactLstat(fsImpl, target);
    return true;
  } catch (error) {
    if (error && error.code === 'ENOENT') return false;
    throw error;
  }
}

function sameOpenFileArtifact(left, right) {
  return !!left && !!right && left.isFile() && right.isFile()
    && left.dev > 0n && left.ino > 0n
    && left.dev === right.dev && left.ino === right.ino
    && left.size === right.size && sameStatTime(left, right, 'mtime');
}

function removeExactOwnerFile(fsImpl, ownerPath, expected, options = {}) {
  if ((options.platform || process.platform) !== 'win32') {
    const current = exactLstat(fsImpl, ownerPath);
    if (!sameFileSnapshot(expected, current)) {
      throw lockCleanupError('quarantined lock owner changed before cleanup', path.dirname(ownerPath));
    }
    fsImpl.unlinkSync(ownerPath);
    return;
  }
  const current = exactLstat(fsImpl, ownerPath);
  if (!sameFileSnapshot(expected, current)) {
    throw lockCleanupError('quarantined lock owner changed before cleanup', path.dirname(ownerPath));
  }
  const noFollow = fs.constants.O_NOFOLLOW || 0;
  let stableFd;
  let deleteFd;
  let rescue = '';
  let deleting = null;
  try {
    stableFd = fsImpl.openSync(ownerPath, fs.constants.O_RDWR | noFollow);
    const stable = exactFstat(fsImpl, stableFd);
    if (!sameFileSnapshot(expected, stable)) {
      throw lockCleanupError('quarantined lock owner changed while opening', path.dirname(ownerPath));
    }
    deleteFd = fsImpl.openSync(ownerPath, fs.constants.O_RDWR | WINDOWS_O_TEMPORARY | noFollow);
    deleting = exactFstat(fsImpl, deleteFd);
    if (!sameFileSnapshot(expected, deleting)) {
      rescue = `${ownerPath}.delete-mismatch.${crypto.randomBytes(24).toString('hex')}`;
      fsImpl.linkSync(ownerPath, rescue);
      const rescued = exactLstat(fsImpl, rescue);
      if (!sameOpenFileArtifact(deleting, rescued)) {
        throw lockCleanupError('changed lock owner could not be retained', rescue);
      }
    }
    if (options.onBeforeExactOwnerDeleteClose) {
      options.onBeforeExactOwnerDeleteClose({ ownerPath, expected, descriptor: deleteFd });
    }
    fsImpl.closeSync(deleteFd);
    deleteFd = undefined;
    fsImpl.closeSync(stableFd);
    stableFd = undefined;
    fsyncDirectoryBestEffort(fsImpl, path.dirname(ownerPath));
    if (rescue) throw lockCleanupError('changed lock owner was retained', path.dirname(ownerPath));
    if (pathStillExists(fsImpl, ownerPath)) {
      throw lockCleanupError('lock owner pathname replacement was retained', path.dirname(ownerPath));
    }
  } catch (error) {
    if (deleteFd !== undefined && deleting && !rescue) {
      try {
        const recovery = `${ownerPath}.delete-error-retain.${crypto.randomBytes(24).toString('hex')}`;
        fsImpl.linkSync(ownerPath, recovery);
        const recovered = exactLstat(fsImpl, recovery);
        if (sameOpenFileArtifact(deleting, recovered)) rescue = recovery;
      } catch {}
    }
    throw error;
  } finally {
    if (deleteFd !== undefined) try { fsImpl.closeSync(deleteFd); } catch {}
    if (stableFd !== undefined) try { fsImpl.closeSync(stableFd); } catch {}
  }
}

function removeExactEmptyDirectory(fsImpl, directory, expected, options = {}) {
  if ((options.platform || process.platform) !== 'win32') {
    const current = exactLstat(fsImpl, directory);
    if (!sameDirectoryIdentity(expected, current) || fsImpl.readdirSync(directory).length !== 0) {
      throw lockCleanupError('quarantined lock directory changed before cleanup', directory);
    }
    fsImpl.rmdirSync(directory);
    return;
  }
  const current = exactLstat(fsImpl, directory);
  if (!sameDirectoryIdentity(expected, current) || fsImpl.readdirSync(directory).length !== 0) {
    throw lockCleanupError('quarantined lock directory changed before cleanup', directory);
  }
  let stableFd;
  let deleteFd;
  let rescue = '';
  try {
    stableFd = fsImpl.openSync(directory, fs.constants.O_RDONLY);
    const stable = exactFstat(fsImpl, stableFd);
    if (!sameDirectoryIdentity(expected, stable)) {
      throw lockCleanupError('quarantined lock directory changed while opening', directory);
    }
    deleteFd = fsImpl.openSync(directory, fs.constants.O_RDONLY | WINDOWS_O_TEMPORARY);
    const deleting = exactFstat(fsImpl, deleteFd);
    if (!sameDirectoryIdentity(expected, deleting)) {
      rescue = `${directory}.delete-mismatch.${crypto.randomBytes(24).toString('hex')}`;
      fsImpl.renameSync(directory, rescue);
      const rescued = exactLstat(fsImpl, rescue);
      if (!sameDirectoryIdentity(deleting, rescued)) {
        throw lockCleanupError('changed lock directory could not be retained', rescue);
      }
      const marker = path.join(rescue, `.retain.${crypto.randomBytes(24).toString('hex')}`);
      fsImpl.writeFileSync(marker, '', { flag: 'wx', mode: 0o600 });
    }
    if (options.onBeforeExactDirectoryDeleteClose) {
      options.onBeforeExactDirectoryDeleteClose({ directory, expected, descriptor: deleteFd });
    }
    fsImpl.closeSync(deleteFd);
    deleteFd = undefined;
    fsImpl.closeSync(stableFd);
    stableFd = undefined;
    fsyncDirectoryBestEffort(fsImpl, path.dirname(directory));
    if (rescue) throw lockCleanupError('changed lock directory was retained', rescue);
    if (pathStillExists(fsImpl, directory)) {
      throw lockCleanupError('lock directory pathname replacement was retained', directory);
    }
  } catch (error) {
    if (deleteFd !== undefined && !rescue) {
      try {
        const marker = path.join(directory, `.delete-error-retain.${crypto.randomBytes(24).toString('hex')}`);
        fsImpl.writeFileSync(marker, '', { flag: 'wx', mode: 0o600 });
      } catch {}
    }
    throw error;
  } finally {
    if (deleteFd !== undefined) try { fsImpl.closeSync(deleteFd); } catch {}
    if (stableFd !== undefined) try { fsImpl.closeSync(stableFd); } catch {}
  }
}

function removeQuarantinedOwnerDirectory(fsImpl, directory, expected, options = {}) {
  let ownerRemoved = false;
  for (let attempt = 0; attempt < CLEANUP_RETRIES; attempt += 1) {
    if (!ownerRemoved) {
      let current;
      try { current = readOwnerSnapshot(directory, fsImpl); } catch (error) {
        throw lockCleanupError('quarantined lock owner could not be verified', directory, error);
      }
      if (!current) {
        let directoryStat;
        let entries;
        try {
          directoryStat = exactLstat(fsImpl, directory);
          entries = fsImpl.readdirSync(directory);
        } catch (error) {
          if (error && error.code === 'ENOENT') return true;
          throw lockCleanupError('quarantined lock owner could not be verified', directory, error);
        }
        if (!sameDirectoryIdentity(expected.directoryStat, directoryStat) || entries.length !== 0) {
          throw lockCleanupError('quarantined lock owner changed before cleanup', directory);
        }
        ownerRemoved = true;
      } else if (!sameSnapshot(expected, current)) {
        throw lockCleanupError('quarantined lock owner changed before cleanup', directory);
      } else {
        try {
          removeExactOwnerFile(fsImpl, current.ownerPath, current.ownerStat, options);
          ownerRemoved = true;
        } catch (error) {
          if (error && error.code === 'ENOENT') ownerRemoved = true;
        }
      }
    }
    if (ownerRemoved) {
      let directoryStat;
      let entries;
      try {
        directoryStat = exactLstat(fsImpl, directory);
        entries = fsImpl.readdirSync(directory);
      } catch (error) {
        if (error && error.code === 'ENOENT') return true;
        throw lockCleanupError('quarantined lock directory could not be verified', directory, error);
      }
      if (!sameDirectoryIdentity(expected.directoryStat, directoryStat) || entries.length !== 0) {
        throw lockCleanupError('quarantined lock directory changed before cleanup', directory);
      }
      try {
        removeExactEmptyDirectory(fsImpl, directory, directoryStat, options);
        fsyncDirectoryBestEffort(fsImpl, path.dirname(directory));
        return true;
      } catch (error) {
        if (error && error.code === 'ENOENT') return true;
      }
    }
    if (attempt + 1 < CLEANUP_RETRIES) {
      Atomics.wait(LOCK_SLEEP, 0, 0, CLEANUP_RETRY_MS);
    }
  }
  throw lockCleanupError('quarantined lock cleanup did not complete', directory);
}

function quarantineAndRemoveOwnerDirectory(fsImpl, directory, expected, options = {}) {
  const quarantine = `${directory}.cleanup.${crypto.randomBytes(24).toString('hex')}`;
  let quarantined = false;
  let lastError = null;
  for (let attempt = 0; attempt < CLEANUP_RETRIES; attempt += 1) {
    let current;
    try { current = readOwnerSnapshot(directory, fsImpl); }
    catch (error) {
      if (error && error.code === 'ENOENT') return true;
      throw lockCleanupError('lock directory could not be verified before quarantine', directory, error);
    }
    if (!current) {
      try { exactLstat(fsImpl, directory); }
      catch (error) {
        if (error && error.code === 'ENOENT') return true;
      }
      return false;
    }
    if (!sameSnapshot(expected, current)) return false;
    try {
      fsImpl.renameSync(directory, quarantine);
      quarantined = true;
      fsyncDirectoryBestEffort(fsImpl, path.dirname(directory));
      break;
    } catch (error) {
      if (error && error.code === 'ENOENT') return true;
      lastError = error;
      if (!error || !['EBUSY', 'EPERM', 'EACCES'].includes(error.code)) break;
      if (attempt + 1 < CLEANUP_RETRIES) {
        Atomics.wait(LOCK_SLEEP, 0, 0, CLEANUP_RETRY_MS);
      }
    }
  }
  if (!quarantined) {
    throw lockCleanupError('lock directory could not be quarantined for cleanup', directory, lastError);
  }
  let current;
  try { current = readOwnerSnapshot(quarantine, fsImpl); }
  catch (error) {
    throw lockCleanupError('quarantined lock owner could not be verified', quarantine, error);
  }
  if (!sameSnapshot(expected, current)) {
    throw lockCleanupError('lock directory changed during cleanup quarantine', quarantine);
  }
  return removeQuarantinedOwnerDirectory(fsImpl, quarantine, current, options);
}

function cleanupOwnedDirectory(fsImpl, directory, ownerName, contents, options = {}) {
  let current;
  try { current = readOwnerSnapshot(directory, fsImpl); } catch { return false; }
  if (!current || current.ownerName !== ownerName || current.contents !== contents) return false;
  quarantineAndRemoveOwnerDirectory(fsImpl, directory, current, options);
  return true;
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
    const directoryBefore = exactLstat(options.fsImpl, lockPath);
    if (!stableDirectory(directoryBefore)) throw new Error('file-mutation lock directory has no stable identity');
    const ownerPath = path.join(lockPath, ownerName);
    const ownerPathStat = exactLstat(options.fsImpl, ownerPath);
    if (!singleLinkRegularFile(ownerPathStat)
        || ownerPathStat.size !== BigInt(Buffer.byteLength(contents))) {
      throw new Error('file-mutation lock owner changed before opening');
    }
    const noFollow = fs.constants.O_NOFOLLOW || 0;
    fd = options.fsImpl.openSync(ownerPath, fs.constants.O_RDONLY | noFollow);
    const ownerStat = exactFstat(options.fsImpl, fd);
    if (!sameFileSnapshot(ownerPathStat, ownerStat)) {
      throw new Error('file-mutation lock owner changed while opening');
    }
    const directoryStat = exactLstat(options.fsImpl, lockPath);
    if (!sameDirectoryIdentity(directoryBefore, directoryStat)) {
      throw new Error('file-mutation lock directory changed while opening owner');
    }
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
      cleanupOptions: options,
      released: false,
    };
  } catch (error) {
    if (fd !== undefined) try { options.fsImpl.closeSync(fd); } catch { /* best effort */ }
    const cleaned = published
      ? cleanupOwnedDirectory(options.fsImpl, lockPath, ownerName, contents, options)
      : cleanupOwnedDirectory(options.fsImpl, tempPath, ownerName, contents, options);
    if (!cleaned) {
      const cleanupError = new Error('file-mutation lock cleanup failed');
      cleanupError.code = 'FILE_MUTATION_LOCK_CLEANUP';
      cleanupError.cause = error;
      cleanupError.retainedPath = published ? lockPath : tempPath;
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
  let callbackFailed = false;
  let callbackError;
  let result;
  try {
    result = callback();
    if (result && typeof result.then === 'function') {
      throw new TypeError('synchronous file mutation callback returned a promise');
    }
  } catch (error) {
    callbackFailed = true;
    callbackError = error;
  }
  if (callbackFailed) {
    try { releaseFileMutationLock(lock); }
    catch (cleanupError) {
      if ((typeof callbackError === 'object' && callbackError !== null)
          || typeof callbackError === 'function') {
        try { callbackError.cleanupError = cleanupError; } catch { /* preserve the callback's thrown value */ }
      }
    }
    throw callbackError;
  }
  try { releaseFileMutationLock(lock); }
  catch (cleanupError) { committedCleanupWarning(cleanupError, options); }
  return result;
}

async function withFileMutationLock(targetPath, callback, options = {}) {
  const lock = await acquireFileMutationLock(targetPath, options);
  let callbackFailed = false;
  let callbackError;
  let result;
  try {
    result = await callback();
  } catch (error) {
    callbackFailed = true;
    callbackError = error;
  }
  if (callbackFailed) {
    try { releaseFileMutationLock(lock); }
    catch (cleanupError) {
      if ((typeof callbackError === 'object' && callbackError !== null)
          || typeof callbackError === 'function') {
        try { callbackError.cleanupError = cleanupError; } catch { /* preserve the callback's thrown value */ }
      }
    }
    throw callbackError;
  }
  try { releaseFileMutationLock(lock); }
  catch (cleanupError) { committedCleanupWarning(cleanupError, options); }
  return result;
}

module.exports = {
  lockPathFor,
  acquireFileMutationLock,
  acquireFileMutationLockSync,
  releaseFileMutationLock,
  withFileMutationLock,
  withFileMutationLockSync,
  committedCleanupHealth,
  notifyCommittedCleanupWarning: committedCleanupWarning,
  _setContentionObserverForTest: setContentionObserverForTest,
  _resetCommittedCleanupHealthForTest: resetCommittedCleanupHealthForTest,
  _internal: {
    linuxGeneration,
    normalizedGeneration,
    ownerFileName,
    parseOwner,
    procStatStartTime,
    releasedOwnerTokenCount: () => releasedOwnerTokens.size,
  },
};
