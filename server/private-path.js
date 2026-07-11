'use strict';

/**
 * One private-file contract for the control plane and packaged Node sensors.
 * Windows paths are restricted to the current owner plus LocalSystem and then
 * inspected; POSIX paths use owner-only modes. Bounded reads stay attached to
 * one no-follow handle and never allocate or consume more than maxBytes + 1.
 */
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const fileMutationLock = require('./file-mutation-lock');

const PRIVATE_DIRECTORY_LOCK_TARGET = '.redactwall-private-directory';
const PRIVATE_DIRECTORY_LOCK_TIMEOUT_MS = 30_000;
const WINDOWS_PRIVATE_LOCK_ROOT = '.redactwall-private-locks';
const WINDOWS_LOCAL_SYSTEM_SID = 'S-1-5-18';
const WINDOWS_OWNER_PATH_ENV = 'REDACTWALL_PRIVATE_OWNER_PATH';
const WINDOWS_OWNER_CACHE_LIMIT = 512;
const WINDOWS_SECURITY_STABILITY_ATTEMPTS = 8;
const _windowsOwnerCache = new Map();
let _windowsPrincipalCache = '';
const WINDOWS_OWNER_INSPECTION_SCRIPT = Buffer.from([
  "$ErrorActionPreference = 'Stop'",
  '[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)',
  '$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()',
  `$ownerPath = $env:${WINDOWS_OWNER_PATH_ENV}`,
  '$section = [System.Security.AccessControl.AccessControlSections]::Owner',
  'if ([System.IO.Directory]::Exists($ownerPath)) { $acl = [System.IO.Directory]::GetAccessControl($ownerPath, $section) } elseif ([System.IO.File]::Exists($ownerPath)) { $acl = [System.IO.File]::GetAccessControl($ownerPath, $section) } else { throw "private path does not exist" }',
  '$owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value',
  "[Console]::Out.Write('redactwall-owner-v1|' + $identity.User.Value + '|' + $owner)",
].join('; '), 'utf16le').toString('base64');

function windowsPrincipal(spawn = spawnSync, label = 'private path') {
  if (spawn === spawnSync && _windowsPrincipalCache) return _windowsPrincipalCache;
  let result;
  try {
    result = spawn('whoami.exe', [], { encoding: 'utf8', windowsHide: true });
  } catch (error) {
    result = { error };
  }
  const principal = String(result?.stdout || '').trim();
  if (!result || result.error || result.status !== 0 || !principal) {
    const detail = String(result?.stderr || result?.error?.message || 'no principal returned').trim();
    throw new Error(`failed to identify the ${label} owner with whoami: ${detail}`);
  }
  if (spawn === spawnSync) _windowsPrincipalCache = principal;
  return principal;
}

function checkedIcacls(spawn, args, target, label = '') {
  let result;
  try {
    result = spawn('icacls.exe', args, { encoding: 'utf8', windowsHide: true });
  } catch (error) {
    result = { error };
  }
  if (result && !result.error && result.status === 0) return;
  const detail = String(result?.stderr || result?.error?.message || 'unknown error').trim();
  const subject = label || target;
  throw new Error(`failed to secure ${subject} with icacls: ${detail}`);
}

function privateAclListing(listing, principal) {
  const lines = String(listing || '').toLowerCase().split(/\r?\n/)
    .filter((line) => /:\s*(?:\([^)]*\))+/.test(line));
  if (lines.length !== 2 || lines.some((line) => {
    const flags = [...line.matchAll(/\(([^)]*)\)/g)].map((match) => match[1]);
    return !flags.includes('f') || flags.some((flag) => !['oi', 'ci', 'f'].includes(flag));
  })) return false;
  const owner = String(principal || '').toLowerCase();
  const ownerLine = lines.some((line) => line.includes(`${owner}:`));
  const systemLine = lines.some((line) => line.includes('nt authority\\system:') || line.includes('s-1-5-18:'));
  return !!owner && ownerLine && systemLine;
}

function normalizeWindowsSid(value) {
  const sid = String(value || '').trim().toUpperCase();
  return /^S-\d+(?:-\d+)+$/.test(sid) ? sid : '';
}

function cleanWindowsPowerShellEnvironment(target) {
  const env = { ...process.env };
  for (const key of Object.keys(env)) {
    if (key.toLowerCase() === 'psmodulepath') delete env[key];
  }
  env[WINDOWS_OWNER_PATH_ENV] = path.resolve(target);
  return env;
}

function windowsOwnerIdentity(target, spawn = spawnSync, label = 'private path') {
  let result;
  try {
    result = spawn('powershell.exe', [
      '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', WINDOWS_OWNER_INSPECTION_SCRIPT,
    ], {
      encoding: 'utf8',
      windowsHide: true,
      env: cleanWindowsPowerShellEnvironment(target),
    });
  } catch (error) {
    result = { error };
  }
  const match = String(result?.stdout || '').trim().match(
    /^redactwall-owner-v1\|(S-\d+(?:-\d+)+)\|(S-\d+(?:-\d+)+)$/i,
  );
  if (!result || result.error || result.status !== 0 || !match) {
    const detail = String(result?.stderr || result?.error?.message || 'no owner SID returned')
      .replace(/\s+/g, ' ').trim().slice(0, 240);
    throw new Error(`failed to inspect the ${label} owner: ${detail}`);
  }
  return { processSid: normalizeWindowsSid(match[1]), ownerSid: normalizeWindowsSid(match[2]) };
}

function windowsOwnerStamp(stat) {
  return [stat.dev, stat.ino, stat.birthtimeMs, stat.ctimeMs, stat.mode].join(':');
}

function cacheWindowsOwner(target, stamp, identity) {
  const key = path.resolve(target).toLowerCase();
  _windowsOwnerCache.delete(key);
  _windowsOwnerCache.set(key, { stamp, identity });
  if (_windowsOwnerCache.size > WINDOWS_OWNER_CACHE_LIMIT) {
    _windowsOwnerCache.delete(_windowsOwnerCache.keys().next().value);
  }
}

function resolvedOwnerIdentity(target, options, spawn, stat) {
  const supplied = typeof options.ownerIdentity === 'function'
    ? options.ownerIdentity(target)
    : options.ownerIdentity;
  let identity = supplied;
  const stamp = stat && spawn === spawnSync ? windowsOwnerStamp(stat) : '';
  const key = stamp ? path.resolve(target).toLowerCase() : '';
  if (!identity && stamp) {
    const cached = _windowsOwnerCache.get(key);
    if (cached?.stamp === stamp) identity = cached.identity;
  }
  if (!identity) {
    identity = windowsOwnerIdentity(target, spawn, options.ownerLabel || options.label);
    if (stamp) cacheWindowsOwner(target, stamp, identity);
  }
  const processSid = normalizeWindowsSid(identity?.processSid);
  const ownerSid = normalizeWindowsSid(identity?.ownerSid);
  if (!processSid || !ownerSid) throw new Error(`${options.label || 'private path'} Windows owner verification failed`);
  return { processSid, ownerSid };
}

function privateWindowsOwner(identity) {
  return identity.ownerSid === identity.processSid || identity.ownerSid === WINDOWS_LOCAL_SYSTEM_SID;
}

function assertPrivateWindowsOwner(target, options = {}, spawn = spawnSync, stat) {
  if (!privateWindowsOwner(resolvedOwnerIdentity(target, options, spawn, stat))) {
    throw new Error(`${options.label || 'private path'} Windows owner verification failed`);
  }
  return target;
}

function privateAclFingerprint(listing) {
  return String(listing || '').toLowerCase().split(/\r?\n/)
    .filter((line) => /:\s*(?:\([^)]*\))+/.test(line))
    .map((line) => line.trim().replace(/\s+/g, ' '))
    .sort().join('\n');
}

function privateWindowsSecurityFingerprint(target, principal, spawn, options, stat) {
  const fingerprint = privateWindowsDaclFingerprint(target, principal, spawn);
  if (!fingerprint) return '';
  const identity = resolvedOwnerIdentity(target, options, spawn, stat);
  if (!privateWindowsOwner(identity)) return '';
  return `${identity.processSid}|${identity.ownerSid}|${fingerprint}`;
}

function privateWindowsDaclFingerprint(target, principal, spawn) {
  let result;
  try {
    result = spawn('icacls.exe', [target], { encoding: 'utf8', windowsHide: true });
  } catch (error) {
    result = { error };
  }
  if (!result || result.error || result.status !== 0 || !privateAclListing(result.stdout, principal)) return '';
  return privateAclFingerprint(result.stdout);
}

function inspectPrivateWindowsPath(target, principal, spawn = spawnSync, options = {}, stat) {
  return !!privateWindowsSecurityFingerprint(target, principal, spawn, options, stat);
}

function pathStat(target, options = {}) {
  const fsImpl = options.fs || fs;
  const stat = fsImpl.lstatSync(target);
  const directory = options.directory ?? stat.isDirectory();
  if (stat.isSymbolicLink() || (directory ? !stat.isDirectory() : !stat.isFile())) {
    throw new Error(`${options.label || 'private path'} is not a safe regular ${directory ? 'directory' : 'file'}`);
  }
  if (!directory && stat.nlink && stat.nlink !== 1) {
    throw new Error(`${options.label || 'private path'} must have exactly one link`);
  }
  return { stat, directory, fsImpl };
}

function restrictPrivatePath(target, options = {}) {
  const { stat, directory, fsImpl } = pathStat(target, options);
  const platform = options.platform || process.platform;
  if (platform !== 'win32') {
    fsImpl.chmodSync(target, directory ? 0o700 : 0o600);
    return target;
  }
  const spawn = options.spawn || spawnSync;
  const principal = options.principal || windowsPrincipal(spawn, options.ownerLabel || 'private path');
  const inheritance = directory ? '(OI)(CI)' : '';
  if (options.fresh === true) {
    checkedIcacls(spawn, [target, '/setowner', principal, '/q'], target, options.label);
  } else {
    assertPrivateWindowsOwner(target, options, spawn, stat);
  }
  checkedIcacls(spawn, [target, '/reset', '/q'], target, options.label);
  checkedIcacls(spawn, [
    target, '/inheritance:r', '/grant:r',
    `${principal}:${inheritance}(F)`, `*S-1-5-18:${inheritance}(F)`, '/q',
  ], target, options.label);
  return target;
}

function assertPrivatePath(target, options = {}) {
  const { stat, directory } = pathStat(target, options);
  const platform = options.platform || process.platform;
  if (platform !== 'win32') {
    if ((stat.mode & 0o077) !== 0) throw new Error(`${options.label || 'private path'} permissions are too broad`);
    return target;
  }
  const spawn = options.spawn || spawnSync;
  const principal = options.principal || windowsPrincipal(spawn, options.ownerLabel || 'private path');
  let before = stat;
  let previousSecurity = '';
  for (let attempt = 0; attempt < WINDOWS_SECURITY_STABILITY_ATTEMPTS; attempt += 1) {
    const security = privateWindowsSecurityFingerprint(target, principal, spawn, options, before);
    if (!security) {
      throw new Error(`${options.label || 'private path'} Windows ACL verification failed`);
    }
    const after = pathStat(target, { ...options, directory }).stat;
    if (!sameIdentity(before, after)) {
      throw new Error(`${options.label || 'private path'} changed during Windows security verification`);
    }
    if (before.ctimeMs === after.ctimeMs) return target;
    // Directory entry creation changes directory ctime even when its security
    // descriptor does not. Two equal complete ACL+owner snapshots on the same
    // inode distinguish that expected churn from security-descriptor drift.
    if (directory && previousSecurity && previousSecurity === security) return target;
    previousSecurity = security;
    before = after;
  }
  throw new Error(`${options.label || 'private path'} changed during Windows security verification`);
}

// Recheck the complete DACL and path identity after a full owner+ACL proof has
// established a trusted parent. This intentionally does not replace the full
// assertion at startup; it carries that proof across entry churn without a
// redundant PowerShell owner process on every commit.
function assertPrivatePathDacl(target, options = {}) {
  const { stat, directory } = pathStat(target, options);
  const platform = options.platform || process.platform;
  if (platform !== 'win32') {
    if ((stat.mode & 0o077) !== 0) throw new Error(`${options.label || 'private path'} permissions are too broad`);
    return target;
  }
  const spawn = options.spawn || spawnSync;
  const principal = options.principal || windowsPrincipal(spawn, options.ownerLabel || 'private path');
  let before = stat;
  let previousSecurity = '';
  for (let attempt = 0; attempt < WINDOWS_SECURITY_STABILITY_ATTEMPTS; attempt += 1) {
    const security = privateWindowsDaclFingerprint(target, principal, spawn);
    if (!security) throw new Error(`${options.label || 'private path'} Windows ACL verification failed`);
    const after = pathStat(target, { ...options, directory }).stat;
    if (!sameIdentity(before, after)) {
      throw new Error(`${options.label || 'private path'} changed during Windows security verification`);
    }
    if (before.ctimeMs === after.ctimeMs) return target;
    if (directory && previousSecurity && previousSecurity === security) return target;
    previousSecurity = security;
    before = after;
  }
  throw new Error(`${options.label || 'private path'} changed during Windows security verification`);
}

function securePrivatePath(target, options = {}) {
  restrictPrivatePath(target, options);
  assertPrivatePath(target, options);
  return target;
}

// A file created exclusively inside an already-verified private directory has
// exactly the directory's two inherited ACEs. Protect that inherited DACL,
// converting it to explicit ACEs, then verify the complete owner and ACL
// contract. Callers must verify and retain control of the parent before create.
function protectInheritedPrivateFile(target, options = {}) {
  const { directory, fsImpl } = pathStat(target, { ...options, directory: false });
  if (directory) throw new Error(`${options.label || 'private file'} is not a safe regular file`);
  const platform = options.platform || process.platform;
  if (platform !== 'win32') {
    fsImpl.chmodSync(target, 0o600);
    return assertPrivatePath(target, { ...options, fs: fsImpl, directory: false });
  }
  const spawn = options.spawn || spawnSync;
  const principal = options.principal || windowsPrincipal(spawn, options.ownerLabel || 'private file');
  checkedIcacls(spawn, [target, '/setowner', principal, '/q'], target, options.label);
  checkedIcacls(spawn, [target, '/inheritance:d', '/q'], target, options.label);
  const verification = {
    ...options,
    fs: fsImpl,
    directory: false,
    principal,
  };
  return options.verifyOwner === false
    ? assertPrivatePathDacl(target, verification)
    : assertPrivatePath(target, verification);
}

function mutationLockOptions(options, fsImpl) {
  return {
    ...options,
    ...(options.lockOptions || {}),
    lockTimeoutMs: options.lockTimeoutMs
      ?? options.lockOptions?.lockTimeoutMs
      ?? PRIVATE_DIRECTORY_LOCK_TIMEOUT_MS,
    fs: fsImpl,
  };
}

function windowsPrivateLockRoot(options = {}) {
  return path.resolve(options.privateLockRoot
    || path.join(os.homedir(), WINDOWS_PRIVATE_LOCK_ROOT));
}

function privateDirectoryLockTarget(directory, options = {}) {
  const resolved = path.resolve(directory);
  if ((options.platform || process.platform) !== 'win32') {
    return path.join(resolved, PRIVATE_DIRECTORY_LOCK_TARGET);
  }
  const identity = resolved.toLowerCase();
  const digest = crypto.createHash('sha256').update(identity).digest('hex');
  return path.join(windowsPrivateLockRoot(options), `directory-${digest}`);
}

function untrustedDirectoryError(label = 'private directory') {
  const error = new Error(`${label} contains state from before its permissions were trusted`);
  error.code = 'PRIVATE_DIRECTORY_UNTRUSTED_STATE';
  return error;
}

function assertEmptyUntrustedDirectory(directory, lockTarget, options) {
  const fsImpl = options.fs || fs;
  const lockPath = fileMutationLock.lockPathFor(lockTarget);
  const localLock = path.dirname(lockPath) === directory ? path.basename(lockPath) : '';
  const entries = fsImpl.readdirSync(directory).filter((entry) => {
    if (!localLock) return true;
    if (entry === localLock) return false;
    const prefix = `${localLock}.`;
    const suffix = '.owner.tmp';
    const token = entry.startsWith(prefix) && entry.endsWith(suffix)
      ? entry.slice(prefix.length, -suffix.length)
      : '';
    return !/^[a-f0-9]{48}$/.test(token);
  });
  if (entries.length) throw untrustedDirectoryError(options.label);
}

function privateDirectoryIsTrusted(directory, options) {
  pathStat(directory, { ...options, directory: true });
  try {
    assertPrivatePath(directory, { ...options, directory: true });
    return true;
  } catch {
    return false;
  }
}

function prepareWindowsPrivateLockRoot(options = {}) {
  const fsImpl = options.fs || fs;
  const root = windowsPrivateLockRoot(options);
  const parent = path.dirname(root);
  if (parent === root) throw new Error('private bootstrap lock root must have a trusted parent');
  const security = {
    ...options,
    fs: fsImpl,
    directory: true,
    label: 'private bootstrap lock directory',
    ownerLabel: 'private bootstrap lock directory',
  };
  try {
    if (privateDirectoryIsTrusted(root, security)) return root;
  } catch (error) {
    if (!error || error.code !== 'ENOENT') throw error;
  }
  const rootDigest = crypto.createHash('sha256').update(root.toLowerCase()).digest('hex');
  const guardTarget = path.join(parent, `redactwall-private-lock-root-${rootDigest}`);
  return fileMutationLock.withFileMutationLockSync(guardTarget, () => {
    fsImpl.mkdirSync(root, { recursive: true, mode: 0o700 });
    if (privateDirectoryIsTrusted(root, security)) return root;
    assertEmptyUntrustedDirectory(root, guardTarget, security);
    securePrivatePath(root, { ...security, fresh: true });
    assertEmptyUntrustedDirectory(root, guardTarget, security);
    return root;
  }, mutationLockOptions(options, fsImpl));
}

function pendingTrustPath(lockTarget) {
  return `${lockTarget}.trust-pending`;
}

function pendingTrustExists(file, fsImpl) {
  try {
    fsImpl.lstatSync(file);
    return true;
  } catch (error) {
    if (error && error.code === 'ENOENT') return false;
    throw error;
  }
}

function pendingTrustSecurity(options, fsImpl) {
  return {
    ...options,
    fs: fsImpl,
    directory: false,
    label: 'private directory trust marker',
    ownerLabel: 'private directory trust marker',
  };
}

function validatePendingTrust(file, options) {
  const fsImpl = options.fs || fs;
  const security = pendingTrustSecurity(options, fsImpl);
  assertPrivatePath(file, security);
  const contents = readBoundedRegularFile(file, { ...security, maxBytes: 32 }).toString('utf8');
  if (contents !== 'redactwall-trust-pending-v1\n') {
    throw new Error('private directory trust marker is corrupt');
  }
}

function createPendingTrust(file, options) {
  const fsImpl = options.fs || fs;
  let fd;
  try {
    fd = fsImpl.openSync(file, 'wx', 0o600);
    fsImpl.writeFileSync(fd, 'redactwall-trust-pending-v1\n', 'utf8');
    fsImpl.fsyncSync(fd);
    fsImpl.closeSync(fd);
    fd = undefined;
    securePrivatePath(file, { ...pendingTrustSecurity(options, fsImpl), fresh: true });
    fsyncDirectory(path.dirname(file), options);
  } finally {
    if (fd !== undefined) { try { fsImpl.closeSync(fd); } catch {} }
  }
}

function clearPendingTrust(file, options) {
  const fsImpl = options.fs || fs;
  validatePendingTrust(file, options);
  fsImpl.unlinkSync(file);
  fsyncDirectory(path.dirname(file), options);
}

function establishPrivateDirectoryTrust(directory, lockTarget, options) {
  const fsImpl = options.fs || fs;
  const platform = options.platform || process.platform;
  const pending = platform === 'win32' ? pendingTrustPath(lockTarget) : '';
  const hasPending = !!pending && pendingTrustExists(pending, fsImpl);
  const trusted = privateDirectoryIsTrusted(directory, options);
  if (hasPending) {
    validatePendingTrust(pending, options);
    assertEmptyUntrustedDirectory(directory, lockTarget, options);
    if (!trusted) securePrivatePath(directory, { ...options, fresh: true });
    assertEmptyUntrustedDirectory(directory, lockTarget, options);
    clearPendingTrust(pending, options);
    return;
  }
  if (trusted) return;
  assertEmptyUntrustedDirectory(directory, lockTarget, options);
  if (pending) createPendingTrust(pending, options);
  securePrivatePath(directory, { ...options, fresh: true });
  assertEmptyUntrustedDirectory(directory, lockTarget, options);
  if (pending) clearPendingTrust(pending, options);
}

// Windows uses a lock rooted in the current user's private profile state so
// directory creation and ACL hardening happen before any target-local state is
// trusted. POSIX mkdir(0700) establishes the same boundary atomically.
function withPrivateDirectoryMutationLockSync(directory, callback, options = {}) {
  const fsImpl = options.fs || fs;
  const resolved = path.resolve(directory);
  const platform = options.platform || process.platform;
  if (platform === 'win32') prepareWindowsPrivateLockRoot({ ...options, fs: fsImpl });
  const lockTarget = privateDirectoryLockTarget(resolved, options);
  return fileMutationLock.withFileMutationLockSync(lockTarget, () => {
    fsImpl.mkdirSync(resolved, { recursive: true, mode: 0o700 });
    const security = { ...options, fs: fsImpl, directory: true };
    establishPrivateDirectoryTrust(resolved, lockTarget, security);
    const before = fsImpl.lstatSync(resolved);
    const result = callback(resolved);
    const after = fsImpl.lstatSync(resolved);
    if (!sameIdentity(before, after)) throw new Error(`${options.label || 'private directory'} changed during initialization`);
    assertPrivatePath(resolved, security);
    return result;
  }, mutationLockOptions(options, fsImpl));
}

function sameIdentity(left, right) {
  if (left.dev && right.dev && left.dev !== right.dev) return false;
  if (left.ino && right.ino && left.ino !== right.ino) return false;
  return true;
}

function readBoundedRegularFile(target, options = {}) {
  const maxBytes = Number(options.maxBytes);
  if (!Number.isInteger(maxBytes) || maxBytes <= 0) throw new TypeError('maxBytes must be a positive integer');
  const { stat: before, fsImpl } = pathStat(target, { ...options, directory: false });
  if (before.size <= 0 || before.size > maxBytes) throw new Error(`${options.label || 'private file'} has an invalid size`);
  const noFollow = fs.constants.O_NOFOLLOW || 0;
  let fd;
  try {
    fd = fsImpl.openSync(target, fs.constants.O_RDONLY | noFollow);
    const opened = fsImpl.fstatSync(fd);
    if (!opened.isFile() || opened.size <= 0 || opened.size > maxBytes
        || opened.size !== before.size || !sameIdentity(before, opened)) {
      throw new Error(`${options.label || 'private file'} changed while opening`);
    }
    const output = Buffer.alloc(maxBytes + 1);
    let offset = 0;
    while (offset < output.length) {
      const read = fsImpl.readSync(fd, output, offset, output.length - offset, null);
      if (!read) break;
      offset += read;
    }
    if (offset > maxBytes) throw new Error(`${options.label || 'private file'} exceeded its size limit while reading`);
    const after = fsImpl.fstatSync(fd);
    if (!after.isFile() || after.size !== opened.size || offset !== opened.size
        || after.mtimeMs !== opened.mtimeMs || after.ctimeMs !== opened.ctimeMs
        || !sameIdentity(opened, after)) {
      throw new Error(`${options.label || 'private file'} changed while reading`);
    }
    return output.subarray(0, offset);
  } finally {
    if (fd !== undefined) fsImpl.closeSync(fd);
  }
}

function unsupportedDirectoryFsync(error, platform = process.platform) {
  if (!error) return false;
  if (['ENOSYS', 'ENOTSUP', 'EOPNOTSUPP'].includes(error.code)) return true;
  return platform === 'win32' && ['EPERM', 'EACCES', 'EINVAL'].includes(error.code);
}

function fsyncDirectory(directory, options = {}) {
  const fsImpl = options.fs || fs;
  let fd;
  try {
    fd = fsImpl.openSync(directory, fs.constants.O_RDONLY);
    fsImpl.fsyncSync(fd);
  } catch (error) {
    if (!unsupportedDirectoryFsync(error, options.platform)) throw error;
  } finally {
    if (fd !== undefined) fsImpl.closeSync(fd);
  }
}

function rollbackPublishedFile(target, backup, options, originalError) {
  const fsImpl = options.fs || fs;
  try {
    if (backup) fsImpl.renameSync(backup, target);
    else fsImpl.unlinkSync(target);
    fsyncDirectory(path.dirname(target), options);
  } catch (rollbackError) {
    originalError.rollbackError = rollbackError;
  }
}

// Publish a completed same-directory temp file and prove the directory entry is
// durable. If that proof fails after rename, restore the exact prior inode (or
// remove a first publication) before returning the storage error to the caller.
function publishFileDurably(temp, target, options = {}) {
  const fsImpl = options.fs || fs;
  const backup = `${target}.rollback.${process.pid}.${crypto.randomBytes(8).toString('hex')}`;
  let hasBackup = false;
  try {
    try {
      fsImpl.linkSync(target, backup);
      hasBackup = true;
    } catch (error) {
      if (!error || error.code !== 'ENOENT') throw error;
    }
    fsImpl.renameSync(temp, target);
    try {
      fsyncDirectory(path.dirname(target), options);
      if (typeof options.verifyPublished === 'function') {
        const verified = options.verifyPublished(target);
        if (verified && typeof verified.then === 'function') {
          throw new TypeError('synchronous publication verifier returned a promise');
        }
      }
    } catch (error) {
      rollbackPublishedFile(target, hasBackup ? backup : '', options, error);
      hasBackup = false;
      throw error;
    }
    if (hasBackup) {
      try { fsImpl.unlinkSync(backup); } catch { /* private stale rollback link; cleaned on the next successful write */ }
      hasBackup = false;
    }
    return target;
  } finally {
    if (hasBackup) {
      try { fsImpl.unlinkSync(backup); } catch { /* preserve the publication error */ }
    }
  }
}

function publishFileExclusiveDurably(temp, target, options = {}) {
  const fsImpl = options.fs || fs;
  let published = false;
  try {
    fsImpl.linkSync(temp, target);
    published = true;
    fsyncDirectory(path.dirname(target), options);
    return target;
  } catch (error) {
    if (published) rollbackPublishedFile(target, '', options, error);
    throw error;
  }
}

module.exports = {
  windowsPrincipal,
  windowsOwnerIdentity,
  privateAclListing,
  inspectPrivateWindowsPath,
  restrictPrivatePath,
  assertPrivatePath,
  assertPrivatePathDacl,
  securePrivatePath,
  protectInheritedPrivateFile,
  privateDirectoryLockTarget,
  withPrivateDirectoryMutationLockSync,
  readBoundedRegularFile,
  fsyncDirectory,
  publishFileDurably,
  publishFileExclusiveDurably,
  unsupportedDirectoryFsync,
};
