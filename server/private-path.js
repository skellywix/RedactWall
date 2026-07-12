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
// libuv maps the Windows CRT _O_TEMPORARY flag to an exact handle-backed
// delete-on-close operation. Node does not currently expose the constant, but
// accepts the CRT value on Windows. Never use this value on POSIX, where the
// numeric bit has a different meaning.
const WINDOWS_O_TEMPORARY = fs.constants.O_TEMPORARY || 0x40;
const _windowsOwnerCache = new Map();
let _windowsPrincipalCache = '';
const _committedCleanupWarnings = [];
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

// The machine-qualified principal must come from the System32 whoami.exe:
// PATH resolution can be shadowed (Git's sh ships a coreutils whoami that
// prints the bare user name), which would make every ACL-owner comparison
// fail — or worse, let a planted binary lie about the principal.
function windowsWhoamiPath() {
  return path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'whoami.exe');
}

function windowsPrincipal(spawn = spawnSync, label = 'private path') {
  if (spawn === spawnSync && _windowsPrincipalCache) return _windowsPrincipalCache;
  let result;
  try {
    result = spawn(windowsWhoamiPath(), [], { encoding: 'utf8', windowsHide: true });
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
  const owner = String(principal || '').trim().toLowerCase();
  if (!owner) return false;
  const systemPrincipals = new Set(['nt authority\\system', 's-1-5-18']);
  const ownerIsSystem = systemPrincipals.has(owner);
  const categories = [];
  if (lines.some((line) => {
    const flags = [...line.matchAll(/\(([^)]*)\)/g)].map((match) => match[1]);
    if (!flags.includes('f') || flags.some((flag) => !['oi', 'ci', 'f'].includes(flag))) return true;
    const principalAndPath = line.slice(0, line.lastIndexOf(':')).trimEnd();
    const endsWithPrincipal = (candidate) => principalAndPath === candidate
      || principalAndPath.endsWith(` ${candidate}`)
      || principalAndPath.endsWith(`\t${candidate}`);
    const ownerAce = endsWithPrincipal(owner);
    const systemAce = [...systemPrincipals].some(endsWithPrincipal);
    if (!ownerAce && !systemAce) return true;
    categories.push(ownerIsSystem || systemAce ? 'system' : 'owner');
    return false;
  })) return false;
  const expected = ownerIsSystem ? ['system'] : ['owner', 'system'];
  return categories.length === expected.length
    && expected.every((category) => categories.filter((value) => value === category).length === 1);
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
  return [stat.dev, stat.ino, stat.birthtimeNs ?? stat.birthtimeMs, stat.ctimeNs ?? stat.ctimeMs, stat.mode].join(':');
}

function exactLstat(fsImpl, target) {
  return fsImpl.lstatSync(target, { bigint: true });
}

function exactFstat(fsImpl, descriptor) {
  return fsImpl.fstatSync(descriptor, { bigint: true });
}

function sameStatValue(left, right) {
  return left !== undefined && right !== undefined && String(left) === String(right);
}

function sameStatTime(left, right, name) {
  return sameStatValue(left[`${name}Ns`] ?? left[`${name}Ms`], right[`${name}Ns`] ?? right[`${name}Ms`]);
}

function cleanupWarningDetails(error, options = {}, phase = 'durable-publication-cleanup') {
  return {
    component: String(options.cleanupComponent || 'durable-file-publication').slice(0, 80),
    phase,
    code: String(error && error.code || 'PRIVATE_PATH_CLEANUP_FAILED').slice(0, 80),
    ...(error && error.retainedPath ? { retainedPath: String(error.retainedPath) } : {}),
    ...(error && error.additionalRetainedPath ? { additionalRetainedPath: String(error.additionalRetainedPath) } : {}),
    ...(error && error.removedPath ? { removedPath: String(error.removedPath) } : {}),
  };
}

function notifyCommittedCleanupWarning(error, options = {}, phase) {
  const warning = cleanupWarningDetails(error, options, phase);
  _committedCleanupWarnings.push(warning);
  if (_committedCleanupWarnings.length > 32) _committedCleanupWarnings.shift();
  if (typeof options.onCommittedCleanupWarning === 'function') {
    try { options.onCommittedCleanupWarning({ ...warning }); } catch { /* committed state must remain success */ }
  }
  return warning;
}

function committedCleanupHealth() {
  const latest = _committedCleanupWarnings[_committedCleanupWarnings.length - 1] || null;
  return {
    ok: _committedCleanupWarnings.length === 0,
    reason: latest ? 'durable-storage-cleanup-degraded' : null,
    count: _committedCleanupWarnings.length,
    latest: latest && { component: latest.component, phase: latest.phase, code: latest.code },
  };
}

function resetCommittedCleanupHealthForTest() {
  _committedCleanupWarnings.length = 0;
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
  const stat = exactLstat(fsImpl, target);
  const directory = options.directory ?? stat.isDirectory();
  if (stat.isSymbolicLink() || (directory ? !stat.isDirectory() : !stat.isFile())) {
    throw new Error(`${options.label || 'private path'} is not a safe regular ${directory ? 'directory' : 'file'}`);
  }
  if (!directory && !sameStatValue(stat.nlink, 1)) {
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
    if ((Number(stat.mode) & 0o077) !== 0) throw new Error(`${options.label || 'private path'} permissions are too broad`);
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
    if (sameStatTime(before, after, 'ctime')) return target;
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
    if ((Number(stat.mode) & 0o077) !== 0) throw new Error(`${options.label || 'private path'} permissions are too broad`);
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
    if (sameStatTime(before, after, 'ctime')) return target;
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
    const before = exactLstat(fsImpl, resolved);
    const result = callback(resolved);
    const after = exactLstat(fsImpl, resolved);
    if (!sameIdentity(before, after)) throw new Error(`${options.label || 'private directory'} changed during initialization`);
    assertPrivatePath(resolved, security);
    return result;
  }, mutationLockOptions(options, fsImpl));
}

async function withPrivateDirectoryMutationLock(directory, callback, options = {}) {
  const fsImpl = options.fs || fs;
  const resolved = path.resolve(directory);
  const platform = options.platform || process.platform;
  if (platform === 'win32') prepareWindowsPrivateLockRoot({ ...options, fs: fsImpl });
  const lockTarget = privateDirectoryLockTarget(resolved, options);
  return fileMutationLock.withFileMutationLock(lockTarget, async () => {
    fsImpl.mkdirSync(resolved, { recursive: true, mode: 0o700 });
    const security = { ...options, fs: fsImpl, directory: true };
    establishPrivateDirectoryTrust(resolved, lockTarget, security);
    const before = exactLstat(fsImpl, resolved);
    const result = await callback(resolved);
    const after = exactLstat(fsImpl, resolved);
    if (!sameIdentity(before, after)) throw new Error(`${options.label || 'private directory'} changed during initialization`);
    assertPrivatePath(resolved, security);
    return result;
  }, mutationLockOptions(options, fsImpl));
}

function sameIdentity(left, right) {
  if (!left || !right || !sameStatValue(left.dev, right.dev) || !sameStatValue(left.ino, right.ino)) return false;
  return String(left.dev) !== '0' && String(left.ino) !== '0';
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
    const opened = exactFstat(fsImpl, fd);
    if (!opened.isFile() || opened.size <= 0 || opened.size > maxBytes
        || !sameStatValue(opened.size, before.size) || !sameIdentity(before, opened)) {
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
    const after = exactFstat(fsImpl, fd);
    if (!after.isFile() || !sameStatValue(after.size, opened.size) || !sameStatValue(offset, opened.size)
        || !sameStatTime(after, opened, 'mtime') || !sameStatTime(after, opened, 'ctime')
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

function publicationSnapshot(fsImpl, target, expectedLinks = null) {
  const stat = exactLstat(fsImpl, target);
  const stable = stat && typeof stat.dev === 'bigint' && typeof stat.ino === 'bigint'
    && typeof stat.size === 'bigint' && stat.dev > 0n && stat.ino > 0n
    && stat.isFile() && !stat.isSymbolicLink() && stat.nlink > 0n;
  if (!stable || (expectedLinks && !expectedLinks.includes(stat.nlink))) {
    throw new Error('durable publication path has no stable single-file identity');
  }
  return stat;
}

function samePublicationArtifact(left, right) {
  return !!left && !!right
    && left.dev === right.dev && left.ino === right.ino
    && left.size === right.size && sameStatTime(left, right, 'mtime');
}

function exactOpenedPublication(fsImpl, descriptor, expected) {
  const opened = exactFstat(fsImpl, descriptor);
  return opened && typeof opened.dev === 'bigint' && typeof opened.ino === 'bigint'
    && typeof opened.size === 'bigint' && opened.dev > 0n && opened.ino > 0n
    && opened.isFile() && opened.nlink === expected.nlink
    && samePublicationArtifact(expected, opened)
    ? opened
    : null;
}

function retainedPathExists(fsImpl, target) {
  try {
    exactLstat(fsImpl, target);
    return true;
  } catch (error) {
    if (error && error.code === 'ENOENT') return false;
    throw error;
  }
}

// Delete the exact opened Windows file, not whichever object happens to own
// the pathname at unlink time. A rename/replacement after the delete handle is
// opened leaves the replacement intact while close removes only the bound
// object. POSIX has no delete-by-open-handle primitive in Node, so trusted
// private directories retain the guarded pathname fallback below.
function removeExactPublicationFile(target, expected, options = {}) {
  const fsImpl = options.fs || fs;
  const platform = options.platform || process.platform;
  if (platform !== 'win32') {
    const current = publicationSnapshot(fsImpl, target, [expected.nlink]);
    if (!samePublicationArtifact(expected, current)) {
      throw publicationError('publication cleanup found a changed replacement', null, {
        retainedPath: target,
      });
    }
    fsImpl.unlinkSync(target);
    fsyncDirectory(path.dirname(target), options);
    return;
  }

  const before = publicationSnapshot(fsImpl, target, [expected.nlink]);
  if (!samePublicationArtifact(expected, before)) {
    throw publicationError('publication cleanup found a changed replacement', null, {
      retainedPath: target,
    });
  }
  const noFollow = fs.constants.O_NOFOLLOW || 0;
  let stableFd;
  let deleteFd;
  let mismatchRescue = '';
  let deleting = null;
  try {
    stableFd = fsImpl.openSync(target, fs.constants.O_RDWR | noFollow);
    if (!exactOpenedPublication(fsImpl, stableFd, expected)) {
      throw new Error('publication cleanup changed while opening a stable handle');
    }
    deleteFd = fsImpl.openSync(target, fs.constants.O_RDWR | WINDOWS_O_TEMPORARY | noFollow);
    deleting = exactFstat(fsImpl, deleteFd);
    const deletesExpected = deleting.nlink === expected.nlink
      && samePublicationArtifact(expected, deleting);
    if (!deletesExpected) {
      // Preserve an object that won the pre-open race before closing its
      // delete-on-close handle. The hard link makes the mismatch recoverable.
      mismatchRescue = quarantineName(target, 'delete-mismatch');
      fsImpl.linkSync(target, mismatchRescue);
      const rescued = publicationSnapshot(fsImpl, mismatchRescue, [deleting.nlink + 1n]);
      if (!samePublicationArtifact(deleting, rescued)) {
        throw new Error('publication cleanup mismatch could not be retained');
      }
    }
    if (typeof options.onBeforeExactFileDeleteClose === 'function') {
      options.onBeforeExactFileDeleteClose({ target, expected, descriptor: deleteFd });
    }
    fsImpl.closeSync(deleteFd);
    deleteFd = undefined;
    fsImpl.closeSync(stableFd);
    stableFd = undefined;
    fsyncDirectory(path.dirname(target), options);
    if (mismatchRescue) {
      throw publicationError('publication cleanup retained a pre-open replacement', null, {
        retainedPath: mismatchRescue,
        ...(retainedPathExists(fsImpl, target) ? { additionalRetainedPath: target } : {}),
      });
    }
    if (retainedPathExists(fsImpl, target)) {
      throw publicationError('publication cleanup retained a changed replacement', null, {
        retainedPath: target,
      });
    }
  } catch (error) {
    if (deleteFd !== undefined && deleting && !mismatchRescue) {
      try {
        const recovery = quarantineName(target, 'delete-error-retain');
        fsImpl.linkSync(target, recovery);
        const recovered = publicationSnapshot(fsImpl, recovery, [deleting.nlink + 1n]);
        if (samePublicationArtifact(deleting, recovered)) {
          error.retainedPath = recovery;
        }
      } catch { /* the exact handle still prevents a pathname replacement from being deleted */ }
    }
    if (deleteFd !== undefined) {
      try { fsImpl.closeSync(deleteFd); } catch {}
    }
    if (stableFd !== undefined) {
      try { fsImpl.closeSync(stableFd); } catch {}
    }
    if (error && !error.retainedPath && !error.additionalRetainedPath && !error.removedPath) {
      try { exactLstat(fsImpl, target); error.retainedPath = target; }
      catch (inspectError) {
        if (inspectError && inspectError.code === 'ENOENT') error.removedPath = target;
      }
    }
    throw error;
  }
}

function publicationError(message, cause, details = {}) {
  const error = new Error(message);
  error.code = 'PRIVATE_PATH_PUBLICATION_UNCERTAIN';
  error.cause = cause;
  Object.assign(error, details);
  return error;
}

function quarantineName(target, label) {
  return `${target}.${label}.${process.pid}.${crypto.randomBytes(12).toString('hex')}`;
}

function restoreQuarantineExclusively(quarantine, target, options) {
  const fsImpl = options.fs || fs;
  const expected = publicationSnapshot(fsImpl, quarantine, [1n]);
  const guard = quarantineName(quarantine, 'restore-guard');
  let quarantinePresent = true;
  let guardPresent = false;
  try {
    fsImpl.linkSync(quarantine, target);
    fsImpl.linkSync(quarantine, guard);
    guardPresent = true;
    let source = publicationSnapshot(fsImpl, quarantine, [3n]);
    let restored = publicationSnapshot(fsImpl, target, [3n]);
    let retained = publicationSnapshot(fsImpl, guard, [3n]);
    if (!samePublicationArtifact(expected, source)
        || !samePublicationArtifact(expected, restored)
        || !samePublicationArtifact(expected, retained)) {
      throw new Error('changed publication restoration could not be identity-bound');
    }
    fsyncDirectory(path.dirname(target), options);
    if ((options.platform || process.platform) === 'win32') {
      removeExactPublicationFile(quarantine, source, options);
    } else {
      fsImpl.unlinkSync(quarantine);
    }
    quarantinePresent = false;
    fsyncDirectory(path.dirname(target), options);
    restored = publicationSnapshot(fsImpl, target, [2n]);
    retained = publicationSnapshot(fsImpl, guard, [2n]);
    if (!samePublicationArtifact(expected, restored) || !samePublicationArtifact(expected, retained)) {
      throw new Error('changed publication replacement changed during restoration');
    }
    if ((options.platform || process.platform) === 'win32') {
      removeExactPublicationFile(guard, retained, options);
    } else {
      fsImpl.unlinkSync(guard);
    }
    guardPresent = false;
    fsyncDirectory(path.dirname(target), options);
    restored = publicationSnapshot(fsImpl, target, [1n]);
    if (!samePublicationArtifact(expected, restored)) {
      throw new Error('changed publication replacement changed after restoration');
    }
    return target;
  } catch (error) {
    throw publicationError('changed publication replacement was retained for recovery', error, {
      ...(error && error.retainedPath
        ? { retainedPath: error.retainedPath }
        : (quarantinePresent ? { retainedPath: quarantine } : { removedPath: quarantine })),
      ...(error && error.additionalRetainedPath
        ? { additionalRetainedPath: error.additionalRetainedPath }
        : (guardPresent ? { additionalRetainedPath: guard } : {})),
      ...(error && error.removedPath ? { removedPath: error.removedPath } : {}),
      replacementPath: target,
    });
  }
}

function removeExactQuarantine(quarantine, expected, options) {
  const fsImpl = options.fs || fs;
  const current = publicationSnapshot(fsImpl, quarantine);
  if (!samePublicationArtifact(expected, current)) {
    throw publicationError('publication cleanup found a changed replacement', null, {
      retainedPath: quarantine,
    });
  }
  if ((options.platform || process.platform) === 'win32') {
    try {
      removeExactPublicationFile(quarantine, current, options);
      return;
    } catch (error) {
      let fallback = {};
      if (!error.retainedPath && !error.additionalRetainedPath && !error.removedPath) {
        try { exactLstat(fsImpl, quarantine); fallback = { retainedPath: quarantine }; }
        catch (inspectError) {
          if (inspectError && inspectError.code === 'ENOENT') fallback = { removedPath: quarantine };
        }
      }
      throw publicationError('publication cleanup could not be durably completed', error, {
        ...(error && error.retainedPath ? { retainedPath: error.retainedPath } : {}),
        ...(error && error.additionalRetainedPath
          ? { additionalRetainedPath: error.additionalRetainedPath }
          : {}),
        ...(error && error.removedPath ? { removedPath: error.removedPath } : {}),
        ...fallback,
        artifactCleanupFailure: true,
      });
    }
  }
  const guard = quarantineName(quarantine, 'unlink-guard');
  let quarantinePresent = true;
  let guardPresent = false;
  try {
    fsImpl.linkSync(quarantine, guard);
    guardPresent = true;
    const linkedCount = current.nlink + 1n;
    const linkedSource = publicationSnapshot(fsImpl, quarantine, [linkedCount]);
    const linkedGuard = publicationSnapshot(fsImpl, guard, [linkedCount]);
    if (!samePublicationArtifact(current, linkedSource)
        || !samePublicationArtifact(current, linkedGuard)) {
      throw new Error('publication cleanup guard changed while linking');
    }
    fsImpl.unlinkSync(quarantine);
    quarantinePresent = false;
    fsyncDirectory(path.dirname(quarantine), options);
    const retained = publicationSnapshot(fsImpl, guard, [current.nlink]);
    if (!samePublicationArtifact(current, retained)) {
      throw new Error('publication cleanup guard changed after source removal');
    }
    fsImpl.unlinkSync(guard);
    guardPresent = false;
    fsyncDirectory(path.dirname(quarantine), options);
  } catch (error) {
    throw publicationError('publication cleanup could not be durably completed', error, {
      ...(quarantinePresent ? { retainedPath: quarantine } : { removedPath: quarantine }),
      ...(guardPresent ? { additionalRetainedPath: guard } : {}),
      artifactCleanupFailure: true,
    });
  }
}

function quarantineVisibleFile(target, label, options) {
  const fsImpl = options.fs || fs;
  const quarantine = quarantineName(target, label);
  try {
    fsImpl.renameSync(target, quarantine);
    return quarantine;
  } catch (error) {
    if (error && error.code === 'ENOENT') return '';
    throw publicationError('publication rollback could not quarantine the visible path', error);
  }
}

function restoreRollbackLink(backup, expected, target, options) {
  const fsImpl = options.fs || fs;
  const current = publicationSnapshot(fsImpl, backup, [1n]);
  if (!samePublicationArtifact(expected, current)) {
    throw publicationError('publication rollback artifact changed before restoration', null, {
      retainedPath: backup,
    });
  }
  try {
    restoreQuarantineExclusively(backup, target, options);
  } catch (error) {
    throw publicationError('prior publication was retained but could not be restored', error, {
      ...(error && error.retainedPath ? { retainedPath: error.retainedPath } : {}),
      ...(error && error.additionalRetainedPath ? { additionalRetainedPath: error.additionalRetainedPath } : {}),
      restoredPath: target,
    });
  }
}

function rollbackPublishedFile(target, backup, published, options, originalError) {
  const fsImpl = options.fs || fs;
  const quarantine = quarantineVisibleFile(target, 'failed-publication', options);
  let quarantined = null;
  if (quarantine) {
    try { quarantined = publicationSnapshot(fsImpl, quarantine); }
    catch (error) {
      throw publicationError('unverifiable publication replacement was retained', originalError || error, {
        retainedPath: quarantine,
        rollbackPath: backup && backup.path,
      });
    }
    if (!samePublicationArtifact(published, quarantined)) {
      try { restoreQuarantineExclusively(quarantine, target, options); }
      catch (restoreError) {
        restoreError.rollbackPath = backup && backup.path;
        throw restoreError;
      }
      throw publicationError('publication changed during rollback; replacement was preserved', originalError, {
        replacementPath: target,
        rollbackPath: backup && backup.path,
      });
    }
  }
  try {
    if (backup) restoreRollbackLink(backup.path, backup.identity, target, options);
    if (quarantine) removeExactQuarantine(quarantine, quarantined, options);
    else fsyncDirectory(path.dirname(target), options);
  } catch (rollbackError) {
    if (!rollbackError.cause) rollbackError.cause = originalError;
    if (quarantine && !rollbackError.retainedPath && rollbackError.removedPath !== quarantine) {
      rollbackError.retainedPath = quarantine;
    }
    else if (quarantine && rollbackError.retainedPath
        && rollbackError.retainedPath !== quarantine) {
      rollbackError.additionalRetainedPath = quarantine;
    }
    throw rollbackError;
  }
}

function quarantinePriorPublication(target, options) {
  const fsImpl = options.fs || fs;
  let prior;
  try { prior = publicationSnapshot(fsImpl, target, [1n]); }
  catch (error) {
    if (error && error.code === 'ENOENT') return null;
    throw error;
  }
  const backup = quarantineName(target, 'rollback');
  fsImpl.renameSync(target, backup);
  let quarantined;
  try { quarantined = publicationSnapshot(fsImpl, backup, [1n]); }
  catch (error) {
    throw publicationError('prior publication could not be verified after quarantine', error, {
      retainedPath: backup,
    });
  }
  if (!samePublicationArtifact(prior, quarantined)) {
    restoreQuarantineExclusively(backup, target, options);
    throw publicationError('publication target changed before quarantine; replacement was preserved', null, {
      replacementPath: target,
    });
  }
  try { fsyncDirectory(path.dirname(target), options); }
  catch (error) {
    restoreRollbackLink(backup, prior, target, options);
    throw error;
  }
  return { path: backup, identity: prior };
}

function publicationTargetExists(fsImpl, target) {
  try {
    publicationSnapshot(fsImpl, target);
    return true;
  } catch (error) {
    if (error && error.code === 'ENOENT') return false;
    return true;
  }
}

function recoverFailedExclusiveLink(target, backup, options, originalError) {
  const fsImpl = options.fs || fs;
  if (publicationTargetExists(fsImpl, target)) {
    throw publicationError('publication target changed before exclusive publication', originalError, {
      replacementPath: target,
      rollbackPath: backup && backup.path,
    });
  }
  if (backup) restoreRollbackLink(backup.path, backup.identity, target, options);
  throw originalError;
}

function cleanupRollbackLink(backup, options) {
  if (!backup) return;
  const fsImpl = options.fs || fs;
  const current = publicationSnapshot(fsImpl, backup.path, [1n]);
  if (!samePublicationArtifact(backup.identity, current)) {
    throw publicationError('publication rollback link changed before cleanup', null, {
      retainedPath: backup.path,
    });
  }
  const quarantine = quarantineName(backup.path, 'cleanup');
  fsImpl.renameSync(backup.path, quarantine);
  removeExactQuarantine(quarantine, current, options);
}

// Publish a completed same-directory temp file and prove the directory entry is
// durable. If that proof fails after rename, restore the exact prior inode (or
// remove a first publication) before returning the storage error to the caller.
function publishFileDurably(temp, target, options = {}) {
  const fsImpl = options.fs || fs;
  const security = { ...options, fs: fsImpl };
  const staged = publicationSnapshot(fsImpl, temp, [1n]);
  let backup = null;
  let published = false;
  try {
    backup = quarantinePriorPublication(target, security);
    try { fsImpl.linkSync(temp, target); }
    catch (error) { recoverFailedExclusiveLink(target, backup, security, error); }
    published = true;
    let current = publicationSnapshot(fsImpl, target, [2n]);
    if (!samePublicationArtifact(staged, current)) {
      throw new Error('durable publication target changed during linking');
    }
    fsyncDirectory(path.dirname(target), security);
    removePublishedSource(temp, staged, security);
    current = publicationSnapshot(fsImpl, target, [1n]);
    verifySynchronousPublication(target, options);
    current = publicationSnapshot(fsImpl, target, [1n]);
    if (!samePublicationArtifact(staged, current)) {
      throw new Error('durable publication target changed during verification');
    }
  } catch (error) {
    if (published) rollbackPublishedFile(target, backup, staged, security, error);
    else {
      try { removePublishedSource(temp, staged, security); }
      catch (cleanupError) { error.cleanupError = cleanupError; }
    }
    throw error;
  }
  try {
    cleanupRollbackLink(backup, security);
  } catch (error) {
    // The exact target and its directory are already verified and durable.
    // Cleanup is post-commit maintenance and must not turn a committed write
    // into a false failure that aborts a coupled database/audit transaction.
    notifyCommittedCleanupWarning(error, security, 'rollback-artifact-cleanup');
  }
  return target;
}

function rollbackExclusivePublication(target, staged, options, originalError) {
  const quarantine = quarantineVisibleFile(target, 'failed-exclusive-publication', options);
  if (!quarantine) return;
  let current;
  try { current = publicationSnapshot(options.fs || fs, quarantine); }
  catch (error) {
    throw publicationError('unverifiable exclusive-publication replacement was retained', originalError || error, {
      retainedPath: quarantine,
    });
  }
  if (!samePublicationArtifact(staged, current)) {
    restoreQuarantineExclusively(quarantine, target, options);
    throw publicationError('exclusive publication changed during rollback; replacement was preserved', originalError, {
      replacementPath: target,
    });
  }
  removeExactQuarantine(quarantine, current, options);
}

function removePublishedSource(temp, staged, options) {
  const fsImpl = options.fs || fs;
  const current = publicationSnapshot(fsImpl, temp);
  if (!samePublicationArtifact(staged, current)) {
    throw publicationError('exclusive publication source changed before cleanup', null, {
      retainedPath: temp,
    });
  }
  removeExactQuarantine(temp, current, options);
}

// Remove a consumed staging source after a FAILED publication. The operation
// claimed nothing durable, so an identity-checked namespace removal is enough;
// escalating a cleanup durability proof here would either mask the primary
// error or strand secured staging debris on a volume whose directory fsync is
// already failing. Never masks the original error; a changed file is retained.
function consumeFailedStagingSource(temp, staged, options, originalError) {
  const fsImpl = options.fs || fs;
  try {
    const current = publicationSnapshot(fsImpl, temp);
    if (!samePublicationArtifact(staged, current)) {
      throw publicationError('failed publication staging changed before cleanup', null, {
        retainedPath: temp,
      });
    }
    fsImpl.unlinkSync(temp);
    try { fsyncDirectory(path.dirname(temp), options); } catch { /* removal is visible; durability is best-effort after a failed operation */ }
  } catch (cleanupError) {
    if (cleanupError && cleanupError.code === 'ENOENT') return;
    originalError.cleanupError = cleanupError;
    if (cleanupError.retainedPath && !originalError.retainedPath) {
      originalError.retainedPath = cleanupError.retainedPath;
    }
  }
}

function verifySynchronousPublication(target, options) {
  if (typeof options.verifyPublished !== 'function') return;
  const verified = options.verifyPublished(target);
  if (verified && typeof verified.then === 'function') {
    throw new TypeError('synchronous publication verifier returned a promise');
  }
}

function publishFileExclusiveDurably(temp, target, options = {}) {
  const fsImpl = options.fs || fs;
  const security = { ...options, fs: fsImpl };
  const consumeSource = options.consumeSource === true;
  const staged = publicationSnapshot(fsImpl, temp, [1n]);
  let published = false;
  try {
    fsImpl.linkSync(temp, target);
    published = true;
    const linked = publicationSnapshot(fsImpl, target, [2n]);
    if (!samePublicationArtifact(staged, linked)) {
      throw new Error('exclusive publication target changed during linking');
    }
    fsyncDirectory(path.dirname(target), security);
    if (consumeSource) removePublishedSource(temp, staged, security);
    const expectedLinks = consumeSource ? [1n] : [2n];
    let settled = publicationSnapshot(fsImpl, target, expectedLinks);
    if (!samePublicationArtifact(staged, settled)) {
      throw new Error('exclusive publication target changed while settling');
    }
    verifySynchronousPublication(target, options);
    settled = publicationSnapshot(fsImpl, target, expectedLinks);
    if (!samePublicationArtifact(staged, settled)) {
      throw new Error('exclusive publication target changed during verification');
    }
    return target;
  } catch (error) {
    if (published) {
      try { rollbackExclusivePublication(target, staged, security, error); }
      catch (rollbackError) {
        // A failure while removing the exact rolled-back artifact does not
        // change the original pre-commit result. Preserve that error while
        // carrying the retained recovery paths for operators. A changed
        // replacement or failed restoration remains the primary uncertainty
        // and rethrows before staging consumption, retaining the source too.
        if (!rollbackError.artifactCleanupFailure) throw rollbackError;
        error.rollbackError = rollbackError;
        for (const field of ['retainedPath', 'additionalRetainedPath', 'removedPath']) {
          if (rollbackError[field] && !error[field]) error[field] = rollbackError[field];
        }
      }
      // The failure claimed nothing durable, so a consumed source must not
      // survive as staging debris.
      if (consumeSource) consumeFailedStagingSource(temp, staged, security, error);
    }
    else if (consumeSource) consumeFailedStagingSource(temp, staged, security, error);
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
  withPrivateDirectoryMutationLock,
  readBoundedRegularFile,
  fsyncDirectory,
  publishFileDurably,
  publishFileExclusiveDurably,
  removeExactPublicationFile,
  unsupportedDirectoryFsync,
  committedCleanupHealth,
  notifyCommittedCleanupWarning,
  _resetCommittedCleanupHealthForTest: resetCommittedCleanupHealthForTest,
};
