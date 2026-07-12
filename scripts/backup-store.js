'use strict';
/**
 * Backup, verify, and offline-restore the evidence store.
 *
 * SQLite (default driver): online `.backup()` copy plus authenticated audit
 * state/checkpoint sidecars and an HMAC-authenticated manifest that binds the
 * complete set.
 * Postgres (REDACTWALL_DB_DRIVER=postgres): drives pg_dump/pg_restore (custom
 * format); credentials travel via libpq environment variables so the
 * connection string never appears in argv, output, or the manifest.
 *
 * Either way the manifest intentionally contains only metadata, hashes,
 * counts, and audit verification results. The backup artifact itself is
 * sensitive runtime state.
 */
require('../server/env').loadEnv();
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const Database = require('better-sqlite3');
const { parse: parsePgConnectionString } = require('pg-connection-string');
const auditIntegrity = require('../server/audit-integrity');
const auditAnchorInternal = require('../server/audit-anchor')._internal;
const privatePaths = require('../server/private-path');
const {
  parsePostgresConnectionUrl,
  validPostgresTlsUrl,
  withoutPostgresConnectionEnv,
} = require('../server/postgres-url');
const RESTORE_COPY_BUFFER_BYTES = 64 * 1024;
const VALUE_OPTIONS = new Set(['out', 'file', 'manifest', 'to', 'audit-dir']);

function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith('--')) {
      out._.push(arg);
      continue;
    }
    const key = arg.slice(2);
    if (key === 'force') {
      out.force = true;
      continue;
    }
    if (!VALUE_OPTIONS.has(key)) throw new Error(`unknown option: --${key}`);
    if (i + 1 >= argv.length || argv[i + 1].startsWith('--')) {
      throw new Error(`--${key} requires a value`);
    }
    out[key] = argv[++i];
  }
  return out;
}

function sha256File(file) {
  const h = crypto.createHash('sha256');
  const buffer = Buffer.alloc(RESTORE_COPY_BUFFER_BYTES);
  let fd;
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    while (true) {
      const count = fs.readSync(fd, buffer, 0, buffer.length, null);
      if (!count) return h.digest('hex');
      h.update(buffer.subarray(0, count));
    }
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

function nowStamp(date = new Date()) {
  return date.toISOString().replace(/[:.]/g, '-');
}

const PRIVATE_DIR_MODE = 0o700;
const PRIVATE_FILE_MODE = 0o600;
const SQLITE_SIDECAR_SUFFIXES = ['-wal', '-shm', '-journal'];
const BACKUP_AUDIT_STATE_SUFFIX = '.audit-state.json';
const BACKUP_AUDIT_CHECKPOINT_SUFFIX = '.audit-checkpoint.json';
const AUDIT_STATE_NAME = '.audit-integrity-state.json';
const AUDIT_CHECKPOINT_NAME = '.audit-integrity-checkpoint.json';
const MAX_AUDIT_STATE_BYTES = 8 * 1024;
const MAX_AUDIT_CHECKPOINT_BYTES = 4 * 1024;
const MANIFEST_AUTH_VERSION = 1;
const SQLITE_BACKUP_FORMAT = 'sqlite-backup';
const SQLITE_RESTORED_FORMAT = 'sqlite-restored-runtime';
const SQLITE_RUNTIME_LAYOUT = 'runtime-audit-directory';
const POSTGRES_AUDIT_SCOPE_TABLE = 'public.redactwall_audit_scope';
const PG_DEFAULT_PORT = 5432;
const PG_SNAPSHOT_DEFAULT_OPTIONS = '-c client_min_messages=notice';
const PG_SNAPSHOT_DEFAULT_APPLICATION = 'redactwall-backup-snapshot';
const SUPPORTED_PG_RESTORE_MAJORS = new Set([16, 17]);
const PG_RESTORE_CONNECTION_LIMIT = 2;
const PG_RESTORE_SESSION_DRAIN_TIMEOUT_MS = 5000;
const DEFAULT_PG_MAINTENANCE_DATABASE = 'postgres';
const PG_DATABASE_IDENTIFIER_RE = /^[A-Za-z_][A-Za-z0-9_$]{0,62}$/;
const PG_RESTORE_SESSION_WAIT = new Int32Array(new SharedArrayBuffer(4));
const CONCLUSIVE_PG_DATABASE_MUTATION_REJECTIONS = new Set([
  '0A000', '22023', '25001', '3D000', '42501', '42601', '42704', '42P04', '55006',
]);
const privateStagingProofs = new Map();
const WINDOWS_DACL_RESTORE = [
  '$path = $env:REDACTWALL_ACL_TARGET;',
  '$section = [System.Security.AccessControl.AccessControlSections]::Access;',
  '$acl = New-Object System.Security.AccessControl.FileSecurity;',
  '$acl.SetSecurityDescriptorSddlForm($env:REDACTWALL_ACL_SDDL, $section);',
  '$isDirectory = ([System.IO.File]::GetAttributes($path) -band [System.IO.FileAttributes]::Directory) -ne 0;',
  'if ($isDirectory) {',
  '$directoryAcl = New-Object System.Security.AccessControl.DirectorySecurity;',
  '$directoryAcl.SetSecurityDescriptorSddlForm($env:REDACTWALL_ACL_SDDL, $section);',
  '[System.IO.Directory]::SetAccessControl($path, $directoryAcl)',
  '} else { [System.IO.File]::SetAccessControl($path, $acl) }',
].join(' ');
const STATS_BLOCKED_STATUSES = new Set([
  'pending',
  'pending_justification',
  'denied',
  'blocked_by_user',
  'destination_blocked',
  'file_upload_blocked',
  'action_blocked',
  'injection_blocked',
  'file_blocked_unscanned',
  'ocr_required',
  'response_flagged',
  'response_blocked',
]);

function ensureParent(file) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
}

function windowsPrincipal(spawn = spawnSync) {
  // System32 path only: a PATH-resolved whoami can be shadowed (Git's sh
  // ships one that omits the machine prefix) and would break or spoof every
  // owner comparison.
  const whoami = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'whoami.exe');
  const result = spawn(whoami, [], { encoding: 'utf8', windowsHide: true });
  const principal = String(result.stdout || '').trim();
  if (result.error || result.status !== 0 || !principal) {
    const detail = String(result.stderr || result.error?.message || 'no principal returned').trim();
    throw new Error(`failed to identify the Windows backup owner with whoami: ${detail}`);
  }
  return principal;
}

function runWindowsAclPowerShell(command, target, options = {}, sddl) {
  const spawn = options.powershellSpawn || spawnSync;
  const env = { ...process.env, REDACTWALL_ACL_TARGET: target };
  if (sddl !== undefined) env.REDACTWALL_ACL_SDDL = sddl;
  return spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', command], {
    encoding: 'utf8',
    windowsHide: true,
    env,
  });
}

function captureWindowsDacl(target, options = {}) {
  if (typeof options.captureDacl === 'function') return options.captureDacl(target);
  const snapshot = path.join(os.tmpdir(), `.redactwall-acl-${process.pid}-${crypto.randomBytes(8).toString('hex')}`);
  const spawn = options.aclSpawn || spawnSync;
  try {
    const result = spawn('icacls.exe', [target, '/save', snapshot, '/q'], {
      encoding: 'utf8',
      windowsHide: true,
    });
    if (result.error || result.status !== 0) {
      const detail = String(result.stderr || result.error?.message || 'unknown error').trim();
      throw new Error(`failed to capture the Windows ACL for ${target}: ${detail}`);
    }
    const sddl = fs.readFileSync(snapshot, 'utf16le').split(/\r?\n/).find((line) => line.startsWith('D:'));
    if (!sddl) throw new Error(`failed to capture the Windows ACL for ${target}: no descriptor returned`);
    return sddl;
  } finally {
    fs.rmSync(snapshot, { force: true });
  }
}

function restoreWindowsDacl(target, sddl, options = {}) {
  if (typeof options.restoreDacl === 'function') return options.restoreDacl(target, sddl);
  const result = runWindowsAclPowerShell(WINDOWS_DACL_RESTORE, target, options, sddl);
  if (result.error || result.status !== 0) {
    const detail = String(result.stderr || result.error?.message || 'unknown error').trim();
    throw new Error(`failed to restore the Windows ACL for ${target}: ${detail}`);
  }
}

function checkedIcacls(spawn, args, target) {
  const result = spawn('icacls.exe', args, { encoding: 'utf8', windowsHide: true });
  if (!result.error && result.status === 0) return;
  const detail = String(result.stderr || result.error?.message || 'unknown error').trim();
  throw new Error(`failed to secure ${target} with icacls: ${detail}`);
}

/** Restrict sensitive backup state to the current account and LocalSystem. */
function restrictPath(target, options = {}) {
  const platform = options.platform || process.platform;
  const directory = options.directory ?? fs.statSync(target).isDirectory();
  if (platform !== 'win32') {
    fs.chmodSync(target, directory ? PRIVATE_DIR_MODE : PRIVATE_FILE_MODE);
    return target;
  }

  const spawn = options.spawn || spawnSync;
  const principal = options.principal || windowsPrincipal(spawn);
  const inheritance = directory ? '(OI)(CI)' : '';
  // /inheritance:r does not remove unrelated explicit ACEs. Reset first so
  // the subsequent protected DACL contains exactly the two trusted owners.
  checkedIcacls(spawn, [target, '/reset', '/q'], target);
  checkedIcacls(spawn, [
    target,
    '/inheritance:r',
    '/grant:r',
    `${principal}:${inheritance}(F)`,
    `*S-1-5-18:${inheritance}(F)`,
    '/q',
  ], target);
  return target;
}

function createPrivateStagingDir(parent = os.tmpdir(), security = {}) {
  fs.mkdirSync(parent, { recursive: true });
  const staging = fs.mkdtempSync(path.join(parent, '.redactwall-backup-'));
  privateStagingProofs.set(comparablePath(staging), exactDirectoryStat(staging, 'private backup staging directory'));
  try {
    return restrictPath(staging, { ...security, directory: true });
  } catch (error) {
    try { cleanupPrivateStagingDirectory(staging); }
    catch (cleanupError) {
      throw new AggregateError(
        [error, cleanupError],
        `failed to secure private backup staging; ${cleanupError.message}`,
      );
    }
    throw error;
  }
}

function sameDirectoryIdentity(left, right) {
  return sameFileIdentity(left, right) && left.birthtimeNs === right.birthtimeNs;
}

function retainChangedStagingDirectory(quarantine, original) {
  let retainedAt = quarantine;
  if (!pathEntryExists(original) && pathEntryExists(quarantine)) {
    try {
      fs.renameSync(quarantine, original);
      retainedAt = original;
    } catch {
      // Keep the changed path at its unpredictable quarantine name when the
      // public pathname is concurrently occupied or cannot be restored.
    }
  }
  try { privatePaths.fsyncDirectory(path.dirname(original), { fs }); } catch {}
  return retainedAt;
}

function cleanupPrivateStagingDirectory(staging, label = 'private backup staging directory') {
  if (!staging) return;
  const resolved = path.resolve(staging);
  const key = comparablePath(resolved);
  const expected = privateStagingProofs.get(key);
  if (!expected) throw new Error(`${label} cleanup has no filesystem identity proof: ${resolved}`);
  const quarantine = quarantinePath(resolved, 'cleanup');
  try {
    fs.renameSync(resolved, quarantine);
  } catch (error) {
    if (error && error.code === 'ENOENT') {
      throw new Error(`${label} cleanup refused; tracked staging disappeared from ${resolved}`, { cause: error });
    }
    const cleanupError = new Error(`${label} cleanup refused; staging retained at ${resolved}`, {
      cause: error,
    });
    cleanupError.code = error && error.code || 'BACKUP_STAGING_CLEANUP_FAILED';
    cleanupError.retainedPath = resolved;
    cleanupError.recoveryPaths = [resolved];
    throw cleanupError;
  }

  let current;
  try {
    current = exactDirectoryStat(quarantine, `quarantined ${label}`);
  } catch (error) {
    privateStagingProofs.delete(key);
    const retainedAt = retainChangedStagingDirectory(quarantine, resolved);
    const cleanupError = new Error(`${label} cleanup refused; unverifiable replacement retained at ${retainedAt}`, {
      cause: error,
    });
    cleanupError.retainedPath = retainedAt;
    cleanupError.recoveryPaths = [retainedAt];
    throw cleanupError;
  }
  if (!sameDirectoryIdentity(expected, current)) {
    privateStagingProofs.delete(key);
    const retainedAt = retainChangedStagingDirectory(quarantine, resolved);
    const error = new Error(`${label} cleanup refused; changed replacement retained at ${retainedAt}`);
    error.retainedPath = retainedAt;
    error.recoveryPaths = [retainedAt];
    throw error;
  }

  try {
    fs.rmSync(quarantine, { recursive: true });
  } catch (error) {
    const cleanupError = new Error(`${label} cleanup failed; exact staging retained at ${quarantine}`, {
      cause: error,
    });
    cleanupError.code = error && error.code || 'BACKUP_STAGING_CLEANUP_FAILED';
    cleanupError.retainedPath = quarantine;
    cleanupError.recoveryPaths = [quarantine];
    throw cleanupError;
  }
  privateStagingProofs.delete(key);
  if (pathEntryExists(quarantine)) {
    const error = new Error(`${label} cleanup removed the owned staging but a changed replacement was retained at ${quarantine}`);
    error.retainedPath = quarantine;
    error.recoveryPaths = [quarantine];
    throw error;
  }
}

function cleanupPrivateStagingDirectories(stagingDirectories) {
  const failures = [];
  for (const staging of stagingDirectories.filter(Boolean)) {
    try { cleanupPrivateStagingDirectory(staging); }
    catch (error) { failures.push(error); }
  }
  if (failures.length === 1) throw failures[0];
  if (failures.length > 1) {
    const error = new AggregateError(failures, failures.map((failure) => failure.message).join('; '));
    error.recoveryPaths = [...new Set(failures.flatMap((failure) => failure.recoveryPaths || []))];
    if (error.recoveryPaths[0]) error.retainedPath = error.recoveryPaths[0];
    throw error;
  }
}

function cleanupPrivateStagingAfterOperation(
  stagingDirectories,
  operationError = null,
  operationFailed = operationError !== null && operationError !== undefined,
) {
  try {
    cleanupPrivateStagingDirectories(stagingDirectories);
  } catch (cleanupError) {
    if (!operationFailed) throw cleanupError;
    const operationMessage = operationError && typeof operationError.message === 'string'
      ? operationError.message : 'operation failed';
    throw new AggregateError(
      [operationError, cleanupError],
      `${operationMessage}; private staging cleanup also failed: ${cleanupError.message}`,
      { cause: operationError },
    );
  }
}

function committedCleanupRecoveryPaths(error, additional = []) {
  const paths = [
    ...additional,
    ...(Array.isArray(error && error.recoveryPaths) ? error.recoveryPaths : []),
    error && error.retainedPath,
    error && error.additionalRetainedPath,
  ];
  return [...new Set(paths.filter((value) => typeof value === 'string' && value.trim())
    .map((value) => path.resolve(value)))];
}

function attachCommittedCleanupWarning(result, error, {
  security = {},
  component,
  phase,
  recoveryPaths = [],
} = {}) {
  const retained = committedCleanupRecoveryPaths(error, recoveryPaths);
  if (retained[0] && !error.retainedPath) error.retainedPath = retained[0];
  const warning = {
    ...privatePaths.notifyCommittedCleanupWarning(error, {
      ...security,
      cleanupComponent: component,
    }, phase),
    committed: true,
    recovery: {
      paths: retained,
      requiresExactIdentityVerification: true,
    },
  };
  if (result && typeof result === 'object') {
    result.cleanupDegraded = true;
    result.cleanupWarnings = [
      ...(Array.isArray(result.cleanupWarnings) ? result.cleanupWarnings : []),
      warning,
    ];
  }
  return warning;
}

function cleanupPrivateStagingAfterCommit(stagingDirectories, result, options) {
  try {
    cleanupPrivateStagingDirectories(stagingDirectories);
  } catch (error) {
    attachCommittedCleanupWarning(result, error, options);
  }
}

function stagingProof(staging, label) {
  const resolved = path.resolve(staging);
  const key = comparablePath(resolved);
  const expected = privateStagingProofs.get(key);
  if (!expected) throw new Error(`${label} has no filesystem identity proof: ${resolved}`);
  return { expected, key, resolved };
}

function retireTransferredPrivateStaging(staging, target, label) {
  const proof = stagingProof(staging, label);
  if (pathEntryExists(proof.resolved)) {
    throw new Error(`${label} transfer left the original staging pathname occupied: ${proof.resolved}`);
  }
  const current = exactDirectoryStat(target, `${label} transfer target`);
  if (!sameDirectoryIdentity(proof.expected, current)) {
    throw new Error(`${label} transfer target identity changed: ${target}`);
  }
  privateStagingProofs.delete(proof.key);
}

function retireRemovedPrivateStaging(staging, removedTarget, removedIdentity, label) {
  const proof = stagingProof(staging, label);
  if (!sameDirectoryIdentity(proof.expected, removedIdentity)
      || pathEntryExists(proof.resolved)
      || pathEntryExists(removedTarget)) {
    throw new Error(`${label} removal could not prove the transferred staging was deleted`);
  }
  privateStagingProofs.delete(proof.key);
}

function withPrivateRestoreDirectory(target, security, callback) {
  const privatePathSecurity = security.privatePathSecurity || security;
  return privatePaths.withPrivateDirectoryMutationLockSync(path.dirname(target), callback, {
    ...privatePathSecurity,
    fs,
    directory: true,
    label: 'SQLite restore directory',
    ownerLabel: 'SQLite restore directory',
  });
}

function withPrivatePgAuditParent(auditDirectory, security, callback) {
  const privatePathSecurity = security.privatePathSecurity || security;
  return privatePaths.withPrivateDirectoryMutationLockSync(path.dirname(auditDirectory), callback, {
    ...privatePathSecurity,
    fs,
    directory: true,
    label: 'Postgres restore audit parent',
    ownerLabel: 'Postgres restore audit parent',
  });
}

function sqliteSidecarPaths(file) {
  return SQLITE_SIDECAR_SUFFIXES.map((suffix) => `${file}${suffix}`);
}

function pathEntryExists(file) {
  try {
    fs.lstatSync(file);
    return true;
  } catch (error) {
    if (error && ['ENOENT', 'ENOTDIR'].includes(error.code)) return false;
    throw error;
  }
}

function targetArtifacts(file, sqlite = false) {
  return sqlite ? [file, ...sqliteSidecarPaths(file)] : [file];
}

function assertNoSqliteSidecars(file) {
  const sidecar = sqliteSidecarPaths(file).find(pathEntryExists);
  if (sidecar) throw new Error(`refusing SQLite artifact with unexpected sidecar: ${sidecar}`);
}

function assertWritable(file, force, { sqlite = false } = {}) {
  ensureParent(file);
  const collision = targetArtifacts(file, sqlite).find(pathEntryExists);
  if (collision && !force) throw new Error(`${collision} already exists; pass --force to overwrite`);
}

function removeTargetArtifacts(file, sqlite = false, directory = false) {
  for (const candidate of targetArtifacts(file, sqlite)) {
    fs.rmSync(candidate, { recursive: directory, force: true });
  }
}

function comparablePath(file) {
  const resolved = path.resolve(file);
  return process.platform === 'win32' ? resolved.toLowerCase() : resolved;
}

function assertDistinctArtifactTargets(items) {
  const seen = new Map();
  for (const item of items) {
    for (const candidate of targetArtifacts(item.target, item.sqlite)) {
      const comparable = comparablePath(candidate);
      if (seen.has(comparable)) {
        throw new Error(`backup output paths overlap: ${candidate} conflicts with ${seen.get(comparable)}`);
      }
      seen.set(comparable, candidate);
    }
  }
}

function writePrivateFile(file, contents, security = {}) {
  let fd;
  try {
    fd = fs.openSync(file, 'wx', PRIVATE_FILE_MODE);
    restrictPath(file, { ...security, directory: false });
    fs.writeFileSync(fd, contents);
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    return file;
  } catch (error) {
    if (fd !== undefined) try { fs.closeSync(fd); } catch {}
    fs.rmSync(file, { force: true });
    throw error;
  }
}

function fsyncFile(file) {
  let fd;
  try {
    // Windows rejects fsync on a read-only regular-file handle with EPERM.
    // These are private staged/published artifacts that we own, so open them
    // read-write while flushing their already-written bytes.
    fd = fs.openSync(file, fs.constants.O_RDWR);
    fs.fsyncSync(fd);
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

function sameFileIdentity(left, right) {
  return left.dev !== 0n && left.ino !== 0n
    && left.dev === right.dev && left.ino === right.ino;
}

function sameArtifactIdentity(left, right, directory = false) {
  if (!sameFileIdentity(left, right)) return false;
  if (directory) return left.birthtimeNs === right.birthtimeNs;
  return left.size === right.size
    && (process.platform === 'win32' || left.birthtimeNs === right.birthtimeNs);
}

function sameStableFileStat(left, right) {
  return sameFileIdentity(left, right)
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs
    && left.birthtimeNs === right.birthtimeNs;
}

function exactDirectoryStat(directory, label) {
  const stat = fs.lstatSync(directory, { bigint: true });
  if (!stat.isDirectory() || stat.isSymbolicLink?.() || stat.dev === 0n || stat.ino === 0n) {
    throw new Error(`${label} is not a stable directory`);
  }
  return stat;
}

function capturePendingFreeDirectory(pendingPath, label) {
  const directory = path.dirname(pendingPath);
  const before = exactDirectoryStat(directory, label);
  if (pathEntryExists(pendingPath)) throw new Error(`${label} contains pending audit high-water state`);
  const after = exactDirectoryStat(directory, label);
  if (!sameStableFileStat(before, after)) throw new Error(`${label} changed while checking pending state`);
  return after;
}

function assertPendingFreeDirectoryUnchanged(pendingPath, expected, label) {
  if (pathEntryExists(pendingPath)) throw new Error(`${label} contains pending audit high-water state`);
  const after = exactDirectoryStat(path.dirname(pendingPath), label);
  if (!sameStableFileStat(expected, after)) throw new Error(`${label} changed during restore`);
}

function assertStableRestoreSource(stat, expectedBytes, maxBytes, label) {
  const expected = BigInt(expectedBytes);
  const maximum = BigInt(maxBytes);
  if (!stat.isFile() || stat.isSymbolicLink?.() || stat.nlink !== 1n
      || stat.size !== expected || stat.size > maximum) {
    throw new Error(`${label} is not the authenticated regular file`);
  }
}

function writeComplete(fd, buffer, length) {
  let offset = 0;
  while (offset < length) {
    const written = fs.writeSync(fd, buffer, offset, length - offset, null);
    if (!written) throw new Error('failed to write the private restore snapshot');
    offset += written;
  }
}

function copyOpenedRestoreArtifact(sourceFd, targetFd, maxBytes, label) {
  const buffer = Buffer.alloc(Math.min(RESTORE_COPY_BUFFER_BYTES, maxBytes + 1));
  let total = 0;
  while (true) {
    const count = fs.readSync(sourceFd, buffer, 0, buffer.length, null);
    if (!count) return total;
    total += count;
    if (total > maxBytes) throw new Error(`${label} exceeded its authenticated size while copying`);
    writeComplete(targetFd, buffer, count);
  }
}

function openStableRestoreSource(source, expectedBytes, maxBytes, label) {
  const before = fs.lstatSync(source, { bigint: true });
  assertStableRestoreSource(before, expectedBytes, maxBytes, label);
  const fd = fs.openSync(source, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const stat = fs.fstatSync(fd, { bigint: true });
    assertStableRestoreSource(stat, expectedBytes, maxBytes, label);
    if (!sameStableFileStat(before, stat)) throw new Error(`${label} changed while opening`);
    return { fd, stat };
  } catch (error) {
    fs.closeSync(fd);
    throw error;
  }
}

function assertRestoreSourceUnchanged(fd, opened, copied, expectedBytes, label) {
  const after = fs.fstatSync(fd, { bigint: true });
  if (copied !== expectedBytes || after.size !== opened.size
      || !sameStableFileStat(opened, after)) throw new Error(`${label} changed while copying`);
}

function finishRestoreArtifactCopy(sourceFd, targetFd, target, targetCreated, complete) {
  let failure = null;
  for (const fd of [targetFd, sourceFd]) {
    if (fd === undefined) continue;
    try { fs.closeSync(fd); } catch (error) { failure ||= error; }
  }
  if (targetCreated && !complete) {
    try { fs.rmSync(target, { force: true }); } catch (error) { failure ||= error; }
  }
  if (failure) throw failure;
}

function copyPrivateRestoreArtifact(source, target, {
  expectedBytes,
  maxBytes = expectedBytes,
  label = 'backup artifact',
  security = {},
} = {}) {
  if (!Number.isSafeInteger(expectedBytes) || expectedBytes < 1
      || !Number.isSafeInteger(maxBytes) || maxBytes < expectedBytes) {
    throw new Error(`${label} has an invalid authenticated size`);
  }
  const sourceFile = openStableRestoreSource(source, expectedBytes, maxBytes, label);
  let targetFd;
  let targetCreated = false;
  let complete = false;
  try {
    targetFd = fs.openSync(target, 'wx', PRIVATE_FILE_MODE);
    targetCreated = true;
    restrictPath(target, { ...security, directory: false });
    const copied = copyOpenedRestoreArtifact(sourceFile.fd, targetFd, maxBytes, label);
    assertRestoreSourceUnchanged(sourceFile.fd, sourceFile.stat, copied, expectedBytes, label);
    fs.fsyncSync(targetFd);
    complete = true;
    return target;
  } finally {
    finishRestoreArtifactCopy(sourceFile.fd, targetFd, target, targetCreated, complete);
  }
}

function fsyncPublishedArtifact(item) {
  if (item.directory) privatePaths.fsyncDirectory(item.target, { fs });
  else fsyncFile(item.target);
  const targetParent = path.dirname(item.target);
  const stagedParent = path.dirname(item.staged);
  privatePaths.fsyncDirectory(targetParent, { fs });
  if (comparablePath(stagedParent) !== comparablePath(targetParent)) {
    // A cross-directory rename is not durable until both the removed source
    // entry and the installed destination entry have reached their parents.
    privatePaths.fsyncDirectory(stagedParent, { fs });
  }
}

function captureArtifactPermissions(target, security = {}) {
  const platform = security.platform || process.platform;
  if (platform === 'win32') {
    return { platform, sddl: captureWindowsDacl(target, security) };
  }
  return { platform, mode: fs.statSync(target).mode & 0o777 };
}

function restoreArtifactPermissions(target, permissions, security = {}) {
  if (permissions.platform === 'win32') {
    restoreWindowsDacl(target, permissions.sddl, security);
  } else {
    fs.chmodSync(target, permissions.mode);
  }
}

function exactArtifactStat(target, directory, label = 'backup artifact') {
  const stat = fs.lstatSync(target, { bigint: true });
  if (stat.isSymbolicLink?.() || stat.dev === 0n || stat.ino === 0n
      || (directory ? !stat.isDirectory() : !stat.isFile())) {
    throw new Error(`${label} has no stable filesystem identity: ${target}`);
  }
  return stat;
}

function assertExistingArtifactType(target, directory) {
  const stat = exactArtifactStat(target, directory, 'replacement artifact');
  if (!directory && stat.nlink !== 1n) {
    throw new Error(`refusing unsafe replacement artifact: ${target}`);
  }
  return stat;
}

function quarantinePath(target, purpose) {
  return path.join(
    path.dirname(target),
    `.${path.basename(target)}.${purpose}-${process.pid}-${crypto.randomBytes(12).toString('hex')}`,
  );
}

function quarantinedArtifactMatchesPublication(artifact, current) {
  if (!sameArtifactIdentity(artifact.identity, current, artifact.directory)) return false;
  if (artifact.directory || current.nlink === 1n) return true;
  if (artifact.finalStat || current.nlink !== 2n) return false;
  try {
    const staged = exactArtifactStat(artifact.staged, false, 'linked staging artifact');
    return staged.nlink === 2n && sameArtifactIdentity(artifact.identity, staged, false);
  } catch {
    return false;
  }
}

function quarantineOwnedArtifact(artifact) {
  if (!pathEntryExists(artifact.target)) {
    return { retained: [`${artifact.target} (missing after publication)`], blocked: [] };
  }
  const quarantine = quarantinePath(artifact.target, 'quarantine');
  try {
    fs.renameSync(artifact.target, quarantine);
  } catch (error) {
    return {
      retained: [],
      blocked: [`${artifact.target} (${error.code || error.message})`],
    };
  }
  try {
    const current = exactArtifactStat(quarantine, artifact.directory, 'quarantined backup artifact');
    if (!quarantinedArtifactMatchesPublication(artifact, current)) {
      return { retained: [quarantine], blocked: [] };
    }
    fs.rmSync(quarantine, { recursive: artifact.directory, force: true });
    privatePaths.fsyncDirectory(path.dirname(artifact.target), { fs });
    return { retained: [], blocked: [] };
  } catch {
    return { retained: [quarantine], blocked: [] };
  }
}

function removePublishedArtifacts(published) {
  const result = { retained: [], blocked: [] };
  for (const artifact of [...published].reverse()) {
    const removed = quarantineOwnedArtifact(artifact);
    result.retained.push(...removed.retained);
    result.blocked.push(...removed.blocked);
  }
  return result;
}

function cleanupRollbackDirs(state) {
  const result = { retained: [], blocked: [] };
  for (const artifact of state.directories.values()) {
    const removed = quarantineOwnedArtifact({ ...artifact, target: artifact.path, directory: true });
    result.retained.push(...removed.retained);
    result.blocked.push(...removed.blocked);
  }
  if (result.retained.length || result.blocked.length) {
    const remaining = [...result.retained, ...result.blocked];
    const error = new Error(`failed to remove private rollback state; recovery directories or paths remain: ${remaining.join(', ')}`);
    error.code = 'BACKUP_ROLLBACK_CLEANUP_FAILED';
    error.recoveryPaths = result.retained.slice();
    if (error.recoveryPaths[0]) error.retainedPath = error.recoveryPaths[0];
    throw error;
  }
}

function quarantineRollbackCollisions(state) {
  const retained = [];
  const blocked = [];
  for (const artifact of state.moved) {
    if (!pathEntryExists(artifact.target)) continue;
    const quarantine = quarantinePath(artifact.target, 'retained');
    try {
      fs.renameSync(artifact.target, quarantine);
      retained.push(quarantine);
    } catch (error) {
      blocked.push(`${artifact.target} (${error.code || error.message})`);
    }
  }
  return { retained, blocked };
}

function restoreMovedArtifacts(state) {
  const failures = [];
  for (const artifact of [...state.moved].reverse()) {
    try {
      if (pathEntryExists(artifact.target)) {
        throw new Error(`rollback target is occupied: ${artifact.target}`);
      }
      const stagedIdentity = exactArtifactStat(artifact.staged, artifact.directory, 'rollback artifact');
      if (!sameArtifactIdentity(artifact.identity, stagedIdentity, artifact.directory)) {
        throw new Error(`rollback artifact identity changed: ${artifact.staged}`);
      }
      fs.renameSync(artifact.staged, artifact.target);
      const restoredIdentity = exactArtifactStat(artifact.target, artifact.directory, 'restored rollback artifact');
      if (!sameArtifactIdentity(artifact.identity, restoredIdentity, artifact.directory)) {
        throw new Error(`restored rollback artifact identity changed: ${artifact.target}`);
      }
      restoreArtifactPermissions(artifact.target, artifact.permissions, state.security);
      fsyncPublishedArtifact({
        staged: artifact.staged,
        target: artifact.target,
        directory: artifact.directory,
      });
    } catch (error) {
      failures.push(error);
    }
  }
  if (failures.length) {
    const recoveryDirs = [...state.directories.values()].map((entry) => entry.path).join(', ');
    throw new Error(`failed to restore replaced backup artifacts; recovery state remains in: ${recoveryDirs}`, {
      cause: failures[0],
    });
  }
  cleanupRollbackDirs(state);
}

function stageExistingArtifacts(items, security = {}) {
  const state = { directories: new Map(), moved: [], security };
  try {
    for (const item of items) {
      for (const target of targetArtifacts(item.target, item.sqlite)) {
        if (!pathEntryExists(target)) continue;
        const parent = path.dirname(target);
        if (!state.directories.has(parent)) {
          const rollbackDirectory = createPrivateStagingDir(parent, security);
          state.directories.set(parent, {
            path: rollbackDirectory,
            identity: exactDirectoryStat(rollbackDirectory, 'private rollback directory'),
          });
        }
        const staged = path.join(state.directories.get(parent).path, `${state.moved.length}-${path.basename(target)}`);
        const permissions = captureArtifactPermissions(target, security);
        const identity = assertExistingArtifactType(target, item.directory === true);
        fs.renameSync(target, staged);
        const movedIdentity = exactArtifactStat(staged, item.directory === true, 'staged rollback artifact');
        if (!sameArtifactIdentity(identity, movedIdentity, item.directory === true)) {
          throw new Error(`replacement artifact identity changed while staging: ${target}`);
        }
        state.moved.push({ target, staged, permissions, identity, directory: item.directory === true });
        restrictPath(staged, { ...security, directory: item.directory === true });
      }
    }
    return state;
  } catch (error) {
    try { restoreMovedArtifacts(state, items); } catch (rollbackError) { throw rollbackError; }
    throw error;
  }
}

function publishStagedFiles(items, security = {}) {
  const published = [];
  try {
    for (const item of items) {
      const identity = exactArtifactStat(item.staged, item.directory === true, 'staged publication artifact');
      if (!item.directory && identity.nlink !== 1n) {
        throw new Error(`staged publication artifact has unexpected links: ${item.staged}`);
      }
      if (item.directory) fs.renameSync(item.staged, item.target);
      else fs.linkSync(item.staged, item.target);
      const artifact = { ...item, identity, directory: item.directory === true };
      published.push(artifact);
      const targetIdentity = exactArtifactStat(item.target, item.directory === true, 'published backup artifact');
      if (!sameArtifactIdentity(identity, targetIdentity, item.directory === true)) {
        throw new Error(`published backup artifact identity changed: ${item.target}`);
      }
      if (!item.directory) fs.unlinkSync(item.staged);
      restrictPath(item.target, { ...security, directory: item.directory === true });
      if (item.sqlite) assertNoSqliteSidecars(item.target);
      fsyncPublishedArtifact(item);
      const finalIdentity = exactArtifactStat(item.target, item.directory === true, 'published backup artifact');
      if (!sameArtifactIdentity(identity, finalIdentity, item.directory === true)
          || (!item.directory && finalIdentity.nlink !== 1n)) {
        throw new Error(`published backup artifact identity changed: ${item.target}`);
      }
      artifact.finalStat = finalIdentity;
    }
    return published;
  } catch (error) {
    error.publishedArtifacts = published;
    throw error;
  }
}

function assertPublishedArtifactsCurrent(published) {
  for (const artifact of published) {
    const current = exactArtifactStat(
      artifact.target,
      artifact.directory,
      'verified published backup artifact',
    );
    if (!sameStableFileStat(artifact.finalStat, current)
        || (!artifact.directory && current.nlink !== 1n)) {
      throw new Error(`published backup artifact identity changed during verification: ${artifact.target}`);
    }
  }
}

/**
 * Publish staged files without overwriting a path created after preflight.
 * Staging lives in each target's parent, so a hard link is an atomic,
 * same-filesystem no-replace operation and preserves the private mode/ACL.
 */
function publishPrivateFiles(items, { force = false, security = {}, verify = null } = {}) {
  assertDistinctArtifactTargets(items);
  for (const item of items) assertWritable(item.target, force, { sqlite: item.sqlite });
  const rollback = force ? stageExistingArtifacts(items, security) : null;
  let published = [];
  let verification;
  try {
    published = publishStagedFiles(items, security);
    verification = typeof verify === 'function' ? verify() : undefined;
    assertPublishedArtifactsCurrent(published);
  } catch (error) {
    published = error.publishedArtifacts || published;
    const cleanup = removePublishedArtifacts(published);
    let retained = cleanup.retained;
    let blocked = cleanup.blocked;
    if (rollback && blocked.length === 0) {
      const collisions = quarantineRollbackCollisions(rollback);
      retained = retained.concat(collisions.retained);
      blocked = blocked.concat(collisions.blocked);
    }
    if (rollback && blocked.length === 0) {
      try {
        restoreMovedArtifacts(rollback);
      } catch (rollbackError) {
        throw new Error(`backup publish failed (${error.message}); ${rollbackError.message}`, { cause: error });
      }
    }
    if (blocked.length) {
      const recovery = rollback ? [...rollback.directories.values()].map((entry) => entry.path) : [];
      throw new Error(`backup publish failed (${error.message}); public paths could not be cleared: ${blocked.join(', ')}; recovery state remains: ${recovery.join(', ')}`, {
        cause: error,
      });
    }
    if (retained.length) {
      throw new Error(`backup publish failed (${error.message}); changed artifacts were preserved at: ${retained.join(', ')}`, { cause: error });
    }
    throw error;
  }
  if (rollback) {
    try {
      cleanupRollbackDirs(rollback);
    } catch (error) {
      attachCommittedCleanupWarning(verification, error, {
        security,
        component: 'backup-artifact-publication',
        phase: 'rollback-artifact-cleanup',
        recoveryPaths: [...rollback.directories.values()].map((entry) => entry.path)
          .filter((directory) => pathEntryExists(directory)),
      });
    }
  }
  return verification;
}

function snapshotStatsFromRows(rows, date = new Date()) {
  const counts = {};
  const entity = {};
  const today = date.toISOString().slice(0, 10);
  let todayBlocked = 0;
  for (const row of rows) {
    counts[row.status] = (counts[row.status] || 0) + 1;
    if (String(row.createdAt || '').slice(0, 10) === today && STATS_BLOCKED_STATUSES.has(row.status)) {
      todayBlocked += 1;
    }
    const stored = typeof row.data === 'string' ? JSON.parse(row.data) : row.data;
    for (const [type, count] of Object.entries((stored && stored.entityCounts) || {})) {
      entity[type] = (entity[type] || 0) + count;
    }
  }
  return {
    total: rows.length,
    pending: counts.pending || 0,
    approved: counts.approved || 0,
    denied: counts.denied || 0,
    allowed: counts.allowed || 0,
    todayBlocked,
    topEntities: Object.entries(entity).sort((a, b) => b[1] - a[1]).slice(0, 8),
  };
}

function inspectSqliteSnapshot(file, security = {}, anchor = null) {
  const staging = createPrivateStagingDir(os.tmpdir(), security);
  const inspectionFile = path.join(staging, 'inspection.db');
  let dbFile;
  let operationError;
  try {
    fs.copyFileSync(file, inspectionFile, fs.constants.COPYFILE_EXCL);
    restrictPath(inspectionFile, { ...security, directory: false });
    dbFile = new Database(inspectionFile, { readonly: true, fileMustExist: true });
    let exactCheckpoint = null;
    const verifyOptions = anchor ? {
      key: anchor.key,
      checkpoint: anchor.checkpoint,
      onVerified(checkpoint) { exactCheckpoint = checkpoint; },
    } : {};
    return {
      auditIntegrity: auditIntegrity.verifyAuditChainForDatabase(dbFile, verifyOptions),
      exactCheckpoint,
      stats: snapshotStatsFromRows(
        dbFile.prepare('SELECT status, createdAt, data FROM queries ORDER BY seq ASC').all(),
      ),
    };
  } catch (error) {
    operationError = error;
    throw error;
  } finally {
    if (dbFile) dbFile.close();
    cleanupPrivateStagingAfterOperation([staging], operationError);
  }
}

function backupAuditArtifactPaths(file) {
  const dbPath = path.resolve(file);
  return {
    statePath: `${dbPath}${BACKUP_AUDIT_STATE_SUFFIX}`,
    checkpointPath: `${dbPath}${BACKUP_AUDIT_CHECKPOINT_SUFFIX}`,
  };
}

function restoredAuditAnchorPaths(file) {
  return runtimeAuditAnchorPaths(`${path.resolve(file)}.audit-integrity`);
}

function runtimeAuditAnchorPaths(directory) {
  const resolved = path.resolve(directory);
  return {
    directory: resolved,
    statePath: path.join(resolved, AUDIT_STATE_NAME),
    checkpointPath: path.join(resolved, AUDIT_CHECKPOINT_NAME),
    pendingPath: path.join(resolved, '.audit-integrity-pending.json'),
  };
}

function auditAnchorReadOptions(security = {}) {
  return security.privatePathSecurity
    ? { privatePathSecurity: security.privatePathSecurity }
    : {};
}

function sameCanonicalJson(left, right) {
  return auditIntegrity.canonical(left) === auditIntegrity.canonical(right);
}

function loadAuthenticatedAuditAnchor(paths, env = process.env, security = {}) {
  if (!paths || !paths.statePath || !paths.checkpointPath) {
    throw new Error('audit integrity sidecar paths are unavailable');
  }
  if (paths.directory) assertExistingArtifactType(path.resolve(paths.directory), true);
  const options = auditAnchorReadOptions(security);
  const externalKey = auditAnchorInternal.configuredKey(env);
  const loaded = auditAnchorInternal.loadState(path.resolve(paths.statePath), externalKey, options);
  const state = auditAnchorInternal.readPrivateJson(
    path.resolve(paths.statePath),
    MAX_AUDIT_STATE_BYTES,
    options,
  );
  const expectedState = auditAnchorInternal.signedState(
    loaded.key,
    loaded.checkpointCreated,
    loaded.embedded,
    loaded.pendingProtocol,
    loaded.databaseScope,
  );
  if (!loaded.checkpointCreated || !sameCanonicalJson(state, expectedState)) {
    throw new Error('audit integrity state authentication failed');
  }
  const checkpoint = auditAnchorInternal.readPrivateJson(
    path.resolve(paths.checkpointPath),
    MAX_AUDIT_CHECKPOINT_BYTES,
    options,
  );
  if (!auditIntegrity.validCheckpoint(checkpoint, loaded.key)) {
    throw new Error('audit integrity checkpoint authentication failed');
  }
  const expectedCheckpoint = auditIntegrity.createCheckpoint(
    checkpoint.count,
    checkpoint.head,
    loaded.key,
    checkpoint.seq,
  );
  if (!sameCanonicalJson(checkpoint, expectedCheckpoint)) {
    throw new Error('audit integrity checkpoint is malformed');
  }
  return { key: loaded.key, embedded: loaded.embedded, state, checkpoint };
}

function independentManifestKey(anchor) {
  if (!anchor || anchor.embedded) {
    const error = new Error(
      'backup manifest authentication requires REDACTWALL_AUDIT_KEY or REDACTWALL_SECRET; embedded audit keys are not independent of the backup',
    );
    error.code = 'BACKUP_MANIFEST_KEY_NOT_INDEPENDENT';
    throw error;
  }
  return anchor.key;
}

function inspectAuthenticatedSqliteSnapshot(file, anchor, security = {}, requireExactCheckpoint = true) {
  const snapshot = inspectSqliteSnapshot(file, security, anchor);
  if (snapshot.auditIntegrity.ok && !snapshot.exactCheckpoint) {
    snapshot.auditIntegrity = {
      ok: false,
      count: snapshot.auditIntegrity.count,
      reason: 'checkpoint-not-produced',
    };
  } else if (snapshot.auditIntegrity.ok && requireExactCheckpoint
      && !sameCanonicalJson(anchor.checkpoint, snapshot.exactCheckpoint)) {
    snapshot.auditIntegrity = {
      ok: false,
      count: snapshot.auditIntegrity.count,
      reason: 'checkpoint-not-snapshot-head',
    };
  }
  return snapshot;
}

function isSafeArtifactBasename(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 255
    && value !== '.' && value !== '..' && !value.includes('/') && !value.includes('\\')
    && path.basename(value) === value;
}

function artifactDescriptor(file, publishedFile = file) {
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.nlink && stat.nlink !== 1)) {
    throw new Error(`backup artifact is not a safe regular file: ${file}`);
  }
  return {
    file: path.basename(publishedFile),
    bytes: stat.size,
    sha256: sha256File(file),
  };
}

function validateArtifactManifest(manifest, driver, paths, descriptors) {
  if (!manifest || manifest.schemaVersion !== 2 || manifest.driver !== driver) {
    return { ok: false, reason: 'unsupported-schema' };
  }
  const names = ['database', 'auditState', 'auditCheckpoint'];
  if (!manifest.artifacts || typeof manifest.artifacts !== 'object' || Array.isArray(manifest.artifacts)
      || Object.keys(manifest.artifacts).sort().join(',') !== names.slice().sort().join(',')) {
    return { ok: false, reason: 'artifact-schema' };
  }
  const expectedPaths = {
    database: paths.database,
    auditState: paths.auditState,
    auditCheckpoint: paths.auditCheckpoint,
  };
  const seen = new Set();
  for (const name of names) {
    const declared = manifest.artifacts[name];
    const actual = descriptors[name];
    const expectedName = path.basename(expectedPaths[name]);
    if (!declared || typeof declared !== 'object' || Array.isArray(declared)
        || !isSafeArtifactBasename(declared.file) || declared.file !== expectedName
        || seen.has(declared.file) || !Number.isSafeInteger(declared.bytes) || declared.bytes < 1
        || !/^[a-f0-9]{64}$/.test(String(declared.sha256 || ''))
        || declared.bytes !== actual.bytes || declared.sha256 !== actual.sha256) {
      return { ok: false, reason: 'artifact-mismatch' };
    }
    seen.add(declared.file);
  }
  const database = descriptors.database;
  if (!isSafeArtifactBasename(manifest.backupFile)
      || manifest.backupFile !== database.file
      || manifest.backupBytes !== database.bytes
      || manifest.backupSha256 !== database.sha256) {
    return { ok: false, reason: 'database-metadata-mismatch' };
  }
  return { ok: true };
}

function validateSqliteManifest(manifest, paths, descriptors, key) {
  const portableLayout = manifest && manifest.format === SQLITE_BACKUP_FORMAT
    && manifest.artifactLayout === undefined;
  const runtimeLayout = manifest && manifest.format === SQLITE_RESTORED_FORMAT
    && manifest.artifactLayout === SQLITE_RUNTIME_LAYOUT;
  if (!portableLayout && !runtimeLayout) {
    return { ok: false, reason: 'unsupported-layout' };
  }
  const artifacts = validateArtifactManifest(manifest, 'sqlite', paths, descriptors);
  if (!artifacts.ok) return artifacts;
  if (!validManifestAuthentication(manifest, key)) {
    return { ok: false, reason: 'manifest-authentication' };
  }
  return artifacts;
}

function sameHex(left, right) {
  if (!/^[a-f0-9]{64}$/i.test(String(left || '')) || !/^[a-f0-9]{64}$/i.test(String(right || ''))) {
    return false;
  }
  return crypto.timingSafeEqual(Buffer.from(left, 'hex'), Buffer.from(right, 'hex'));
}

function authenticateManifest(manifest, key) {
  const body = { ...manifest };
  return {
    ...body,
    manifestAuthentication: {
      version: MANIFEST_AUTH_VERSION,
      algorithm: 'hmac-sha256',
      mac: auditIntegrity.hmac(key, auditIntegrity.canonical(body)),
    },
  };
}

function buildRestoredSqliteManifest(sourceManifest, descriptors, key) {
  const {
    manifestAuthentication: sourceAuthentication,
    artifacts: _sourceArtifacts,
    backupFile: sourceBackupFile,
    backupBytes: _sourceBackupBytes,
    backupSha256: sourceBackupSha256,
    format: _sourceFormat,
    artifactLayout: _sourceLayout,
    restoredAt: _previousRestoredAt,
    restoredFrom: _previousRestore,
    note: _sourceNote,
    ...metadata
  } = sourceManifest;
  return authenticateManifest({
    ...metadata,
    schemaVersion: 2,
    driver: 'sqlite',
    format: SQLITE_RESTORED_FORMAT,
    artifactLayout: SQLITE_RUNTIME_LAYOUT,
    restoredAt: new Date().toISOString(),
    restoredFrom: {
      backupFile: sourceBackupFile,
      backupSha256: sourceBackupSha256,
      manifestMac: sourceAuthentication.mac,
    },
    backupFile: descriptors.database.file,
    backupBytes: descriptors.database.bytes,
    backupSha256: descriptors.database.sha256,
    artifacts: descriptors,
    note: 'This authenticated manifest binds the restored database to its runtime audit state and checkpoint sidecars.',
  }, key);
}

function validManifestAuthentication(manifest, key) {
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) return false;
  const { manifestAuthentication, ...body } = manifest;
  if (!manifestAuthentication || typeof manifestAuthentication !== 'object'
      || Array.isArray(manifestAuthentication)
      || Object.keys(manifestAuthentication).sort().join(',') !== 'algorithm,mac,version'
      || manifestAuthentication.version !== MANIFEST_AUTH_VERSION
      || manifestAuthentication.algorithm !== 'hmac-sha256') {
    return false;
  }
  const expected = auditIntegrity.hmac(key, auditIntegrity.canonical(body));
  return sameHex(manifestAuthentication.mac, expected);
}

function validatePgManifest(manifest, paths, descriptors, checkpoint, key) {
  const artifacts = validateArtifactManifest(manifest, 'postgres', paths, descriptors);
  if (!artifacts.ok) return artifacts;
  if (!validManifestAuthentication(manifest, key)) {
    return { ok: false, reason: 'manifest-authentication' };
  }
  if (!sameCanonicalJson(manifest.checkpoint, checkpoint)) {
    return { ok: false, reason: 'checkpoint-metadata-mismatch' };
  }
  if (manifest.format !== 'pg_dump-custom'
      || !manifest.sourceIntegrity || manifest.sourceIntegrity.ok !== true
      || !Number.isSafeInteger(manifest.sourceIntegrity.count)
      || manifest.sourceIntegrity.count !== checkpoint.count
      || !manifest.backupIntegrity || manifest.backupIntegrity.ok !== true
      || manifest.backupIntegrity.count !== checkpoint.count
      || !sameCanonicalJson(manifest.sourceIntegrity, manifest.backupIntegrity)) {
    return { ok: false, reason: 'integrity-metadata-mismatch' };
  }
  try {
    validatePgDatabaseDefinition(manifest.sourceDatabaseDefinition);
  } catch {
    return { ok: false, reason: 'database-definition' };
  }
  return artifacts;
}

function resolveCreateTargets({ outDir, file, manifestFile, extension = '.db' } = {}) {
  const backupDir = path.resolve(outDir || path.join(process.cwd(), 'backups'));
  const backupFile = path.resolve(file || path.join(backupDir, `redactwall-${nowStamp()}${extension}`));
  const manifestPath = path.resolve(manifestFile || `${backupFile}.manifest.json`);
  return { backupFile, manifestPath };
}

function assertBackupSource(db) {
  const sourceIntegrity = db.verifyAuditChain();
  if (!sourceIntegrity.ok) {
    throw new Error(`refusing to back up a database with broken audit integrity: ${sourceIntegrity.reason || 'unknown'}`);
  }
  return sourceIntegrity;
}

function readManifest(file) {
  const manifestPath = file.endsWith('.json') ? file : `${file}.manifest.json`;
  if (!fs.existsSync(manifestPath)) return null;
  return JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
}

// ---- Postgres mode -----------------------------------------------------------

const PG_TOOL_INSTALL_HINT = 'install the PostgreSQL client tools (Debian/Ubuntu: apt-get install postgresql-client; ' +
  'RHEL/Amazon Linux: dnf install postgresql16; macOS: brew install libpq) with a major version >= the server\'s';

function assertPostgresConnectionUrl(connectionString, options = {}) {
  const env = options.env || process.env;
  const allowLoopbackPlaintext = env.NODE_ENV !== 'production';
  try {
    parsePostgresConnectionUrl(connectionString);
  } catch {
    throw new Error('Postgres backup connection URL is invalid, ambiguous, or uses unsupported parameters');
  }
  if (!validPostgresTlsUrl(connectionString, { allowLoopbackPlaintext })) {
    throw new Error('Postgres backup connections must use sslmode=require, verify-ca, or verify-full; only loopback plaintext is allowed outside production');
  }
  return connectionString;
}

function postgresDriverConfigured(env = process.env) {
  return new Set(['postgres', 'postgresql', 'pg'])
    .has(String(env.REDACTWALL_DB_DRIVER || '').trim().toLowerCase());
}

function pgConnectionString(explicit) {
  const connectionString = explicit || process.env.REDACTWALL_DATABASE_URL || process.env.DATABASE_URL;
  if (!connectionString) throw new Error('postgres backups require REDACTWALL_DATABASE_URL');
  return assertPostgresConnectionUrl(connectionString);
}

/** Custom-format pg_dump archives start with the "PGDMP" magic bytes. */
function isPgDumpFile(file) {
  let fd;
  try { fd = fs.openSync(file, 'r'); } catch { return false; }
  try {
    const head = Buffer.alloc(5);
    fs.readSync(fd, head, 0, 5, 0);
    return head.toString('latin1') === 'PGDMP';
  } finally {
    fs.closeSync(fd);
  }
}

const LIBPQ_QUERY_ENV = Object.freeze({
  options: 'PGOPTIONS',
  application_name: 'PGAPPNAME',
  sslmode: 'PGSSLMODE',
  sslcert: 'PGSSLCERT',
  sslkey: 'PGSSLKEY',
  sslrootcert: 'PGSSLROOTCERT',
});

const SENSITIVE_DATABASE_QUERY_PARAMS = new Set([
  'password',
  'sslpassword',
  'passfile',
  'sslcert',
  'sslkey',
  'sslrootcert',
  'sslcrl',
  'sslcrldir',
]);

/** libpq environment for pg_dump/pg_restore: credentials via env, never argv. */
function pgConnectionEnv(connectionString) {
  assertPostgresConnectionUrl(connectionString);
  const parsed = parsePostgresConnectionUrl(connectionString);
  const env = withoutPostgresConnectionEnv(process.env);
  env.PGHOST = parsed.host;
  if (parsed.port) env.PGPORT = parsed.port;
  env.PGUSER = parsed.user;
  if (parsed.password) env.PGPASSWORD = parsed.password;
  env.PGDATABASE = parsed.database;
  for (const [parameter, variable] of Object.entries(LIBPQ_QUERY_ENV)) {
    if (Object.prototype.hasOwnProperty.call(parsed.query, parameter)) {
      env[variable] = parsed.query[parameter];
    }
  }
  return env;
}

/**
 * Explicit node-postgres authority matching the validated URL/libpq target.
 * Every field that node-postgres otherwise fills from PG* is set here. The
 * password stays non-enumerable and is supplied by a function even when empty,
 * preventing pgpass/PGPASSWORD fallback without exposing it in logged config.
 */
function pgClientConfig(connectionString, options = {}) {
  assertPostgresConnectionUrl(connectionString, options);
  const parsed = parsePostgresConnectionUrl(connectionString);
  const nodeParsed = parsePgConnectionString(parsed.raw);
  const config = {
    host: parsed.host,
    port: parsed.port ? Number(parsed.port) : PG_DEFAULT_PORT,
    user: parsed.user,
    database: parsed.database,
    ssl: Object.prototype.hasOwnProperty.call(nodeParsed, 'ssl') ? nodeParsed.ssl : false,
    options: parsed.query.options || PG_SNAPSHOT_DEFAULT_OPTIONS,
    application_name: parsed.query.application_name || PG_SNAPSHOT_DEFAULT_APPLICATION,
    connectionTimeoutMillis: 0,
    client_encoding: 'UTF8',
    replication: 'false',
    sslnegotiation: 'postgres',
  };
  Object.defineProperty(config, 'password', {
    configurable: false,
    enumerable: false,
    writable: false,
    value: () => parsed.password,
  });
  return config;
}

function pgDatabaseName(connectionString) {
  return parsePostgresConnectionUrl(connectionString).database;
}

/** `to` is either a bare database name (same server) or a full postgres:// URL. */
function deriveDatabaseUrl(baseConnectionString, to) {
  if (/^[A-Za-z_][A-Za-z0-9_$]*$/.test(to)) {
    const url = new URL(baseConnectionString);
    url.pathname = '/' + to;
    return url.toString();
  }
  return new URL(to).toString();
}

function requirePgDatabaseIdentifier(value, label = 'Postgres database') {
  const name = String(value || '');
  if (!PG_DATABASE_IDENTIFIER_RE.test(name)) {
    throw new Error(`${label} name must be a 1-63 byte unquoted Postgres identifier`);
  }
  return name;
}

function quotePgIdentifier(value) {
  return `"${String(value).replace(/"/g, '""')}"`;
}

function quotePgLiteral(value) {
  return `'${String(value).replace(/'/g, "''")}'`;
}

function pgDatabaseDefinitionClauses(value, targetServerMajor) {
  const definition = validatePgDatabaseDefinition(value);
  if (![16, 17].includes(Number(targetServerMajor))
      || (definition.localeProvider === 'builtin' && Number(targetServerMajor) < 17)) {
    throw new Error('Postgres target cannot reproduce the authenticated source database definition');
  }
  const clauses = [
    `ENCODING ${quotePgLiteral(definition.encoding)}`,
    `LOCALE_PROVIDER ${definition.localeProvider}`,
    `LC_COLLATE ${quotePgLiteral(definition.lcCollate)}`,
    `LC_CTYPE ${quotePgLiteral(definition.lcCtype)}`,
  ];
  if (definition.localeProvider === 'icu') clauses.push(`ICU_LOCALE ${quotePgLiteral(definition.locale)}`);
  if (definition.localeProvider === 'builtin') clauses.push(`BUILTIN_LOCALE ${quotePgLiteral(definition.locale)}`);
  if (definition.icuRules) clauses.push(`ICU_RULES ${quotePgLiteral(definition.icuRules)}`);
  return clauses;
}

function pgUrlForDatabase(connectionString, database) {
  const name = requirePgDatabaseIdentifier(database);
  const url = new URL(connectionString);
  url.pathname = `/${name}`;
  return url.toString();
}

function pgRestoreDatabasePlan(baseConnectionString, to, env = process.env, randomBytes = crypto.randomBytes) {
  const fullTarget = /^(?:postgres|postgresql):\/\//i.test(String(to || ''));
  if (!fullTarget) requirePgDatabaseIdentifier(to, 'Postgres restore target');
  const targetUrl = deriveDatabaseUrl(baseConnectionString, to);
  assertPostgresConnectionUrl(targetUrl, { env });
  const targetDatabase = requirePgDatabaseIdentifier(pgDatabaseName(targetUrl), 'Postgres restore target');
  const maintenanceDatabase = fullTarget
    ? requirePgDatabaseIdentifier(
        env.REDACTWALL_PG_MAINTENANCE_DATABASE || DEFAULT_PG_MAINTENANCE_DATABASE,
        'Postgres maintenance database',
      )
    : pgDatabaseName(baseConnectionString);
  const maintenanceUrl = fullTarget
    ? pgUrlForDatabase(targetUrl, maintenanceDatabase)
    : baseConnectionString;
  assertPostgresConnectionUrl(maintenanceUrl, { env });
  const entropy = randomBytes(12);
  if (!Buffer.isBuffer(entropy) || entropy.length !== 12) {
    throw new Error('Postgres restore staging-name entropy is unavailable');
  }
  const stagingDatabase = requirePgDatabaseIdentifier(
    `redactwall_restore_${entropy.toString('hex')}`,
    'Postgres restore staging database',
  );
  return {
    maintenanceUrl,
    maintenanceDatabase,
    targetUrl,
    targetDatabase,
    stagingUrl: pgUrlForDatabase(targetUrl, stagingDatabase),
    stagingDatabase,
  };
}

/** Credential-free form for output: user and host stay, the password goes. */
function sanitizeDatabaseUrl(connectionString) {
  const url = new URL(connectionString);
  url.password = '';
  url.hash = '';
  for (const parameter of SENSITIVE_DATABASE_QUERY_PARAMS) url.searchParams.delete(parameter);
  return url.toString();
}

function runPgTool(tool, args, connectionString) {
  const result = spawnSync(tool, [...args, '--no-password'], {
    env: pgConnectionEnv(connectionString),
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.error && result.error.code === 'ENOENT') {
    throw new Error(`${tool} not found on PATH; ${PG_TOOL_INSTALL_HINT}`);
  }
  if (result.error) throw result.error;
  if (result.status !== 0) {
    const stderr = String(result.stderr || '').trim().split(/\r?\n/).slice(-4).join(' | ');
    throw new Error(`${tool} exited with status ${result.status}: ${stderr || 'no error output'}`);
  }
  return result;
}

function assertPgToolAvailable(tool, spawn = spawnSync) {
  const result = spawn(tool, ['--version'], { encoding: 'utf8', windowsHide: true });
  if (result.error && result.error.code === 'ENOENT') {
    throw new Error(`${tool} not found on PATH; ${PG_TOOL_INSTALL_HINT}`);
  }
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`${tool} --version exited with status ${result.status}`);
}

function parseStoredJson(value) {
  return typeof value === 'string' ? JSON.parse(value) : value;
}

async function verifyPgSnapshotIntegrity(client, anchor) {
  const storedRows = (await client.query('SELECT seq, entry FROM audit ORDER BY seq ASC')).rows;
  const rows = storedRows.map((row) => parseStoredJson(row.entry));
  const key = anchor && anchor.key;
  const checkpoint = anchor && anchor.checkpoint;
  if (!key || !checkpoint) {
    return { ok: false, count: rows.length, reason: 'checkpoint-unavailable' };
  }
  if (!auditIntegrity.validCheckpoint(checkpoint, key)) {
    return { ok: false, count: rows.length, reason: 'checkpoint-authentication' };
  }
  if (rows.length < checkpoint.count) {
    return { ok: false, count: rows.length, reason: 'checkpoint-truncated' };
  }
  let prev = auditIntegrity.ZERO;
  let lastSeq = 0;
  for (let index = 0; index < rows.length; index += 1) {
    const entry = rows[index];
    const rowSeq = Number(storedRows[index].seq);
    if (!Number.isSafeInteger(rowSeq) || rowSeq <= lastSeq) {
      return { ok: false, count: rows.length, brokenAt: entry.id, reason: 'chain' };
    }
    const { hash, mac, ...body } = entry;
    if (entry.prevHash !== prev || auditIntegrity.sha(auditIntegrity.canonical(body)) !== hash) {
      return { ok: false, count: rows.length, brokenAt: entry.id, reason: 'chain' };
    }
    if (mac && !auditIntegrity.validAuthenticatedEntry(entry, key)) {
      return { ok: false, count: rows.length, brokenAt: entry.id, reason: 'entry-authentication' };
    }
    if (!mac && index >= checkpoint.count) {
      return { ok: false, count: rows.length, brokenAt: entry.id, reason: 'entry-authentication-missing' };
    }
    prev = hash;
    lastSeq = rowSeq;
  }
  const checkpointHead = checkpoint.count ? rows[checkpoint.count - 1].hash : auditIntegrity.ZERO;
  const checkpointSeq = checkpoint.count ? Number(storedRows[checkpoint.count - 1].seq) : 0;
  if (checkpoint.head !== checkpointHead || checkpoint.seq !== checkpointSeq) {
    return { ok: false, count: rows.length, reason: 'checkpoint-diverged' };
  }

  const latest = new Map();
  for (const entry of rows) {
    if (entry.queryId && entry.contentHash) latest.set(entry.queryId, entry);
  }
  const queryRows = await client.query('SELECT id FROM queries ORDER BY id ASC');
  for (const row of queryRows.rows) {
    if (!latest.has(row.id)) {
      return {
        ok: false,
        count: rows.length,
        reason: 'evidence-unanchored',
        queryId: row.id,
      };
    }
  }
  const liveHashes = new Map();
  const ids = [...latest.keys()];
  for (let i = 0; i < ids.length; i += 500) {
    const chunk = ids.slice(i, i + 500);
    const result = await client.query(
      'SELECT id, data FROM queries WHERE id = ANY($1::text[])',
      [chunk],
    );
    for (const row of result.rows) {
      liveHashes.set(row.id, auditIntegrity.sha(auditIntegrity.canonical(parseStoredJson(row.data))));
    }
  }
  for (const [queryId, entry] of latest) {
    const liveHash = liveHashes.get(queryId);
    if (!liveHash) {
      return {
        ok: false,
        count: rows.length,
        brokenAt: entry.id,
        reason: 'evidence-missing',
        queryId,
      };
    }
    if (liveHash !== entry.contentHash) {
      return { ok: false, count: rows.length, brokenAt: entry.id, reason: 'evidence', queryId };
    }
  }
  return {
    ok: true,
    count: rows.length,
    exactCheckpoint: auditIntegrity.createCheckpoint(rows.length, prev, key, lastSeq),
  };
}

function assertSnapshotId(snapshotId) {
  const value = String(snapshotId || '');
  if (!/^[A-Za-z0-9-]+$/.test(value)) throw new Error('Postgres returned an invalid exported snapshot id');
  return value;
}

const PG_LOCALE_PROVIDERS = Object.freeze({ c: 'libc', i: 'icu', b: 'builtin' });

function validatePgDatabaseDefinition(value) {
  const definition = value && typeof value === 'object' ? value : null;
  const serverMajor = Number(definition && definition.serverMajor);
  const provider = String(definition && definition.localeProvider || '');
  const encoding = String(definition && definition.encoding || '');
  const lcCollate = String(definition && definition.lcCollate || '');
  const lcCtype = String(definition && definition.lcCtype || '');
  const locale = definition && definition.locale == null ? null : String(definition.locale);
  const rules = definition && definition.icuRules == null ? null : String(definition.icuRules);
  if (![16, 17].includes(serverMajor)
      || !['libc', 'icu', 'builtin'].includes(provider)
      || (provider === 'builtin' && serverMajor < 17)
      || !/^[A-Z0-9_-]{1,32}$/.test(encoding)
      || !lcCollate || !lcCtype
      || [lcCollate, lcCtype, locale, rules].some((item) => item && (item.includes('\0') || item.length > 4096))
      || (provider !== 'libc' && !locale)
      || (provider !== 'icu' && rules)) {
    throw new Error('Postgres source database definition is invalid or unsupported');
  }
  return { serverMajor, encoding, localeProvider: provider, lcCollate, lcCtype, locale, icuRules: rules };
}

async function readPgDatabaseDefinition(client) {
  const version = await client.query("SELECT current_setting('server_version_num') AS n");
  const serverVersionNum = Number(version.rows[0] && version.rows[0].n);
  const serverMajor = Math.floor(serverVersionNum / 10000);
  if (!SUPPORTED_PG_RESTORE_MAJORS.has(serverMajor)) {
    throw new Error('Postgres source database definition is unsupported for this server version');
  }
  const localeColumn = serverMajor >= 17 ? 'datlocale' : 'daticulocale';
  const result = await client.query(`
    SELECT pg_catalog.pg_encoding_to_char(encoding) AS encoding,
           datlocprovider::text AS provider,
           datcollate AS lc_collate,
           datctype AS lc_ctype,
           ${localeColumn} AS locale,
           daticurules AS icu_rules
      FROM pg_catalog.pg_database
     WHERE datname = current_database()
  `);
  const row = result.rows[0] || {};
  return validatePgDatabaseDefinition({
    serverMajor,
    encoding: row.encoding,
    localeProvider: PG_LOCALE_PROVIDERS[row.provider],
    lcCollate: row.lc_collate,
    lcCtype: row.lc_ctype,
    locale: row.locale,
    icuRules: row.icu_rules,
  });
}

async function readPgSnapshotEvidence(client, sourceAnchor) {
  const verified = await verifyPgSnapshotIntegrity(client, sourceAnchor);
  if (!verified.ok) {
    throw new Error(`refusing to back up a snapshot with broken audit integrity: ${verified.reason || 'unknown'}`);
  }
  const { exactCheckpoint, ...sourceIntegrity } = verified;
  const queryRows = await client.query(
    'SELECT status, "createdAt" AS "createdAt", data FROM queries ORDER BY seq ASC',
  );
  const databaseDefinition = await readPgDatabaseDefinition(client);
  return {
    sourceIntegrity,
    exactCheckpoint,
    stats: snapshotStatsFromRows(queryRows.rows),
    databaseDefinition,
  };
}

async function withPgSnapshot(connectionString, callback, options = {}) {
  assertPostgresConnectionUrl(connectionString, options);
  const createClient = options.createClient || ((config) => {
    const { Client } = require('pg');
    return new Client(config);
  });
  const client = createClient(pgClientConfig(connectionString, options));
  let transactionOpen = false;
  await client.connect();
  try {
    await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    transactionOpen = true;
    const exported = await client.query('SELECT pg_export_snapshot() AS snapshot_id');
    const snapshotId = assertSnapshotId(exported.rows[0] && exported.rows[0].snapshot_id);
    const evidence = await readPgSnapshotEvidence(client, options.sourceAnchor);
    const result = await callback({ snapshotId, ...evidence });
    await client.query('COMMIT');
    transactionOpen = false;
    return result;
  } catch (error) {
    if (transactionOpen) {
      try { await client.query('ROLLBACK'); } catch {}
    }
    throw error;
  } finally {
    await client.end();
  }
}

function buildPgManifest({
  connectionString,
  publishedFile,
  descriptors,
  sourceIntegrity,
  checkpoint,
  stats,
  databaseDefinition,
  key,
}) {
  const backupSha256 = descriptors.database.sha256;
  return authenticateManifest({
    schemaVersion: 2,
    driver: 'postgres',
    format: 'pg_dump-custom',
    createdAt: new Date().toISOString(),
    service: { name: 'RedactWall', version: require('../package.json').version },
    sourceDatabase: pgDatabaseName(connectionString),
    backupFile: path.basename(publishedFile),
    backupBytes: descriptors.database.bytes,
    backupSha256,
    artifacts: descriptors,
    sourceIntegrity,
    backupIntegrity: sourceIntegrity,
    checkpoint,
    stats,
    sourceDatabaseDefinition: validatePgDatabaseDefinition(databaseDefinition),
    rawPromptBodiesIncluded: false,
    note: 'The dump and authenticated audit sidecars are sensitive runtime state. This manifest contains no prompt bodies and no connection credentials; verify restores with backup-drill.',
  }, key);
}

function pgDumpArgs(snapshotId, connectionString, stagedBackup) {
  return [
    '--format=custom',
    '--enable-row-security',
    `--snapshot=${assertSnapshotId(snapshotId)}`,
    `--exclude-table=${POSTGRES_AUDIT_SCOPE_TABLE}`,
    `--dbname=${pgDatabaseName(connectionString)}`,
    `--file=${stagedBackup}`,
  ];
}

/**
 * Postgres backup: pg_dump custom format plus the exact authenticated audit
 * state/checkpoint that covers the exported snapshot. A restore still verifies
 * the dump rows against that checkpoint before it is accepted.
 */
async function createPgBackup({
  outDir,
  file,
  manifestFile,
  dbModule,
  connectionString,
  force = false,
  runPgTool: pgRunner = runPgTool,
  withPgSnapshot: snapshotRunner = withPgSnapshot,
  security = {},
  env = process.env,
} = {}) {
  const db = dbModule || require('../server/db');
  const connString = pgConnectionString(connectionString);
  assertBackupSource(db);
  if (pgRunner === runPgTool) assertPgToolAvailable('pg_dump');
  const sourceAnchor = loadAuthenticatedAuditAnchor(db._auditAnchorPaths, env);
  const manifestKey = independentManifestKey(sourceAnchor);
  const { backupFile, manifestPath } = resolveCreateTargets({ outDir, file, manifestFile, extension: '.dump' });
  const auditPaths = backupAuditArtifactPaths(backupFile);
  assertDistinctArtifactTargets([
    { target: backupFile },
    { target: auditPaths.statePath },
    { target: auditPaths.checkpointPath },
    { target: manifestPath },
  ]);
  assertWritable(backupFile, force);
  assertWritable(auditPaths.statePath, force);
  assertWritable(auditPaths.checkpointPath, force);
  assertWritable(manifestPath, force);
  let backupStaging;
  let manifestStaging;
  let operationError;
  let operationFailed = false;
  let committedResult;

  try {
    backupStaging = createPrivateStagingDir(path.dirname(backupFile), security);
    manifestStaging = createPrivateStagingDir(path.dirname(manifestPath), security);
    const stagedBackup = path.join(backupStaging, path.basename(backupFile));
    const stagedAuditState = path.join(backupStaging, path.basename(auditPaths.statePath));
    const stagedAuditCheckpoint = path.join(backupStaging, path.basename(auditPaths.checkpointPath));
    const stagedManifest = path.join(manifestStaging, path.basename(manifestPath));
    const snapshotEvidence = await snapshotRunner(connString, async (evidence) => {
      const snapshotId = assertSnapshotId(evidence.snapshotId);
      if (!evidence.sourceIntegrity || !evidence.sourceIntegrity.ok) {
        throw new Error('refusing to back up a snapshot with broken audit integrity');
      }
      if (!evidence.stats || !Number.isSafeInteger(evidence.stats.total) || evidence.stats.total < 0) {
        throw new Error('Postgres snapshot did not provide a valid query count');
      }
      const databaseDefinition = validatePgDatabaseDefinition(evidence.databaseDefinition);
      if (!evidence.exactCheckpoint
          || !auditIntegrity.validCheckpoint(evidence.exactCheckpoint, sourceAnchor.key)
          || evidence.exactCheckpoint.count !== evidence.sourceIntegrity.count) {
        throw new Error('Postgres snapshot did not provide an authenticated exact checkpoint');
      }
      // --enable-row-security: queries has FORCE ROW LEVEL SECURITY, which
      // pg_dump otherwise refuses as a non-BYPASSRLS role. The exported
      // snapshot binds the dump to the exact rows counted and verified here.
      pgRunner('pg_dump', pgDumpArgs(snapshotId, connString, stagedBackup), connString);
      if (!isPgDumpFile(stagedBackup)) throw new Error('pg_dump did not produce a valid custom-format archive');
      return {
        sourceIntegrity: evidence.sourceIntegrity,
        exactCheckpoint: evidence.exactCheckpoint,
        stats: evidence.stats,
        databaseDefinition,
      };
    }, { sourceAnchor });
    restrictPath(stagedBackup, { ...security, directory: false });
    fsyncFile(stagedBackup);
    writePrivateFile(stagedAuditState, JSON.stringify(sourceAnchor.state), security);
    writePrivateFile(stagedAuditCheckpoint, JSON.stringify(snapshotEvidence.exactCheckpoint), security);
    const descriptors = {
      database: artifactDescriptor(stagedBackup, backupFile),
      auditState: artifactDescriptor(stagedAuditState, auditPaths.statePath),
      auditCheckpoint: artifactDescriptor(stagedAuditCheckpoint, auditPaths.checkpointPath),
    };
    const manifest = buildPgManifest({
      connectionString: connString,
      publishedFile: backupFile,
      descriptors,
      sourceIntegrity: snapshotEvidence.sourceIntegrity,
      checkpoint: snapshotEvidence.exactCheckpoint,
      stats: snapshotEvidence.stats,
      databaseDefinition: snapshotEvidence.databaseDefinition,
      key: manifestKey,
    });
    writePrivateFile(stagedManifest, JSON.stringify(manifest, null, 2), security);
    const verified = publishPrivateFiles([
      { staged: stagedBackup, target: backupFile },
      { staged: stagedAuditState, target: auditPaths.statePath },
      { staged: stagedAuditCheckpoint, target: auditPaths.checkpointPath },
      { staged: stagedManifest, target: manifestPath },
    ], {
      force,
      security,
      verify: () => verifyPgBackup({ file: backupFile, manifestFile: manifestPath, security, env }),
    });
    committedResult = {
      ...verified,
      auditIntegrity: snapshotEvidence.sourceIntegrity,
      manifestFile: manifestPath,
      auditStateFile: auditPaths.statePath,
      auditCheckpointFile: auditPaths.checkpointPath,
      manifest,
    };
    return committedResult;
  } catch (error) {
    operationFailed = true;
    operationError = error;
    throw error;
  } finally {
    if (operationFailed) {
      cleanupPrivateStagingAfterOperation([backupStaging, manifestStaging], operationError, true);
    } else {
      cleanupPrivateStagingAfterCommit([backupStaging, manifestStaging], committedResult, {
        security,
        component: 'postgres-backup',
        phase: 'private-staging-cleanup',
      });
    }
  }
}

function inspectPgBackupArtifactSet({ file, manifestFile, security = {}, env = process.env } = {}) {
  const dumpPath = path.resolve(file);
  const auditPaths = backupAuditArtifactPaths(dumpPath);
  const manifest = manifestFile
    ? JSON.parse(fs.readFileSync(path.resolve(manifestFile), 'utf8'))
    : readManifest(dumpPath);
  const paths = {
    database: dumpPath,
    auditState: auditPaths.statePath,
    auditCheckpoint: auditPaths.checkpointPath,
  };
  const descriptors = { database: artifactDescriptor(dumpPath) };
  let artifactError = null;
  try {
    descriptors.auditState = artifactDescriptor(auditPaths.statePath);
    descriptors.auditCheckpoint = artifactDescriptor(auditPaths.checkpointPath);
  } catch (error) {
    artifactError = error;
  }
  let anchor = null;
  let anchorError = null;
  let manifestKey = null;
  if (!artifactError) {
    try {
      anchor = loadAuthenticatedAuditAnchor(auditPaths, env, security);
      manifestKey = independentManifestKey(anchor);
    } catch (error) { anchorError = error; }
  }
  const unverifiable = !manifest;
  const manifestResult = unverifiable
    ? { ok: false, reason: 'manifest-missing' }
    : artifactError
      ? { ok: false, reason: 'artifact-unavailable' }
      : anchorError
        ? {
            ok: false,
            reason: anchorError.code === 'BACKUP_MANIFEST_KEY_NOT_INDEPENDENT'
              ? 'manifest-authentication-key' : 'audit-sidecar-unavailable',
          }
        : validatePgManifest(manifest, paths, descriptors, anchor.checkpoint, manifestKey);
  const auditIntegrityResult = anchor
    ? { ok: true, count: anchor.checkpoint.count, scope: 'authenticated-checkpoint' }
    : {
        ok: false,
        count: 0,
        reason: (artifactError || anchorError) && (artifactError || anchorError).code === 'ENOENT'
          ? 'audit-sidecar-missing' : 'audit-sidecar-unavailable',
      };
  const backupSha256 = descriptors.database.sha256;
  const verification = {
    ok: manifestResult.ok && auditIntegrityResult.ok,
    driver: 'postgres',
    file: dumpPath,
    bytes: descriptors.database.bytes,
    backupSha256,
    auditStateFile: auditPaths.statePath,
    auditCheckpointFile: auditPaths.checkpointPath,
    auditStateSha256: descriptors.auditState ? descriptors.auditState.sha256 : null,
    auditCheckpointSha256: descriptors.auditCheckpoint ? descriptors.auditCheckpoint.sha256 : null,
    auditIntegrity: auditIntegrityResult,
    manifestOk: manifestResult.ok,
    manifestReason: manifestResult.reason || null,
    unverifiable,
    note: unverifiable
      ? 'no authenticated manifest found next to the dump; restore is refused even when replacing a target'
      : 'pg_dump archive and authenticated snapshot sidecars verified; run backup:drill (or a restore) to verify the dump rows end to end',
  };
  return { anchor, manifest, verification };
}

/** Verify the portable dump, manifest, and authenticated snapshot sidecars. */
function verifyPgBackup(options = {}) {
  return inspectPgBackupArtifactSet(options).verification;
}

function verifyRestoredPgDriver(driver, anchor) {
  let exactCheckpoint = null;
  let auditIntegrityResult = anchor
    ? auditIntegrity.verifyAuditChainForDatabase(driver, {
        key: anchor.key,
        checkpoint: anchor.checkpoint,
        onVerified(checkpoint) { exactCheckpoint = checkpoint; },
      })
    : { ok: false, count: 0, reason: 'checkpoint-unavailable' };
  if (auditIntegrityResult.ok && !sameCanonicalJson(anchor.checkpoint, exactCheckpoint)) {
    auditIntegrityResult = {
      ok: false,
      count: auditIntegrityResult.count,
      reason: 'checkpoint-not-snapshot-head',
    };
  }
  return {
    auditIntegrity: auditIntegrityResult,
    queryCount: driver.prepare('SELECT COUNT(*) n FROM queries').get().n,
    auditCount: driver.prepare('SELECT COUNT(*) n FROM audit').get().n,
  };
}

/** Open the restored database through the production driver and measure it. */
function verifyRestoredPgDatabase(targetUrl, anchor) {
  assertPostgresConnectionUrl(targetUrl);
  const { createPgDriver } = require('../server/storage/pg-driver');
  const driver = createPgDriver(targetUrl);
  try { return verifyRestoredPgDriver(driver, anchor); }
  finally { driver.close(); }
}

const PG_RESTORE_INVENTORY_NAMES = Object.freeze([
  'relations',
  'routines',
  'types',
  'operators',
  'collations',
  'conversions',
  'text_search_configurations',
  'text_search_dictionaries',
  'text_search_parsers',
  'text_search_templates',
  'operator_classes',
  'operator_families',
  'extended_statistics',
  'public_schema_metadata',
  'current_database_metadata',
  'extra_schemas',
  'extensions',
  'event_triggers',
  'publications',
  'subscriptions_current_database',
  'default_acls',
  'database_role_settings',
  'foreign_data_wrappers',
  'foreign_servers',
  'user_mappings',
  'large_objects',
  'user_casts',
  'user_access_methods',
  'user_languages',
  'security_labels',
]);

function pgRestoreInventorySql(serverVersionNum, options = {}) {
  const major = Math.floor(Number(serverVersionNum) / 10000);
  if (!Number.isSafeInteger(major) || !SUPPORTED_PG_RESTORE_MAJORS.has(major)) {
    throw new Error('Postgres restore target inventory is unsupported for this server version');
  }
  const expectedConnectionLimit = options.expectedDatabaseConnectionLimit === undefined
    ? -1 : Number(options.expectedDatabaseConnectionLimit);
  if (!Number.isSafeInteger(expectedConnectionLimit) || expectedConnectionLimit < -1) {
    throw new Error('Postgres restore target connection-limit expectation is invalid');
  }
  const databaseAclPredicate = options.expectedDatabaseOwnerOnlyAcl === true
    ? `AND datacl IS NOT NULL
       AND (SELECT COUNT(*) FROM current_database_acl) = 3
       AND (SELECT COUNT(*) FROM current_database_acl
             WHERE grantor = current_user::pg_catalog.regrole
               AND grantee = current_user::pg_catalog.regrole
               AND is_grantable = false
               AND privilege_type IN ('CREATE', 'CONNECT', 'TEMPORARY')) = 3`
    : 'AND datacl IS NULL';
  return `
    WITH user_namespaces AS (
      SELECT oid
        FROM pg_catalog.pg_namespace
       WHERE nspname NOT IN ('pg_catalog', 'information_schema')
         AND nspname NOT LIKE 'pg_toast%'
         AND nspname NOT LIKE 'pg_temp_%'
    ), public_schema AS (
      SELECT oid, nspowner, nspacl,
             pg_catalog.obj_description(oid, 'pg_namespace') AS description
        FROM pg_catalog.pg_namespace
       WHERE nspname = 'public'
    ), public_schema_acl AS (
      SELECT acl.grantor, acl.grantee, acl.privilege_type, acl.is_grantable
        FROM public_schema schema_row
        CROSS JOIN LATERAL pg_catalog.aclexplode(schema_row.nspacl) acl
    ), current_database_row AS (
      SELECT oid, datdba, datistemplate, datallowconn, datconnlimit, datacl,
             pg_catalog.shobj_description(oid, 'pg_database') AS description
        FROM pg_catalog.pg_database
       WHERE datname = current_database()
    ), current_database_acl AS (
      SELECT acl.grantor, acl.grantee, acl.privilege_type, acl.is_grantable
        FROM current_database_row db
        CROSS JOIN LATERAL pg_catalog.aclexplode(db.datacl) acl
    )
    SELECT 'relations' AS name, COUNT(*) AS n
      FROM pg_catalog.pg_class o JOIN user_namespaces ns ON ns.oid = o.relnamespace
    UNION ALL SELECT 'routines', COUNT(*)
      FROM pg_catalog.pg_proc o JOIN user_namespaces ns ON ns.oid = o.pronamespace
    UNION ALL SELECT 'types', COUNT(*)
      FROM pg_catalog.pg_type o JOIN user_namespaces ns ON ns.oid = o.typnamespace
    UNION ALL SELECT 'operators', COUNT(*)
      FROM pg_catalog.pg_operator o JOIN user_namespaces ns ON ns.oid = o.oprnamespace
    UNION ALL SELECT 'collations', COUNT(*)
      FROM pg_catalog.pg_collation o JOIN user_namespaces ns ON ns.oid = o.collnamespace
    UNION ALL SELECT 'conversions', COUNT(*)
      FROM pg_catalog.pg_conversion o JOIN user_namespaces ns ON ns.oid = o.connamespace
    UNION ALL SELECT 'text_search_configurations', COUNT(*)
      FROM pg_catalog.pg_ts_config o JOIN user_namespaces ns ON ns.oid = o.cfgnamespace
    UNION ALL SELECT 'text_search_dictionaries', COUNT(*)
      FROM pg_catalog.pg_ts_dict o JOIN user_namespaces ns ON ns.oid = o.dictnamespace
    UNION ALL SELECT 'text_search_parsers', COUNT(*)
      FROM pg_catalog.pg_ts_parser o JOIN user_namespaces ns ON ns.oid = o.prsnamespace
    UNION ALL SELECT 'text_search_templates', COUNT(*)
      FROM pg_catalog.pg_ts_template o JOIN user_namespaces ns ON ns.oid = o.tmplnamespace
    UNION ALL SELECT 'operator_classes', COUNT(*)
      FROM pg_catalog.pg_opclass o JOIN user_namespaces ns ON ns.oid = o.opcnamespace
    UNION ALL SELECT 'operator_families', COUNT(*)
      FROM pg_catalog.pg_opfamily o JOIN user_namespaces ns ON ns.oid = o.opfnamespace
    UNION ALL SELECT 'extended_statistics', COUNT(*)
      FROM pg_catalog.pg_statistic_ext o JOIN user_namespaces ns ON ns.oid = o.stxnamespace
    UNION ALL SELECT 'public_schema_metadata',
      CASE WHEN
        (SELECT COUNT(*) FROM public_schema) = 1
        AND (SELECT COUNT(*) FROM public_schema
              WHERE nspowner = 'pg_database_owner'::pg_catalog.regrole
                AND description = 'standard public schema') = 1
        AND (SELECT COUNT(*) FROM public_schema_acl) = 3
        AND (SELECT COUNT(*) FROM public_schema_acl
              WHERE grantor = 'pg_database_owner'::pg_catalog.regrole
                AND is_grantable = false
                AND (
                  (grantee = 0 AND privilege_type = 'USAGE')
                  OR (grantee = 'pg_database_owner'::pg_catalog.regrole
                      AND privilege_type IN ('CREATE', 'USAGE'))
                )) = 3
        THEN 0 ELSE 1
      END
    UNION ALL SELECT 'current_database_metadata',
      CASE WHEN
        (SELECT COUNT(*) FROM current_database_row
          WHERE datdba = current_user::pg_catalog.regrole
            AND datistemplate = false
            AND datallowconn = true
            AND datconnlimit = ${expectedConnectionLimit}
            ${databaseAclPredicate}
            AND description IS NULL) = 1
        AND NOT EXISTS (
          SELECT 1
            FROM pg_catalog.pg_shseclabel label
            JOIN current_database_row db ON db.oid = label.objoid
           WHERE label.classoid = 'pg_database'::pg_catalog.regclass
        )
        THEN 0 ELSE 1
      END
    UNION ALL SELECT 'extra_schemas', COUNT(*)
      FROM user_namespaces WHERE oid <> 'public'::pg_catalog.regnamespace
    UNION ALL SELECT 'extensions', COUNT(*)
      FROM pg_catalog.pg_extension WHERE extname <> 'plpgsql'
    UNION ALL SELECT 'event_triggers', COUNT(*) FROM pg_catalog.pg_event_trigger
    UNION ALL SELECT 'publications', COUNT(*) FROM pg_catalog.pg_publication
    UNION ALL SELECT 'subscriptions_current_database', COUNT(*)
      FROM pg_catalog.pg_subscription o JOIN current_database_row db ON db.oid = o.subdbid
    UNION ALL SELECT 'default_acls', COUNT(*) FROM pg_catalog.pg_default_acl
    UNION ALL SELECT 'database_role_settings', COUNT(*)
      FROM pg_catalog.pg_db_role_setting o JOIN current_database_row db ON db.oid = o.setdatabase
    UNION ALL SELECT 'foreign_data_wrappers', COUNT(*) FROM pg_catalog.pg_foreign_data_wrapper
    UNION ALL SELECT 'foreign_servers', COUNT(*) FROM pg_catalog.pg_foreign_server
    UNION ALL SELECT 'user_mappings', COUNT(*) FROM pg_catalog.pg_user_mappings
    UNION ALL SELECT 'large_objects', COUNT(*) FROM pg_catalog.pg_largeobject_metadata
    UNION ALL SELECT 'user_casts', COUNT(*) FROM pg_catalog.pg_cast WHERE oid >= 16384
    UNION ALL SELECT 'user_access_methods', COUNT(*) FROM pg_catalog.pg_am WHERE oid >= 16384
    UNION ALL SELECT 'user_languages', COUNT(*) FROM pg_catalog.pg_language WHERE oid >= 16384
    UNION ALL SELECT 'security_labels', COUNT(*) FROM pg_catalog.pg_seclabel
  `;
}

function parsePgRestoreInventory(rows) {
  if (!Array.isArray(rows)) throw new Error('Postgres restore target inventory is invalid');
  const inventory = Object.create(null);
  const expected = new Set(PG_RESTORE_INVENTORY_NAMES);
  for (const row of rows) {
    const name = String(row && row.name || '');
    const count = Number(row && row.n);
    if (!expected.delete(name) || !Number.isSafeInteger(count) || count < 0) {
      throw new Error('Postgres restore target inventory is invalid');
    }
    inventory[name] = count;
  }
  if (expected.size) throw new Error('Postgres restore target inventory is incomplete');
  return inventory;
}

function inspectEmptyPgRestoreTarget(targetUrl, deps = {}) {
  assertPostgresConnectionUrl(targetUrl);
  const createPgDriver = deps.createPgDriver || require('../server/storage/pg-driver').createPgDriver;
  const driver = createPgDriver(targetUrl);
  try {
    const versionRow = driver.prepare("SELECT current_setting('server_version_num') AS n").get();
    const serverVersionNum = Number(versionRow && versionRow.n);
    if (!Number.isSafeInteger(serverVersionNum) || serverVersionNum < 1) {
      throw new Error('Postgres restore target server version is unavailable');
    }
    const rows = driver.prepare(pgRestoreInventorySql(serverVersionNum, deps)).all();
    const inventory = parsePgRestoreInventory(rows);
    const objectCount = Object.values(inventory).reduce((sum, count) => {
      const next = sum + count;
      if (!Number.isSafeInteger(next)) {
        throw new Error('Postgres restore target inventory count is invalid');
      }
      return next;
    }, 0);
    return { empty: objectCount === 0, objectCount, serverVersionNum, inventory };
  } finally {
    driver.close();
  }
}

function assertEmptyPgRestoreTarget(targetUrl, deps = {}) {
  const inspect = deps.inspectPgRestoreTarget || inspectEmptyPgRestoreTarget;
  const result = inspect(targetUrl, deps);
  if (!result || result.empty !== true || result.objectCount !== 0) {
    const nonempty = Object.entries(result && result.inventory || {})
      .filter(([, count]) => Number(count) !== 0)
      .map(([name, count]) => `${name}=${Number(count)}`)
      .join(', ');
    throw new Error(`Postgres restore staging database is not fresh and empty${nonempty ? ` (${nonempty})` : ''}`);
  }
  return result;
}

function pgRestoreArtifactPaths(database, directory = null) {
  const auditPaths = backupAuditArtifactPaths(database);
  if (!directory) {
    return {
      database,
      auditState: auditPaths.statePath,
      auditCheckpoint: auditPaths.checkpointPath,
    };
  }
  return {
    directory,
    database: path.join(directory, path.basename(database)),
    auditState: path.join(directory, path.basename(auditPaths.statePath)),
    auditCheckpoint: path.join(directory, path.basename(auditPaths.checkpointPath)),
  };
}

function copyPgRestoreArtifacts(source, staged, manifest, security) {
  const artifacts = manifest.artifacts;
  copyPrivateRestoreArtifact(source.database, staged.database, {
    expectedBytes: artifacts.database.bytes,
    label: 'Postgres dump',
    security,
  });
  copyPrivateRestoreArtifact(source.auditState, staged.auditState, {
    expectedBytes: artifacts.auditState.bytes,
    maxBytes: MAX_AUDIT_STATE_BYTES,
    label: 'audit state sidecar',
    security,
  });
  copyPrivateRestoreArtifact(source.auditCheckpoint, staged.auditCheckpoint, {
    expectedBytes: artifacts.auditCheckpoint.bytes,
    maxBytes: MAX_AUDIT_CHECKPOINT_BYTES,
    label: 'audit checkpoint sidecar',
    security,
  });
  privatePaths.fsyncDirectory(staged.directory, { fs });
}

function validatePgRestoreSnapshot(staged, manifest, env, security) {
  const descriptors = {
    database: artifactDescriptor(staged.database),
    auditState: artifactDescriptor(staged.auditState),
    auditCheckpoint: artifactDescriptor(staged.auditCheckpoint),
  };
  const anchor = loadAuthenticatedAuditAnchor({
    directory: staged.directory,
    statePath: staged.auditState,
    checkpointPath: staged.auditCheckpoint,
  }, env, security);
  const result = validatePgManifest(
    manifest,
    staged,
    descriptors,
    anchor.checkpoint,
    independentManifestKey(anchor),
  );
  if (!result.ok) throw new Error(`backup artifacts changed during restore: ${result.reason}`);
  return anchor;
}

function createPgRestoreSnapshot(file, manifest, env, security, stagingParent = os.tmpdir()) {
  const database = path.resolve(file);
  const staging = createPrivateStagingDir(stagingParent, security);
  let complete = false;
  let operationError;
  try {
    const source = pgRestoreArtifactPaths(database);
    const staged = pgRestoreArtifactPaths(database, staging);
    copyPgRestoreArtifacts(source, staged, manifest, security);
    const anchor = validatePgRestoreSnapshot(staged, manifest, env, security);
    complete = true;
    return {
      anchor,
      archive: staged.database,
      auditState: staged.auditState,
      auditCheckpoint: staged.auditCheckpoint,
      staging,
    };
  } catch (error) {
    operationError = error;
    throw error;
  } finally {
    if (!complete) cleanupPrivateStagingAfterOperation([staging], operationError);
  }
}

function requireNewPgAuditDirectory(auditDir) {
  if (typeof auditDir !== 'string' || !auditDir.trim()) {
    throw new Error('Postgres restore requires an explicit new --audit-dir <directory>');
  }
  const paths = runtimeAuditAnchorPaths(auditDir);
  if (pathEntryExists(paths.directory)) {
    throw new Error(`Postgres restore target audit directory already exists: ${paths.directory}`);
  }
  return paths;
}

function createPgRuntimeAuditStaging(snapshot, manifest, targetPaths, env, security) {
  const staging = createPrivateStagingDir(path.dirname(targetPaths.directory), security);
  let complete = false;
  let operationError;
  try {
    const stagedPaths = runtimeAuditAnchorPaths(staging);
    copyPrivateRestoreArtifact(snapshot.auditState, stagedPaths.statePath, {
      expectedBytes: manifest.artifacts.auditState.bytes,
      maxBytes: MAX_AUDIT_STATE_BYTES,
      label: 'Postgres runtime audit state',
      security,
    });
    copyPrivateRestoreArtifact(snapshot.auditCheckpoint, stagedPaths.checkpointPath, {
      expectedBytes: manifest.artifacts.auditCheckpoint.bytes,
      maxBytes: MAX_AUDIT_CHECKPOINT_BYTES,
      label: 'Postgres runtime audit checkpoint',
      security,
    });
    if (pathEntryExists(stagedPaths.pendingPath)) {
      throw new Error('Postgres runtime audit staging unexpectedly contains pending high-water state');
    }
    privatePaths.fsyncDirectory(staging, { fs });
    const anchor = loadAuthenticatedAuditAnchor(stagedPaths, env, security);
    if (!sameCanonicalJson(anchor.state, snapshot.anchor.state)
        || !sameCanonicalJson(anchor.checkpoint, snapshot.anchor.checkpoint)) {
      throw new Error('Postgres runtime audit state changed while staging');
    }
    complete = true;
    return { anchor, paths: stagedPaths, staging };
  } catch (error) {
    operationError = error;
    throw error;
  } finally {
    if (!complete) cleanupPrivateStagingAfterOperation([staging], operationError);
  }
}

function requirePgDatabaseScope(value) {
  if (!auditAnchorInternal.validDatabaseScope(value)) {
    throw new Error('Postgres restore target audit database identity is unavailable');
  }
  return value;
}

function targetPgDatabaseScopeForDriver(driver) {
  if (!driver || typeof driver.auditDatabaseScope !== 'function') {
    throw new Error('Postgres restore target audit database identity is unavailable');
  }
  return requirePgDatabaseScope(driver.auditDatabaseScope());
}

function targetPgDatabaseScope(targetUrl, deps = {}) {
  assertPostgresConnectionUrl(targetUrl, deps);
  const createDriver = deps.createPgDriver || require('../server/storage/pg-driver').createPgDriver;
  const driver = createDriver(targetUrl);
  try { return targetPgDatabaseScopeForDriver(driver); }
  finally { driver?.close?.(); }
}

function replaceStagedPgRuntimeState(staged, snapshot, databaseScope, env, security) {
  const scope = requirePgDatabaseScope(databaseScope);
  if (snapshot.anchor.state.databaseScope === scope) {
    throw new Error('Postgres restore target retained the source audit database identity');
  }
  const rebound = auditAnchorInternal.signedState(
    snapshot.anchor.key,
    snapshot.anchor.state.checkpointCreated,
    snapshot.anchor.embedded,
    snapshot.anchor.state.pendingProtocol,
    scope,
  );
  const replacement = `${staged.paths.statePath}.${process.pid}.${crypto.randomBytes(12).toString('hex')}.rebind`;
  try {
    writePrivateFile(replacement, JSON.stringify(rebound), security);
    fs.renameSync(replacement, staged.paths.statePath);
    restrictPath(staged.paths.statePath, { ...security, directory: false });
    fsyncFile(staged.paths.statePath);
    privatePaths.fsyncDirectory(staged.staging, { fs });
  } finally {
    fs.rmSync(replacement, { force: true });
  }
  const anchor = loadAuthenticatedAuditAnchor(staged.paths, env, security);
  if (anchor.state.databaseScope !== scope
      || !sameCanonicalJson(anchor.checkpoint, snapshot.anchor.checkpoint)) {
    throw new Error('Postgres runtime audit state rebind verification failed');
  }
  staged.anchor = anchor;
  return staged;
}

function assertPublishedDirectoryIdentity(target, expected) {
  const current = exactDirectoryStat(target, 'Postgres restore audit directory');
  if (!sameDirectoryIdentity(expected, current)) {
    throw new Error('Postgres restore audit directory identity changed during publication');
  }
  return current;
}

function retainChangedPgAuditQuarantine(quarantine, target) {
  let retainedAt = quarantine;
  if (!pathEntryExists(target) && pathEntryExists(quarantine)) {
    try {
      fs.renameSync(quarantine, target);
      retainedAt = target;
    } catch {
      // A concurrently occupied target or a failed rename leaves the changed
      // directory at its private quarantine path. Never delete either path.
    }
  }
  try { privatePaths.fsyncDirectory(path.dirname(target), { fs }); } catch {}
  return retainedAt;
}

function removePublishedPgAuditDirectory(target, expected, originalError) {
  const quarantine = path.join(
    path.dirname(target),
    `.${path.basename(target)}.failed-${process.pid}-${crypto.randomBytes(12).toString('hex')}`,
  );
  try {
    // Move first so a replacement installed at the public pathname after a
    // check can never be recursively removed. The unpredictable quarantine
    // name is inside the trusted private parent held by the mutation lock.
    fs.renameSync(target, quarantine);
  } catch (renameError) {
    throw new Error('Postgres runtime audit publication failed; refusing cleanup because the published directory could not be quarantined', {
      cause: originalError || renameError,
    });
  }
  let quarantinedIdentity;
  try {
    quarantinedIdentity = exactDirectoryStat(quarantine, 'Postgres restore quarantined audit directory');
  } catch (identityError) {
    const retainedAt = retainChangedPgAuditQuarantine(quarantine, target);
    throw new Error(`Postgres runtime audit publication failed; refusing to remove an unverifiable replacement directory retained at ${retainedAt}`, {
      cause: originalError || identityError,
    });
  }
  if (!sameDirectoryIdentity(expected, quarantinedIdentity)) {
    const retainedAt = retainChangedPgAuditQuarantine(quarantine, target);
    throw new Error(`Postgres runtime audit publication failed; refusing to remove a changed replacement directory retained at ${retainedAt}`, {
      cause: originalError,
    });
  }
  fs.rmSync(quarantine, { recursive: true, force: true });
  privatePaths.fsyncDirectory(path.dirname(target), { fs });
}

function publishNewPgRuntimeAuditDirectory(staged, targetPaths, env, security) {
  if (pathEntryExists(targetPaths.directory)) {
    throw new Error(`Postgres restore target audit directory already exists: ${targetPaths.directory}`);
  }
  let publishedIdentity = null;
  try {
    // The parent is private and held under its mutation lock for this whole
    // operation, so the absence check plus rename is no-replace for actors in
    // RedactWall's trust model. Identity pinning protects every later cleanup.
    fs.renameSync(staged.staging, targetPaths.directory);
    publishedIdentity = exactDirectoryStat(targetPaths.directory, 'Postgres restore audit directory');
    assertPublishedDirectoryIdentity(targetPaths.directory, publishedIdentity);
    restrictPath(targetPaths.directory, { ...security, directory: true });
    assertPublishedDirectoryIdentity(targetPaths.directory, publishedIdentity);
    fsyncPublishedArtifact({
      staged: staged.staging,
      target: targetPaths.directory,
      directory: true,
    });
    assertPublishedDirectoryIdentity(targetPaths.directory, publishedIdentity);
    if (pathEntryExists(targetPaths.pendingPath)) {
      throw new Error('Postgres restore published unexpected pending high-water state');
    }
    assertPublishedDirectoryIdentity(targetPaths.directory, publishedIdentity);
    const anchor = loadAuthenticatedAuditAnchor(targetPaths, env, security);
    assertPublishedDirectoryIdentity(targetPaths.directory, publishedIdentity);
    if (!sameCanonicalJson(anchor.state, staged.anchor.state)
        || !sameCanonicalJson(anchor.checkpoint, staged.anchor.checkpoint)) {
      throw new Error('Postgres restore published different runtime audit state');
    }
    retireTransferredPrivateStaging(
      staged.staging,
      targetPaths.directory,
      'Postgres runtime audit staging',
    );
    staged.staging = null;
    return anchor;
  } catch (error) {
    if (publishedIdentity) {
      try {
        removePublishedPgAuditDirectory(targetPaths.directory, publishedIdentity, error);
        retireRemovedPrivateStaging(
          staged.staging,
          targetPaths.directory,
          publishedIdentity,
          'Postgres runtime audit staging',
        );
        staged.staging = null;
      } catch (cleanupError) {
        throw new Error(`Postgres runtime audit publication failed and cleanup was incomplete: ${cleanupError.message}`, {
          cause: error,
        });
      }
    }
    throw error;
  }
}

function pgDatabaseCatalogRow(driver, name) {
  const row = driver.prepare(`
    SELECT oid::text AS oid,
           datname,
           datdba::text AS owner_oid,
           pg_catalog.pg_get_userbyid(datdba) AS owner_name,
           datallowconn,
           datconnlimit,
           datistemplate
      FROM pg_catalog.pg_database
     WHERE datname = ?
  `).get(name);
  return row || null;
}

function pgDatabaseSessions(driver, name) {
  return driver.prepare(`
    SELECT pid, backend_start::text AS backend_start
      FROM pg_catalog.pg_stat_activity
     WHERE datname = ?
     ORDER BY pid
  `).all(name);
}

function waitForNoPgDatabaseSessions(driver, name, timeoutMs = PG_RESTORE_SESSION_DRAIN_TIMEOUT_MS) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const active = pgDatabaseSessions(driver, name);
    if (active.length === 0) return;
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      throw new Error('Postgres restore database still has active connections and was retained');
    }
    Atomics.wait(PG_RESTORE_SESSION_WAIT, 0, 0, Math.min(25, remaining));
  }
}

function samePgDatabaseIdentity(expected, actual) {
  return !!expected && !!actual
    && String(expected.oid) === String(actual.oid)
    && String(expected.owner_oid) === String(actual.owner_oid);
}

function assertPgDatabaseState(actual, expected, label) {
  if (!samePgDatabaseIdentity(expected, actual)
      || actual.datname !== expected.datname
      || actual.datistemplate !== false
      || (expected.datallowconn !== undefined && actual.datallowconn !== expected.datallowconn)
      || (expected.datconnlimit !== undefined && Number(actual.datconnlimit) !== expected.datconnlimit)) {
    throw new Error(`${label} database identity or state changed`);
  }
  return actual;
}

function pgRestoreRole(driver) {
  const row = driver.prepare(`
    SELECT active.rolname AS role_name,
           active.oid::text AS owner_oid,
           active.rolsuper AS role_super,
           active.rolcreatedb AS role_createdb,
           login.rolname AS session_role_name,
           login.oid::text AS session_owner_oid,
           login.rolsuper AS session_super,
           login.rolcreatedb AS session_createdb,
           (SELECT COUNT(*)::int FROM pg_catalog.pg_auth_members membership
             WHERE membership.roleid = active.oid) AS granted_member_count
      FROM pg_catalog.pg_roles active
      JOIN pg_catalog.pg_roles login ON login.rolname = session_user
     WHERE active.rolname = current_user
  `).get();
  if (!row || row.role_super !== false || row.role_createdb !== true
      || row.session_super !== false || row.session_createdb !== true
      || row.role_name !== row.session_role_name || row.owner_oid !== row.session_owner_oid
      || Number(row.granted_member_count) !== 0) {
    throw new Error(
      'Postgres guarded restore requires one directly authenticated non-superuser CREATEDB role with no granted members',
    );
  }
  return { name: String(row.role_name), oid: String(row.owner_oid) };
}

function pgDatabaseAclRows(driver, name) {
  return driver.prepare(`
    SELECT acl.grantor::text AS grantor_oid,
           acl.grantee::text AS grantee_oid,
           acl.privilege_type,
           acl.is_grantable
      FROM pg_catalog.pg_database db
      CROSS JOIN LATERAL pg_catalog.aclexplode(db.datacl) acl
     WHERE db.datname = ?
     ORDER BY acl.grantee, acl.privilege_type
  `).all(name);
}

function assertPgOwnerOnlyDatabaseAcl(driver, name, ownerOid) {
  const privileges = pgDatabaseAclRows(driver, name);
  const names = privileges.map((row) => String(row.privilege_type)).sort();
  if (privileges.length !== 3
      || privileges.some((row) => row.grantor_oid !== ownerOid
        || row.grantee_oid !== ownerOid || row.is_grantable !== false)
      || names.join(',') !== 'CONNECT,CREATE,TEMPORARY') {
    throw new Error('Postgres restore staging database access is not owner-only');
  }
}

function pgGuardSession(driver) {
  const row = driver.prepare(`
    SELECT pg_backend_pid() AS pid,
           current_database() AS database_name,
           backend_start::text AS backend_start
      FROM pg_catalog.pg_stat_activity
     WHERE pid = pg_backend_pid()
  `).get();
  if (!row || !Number.isSafeInteger(Number(row.pid)) || !row.backend_start) {
    throw new Error('Postgres restore guard identity is unavailable');
  }
  return { pid: Number(row.pid), database: String(row.database_name), backendStart: String(row.backend_start) };
}

function enablePgRestoreTarget(maintenance, targetDatabase, stagingIdentity) {
  let alterError = null;
  try {
    maintenance.exec(`ALTER DATABASE ${quotePgIdentifier(targetDatabase)} WITH ALLOW_CONNECTIONS true`);
  } catch (error) {
    alterError = error;
  }
  let current;
  try {
    current = pgDatabaseCatalogRow(maintenance, targetDatabase);
  } catch (error) {
    const uncertain = new Error('Postgres restore target enable outcome is uncertain', {
      cause: alterError || error,
    });
    uncertain.pgEnableOutcome = 'ambiguous';
    throw uncertain;
  }
  try {
    return assertPgDatabaseState(current, {
      ...stagingIdentity, datname: targetDatabase, datallowconn: true, datconnlimit: -1,
    }, 'enabled Postgres restore');
  } catch (stateError) {
    if (samePgDatabaseIdentity(stagingIdentity, current) && current.datallowconn === false) {
      const frozen = alterError || stateError;
      frozen.pgEnableOutcome = 'frozen';
      throw frozen;
    }
    stateError.pgEnableOutcome = 'ambiguous';
    throw stateError;
  }
}

function createPgRestoreControl(plan, databaseDefinition, deps = {}) {
  const createDriver = deps.createControlPgDriver
    || deps.createPgDriver
    || require('../server/storage/pg-driver').createPgDriver;
  const createGuardDriver = deps.createGuardPgDriver || createDriver;
  const maintenance = createDriver(plan.maintenanceUrl);
  let guard = null;
  let guardIdentity = null;
  let role = null;
  let stagingIdentity = null;

  const sessions = (name) => pgDatabaseSessions(maintenance, name);

  function assertOnlyGuard() {
    if (!guard || !guardIdentity) throw new Error('Postgres restore guard is not open');
    const live = pgGuardSession(guard);
    if (live.pid !== guardIdentity.pid
        || live.database !== guardIdentity.database
        || live.backendStart !== guardIdentity.backendStart) {
      throw new Error('Postgres restore guard connection changed');
    }
    const active = sessions(plan.stagingDatabase);
    if (active.length !== 1
        || Number(active[0].pid) !== guardIdentity.pid
        || String(active[0].backend_start) !== guardIdentity.backendStart) {
      throw new Error('Postgres restore staging database has an unexpected connection');
    }
  }

  function freeze(name, expected) {
    maintenance.exec(`ALTER DATABASE ${quotePgIdentifier(name)} WITH ALLOW_CONNECTIONS false`);
    maintenance.exec(`ALTER DATABASE ${quotePgIdentifier(name)} WITH CONNECTION LIMIT -1`);
    return assertPgDatabaseState(pgDatabaseCatalogRow(maintenance, name), {
      ...expected,
      datname: name,
      datallowconn: false,
      datconnlimit: -1,
    }, 'frozen Postgres restore');
  }

  return {
    preflight() {
      role = pgRestoreRole(maintenance);
      if (pgDatabaseCatalogRow(maintenance, plan.targetDatabase)) {
        throw new Error(`Postgres restore target database already exists: ${plan.targetDatabase}`);
      }
      if (pgDatabaseCatalogRow(maintenance, plan.stagingDatabase)) {
        throw new Error('Postgres restore staging-name collision');
      }
      const version = maintenance.prepare("SELECT current_setting('server_version_num') AS n").get();
      const targetServerMajor = Math.floor(Number(version && version.n) / 10000);
      if (!SUPPORTED_PG_RESTORE_MAJORS.has(targetServerMajor)) {
        throw new Error('Postgres guarded restore is unsupported for this target server version');
      }
      return { role, targetServerMajor };
    },
    createStaging(targetServerMajor) {
      const clauses = pgDatabaseDefinitionClauses(databaseDefinition, targetServerMajor);
      maintenance.exec(`
        CREATE DATABASE ${quotePgIdentifier(plan.stagingDatabase)}
          WITH TEMPLATE template0
               OWNER ${quotePgIdentifier(role.name)}
               ALLOW_CONNECTIONS false
               CONNECTION LIMIT ${PG_RESTORE_CONNECTION_LIMIT}
               ${clauses.join('\n               ')}
      `);
      const row = pgDatabaseCatalogRow(maintenance, plan.stagingDatabase);
      stagingIdentity = assertPgDatabaseState(row, {
        oid: row && row.oid,
        owner_oid: role.oid,
        datname: plan.stagingDatabase,
        datallowconn: false,
        datconnlimit: PG_RESTORE_CONNECTION_LIMIT,
      }, 'created Postgres restore staging');
      return stagingIdentity;
    },
    openGuard() {
      maintenance.exec(
        `REVOKE CONNECT, TEMPORARY ON DATABASE ${quotePgIdentifier(plan.stagingDatabase)} FROM PUBLIC`,
      );
      assertPgOwnerOnlyDatabaseAcl(maintenance, plan.stagingDatabase, role.oid);
      maintenance.exec(`ALTER DATABASE ${quotePgIdentifier(plan.stagingDatabase)} WITH ALLOW_CONNECTIONS true`);
      assertPgDatabaseState(pgDatabaseCatalogRow(maintenance, plan.stagingDatabase), {
        ...stagingIdentity,
        datname: plan.stagingDatabase,
        datallowconn: true,
        datconnlimit: PG_RESTORE_CONNECTION_LIMIT,
      }, 'guarded Postgres restore staging');
      guard = createGuardDriver(plan.stagingUrl);
      guardIdentity = pgGuardSession(guard);
      if (guardIdentity.database !== plan.stagingDatabase) {
        throw new Error('Postgres restore guard connected to the wrong database');
      }
      assertOnlyGuard();
      return guard;
    },
    guardDriver: () => guard,
    assertOnlyGuard,
    freeze() { return freeze(plan.stagingDatabase, stagingIdentity); },
    closeGuardAndAssertNoConnections() {
      guard?.close?.();
      guard = null;
      guardIdentity = null;
      waitForNoPgDatabaseSessions(maintenance, plan.stagingDatabase);
    },
    rename() {
      if (pgDatabaseCatalogRow(maintenance, plan.targetDatabase)) {
        const error = new Error(`Postgres restore target database appeared before rename: ${plan.targetDatabase}`);
        error.code = '42P04';
        throw error;
      }
      maintenance.exec(
        `ALTER DATABASE ${quotePgIdentifier(plan.stagingDatabase)} RENAME TO ${quotePgIdentifier(plan.targetDatabase)}`,
      );
      const renamed = pgDatabaseCatalogRow(maintenance, plan.targetDatabase);
      assertPgDatabaseState(renamed, {
        ...stagingIdentity,
        datname: plan.targetDatabase,
        datallowconn: false,
        datconnlimit: -1,
      }, 'renamed Postgres restore');
      if (pgDatabaseCatalogRow(maintenance, plan.stagingDatabase)) {
        throw new Error('Postgres restore staging name survived rename');
      }
      return renamed;
    },
    enable() {
      return enablePgRestoreTarget(maintenance, plan.targetDatabase, stagingIdentity);
    },
    reconcileRename() {
      const staging = pgDatabaseCatalogRow(maintenance, plan.stagingDatabase);
      const target = pgDatabaseCatalogRow(maintenance, plan.targetDatabase);
      if (samePgDatabaseIdentity(stagingIdentity, staging)) return 'staging';
      if (!staging && samePgDatabaseIdentity(stagingIdentity, target) && target.datallowconn === false) return 'target';
      return 'ambiguous';
    },
    cleanupOwnedStaging() {
      if (!stagingIdentity) return;
      freeze(plan.stagingDatabase, stagingIdentity);
      guard?.close?.();
      guard = null;
      guardIdentity = null;
      waitForNoPgDatabaseSessions(maintenance, plan.stagingDatabase);
      assertPgDatabaseState(pgDatabaseCatalogRow(maintenance, plan.stagingDatabase), {
        ...stagingIdentity,
        datname: plan.stagingDatabase,
        datallowconn: false,
        datconnlimit: -1,
      }, 'owned Postgres restore staging cleanup');
      maintenance.exec(`DROP DATABASE ${quotePgIdentifier(plan.stagingDatabase)}`);
      if (pgDatabaseCatalogRow(maintenance, plan.stagingDatabase)) {
        throw new Error('owned Postgres restore staging database remained after DROP');
      }
      stagingIdentity = null;
    },
    close() {
      guard?.close?.();
      guard = null;
      maintenance?.close?.();
    },
  };
}

function requirePgRestoreDatabaseIdentity(value) {
  const name = requirePgDatabaseIdentifier(value && value.name, 'Postgres cleanup target');
  const oid = String(value && value.oid || '');
  const ownerOid = String(value && value.ownerOid || '');
  if (!/^[1-9][0-9]*$/.test(oid) || !/^[1-9][0-9]*$/.test(ownerOid)) {
    throw new Error('Postgres cleanup database identity is invalid');
  }
  return { name, oid, ownerOid };
}

function pgCleanupMaintenanceUrl(connectionString, targetName, env) {
  assertPostgresConnectionUrl(connectionString, { env });
  if (pgDatabaseName(connectionString) !== targetName) return connectionString;
  const maintenanceName = requirePgDatabaseIdentifier(
    env.REDACTWALL_PG_MAINTENANCE_DATABASE || DEFAULT_PG_MAINTENANCE_DATABASE,
    'Postgres maintenance database',
  );
  return pgUrlForDatabase(connectionString, maintenanceName);
}

/** Drop only the exact database returned by guarded restore; never force sessions. */
function cleanupPgRestoreDatabase({
  connectionString = pgConnectionString(), databaseIdentity, env = process.env,
} = {}, deps = {}) {
  const identity = requirePgRestoreDatabaseIdentity(databaseIdentity);
  const createDriver = deps.createPgDriver || require('../server/storage/pg-driver').createPgDriver;
  const maintenance = createDriver(pgCleanupMaintenanceUrl(connectionString, identity.name, env));
  try {
    const role = pgRestoreRole(maintenance);
    if (role.oid !== identity.ownerOid) {
      throw new Error('Postgres cleanup role does not own the guarded restore database');
    }
    const expected = { oid: identity.oid, owner_oid: identity.ownerOid };
    const current = pgDatabaseCatalogRow(maintenance, identity.name);
    if (!current) return { ok: true, alreadyAbsent: true, databaseIdentity: identity };
    assertPgDatabaseState(current, { ...expected, datname: identity.name }, 'Postgres cleanup target');
    maintenance.exec(`ALTER DATABASE ${quotePgIdentifier(identity.name)} WITH ALLOW_CONNECTIONS false`);
    maintenance.exec(`ALTER DATABASE ${quotePgIdentifier(identity.name)} WITH CONNECTION LIMIT -1`);
    assertPgDatabaseState(pgDatabaseCatalogRow(maintenance, identity.name), {
      ...expected, datname: identity.name, datallowconn: false, datconnlimit: -1,
    }, 'frozen Postgres cleanup target');
    waitForNoPgDatabaseSessions(maintenance, identity.name);
    assertPgDatabaseState(pgDatabaseCatalogRow(maintenance, identity.name), {
      ...expected, datname: identity.name, datallowconn: false, datconnlimit: -1,
    }, 'drained Postgres cleanup target');
    maintenance.exec(`DROP DATABASE ${quotePgIdentifier(identity.name)}`);
    if (pgDatabaseCatalogRow(maintenance, identity.name)) {
      throw new Error('Postgres cleanup target remained after DROP');
    }
    return { ok: true, alreadyAbsent: false, databaseIdentity: identity };
  } catch (error) {
    throw new Error(
      `Postgres guarded restore cleanup did not conclusively remove ${identity.name}; inspect its exact database identity before manual cleanup: ${error.message}`,
      { cause: error },
    );
  } finally {
    maintenance.close();
  }
}

function runAndVerifyPgRestore(snapshot, targetUrl, flags, deps, control) {
  (deps.runPgTool || runPgTool)(
    'pg_restore',
    [...flags, `--dbname=${pgDatabaseName(targetUrl)}`, snapshot.archive],
    targetUrl,
  );
  control.assertOnlyGuard();
  control.freeze();
  const guard = control.guardDriver();
  const inspection = deps.verifyRestoredPgDatabase
    ? deps.verifyRestoredPgDatabase(targetUrl, snapshot.anchor, guard)
    : verifyRestoredPgDriver(guard, snapshot.anchor);
  if (!inspection.auditIntegrity || !inspection.auditIntegrity.ok) {
    throw new Error(`refusing to publish Postgres runtime audit state after failed restore verification: ${inspection.auditIntegrity?.reason || 'unknown'}`);
  }
  const databaseScope = deps.targetPgDatabaseScope
    ? deps.targetPgDatabaseScope(targetUrl, guard)
    : targetPgDatabaseScopeForDriver(guard);
  control.assertOnlyGuard();
  return { ...inspection, databaseScope: requirePgDatabaseScope(databaseScope) };
}

function pgRestoreResult(verification, inspection, targetUrl, auditPaths, databaseIdentity) {
  return {
    ok: true,
    driver: 'postgres',
    file: verification.file,
    backupSha256: verification.backupSha256,
    manifestOk: verification.manifestOk,
    auditIntegrity: inspection.auditIntegrity,
    queryCount: inspection.queryCount,
    auditCount: inspection.auditCount,
    auditDirectory: auditPaths.directory,
    auditStateFile: auditPaths.statePath,
    auditCheckpointFile: auditPaths.checkpointPath,
    auditPendingFile: auditPaths.pendingPath,
    restoredTo: sanitizeDatabaseUrl(targetUrl),
    databaseIdentity: {
      name: String(databaseIdentity.datname),
      oid: String(databaseIdentity.oid),
      ownerOid: String(databaseIdentity.owner_oid),
    },
  };
}

function pgCreateOutcomeIsConclusive(error) {
  return CONCLUSIVE_PG_DATABASE_MUTATION_REJECTIONS.has(String(error && error.code || ''));
}

function pgRestoreRecoveryError(state, error, retained, cleanupError = null) {
  const target = state.plan.targetDatabase;
  const staging = state.plan.stagingDatabase;
  const details = cleanupError ? ` Cleanup also failed: ${cleanupError.message}.` : '';
  const enableUncertain = state.enableAttempted && !state.enabled && error.pgEnableOutcome !== 'frozen';
  const manual = retained === 'target'
    ? enableUncertain
      ? `Target ${target} was retained and may already be connectable. Inspect its exact OID and connection state immediately; disable connections before any manual recovery.`
      : `Target ${target} was retained. Inspect pg_database and the runtime audit directory; keep it non-connectable until publication is verified, then enable or remove it manually.`
    : retained === 'ambiguous'
      ? `Database transition outcome is uncertain. Inspect both staging ${staging} and target ${target}; remove neither until exact ownership and OID are proven.`
      : `Staging database ${staging} was retained. Inspect pg_database and remove it manually only after its owner and OID are proven.`;
  return new Error(`Postgres guarded restore failed in phase ${state.phase}: ${error.message}.${details} ${manual}`, {
    cause: error,
  });
}

function handlePgRestoreDatabaseFailure(state, control, error) {
  if (state.createUncertain) return pgRestoreRecoveryError(state, error, 'ambiguous');
  if (state.renameAttempted && !state.renamed) {
    try {
      const location = control.reconcileRename();
      if (location === 'target') {
        state.renamed = true;
        state.stagingOwned = false;
      } else if (location === 'ambiguous') {
        return pgRestoreRecoveryError(state, error, 'ambiguous');
      }
    } catch (reconcileError) {
      return pgRestoreRecoveryError(state, error, 'ambiguous', reconcileError);
    }
  }
  if (state.renamed) return pgRestoreRecoveryError(state, error, 'target');
  if (!state.stagingOwned) return error;
  try {
    control.cleanupOwnedStaging();
    state.stagingOwned = false;
    return error;
  } catch (cleanupError) {
    return pgRestoreRecoveryError(state, error, 'staging', cleanupError);
  }
}

function restorePgBackupLocked(context) {
  const { file, inspected, targetAuditPaths, databasePlan, flags, env, security, deps } = context;
  requireNewPgAuditDirectory(targetAuditPaths.directory);
  const snapshot = createPgRestoreSnapshot(
    file,
    inspected.manifest,
    env,
    security,
    deps.restoreStagingParent || os.tmpdir(),
  );
  let runtimeStaging;
  let operationError;
  let control;
  let stagingCleanupAttempted = false;
  const state = {
    phase: 'artifact-staging',
    plan: databasePlan,
    stagingOwned: false,
    createUncertain: false,
    renameAttempted: false,
    renamed: false,
    published: false,
    enableAttempted: false,
    enabled: false,
  };
  try {
    runtimeStaging = createPgRuntimeAuditStaging(snapshot, inspected.manifest, targetAuditPaths, env, security);
    if (pathEntryExists(targetAuditPaths.directory)) {
      throw new Error(`Postgres restore target audit directory already exists: ${targetAuditPaths.directory}`);
    }
    const controlFactory = deps.createPgRestoreControl || createPgRestoreControl;
    control = controlFactory(databasePlan, inspected.manifest.sourceDatabaseDefinition, deps);
    state.phase = 'preflight';
    const preflight = control.preflight();
    state.phase = 'create-staging';
    try {
      control.createStaging(preflight.targetServerMajor);
      state.stagingOwned = true;
    } catch (error) {
      if (!pgCreateOutcomeIsConclusive(error)) state.createUncertain = true;
      throw error;
    }
    state.phase = 'open-guard';
    control.openGuard();
    if (deps.beforeGuardInventory) deps.beforeGuardInventory({ state, control, databasePlan });
    state.phase = 'guard-inventory';
    assertEmptyPgRestoreTarget(databasePlan.stagingUrl, {
      ...deps,
      expectedDatabaseConnectionLimit: PG_RESTORE_CONNECTION_LIMIT,
      expectedDatabaseOwnerOnlyAcl: true,
    });
    control.assertOnlyGuard();
    if (deps.afterGuardInventory) deps.afterGuardInventory({ state, control, databasePlan });
    state.phase = 'restore-and-verify';
    const inspection = runAndVerifyPgRestore(snapshot, databasePlan.stagingUrl, flags, deps, control);
    replaceStagedPgRuntimeState(
      runtimeStaging,
      snapshot,
      inspection.databaseScope,
      env,
      security,
    );
    state.phase = 'close-guard';
    control.closeGuardAndAssertNoConnections();
    state.phase = 'rename';
    state.renameAttempted = true;
    const renamedIdentity = control.rename();
    state.renamed = true;
    state.stagingOwned = false;
    state.phase = 'publish-runtime-audit';
    (deps.publishPgRuntimeAuditDirectory || publishNewPgRuntimeAuditDirectory)(
      runtimeStaging,
      targetAuditPaths,
      env,
      security,
    );
    state.published = true;
    const result = pgRestoreResult(
      inspected.verification,
      inspection,
      databasePlan.targetUrl,
      targetAuditPaths,
      renamedIdentity,
    );
    state.phase = 'pre-enable-staging-cleanup';
    stagingCleanupAttempted = true;
    (deps.cleanupPgRestoreStaging || cleanupPrivateStagingAfterOperation)([
      snapshot.staging,
      runtimeStaging && runtimeStaging.staging,
    ]);
    state.phase = 'enable-target';
    state.enableAttempted = true;
    control.enable();
    state.enabled = true;
    try { control.close(); } catch {}
    control = null;
    state.phase = 'complete';
    return result;
  } catch (error) {
    operationError = control ? handlePgRestoreDatabaseFailure(state, control, error) : error;
    throw operationError;
  } finally {
    let closeError = null;
    try { control?.close?.(); }
    catch (error) { closeError = error; }
    const finalizationError = closeError && operationError
      ? new AggregateError(
          [operationError, closeError],
          `${operationError.message}; Postgres restore control cleanup also failed: ${closeError.message}`,
          { cause: operationError },
        )
      : closeError;
    if (!stagingCleanupAttempted) {
      cleanupPrivateStagingAfterOperation([
        snapshot.staging,
        runtimeStaging && runtimeStaging.staging,
      ], finalizationError || operationError);
    }
    if (finalizationError) throw finalizationError;
  }
}

/** Verifier-first: the complete authenticated artifact set must match first. */
function restorePgBackup({
  file,
  to,
  manifestFile,
  auditDir,
  force = false,
  security = {},
  env = process.env,
} = {}, deps = {}) {
  const targetAuditPaths = requireNewPgAuditDirectory(auditDir);
  const inspected = inspectPgBackupArtifactSet({ file, manifestFile, security, env });
  const { verification } = inspected;
  if (!verification.ok) {
    throw new Error(verification.unverifiable
      ? verification.auditIntegrity.ok
        ? 'refusing to restore a backup without an authenticated manifest; create a fresh backup or pass --manifest <file>'
        : 'refusing to restore a backup with missing or invalid authenticated audit sidecars'
      : 'refusing to restore a backup that does not verify');
  }
  if (force) {
    throw new Error('Postgres restore does not support --force; the requested target database must not exist');
  }
  const connectionString = deps.connectionString || pgConnectionString();
  const databasePlan = pgRestoreDatabasePlan(
    connectionString,
    to,
    env,
    deps.randomBytes || crypto.randomBytes,
  );
  const flags = ['--no-owner', '--no-privileges', '--exit-on-error', '--single-transaction'];
  const context = { file, inspected, targetAuditPaths, databasePlan, flags, env, security, deps };
  return withPrivatePgAuditParent(
    targetAuditPaths.directory,
    security,
    () => restorePgBackupLocked(context),
  );
}

// ---- SQLite mode + driver dispatch --------------------------------------------

function verifyBackup({ file, manifestFile, security = {}, env = process.env } = {}) {
  if (!file) throw new Error('--file is required');
  const dbPath = path.resolve(file);
  if (isPgDumpFile(dbPath)) return verifyPgBackup({ file: dbPath, manifestFile, security, env });
  assertNoSqliteSidecars(dbPath);
  const manifest = manifestFile
    ? JSON.parse(fs.readFileSync(path.resolve(manifestFile), 'utf8'))
    : readManifest(dbPath);
  const backupAuditPaths = backupAuditArtifactPaths(dbPath);
  const runtimeAuditPaths = restoredAuditAnchorPaths(dbPath);
  const hasBackupAuditArtifact = pathEntryExists(backupAuditPaths.statePath)
    || pathEntryExists(backupAuditPaths.checkpointPath);
  const runtimeManifest = manifest && manifest.format === SQLITE_RESTORED_FORMAT
    && manifest.artifactLayout === SQLITE_RUNTIME_LAYOUT;
  const pendingPresent = runtimeManifest && pathEntryExists(runtimeAuditPaths.pendingPath);
  // A restored runtime intentionally uses server/db's normal audit directory,
  // while a portable backup keeps its two authenticated files beside the DB.
  // Only the authenticated runtime format selects the runtime layout. Other
  // present manifests stay on the portable paths and fail validation if edited.
  const auditPaths = runtimeManifest
    ? runtimeAuditPaths
    : !manifest && !hasBackupAuditArtifact && pathEntryExists(runtimeAuditPaths.directory)
      ? runtimeAuditPaths
      : backupAuditPaths;
  const paths = {
    database: dbPath,
    auditState: auditPaths.statePath,
    auditCheckpoint: auditPaths.checkpointPath,
  };
  const descriptors = { database: artifactDescriptor(dbPath) };
  let artifactError = null;
  try {
    descriptors.auditState = artifactDescriptor(auditPaths.statePath);
    descriptors.auditCheckpoint = artifactDescriptor(auditPaths.checkpointPath);
  } catch (error) {
    artifactError = error;
  }
  // A missing manifest is not a pass. Without an authenticated binding for
  // every artifact and semantic field, a hand-crafted database must not be
  // treated as a verified backup.
  const unverifiable = !manifest;
  let anchor = null;
  let anchorError = null;
  let manifestKey = null;
  if (!artifactError) {
    try {
      anchor = loadAuthenticatedAuditAnchor(auditPaths, env, security);
      if (manifest || hasBackupAuditArtifact) manifestKey = independentManifestKey(anchor);
    } catch (error) { anchorError = error; }
  }
  const manifestResult = unverifiable
    ? { ok: false, reason: 'manifest-missing' }
    : artifactError
      ? { ok: false, reason: 'artifact-unavailable' }
      : anchorError
        ? {
            ok: false,
            reason: anchorError.code === 'BACKUP_MANIFEST_KEY_NOT_INDEPENDENT'
              ? 'manifest-authentication-key' : 'audit-sidecar-unavailable',
          }
        : validateSqliteManifest(manifest, paths, descriptors, manifestKey);
  let auditIntegrityResult;
  if (pendingPresent) {
    auditIntegrityResult = {
      ok: false,
      count: anchor ? anchor.checkpoint.count : 0,
      reason: 'audit-pending-present',
    };
  } else if (anchor) {
    auditIntegrityResult = inspectAuthenticatedSqliteSnapshot(dbPath, anchor, security, true).auditIntegrity;
  } else {
    auditIntegrityResult = {
      ok: false,
      count: 0,
      reason: (artifactError || anchorError) && (artifactError || anchorError).code === 'ENOENT'
        ? 'audit-sidecar-missing' : 'audit-sidecar-unavailable',
    };
  }
  const backupSha256 = descriptors.database.sha256;
  return {
    ok: auditIntegrityResult.ok && manifestResult.ok,
    file: dbPath,
    bytes: descriptors.database.bytes,
    backupSha256,
    auditStateFile: auditPaths.statePath,
    auditCheckpointFile: auditPaths.checkpointPath,
    auditPendingFile: runtimeManifest ? runtimeAuditPaths.pendingPath : null,
    auditPendingPresent: !!pendingPresent,
    auditStateSha256: descriptors.auditState ? descriptors.auditState.sha256 : null,
    auditCheckpointSha256: descriptors.auditCheckpoint ? descriptors.auditCheckpoint.sha256 : null,
    auditIntegrity: auditIntegrityResult,
    manifestOk: manifestResult.ok,
    manifestReason: manifestResult.reason || null,
    unverifiable,
  };
}

async function createBackup(opts = {}) {
  let db = opts.dbModule;
  // Validate before requiring server/db. The Postgres driver connects and runs
  // migrations during module initialization, which is already too late for a
  // backup-specific transport guard.
  if (!db && postgresDriverConfigured()) pgConnectionString(opts.connectionString);
  db = db || require('../server/db');
  const kind = db._driverKind || 'sqlite';
  if (kind === 'postgres') return createPgBackup({ ...opts, dbModule: db });
  if (kind !== 'sqlite') {
    throw new Error(`this backup tool covers the SQLite and Postgres stores; unsupported driver: ${kind}`);
  }
  return createSqliteBackup({ ...opts, dbModule: db });
}

async function createSqliteBackup({
  outDir,
  file,
  manifestFile,
  dbModule: db,
  force = false,
  security = {},
  env = process.env,
} = {}) {
  assertBackupSource(db);
  // Capture authenticated state before the online SQLite copy. The captured
  // checkpoint is a lower bound; authenticated entries committed before the
  // copy's snapshot are accepted and rolled into its exact staged checkpoint.
  const sourceAnchor = loadAuthenticatedAuditAnchor(db._auditAnchorPaths, env);
  const manifestKey = independentManifestKey(sourceAnchor);
  const { backupFile, manifestPath } = resolveCreateTargets({ outDir, file, manifestFile });
  const auditPaths = backupAuditArtifactPaths(backupFile);
  assertDistinctArtifactTargets([
    { target: backupFile, sqlite: true },
    { target: auditPaths.statePath },
    { target: auditPaths.checkpointPath },
    { target: manifestPath },
  ]);
  assertWritable(backupFile, force, { sqlite: true });
  assertWritable(auditPaths.statePath, force);
  assertWritable(auditPaths.checkpointPath, force);
  assertWritable(manifestPath, force);
  let backupStaging;
  let manifestStaging;
  let operationError;
  let operationFailed = false;
  let committedResult;

  try {
    backupStaging = createPrivateStagingDir(path.dirname(backupFile), security);
    manifestStaging = createPrivateStagingDir(path.dirname(manifestPath), security);
    const stagedBackup = path.join(backupStaging, path.basename(backupFile));
    const stagedAuditState = path.join(backupStaging, path.basename(auditPaths.statePath));
    const stagedAuditCheckpoint = path.join(backupStaging, path.basename(auditPaths.checkpointPath));
    const stagedManifest = path.join(manifestStaging, path.basename(manifestPath));
    await db._db.backup(stagedBackup);
    restrictPath(stagedBackup, { ...security, directory: false });
    fsyncFile(stagedBackup);
    assertNoSqliteSidecars(stagedBackup);
    const snapshot = inspectAuthenticatedSqliteSnapshot(stagedBackup, sourceAnchor, security, false);
    const backupIntegrity = snapshot.auditIntegrity;
    if (!backupIntegrity.ok || !snapshot.exactCheckpoint) {
      throw new Error(`refusing to publish a backup with broken audit integrity: ${backupIntegrity.reason || 'unknown'}`);
    }
    writePrivateFile(stagedAuditState, JSON.stringify(sourceAnchor.state), security);
    writePrivateFile(stagedAuditCheckpoint, JSON.stringify(snapshot.exactCheckpoint), security);
    const descriptors = {
      database: artifactDescriptor(stagedBackup, backupFile),
      auditState: artifactDescriptor(stagedAuditState, auditPaths.statePath),
      auditCheckpoint: artifactDescriptor(stagedAuditCheckpoint, auditPaths.checkpointPath),
    };
    const backupSha256 = descriptors.database.sha256;
    const manifest = authenticateManifest({
      schemaVersion: 2,
      driver: 'sqlite',
      format: SQLITE_BACKUP_FORMAT,
      createdAt: new Date().toISOString(),
      service: { name: 'RedactWall', version: require('../package.json').version },
      sourceDbFile: path.basename(db._dbPath || 'redactwall.db'),
      sourceDbPathHash: crypto.createHash('sha256').update(String(db._dbPath || '')).digest('hex'),
      backupFile: path.basename(backupFile),
      backupBytes: descriptors.database.bytes,
      backupSha256,
      artifacts: descriptors,
      sourceIntegrity: backupIntegrity,
      backupIntegrity,
      stats: snapshot.stats,
      rawPromptBodiesIncluded: false,
      note: 'The backup database and authenticated audit sidecars are sensitive runtime state. This manifest contains no prompt bodies.',
    }, manifestKey);
    writePrivateFile(stagedManifest, JSON.stringify(manifest, null, 2), security);
    const verified = publishPrivateFiles([
      { staged: stagedBackup, target: backupFile, sqlite: true },
      { staged: stagedAuditState, target: auditPaths.statePath },
      { staged: stagedAuditCheckpoint, target: auditPaths.checkpointPath },
      { staged: stagedManifest, target: manifestPath },
    ], {
      force,
      security,
      verify: () => verifyBackup({ file: backupFile, manifestFile: manifestPath, security, env }),
    });
    committedResult = {
      ...verified,
      manifestFile: manifestPath,
      auditStateFile: auditPaths.statePath,
      auditCheckpointFile: auditPaths.checkpointPath,
      manifest,
    };
    return committedResult;
  } catch (error) {
    operationFailed = true;
    operationError = error;
    throw error;
  } finally {
    if (operationFailed) {
      cleanupPrivateStagingAfterOperation([backupStaging, manifestStaging], operationError, true);
    } else {
      cleanupPrivateStagingAfterCommit([backupStaging, manifestStaging], committedResult, {
        security,
        component: 'sqlite-backup',
        phase: 'private-staging-cleanup',
      });
    }
  }
}

function sqliteRestoreContext(file, to, manifestFile, verification) {
  const target = path.resolve(to);
  const source = path.resolve(file);
  const sourceManifestPath = path.resolve(manifestFile || `${source}.manifest.json`);
  const targetAuditPaths = restoredAuditAnchorPaths(target);
  const targetManifestPath = `${target}.manifest.json`;
  return {
    source,
    target,
    sourceManifestPath,
    sourceManifest: JSON.parse(fs.readFileSync(sourceManifestPath, 'utf8')),
    sourceAuditPaths: {
      statePath: verification.auditStateFile,
      checkpointPath: verification.auditCheckpointFile,
    },
    sourcePendingPath: verification.auditPendingFile,
    targetAuditPaths,
    targetManifestPath,
  };
}

function assertSqliteRestoreTargets(context, force) {
  assertDistinctArtifactTargets([
    { target: context.target, sqlite: true },
    { target: context.targetAuditPaths.directory, directory: true },
    { target: context.targetManifestPath },
  ]);
  assertWritable(context.target, force, { sqlite: true });
  assertWritable(context.targetAuditPaths.directory, force);
  assertWritable(context.targetManifestPath, force);
}

function copySqliteRestoreAuditSidecars(context, staged, security) {
  fs.mkdirSync(staged.auditDirectory, { mode: PRIVATE_DIR_MODE });
  restrictPath(staged.auditDirectory, { ...security, directory: true });
  copyPrivateRestoreArtifact(context.sourceAuditPaths.statePath, staged.auditState, {
    expectedBytes: context.sourceManifest.artifacts.auditState.bytes,
    maxBytes: MAX_AUDIT_STATE_BYTES,
    label: 'SQLite audit state sidecar',
    security,
  });
  copyPrivateRestoreArtifact(context.sourceAuditPaths.checkpointPath, staged.auditCheckpoint, {
    expectedBytes: context.sourceManifest.artifacts.auditCheckpoint.bytes,
    maxBytes: MAX_AUDIT_CHECKPOINT_BYTES,
    label: 'SQLite audit checkpoint sidecar',
    security,
  });
  privatePaths.fsyncDirectory(staged.auditDirectory, { fs });
}

function createSqliteRestoreStaging(context, security) {
  const staging = createPrivateStagingDir(path.dirname(context.target), security);
  const staged = {
    staging,
    database: path.join(staging, path.basename(context.target)),
    auditDirectory: path.join(staging, 'audit-integrity'),
    manifest: path.join(staging, path.basename(context.targetManifestPath)),
  };
  staged.auditState = path.join(staged.auditDirectory, AUDIT_STATE_NAME);
  staged.auditCheckpoint = path.join(staged.auditDirectory, AUDIT_CHECKPOINT_NAME);
  try {
    const sourceDirectory = context.sourcePendingPath
      ? capturePendingFreeDirectory(context.sourcePendingPath, 'SQLite runtime restore source')
      : null;
    copyPrivateRestoreArtifact(context.source, staged.database, {
      expectedBytes: context.sourceManifest.artifacts.database.bytes,
      label: 'SQLite backup database',
      security,
    });
    copySqliteRestoreAuditSidecars(context, staged, security);
    if (sourceDirectory) {
      assertPendingFreeDirectoryUnchanged(
        context.sourcePendingPath,
        sourceDirectory,
        'SQLite runtime restore source',
      );
    }
    assertNoSqliteSidecars(staged.database);
    return staged;
  } catch (error) {
    cleanupPrivateStagingAfterOperation([staging], error);
    throw error;
  }
}

function validateStableSqliteSource(context, staged, key) {
  const descriptors = {
    database: artifactDescriptor(staged.database, context.source),
    auditState: artifactDescriptor(staged.auditState, context.sourceAuditPaths.statePath),
    auditCheckpoint: artifactDescriptor(staged.auditCheckpoint, context.sourceAuditPaths.checkpointPath),
  };
  const result = validateSqliteManifest(context.sourceManifest, {
    database: context.source,
    auditState: context.sourceAuditPaths.statePath,
    auditCheckpoint: context.sourceAuditPaths.checkpointPath,
  }, descriptors, key);
  if (!result.ok) throw new Error(`backup artifacts changed during restore: ${result.reason}`);
}

function validateSqliteRestoreStaging(context, staged, env, security) {
  const anchor = loadAuthenticatedAuditAnchor({
    directory: staged.auditDirectory,
    statePath: staged.auditState,
    checkpointPath: staged.auditCheckpoint,
  }, env, security);
  const key = independentManifestKey(anchor);
  validateStableSqliteSource(context, staged, key);
  const audit = inspectAuthenticatedSqliteSnapshot(staged.database, anchor, security, true).auditIntegrity;
  if (!audit.ok) throw new Error('refusing to publish a restored database with broken audit integrity');
  return key;
}

function sqliteTargetDescriptors(context, staged) {
  return {
    database: artifactDescriptor(staged.database, context.target),
    auditState: artifactDescriptor(staged.auditState, context.targetAuditPaths.statePath),
    auditCheckpoint: artifactDescriptor(staged.auditCheckpoint, context.targetAuditPaths.checkpointPath),
  };
}

function publishSqliteRestore(context, staged, key, force, security, env) {
  const manifest = buildRestoredSqliteManifest(
    context.sourceManifest,
    sqliteTargetDescriptors(context, staged),
    key,
  );
  writePrivateFile(staged.manifest, JSON.stringify(manifest, null, 2), security);
  const verified = publishPrivateFiles([
    { staged: staged.database, target: context.target, sqlite: true },
    { staged: staged.auditDirectory, target: context.targetAuditPaths.directory, directory: true },
    { staged: staged.manifest, target: context.targetManifestPath },
  ], {
    force,
    security,
    verify() {
      if (pathEntryExists(context.targetAuditPaths.pendingPath)) {
        throw new Error('restored SQLite target unexpectedly contains pending audit high-water state');
      }
      const result = verifyBackup({
        file: context.target,
        manifestFile: context.targetManifestPath,
        security,
        env,
      });
      if (!result.ok) {
        throw new Error(`restored SQLite artifact set failed target-layout verification: ${result.manifestReason || result.auditIntegrity.reason || 'unknown'}`);
      }
      return result;
    },
  });
  return { verified, manifest };
}

function restoreSqliteBackup(context, force, security, env) {
  return withPrivateRestoreDirectory(context.target, security, () => {
    assertSqliteRestoreTargets(context, force);
    const staged = createSqliteRestoreStaging(context, security);
    let operationError;
    let operationFailed = false;
    let committedResult;
    try {
      const key = validateSqliteRestoreStaging(context, staged, env, security);
      const { verified, manifest } = publishSqliteRestore(context, staged, key, force, security, env);
      committedResult = {
        ...verified,
        restoredTo: context.target,
        file: context.target,
        manifestFile: context.targetManifestPath,
        manifest,
        auditStateFile: context.targetAuditPaths.statePath,
        auditCheckpointFile: context.targetAuditPaths.checkpointPath,
        sourceManifestFile: context.sourceManifestPath,
      };
      return committedResult;
    } catch (error) {
      operationFailed = true;
      operationError = error;
      throw error;
    } finally {
      if (operationFailed) {
        cleanupPrivateStagingAfterOperation([staged.staging], operationError, true);
      } else {
        cleanupPrivateStagingAfterCommit([staged.staging], committedResult, {
          security,
          component: 'sqlite-restore',
          phase: 'private-staging-cleanup',
        });
      }
    }
  });
}

function restoreBackup({ file, to, manifestFile, auditDir, force = false, security = {}, env = process.env } = {}) {
  if (!to) throw new Error('--to is required');
  if (file && isPgDumpFile(path.resolve(file))) {
    return restorePgBackup({ file, to, manifestFile, auditDir, force, security, env });
  }
  const verification = verifyBackup({ file, manifestFile, security, env });
  if (!verification.ok) {
    throw new Error(verification.unverifiable
      ? verification.auditIntegrity.ok
        ? 'refusing to restore a backup without an authenticated manifest; create a fresh backup or pass --manifest <file>'
        : 'refusing to restore a backup with missing or invalid authenticated audit sidecars'
      : 'refusing to restore a backup that does not verify');
  }
  return restoreSqliteBackup(sqliteRestoreContext(file, to, manifestFile, verification), force, security, env);
}

async function main(argv = process.argv.slice(2), deps = {}) {
  const io = deps.console || console;
  const create = deps.createBackup || createBackup;
  const verify = deps.verifyBackup || verifyBackup;
  const restore = deps.restoreBackup || restoreBackup;
  const setExitCode = deps.setExitCode || ((code) => { process.exitCode = code; });
  const args = parseArgs(argv);
  const command = args._[0] || 'create';
  const positional = args._.slice(1);
  let result;
  if (command === 'create') {
    result = await create({
      outDir: args.out || positional[0],
      file: args.file,
      manifestFile: args.manifest,
      force: args.force,
    });
  } else if (command === 'verify') {
    result = verify({ file: args.file || positional[0], manifestFile: args.manifest });
  } else if (command === 'restore') {
    result = restore({
      file: args.file || positional[0],
      to: args.to || positional[1],
      manifestFile: args.manifest,
      auditDir: args['audit-dir'],
      force: args.force,
    });
  }
  else throw new Error(`unknown command: ${command}`);
  io.log(JSON.stringify(result, null, 2));
  if (result && result.ok === false) setExitCode(1);
  return result;
}

if (require.main === module) main().catch((e) => { console.error(e.message); process.exit(1); });

module.exports = {
  parseArgs,
  createBackup,
  main,
  verifyBackup,
  restoreBackup,
  isPgDumpFile,
  pgConnectionEnv,
  pgClientConfig,
  assertPostgresConnectionUrl,
  deriveDatabaseUrl,
  sanitizeDatabaseUrl,
  runPgTool,
  verifyRestoredPgDatabase,
  cleanupPgRestoreDatabase,
  _internal: {
    createPrivateStagingDir,
    cleanupPrivateStagingDirectory,
    copyPrivateRestoreArtifact,
    withPrivateRestoreDirectory,
    inspectSqliteSnapshot,
    pgDatabaseName,
    captureWindowsDacl,
    restrictPath,
    snapshotStatsFromRows,
    sqliteSidecarPaths,
    verifyPgSnapshotIntegrity,
    inspectEmptyPgRestoreTarget,
    pgRestoreInventorySql,
    parsePgRestoreInventory,
    PG_RESTORE_INVENTORY_NAMES,
    pgRestoreDatabasePlan,
    createPgRestoreControl,
    enablePgRestoreTarget,
    cleanupPgRestoreDatabase,
    pgRestoreRole,
    pgDatabaseCatalogRow,
    samePgDatabaseIdentity,
    validatePgDatabaseDefinition,
    pgDatabaseDefinitionClauses,
    verifyRestoredPgDriver,
    targetPgDatabaseScopeForDriver,
    restorePgBackup,
    withPgSnapshot,
    pgDumpArgs,
    targetPgDatabaseScope,
    replaceStagedPgRuntimeState,
    fsyncPublishedArtifact,
  },
};
