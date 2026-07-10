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
const auditIntegrity = require('../server/audit-integrity');
const auditAnchorInternal = require('../server/audit-anchor')._internal;
const privatePaths = require('../server/private-path');
const {
  parsePostgresConnectionUrl,
  validPostgresTlsUrl,
  withoutPostgresConnectionEnv,
} = require('../server/postgres-url');

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
    out[key] = argv[++i];
  }
  return out;
}

function sha256File(file) {
  const h = crypto.createHash('sha256');
  h.update(fs.readFileSync(file));
  return h.digest('hex');
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
const RESTORE_COPY_BUFFER_BYTES = 64 * 1024;
const MANIFEST_AUTH_VERSION = 1;
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
  const result = spawn('whoami.exe', [], { encoding: 'utf8', windowsHide: true });
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
  try {
    return restrictPath(staging, { ...security, directory: true });
  } catch (error) {
    fs.rmSync(staging, { recursive: true, force: true });
    throw error;
  }
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
  if (left.dev && right.dev && left.dev !== right.dev) return false;
  if (left.ino && right.ino && left.ino !== right.ino) return false;
  return true;
}

function assertStableRestoreSource(stat, expectedBytes, maxBytes, label) {
  if (!stat.isFile() || stat.isSymbolicLink?.() || (stat.nlink && stat.nlink !== 1)
      || stat.size !== expectedBytes || stat.size > maxBytes) {
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
  const before = fs.lstatSync(source);
  assertStableRestoreSource(before, expectedBytes, maxBytes, label);
  const noFollow = fs.constants.O_NOFOLLOW || 0;
  let sourceFd;
  let targetFd;
  let complete = false;
  try {
    sourceFd = fs.openSync(source, fs.constants.O_RDONLY | noFollow);
    const opened = fs.fstatSync(sourceFd);
    assertStableRestoreSource(opened, expectedBytes, maxBytes, label);
    if (!sameFileIdentity(before, opened) || opened.mtimeMs !== before.mtimeMs
        || opened.ctimeMs !== before.ctimeMs) throw new Error(`${label} changed while opening`);
    targetFd = fs.openSync(target, 'wx', PRIVATE_FILE_MODE);
    restrictPath(target, { ...security, directory: false });
    const copied = copyOpenedRestoreArtifact(sourceFd, targetFd, maxBytes, label);
    const after = fs.fstatSync(sourceFd);
    if (copied !== expectedBytes || after.size !== opened.size
        || after.mtimeMs !== opened.mtimeMs || after.ctimeMs !== opened.ctimeMs
        || !sameFileIdentity(opened, after)) throw new Error(`${label} changed while copying`);
    fs.fsyncSync(targetFd);
    complete = true;
    return target;
  } finally {
    if (targetFd !== undefined) fs.closeSync(targetFd);
    if (sourceFd !== undefined) fs.closeSync(sourceFd);
    if (!complete) fs.rmSync(target, { force: true });
  }
}

function fsyncPublishedArtifact(item) {
  if (item.directory) privatePaths.fsyncDirectory(item.target, { fs });
  else fsyncFile(item.target);
  privatePaths.fsyncDirectory(path.dirname(item.target), { fs });
  if (!item.directory) privatePaths.fsyncDirectory(path.dirname(item.staged), { fs });
}

function cleanupRollbackDirs(state) {
  const failures = [];
  for (const directory of state.directories.values()) {
    try {
      fs.rmSync(directory, { recursive: true, force: true });
    } catch (error) {
      failures.push(error);
    }
  }
  if (failures.length) {
    const remaining = [...state.directories.values()].filter((directory) => fs.existsSync(directory));
    throw new Error(`failed to remove private rollback state; recovery directories remain: ${remaining.join(', ')}`, {
      cause: failures[0],
    });
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

function assertExistingArtifactType(target, directory) {
  const stat = fs.lstatSync(target);
  if (stat.isSymbolicLink() || (directory ? !stat.isDirectory() : !stat.isFile())
      || (!directory && stat.nlink && stat.nlink !== 1)) {
    throw new Error(`refusing unsafe replacement artifact: ${target}`);
  }
}

function restoreMovedArtifacts(state, items, clearTargets = false) {
  if (clearTargets) {
    for (const item of items) removeTargetArtifacts(item.target, item.sqlite, item.directory);
  }
  const failures = [];
  for (const artifact of [...state.moved].reverse()) {
    try {
      fs.rmSync(artifact.target, { recursive: artifact.directory, force: true });
      fs.renameSync(artifact.staged, artifact.target);
      restoreArtifactPermissions(artifact.target, artifact.permissions, state.security);
    } catch (error) {
      failures.push(error);
    }
  }
  if (failures.length) {
    const recoveryDirs = [...state.directories.values()].join(', ');
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
        assertExistingArtifactType(target, item.directory === true);
        const parent = path.dirname(target);
        if (!state.directories.has(parent)) {
          state.directories.set(parent, createPrivateStagingDir(parent, security));
        }
        const staged = path.join(state.directories.get(parent), `${state.moved.length}-${path.basename(target)}`);
        const permissions = captureArtifactPermissions(target, security);
        fs.renameSync(target, staged);
        state.moved.push({ target, staged, permissions, directory: item.directory === true });
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
      if (item.directory) fs.renameSync(item.staged, item.target);
      else fs.linkSync(item.staged, item.target);
      published.push(item);
      if (!item.directory) fs.unlinkSync(item.staged);
      restrictPath(item.target, { ...security, directory: item.directory === true });
      if (item.sqlite) assertNoSqliteSidecars(item.target);
      fsyncPublishedArtifact(item);
    }
  } catch (error) {
    for (const item of published) removeTargetArtifacts(item.target, item.sqlite, item.directory);
    throw error;
  }
}

/**
 * Publish staged files without overwriting a path created after preflight.
 * Staging lives in each target's parent, so a hard link is an atomic,
 * same-filesystem no-replace operation and preserves the private mode/ACL.
 */
function publishPrivateFiles(items, { force = false, security = {} } = {}) {
  assertDistinctArtifactTargets(items);
  for (const item of items) assertWritable(item.target, force, { sqlite: item.sqlite });
  if (!force) return publishStagedFiles(items, security);

  const rollback = stageExistingArtifacts(items, security);
  try {
    publishStagedFiles(items, security);
  } catch (error) {
    try {
      restoreMovedArtifacts(rollback, items, true);
    } catch (rollbackError) {
      throw new Error(`backup publish failed; ${rollbackError.message}`, { cause: error });
    }
    throw error;
  }
  try {
    cleanupRollbackDirs(rollback);
  } catch (error) {
    throw new Error(`backup publish succeeded, but prior artifacts remain in private recovery directories: ${error.message}`, {
      cause: error,
    });
  }
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
  } finally {
    if (dbFile) dbFile.close();
    fs.rmSync(staging, { recursive: true, force: true });
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
  const directory = `${path.resolve(file)}.audit-integrity`;
  return {
    directory,
    statePath: path.join(directory, AUDIT_STATE_NAME),
    checkpointPath: path.join(directory, AUDIT_CHECKPOINT_NAME),
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

async function readPgSnapshotEvidence(client, sourceAnchor) {
  const verified = await verifyPgSnapshotIntegrity(client, sourceAnchor);
  if (!verified.ok) {
    throw new Error(`refusing to back up a snapshot with broken audit integrity: ${verified.reason || 'unknown'}`);
  }
  const { exactCheckpoint, ...sourceIntegrity } = verified;
  const queryRows = await client.query(
    'SELECT status, "createdAt" AS "createdAt", data FROM queries ORDER BY seq ASC',
  );
  return { sourceIntegrity, exactCheckpoint, stats: snapshotStatsFromRows(queryRows.rows) };
}

async function withPgSnapshot(connectionString, callback, options = {}) {
  assertPostgresConnectionUrl(connectionString, options);
  const createClient = options.createClient || ((url) => {
    const { Client } = require('pg');
    return new Client({ connectionString: url });
  });
  const client = createClient(connectionString);
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
    rawPromptBodiesIncluded: false,
    note: 'The dump and authenticated audit sidecars are sensitive runtime state. This manifest contains no prompt bodies and no connection credentials; verify restores with backup-drill.',
  }, key);
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
      if (!evidence.exactCheckpoint
          || !auditIntegrity.validCheckpoint(evidence.exactCheckpoint, sourceAnchor.key)
          || evidence.exactCheckpoint.count !== evidence.sourceIntegrity.count) {
        throw new Error('Postgres snapshot did not provide an authenticated exact checkpoint');
      }
      // --enable-row-security: queries has FORCE ROW LEVEL SECURITY, which
      // pg_dump otherwise refuses as a non-BYPASSRLS role. The exported
      // snapshot binds the dump to the exact rows counted and verified here.
      pgRunner('pg_dump', [
        '--format=custom',
        '--enable-row-security',
        `--snapshot=${snapshotId}`,
        `--dbname=${pgDatabaseName(connString)}`,
        `--file=${stagedBackup}`,
      ], connString);
      if (!isPgDumpFile(stagedBackup)) throw new Error('pg_dump did not produce a valid custom-format archive');
      return {
        sourceIntegrity: evidence.sourceIntegrity,
        exactCheckpoint: evidence.exactCheckpoint,
        stats: evidence.stats,
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
      key: manifestKey,
    });
    writePrivateFile(stagedManifest, JSON.stringify(manifest, null, 2), security);
    publishPrivateFiles([
      { staged: stagedBackup, target: backupFile },
      { staged: stagedAuditState, target: auditPaths.statePath },
      { staged: stagedAuditCheckpoint, target: auditPaths.checkpointPath },
      { staged: stagedManifest, target: manifestPath },
    ], { force, security });
    const verified = verifyPgBackup({ file: backupFile, manifestFile: manifestPath, security, env });
    return {
      ...verified,
      auditIntegrity: snapshotEvidence.sourceIntegrity,
      manifestFile: manifestPath,
      auditStateFile: auditPaths.statePath,
      auditCheckpointFile: auditPaths.checkpointPath,
      manifest,
    };
  } finally {
    if (backupStaging) fs.rmSync(backupStaging, { recursive: true, force: true });
    if (manifestStaging) fs.rmSync(manifestStaging, { recursive: true, force: true });
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

/** Open the restored database through the production driver and measure it. */
function verifyRestoredPgDatabase(targetUrl, anchor) {
  assertPostgresConnectionUrl(targetUrl);
  const { createPgDriver } = require('../server/storage/pg-driver');
  const driver = createPgDriver(targetUrl);
  try {
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
  } finally {
    driver.close();
  }
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
  return { anchor, descriptors };
}

function createPgRestoreSnapshot(file, manifest, env, security, stagingParent = os.tmpdir()) {
  const database = path.resolve(file);
  const staging = createPrivateStagingDir(stagingParent, security);
  let complete = false;
  try {
    const source = pgRestoreArtifactPaths(database);
    const staged = pgRestoreArtifactPaths(database, staging);
    copyPgRestoreArtifacts(source, staged, manifest, security);
    const verified = validatePgRestoreSnapshot(staged, manifest, env, security);
    complete = true;
    return { ...verified, archive: staged.database, staging };
  } finally {
    if (!complete) fs.rmSync(staging, { recursive: true, force: true });
  }
}

/** Verifier-first: the complete authenticated artifact set must match first. */
function restorePgBackup({
  file,
  to,
  manifestFile,
  force = false,
  security = {},
  env = process.env,
} = {}, deps = {}) {
  const inspected = inspectPgBackupArtifactSet({ file, manifestFile, security, env });
  const { verification } = inspected;
  if (!verification.ok) {
    throw new Error(verification.unverifiable
      ? verification.auditIntegrity.ok
        ? 'refusing to restore a backup without an authenticated manifest; create a fresh backup or pass --manifest <file>'
        : 'refusing to restore a backup with missing or invalid authenticated audit sidecars'
      : 'refusing to restore a backup that does not verify');
  }
  const targetUrl = deriveDatabaseUrl(deps.connectionString || pgConnectionString(), to);
  assertPostgresConnectionUrl(targetUrl, deps);
  const flags = ['--no-owner', '--no-privileges', '--exit-on-error', '--single-transaction'];
  if (force) flags.push('--clean', '--if-exists');
  const snapshot = createPgRestoreSnapshot(
    file,
    inspected.manifest,
    env,
    security,
    deps.restoreStagingParent || os.tmpdir(),
  );
  try {
    (deps.runPgTool || runPgTool)(
      'pg_restore',
      [...flags, `--dbname=${pgDatabaseName(targetUrl)}`, snapshot.archive],
      targetUrl,
    );
    const inspection = (deps.verifyRestoredPgDatabase || verifyRestoredPgDatabase)(targetUrl, snapshot.anchor);
    return {
      ok: inspection.auditIntegrity.ok,
      driver: 'postgres',
      file: verification.file,
      backupSha256: verification.backupSha256,
      manifestOk: verification.manifestOk,
      auditIntegrity: inspection.auditIntegrity,
      queryCount: inspection.queryCount,
      auditCount: inspection.auditCount,
      auditStateFile: verification.auditStateFile,
      auditCheckpointFile: verification.auditCheckpointFile,
      restoredTo: sanitizeDatabaseUrl(targetUrl),
    };
  } finally {
    fs.rmSync(snapshot.staging, { recursive: true, force: true });
  }
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
  // A restored runtime intentionally uses server/db's normal audit directory,
  // while a portable backup keeps its two authenticated files beside the DB.
  // A present manifest always selects the portable layout, so missing backup
  // artifacts cannot be disguised by adding a runtime directory.
  const auditPaths = !manifest && !hasBackupAuditArtifact && pathEntryExists(runtimeAuditPaths.directory)
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
  if (anchor) {
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
      format: 'sqlite-backup',
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
    publishPrivateFiles([
      { staged: stagedBackup, target: backupFile, sqlite: true },
      { staged: stagedAuditState, target: auditPaths.statePath },
      { staged: stagedAuditCheckpoint, target: auditPaths.checkpointPath },
      { staged: stagedManifest, target: manifestPath },
    ], { force, security });
    const verified = verifyBackup({ file: backupFile, manifestFile: manifestPath, security, env });
    return {
      ...verified,
      manifestFile: manifestPath,
      auditStateFile: auditPaths.statePath,
      auditCheckpointFile: auditPaths.checkpointPath,
      manifest,
    };
  } finally {
    if (backupStaging) fs.rmSync(backupStaging, { recursive: true, force: true });
    if (manifestStaging) fs.rmSync(manifestStaging, { recursive: true, force: true });
  }
}

function restoreBackup({ file, to, manifestFile, force = false, security = {}, env = process.env } = {}) {
  if (!to) throw new Error('--to is required');
  if (file && isPgDumpFile(path.resolve(file))) {
    return restorePgBackup({ file, to, manifestFile, force, security, env });
  }
  const verification = verifyBackup({ file, manifestFile, security, env });
  if (!verification.ok) {
    throw new Error(verification.unverifiable
      ? verification.auditIntegrity.ok
        ? 'refusing to restore a backup without an authenticated manifest; create a fresh backup or pass --manifest <file>'
        : 'refusing to restore a backup with missing or invalid authenticated audit sidecars'
      : 'refusing to restore a backup that does not verify');
  }
  const target = path.resolve(to);
  const sourceAuditPaths = backupAuditArtifactPaths(path.resolve(file));
  const targetAuditPaths = restoredAuditAnchorPaths(target);
  assertDistinctArtifactTargets([
    { target, sqlite: true },
    { target: targetAuditPaths.directory, directory: true },
  ]);
  assertWritable(target, force, { sqlite: true });
  assertWritable(targetAuditPaths.directory, force);
  const staging = createPrivateStagingDir(path.dirname(target), security);
  const stagedTarget = path.join(staging, path.basename(target));
  const stagedAuditDirectory = path.join(staging, 'audit-integrity');
  const stagedAuditState = path.join(stagedAuditDirectory, AUDIT_STATE_NAME);
  const stagedAuditCheckpoint = path.join(stagedAuditDirectory, AUDIT_CHECKPOINT_NAME);
  try {
    fs.copyFileSync(path.resolve(file), stagedTarget, fs.constants.COPYFILE_EXCL);
    restrictPath(stagedTarget, { ...security, directory: false });
    fsyncFile(stagedTarget);
    fs.mkdirSync(stagedAuditDirectory, { mode: PRIVATE_DIR_MODE });
    restrictPath(stagedAuditDirectory, { ...security, directory: true });
    fs.copyFileSync(sourceAuditPaths.statePath, stagedAuditState, fs.constants.COPYFILE_EXCL);
    restrictPath(stagedAuditState, { ...security, directory: false });
    fsyncFile(stagedAuditState);
    fs.copyFileSync(sourceAuditPaths.checkpointPath, stagedAuditCheckpoint, fs.constants.COPYFILE_EXCL);
    restrictPath(stagedAuditCheckpoint, { ...security, directory: false });
    fsyncFile(stagedAuditCheckpoint);
    assertNoSqliteSidecars(stagedTarget);
    const stagedDescriptors = {
      database: artifactDescriptor(stagedTarget),
      auditState: artifactDescriptor(stagedAuditState),
      auditCheckpoint: artifactDescriptor(stagedAuditCheckpoint),
    };
    if (stagedDescriptors.database.sha256 !== verification.backupSha256
        || stagedDescriptors.auditState.sha256 !== verification.auditStateSha256
        || stagedDescriptors.auditCheckpoint.sha256 !== verification.auditCheckpointSha256) {
      throw new Error('backup artifacts changed during restore');
    }
    const stagedAnchor = loadAuthenticatedAuditAnchor({
      statePath: stagedAuditState,
      checkpointPath: stagedAuditCheckpoint,
    }, env, security);
    const auditIntegrityResult = inspectAuthenticatedSqliteSnapshot(
      stagedTarget,
      stagedAnchor,
      security,
      true,
    ).auditIntegrity;
    if (!auditIntegrityResult.ok) throw new Error('refusing to publish a restored database with broken audit integrity');
    publishPrivateFiles([
      { staged: stagedTarget, target, sqlite: true },
      { staged: stagedAuditDirectory, target: targetAuditPaths.directory, directory: true },
    ], { force, security });
    return {
      ok: true,
      restoredTo: target,
      file: target,
      backupSha256: sha256File(target),
      auditIntegrity: auditIntegrityResult,
      auditStateFile: targetAuditPaths.statePath,
      auditCheckpointFile: targetAuditPaths.checkpointPath,
      unverifiable: verification.unverifiable,
    };
  } finally {
    fs.rmSync(staging, { recursive: true, force: true });
  }
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
    result = restore({ file: args.file || positional[0], to: args.to || positional[1], manifestFile: args.manifest, force: args.force });
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
  assertPostgresConnectionUrl,
  deriveDatabaseUrl,
  sanitizeDatabaseUrl,
  runPgTool,
  verifyRestoredPgDatabase,
  _internal: {
    createPrivateStagingDir,
    inspectSqliteSnapshot,
    pgDatabaseName,
    captureWindowsDacl,
    restrictPath,
    snapshotStatsFromRows,
    sqliteSidecarPaths,
    verifyPgSnapshotIntegrity,
    restorePgBackup,
    withPgSnapshot,
  },
};
