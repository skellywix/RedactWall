'use strict';
/**
 * Admin-triggered source updates.
 *
 * The updater is intentionally conservative:
 * - it only uses an existing Git remote,
 * - production API calls require that remote to be GitHub,
 * - the working tree must be clean before source is changed,
 * - the SQLite evidence store is verified and backed up first,
 * - updates are fast-forward only.
 */
require('./env').loadEnv();
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFile } = require('child_process');

const backupStore = require('../scripts/backup-store');
const fileMutationLock = require('./file-mutation-lock');
const privatePaths = require('./private-path');
const { securePrivatePath } = privatePaths;

const ROOT = path.resolve(__dirname, '..');
const COMMAND_TIMEOUT_MS = 2 * 60 * 1000;
const UPDATE_TIMEOUT_MS = 8 * 60 * 1000;
const MAX_BUFFER = 512 * 1024;
const MAX_UPDATER_FILE_BYTES = 4 * 1024 * 1024;
const MAX_UPDATE_CONFIG_BYTES = 64 * 1024;
const DEFAULT_CONFIG = {
  remoteName: 'origin',
  branch: 'main',
  installMode: 'npm-ci-omit-dev',
  restartCommand: '',
  restartAfterUpdate: false,
};
const SAFE_RESTART_COMMAND = /^[A-Za-z0-9 ._:/\\@+=,-]+$/;
const GIT_LOCAL_ENVIRONMENT_VARIABLES = Object.freeze([
  'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_CONFIG', 'GIT_CONFIG_PARAMETERS',
  'GIT_CONFIG_COUNT', 'GIT_OBJECT_DIRECTORY', 'GIT_DIR', 'GIT_WORK_TREE',
  'GIT_IMPLICIT_WORK_TREE', 'GIT_GRAFT_FILE', 'GIT_INDEX_FILE',
  'GIT_NO_REPLACE_OBJECTS', 'GIT_REPLACE_REF_BASE', 'GIT_PREFIX',
  'GIT_INTERNAL_SUPER_PREFIX', 'GIT_SHALLOW_FILE', 'GIT_COMMON_DIR',
]);

let activeRun = null;
let cachedDb = null;

function activeDb(opts = {}) {
  if (opts.dbModule) return opts.dbModule;
  if (!cachedDb) cachedDb = require('./db');
  return cachedDb;
}

function dataRoot(opts = {}) {
  if (opts.dataRoot) return path.resolve(opts.dataRoot);
  if (process.env.REDACTWALL_UPDATE_DATA_ROOT) return path.resolve(process.env.REDACTWALL_UPDATE_DATA_ROOT);
  if (process.env.REDACTWALL_UPDATE_CONFIG_PATH) return path.dirname(path.resolve(process.env.REDACTWALL_UPDATE_CONFIG_PATH));
  const db = activeDb(opts);
  // On Postgres db._dbPath is the literal 'postgres' (not a filesystem path), so
  // dirname would land in the process CWD. Fall back to the data directory
  // whenever the driver path isn't an absolute filesystem path.
  if (!db._dbPath || !path.isAbsolute(db._dbPath)) return path.join(ROOT, 'data');
  return path.dirname(db._dbPath);
}

function configPath(opts = {}) {
  if (opts.configPath) return path.resolve(opts.configPath);
  if (opts.dataRoot) return path.join(dataRoot(opts), 'update-settings.json');
  return process.env.REDACTWALL_UPDATE_CONFIG_PATH || path.join(dataRoot(opts), 'update-settings.json');
}

function statePath(opts = {}) {
  if (opts.statePath) return path.resolve(opts.statePath);
  if (opts.dataRoot) return path.join(dataRoot(opts), 'update-state.json');
  return process.env.REDACTWALL_UPDATE_STATE_PATH || path.join(dataRoot(opts), 'update-state.json');
}

function updateBackupDir(opts = {}) {
  return path.join(dataRoot(opts), 'backups', 'updates');
}

function ensureParent(file, fsImpl = fs) {
  fsImpl.mkdirSync(path.dirname(file), { recursive: true });
}

function readJson(file, fallback = null) {
  try {
    if (!fs.existsSync(file)) return fallback;
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return fallback;
  }
}

function writeFileAtomic(file, contents, opts = {}) {
  const fsImpl = opts.fs || fs;
  ensureParent(file, fsImpl);
  const mode = opts.mode == null ? 0o600 : opts.mode;
  const contentsBuffer = Buffer.isBuffer(contents)
    ? Buffer.from(contents)
    : Buffer.from(String(contents), 'utf8');
  if (contentsBuffer.length > MAX_UPDATER_FILE_BYTES) {
    throw updateFileFailure('updater file exceeds its size limit');
  }
  const suffix = (opts.randomBytes || crypto.randomBytes)(8).toString('hex');
  const tmp = `${file}.${process.pid}.${suffix}.tmp`;
  let fd;
  let publicationStarted = false;
  let publishedCandidate = null;
  try {
    fd = fsImpl.openSync(tmp, 'wx', mode);
    securePrivatePath(tmp, {
      fs: fsImpl,
      directory: false,
      fresh: true,
      label: 'updater staging file',
      ownerLabel: 'updater staging file',
    });
    fsImpl.writeFileSync(fd, contentsBuffer);
    if (typeof fsImpl.fsyncSync === 'function') fsImpl.fsyncSync(fd);
    fsImpl.closeSync(fd);
    fd = undefined;
    publicationStarted = true;
    const callerVerify = opts.verifyPublished;
    const publish = opts.exclusive
      ? privatePaths.publishFileExclusiveDurably
      : privatePaths.publishFileDurably;
    publish(tmp, file, {
      ...opts,
      fs: fsImpl,
      cleanupComponent: 'updater-file-publication',
      ...(opts.exclusive ? { consumeSource: true } : {}),
      verifyPublished(published) {
        const candidate = updaterFileSnapshot(published, {
          ...opts,
          fs: fsImpl,
          maxBytes: MAX_UPDATER_FILE_BYTES,
        });
        if (!candidate.exists || !candidate.contents.equals(contentsBuffer)) {
          throw updateFileFailure('published updater file bytes could not be verified');
        }
        publishedCandidate = candidate;
        if (typeof callerVerify === 'function') return callerVerify(published);
        return undefined;
      },
    });
  } catch (error) {
    if (fd !== undefined) {
      try { fsImpl.closeSync(fd); } catch {}
    }
    if (!publicationStarted) try { fsImpl.unlinkSync(tmp); } catch {}
    throw error;
  }
  if (!publishedCandidate) throw updateFileFailure('published updater file identity was not captured');
  return publishedCandidate;
}

function writeJson(file, value, opts = {}) {
  return writeFileAtomic(file, JSON.stringify(value, null, 2), opts);
}

function exactUpdaterLstat(fsImpl, target) {
  return fsImpl.lstatSync(target, { bigint: true });
}

function exactUpdaterFstat(fsImpl, descriptor) {
  return fsImpl.fstatSync(descriptor, { bigint: true });
}

function stableUpdaterFile(stat, expectedLinks = 1n) {
  return !!stat && typeof stat.dev === 'bigint' && typeof stat.ino === 'bigint'
    && typeof stat.size === 'bigint' && typeof stat.mode === 'bigint'
    && stat.dev > 0n && stat.ino > 0n && stat.size >= 0n
    && stat.isFile() && !stat.isSymbolicLink() && stat.nlink === expectedLinks;
}

function sameUpdaterStatTime(left, right, name) {
  const ns = `${name}Ns`;
  if (left[ns] !== undefined || right[ns] !== undefined) {
    return left[ns] !== undefined && right[ns] !== undefined && left[ns] === right[ns];
  }
  const ms = `${name}Ms`;
  return left[ms] !== undefined && right[ms] !== undefined && left[ms] === right[ms];
}

function sameUpdaterSnapshot(left, right) {
  return stableUpdaterFile(left) && stableUpdaterFile(right)
    && left.dev === right.dev && left.ino === right.ino && left.size === right.size
    && sameUpdaterStatTime(left, right, 'mtime') && sameUpdaterStatTime(left, right, 'ctime');
}

function updateFileFailure(message, cause) {
  const error = publicFailure(message, 500);
  error.code = 'UPDATE_CONFIG_FILE_INVALID';
  if (cause) error.cause = cause;
  return error;
}

function inspectUpdaterFile(file, fsImpl, maxBytes) {
  let before;
  try { before = exactUpdaterLstat(fsImpl, file); }
  catch (error) {
    if (error && error.code === 'ENOENT') return null;
    throw updateFileFailure('update configuration could not be inspected', error);
  }
  if (!stableUpdaterFile(before) || before.size > BigInt(maxBytes)) {
    throw updateFileFailure('update configuration path is not a bounded private regular file');
  }
  return before;
}

function readUpdaterSnapshot(file, before, fsImpl, maxBytes) {
  const output = Buffer.alloc(Math.min(maxBytes + 1, Number(before.size) + 1));
  const noFollow = fs.constants.O_NOFOLLOW || 0;
  let descriptor;
  try {
    descriptor = fsImpl.openSync(file, fs.constants.O_RDONLY | noFollow);
    const opened = exactUpdaterFstat(fsImpl, descriptor);
    if (!sameUpdaterSnapshot(before, opened)) {
      throw updateFileFailure('update configuration changed while opening');
    }
    let offset = 0;
    while (offset < output.length) {
      const count = fsImpl.readSync(descriptor, output, offset, output.length - offset, null);
      if (!count) break;
      offset += count;
    }
    const after = exactUpdaterFstat(fsImpl, descriptor);
    const pathAfter = exactUpdaterLstat(fsImpl, file);
    if (offset > maxBytes || BigInt(offset) !== opened.size
        || !sameUpdaterSnapshot(opened, after) || !sameUpdaterSnapshot(after, pathAfter)) {
      throw updateFileFailure('update configuration changed while reading');
    }
    return output.subarray(0, offset);
  } catch (error) {
    if (error && error.code === 'UPDATE_CONFIG_FILE_INVALID') throw error;
    throw updateFileFailure('update configuration could not be read', error);
  } finally {
    if (descriptor !== undefined) try { fsImpl.closeSync(descriptor); } catch {}
  }
}

function updaterFileSnapshot(file, opts = {}) {
  const fsImpl = opts.fs || fs;
  const maxBytes = opts.maxBytes || MAX_UPDATE_CONFIG_BYTES;
  const before = inspectUpdaterFile(file, fsImpl, maxBytes);
  if (!before) return { exists: false };
  const contents = readUpdaterSnapshot(file, before, fsImpl, maxBytes);
  const after = inspectUpdaterFile(file, fsImpl, maxBytes);
  if (!after || !sameUpdaterSnapshot(before, after)) {
    throw updateFileFailure('update configuration changed after reading');
  }
  return {
    exists: true,
    contents,
    mode: Number(before.mode & 0o777n),
    identity: after,
  };
}

function fileSnapshot(file, opts = {}) {
  return updaterFileSnapshot(file, { ...opts, maxBytes: MAX_UPDATE_CONFIG_BYTES });
}

function updateRollbackFailure(message, cause, details = {}) {
  const error = publicFailure('update configuration audit failed and the prior file could not be restored', 500);
  error.message = message;
  error.code = 'UPDATE_CONFIG_ROLLBACK_FAILED';
  error.cause = cause;
  Object.assign(error, details);
  return error;
}

function sameUpdaterCandidate(left, right) {
  return !!left?.exists && !!right?.exists
    && stableUpdaterFile(left.identity) && stableUpdaterFile(right.identity)
    && left.identity.dev === right.identity.dev && left.identity.ino === right.identity.ino
    && Buffer.isBuffer(left.contents) && Buffer.isBuffer(right.contents)
    && left.contents.equals(right.contents);
}

function linkedUpdaterStat(target, expectedLinks, fsImpl) {
  const stat = exactUpdaterLstat(fsImpl, target);
  if (!stableUpdaterFile(stat, BigInt(expectedLinks))) {
    throw new Error('retained updater artifact has no stable identity');
  }
  return stat;
}

function sameLinkedUpdater(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size
    && sameUpdaterStatTime(left, right, 'mtime');
}

function removeExactUpdaterArtifact(target, expected, opts = {}) {
  const fsImpl = opts.fs || fs;
  try {
    privatePaths.removeExactPublicationFile(target, expected, { ...opts, fs: fsImpl });
  } catch (error) {
    if (!error.retainedPath && !error.additionalRetainedPath && !error.removedPath) {
      try { exactUpdaterLstat(fsImpl, target); error.retainedPath = target; }
      catch (inspectError) {
        if (inspectError && inspectError.code === 'ENOENT') error.removedPath = target;
      }
    }
    throw error;
  }
}

function restoreFileSnapshot(file, snapshot, opts = {}) {
  const fsImpl = opts.fs || fs;
  if (snapshot.exists) {
    return writeFileAtomic(file, snapshot.contents, {
      ...opts,
      mode: snapshot.mode,
      exclusive: true,
      randomBytes: crypto.randomBytes,
    });
  }
  const current = inspectUpdaterFile(file, fsImpl, MAX_UPDATE_CONFIG_BYTES);
  if (current) {
    const error = updateFileFailure('a replacement update configuration appeared during rollback');
    error.replacementPath = file;
    throw error;
  }
  return null;
}

function restoreChangedUpdaterFile(quarantine, file, opts, originalError) {
  const fsImpl = opts.fs || fs;
  const guard = `${quarantine}.restore.${process.pid}.${crypto.randomBytes(12).toString('hex')}`;
  let quarantinePresent = true;
  let guardPresent = false;
  try {
    const source = updaterFileSnapshot(quarantine, {
      ...opts,
      fs: fsImpl,
      maxBytes: MAX_UPDATER_FILE_BYTES,
    });
    if (!source.exists) throw new Error('changed updater replacement is unavailable');
    fsImpl.linkSync(quarantine, file);
    fsImpl.linkSync(quarantine, guard);
    guardPresent = true;
    let restored = linkedUpdaterStat(file, 3, fsImpl);
    let retained = linkedUpdaterStat(guard, 3, fsImpl);
    const sourceLink = linkedUpdaterStat(quarantine, 3, fsImpl);
    if (!sameLinkedUpdater(source.identity, restored) || !sameLinkedUpdater(source.identity, retained)
        || !sameLinkedUpdater(source.identity, sourceLink)) {
      throw new Error('changed updater replacement could not be identity-bound');
    }
    removeExactUpdaterArtifact(quarantine, sourceLink, opts);
    quarantinePresent = false;
    restored = linkedUpdaterStat(file, 2, fsImpl);
    retained = linkedUpdaterStat(guard, 2, fsImpl);
    if (!sameLinkedUpdater(source.identity, restored) || !sameLinkedUpdater(source.identity, retained)) {
      throw new Error('changed updater replacement changed during restoration');
    }
    removeExactUpdaterArtifact(guard, retained, opts);
    guardPresent = false;
    restored = linkedUpdaterStat(file, 1, fsImpl);
    if (!sameLinkedUpdater(source.identity, restored)) {
      throw new Error('changed updater replacement changed after restoration');
    }
  } catch (error) {
    throw updateRollbackFailure('changed updater replacement was retained for recovery', originalError || error, {
      ...(error.retainedPath
        ? { retainedPath: error.retainedPath }
        : (quarantinePresent ? { retainedPath: quarantine } : {})),
      ...(error.additionalRetainedPath
        ? { additionalRetainedPath: error.additionalRetainedPath }
        : (guardPresent ? { additionalRetainedPath: guard } : {})),
      ...(error.removedPath ? { removedPath: error.removedPath } : {}),
      replacementPath: file,
    });
  }
  throw updateRollbackFailure('update configuration changed during rollback; replacement was preserved', originalError, {
    replacementPath: file,
  });
}

function cleanupUpdaterCandidate(quarantine, candidate, opts, originalError) {
  const fsImpl = opts.fs || fs;
  const guard = `${quarantine}.cleanup.${process.pid}.${crypto.randomBytes(12).toString('hex')}`;
  let quarantinePresent = true;
  let guardPresent = false;
  try {
    fsImpl.linkSync(quarantine, guard);
    guardPresent = true;
    const source = linkedUpdaterStat(quarantine, 2, fsImpl);
    const retained = linkedUpdaterStat(guard, 2, fsImpl);
    if (!sameLinkedUpdater(candidate.identity, source) || !sameLinkedUpdater(candidate.identity, retained)) {
      throw new Error('updater cleanup guard changed');
    }
    removeExactUpdaterArtifact(quarantine, source, opts);
    quarantinePresent = false;
    const exact = updaterFileSnapshot(guard, {
      ...opts,
      fs: fsImpl,
      maxBytes: MAX_UPDATER_FILE_BYTES,
    });
    if (!sameUpdaterCandidate(candidate, exact)) {
      throw new Error('updater cleanup guard changed after quarantine removal');
    }
    removeExactUpdaterArtifact(guard, exact.identity, opts);
    guardPresent = false;
  } catch (error) {
    throw updateRollbackFailure('updater candidate quarantine could not be removed', originalError || error, {
      ...(error.retainedPath
        ? { retainedPath: error.retainedPath }
        : (quarantinePresent ? { retainedPath: quarantine } : {})),
      ...(error.additionalRetainedPath
        ? { additionalRetainedPath: error.additionalRetainedPath }
        : (guardPresent ? { additionalRetainedPath: guard } : {})),
      ...(error.removedPath ? { removedPath: error.removedPath } : {}),
    });
  }
}

function rollbackUpdaterCandidate(file, before, candidate, opts, originalError) {
  const fsImpl = opts.fs || fs;
  const quarantine = `${file}.failed-mutation.${process.pid}.${crypto.randomBytes(12).toString('hex')}`;
  try { fsImpl.renameSync(file, quarantine); }
  catch (error) {
    throw updateRollbackFailure('updater rollback could not quarantine the published candidate', originalError || error);
  }
  let quarantined;
  try {
    quarantined = updaterFileSnapshot(quarantine, {
      ...opts,
      fs: fsImpl,
      maxBytes: MAX_UPDATER_FILE_BYTES,
    });
  } catch (error) {
    throw updateRollbackFailure('updater rollback retained an unverifiable replacement', originalError || error, {
      retainedPath: quarantine,
    });
  }
  if (!sameUpdaterCandidate(candidate, quarantined)) {
    restoreChangedUpdaterFile(quarantine, file, opts, originalError);
  }
  try { restoreFileSnapshot(file, before, opts); }
  catch (error) {
    throw updateRollbackFailure('prior update configuration could not be restored', originalError || error, {
      retainedPath: quarantine,
      ...(error.replacementPath ? { replacementPath: error.replacementPath } : {}),
    });
  }
  let exact;
  try {
    exact = updaterFileSnapshot(quarantine, {
      ...opts,
      fs: fsImpl,
      maxBytes: MAX_UPDATER_FILE_BYTES,
    });
  } catch (error) {
    throw updateRollbackFailure('updater candidate quarantine could not be reverified', originalError || error, {
      retainedPath: quarantine,
    });
  }
  if (!sameUpdaterCandidate(candidate, exact)) {
    throw updateRollbackFailure('updater candidate quarantine changed before cleanup', originalError, {
      retainedPath: quarantine,
    });
  }
  cleanupUpdaterCandidate(quarantine, candidate, opts, originalError);
}

function normalizeConfig(input = {}) {
  const installMode = ['npm-ci-omit-dev', 'npm-ci', 'skip'].includes(input.installMode)
    ? input.installMode
    : DEFAULT_CONFIG.installMode;
  return {
    remoteName: String(input.remoteName || DEFAULT_CONFIG.remoteName).trim(),
    branch: String(input.branch || DEFAULT_CONFIG.branch).trim(),
    installMode,
    restartCommand: String(input.restartCommand || '').trim(),
    restartAfterUpdate: input.restartAfterUpdate === true,
  };
}

function loadConfig(opts = {}) {
  return normalizeConfig({ ...DEFAULT_CONFIG, ...(readJson(configPath(opts), {}) || {}) });
}

function publicConfig(config = loadConfig(), opts = {}) {
  return {
    remoteName: config.remoteName,
    branch: config.branch,
    installMode: config.installMode,
    restartCommand: config.restartCommand,
    restartAfterUpdate: config.restartAfterUpdate === true,
    restartEnabled: restartEnabled(),
    restartCommandSource: process.env.REDACTWALL_UPDATE_RESTART_COMMAND ? 'env' : (config.restartCommand ? 'config' : 'manual'),
    configPath: configPath(opts),
    backupDir: updateBackupDir(opts),
  };
}

function normalizedConfigForWrite(input = {}) {
  const config = normalizeConfig(input);
  validateConfig(config);
  return config;
}

function saveConfigUnlocked(input = {}, opts = {}) {
  const config = normalizedConfigForWrite(input);
  writeJson(configPath(opts), config, opts);
  return config;
}

function saveConfig(input = {}, opts = {}) {
  const file = configPath(opts);
  return fileMutationLock.withFileMutationLockSync(file, () => saveConfigUnlocked(input, opts), {
    ...opts,
    cleanupComponent: 'updater-config-lock',
  });
}

async function saveConfigWithAudit(input = {}, appendAudit, opts = {}) {
  if (typeof appendAudit !== 'function') throw publicFailure('update configuration audit callback is required', 500);
  const file = configPath(opts);
  const config = normalizedConfigForWrite(input);
  return fileMutationLock.withFileMutationLock(file, async () => {
    const before = fileSnapshot(file, opts);
    const candidate = writeJson(file, config, opts);
    try {
      await appendAudit(config);
      return config;
    } catch (auditError) {
      try {
        rollbackUpdaterCandidate(file, before, candidate, opts, auditError);
      } catch (rollbackError) {
        if (rollbackError && rollbackError.code === 'UPDATE_CONFIG_ROLLBACK_FAILED') {
          rollbackError.originalCause = auditError;
          throw rollbackError;
        }
        throw updateRollbackFailure('update configuration rollback failed after audit failure', auditError, {
          rollbackCause: rollbackError,
        });
      }
      const failure = publicFailure('update configuration could not be audited', 500);
      failure.cause = auditError;
      throw failure;
    }
  }, { ...opts, cleanupComponent: 'updater-config-lock' });
}

function validateConfig(config) {
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/.test(config.remoteName)) {
    throw publicFailure('invalid remote name');
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$/.test(config.branch)
    || config.branch.startsWith('-')
    || config.branch.includes('..')
    || config.branch.includes('//')
    || config.branch.endsWith('/')
    || config.branch.endsWith('.')
    || config.branch.endsWith('.lock')) {
    throw publicFailure('invalid branch name');
  }
  if (config.restartCommand && !SAFE_RESTART_COMMAND.test(config.restartCommand)) {
    throw publicFailure('restart command contains unsupported characters');
  }
  return config;
}

function publicFailure(message, statusCode = 400) {
  const err = new Error(message);
  err.publicMessage = message;
  err.statusCode = statusCode;
  return err;
}

function trimOutput(value) {
  const text = String(value || '').trim();
  if (text.length <= 6000) return text;
  return `${text.slice(0, 3000)}\n...\n${text.slice(-3000)}`;
}

function runCommand(file, args = [], opts = {}) {
  return new Promise((resolve, reject) => {
    execFile(file, args, {
      cwd: opts.cwd || ROOT,
      env: opts.env || process.env,
      windowsHide: true,
      timeout: opts.timeoutMs || COMMAND_TIMEOUT_MS,
      maxBuffer: opts.maxBuffer || MAX_BUFFER,
    }, (err, stdout, stderr) => {
      const result = {
        file,
        args,
        code: err ? (typeof err.code === 'number' ? err.code : 1) : 0,
        stdout: trimOutput(stdout),
        stderr: trimOutput(stderr),
      };
      const allowed = opts.allowExitCodes || [0];
      if (err && !allowed.includes(result.code)) {
        err.result = result;
        err.publicMessage = opts.publicError || commandFailureMessage(file, args);
        return reject(err);
      }
      return resolve(result);
    });
  });
}

function commandFailureMessage(file, args = []) {
  const action = file === 'git' ? `git ${args[0] || 'command'}` : path.basename(file);
  return `${action} failed`;
}

function isolatedGitEnvironment(environment = process.env) {
  const env = { ...environment };
  for (const variable of GIT_LOCAL_ENVIRONMENT_VARIABLES) delete env[variable];
  return env;
}

async function git(args, opts = {}) {
  const result = await runCommand('git', args, {
    ...opts,
    cwd: opts.repoRoot || opts.cwd || ROOT,
    env: isolatedGitEnvironment(opts.env),
    publicError: opts.publicError || `git ${args[0] || 'command'} failed`,
  });
  return result.stdout;
}

function npmExecutable() {
  return process.platform === 'win32' ? 'npm.cmd' : 'npm';
}

async function runInstall(config, opts = {}) {
  if (config.installMode === 'skip') {
    return { skipped: true, command: 'skip' };
  }
  const args = config.installMode === 'npm-ci' ? ['ci'] : ['ci', '--omit=dev'];
  const npm = opts.npmExecutable || npmExecutable();
  const exec = opts.runCommand || runCommand;
  await exec(npm, args, {
    cwd: opts.repoRoot || ROOT,
    timeoutMs: UPDATE_TIMEOUT_MS,
    maxBuffer: 1024 * 1024,
    publicError: 'dependency install failed',
  });
  return { skipped: false, command: [npm, ...args].join(' ') };
}

function parseStatus(output) {
  return String(output || '')
    .split(/\r?\n/)
    .map((line) => line.trimEnd())
    .filter(Boolean)
    .map((line) => ({
      status: line.slice(0, 2).trim(),
      path: line.slice(3).trim(),
    }));
}

function redactRemoteUrl(remoteUrl) {
  const text = String(remoteUrl || '').trim();
  if (!text) return '';
  try {
    const parsed = new URL(text);
    parsed.username = parsed.username ? 'redacted' : '';
    parsed.password = '';
    return parsed.toString();
  } catch {
    return text.replace(/\/\/[^/@]+@/, '//redacted@');
  }
}

function redactCommandText(value) {
  return String(value || '')
    .replace(/https:\/\/[^/\s@]+@github\.com/gi, 'https://redacted@github.com')
    .replace(/\/\/[^/\s@]+@/g, '//redacted@');
}

function githubRemoteInfo(remoteUrl) {
  const text = String(remoteUrl || '').trim();
  let match = text.match(/^https:\/\/github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?\/?$/i);
  if (match) return { ok: true, host: 'github.com', owner: match[1], repo: match[2] };
  match = text.match(/^git@github\.com:([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?$/i);
  if (match) return { ok: true, host: 'github.com', owner: match[1], repo: match[2] };
  match = text.match(/^ssh:\/\/git@github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?\/?$/i);
  if (match) return { ok: true, host: 'github.com', owner: match[1], repo: match[2] };
  return { ok: false, host: '' };
}

async function repoInfo(opts = {}) {
  const repoRoot = opts.repoRoot || ROOT;
  const config = normalizeConfig(opts.config || loadConfig(opts));
  const root = await git(['rev-parse', '--show-toplevel'], { repoRoot });
  const branch = await git(['rev-parse', '--abbrev-ref', 'HEAD'], { repoRoot });
  const head = await git(['rev-parse', 'HEAD'], { repoRoot });
  const remoteUrl = await git(['remote', 'get-url', config.remoteName], {
    repoRoot,
    publicError: 'configured Git remote not found',
  });
  const statusOutput = await git(['status', '--porcelain', '--untracked-files=all'], { repoRoot });
  const github = githubRemoteInfo(remoteUrl);
  return {
    root,
    branch,
    head,
    shortHead: head.slice(0, 12),
    remoteName: config.remoteName,
    remoteUrl: redactRemoteUrl(remoteUrl),
    remoteIsGithub: github.ok,
    remoteHost: github.host,
    remoteOwner: github.owner || '',
    remoteRepo: github.repo || '',
    dirtyFiles: parseStatus(statusOutput),
  };
}

function assertGithubRemote(info, opts = {}) {
  if (opts.allowLocalRemote) return;
  if (!info.remoteIsGithub) {
    throw publicFailure('updates require an existing GitHub remote');
  }
}

function assertConfiguredBranch(info, config) {
  if (info.branch !== config.branch) {
    throw publicFailure(`checked-out branch ${info.branch} does not match configured update branch ${config.branch}`, 409);
  }
}

function assertCleanWorktree(info) {
  if (info.dirtyFiles.length) {
    const sample = info.dirtyFiles.slice(0, 6).map((item) => item.path).join(', ');
    throw publicFailure(`source tree has local changes; commit or remove them before updating (${sample})`, 409);
  }
}

async function checkForUpdates(opts = {}) {
  const config = validateConfig(normalizeConfig(opts.config || loadConfig(opts)));
  const info = await repoInfo({ ...opts, config });
  assertGithubRemote(info, opts);
  assertConfiguredBranch(info, config);
  await git(['fetch', '--prune', config.remoteName, config.branch], {
    ...opts,
    publicError: 'GitHub fetch failed',
  });
  const remoteRef = `${config.remoteName}/${config.branch}`;
  const latest = await git(['rev-parse', remoteRef], {
    ...opts,
    publicError: 'remote branch not found after fetch',
  });
  const local = await git(['rev-parse', 'HEAD'], opts);
  const ahead = Number(await git(['rev-list', '--count', `${remoteRef}..HEAD`], opts)) || 0;
  const behind = Number(await git(['rev-list', '--count', `HEAD..${remoteRef}`], opts)) || 0;
  const ancestor = await runCommand('git', ['merge-base', '--is-ancestor', 'HEAD', remoteRef], {
    cwd: opts.repoRoot || ROOT,
    env: isolatedGitEnvironment(opts.env),
    allowExitCodes: [0, 1],
    publicError: 'could not compare local and remote commits',
  });
  return {
    ok: true,
    checkedAt: new Date().toISOString(),
    updateAvailable: local !== latest && ancestor.code === 0,
    blocked: local !== latest && ancestor.code !== 0,
    blockedReason: local !== latest && ancestor.code !== 0 ? 'local branch is not a fast-forward of the GitHub branch' : '',
    currentCommit: local,
    currentShortCommit: local.slice(0, 12),
    latestCommit: latest,
    latestShortCommit: latest.slice(0, 12),
    ahead,
    behind,
    remoteRef,
    repo: { ...info, dirty: info.dirtyFiles.length > 0 },
    config: publicConfig(config, opts),
  };
}

async function createBackup(config, opts = {}) {
  if (opts.createBackup) return opts.createBackup({ outDir: updateBackupDir(opts), config });
  const store = opts.backupStore || backupStore;
  return store.createBackup({ outDir: updateBackupDir(opts), dbModule: activeDb(opts) });
}

function writeState(patch, opts = {}) {
  const next = {
    ...(readJson(statePath(opts), {}) || {}),
    ...patch,
    updatedAt: new Date().toISOString(),
  };
  writeJson(statePath(opts), next, opts);
  return next;
}

async function applyUpdate(opts = {}) {
  if (activeRun) throw publicFailure('an update is already running', 409);
  if (opts.confirmBackup !== true) throw publicFailure('backup confirmation is required');
  activeRun = runApplyUpdate(opts);
  try {
    return await activeRun;
  } finally {
    activeRun = null;
  }
}

async function runApplyUpdate(opts = {}) {
  const startedAt = new Date().toISOString();
  const config = validateConfig(normalizeConfig(opts.config || loadConfig(opts)));
  writeState({ status: 'running', stage: 'checking', startedAt, error: '' }, opts);
  try {
    const check = await checkForUpdates({ ...opts, config });
    assertCleanWorktree(check.repo);
    if (check.blocked) throw publicFailure(check.blockedReason, 409);
    if (!check.updateAvailable) {
      const state = writeState({
        status: 'up-to-date',
        stage: 'complete',
        startedAt,
        completedAt: new Date().toISOString(),
        fromCommit: check.currentCommit,
        toCommit: check.latestCommit,
        restartRequired: false,
      }, opts);
      return { ok: true, updated: false, check, state };
    }

    writeState({ status: 'running', stage: 'backup', startedAt }, opts);
    const backup = await createBackup(config, opts);

    writeState({ status: 'running', stage: 'fast-forward', startedAt, backup: backupSummary(backup) }, opts);
    await git(['merge', '--ff-only', `${config.remoteName}/${config.branch}`], {
      ...opts,
      publicError: 'fast-forward update failed',
    });
    const updatedHead = await git(['rev-parse', 'HEAD'], opts);

    writeState({ status: 'running', stage: 'install', startedAt, toCommit: updatedHead }, opts);
    const install = await runInstall(config, opts);
    const restartRequired = true;
    const state = writeState({
      status: 'updated',
      stage: 'complete',
      startedAt,
      completedAt: new Date().toISOString(),
      fromCommit: check.currentCommit,
      toCommit: updatedHead,
      backup: backupSummary(backup),
      install,
      restartRequired,
      autoRestartRequested: config.restartAfterUpdate === true,
    }, opts);

    if (config.restartAfterUpdate === true && restartEnabled() && effectiveRestartCommand(config)) {
      scheduleRestart(config, opts);
      return { ok: true, updated: true, check, backup: backupSummary(backup), install, state, restartScheduled: true };
    }

    return { ok: true, updated: true, check, backup: backupSummary(backup), install, state, restartScheduled: false };
  } catch (err) {
    writeState({
      status: 'failed',
      stage: 'failed',
      startedAt,
      completedAt: new Date().toISOString(),
      error: publicError(err),
    }, opts);
    throw err;
  }
}

function backupSummary(backup = {}) {
  return {
    ok: backup.ok !== false,
    file: backup.file || '',
    manifestFile: backup.manifestFile || '',
    bytes: backup.bytes || backup.backupBytes || 0,
    backupSha256: backup.backupSha256 || '',
    auditIntegrity: backup.auditIntegrity || (backup.manifest && backup.manifest.backupIntegrity) || null,
  };
}

function parseRestartCommand(command) {
  const text = String(command || '').trim();
  if (!text) throw publicFailure('restart command is not configured');
  if (!SAFE_RESTART_COMMAND.test(text)) throw publicFailure('restart command contains unsupported characters');
  const parts = text.split(/\s+/).filter(Boolean);
  if (!parts.length) throw publicFailure('restart command is not configured');
  return { file: parts[0], args: parts.slice(1) };
}

function restartEnabled() {
  return ['1', 'true', 'yes', 'on'].includes(String(process.env.REDACTWALL_UPDATE_RESTART_ENABLED || '').toLowerCase());
}

function effectiveRestartCommand(config = {}) {
  return String(process.env.REDACTWALL_UPDATE_RESTART_COMMAND || config.restartCommand || '').trim();
}

function scheduleRestart(config = loadConfig(), opts = {}) {
  if (!restartEnabled()) {
    throw publicFailure('backend restart command execution is disabled on this host', 403);
  }
  const parsed = parseRestartCommand(effectiveRestartCommand(config));
  const state = writeState({ status: 'restart-scheduled', restartRequired: true, restartScheduledAt: new Date().toISOString() }, opts);
  setTimeout(() => {
    runCommand(parsed.file, parsed.args, {
      cwd: opts.repoRoot || ROOT,
      timeoutMs: 60 * 1000,
      publicError: 'restart command failed',
    })
      .then(() => writeState({ status: 'restart-command-ran', restartRequired: false }, opts))
      .catch((err) => writeState({ status: 'restart-failed', restartRequired: true, error: publicError(err) }, opts));
  }, opts.restartDelayMs || 500).unref();
  return { ok: true, scheduled: true, state };
}

// Full audit-chain verification re-hashes every audit row (plus a per-queryId
// content-hash SELECT), so status() — polled by the console Updates view — must
// not run it inline on every request. Cache the result for a short TTL, keyed by
// the db handle so tests with a mock db aren't served a stale snapshot.
let _auditCache = { db: null, at: 0, result: null };
const AUDIT_CACHE_TTL_MS = 30 * 1000;
function auditIntegritySnapshot(db) {
  const now = Date.now();
  if (_auditCache.db === db && now - _auditCache.at < AUDIT_CACHE_TTL_MS) return _auditCache.result;
  const result = db.verifyAuditChain();
  _auditCache = { db, at: now, result };
  return result;
}

async function status(opts = {}) {
  const config = loadConfig(opts);
  const db = activeDb(opts);
  let info = null;
  let repoError = '';
  try {
    info = await repoInfo({ ...opts, config });
    if (!opts.allowLocalRemote) assertGithubRemote(info, opts);
  } catch (err) {
    repoError = publicError(err);
  }
  return {
    ok: !repoError,
    inProgress: !!activeRun,
    now: new Date().toISOString(),
    config: publicConfig(config, opts),
    repo: info ? { ...info, dirty: info.dirtyFiles.length > 0 } : null,
    safety: {
      dataRoot: dataRoot(opts),
      databasePath: db._dbPath || '',
      backupDir: updateBackupDir(opts),
      auditIntegrity: auditIntegritySnapshot(db),
      sourceTreeClean: info ? info.dirtyFiles.length === 0 : false,
      configuredBranch: info ? info.branch === config.branch : false,
      githubRemote: info ? info.remoteIsGithub : false,
    },
    lastRun: readJson(statePath(opts), null),
    error: repoError,
  };
}

function publicError(err) {
  if (!err) return 'unknown error';
  if (err.publicMessage) return String(err.publicMessage);
  if (err.result && err.result.stderr) return redactCommandText(err.result.stderr).split(/\r?\n/).slice(-2).join(' ').slice(0, 300);
  return redactCommandText(err.message || err).slice(0, 300);
}

module.exports = {
  DEFAULT_CONFIG,
  loadConfig,
  publicConfig,
  saveConfig,
  saveConfigWithAudit,
  status,
  checkForUpdates,
  applyUpdate,
  scheduleRestart,
  repoInfo,
  publicError,
  _internal: {
    githubRemoteInfo,
    normalizeConfig,
    npmExecutable,
    parseRestartCommand,
    redactCommandText,
    redactRemoteUrl,
    runInstall,
    createBackup,
    runCommand,
    writeJson,
  },
};
