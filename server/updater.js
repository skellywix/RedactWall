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
const { execFile } = require('child_process');

const backupStore = require('../scripts/backup-store');

const ROOT = path.resolve(__dirname, '..');
const COMMAND_TIMEOUT_MS = 2 * 60 * 1000;
const UPDATE_TIMEOUT_MS = 8 * 60 * 1000;
const MAX_BUFFER = 512 * 1024;
const DEFAULT_CONFIG = {
  remoteName: 'origin',
  branch: 'main',
  installMode: 'npm-ci-omit-dev',
  restartCommand: '',
  restartAfterUpdate: false,
};
const SAFE_RESTART_COMMAND = /^[A-Za-z0-9 ._:/\\@+=,-]+$/;

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
  return path.dirname(db._dbPath || path.join(ROOT, 'data', 'redactwall.db'));
}

function configPath(opts = {}) {
  return process.env.REDACTWALL_UPDATE_CONFIG_PATH || path.join(dataRoot(opts), 'update-settings.json');
}

function statePath(opts = {}) {
  return process.env.REDACTWALL_UPDATE_STATE_PATH || path.join(dataRoot(opts), 'update-state.json');
}

function updateBackupDir(opts = {}) {
  return path.join(dataRoot(opts), 'backups', 'updates');
}

function ensureParent(file) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
}

function readJson(file, fallback = null) {
  try {
    if (!fs.existsSync(file)) return fallback;
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return fallback;
  }
}

function writeJson(file, value) {
  ensureParent(file);
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(value, null, 2));
  fs.renameSync(tmp, file);
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

function saveConfig(input = {}, opts = {}) {
  const config = normalizeConfig(input);
  validateConfig(config);
  writeJson(configPath(opts), config);
  return config;
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

async function git(args, opts = {}) {
  const result = await runCommand('git', args, {
    ...opts,
    cwd: opts.repoRoot || opts.cwd || ROOT,
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
  writeJson(statePath(opts), next);
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
      auditIntegrity: db.verifyAuditChain(),
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
  },
};
