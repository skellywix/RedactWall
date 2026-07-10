'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');

const auditAnchor = require('../server/audit-anchor');
const auditIntegrity = require('../server/audit-integrity');
const privatePaths = require('../server/private-path');
const fileMutationLock = require('../server/file-mutation-lock');

const WORKER_COUNT = 12;

function tempRoot(t, label) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `redactwall-${label}-`));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}

function wait(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function waitForReady(directory, count) {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    const ready = fs.readdirSync(directory).filter((name) => name.startsWith('ready-')).length;
    if (ready === count) return;
    await wait(20);
  }
  throw new Error(`only ${fs.readdirSync(directory).filter((name) => name.startsWith('ready-')).length}/${count} audit workers became ready`);
}

function runStressWorker(environment) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [path.join(__dirname, 'support', 'audit-anchor-worker.js')], {
      cwd: path.join(__dirname, '..'),
      env: { ...process.env, ...environment },
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.once('error', reject);
    child.once('exit', (code) => resolve({ code, stdout: stdout.trim(), stderr: stderr.trim() }));
  });
}

function exactAcl(target, principal) {
  let inheritance = '';
  try { inheritance = fs.lstatSync(target).isDirectory() ? '(OI)(CI)' : ''; } catch {}
  return [
    `${target} ${principal}:${inheritance}(F)`,
    `          NT AUTHORITY\\SYSTEM:${inheritance}(F)`,
    'Successfully processed 1 files',
  ].join('\r\n');
}

function aclHarness(options) {
  const secured = new Set();
  const principal = options.principal;
  const normalize = (target) => path.resolve(target).toLowerCase();
  const inherited = (target) => options.inheritFrom
    && normalize(target).startsWith(`${normalize(options.inheritFrom)}${path.sep}`)
    && secured.has(normalize(options.inheritFrom));
  return function spawnIcacls(command, args) {
    assert.strictEqual(command, 'icacls.exe');
    const target = path.resolve(args[0]);
    if (args.length === 1) {
      if (typeof options.onInspect === 'function') options.onInspect(target);
      const exact = exactAcl(target, principal);
      const trusted = secured.has(normalize(target)) || inherited(target);
      return {
        status: 0,
        stdout: trusted ? exact : exact.replace(
          'Successfully processed 1 files',
          '          BUILTIN\\Users:(RX)\r\nSuccessfully processed 1 files',
        ),
      };
    }
    if (args.includes('/grant:r')) {
      secured.add(normalize(target));
      if (typeof options.onGrant === 'function') options.onGrant(target);
    }
    return { status: 0, stdout: 'Successfully processed 1 files' };
  };
}

test('twelve fresh processes serialize Windows audit-directory ACL hardening', { timeout: 120_000 }, async (t) => {
  const root = tempRoot(t, 'audit-anchor-acl-stress');
  const directory = path.join(root, 'audit');
  const privateLockRoot = path.join(root, 'locks');
  const coordination = path.join(root, 'coordination');
  fs.mkdirSync(coordination);
  const workers = Array.from({ length: WORKER_COUNT }, (_, index) => runStressWorker({
    AUDIT_DIRECTORY: directory,
    PRIVATE_LOCK_ROOT: privateLockRoot,
    COORDINATION_DIRECTORY: coordination,
    WORKER_ID: String(index),
  }));
  await waitForReady(coordination, WORKER_COUNT);
  fs.writeFileSync(path.join(coordination, 'go'), 'go');
  const results = await Promise.all(workers);
  assert.deepStrictEqual(
    results.map(({ code }) => code),
    Array(WORKER_COUNT).fill(0),
    results.filter(({ code }) => code !== 0).map(({ stderr }) => stderr).join('\n'),
  );
  assert.strictEqual(new Set(results.map(({ stdout }) => stdout)).size, 1);
  assert.match(results[0].stdout, /^[a-f0-9]{64}$/);
});

test('audit-directory ACL hardening occurs only while its trusted bootstrap lock is held', (t) => {
  const root = tempRoot(t, 'audit-anchor-acl-lock');
  const directory = path.join(root, 'audit');
  const privateLockRoot = path.join(root, 'locks');
  const principal = 'TEST\\audit-owner';
  const security = { platform: 'win32', principal, privateLockRoot };
  const directoryLock = fileMutationLock.lockPathFor(
    privatePaths.privateDirectoryLockTarget(directory, security),
  );
  const checkpointPath = path.join(directory, '.audit-integrity-checkpoint.json');
  const checkpointLock = fileMutationLock.lockPathFor(checkpointPath);
  const lockEvidence = [];
  let initializeEvidence;
  const spawnIcacls = aclHarness({
    principal,
    onGrant(target) {
      if (path.resolve(target) === path.resolve(directory)) lockEvidence.push(fs.existsSync(directoryLock));
    },
  });
  auditAnchor.openAuditAnchor({
    directory,
    checkpointPath,
    allowBootstrap: true,
    env: {},
    privatePathSecurity: { ...security, spawn: spawnIcacls },
    initialize() {
      initializeEvidence = [fs.existsSync(directoryLock), fs.existsSync(checkpointLock)];
    },
  });
  assert.deepStrictEqual(lockEvidence, [true]);
  assert.deepStrictEqual(initializeEvidence, [true, true]);
});

test('audit-anchor initialization honors its full sixty-second lock budget', (t) => {
  const root = tempRoot(t, 'audit-anchor-lock-budget');
  const directory = path.join(root, 'audit');
  const checkpointPath = path.join(directory, '.audit-integrity-checkpoint.json');
  const principal = 'TEST\\audit-owner';
  const privatePathSecurity = {
    platform: 'win32',
    principal,
    privateLockRoot: path.join(root, 'locks'),
    spawn: aclHarness({ principal }),
  };
  auditAnchor.openAuditAnchor({
    directory,
    checkpointPath,
    allowBootstrap: true,
    env: {},
    privatePathSecurity,
  });
  const held = fileMutationLock.acquireFileMutationLockSync(checkpointPath);
  try {
    const auditTimes = [0, 30_000, auditAnchor._internal.INITIALIZATION_LOCK_TIMEOUT_MS];
    let auditTimeIndex = 0;
    let observedAuditTime = 0;
    assert.throws(() => auditAnchor.openAuditAnchor({
      directory,
      checkpointPath,
      allowBootstrap: true,
      env: {},
      privatePathSecurity,
      initializationLockTimeoutMs: auditAnchor._internal.INITIALIZATION_LOCK_TIMEOUT_MS,
      now: () => {
        observedAuditTime = auditTimes[Math.min(auditTimeIndex, auditTimes.length - 1)];
        auditTimeIndex += 1;
        return observedAuditTime;
      },
      sleep: () => {},
    }), (error) => error && error.code === 'FILE_MUTATION_LOCK_TIMEOUT');
    assert.strictEqual(observedAuditTime, auditAnchor._internal.INITIALIZATION_LOCK_TIMEOUT_MS);

    const routineTimes = [0, 30_000];
    let routineTimeIndex = 0;
    let observedRoutineTime = 0;
    assert.throws(() => fileMutationLock.acquireFileMutationLockSync(checkpointPath, {
      lockTimeoutMs: auditAnchor._internal.INITIALIZATION_LOCK_TIMEOUT_MS,
      now: () => {
        observedRoutineTime = routineTimes[Math.min(routineTimeIndex, routineTimes.length - 1)];
        routineTimeIndex += 1;
        return observedRoutineTime;
      },
      sleep: () => {},
    }), (error) => error && error.code === 'FILE_MUTATION_LOCK_TIMEOUT');
    assert.strictEqual(observedRoutineTime, 30_000, 'routine mutation locks retain their thirty-second ceiling');
  } finally {
    fileMutationLock.releaseFileMutationLock(held);
  }
});

test('later Windows checkpoint writes inspect but never re-harden the audit directory', (t) => {
  const root = tempRoot(t, 'audit-anchor-checkpoint-acl');
  const directory = path.join(root, 'audit');
  const principal = 'TEST\\audit-owner';
  let directoryGrants = 0;
  let directoryInspections = 0;
  const sameDirectory = (target) => path.resolve(target) === path.resolve(directory);
  const spawnIcacls = aclHarness({
    principal,
    onGrant(target) { if (sameDirectory(target)) directoryGrants += 1; },
    onInspect(target) { if (sameDirectory(target)) directoryInspections += 1; },
  });
  const anchor = auditAnchor.openAuditAnchor({
    directory,
    allowBootstrap: true,
    env: {},
    privatePathSecurity: {
      platform: 'win32',
      principal,
      privateLockRoot: path.join(root, 'locks'),
      spawn: spawnIcacls,
    },
  });
  directoryGrants = 0;
  directoryInspections = 0;
  const emptyDatabase = {
    prepare(sql) {
      if (sql === 'SELECT COUNT(*) n FROM audit') return { get: () => ({ n: 0 }) };
      return { all: () => [] };
    },
  };
  assert.deepStrictEqual(anchor.verifyDatabase(emptyDatabase), { ok: true, count: 0 });
  assert.strictEqual(directoryGrants, 0);
  assert.ok(directoryInspections >= 2, 'checkpoint and state publications both verify the directory ACL');
});

function auditDatabase(rows) {
  return {
    prepare(sql) {
      if (sql === 'SELECT COUNT(*) n FROM audit') {
        return { get: () => ({ n: rows.length }) };
      }
      if (sql === 'SELECT seq, entry FROM audit ORDER BY seq ASC') {
        return { all: () => rows.slice() };
      }
      if (sql === 'SELECT seq, entry FROM audit WHERE seq > ? ORDER BY seq ASC') {
        return { all: (seq) => rows.filter((row) => row.seq > seq) };
      }
      if (sql === 'SELECT seq, entry FROM audit WHERE seq = ?') {
        return { get: (seq) => rows.find((row) => row.seq === seq) };
      }
      if (sql === 'SELECT id FROM queries') return { all: () => [] };
      throw new Error(`unexpected audit test query: ${sql}`);
    },
  };
}

function failingCheckpointFs(checkpointPath, failure) {
  const checkpoint = path.resolve(checkpointPath);
  return new Proxy(fs, {
    get(target, property) {
      if (property === 'renameSync') {
        return (source, destination) => {
          if (failure.enabled && path.resolve(destination) === checkpoint) {
            const error = new Error('synthetic checkpoint publication denial');
            error.code = 'EACCES';
            throw error;
          }
          return target.renameSync(source, destination);
        };
      }
      const value = target[property];
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });
}

test('failed checkpoint publication freezes mutation, rejects tail truncation, and recovers only with the exact tail', (t) => {
  const root = tempRoot(t, 'audit-anchor-publication-failure');
  const directory = path.join(root, 'audit');
  const checkpointPath = path.join(directory, '.audit-integrity-checkpoint.json');
  const failure = { enabled: false };
  const rows = [];
  const database = auditDatabase(rows);
  const anchor = auditAnchor.openAuditAnchor({
    directory,
    checkpointPath,
    allowBootstrap: true,
    env: {},
    fs: failingCheckpointFs(checkpointPath, failure),
  });
  assert.deepStrictEqual(anchor.verifyDatabase(database), { ok: true, count: 0 });

  const entry = anchor.authenticate(auditIntegrity.ZERO, {
    id: 'a_committed_tail',
    ts: '2026-07-10T12:00:00.000Z',
    action: 'CHECKPOINT_FAILURE_TEST',
    queryId: '',
    actor: 'test',
    detail: 'sanitized',
  });
  rows.push({ seq: 1, entry: JSON.stringify(entry) });
  failure.enabled = true;
  assert.deepStrictEqual(anchor.advanceCheckpoint(database), {
    ok: false,
    count: 0,
    reason: 'checkpoint-unavailable',
  });
  assert.strictEqual(anchor.status().ok, false);

  rows.length = 0;
  failure.enabled = false;
  assert.throws(
    () => anchor.requireMutationReady(database),
    (error) => error && error.code === 'REDACTWALL_AUDIT_CHECKPOINT_UNHEALTHY'
      && error.integrity && error.integrity.reason === 'checkpoint-truncated',
  );
  assert.strictEqual(anchor.status().ok, false, 'the old durable checkpoint cannot bless a lost committed tail');

  rows.push({ seq: 1, entry: JSON.stringify(entry) });
  assert.deepStrictEqual(anchor.requireMutationReady(database), { ok: true, count: 1 });
  assert.strictEqual(anchor.status().ok, true);
  assert.strictEqual(JSON.parse(fs.readFileSync(checkpointPath, 'utf8')).head, entry.hash);
});

test('POSIX audit-anchor initialization creates owner-only durable state', {
  skip: process.platform === 'win32' && 'POSIX permissions are not meaningful on Windows',
}, (t) => {
  const root = tempRoot(t, 'audit-anchor-posix');
  const directory = path.join(root, 'audit');
  const anchor = auditAnchor.openAuditAnchor({ directory, allowBootstrap: true, env: {} });
  const emptyDatabase = {
    prepare(sql) {
      if (sql === 'SELECT COUNT(*) n FROM audit') return { get: () => ({ n: 0 }) };
      return { all: () => [] };
    },
  };
  assert.deepStrictEqual(anchor.verifyDatabase(emptyDatabase), { ok: true, count: 0 });
  assert.strictEqual(fs.statSync(directory).mode & 0o777, 0o700);
  assert.strictEqual(fs.statSync(anchor.paths.statePath).mode & 0o777, 0o600);
  assert.strictEqual(fs.statSync(anchor.paths.checkpointPath).mode & 0o777, 0o600);
});

test('mixed-case Windows audit path aliases acquire one bootstrap lock', {
  skip: process.platform !== 'win32' && 'Windows paths are case-insensitive',
}, (t) => {
  const root = tempRoot(t, 'audit-anchor-case-alias');
  const directory = path.join(root, 'audit');
  const statePath = path.join(root, 'AUDIT', '.audit-integrity-state.json');
  const checkpointPath = path.join(root, 'Audit', '.audit-integrity-checkpoint.json');
  const principal = 'TEST\\audit-owner';
  const privateLockRoot = path.join(root, 'locks');
  const spawnIcacls = aclHarness({ principal });
  assert.doesNotThrow(() => auditAnchor.openAuditAnchor({
    directory,
    statePath,
    checkpointPath,
    allowBootstrap: true,
    initializationLockTimeoutMs: 500,
    env: {},
    privatePathSecurity: {
      platform: 'win32',
      principal,
      privateLockRoot,
      spawn: spawnIcacls,
    },
  }));
});

test('audit anchor refuses authenticated state planted before Windows directory trust', (t) => {
  const root = tempRoot(t, 'audit-anchor-planted');
  const directory = path.join(root, 'audit');
  const privateLockRoot = path.join(root, 'locks');
  const statePath = path.join(directory, '.audit-integrity-state.json');
  const principal = 'TEST\\audit-owner';
  fs.mkdirSync(directory);
  fs.writeFileSync(statePath, JSON.stringify(auditAnchor._internal.signedState(Buffer.alloc(32, 7), false, true)));
  const before = fs.readFileSync(statePath);
  const spawnIcacls = aclHarness({ principal, inheritFrom: directory });
  assert.throws(() => auditAnchor.openAuditAnchor({
    directory,
    allowBootstrap: true,
    env: {},
    privatePathSecurity: {
      platform: 'win32',
      principal,
      privateLockRoot,
      spawn: spawnIcacls,
    },
  }), /before its permissions were trusted/);
  assert.deepStrictEqual(fs.readFileSync(statePath), before);
});

function crashDirectoryInitialization(directory) {
  const script = [
    "const privatePaths = require('./server/private-path');",
    'privatePaths.withPrivateDirectoryMutationLockSync(process.env.AUDIT_DIRECTORY, () => process.exit(17));',
  ].join('');
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['-e', script], {
      cwd: path.join(__dirname, '..'),
      env: { ...process.env, AUDIT_DIRECTORY: directory },
      stdio: ['ignore', 'ignore', 'pipe'],
      windowsHide: true,
    });
    let stderr = '';
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.once('error', reject);
    child.once('exit', (code) => code === 17 ? resolve() : reject(new Error(stderr || `crash worker exited ${code}`)));
  });
}

test('audit-anchor startup reclaims a crashed Windows directory-bootstrap lock', {
  timeout: 60_000,
  skip: process.platform !== 'win32' && 'POSIX initialization does not use the Windows bootstrap lock',
}, async (t) => {
  const root = tempRoot(t, 'audit-anchor-crash');
  const directory = path.join(root, 'audit');
  const bootstrapTarget = privatePaths.privateDirectoryLockTarget(directory);
  const lockPath = fileMutationLock.lockPathFor(bootstrapTarget);
  t.after(() => fs.rmSync(lockPath, { recursive: true, force: true }));
  await crashDirectoryInitialization(directory);
  assert.strictEqual(fs.existsSync(lockPath), true);
  auditAnchor.openAuditAnchor({ directory, allowBootstrap: true, env: {} });
  assert.strictEqual(fs.existsSync(lockPath), false);
});
