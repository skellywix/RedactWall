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
const TEST_OWNER_IDENTITY = {
  processSid: 'S-1-5-21-1000-1000-1000-1001',
  ownerSid: 'S-1-5-21-1000-1000-1000-1001',
};
const TEST_OWNER_SID = 'S-1-5-21-100-200-300-1001';

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
    if (command === 'powershell.exe') {
      return { status: 0, stdout: `redactwall-owner-v1|${TEST_OWNER_SID}|${TEST_OWNER_SID}` };
    }
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
  const security = { platform: 'win32', principal, ownerIdentity: TEST_OWNER_IDENTITY, privateLockRoot };
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
    ownerIdentity: TEST_OWNER_IDENTITY,
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

test('audit transaction preparation uses the full routine lock budget', (t) => {
  const root = tempRoot(t, 'audit-anchor-transaction-lock-budget');
  const directory = path.join(root, 'audit');
  const checkpointPath = path.join(directory, '.audit-integrity-checkpoint.json');
  const clock = { simulated: false, index: 0, observed: 0 };
  const times = [0, 15_000, auditAnchor._internal.TRANSACTION_LOCK_TIMEOUT_MS];
  const anchor = auditAnchor.openAuditAnchor({
    directory,
    checkpointPath,
    allowBootstrap: true,
    env: {},
    now() {
      if (!clock.simulated) return Date.now();
      clock.observed = times[Math.min(clock.index, times.length - 1)];
      clock.index += 1;
      return clock.observed;
    },
    sleep() {},
  });
  const held = fileMutationLock.acquireFileMutationLockSync(checkpointPath);
  try {
    clock.simulated = true;
    assert.throws(
      () => anchor.prepareTransactionCommit({}, [{}]),
      (error) => error && error.code === 'FILE_MUTATION_LOCK_TIMEOUT',
    );
    assert.strictEqual(
      clock.observed,
      auditAnchor._internal.TRANSACTION_LOCK_TIMEOUT_MS,
      'pre-COMMIT checkpoint contention retains the routine thirty-second ceiling',
    );
    assert.strictEqual(anchor.status().ok, true, 'ordinary healthy lock contention is transient');
  } finally {
    fileMutationLock.releaseFileMutationLock(held);
  }
});

test('external audit coordination receives the full first-verification timeout budget', (t) => {
  const root = tempRoot(t, 'audit-anchor-external-lock-budget');
  const calls = [];
  const anchor = auditAnchor.openAuditAnchor({
    directory: path.join(root, 'audit'),
    allowBootstrap: true,
    env: {},
    withCoordinationLock(callback, options = {}) {
      calls.push({ ...options });
      return callback();
    },
  });
  const database = auditDatabase([]);

  assert.strictEqual(calls[0].timeoutMs, auditAnchor._internal.INITIALIZATION_LOCK_TIMEOUT_MS);
  assert.deepStrictEqual(anchor.verifyDatabase(database), { ok: true, count: 0 });
  assert.strictEqual(
    calls[1].timeoutMs,
    auditAnchor._internal.INITIALIZATION_LOCK_TIMEOUT_MS,
    'the first database verification keeps the initialization-only sixty-second budget',
  );
  assert.deepStrictEqual(anchor.verifyDatabase(database), { ok: true, count: 0 });
  assert.strictEqual(calls[2].timeoutMs, undefined, 'steady-state coordination uses the routine default');
});

test('checkpoint lock storage failure marks audit readiness unhealthy', (t) => {
  const root = tempRoot(t, 'audit-anchor-lock-storage-failure');
  const directory = path.join(root, 'audit');
  let denyCheckpointParent = false;
  const fsImpl = new Proxy(fs, {
    get(target, property) {
      if (property === 'mkdirSync') {
        return (targetPath, options) => {
          if (denyCheckpointParent && path.resolve(targetPath) === path.resolve(directory)) {
            const error = new Error('synthetic checkpoint parent denial');
            error.code = 'EACCES';
            throw error;
          }
          return target.mkdirSync(targetPath, options);
        };
      }
      const value = target[property];
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });
  const rows = [];
  const database = auditDatabase(rows);
  const anchor = auditAnchor.openAuditAnchor({ directory, allowBootstrap: true, env: {}, fs: fsImpl });
  assert.deepStrictEqual(anchor.verifyDatabase(database), { ok: true, count: 0 });
  const entry = anchor.authenticate(auditIntegrity.ZERO, {
    id: 'a_lock_storage_failure', ts: '2026-07-10T12:00:00.000Z',
    action: 'LOCK_STORAGE_TEST', queryId: '', actor: 'test', detail: 'sanitized',
  });
  rows.push({ seq: 1, entry: JSON.stringify(entry) });
  denyCheckpointParent = true;
  assert.throws(
    () => anchor.prepareTransactionCommit(database, [entry]),
    (error) => error && error.code === 'EACCES',
  );
  assert.strictEqual(anchor.status().ok, false);
  assert.strictEqual(anchor.status().reason, 'checkpoint-unavailable');
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
      ownerIdentity: TEST_OWNER_IDENTITY,
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
      if (sql === 'SELECT seq, entry FROM audit ORDER BY seq DESC LIMIT ?') {
        return { all: (limit) => rows.slice().sort((a, b) => b.seq - a.seq).slice(0, limit) };
      }
      if (sql === 'SELECT id FROM queries') return { all: () => [] };
      throw new Error(`unexpected audit test query: ${sql}`);
    },
  };
}

test('steady-state pending proof avoids redundant sidecar ACL subprocesses', (t) => {
  const root = tempRoot(t, 'audit-anchor-steady-acl');
  const directory = path.join(root, 'audit');
  const principal = 'TEST\\audit-owner';
  const calls = [];
  const harness = aclHarness({ principal, inheritFrom: directory });
  const spawn = (command, args, options) => {
    calls.push({ command, args: args.slice() });
    return harness(command, args, options);
  };
  const rows = [];
  const database = auditDatabase(rows);
  const anchor = auditAnchor.openAuditAnchor({
    directory,
    allowBootstrap: true,
    env: {},
    privatePathSecurity: {
      platform: 'win32',
      principal,
      ownerIdentity: TEST_OWNER_IDENTITY,
      privateLockRoot: path.join(root, 'locks'),
      spawn,
    },
  });
  assert.deepStrictEqual(anchor.verifyDatabase(database), { ok: true, count: 0 });
  calls.length = 0;
  const entry = anchor.authenticate(auditIntegrity.ZERO, {
    id: 'a_steady_acl',
    ts: '2026-07-10T12:00:00.000Z',
    action: 'STEADY_ACL_TEST',
    queryId: '',
    actor: 'test',
    detail: 'sanitized',
  });
  rows.push({ seq: 1, entry: JSON.stringify(entry) });
  anchor.prepareTransactionCommit(database, [entry]);

  assert.strictEqual(calls.length, 4, 'one parent check plus owner, inheritance, and temp DACL proof');
  assert.ok(calls.every(({ command }) => command === 'icacls.exe'));
  assert.deepStrictEqual(calls[0].args, [directory]);
  assert.ok(calls[1].args.includes('/setowner'));
  assert.ok(calls[2].args.includes('/inheritance:d'));
  assert.strictEqual(calls[3].args.length, 1, 'the protected temp DACL is inspected once');
  assert.ok(!calls.some(({ args }) => args.includes('/reset') || args.includes('/grant:r')));
  assert.ok(!calls.some(({ args }) => [anchor.paths.statePath, anchor.paths.checkpointPath]
    .includes(path.resolve(args[0]))), 'trusted HMAC reads do not respawn file ACL probes');

  anchor.transactionCommitted(database);
  assert.deepStrictEqual(anchor.advanceCheckpoint(database), { ok: true, count: 1 });
});

test('pending publication rejects a temp-to-destination identity substitution', (t) => {
  const root = tempRoot(t, 'audit-anchor-publish-identity');
  const directory = path.join(root, 'audit');
  const pendingPath = path.join(directory, '.audit-integrity-pending.json');
  let substituteIdentity = false;
  const fsImpl = new Proxy(fs, {
    get(target, property) {
      if (property === 'lstatSync') {
        return (file, options) => {
          const stat = target.lstatSync(file, options);
          if (!substituteIdentity || path.resolve(file) !== path.resolve(pendingPath)) return stat;
          const changed = Object.create(stat);
          const next = typeof stat.ino === 'bigint' ? stat.ino + 1n : stat.ino + 1;
          Object.defineProperty(changed, 'ino', { value: next });
          return changed;
        };
      }
      const value = target[property];
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });
  const rows = [];
  const database = auditDatabase(rows);
  const anchor = auditAnchor.openAuditAnchor({
    directory,
    pendingPath,
    allowBootstrap: true,
    env: {},
    fs: fsImpl,
  });
  assert.deepStrictEqual(anchor.verifyDatabase(database), { ok: true, count: 0 });
  const entry = anchor.authenticate(auditIntegrity.ZERO, {
    id: 'a_identity_swap',
    ts: '2026-07-10T12:00:00.000Z',
    action: 'IDENTITY_SWAP_TEST',
    queryId: '',
    actor: 'test',
    detail: 'sanitized',
  });
  rows.push({ seq: 1, entry: JSON.stringify(entry) });
  substituteIdentity = true;
  assert.throws(
    () => anchor.prepareTransactionCommit(database, [entry]),
    /changed during (?:linking|publication)/,
  );
  assert.strictEqual(fs.existsSync(pendingPath), false, 'failed first publication is rolled back');
});

test('pending publication fails closed when the filesystem exposes no stable file id', (t) => {
  const root = tempRoot(t, 'audit-anchor-zero-file-identity');
  const directory = path.join(root, 'audit');
  const pendingPath = path.join(directory, '.audit-integrity-pending.json');
  let zeroPendingTempIdentity = false;
  const fsImpl = new Proxy(fs, {
    get(target, property) {
      if (property === 'lstatSync') {
        return (file, options) => {
          const stat = target.lstatSync(file, options);
          if (!zeroPendingTempIdentity || !String(file).includes('.audit-integrity-pending.json.')
              || !String(file).endsWith('.tmp')) return stat;
          const changed = Object.create(stat);
          Object.defineProperty(changed, 'ino', { value: typeof stat.ino === 'bigint' ? 0n : 0 });
          return changed;
        };
      }
      const value = target[property];
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });
  const rows = [];
  const database = auditDatabase(rows);
  const anchor = auditAnchor.openAuditAnchor({ directory, pendingPath, allowBootstrap: true, env: {}, fs: fsImpl });
  assert.deepStrictEqual(anchor.verifyDatabase(database), { ok: true, count: 0 });
  const entry = anchor.authenticate(auditIntegrity.ZERO, {
    id: 'a_zero_file_id', ts: '2026-07-10T12:00:00.000Z',
    action: 'ZERO_FILE_ID_TEST', queryId: '', actor: 'test', detail: 'sanitized',
  });
  rows.push({ seq: 1, entry: JSON.stringify(entry) });
  zeroPendingTempIdentity = true;
  assert.throws(
    () => anchor.prepareTransactionCommit(database, [entry]),
    /audit integrity sidecar (?:has no stable filesystem identity|changed during Windows security verification)/,
  );
  assert.strictEqual(fs.existsSync(pendingPath), false);
});

test('pending publication rejects a verified sidecar directory identity swap', (t) => {
  const root = tempRoot(t, 'audit-anchor-directory-identity');
  const directory = path.join(root, 'audit');
  const pendingPath = path.join(directory, '.audit-integrity-pending.json');
  let substituteDirectoryIdentity = false;
  const fsImpl = new Proxy(fs, {
    get(target, property) {
      if (property === 'linkSync') {
        return (source, destination) => {
          const result = target.linkSync(source, destination);
          if (path.resolve(destination) === path.resolve(pendingPath)) {
            substituteDirectoryIdentity = true;
          }
          return result;
        };
      }
      if (property === 'lstatSync') {
        return (file, options) => {
          const stat = target.lstatSync(file, options);
          if (!substituteDirectoryIdentity || path.resolve(file) !== path.resolve(directory)) return stat;
          const changed = Object.create(stat);
          const next = typeof stat.ino === 'bigint' ? stat.ino + 1n : stat.ino + 1;
          Object.defineProperty(changed, 'ino', { value: next });
          return changed;
        };
      }
      const value = target[property];
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });
  const principal = 'TEST\\audit-owner';
  const rows = [];
  const database = auditDatabase(rows);
  const anchor = auditAnchor.openAuditAnchor({
    directory,
    pendingPath,
    allowBootstrap: true,
    env: {},
    fs: fsImpl,
    privatePathSecurity: {
      platform: 'win32',
      principal,
      ownerIdentity: TEST_OWNER_IDENTITY,
      privateLockRoot: path.join(root, 'locks'),
      spawn: aclHarness({ principal, inheritFrom: directory }),
    },
  });
  assert.deepStrictEqual(anchor.verifyDatabase(database), { ok: true, count: 0 });
  const entry = anchor.authenticate(auditIntegrity.ZERO, {
    id: 'a_directory_swap', ts: '2026-07-10T12:00:00.000Z',
    action: 'DIRECTORY_SWAP_TEST', queryId: '', actor: 'test', detail: 'sanitized',
  });
  rows.push({ seq: 1, entry: JSON.stringify(entry) });
  assert.throws(
    () => anchor.prepareTransactionCommit(database, [entry]),
    /audit integrity directory identity changed/,
  );
  assert.strictEqual(fs.existsSync(pendingPath), false, 'failed publication rolls back the pending witness');
  assert.strictEqual(anchor.status().ok, false);
});

test('final bound-directory verification remains inside exact pending rollback scope', (t) => {
  const root = tempRoot(t, 'audit-anchor-directory-rollback-scope');
  const directory = path.join(root, 'audit');
  const pendingPath = path.join(directory, '.audit-integrity-pending.json');
  let replacingPending = false;
  let postRenameDirectoryStats = 0;
  let pendingPublications = 0;
  const fsImpl = new Proxy(fs, {
    get(target, property) {
      if (property === 'linkSync') {
        return (source, destination) => {
          const publishesPending = path.resolve(destination) === path.resolve(pendingPath);
          const result = target.linkSync(source, destination);
          if (publishesPending && ++pendingPublications >= 2) replacingPending = true;
          return result;
        };
      }
      if (property === 'lstatSync') {
        return (file, options) => {
          const stat = target.lstatSync(file, options);
          if (!replacingPending || path.resolve(file) !== path.resolve(directory)) return stat;
          postRenameDirectoryStats += 1;
          if (postRenameDirectoryStats === 1) return stat;
          const changed = Object.create(stat);
          Object.defineProperty(changed, 'ino', {
            value: typeof stat.ino === 'bigint' ? stat.ino + 1n : stat.ino + 1,
          });
          return changed;
        };
      }
      const value = target[property];
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });
  const principal = 'TEST\\audit-owner';
  const rows = [];
  const database = auditDatabase(rows);
  const anchor = auditAnchor.openAuditAnchor({
    directory,
    pendingPath,
    allowBootstrap: true,
    env: {},
    fs: fsImpl,
    privatePathSecurity: {
      platform: 'win32',
      principal,
      ownerIdentity: TEST_OWNER_IDENTITY,
      privateLockRoot: path.join(root, 'locks'),
      spawn: aclHarness({ principal, inheritFrom: directory }),
    },
  });
  assert.deepStrictEqual(anchor.verifyDatabase(database), { ok: true, count: 0 });
  const first = anchor.authenticate(auditIntegrity.ZERO, {
    id: 'a_rollback_scope_1', ts: '2026-07-10T12:00:00.000Z',
    action: 'ROLLBACK_SCOPE_TEST', queryId: '', actor: 'test', detail: 'sanitized',
  });
  rows.push({ seq: 1, entry: JSON.stringify(first) });
  anchor.prepareTransactionCommit(database, [first]);
  anchor.transactionCommitted(database);
  const priorPending = fs.readFileSync(pendingPath);

  const second = anchor.authenticate(first.hash, {
    id: 'a_rollback_scope_2', ts: '2026-07-10T12:00:01.000Z',
    action: 'ROLLBACK_SCOPE_TEST', queryId: '', actor: 'test', detail: 'sanitized',
  });
  rows.push({ seq: 2, entry: JSON.stringify(second) });
  assert.throws(
    () => anchor.prepareTransactionCommit(database, [second]),
    /audit integrity directory identity changed/,
  );
  assert.deepStrictEqual(fs.readFileSync(pendingPath), priorPending, 'the exact prior pending witness is restored');
  assert.strictEqual(postRenameDirectoryStats, 2, 'both fallible final checks ran before rollback authority was released');
});

test('Windows atomic replacement accepts retained destination creation time but binds the file id', (t) => {
  const root = tempRoot(t, 'audit-anchor-windows-replace-identity');
  const directory = path.join(root, 'audit');
  const pendingPath = path.join(directory, '.audit-integrity-pending.json');
  let replacedExistingPending = false;
  const fsImpl = new Proxy(fs, {
    get(target, property) {
      if (property === 'renameSync') {
        return (source, destination) => {
          if (path.resolve(destination) === path.resolve(pendingPath) && target.existsSync(destination)) {
            replacedExistingPending = true;
          }
          return target.renameSync(source, destination);
        };
      }
      if (property === 'lstatSync') {
        return (file, options) => {
          const stat = target.lstatSync(file, options);
          if (!replacedExistingPending || path.resolve(file) !== path.resolve(pendingPath)) return stat;
          const changed = Object.create(stat);
          const delta = typeof stat.birthtimeNs === 'bigint' ? 1_000_000n : 1;
          if (stat.birthtimeNs !== undefined) {
            Object.defineProperty(changed, 'birthtimeNs', { value: stat.birthtimeNs - delta });
          } else {
            Object.defineProperty(changed, 'birthtimeMs', { value: stat.birthtimeMs - delta });
          }
          return changed;
        };
      }
      const value = target[property];
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });
  const principal = 'TEST\\audit-owner';
  const rows = [];
  const database = auditDatabase(rows);
  const anchor = auditAnchor.openAuditAnchor({
    directory,
    pendingPath,
    allowBootstrap: true,
    env: {},
    fs: fsImpl,
    privatePathSecurity: {
      platform: 'win32',
      principal,
      ownerIdentity: TEST_OWNER_IDENTITY,
      privateLockRoot: path.join(root, 'locks'),
      spawn: aclHarness({ principal, inheritFrom: directory }),
    },
  });
  assert.deepStrictEqual(anchor.verifyDatabase(database), { ok: true, count: 0 });
  const first = anchor.authenticate(auditIntegrity.ZERO, {
    id: 'a_windows_replace_1', ts: '2026-07-10T12:00:00.000Z',
    action: 'WINDOWS_REPLACE_TEST', queryId: '', actor: 'test', detail: 'sanitized',
  });
  rows.push({ seq: 1, entry: JSON.stringify(first) });
  anchor.prepareTransactionCommit(database, [first]);
  anchor.transactionCommitted(database);
  const second = anchor.authenticate(first.hash, {
    id: 'a_windows_replace_2', ts: '2026-07-10T12:00:01.000Z',
    action: 'WINDOWS_REPLACE_TEST', queryId: '', actor: 'test', detail: 'sanitized',
  });
  rows.push({ seq: 2, entry: JSON.stringify(second) });
  assert.doesNotThrow(() => anchor.prepareTransactionCommit(database, [second]));
  anchor.transactionCommitted(database);
  assert.strictEqual(JSON.parse(fs.readFileSync(pendingPath, 'utf8')).count, 2);
});

test('steady-state prepare re-authenticates the durable audit state', (t) => {
  const root = tempRoot(t, 'audit-anchor-state-reauth-prepare');
  const directory = path.join(root, 'audit');
  const rows = [];
  const database = auditDatabase(rows);
  const anchor = auditAnchor.openAuditAnchor({ directory, allowBootstrap: true, env: {} });
  assert.deepStrictEqual(anchor.verifyDatabase(database), { ok: true, count: 0 });
  const state = JSON.parse(fs.readFileSync(anchor.paths.statePath, 'utf8'));
  fs.writeFileSync(anchor.paths.statePath, JSON.stringify({ ...state, mac: '0'.repeat(64) }), { mode: 0o600 });
  const entry = anchor.authenticate(auditIntegrity.ZERO, {
    id: 'a_tampered_state_prepare', ts: '2026-07-10T12:00:00.000Z',
    action: 'STATE_REAUTH_TEST', queryId: '', actor: 'test', detail: 'sanitized',
  });
  rows.push({ seq: 1, entry: JSON.stringify(entry) });
  assert.throws(
    () => anchor.prepareTransactionCommit(database, [entry]),
    /audit integrity state authentication failed/,
  );
});

test('self-signed replacement state cannot rotate the pinned embedded audit key', (t) => {
  const root = tempRoot(t, 'audit-anchor-state-key-continuity');
  const directory = path.join(root, 'audit');
  const rows = [];
  const database = auditDatabase(rows);
  const anchor = auditAnchor.openAuditAnchor({ directory, allowBootstrap: true, env: {} });
  assert.deepStrictEqual(anchor.verifyDatabase(database), { ok: true, count: 0 });
  const originalBytes = fs.readFileSync(anchor.paths.statePath);
  const originalState = JSON.parse(originalBytes);
  const pinnedKey = Buffer.from(originalState.key, 'base64');
  const replacementKey = Buffer.alloc(32, 0x5a);
  fs.writeFileSync(
    anchor.paths.statePath,
    JSON.stringify(auditAnchor._internal.signedState(
      replacementKey,
      originalState.checkpointCreated,
      true,
      originalState.pendingProtocol,
    )),
    { mode: 0o600 },
  );
  const entry = anchor.authenticate(auditIntegrity.ZERO, {
    id: 'a_replacement_key_prepare', ts: '2026-07-10T12:00:00.000Z',
    action: 'STATE_KEY_CONTINUITY_TEST', queryId: '', actor: 'test', detail: 'sanitized',
  });
  rows.push({ seq: 1, entry: JSON.stringify(entry) });
  assert.throws(
    () => anchor.prepareTransactionCommit(database, [entry]),
    (error) => error && error.code === 'REDACTWALL_AUDIT_STATE_CONTINUITY',
  );
  assert.strictEqual(anchor.status().ok, false);
  assert.throws(
    () => anchor.requireMutationReady(database),
    (error) => error && error.code === 'REDACTWALL_AUDIT_CHECKPOINT_UNHEALTHY',
  );

  rows.pop();
  fs.writeFileSync(anchor.paths.statePath, originalBytes, { mode: 0o600 });
  assert.deepStrictEqual(anchor.requireMutationReady(database), { ok: true, count: 0 });
  const after = anchor.authenticate(auditIntegrity.ZERO, {
    id: 'a_original_key_retained', ts: '2026-07-10T12:00:01.000Z',
    action: 'STATE_KEY_CONTINUITY_TEST', queryId: '', actor: 'test', detail: 'sanitized',
  });
  assert.strictEqual(auditIntegrity.validAuthenticatedEntry(after, pinnedKey), true);
  assert.strictEqual(auditIntegrity.validAuthenticatedEntry(after, replacementKey), false);
});

test('steady-state checkpoint advance refuses a missing durable audit state', (t) => {
  const root = tempRoot(t, 'audit-anchor-state-reauth-advance');
  const directory = path.join(root, 'audit');
  const rows = [];
  const database = auditDatabase(rows);
  const anchor = auditAnchor.openAuditAnchor({ directory, allowBootstrap: true, env: {} });
  assert.deepStrictEqual(anchor.verifyDatabase(database), { ok: true, count: 0 });
  fs.unlinkSync(anchor.paths.statePath);
  assert.deepStrictEqual(anchor.advanceCheckpoint(database), {
    ok: false,
    count: 0,
    reason: 'checkpoint-unavailable',
  });
  assert.strictEqual(anchor.status().ok, false);
});

function failingCheckpointFs(checkpointPath, failure) {
  const checkpoint = path.resolve(checkpointPath);
  return new Proxy(fs, {
    get(target, property) {
      if (property === 'linkSync') {
        return (source, destination) => {
          if (failure.enabled
              && path.resolve(destination) === checkpoint
              && String(source).endsWith('.tmp')) {
            const error = new Error('synthetic checkpoint publication denial');
            error.code = 'EACCES';
            throw error;
          }
          return target.linkSync(source, destination);
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
  anchor.prepareTransactionCommit(database, [entry]);
  anchor.transactionCommitted(database);
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

test('protocol-enabled restart refuses an authenticated tail that has no pending commit proof', (t) => {
  const root = tempRoot(t, 'audit-anchor-missing-pending');
  const directory = path.join(root, 'audit');
  const rows = [];
  const database = auditDatabase(rows);
  const options = {
    directory,
    allowBootstrap: true,
    env: {},
  };
  const first = auditAnchor.openAuditAnchor(options);
  assert.deepStrictEqual(first.verifyDatabase(database), { ok: true, count: 0 });
  const entry = first.authenticate(auditIntegrity.ZERO, {
    id: 'a_without_pending',
    ts: '2026-07-10T12:00:00.000Z',
    action: 'MISSING_PENDING_TEST',
    queryId: '',
    actor: 'test',
    detail: 'sanitized',
  });
  rows.push({ seq: 1, entry: JSON.stringify(entry) });

  const restarted = auditAnchor.openAuditAnchor({ ...options, allowBootstrap: false });
  assert.deepStrictEqual(restarted.verifyDatabase(database), {
    ok: false,
    count: 1,
    reason: 'pending-missing',
  });
});

test('first bootstrap checkpoints a valid legacy unkeyed tail before enabling the pending protocol', (t) => {
  const root = tempRoot(t, 'audit-anchor-legacy-bootstrap');
  const directory = path.join(root, 'audit');
  const unsigned = {
    id: 'a_legacy_bootstrap',
    ts: '2026-07-10T12:00:00.000Z',
    action: 'LEGACY_BOOTSTRAP_TEST',
    queryId: '',
    actor: 'legacy-system',
    detail: 'sanitized legacy evidence',
    prevHash: auditIntegrity.ZERO,
  };
  const legacy = { ...unsigned, hash: auditIntegrity.sha(auditIntegrity.canonical(unsigned)) };
  const database = auditDatabase([{ seq: 1, entry: JSON.stringify(legacy) }]);

  const anchor = auditAnchor.openAuditAnchor({ directory, allowBootstrap: true, env: {} });
  const initialState = JSON.parse(fs.readFileSync(anchor.paths.statePath, 'utf8'));
  assert.strictEqual(initialState.version, 1, 'the one-time legacy bootstrap must precede protocol-v2 enforcement');
  assert.deepStrictEqual(anchor.verifyDatabase(database), { ok: true, count: 1 });

  const checkpoint = JSON.parse(fs.readFileSync(anchor.paths.checkpointPath, 'utf8'));
  assert.strictEqual(checkpoint.count, 1);
  assert.strictEqual(checkpoint.seq, 1);
  assert.strictEqual(checkpoint.head, legacy.hash);
  const upgradedState = JSON.parse(fs.readFileSync(anchor.paths.statePath, 'utf8'));
  assert.strictEqual(upgradedState.version, 2);
  assert.strictEqual(upgradedState.pendingProtocol, true);

  const restarted = auditAnchor.openAuditAnchor({ directory, allowBootstrap: false, env: {} });
  assert.deepStrictEqual(restarted.verifyDatabase(database), { ok: true, count: 1 });
});

test('migration-complete restart cannot bless a tail injected before the first checkpoint', (t) => {
  const root = tempRoot(t, 'audit-anchor-bootstrap-crash');
  const directory = path.join(root, 'audit');
  auditAnchor.openAuditAnchor({ directory, allowBootstrap: true, env: {} });
  const unsigned = {
    id: 'a_forged_after_migration',
    ts: '2026-07-10T12:00:00.000Z',
    action: 'FORGED_BOOTSTRAP_TEST',
    queryId: '',
    actor: 'attacker',
    detail: 'forged but self-consistent',
    prevHash: auditIntegrity.ZERO,
  };
  const forged = { ...unsigned, hash: auditIntegrity.sha(auditIntegrity.canonical(unsigned)) };
  const database = auditDatabase([{ seq: 1, entry: JSON.stringify(forged) }]);

  const restarted = auditAnchor.openAuditAnchor({ directory, allowBootstrap: false, env: {} });
  assert.deepStrictEqual(restarted.verifyDatabase(database), {
    ok: false,
    count: 1,
    reason: 'checkpoint-missing',
  });
});

test('pre-migration restart cannot bootstrap a forged tail from protocol-v2 state without its checkpoint', (t) => {
  const root = tempRoot(t, 'audit-anchor-v2-missing-checkpoint');
  const directory = path.join(root, 'audit');
  const statePath = path.join(directory, '.audit-integrity-state.json');
  const env = { REDACTWALL_AUDIT_KEY: 'protocol-v2-missing-checkpoint-test-key' };
  const key = auditAnchor._internal.configuredKey(env);
  privatePaths.withPrivateDirectoryMutationLockSync(directory, () => {
    auditAnchor._internal.writePrivateJson(
      statePath,
      auditAnchor._internal.signedState(key, true, false, true),
    );
  }, { label: 'audit integrity directory', ownerLabel: 'audit integrity directory' });

  const unsigned = {
    id: 'a_forged_pre_migration_v2',
    ts: '2026-07-10T12:00:00.000Z',
    action: 'FORGED_BOOTSTRAP_TEST',
    queryId: '',
    actor: 'attacker',
    detail: 'forged but self-consistent',
    prevHash: auditIntegrity.ZERO,
  };
  const forged = { ...unsigned, hash: auditIntegrity.sha(auditIntegrity.canonical(unsigned)) };
  const database = auditDatabase([{ seq: 1, entry: JSON.stringify(forged) }]);

  assert.throws(
    () => auditAnchor.openAuditAnchor({
      directory,
      allowBootstrap: true,
      env,
      initialize({ bootstrapLegacyDatabase }) {
        bootstrapLegacyDatabase(database);
      },
    }),
    /legacy audit bootstrap failed \(checkpoint-missing\)/,
  );
  assert.strictEqual(fs.existsSync(path.join(directory, '.audit-integrity-checkpoint.json')), false);
});

test('legacy authenticated state upgrades only after its current checkpoint verifies', (t) => {
  const root = tempRoot(t, 'audit-anchor-protocol-upgrade');
  const directory = path.join(root, 'audit');
  const statePath = path.join(directory, '.audit-integrity-state.json');
  const checkpointPath = path.join(directory, '.audit-integrity-checkpoint.json');
  const env = { REDACTWALL_AUDIT_KEY: 'legacy-audit-key-for-protocol-upgrade' };
  const key = auditAnchor._internal.configuredKey(env);
  privatePaths.withPrivateDirectoryMutationLockSync(directory, () => {
    auditAnchor._internal.writePrivateJson(
      statePath,
      auditAnchor._internal.signedState(key, true, false, false),
    );
    auditAnchor._internal.writePrivateJson(
      checkpointPath,
      auditIntegrity.createCheckpoint(0, auditIntegrity.ZERO, key, 0),
    );
  }, { label: 'audit integrity directory', ownerLabel: 'audit integrity directory' });
  const anchor = auditAnchor.openAuditAnchor({
    directory,
    allowBootstrap: false,
    env,
  });
  assert.deepStrictEqual(anchor.verifyDatabase(auditDatabase([])), { ok: true, count: 0 });
  const upgraded = JSON.parse(fs.readFileSync(statePath, 'utf8'));
  assert.strictEqual(upgraded.version, 2);
  assert.strictEqual(upgraded.pendingProtocol, true);
});

test('authenticated audit state is bound to one opaque database scope', (t) => {
  const root = tempRoot(t, 'audit-anchor-database-scope');
  const directory = path.join(root, 'audit');
  const firstScope = 'a'.repeat(64);
  const secondScope = 'b'.repeat(64);
  const first = auditAnchor.openAuditAnchor({
    directory,
    allowBootstrap: true,
    databaseScope: firstScope,
    env: {},
  });
  const state = JSON.parse(fs.readFileSync(first.paths.statePath, 'utf8'));
  assert.strictEqual(state.version, 3);
  assert.strictEqual(state.databaseScope, firstScope);
  assert.match(state.mac, /^[a-f0-9]{64}$/);

  assert.throws(
    () => auditAnchor.openAuditAnchor({
      directory,
      allowBootstrap: true,
      databaseScope: secondScope,
      env: {},
    }),
    (error) => error
      && error.message === 'audit integrity state database scope mismatch'
      && !error.message.includes(firstScope)
      && !error.message.includes(secondScope),
  );

  state.databaseScope = secondScope;
  fs.writeFileSync(first.paths.statePath, JSON.stringify(state));
  assert.throws(
    () => auditAnchor.openAuditAnchor({
      directory,
      allowBootstrap: true,
      databaseScope: secondScope,
      env: {},
    }),
    /audit integrity state authentication failed/,
  );
});

test('a live anchor rejects a valid same-key state replacement from another database scope', (t) => {
  const root = tempRoot(t, 'audit-anchor-live-database-scope-replacement');
  const directory = path.join(root, 'audit');
  const firstScope = 'd'.repeat(64);
  const secondScope = 'e'.repeat(64);
  const env = { REDACTWALL_AUDIT_KEY: 'shared-external-key-for-live-scope-replacement' };
  const database = auditDatabase([]);
  const anchor = auditAnchor.openAuditAnchor({
    directory,
    allowBootstrap: true,
    databaseScope: firstScope,
    env,
  });
  assert.deepStrictEqual(anchor.verifyDatabase(database), { ok: true, count: 0 });

  const active = JSON.parse(fs.readFileSync(anchor.paths.statePath, 'utf8'));
  const key = auditAnchor._internal.configuredKey(env);
  fs.writeFileSync(
    anchor.paths.statePath,
    JSON.stringify(auditAnchor._internal.signedState(
      key,
      active.checkpointCreated,
      active.embedded,
      active.pendingProtocol,
      secondScope,
    )),
  );

  assert.deepStrictEqual(anchor.verifyDatabase(database), {
    ok: false,
    count: 0,
    reason: 'checkpoint-unavailable',
  });
  assert.strictEqual(anchor.status().ok, false);
});

test('a verified unscoped state upgrades without breaking legacy compatibility', (t) => {
  const root = tempRoot(t, 'audit-anchor-database-scope-upgrade');
  const directory = path.join(root, 'audit');
  const database = auditDatabase([]);
  const legacy = auditAnchor.openAuditAnchor({ directory, allowBootstrap: true, env: {} });
  assert.deepStrictEqual(legacy.verifyDatabase(database), { ok: true, count: 0 });
  assert.strictEqual(
    JSON.parse(fs.readFileSync(legacy.paths.statePath, 'utf8')).databaseScope,
    undefined,
  );

  const databaseScope = 'c'.repeat(64);
  const upgraded = auditAnchor.openAuditAnchor({
    directory,
    allowBootstrap: false,
    databaseScope,
    env: {},
    initialize({ bindDatabaseScope }) {
      bindDatabaseScope(database);
    },
  });
  const state = JSON.parse(fs.readFileSync(upgraded.paths.statePath, 'utf8'));
  assert.strictEqual(state.version, 3);
  assert.strictEqual(state.databaseScope, databaseScope);
  assert.strictEqual(state.pendingProtocol, true);
  const claim = JSON.parse(fs.readFileSync(`${upgraded.paths.statePath}.database-scope-claim`, 'utf8'));
  assert.strictEqual(claim.databaseScope, databaseScope);
  assert.match(claim.mac, /^[a-f0-9]{64}$/);
  assert.deepStrictEqual(upgraded.verifyDatabase(database), { ok: true, count: 0 });
});

test('failed exclusive state cleanup quarantines and preserves a replacement', (t) => {
  const root = tempRoot(t, 'audit-anchor-exclusive-cleanup-race');
  const directory = path.join(root, 'audit');
  const statePath = path.join(directory, 'state.json');
  const movedOriginal = path.join(directory, 'original-owned');
  const principal = 'TEST\\audit-owner';
  const privatePathSecurity = {
    platform: 'win32',
    principal,
    ownerIdentity: TEST_OWNER_IDENTITY,
    privateLockRoot: path.join(root, 'locks'),
    spawn: aclHarness({ principal }),
  };
  fs.mkdirSync(directory);
  privatePaths.securePrivatePath(directory, {
    ...privatePathSecurity,
    directory: true,
    label: 'audit integrity directory',
    ownerLabel: 'audit integrity directory',
  });
  let mismatchInjected = false;
  let cleanupSwapped = false;
  let quarantinePath = null;
  const fsImpl = new Proxy(fs, {
    get(target, property) {
      if (property === 'lstatSync') {
        return (targetPath, options) => {
          const stat = target.lstatSync(targetPath, options);
          if (!mismatchInjected && path.resolve(targetPath) === path.resolve(statePath)
              && Number(stat.nlink) === 2) {
            mismatchInjected = true;
            return { ...stat, size: stat.size + 1n };
          }
          return stat;
        };
      }
      if (property === 'renameSync') {
        return (source, destination) => {
          if (!cleanupSwapped && path.resolve(source) === path.resolve(statePath)
              && path.basename(destination).includes('.failed-new-state-')) {
            cleanupSwapped = true;
            quarantinePath = destination;
            target.renameSync(source, movedOriginal);
            target.writeFileSync(source, 'replacement-owned');
          }
          return target.renameSync(source, destination);
        };
      }
      const value = target[property];
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });

  assert.throws(
    () => auditAnchor._internal.writeNewPrivateJson(statePath, { version: 1 }, {
      fs: fsImpl,
      privatePathSecurity,
    }),
    /changed replacement retained at/,
  );
  assert.strictEqual(mismatchInjected, true);
  assert.strictEqual(cleanupSwapped, true);
  assert.strictEqual(fs.readFileSync(quarantinePath, 'utf8'), 'replacement-owned');
  assert.strictEqual(fs.existsSync(movedOriginal), true, 'the originally linked inode was not confused with the replacement');
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

test('POSIX initialization prepares distinct missing sidecar parents before binding them', {
  skip: process.platform === 'win32' && 'POSIX permissions are not meaningful on Windows',
}, (t) => {
  const root = tempRoot(t, 'audit-anchor-distinct-posix-parents');
  const directory = path.join(root, 'anchor');
  const statePath = path.join(root, 'state-parent', 'state.json');
  const checkpointPath = path.join(root, 'checkpoint-parent', 'checkpoint.json');
  const pendingPath = path.join(root, 'pending-parent', 'pending.json');
  const anchor = auditAnchor.openAuditAnchor({
    directory,
    statePath,
    checkpointPath,
    pendingPath,
    allowBootstrap: true,
    env: {},
  });
  assert.deepStrictEqual(anchor.verifyDatabase(auditDatabase([])), { ok: true, count: 0 });
  for (const parent of [directory, path.dirname(statePath), path.dirname(checkpointPath), path.dirname(pendingPath)]) {
    assert.strictEqual(fs.statSync(parent).mode & 0o777, 0o700);
  }
});

test('POSIX audit-directory preparation preserves case-distinct paths', {
  skip: process.platform === 'win32' && 'Windows paths are case-insensitive',
}, (t) => {
  const root = tempRoot(t, 'audit-anchor-case-distinct-posix-parents');
  const lower = path.join(root, 'audit');
  const upper = path.join(root, 'AUDIT');
  auditAnchor._internal.withPreparedAuditDirectories([lower, upper], () => {
    assert.strictEqual(fs.existsSync(lower), true);
    assert.strictEqual(fs.existsSync(upper), true);
  }, { platform: 'linux' });
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
      ownerIdentity: TEST_OWNER_IDENTITY,
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
      ownerIdentity: TEST_OWNER_IDENTITY,
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
