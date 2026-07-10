'use strict';
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');

const policy = require('../server/policy');
const fileMutationLock = require('../server/file-mutation-lock');

const mutationWorker = path.join(__dirname, 'support', 'file-mutation-worker.js');
const GENERATION_A = 'linux:11111111-1111-4111-8111-111111111111:1000';
const GENERATION_B = 'linux:22222222-2222-4222-8222-222222222222:2000';

function writeConfig(file, value) {
  fs.writeFileSync(file, typeof value === 'string' ? value : JSON.stringify(value));
  const future = new Date(Date.now() + 5000);
  fs.utimesSync(file, future, future);
}

function launchMutationWorker(mode, env) {
  const child = spawn(process.execPath, [mutationWorker, mode], {
    env: { ...process.env, ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.output = '';
  child.stdout.on('data', (chunk) => { child.output += chunk.toString(); });
  child.stderr.on('data', (chunk) => { child.output += chunk.toString(); });
  return child;
}

async function waitForFile(child, file, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (fs.existsSync(file)) return;
    if (child.exitCode !== null) throw new Error(`mutation worker exited early: ${child.output}`);
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error(`mutation worker marker timed out: ${file}`);
}

async function waitForExit(child) {
  if (child.exitCode === null) await new Promise((resolve) => child.once('exit', resolve));
  assert.strictEqual(child.exitCode, 0, child.output);
}

function writeLockOwner(lockPath, fields) {
  const owner = {
    ...fields,
    token: fields.token || crypto.randomBytes(24).toString('hex'),
  };
  const ownerName = fileMutationLock._internal.ownerFileName(owner.token);
  const ownerPath = path.join(lockPath, ownerName);
  const contents = `${JSON.stringify(owner)}\n`;
  fs.mkdirSync(lockPath, { mode: 0o700 });
  fs.writeFileSync(ownerPath, contents, { mode: 0o600 });
  return { owner, ownerName, ownerPath, contents };
}

function readLockOwner(lockPath) {
  const entries = fs.readdirSync(lockPath);
  assert.strictEqual(entries.length, 1);
  const ownerPath = path.join(lockPath, entries[0]);
  return { ownerPath, contents: fs.readFileSync(ownerPath, 'utf8') };
}

function removeExactLockOwner(lockPath, ownerPath) {
  fs.unlinkSync(ownerPath);
  fs.rmdirSync(lockPath);
}

function windowsRenameSemantics(existingCode = 'EPERM') {
  return {
    ...fs,
    renameSync(from, to) {
      if (fs.existsSync(to)) {
        const error = new Error('Windows does not replace an existing directory');
        error.code = existingCode;
        error.syscall = 'rename';
        throw error;
      }
      return fs.renameSync(from, to);
    },
  };
}

test('explicit missing and malformed policy files fail readiness while enforcing conservative defaults', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-policy-health-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const missing = policy.createPolicyLoader(path.join(dir, 'missing.json'), true);

  assert.strictEqual(missing.loadPolicy().enforcementMode, 'block');
  assert.deepStrictEqual(missing.status(), {
    ok: false,
    configured: true,
    error: 'configured policy file is missing',
    usingLastKnownGood: false,
  });

  const malformedPath = path.join(dir, 'malformed.json');
  writeConfig(malformedPath, '{not json');
  const malformed = policy.createPolicyLoader(malformedPath, true);
  assert.strictEqual(malformed.loadPolicy().enforcementMode, 'block');
  assert.strictEqual(malformed.status().ok, false);
  assert.match(malformed.status().error, /valid JSON/i);
});

test('syntactically valid but semantically malformed policies fail readiness without reaching runtime', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-policy-semantic-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'policy.json');
  writeConfig(file, { ignore: {} });
  const loader = policy.createPolicyLoader(file, true);
  const enforced = loader.loadPolicy();

  assert.doesNotThrow(() => policy.analyzeOpts(enforced));
  assert.strictEqual(enforced.enforcementMode, 'block');
  assert.deepStrictEqual(enforced.ignore, []);
  assert.deepStrictEqual(loader.status(), {
    ok: false,
    configured: true,
    error: 'policy file failed semantic validation',
    usingLastKnownGood: false,
  });
});

test('policy loader retains the exact last-known-good policy after corruption or disappearance', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-policy-lkg-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'policy.json');
  writeConfig(file, { ...policy.DEFAULT_POLICY, enforcementMode: 'warn' });
  const loader = policy.createPolicyLoader(file, true);
  const good = loader.loadPolicy();

  assert.strictEqual(good.enforcementMode, 'warn');
  assert.strictEqual(loader.loadPolicy(), good);

  writeConfig(file, { ...policy.DEFAULT_POLICY, enforcementMode: 'warn', ignore: {} });
  assert.strictEqual(loader.loadPolicy(), good, 'semantic failure retains the exact LKG object');
  assert.strictEqual(loader.status().error, 'policy file failed semantic validation');

  writeConfig(file, '[]');
  assert.strictEqual(loader.loadPolicy(), good, 'invalid shape retains the exact LKG object');
  assert.strictEqual(loader.status().usingLastKnownGood, true);

  fs.rmSync(file);
  assert.strictEqual(loader.loadPolicy(), good, 'disappearance retains the exact LKG object');
  assert.deepStrictEqual(loader.status(), {
    ok: false,
    configured: true,
    error: 'policy file disappeared after a successful load',
    usingLastKnownGood: true,
  });
});

test('never-seen absent optional native policy uses healthy conservative defaults', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-policy-optional-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const loader = policy.createPolicyLoader(path.join(dir, 'optional.json'), false);

  assert.strictEqual(loader.loadPolicy().enforcementMode, 'block');
  assert.deepStrictEqual(loader.status(), {
    ok: true,
    configured: false,
    error: null,
    usingLastKnownGood: false,
  });
});

test('atomic policy save fsyncs the file, renames within one directory, fsyncs the directory, and leaves no temp file', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-policy-save-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const target = path.join(dir, 'policy.json');
  fs.writeFileSync(target, JSON.stringify({ ...policy.DEFAULT_POLICY, enforcementMode: 'warn' }));
  const calls = [];
  const fsImpl = {
    ...fs,
    openSync(file, flags, mode) {
      calls.push(['open', path.resolve(file), flags, mode]);
      return fs.openSync(file, flags, mode);
    },
    fsyncSync(fd) {
      calls.push(['fsync', fd]);
      return fs.fsyncSync(fd);
    },
    renameSync(from, to) {
      calls.push(['rename', path.resolve(from), path.resolve(to)]);
      return fs.renameSync(from, to);
    },
  };

  policy.writePolicyAtomically(target, { ...policy.DEFAULT_POLICY, enforcementMode: 'justify' }, {
    fs: fsImpl,
    nonce: 'fixed-nonce',
  });

  assert.strictEqual(JSON.parse(fs.readFileSync(target, 'utf8')).enforcementMode, 'justify');
  const rename = calls.find((entry) => entry[0] === 'rename');
  assert.ok(rename);
  assert.strictEqual(path.dirname(rename[1]), dir);
  assert.strictEqual(rename[2], target);
  assert.ok(calls.filter((entry) => entry[0] === 'fsync').length >= 2, 'file and directory are fsynced');
  assert.deepStrictEqual(fs.readdirSync(dir), ['policy.json']);
});

test('atomic policy save cleans its same-directory temp file after a rename failure', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-policy-save-fail-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const target = path.join(dir, 'policy.json');
  const fsImpl = {
    ...fs,
    renameSync() {
      const error = new Error('synthetic rename failure');
      error.code = 'EIO';
      throw error;
    },
  };

  assert.throws(
    () => policy.writePolicyAtomically(target, policy.DEFAULT_POLICY, {
      fs: fsImpl,
      nonce: crypto.randomBytes(4).toString('hex'),
    }),
    /synthetic rename failure/,
  );
  assert.deepStrictEqual(fs.readdirSync(dir), []);
});

test('atomic policy save rejects semantically invalid policy before creating a temp file', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-policy-save-invalid-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const target = path.join(dir, 'policy.json');

  assert.throws(
    () => policy.writePolicyAtomically(target, { ...policy.DEFAULT_POLICY, ignore: {} }),
    /semantic validation/,
  );
  assert.throws(
    () => policy.writePolicyAtomically(target, {
      ...policy.DEFAULT_POLICY,
      policyScopes: [{ id: 'invalid scope id' }],
    }),
    /semantic validation/,
  );
  assert.deepStrictEqual(fs.readdirSync(dir), []);
});

test('atomic policy save never removes a colliding temp file it did not create', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-policy-save-collision-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const target = path.join(dir, 'policy.json');
  const nonce = 'preexisting';
  const collision = path.join(dir, `.policy.json.${process.pid}.${nonce}.tmp`);
  fs.writeFileSync(collision, 'owned by another writer');

  assert.throws(
    () => policy.writePolicyAtomically(target, policy.DEFAULT_POLICY, { nonce }),
    (error) => error && error.code === 'EEXIST',
  );
  assert.strictEqual(fs.readFileSync(collision, 'utf8'), 'owned by another writer');
  assert.strictEqual(fs.existsSync(target), false);
});

test('policy loader retries a transient read failure even when the file signature is unchanged', () => {
  const payload = JSON.stringify({ ...policy.DEFAULT_POLICY, enforcementMode: 'warn' });
  let reads = 0;
  const flakyFs = {
    ...fs,
    statSync: () => ({ mtimeMs: 1, ctimeMs: 1, size: payload.length }),
    readFileSync() {
      reads += 1;
      if (reads === 1) {
        const error = new Error('synthetic read failure');
        error.code = 'EIO';
        throw error;
      }
      return payload;
    },
  };
  const loader = policy.createPolicyLoader('flaky.json', true, flakyFs);

  assert.strictEqual(loader.loadPolicy().enforcementMode, 'block');
  assert.strictEqual(loader.loadPolicy().enforcementMode, 'warn');
  assert.strictEqual(loader.status().ok, true);
  assert.strictEqual(reads, 2);
});

test('policy mutation rejects a stale pre-lock policy without writing', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-policy-stale-write-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'policy.json');
  const expected = { ...policy.DEFAULT_POLICY, enforcementMode: 'block' };
  const winner = { ...policy.DEFAULT_POLICY, enforcementMode: 'warn' };
  writeConfig(file, winner);
  let callbackRan = false;

  assert.throws(
    () => policy.withPolicyFileMutation(expected, () => {
      callbackRan = true;
    }, { configPath: file }),
    (error) => error && error.code === 'POLICY_WRITE_CONFLICT',
  );
  assert.strictEqual(callbackRan, false);
  assert.strictEqual(JSON.parse(fs.readFileSync(file, 'utf8')).enforcementMode, 'warn');
});

test('policy mutation lock never reaps an old lock whose owner is still alive', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-policy-lock-timeout-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'policy.json');
  const lockFile = fileMutationLock.lockPathFor(file);
  const existing = writeLockOwner(lockFile, {
    version: 1,
    pid: process.pid,
    hostname: os.hostname(),
  });
  writeConfig(file, policy.DEFAULT_POLICY);
  const old = new Date(Date.now() - 24 * 60 * 60 * 1000);
  fs.utimesSync(lockFile, old, old);
  fs.utimesSync(existing.ownerPath, old, old);
  const started = Date.now();

  assert.throws(
    () => policy.withPolicyFileMutation(policy.DEFAULT_POLICY, () => true, {
      configPath: file,
      lockTimeoutMs: 40,
      lockRetryMs: 5,
    }),
    (error) => error && error.code === 'FILE_MUTATION_LOCK_TIMEOUT',
  );
  assert.ok(Date.now() - started < 1000, 'lock wait is bounded');
  assert.strictEqual(fs.readFileSync(existing.ownerPath, 'utf8'), existing.contents);
});

test('same PID with a different process start fingerprint reclaims the prior instance', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-policy-lock-pid-reuse-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'policy.json');
  const lockFile = fileMutationLock.lockPathFor(file);
  const baseline = { ...policy.DEFAULT_POLICY, enforcementMode: 'block' };
  writeConfig(file, baseline);
  writeLockOwner(lockFile, {
    version: 2,
    pid: 1,
    hostname: 'redactwall',
    processStart: '1000.125',
  });
  let killCalls = 0;

  policy.withPolicyFileMutation(baseline, ({ write }) => {
    write({ ...baseline, enforcementMode: 'warn' });
  }, {
    configPath: file,
    hostname: 'redactwall',
    pid: 1,
    processStart: '2000.5',
    processKill: () => { killCalls += 1; },
    lockTimeoutMs: 1000,
  });

  assert.strictEqual(killCalls, 0, 'same-PID instance mismatch is conclusive without probing the reused PID');
  assert.strictEqual(JSON.parse(fs.readFileSync(file, 'utf8')).enforcementMode, 'warn');
});

test('different-host owner evidence remains ambiguous and is never reclaimed', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-policy-lock-remote-owner-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'policy.json');
  const lockFile = fileMutationLock.lockPathFor(file);
  writeConfig(file, policy.DEFAULT_POLICY);
  const existing = writeLockOwner(lockFile, {
    version: 2,
    pid: 1,
    hostname: 'remote-redactwall',
    processStart: '1000',
  });

  assert.throws(
    () => fileMutationLock.acquireFileMutationLockSync(file, {
      hostname: 'local-redactwall',
      pid: 1,
      processStart: '2000',
      processKill: () => { const error = new Error('missing'); error.code = 'ESRCH'; throw error; },
      lockTimeoutMs: 40,
      lockRetryMs: 5,
    }),
    (error) => error && error.code === 'FILE_MUTATION_LOCK_TIMEOUT',
  );
  assert.strictEqual(fs.readFileSync(existing.ownerPath, 'utf8'), existing.contents);
});

test('different Linux PID-namespace generation reclaims an occupied prior PID', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-policy-lock-generation-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'policy.json');
  const lockPath = fileMutationLock.lockPathFor(file);
  writeLockOwner(lockPath, {
    version: 3,
    pid: 4242,
    hostname: 'redactwall-generation',
    processStart: '1000',
    generation: GENERATION_A,
  });
  let killCalls = 0;

  const lock = fileMutationLock.acquireFileMutationLockSync(file, {
    hostname: 'redactwall-generation',
    pid: 5252,
    processStart: '2000',
    generation: GENERATION_B,
    processKill: () => { killCalls += 1; },
    lockTimeoutMs: 100,
  });

  assert.strictEqual(killCalls, 0, 'generation mismatch is conclusive before probing the reused PID');
  fileMutationLock.releaseFileMutationLock(lock);
  assert.strictEqual(fs.existsSync(lockPath), false);
});

test('Linux generation fingerprint binds boot id to PID namespace init start time', () => {
  const fields = ['S', ...Array(18).fill('0'), '987654'];
  const procStat = `1 (init worker) name) ${fields.join(' ')}`;
  const generation = fileMutationLock._internal.linuxGeneration({
    readFileSync(file) {
      if (file.endsWith('boot_id')) return 'ABCDEFAB-CDEF-4ABC-8DEF-ABCDEFABCDEF\n';
      if (file === '/proc/1/stat') return procStat;
      throw new Error('unexpected proc path');
    },
  }, 'linux');

  assert.strictEqual(fileMutationLock._internal.procStatStartTime(procStat), '987654');
  assert.strictEqual(generation, 'linux:abcdefab-cdef-4abc-8def-abcdefabcdef:987654');
  assert.strictEqual(fileMutationLock._internal.procStatStartTime('malformed'), null);
});

test('same Linux generation with a live different PID is never reclaimed', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-policy-lock-same-generation-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'policy.json');
  const lockPath = fileMutationLock.lockPathFor(file);
  const existing = writeLockOwner(lockPath, {
    version: 3,
    pid: 4242,
    hostname: 'redactwall-generation',
    processStart: '1000',
    generation: GENERATION_A,
  });
  let killCalls = 0;

  assert.throws(() => fileMutationLock.acquireFileMutationLockSync(file, {
    hostname: 'redactwall-generation',
    pid: 5252,
    processStart: '2000',
    generation: GENERATION_A,
    processKill: () => { killCalls += 1; },
    lockTimeoutMs: 40,
    lockRetryMs: 5,
  }), (error) => error && error.code === 'FILE_MUTATION_LOCK_TIMEOUT');

  assert.ok(killCalls > 0);
  assert.strictEqual(fs.readFileSync(existing.ownerPath, 'utf8'), existing.contents);
});

test('missing or malformed generation evidence fails closed while the prior PID is occupied', async (t) => {
  for (const [label, owner] of [
    ['missing', {
      version: 3,
      pid: 4242,
      hostname: 'redactwall-generation',
      processStart: '1000',
    }],
    ['malformed', {
      version: 3,
      pid: 4242,
      hostname: 'redactwall-generation',
      processStart: '1000',
      generation: 'linux:not-a-generation',
    }],
  ]) {
    await t.test(label, () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), `rw-policy-lock-${label}-generation-`));
      t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
      const file = path.join(dir, 'policy.json');
      const lockPath = fileMutationLock.lockPathFor(file);
      const existing = writeLockOwner(lockPath, owner);

      assert.throws(() => fileMutationLock.acquireFileMutationLockSync(file, {
        hostname: 'redactwall-generation',
        pid: 5252,
        processStart: '2000',
        generation: GENERATION_B,
        processKill: () => {},
        lockTimeoutMs: 40,
        lockRetryMs: 5,
      }), (error) => error && error.code === 'FILE_MUTATION_LOCK_TIMEOUT');
      assert.strictEqual(fs.readFileSync(existing.ownerPath, 'utf8'), existing.contents);
    });
  }
});

test('a late reclaimer cannot unlink a replacement token owner', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-policy-lock-late-reclaimer-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'policy.json');
  const lockPath = fileMutationLock.lockPathFor(file);
  writeLockOwner(lockPath, {
    version: 3,
    pid: 4242,
    hostname: 'redactwall-late-reclaimer',
    processStart: '1000',
    generation: GENERATION_A,
  });
  let replacement;
  let hookCalls = 0;

  assert.throws(() => fileMutationLock.acquireFileMutationLockSync(file, {
    hostname: 'redactwall-late-reclaimer',
    pid: 5252,
    processStart: '2000',
    generation: GENERATION_B,
    processKill: () => {},
    lockTimeoutMs: 40,
    lockRetryMs: 5,
    onBeforeReclaim({ ownerPath }) {
      hookCalls += 1;
      removeExactLockOwner(lockPath, ownerPath);
      replacement = fileMutationLock.acquireFileMutationLockSync(file, {
        hostname: 'redactwall-late-reclaimer',
        pid: 6262,
        processStart: '3000',
        generation: GENERATION_B,
      });
    },
  }), (error) => error && error.code === 'FILE_MUTATION_LOCK_TIMEOUT');

  assert.strictEqual(hookCalls, 1);
  assert.ok(replacement);
  assert.strictEqual(fs.readFileSync(replacement.ownerPath, 'utf8'), replacement.contents);
  fileMutationLock.releaseFileMutationLock(replacement);
});

test('an empty crash-orphan directory is reclaimed under Windows rename semantics', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-policy-lock-empty-windows-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'policy.json');
  const lockPath = fileMutationLock.lockPathFor(file);
  fs.mkdirSync(lockPath, { mode: 0o700 });

  const lock = fileMutationLock.acquireFileMutationLockSync(file, {
    fs: windowsRenameSemantics(),
    lockTimeoutMs: 100,
  });

  assert.strictEqual(fs.statSync(lock.lockPath).isDirectory(), true);
  assert.strictEqual(fs.existsSync(lock.ownerPath), true);
  fileMutationLock.releaseFileMutationLock(lock);
  assert.strictEqual(fs.existsSync(lockPath), false);
});

test('transient Windows cleanup denial leaves no unpublished lock temp directories', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-policy-lock-cleanup-retry-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'policy.json');
  const holder = fileMutationLock.acquireFileMutationLockSync(file, {
    fs: windowsRenameSemantics(),
    lockTimeoutMs: 100,
  });
  const denied = new Set();
  const fsImpl = {
    ...windowsRenameSemantics('EBUSY'),
    unlinkSync(target) {
      if (String(target).includes('.owner.tmp') && !denied.has(target)) {
        denied.add(target);
        const error = new Error('transient scanner denial');
        error.code = 'EPERM';
        throw error;
      }
      return fs.unlinkSync(target);
    },
  };

  assert.throws(() => fileMutationLock.acquireFileMutationLockSync(file, {
    fs: fsImpl,
    lockTimeoutMs: 40,
    lockRetryMs: 5,
  }), (error) => error && error.code === 'FILE_MUTATION_LOCK_TIMEOUT');
  assert.deepStrictEqual(
    fs.readdirSync(dir).filter((name) => name.endsWith('.owner.tmp')),
    [],
  );
  fileMutationLock.releaseFileMutationLock(holder);
});

test('lock release reports persistent cleanup denial and can be retried exactly', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-policy-lock-release-retry-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'policy.json');
  let denyOwnerUnlink = true;
  const fsImpl = {
    ...fs,
    unlinkSync(target) {
      if (denyOwnerUnlink && String(target).includes('.mutation.lock')) {
        const error = new Error('persistent scanner denial');
        error.code = 'EPERM';
        throw error;
      }
      return fs.unlinkSync(target);
    },
  };
  const lock = fileMutationLock.acquireFileMutationLockSync(file, { fs: fsImpl });

  assert.throws(
    () => fileMutationLock.releaseFileMutationLock(lock),
    (error) => error && error.code === 'FILE_MUTATION_LOCK_CLEANUP',
  );
  assert.strictEqual(lock.released, false, 'failed cleanup must not claim release');
  assert.strictEqual(fs.existsSync(lock.ownerPath), true);

  denyOwnerUnlink = false;
  fileMutationLock.releaseFileMutationLock(lock);
  assert.strictEqual(lock.released, true);
  assert.strictEqual(fs.existsSync(lock.lockPath), false);
});

test('an empty lock directory does not retain a released-owner token after cleanup failure', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-policy-lock-empty-release-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'policy.json');
  const before = fileMutationLock._internal.releasedOwnerTokenCount();
  let denyRmdir = true;
  const fsImpl = {
    ...fs,
    rmdirSync(target) {
      if (denyRmdir && String(target).endsWith('.mutation.lock')) {
        const error = new Error('persistent directory scanner denial');
        error.code = 'EPERM';
        throw error;
      }
      return fs.rmdirSync(target);
    },
  };
  const lock = fileMutationLock.acquireFileMutationLockSync(file, { fs: fsImpl });

  assert.throws(
    () => fileMutationLock.releaseFileMutationLock(lock),
    (error) => error && error.code === 'FILE_MUTATION_LOCK_CLEANUP',
  );
  assert.deepStrictEqual(fs.readdirSync(lock.lockPath), []);
  assert.strictEqual(fileMutationLock._internal.releasedOwnerTokenCount(), before);

  denyRmdir = false;
  const recovered = fileMutationLock.acquireFileMutationLockSync(file, { fs: fsImpl, lockTimeoutMs: 200 });
  fileMutationLock.releaseFileMutationLock(recovered);
  assert.strictEqual(fs.existsSync(lock.lockPath), false);
});

test('callback failures remain primary when lock cleanup also fails', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-policy-lock-error-order-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'policy.json');
  let denyOwnerUnlink = true;
  const fsImpl = {
    ...fs,
    unlinkSync(target) {
      if (denyOwnerUnlink && String(target).includes('.mutation.lock')) {
        const error = new Error('persistent scanner denial');
        error.code = 'EPERM';
        throw error;
      }
      return fs.unlinkSync(target);
    },
  };
  const callbackError = new Error('synthetic mutation failure');

  assert.throws(
    () => fileMutationLock.withFileMutationLockSync(file, () => { throw callbackError; }, { fs: fsImpl }),
    (error) => error === callbackError
      && error.cleanupError
      && error.cleanupError.code === 'FILE_MUTATION_LOCK_CLEANUP',
  );

  denyOwnerUnlink = false;
  const recovered = fileMutationLock.acquireFileMutationLockSync(file, { fs: fsImpl, lockTimeoutMs: 200 });
  fileMutationLock.releaseFileMutationLock(recovered);
  assert.strictEqual(fs.existsSync(fileMutationLock.lockPathFor(file)), false);
});

test('a delayed empty-directory reclaimer preserves a concurrently published owner', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-policy-lock-empty-replacement-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'policy.json');
  const lockPath = fileMutationLock.lockPathFor(file);
  const fsImpl = windowsRenameSemantics();
  fs.mkdirSync(lockPath, { mode: 0o700 });
  let replacement;
  let hookCalls = 0;

  assert.throws(() => fileMutationLock.acquireFileMutationLockSync(file, {
    fs: fsImpl,
    lockTimeoutMs: 40,
    lockRetryMs: 5,
    onBeforeEmptyReclaim() {
      hookCalls += 1;
      fs.rmdirSync(lockPath);
      replacement = fileMutationLock.acquireFileMutationLockSync(file, {
        fs: fsImpl,
        lockTimeoutMs: 100,
      });
    },
  }), (error) => error && error.code === 'FILE_MUTATION_LOCK_TIMEOUT');

  assert.strictEqual(hookCalls, 1);
  assert.ok(replacement);
  assert.strictEqual(fs.readFileSync(replacement.ownerPath, 'utf8'), replacement.contents);
  fileMutationLock.releaseFileMutationLock(replacement);
});

test('lock release never removes a replacement owned by another writer', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-policy-lock-owner-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'policy.json');
  const lock = fileMutationLock.acquireFileMutationLockSync(file);
  fs.closeSync(lock.fd);
  removeExactLockOwner(lock.lockPath, lock.ownerPath);
  const replacement = fileMutationLock.acquireFileMutationLockSync(file);
  fileMutationLock.releaseFileMutationLock(lock);

  assert.strictEqual(fs.readFileSync(replacement.ownerPath, 'utf8'), replacement.contents);
  fileMutationLock.releaseFileMutationLock(replacement);
});

test('a crashed lock owner is proven dead and reclaimed before the next policy write', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-policy-lock-crash-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'policy.json');
  const ready = path.join(dir, 'crash-ready');
  const baseline = { ...policy.DEFAULT_POLICY, enforcementMode: 'block' };
  writeConfig(file, baseline);
  const crashed = launchMutationWorker('lock-crash', {
    MUTATION_TARGET: file,
    MUTATION_READY: ready,
  });
  await waitForFile(crashed, ready);
  if (crashed.exitCode === null) await new Promise((resolve) => crashed.once('exit', resolve));
  assert.strictEqual(crashed.exitCode, 17, crashed.output);
  assert.strictEqual(fs.existsSync(fileMutationLock.lockPathFor(file)), true);

  policy.withPolicyFileMutation(baseline, ({ write }) => {
    write({ ...baseline, enforcementMode: 'warn' });
  }, { configPath: file, lockTimeoutMs: 1000 });

  assert.strictEqual(JSON.parse(fs.readFileSync(file, 'utf8')).enforcementMode, 'warn');
  assert.strictEqual(fs.existsSync(fileMutationLock.lockPathFor(file)), false);
});

test('a restarted container process reclaims a crashed same-PID prior instance', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-policy-lock-container-restart-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'policy.json');
  const ready = path.join(dir, 'container-crash-ready');
  const baseline = { ...policy.DEFAULT_POLICY, enforcementMode: 'block' };
  writeConfig(file, baseline);
  const crashed = launchMutationWorker('lock-crash', {
    MUTATION_TARGET: file,
    MUTATION_READY: ready,
    MUTATION_HOSTNAME: 'redactwall',
    MUTATION_PID: '1',
    MUTATION_PROCESS_START: '1000',
  });
  await waitForFile(crashed, ready);
  if (crashed.exitCode === null) await new Promise((resolve) => crashed.once('exit', resolve));
  assert.strictEqual(crashed.exitCode, 17, crashed.output);

  policy.withPolicyFileMutation(baseline, ({ write }) => {
    write({ ...baseline, enforcementMode: 'justify' });
  }, {
    configPath: file,
    hostname: 'redactwall',
    pid: 1,
    processStart: '2000',
    processKill: () => { throw new Error('same-PID restart should not need a liveness probe'); },
    lockTimeoutMs: 1000,
  });

  assert.strictEqual(JSON.parse(fs.readFileSync(file, 'utf8')).enforcementMode, 'justify');
  assert.strictEqual(fs.existsSync(fileMutationLock.lockPathFor(file)), false);
});

test('three processes preserve a replacement owner during a delayed reclaim interleaving', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-policy-lock-three-process-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'policy.json');
  const crashedReady = path.join(dir, 'crashed-ready');
  const reclaimValidated = path.join(dir, 'reclaim-validated');
  const reclaimContinue = path.join(dir, 'reclaim-continue');
  const reclaimWaiting = path.join(dir, 'reclaim-waiting');
  const reclaimDone = path.join(dir, 'reclaim-done');
  const replacementReady = path.join(dir, 'replacement-ready');
  const replacementRelease = path.join(dir, 'replacement-release');
  const replacementDone = path.join(dir, 'replacement-done');
  const common = {
    MUTATION_TARGET: file,
    MUTATION_HOSTNAME: 'redactwall-three-process',
  };
  const crashed = launchMutationWorker('lock-crash', {
    ...common,
    MUTATION_READY: crashedReady,
    MUTATION_PID: '1',
    MUTATION_PROCESS_START: '1000',
    MUTATION_GENERATION: GENERATION_A,
  });
  await waitForFile(crashed, crashedReady);
  if (crashed.exitCode === null) await new Promise((resolve) => crashed.once('exit', resolve));
  assert.strictEqual(crashed.exitCode, 17, crashed.output);

  const reclaimer = launchMutationWorker('lock-reclaim', {
    ...common,
    MUTATION_GENERATION: GENERATION_B,
    MUTATION_RECLAIM_READY: reclaimValidated,
    MUTATION_RECLAIM_CONTINUE: reclaimContinue,
    MUTATION_WAITING: reclaimWaiting,
    MUTATION_DONE: reclaimDone,
  });
  t.after(() => { if (reclaimer.exitCode === null) reclaimer.kill(); });
  await waitForFile(reclaimer, reclaimValidated);

  const replacement = launchMutationWorker('lock-hold', {
    ...common,
    MUTATION_GENERATION: GENERATION_B,
    MUTATION_READY: replacementReady,
    MUTATION_RELEASE: replacementRelease,
    MUTATION_DONE: replacementDone,
  });
  t.after(() => { if (replacement.exitCode === null) replacement.kill(); });
  await waitForFile(replacement, replacementReady);

  fs.writeFileSync(reclaimContinue, 'continue\n');
  await waitForFile(reclaimer, reclaimWaiting);
  const active = JSON.parse(readLockOwner(fileMutationLock.lockPathFor(file)).contents);
  assert.strictEqual(active.pid, replacement.pid);
  assert.strictEqual(active.generation, GENERATION_B);
  assert.strictEqual(fs.existsSync(reclaimDone), false, 'late reclaimer remains excluded by the replacement owner');

  fs.writeFileSync(replacementRelease, 'release\n');
  await Promise.all([waitForExit(replacement), waitForExit(reclaimer)]);
  assert.strictEqual(fs.existsSync(replacementDone), true);
  assert.strictEqual(fs.existsSync(reclaimDone), true);
  assert.strictEqual(fs.existsSync(fileMutationLock.lockPathFor(file)), false);
});

test('two policy processes serialize failed rollback before a successful writer', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-policy-two-process-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'policy.json');
  const expectedFile = path.join(dir, 'expected.json');
  const ready = path.join(dir, 'failed-ready');
  const release = path.join(dir, 'release-failed');
  const successStarted = path.join(dir, 'success-started');
  const successWaiting = path.join(dir, 'success-waiting');
  const failedDone = path.join(dir, 'failed-done');
  const successDone = path.join(dir, 'success-done');
  const winningBytes = path.join(dir, 'winning-bytes');
  const baseline = { ...policy.DEFAULT_POLICY, enforcementMode: 'block' };
  const baselineBytes = Buffer.from(`${JSON.stringify(baseline, null, 2)}\n\n`);
  fs.writeFileSync(file, baselineBytes);
  fs.writeFileSync(expectedFile, JSON.stringify(baseline));
  const common = {
    MUTATION_TARGET: file,
    MUTATION_EXPECTED: expectedFile,
    MUTATION_READY: ready,
    MUTATION_RELEASE: release,
    REDACTWALL_POLICY_PATH: file,
  };
  const failing = launchMutationWorker('policy-fail', { ...common, MUTATION_DONE: failedDone });
  t.after(() => { if (failing.exitCode === null) failing.kill(); });
  await waitForFile(failing, ready);
  assert.strictEqual(JSON.parse(fs.readFileSync(file, 'utf8')).enforcementMode, 'justify');

  const succeeding = launchMutationWorker('policy-success', {
    ...common,
    MUTATION_STARTED: successStarted,
    MUTATION_WAITING: successWaiting,
    MUTATION_DONE: successDone,
    MUTATION_WINNER_BYTES: winningBytes,
  });
  t.after(() => { if (succeeding.exitCode === null) succeeding.kill(); });
  await waitForFile(succeeding, successStarted);
  await waitForFile(succeeding, successWaiting);
  assert.strictEqual(fs.existsSync(successDone), false, 'successful writer remains excluded while rollback is pending');

  fs.writeFileSync(release, 'release\n');
  await Promise.all([waitForExit(failing), waitForExit(succeeding)]);
  assert.strictEqual(fs.existsSync(failedDone), true);
  assert.strictEqual(fs.existsSync(successDone), true);
  assert.deepStrictEqual(fs.readFileSync(file), fs.readFileSync(winningBytes));
  assert.strictEqual(JSON.parse(fs.readFileSync(file, 'utf8')).enforcementMode, 'warn');
  assert.strictEqual(fs.existsSync(fileMutationLock.lockPathFor(file)), false);
});
