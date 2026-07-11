'use strict';
/** Admin auth: password check, brute-force lockout, session signing. node --test */
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const { execFileSync, spawn } = require('node:child_process');
const path = require('node:path');

process.env.ADMIN_PASSWORD = 'unit-pass';
process.env.ADMIN_TOTP_SECRET = 'JBSWY3DPEHPK3PXP';
process.env.APPROVER_USER = 'approver';
process.env.APPROVER_PASSWORD = 'approver-pass';
process.env.AUDITOR_USER = 'auditor';
process.env.AUDITOR_PASSWORD = 'auditor-pass';
process.env.REDACTWALL_SECRET = 'unit-secret-stable';
process.env.LOGIN_MAX_ATTEMPTS = '3';
process.env.LOGIN_WINDOW_MS = '100000';
const auth = require('../server/auth');
const privatePaths = require('../server/private-path');
const fileMutationLock = require('../server/file-mutation-lock');
const TEST_OWNER_IDENTITY = Object.freeze({
  processSid: 'S-1-5-21-100-200-300-1001',
  ownerSid: 'S-1-5-21-100-200-300-1001',
});

function resolveSecretInChild(dataDir) {
  const script = [
    "const auth = require('./server/auth');",
    'const stored = auth._internal.resolveSecret({ env: process.env });',
    "process.stdout.write(JSON.stringify({ ...stored, liveKey: auth.deriveKey('bootstrap-stress').toString('hex') }));",
  ].join('');
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['-e', script], {
      cwd: path.join(__dirname, '..'),
      env: {
        ...process.env,
        REDACTWALL_SECRET: '',
        PROMPTWALL_SECRET: '',
        SENTINEL_SECRET: '',
        REDACTWALL_DATA_DIR: dataDir,
        PROMPTWALL_DATA_DIR: '',
        SENTINEL_DATA_DIR: '',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', reject);
    child.on('exit', (code) => {
      if (code !== 0) return reject(new Error(`secret child failed (${code}): ${stderr}`));
      try { resolve(JSON.parse(stdout)); } catch (error) { reject(error); }
    });
  });
}

function crashPrivateInitialization(directory, target) {
  const script = [
    "const privatePaths = require('./server/private-path');",
    "const locks = require('./server/file-mutation-lock');",
    'privatePaths.withPrivateDirectoryMutationLockSync(process.env.MUTATION_DIRECTORY, () => {',
    'locks.acquireFileMutationLockSync(process.env.MUTATION_TARGET, { lockTimeoutMs: 30000 });',
    'process.exit(17);',
    '});',
  ].join('');
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['-e', script], {
      cwd: path.join(__dirname, '..'),
      env: { ...process.env, MUTATION_DIRECTORY: directory, MUTATION_TARGET: target },
      stdio: ['ignore', 'ignore', 'pipe'],
      windowsHide: true,
    });
    let stderr = '';
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', reject);
    child.on('exit', (code) => code === 17 ? resolve() : reject(new Error(stderr || `lock crash exited ${code}`)));
  });
}

function secureExistingState(directory, file) {
  privatePaths.securePrivatePath(directory, { directory: true, label: 'test private directory' });
  if (file) privatePaths.securePrivatePath(file, { label: 'test private file' });
}

function signedSession(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const mac = crypto.createHmac('sha256', process.env.REDACTWALL_SECRET).update(body).digest('base64url');
  return `${body}.${mac}`;
}

function responseCapture() {
  return {
    statusCode: null,
    body: null,
    redirectTo: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(body) {
      this.body = body;
      return this;
    },
    redirect(url) {
      this.redirectTo = url;
      return this;
    },
  };
}

test('verifyPassword accepts only the right user+password', () => {
  assert.ok(auth.verifyPassword('admin', 'unit-pass'));
  assert.ok(auth.verifyPassword('approver', 'approver-pass'));
  assert.ok(auth.verifyPassword('auditor', 'auditor-pass'));
  assert.ok(!auth.verifyPassword('admin', 'wrong'));
  assert.ok(!auth.verifyPassword('approver', 'unit-pass'));
  assert.ok(!auth.verifyPassword('auditor', 'unit-pass'));
  assert.ok(!auth.verifyPassword('mallory', 'unit-pass'));
});

test('authenticate returns the account role without leaking hashes', () => {
  assert.deepStrictEqual(auth.authenticate('admin', 'unit-pass'), {
    user: 'admin',
    role: 'security_admin',
  });
  assert.deepStrictEqual(auth.authenticate('approver', 'approver-pass'), {
    user: 'approver',
    role: 'approver',
  });
  assert.deepStrictEqual(auth.authenticate('auditor', 'auditor-pass'), {
    user: 'auditor',
    role: 'auditor',
  });
  assert.strictEqual(auth.authenticate('approver', 'wrong'), null);
  assert.strictEqual(auth.authenticate('auditor', 'wrong'), null);
  assert.strictEqual(auth.APPROVER_ENABLED, true);
  assert.strictEqual(auth.AUDITOR_ENABLED, true);
});

test('totp codes verify for the configured admin mfa secret', () => {
  const now = 1700000000000;
  const code = auth.totpCode(process.env.ADMIN_TOTP_SECRET, now);
  assert.match(code, /^\d{6}$/);
  assert.strictEqual(auth.verifyTotpCode(code, now), true);
  assert.strictEqual(auth.verifyTotpCode(code, now + 30000), true, 'one time step of skew is accepted');
  assert.strictEqual(auth.verifyTotpCode(code, now + 90000), false, 'wide clock skew is rejected');
  assert.strictEqual(auth.verifyTotpCode(code === '000000' ? '111111' : '000000', now), false);
  assert.strictEqual(auth.totpCode('not-valid', now), null);
  assert.strictEqual(auth.ADMIN_MFA_REQUIRED, true);
  assert.strictEqual(auth.ADMIN_MFA_CONFIGURED, true);
});

test('locks out after the configured number of failures, resets on success', () => {
  const k = 'admin|10.0.0.5';
  assert.strictEqual(auth.loginStatus(k).locked, false);
  auth.registerFail(k); auth.registerFail(k);
  assert.strictEqual(auth.loginStatus(k).locked, false, 'not locked before threshold');
  const r = auth.registerFail(k); // 3rd
  assert.ok(r.locked && auth.loginStatus(k).locked, 'locked at threshold');
  assert.ok(auth.loginStatus(k).retryMs > 0);
  auth.registerSuccess(k);
  assert.strictEqual(auth.loginStatus(k).locked, false, 'success clears the lock');
});

test('lockout expires after the configured window and a correct login succeeds again', () => {
  const script = [
    "const auth = require('./server/auth');",
    "const k = 'admin|10.0.0.9';",
    "auth.registerFail(k); auth.registerFail(k);",
    "const locked = auth.registerFail(k).locked && auth.loginStatus(k).locked;",
    "setTimeout(() => {",
    "  console.log(JSON.stringify({ locked, after: auth.loginStatus(k), login: auth.authenticate('admin', 'unit-pass') }));",
    "}, 150);",
  ].join('');
  const output = execFileSync(process.execPath, ['-e', script], {
    cwd: path.join(__dirname, '..'),
    env: {
      ...process.env,
      LOGIN_MAX_ATTEMPTS: '3',
      LOGIN_WINDOW_MS: '50',
      REDACTWALL_SECRET: 'unit-secret-stable',
    },
    encoding: 'utf8',
  });
  const result = JSON.parse(output);
  assert.strictEqual(result.locked, true, 'locked at threshold before the window elapses');
  assert.deepStrictEqual(result.after, { locked: false }, 'lock releases once the window passes');
  assert.deepStrictEqual(result.login, { user: 'admin', role: 'security_admin' });
});

test('tracked attempt keys stay under the configured hard cap', () => {
  const script = [
    "const auth = require('./server/auth');",
    "for (let i = 0; i < 100; i += 1) auth.registerFail('spray-' + i);",
    "process.stdout.write(String(auth._internal.attemptCount()));",
  ].join('');
  const output = execFileSync(process.execPath, ['-e', script], {
    cwd: path.join(__dirname, '..'),
    env: { ...process.env, LOGIN_MAX_TRACKED_KEYS: '3' },
    encoding: 'utf8',
  });
  assert.strictEqual(Number(output), 3);
});

test('invalid or unsafe login limiter configuration falls back to bounded defaults', () => {
  const script = "process.stdout.write(JSON.stringify(require('./server/auth')._internal.loginLimits));";
  const invalidValues = ['Infinity', 'NaN', '0', '-1', '1.5', '999999999999999999999'];
  for (const value of invalidValues) {
    const output = execFileSync(process.execPath, ['-e', script], {
      cwd: path.join(__dirname, '..'),
      env: {
        ...process.env,
        LOGIN_MAX_ATTEMPTS: value,
        LOGIN_WINDOW_MS: value,
        LOGIN_MAX_TRACKED_KEYS: value,
      },
      encoding: 'utf8',
    });
    assert.deepStrictEqual(JSON.parse(output), {
      maxAttempts: 7,
      windowMs: 15 * 60 * 1000,
      maxAttemptKeys: 10000,
    }, `unsafe limiter value ${value} must not weaken the defaults`);
  }
});

test('session token signs and verifies; tampered/none rejected', () => {
  const t = auth.createSession('admin');
  assert.strictEqual(auth.verify(t).user, 'admin');
  assert.strictEqual(auth.verify(t).role, 'security_admin');
  const auditor = auth.createSession('auditor', 'auditor');
  assert.strictEqual(auth.verify(auditor).user, 'auditor');
  assert.strictEqual(auth.verify(auditor).role, 'auditor');
  const approver = auth.createSession('approver', 'approver');
  assert.strictEqual(auth.verify(approver).user, 'approver');
  assert.strictEqual(auth.verify(approver).role, 'approver');
  assert.strictEqual(auth.verify('bad.token'), null);
  assert.strictEqual(auth.verify(null), null);
});

test('session secret resolution uses durable storage and fails closed when storage is unavailable', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-auth-secret-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));

  assert.deepStrictEqual(auth._internal.resolveSecret({
    env: { REDACTWALL_SECRET: 'env-secret' },
    dataDir: dir,
  }), {
    secret: 'env-secret',
    source: 'env',
  });

  const existingDir = path.join(dir, 'existing');
  fs.mkdirSync(existingDir, { mode: 0o700 });
  const fileSecret = '12'.repeat(32);
  const existingFile = path.join(existingDir, '.session-secret');
  fs.writeFileSync(existingFile, fileSecret, { mode: 0o600 });
  secureExistingState(existingDir, existingFile);
  assert.deepStrictEqual(auth._internal.resolveSecret({
    env: {},
    dataDir: existingDir,
  }), {
    secret: fileSecret,
    source: 'file',
  });

  const generatedDir = path.join(dir, 'generated');
  const generated = auth._internal.resolveSecret({
    env: {},
    dataDir: generatedDir,
    randomBytes: () => Buffer.alloc(32, 0xab),
  });
  assert.deepStrictEqual(generated, {
    secret: 'ab'.repeat(32),
    source: 'generated',
  });
  assert.strictEqual(fs.readFileSync(path.join(generatedDir, '.session-secret'), 'utf8'), generated.secret);

  assert.throws(() => auth._internal.resolveSecret({
    env: {},
    dataDir: path.join(dir, 'denied'),
    fs: {
      ...fs,
      mkdirSync() {
        throw new Error('storage denied');
      },
    },
  }), /storage denied/);
});

test('eight concurrent local processes converge on one exclusively published session secret', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-auth-secret-converge-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));

  const results = await Promise.all(Array.from({ length: 8 }, () => resolveSecretInChild(dir)));
  const persisted = fs.readFileSync(path.join(dir, '.session-secret'), 'utf8');

  assert.match(persisted, /^[a-f0-9]{64}$/);
  assert.ok(results.every((result) => result.secret === persisted));
  assert.ok(results.every((result) => result.source === 'file'));
  const expectedLiveKey = crypto.createHash('sha256').update(`bootstrap-stress:${persisted}`).digest('hex');
  assert.ok(results.every((result) => result.liveKey === expectedLiveKey));
  assert.strictEqual(fs.existsSync(path.join(dir, '..session-secret.mutation.lock')), false);
  assert.deepStrictEqual(fs.readdirSync(dir).filter((name) => name.endsWith('.tmp')), []);
  if (process.platform === 'win32') {
    assert.doesNotThrow(() => privatePaths.assertPrivatePath(dir, {
      directory: true,
      label: 'session secret directory',
    }));
    assert.doesNotThrow(() => privatePaths.assertPrivatePath(path.join(dir, '.session-secret'), {
      label: 'session secret',
    }));
  }
});

test('session-secret initialization honors its full sixty-second lock budget', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-auth-secret-lock-budget-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  privatePaths.withPrivateDirectoryMutationLockSync(dir, () => {}, {
    directory: true,
    label: 'session secret test directory',
  });
  const lockTarget = privatePaths.privateDirectoryLockTarget(dir);
  const held = fileMutationLock.acquireFileMutationLockSync(lockTarget);
  try {
    const times = [0, 30_000, auth._internal.PRIVATE_INIT_LOCK_TIMEOUT_MS];
    let index = 0;
    let observed = 0;
    assert.throws(() => auth._internal.resolveSecret({
      dataDir: dir,
      env: {},
      lockOptions: {
        now() {
          observed = times[Math.min(index, times.length - 1)];
          index += 1;
          return observed;
        },
        sleep() {},
      },
    }), (error) => error && error.code === 'FILE_MUTATION_LOCK_TIMEOUT');
    assert.strictEqual(observed, auth._internal.PRIVATE_INIT_LOCK_TIMEOUT_MS);
  } finally {
    fileMutationLock.releaseFileMutationLock(held);
  }
});

test('session secret hardens its directory before acquiring the target publication lock', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-auth-secret-lock-order-'));
  const dir = path.join(root, 'data');
  const target = path.join(dir, '.session-secret');
  const lockPath = fileMutationLock.lockPathFor(target);
  const principal = 'TEST\\session-user';
  const privatePathSecurity = {
    platform: 'win32',
    principal,
    ownerIdentity: TEST_OWNER_IDENTITY,
    privateLockRoot: path.join(root, 'locks'),
  };
  const directoryLockPath = fileMutationLock.lockPathFor(
    privatePaths.privateDirectoryLockTarget(dir, privatePathSecurity),
  );
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  let directoryObserved = false;
  let publicationObserved = false;
  let directorySecured = false;
  auth._internal.resolveSecret({
    env: {},
    dataDir: dir,
    randomBytes: () => Buffer.alloc(32, 0xcd),
    privatePathSecurity: {
      ...privatePathSecurity,
      spawn(command, args) {
        if (args[0] === dir && args.includes('/grant:r')) {
          directoryObserved = !fs.existsSync(lockPath) && fs.existsSync(directoryLockPath);
          directorySecured = true;
        }
        if (args[0].endsWith('.tmp') && args.includes('/grant:r')) {
          publicationObserved = fs.existsSync(lockPath) && fs.existsSync(directoryLockPath);
        }
        const broad = `${args[0]} ${principal}:(F)\r\n BUILTIN\\Users:(R)\r\n NT AUTHORITY\\SYSTEM:(F)`;
        return args.length === 1
          ? { status: 0, stdout: args[0] === dir && !directorySecured ? broad : `${args[0]} ${principal}:(F)\r\n NT AUTHORITY\\SYSTEM:(F)` }
          : { status: 0, stdout: 'processed 1 file' };
      },
    },
  });
  assert.strictEqual(directoryObserved, true);
  assert.strictEqual(publicationObserved, true);
  assert.strictEqual(fs.existsSync(lockPath), false);
  assert.strictEqual(fs.existsSync(directoryLockPath), false);
});

test('session secret rejects bytes planted while an inherited directory ACL is being removed', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-auth-secret-preseed-'));
  const dir = path.join(root, 'data');
  const target = path.join(dir, '.session-secret');
  const principal = 'TEST\\session-user';
  let directorySecured = false;
  let planted = false;
  let generated = false;
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const options = {
    env: {},
    dataDir: dir,
    randomBytes() { generated = true; return Buffer.alloc(32, 0xaa); },
    privatePathSecurity: {
      platform: 'win32',
      principal,
      ownerIdentity: TEST_OWNER_IDENTITY,
      privateLockRoot: path.join(root, 'locks'),
      spawn(command, args) {
        if (args[0] === dir && args.includes('/reset')) {
          fs.writeFileSync(target, '42'.repeat(32), { mode: 0o600 });
          planted = true;
        }
        if (args[0] === dir && args.includes('/grant:r')) directorySecured = true;
        const exact = `${args[0]} ${principal}:(F)\r\n NT AUTHORITY\\SYSTEM:(F)`;
        const broad = `${exact}\r\n BUILTIN\\Users:(R)`;
        return args.length === 1
          ? { status: 0, stdout: args[0] === dir && !directorySecured ? broad : exact }
          : { status: 0, stdout: 'processed 1 file' };
      },
    },
  };
  assert.throws(() => auth._internal.resolveSecret(options), /before its permissions were trusted/);
  assert.strictEqual(planted, true);
  assert.strictEqual(generated, false);
  assert.strictEqual(fs.readFileSync(target, 'utf8'), '42'.repeat(32));
  assert.throws(
    () => auth._internal.resolveSecret(options),
    /before its permissions were trusted/,
    'the next process must not accept bytes left behind after the first rejection',
  );
  assert.strictEqual(generated, false);
});

test('session secret startup reclaims a crashed directory-bootstrap lock', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-auth-secret-crash-'));
  const target = path.join(dir, '.session-secret');
  const bootstrapTarget = privatePaths.privateDirectoryLockTarget(dir);
  const lockPath = fileMutationLock.lockPathFor(bootstrapTarget);
  const targetLockPath = fileMutationLock.lockPathFor(target);
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));

  await crashPrivateInitialization(dir, target);
  assert.strictEqual(fs.existsSync(lockPath), true);
  assert.strictEqual(fs.existsSync(targetLockPath), true);
  const result = await resolveSecretInChild(dir);
  assert.match(result.secret, /^[a-f0-9]{64}$/);
  assert.strictEqual(fs.readFileSync(target, 'utf8'), result.secret);
  assert.strictEqual(fs.existsSync(lockPath), false);
  assert.strictEqual(fs.existsSync(targetLockPath), false);
});

test('session secret storage honors RedactWall and legacy data-directory aliases', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-auth-secret-alias-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const [index, variable] of [
    'REDACTWALL_DATA_DIR',
    'PROMPTWALL_DATA_DIR',
    'SENTINEL_DATA_DIR',
  ].entries()) {
    await t.test(variable, () => {
      const dir = path.join(root, String(index));
      const result = auth._internal.resolveSecret({
        env: { [variable]: dir },
        randomBytes: () => Buffer.alloc(32, index + 1),
      });
      assert.strictEqual(result.secret, (index + 1).toString(16).padStart(2, '0').repeat(32));
      assert.strictEqual(fs.readFileSync(path.join(dir, '.session-secret'), 'utf8'), result.secret);
    });
  }
});

test('session secret resolution refuses corrupt, oversized, and symlink storage', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-auth-secret-invalid-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const [label, contents, expected] of [
    ['corrupt', 'z'.repeat(64), /corrupt/],
    ['oversized', 'a'.repeat(65), /invalid size/],
  ]) {
    await t.test(label, () => {
      const dir = path.join(root, label);
      const secretPath = path.join(dir, '.session-secret');
      fs.mkdirSync(dir, { mode: 0o700 });
      fs.writeFileSync(secretPath, contents, { mode: 0o600 });
      secureExistingState(dir, secretPath);
      assert.throws(() => auth._internal.resolveSecret({ env: {}, dataDir: dir }), expected);
      assert.strictEqual(fs.readFileSync(secretPath, 'utf8'), contents, 'invalid bytes are never rotated or replaced');
      assert.deepStrictEqual(fs.readdirSync(dir), ['.session-secret']);
    });
  }

  await t.test('symlink', () => {
    const dir = path.join(root, 'symlink');
    const target = path.join(root, 'symlink-target');
    const secretPath = path.join(dir, '.session-secret');
    fs.mkdirSync(dir, { mode: 0o700 });
    secureExistingState(dir);
    fs.writeFileSync(target, 'ab'.repeat(32), { mode: 0o600 });
    try {
      fs.symlinkSync(target, secretPath, 'file');
    } catch (error) {
      if (error && ['EPERM', 'EACCES'].includes(error.code)) {
        const junctionTarget = path.join(root, 'symlink-target-directory');
        fs.mkdirSync(junctionTarget);
        fs.symlinkSync(junctionTarget, secretPath, 'junction');
      } else {
        throw error;
      }
    }
    assert.throws(
      () => auth._internal.resolveSecret({ env: {}, dataDir: dir }),
      /not a safe regular file/,
    );
    assert.strictEqual(fs.lstatSync(secretPath).isSymbolicLink(), true);
    assert.strictEqual(fs.readFileSync(target, 'utf8'), 'ab'.repeat(32));
  });
});

test('generated session-secret directory and file satisfy the Windows private ACL contract', {
  skip: process.platform !== 'win32',
}, (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-auth-secret-acl-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  auth._internal.resolveSecret({ env: {}, dataDir: dir });

  assert.doesNotThrow(() => privatePaths.assertPrivatePath(dir, {
    directory: true,
    label: 'session secret directory',
  }));
  assert.doesNotThrow(() => privatePaths.assertPrivatePath(path.join(dir, '.session-secret'), {
    directory: false,
    label: 'session secret',
  }));
});

test('oidc session extras are signed and can satisfy fresh step-up', () => {
  const now = Date.now();
  const token = auth.createSession('reviewer@example.test', 'approver', {
    provider: 'oidc',
    idpSubject: 'subject-1',
    idpIssuer: 'https://login.example.test',
    stepUpUntil: now + 60000,
  });
  const verified = auth.verify(token);
  assert.strictEqual(verified.user, 'reviewer@example.test');
  assert.strictEqual(verified.role, 'approver');
  assert.strictEqual(verified.provider, 'oidc');
  assert.strictEqual(verified.idpSubject, 'subject-1');
  assert.strictEqual(verified.idpIssuer, 'https://login.example.test');
  assert.strictEqual(auth.oidcStepUpSatisfied(verified, now), true);
  assert.strictEqual(auth.oidcStepUpSatisfied({ ...verified, stepUpUntil: now - 1 }, now), false);
  assert.strictEqual(auth.oidcStepUpSatisfied({ user: 'admin', role: 'security_admin' }, now), false);
});

test('session verification preserves legacy admin cookies and rejects unknown roles', () => {
  const legacy = signedSession({ user: 'admin', iat: Date.now(), exp: Date.now() + 60000 });
  const verifiedLegacy = auth.verify(legacy);
  assert.deepStrictEqual(verifiedLegacy, {
    user: 'admin',
    role: 'security_admin',
    iat: verifiedLegacy.iat,
    exp: verifiedLegacy.exp,
    stepUpUntil: 0,
  });

  const unknownRole = signedSession({ user: 'admin', role: 'owner', iat: Date.now(), exp: Date.now() + 60000 });
  assert.strictEqual(auth.verify(unknownRole), null);
  const missingUser = signedSession({ role: 'security_admin', iat: Date.now(), exp: Date.now() + 60000 });
  assert.strictEqual(auth.verify(missingUser), null);
});

test('duplicate auditor username is not enabled at runtime', () => {
  const script = [
    "const auth = require('./server/auth');",
    "console.log(JSON.stringify({ enabled: auth.AUDITOR_ENABLED, admin: auth.authenticate('admin', 'unit-pass'), duplicate: auth.authenticate('admin', 'auditor-pass') }));",
  ].join('');
  const output = execFileSync(process.execPath, ['-e', script], {
    cwd: path.join(__dirname, '..'),
    env: {
      ...process.env,
      ADMIN_USER: 'admin',
      ADMIN_PASSWORD: 'unit-pass',
      AUDITOR_USER: ' admin ',
      AUDITOR_PASSWORD: 'auditor-pass',
      REDACTWALL_SECRET: 'unit-secret-stable',
    },
    encoding: 'utf8',
  });
  const result = JSON.parse(output);
  assert.strictEqual(result.enabled, false);
  assert.deepStrictEqual(result.admin, { user: 'admin', role: 'security_admin' });
  assert.strictEqual(result.duplicate, null);
});

test('csrf token is bound to the signed session token', () => {
  const t = auth.createSession('admin');
  const csrf = auth.createCsrfToken(t);
  assert.ok(csrf);
  assert.strictEqual(auth.verifyCsrfToken(t, csrf), true);
  assert.strictEqual(auth.verifyCsrfToken(t, csrf + 'x'), false);
  assert.strictEqual(auth.verifyCsrfToken(auth.createSession('other-admin'), csrf), false);
});

test('auth middleware protects API and page routes and enforces roles', () => {
  const apiRes = responseCapture();
  auth.requireAuth({ path: '/api/audit', cookies: {} }, apiRes, () => {
    throw new Error('unauthenticated API should not continue');
  });
  assert.strictEqual(apiRes.statusCode, 401);
  assert.deepStrictEqual(apiRes.body, { error: 'unauthenticated' });

  const pageRes = responseCapture();
  auth.requireAuth({ path: '/app', cookies: {} }, pageRes, () => {
    throw new Error('unauthenticated page should not continue');
  });
  assert.strictEqual(pageRes.redirectTo, '/login.html');

  const req = { path: '/api/me', cookies: { [auth.SESSION_COOKIE_NAME]: auth.createSession('admin') } };
  let continued = false;
  auth.requireAuth(req, responseCapture(), () => { continued = true; });
  assert.strictEqual(continued, true);
  assert.strictEqual(req.user.role, 'security_admin');

  const forbidden = responseCapture();
  auth.requireRole('auditor')(req, forbidden, () => {
    throw new Error('wrong role should not continue');
  });
  assert.strictEqual(forbidden.statusCode, 403);
  assert.deepStrictEqual(forbidden.body, { error: 'forbidden' });

  let allowed = false;
  auth.requireRole('security_admin')(req, responseCapture(), () => { allowed = true; });
  assert.strictEqual(allowed, true);
});

test('requireRole with multiple roles allows any listed role and rejects unlisted ones', () => {
  const middleware = auth.requireRole('security_admin', 'approver');

  let allowed = false;
  middleware({ user: { user: 'approver', role: 'approver' } }, responseCapture(), () => { allowed = true; });
  assert.strictEqual(allowed, true, 'second listed role passes');

  const forbidden = responseCapture();
  middleware({ user: { user: 'auditor', role: 'auditor' } }, forbidden, () => {
    throw new Error('unlisted role should not continue');
  });
  assert.strictEqual(forbidden.statusCode, 403);
  assert.deepStrictEqual(forbidden.body, { error: 'forbidden' });
});

test('session verification strips forged idp extras from non-oidc cookies', () => {
  const forged = signedSession({
    user: 'admin',
    role: 'security_admin',
    provider: 'password',
    idpSubject: 'forged-subject',
    idpIssuer: 'https://forged-issuer.example.test',
    iat: Date.now(),
    exp: Date.now() + 60000,
  });
  const verified = auth.verify(forged);
  assert.strictEqual(verified.user, 'admin');
  assert.strictEqual(verified.role, 'security_admin');
  assert.ok(!('provider' in verified), 'non-oidc provider marker is dropped');
  assert.ok(!('idpSubject' in verified), 'forged idpSubject is stripped');
  assert.ok(!('idpIssuer' in verified), 'forged idpIssuer is stripped');
});

test('csrf middleware allows safe methods and rejects missing or wrong tokens', () => {
  const session = auth.createSession('admin');
  let safeContinued = false;
  auth.requireCsrf({ method: 'GET', cookies: {}, get: () => '' }, responseCapture(), () => { safeContinued = true; });
  assert.strictEqual(safeContinued, true);

  const rejected = responseCapture();
  auth.requireCsrf({
    method: 'POST',
    cookies: { [auth.SESSION_COOKIE_NAME]: session },
    get: () => '',
  }, rejected, () => {
    throw new Error('missing csrf should not continue');
  });
  assert.strictEqual(rejected.statusCode, 403);
  assert.deepStrictEqual(rejected.body, { error: 'invalid csrf token' });

  let unsafeContinued = false;
  auth.requireCsrf({
    method: 'POST',
    cookies: { [auth.SESSION_COOKIE_NAME]: session },
    get: (name) => (name === 'x-csrf-token' ? auth.createCsrfToken(session) : ''),
  }, responseCapture(), () => { unsafeContinued = true; });
  assert.strictEqual(unsafeContinued, true);
});

test('derived auth keys are purpose scoped and deterministic', () => {
  assert.strictEqual(auth.deriveKey('receipts').equals(auth.deriveKey('receipts')), true);
  assert.strictEqual(auth.deriveKey('receipts').equals(auth.deriveKey('other-purpose')), false);
});

test('session token lookup prefers RedactWall cookie with legacy fallback', () => {
  const redactwall = auth.createSession('admin');
  const legacy = auth.createSession('auditor', 'auditor');

  assert.strictEqual(auth.sessionTokenFromRequest({ cookies: { redactwall_session: redactwall } }), redactwall);
  assert.strictEqual(auth.sessionTokenFromRequest({ cookies: { sentinel_session: legacy } }), legacy);
  assert.strictEqual(auth.sessionTokenFromRequest({
    cookies: {
      redactwall_session: redactwall,
      sentinel_session: legacy,
    },
  }), redactwall);
  assert.strictEqual(auth.sessionTokenFromRequest({ cookies: {} }), '');
});

test('duplicate approver username is not enabled at runtime', () => {
  const script = [
    "const auth = require('./server/auth');",
    "console.log(JSON.stringify({ enabled: auth.APPROVER_ENABLED, admin: auth.authenticate('admin', 'unit-pass'), duplicate: auth.authenticate('admin', 'approver-pass') }));",
  ].join('');
  const output = execFileSync(process.execPath, ['-e', script], {
    cwd: path.join(__dirname, '..'),
    env: {
      ...process.env,
      ADMIN_USER: 'admin',
      ADMIN_PASSWORD: 'unit-pass',
      APPROVER_USER: ' admin ',
      APPROVER_PASSWORD: 'approver-pass',
      REDACTWALL_SECRET: 'unit-secret-stable',
    },
    encoding: 'utf8',
  });
  const result = JSON.parse(output);
  assert.strictEqual(result.enabled, false);
  assert.deepStrictEqual(result.admin, { user: 'admin', role: 'security_admin' });
  assert.strictEqual(result.duplicate, null);
});

test('secret from env is reported stable (survives restarts / multi-instance)', () => {
  assert.strictEqual(auth.SECRET_IS_STABLE, true);
});
