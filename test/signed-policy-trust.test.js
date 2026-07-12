'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const vm = require('node:vm');

const policyBundle = require('../server/policy-bundle');
const fileMutationLock = require('../server/file-mutation-lock');
const privatePaths = require('../server/private-path');
const signedPolicy = require('../sensors/shared/signed-policy');
const endpoint = require('../sensors/endpoint-agent/agent');
const mcp = require('../sensors/mcp-guard/guard');
const TEST_OWNER_IDENTITY = Object.freeze({
  processSid: 'S-1-5-21-100-200-300-1001',
  ownerSid: 'S-1-5-21-100-200-300-1001',
});

const roots = [];
function tempDir(label) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `redactwall-${label}-`));
  roots.push(dir);
  return dir;
}
test.after(() => roots.forEach((dir) => fs.rmSync(dir, { recursive: true, force: true })));

function signingFixture(label = 'signed-policy') {
  const dir = tempDir(label);
  const keyFile = path.join(dir, 'policy-key.pem');
  policyBundle._resetForTest();
  const publicKey = policyBundle.publicKeyPem({ keyFile, reload: true });
  const bundle = policyBundle.buildBundle({
    enforcementMode: 'block',
    alwaysBlock: ['US_SSN'],
    mcpAllowedTools: [],
    mcpBlockedTools: [],
    mcpApprovalRequiredTools: [],
  }, { keyFile });
  return { dir, keyFile, publicKey, bundle, cachePath: path.join(dir, 'lkg.json') };
}

function response(bundle, status = 200) {
  return new Response(JSON.stringify(bundle), { status, headers: { 'content-type': 'application/json' } });
}

function runKeyWorker(dataDir) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [path.join(__dirname, 'support', 'policy-key-worker.js')], {
      cwd: path.join(__dirname, '..'),
      env: { ...process.env, REDACTWALL_DATA_DIR: dataDir, NODE_ENV: 'production' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.once('error', reject);
    child.once('exit', (code) => code === 0 ? resolve(stdout.trim()) : reject(new Error(stderr || `worker exited ${code}`)));
  });
}

function runAuthWorker(dataDir) {
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
        NODE_ENV: 'production',
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
    child.once('error', reject);
    child.once('exit', (code) => {
      if (code !== 0) return reject(new Error(stderr || `auth worker exited ${code}`));
      try { return resolve(JSON.parse(stdout)); } catch { return reject(new Error('auth worker returned invalid JSON')); }
    });
  });
}

function runCacheWorker(bundleFile, publicKeyPath, cachePath) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [
      path.join(__dirname, 'support', 'policy-cache-worker.js'),
      bundleFile,
      publicKeyPath,
      cachePath,
    ], {
      cwd: path.join(__dirname, '..'),
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.once('error', reject);
    child.once('exit', (code) => {
      if (code !== 0) return reject(new Error(stderr || `cache worker exited ${code}`));
      try { return resolve(JSON.parse(stdout)); } catch { return reject(new Error('cache worker returned invalid JSON')); }
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
    child.once('error', reject);
    child.once('exit', (code) => code === 17 ? resolve() : reject(new Error(stderr || `lock crash exited ${code}`)));
  });
}

function runProductionScript(script) {
  return new Promise((resolve, reject) => {
    const env = { ...process.env, NODE_ENV: 'production' };
    delete env.NODE_TEST_CONTEXT;
    const child = spawn(process.execPath, ['-e', script], {
      cwd: path.join(__dirname, '..'),
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.once('error', reject);
    child.once('exit', (code) => {
      if (code !== 0) return reject(new Error(stderr || `production script exited ${code}`));
      return resolve(JSON.parse(stdout));
    });
  });
}

test('eight real processes initialize one stable durable signing identity', async () => {
  const dir = tempDir('policy-key-race');
  const fingerprints = await Promise.all(Array.from({ length: 8 }, () => runKeyWorker(dir)));
  assert.strictEqual(new Set(fingerprints).size, 1);
  const file = path.join(dir, '.policy-bundle-key.pem');
  assert.ok(fs.statSync(file).isFile());
  if (process.platform !== 'win32') assert.strictEqual(fs.statSync(file).mode & 0o077, 0);
  else {
    assert.doesNotThrow(() => require('../server/private-path').assertPrivatePath(dir, {
      directory: true,
      label: 'policy signing key directory',
    }));
    assert.doesNotThrow(() => require('../server/private-path').assertPrivatePath(file, {
      label: 'policy signing key',
    }));
  }
  assert.strictEqual(fs.readdirSync(dir).filter((name) => name.endsWith('.tmp') || name.endsWith('.lock')).length, 0);
});

test('policy signing-key startup reclaims a crashed directory-bootstrap lock', async () => {
  const dir = tempDir('policy-key-crash');
  const file = path.join(dir, '.policy-bundle-key.pem');
  const bootstrapTarget = privatePaths.privateDirectoryLockTarget(dir);
  const lockPath = fileMutationLock.lockPathFor(bootstrapTarget);
  const targetLockPath = fileMutationLock.lockPathFor(file);
  await crashPrivateInitialization(dir, file);
  assert.strictEqual(fs.existsSync(lockPath), true);
  assert.strictEqual(fs.existsSync(targetLockPath), true);

  const fingerprint = await runKeyWorker(dir);
  assert.match(fingerprint, /^[a-f0-9]{64}$/);
  assert.ok(fs.statSync(file).isFile());
  assert.strictEqual(fs.existsSync(lockPath), false);
  assert.strictEqual(fs.existsSync(targetLockPath), false);
});

test('an existing corrupt signing key is refused and never rotated', () => {
  const dir = tempDir('policy-key-corrupt');
  const file = path.join(dir, '.policy-bundle-key.pem');
  fs.writeFileSync(file, 'partial-key', { mode: 0o600 });
  privatePaths.securePrivatePath(dir, { directory: true, label: 'test policy-key directory' });
  privatePaths.securePrivatePath(file, { label: 'test policy key' });
  const before = fs.readFileSync(file);
  policyBundle._resetForTest();
  assert.throws(() => policyBundle.publicKeyPem({ keyFile: file, reload: true }), /unreadable or corrupt/);
  assert.deepStrictEqual(fs.readFileSync(file), before);
});

test('an unusable production key path fails without an ephemeral signing identity', () => {
  const dir = tempDir('policy-key-unusable');
  const blocker = path.join(dir, 'not-a-directory');
  fs.writeFileSync(blocker, 'occupied');
  const file = path.join(blocker, '.policy-bundle-key.pem');
  policyBundle._resetForTest();
  const status = policyBundle.signingKeyStatus({ keyFile: file, initialize: true, reload: true });
  assert.strictEqual(status.ok, false);
  assert.strictEqual(status.persistent, false);
  assert.throws(() => policyBundle.publicKeyPem({ keyFile: file, reload: true }));
  assert.strictEqual(fs.readFileSync(blocker, 'utf8'), 'occupied');
});

test('valid current and fresh cached bundles verify while tamper, expiry, wrong keys, and key swaps do not replace LKG', () => {
  const fixture = signingFixture();
  const options = { policyPublicKey: fixture.publicKey, policyCachePath: fixture.cachePath, sensorId: 'unit' };
  const accepted = signedPolicy.acceptSignedPolicyBundle(fixture.bundle, options);
  assert.strictEqual(accepted.ok, true);
  assert.strictEqual(accepted.persisted, true);

  const tampered = { ...fixture.bundle, policy: { ...fixture.bundle.policy, mcpAllowedTools: ['*'] } };
  assert.strictEqual(signedPolicy.acceptSignedPolicyBundle(tampered, options).ok, false);
  assert.deepStrictEqual(signedPolicy.readCachedSignedPolicy(options).policy, fixture.bundle.policy);

  const wrong = crypto.generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' }).toString();
  assert.strictEqual(signedPolicy.readCachedSignedPolicy({ ...options, policyPublicKey: wrong }).ok, false);
  assert.strictEqual(signedPolicy.acceptSignedPolicyBundle({ ...fixture.bundle, signature: 'x' }, options).ok, false);

  const expired = policyBundle.buildBundle(fixture.bundle.policy, {
    keyFile: fixture.keyFile,
    now: '2020-01-01T00:00:00.000Z',
    ttlMs: 1000,
  });
  assert.strictEqual(signedPolicy.acceptSignedPolicyBundle(expired, options).reason, 'expired');
  assert.deepStrictEqual(signedPolicy.readCachedSignedPolicy(options).policy, fixture.bundle.policy);
});

test('older signed policy replay is rejected by runtime and persisted high-water across restart', () => {
  const fixture = signingFixture('policy-rollback');
  const now = Date.now();
  const older = policyBundle.buildBundle({ ...fixture.bundle.policy, enforcementMode: 'warn' }, {
    keyFile: fixture.keyFile,
    now: new Date(now - (2 * 60 * 60 * 1000)).toISOString(),
    ttlMs: 24 * 60 * 60 * 1000,
  });
  const newer = policyBundle.buildBundle({ ...fixture.bundle.policy, enforcementMode: 'block' }, {
    keyFile: fixture.keyFile,
    now: new Date(now - (60 * 60 * 1000)).toISOString(),
    ttlMs: 61 * 60 * 1000,
  });
  const options = { policyPublicKey: fixture.publicKey, policyCachePath: fixture.cachePath, sensorId: 'rollback' };
  signedPolicy._resetForTest();
  assert.strictEqual(signedPolicy.acceptSignedPolicyBundle(newer, options).ok, true);
  const persisted = fs.readFileSync(fixture.cachePath);

  assert.strictEqual(signedPolicy.acceptSignedPolicyBundle(older, options).reason, 'rollback_detected');
  assert.deepStrictEqual(fs.readFileSync(fixture.cachePath), persisted);

  // Simulate a new sensor process after the newer LKG has expired. Its signed
  // issuedAt remains the durable high-water and an older long-lived replay is
  // still refused.
  signedPolicy._resetForTest();
  const restarted = signedPolicy.acceptSignedPolicyBundle(older, {
    ...options,
    now: now + (2 * 60 * 1000),
  });
  assert.strictEqual(restarted.reason, 'rollback_detected');
  assert.deepStrictEqual(fs.readFileSync(fixture.cachePath), persisted);
});

test('a newly verified policy is not activated when durable cache publication fails', () => {
  const fixture = signingFixture('policy-cache-write-failure');
  const now = Date.now();
  const older = policyBundle.buildBundle({ ...fixture.bundle.policy, enforcementMode: 'block' }, {
    keyFile: fixture.keyFile,
    now: new Date(now - (3 * 60 * 1000)).toISOString(),
    ttlMs: 60 * 60 * 1000,
  });
  const middle = policyBundle.buildBundle({ ...fixture.bundle.policy, enforcementMode: 'justify' }, {
    keyFile: fixture.keyFile,
    now: new Date(now - (2 * 60 * 1000)).toISOString(),
    ttlMs: 60 * 60 * 1000,
  });
  const newest = policyBundle.buildBundle({ ...fixture.bundle.policy, enforcementMode: 'warn' }, {
    keyFile: fixture.keyFile,
    now: new Date(now - (60 * 1000)).toISOString(),
    ttlMs: 60 * 60 * 1000,
  });
  const options = { policyPublicKey: fixture.publicKey, policyCachePath: fixture.cachePath, sensorId: 'write-failure' };
  signedPolicy._resetForTest();
  assert.strictEqual(signedPolicy.acceptSignedPolicyBundle(older, options).ok, true);
  const persisted = fs.readFileSync(fixture.cachePath);

  const failingFs = Object.create(fs);
  let failedPublication = false;
  failingFs.linkSync = (source, destination) => {
    if (!failedPublication && path.resolve(destination) === path.resolve(fixture.cachePath)) {
      failedPublication = true;
      const error = new Error('simulated cache publication failure');
      error.code = 'EACCES';
      throw error;
    }
    return fs.linkSync(source, destination);
  };
  const rejected = signedPolicy.acceptSignedPolicyBundle(newest, { ...options, fs: failingFs });
  assert.deepStrictEqual(rejected, { ok: false, reason: 'policy_cache_unavailable' });
  assert.strictEqual(failedPublication, true);
  assert.deepStrictEqual(fs.readFileSync(fixture.cachePath), persisted);

  // A failed publication must not advance the process-local high-water mark.
  // Otherwise this valid middle bundle would be rejected as a rollback.
  const accepted = signedPolicy.acceptSignedPolicyBundle(middle, options);
  assert.strictEqual(accepted.ok, true);
  assert.strictEqual(accepted.policy.enforcementMode, 'justify');
});

test('eight sensor processes serialize policy cache publication without losing the newest bundle', async () => {
  const fixture = signingFixture('policy-cache-race');
  const now = Date.now();
  const older = policyBundle.buildBundle({ ...fixture.bundle.policy, enforcementMode: 'warn' }, {
    keyFile: fixture.keyFile,
    now: new Date(now - (2 * 60 * 1000)).toISOString(),
    ttlMs: 60 * 60 * 1000,
  });
  const newer = policyBundle.buildBundle({ ...fixture.bundle.policy, enforcementMode: 'block' }, {
    keyFile: fixture.keyFile,
    now: new Date(now - (60 * 1000)).toISOString(),
    ttlMs: 60 * 60 * 1000,
  });
  const olderFile = path.join(fixture.dir, 'older.json');
  const newerFile = path.join(fixture.dir, 'newer.json');
  const publicKeyPath = path.join(fixture.dir, 'policy-public.pem');
  fs.writeFileSync(olderFile, JSON.stringify(older));
  fs.writeFileSync(newerFile, JSON.stringify(newer));
  fs.writeFileSync(publicKeyPath, fixture.publicKey, { mode: 0o600 });

  const results = await Promise.all(Array.from({ length: 8 }, (_, index) => (
    runCacheWorker(index % 2 ? newerFile : olderFile, publicKeyPath, fixture.cachePath)
  )));
  assert.ok(results.some((result) => result.ok));
  signedPolicy._resetForTest();
  const cached = signedPolicy.readCachedSignedPolicy({
    policyPublicKeyPath: publicKeyPath,
    policyCachePath: fixture.cachePath,
    sensorId: 'process-race',
  });
  assert.strictEqual(cached.ok, true);
  assert.strictEqual(cached.bundle.signature, newer.signature);
  if (process.platform === 'win32') {
    assert.doesNotThrow(() => privatePaths.assertPrivatePath(fixture.dir, {
      directory: true,
      label: 'signed policy cache directory',
    }));
    assert.doesNotThrow(() => privatePaths.assertPrivatePath(fixture.cachePath, {
      label: 'signed policy cache',
    }));
  }
  assert.strictEqual(fs.readdirSync(fixture.dir).filter((name) => name.endsWith('.tmp') || name.endsWith('.lock')).length, 0);
});

test('eight mixed auth, signing-key, and signed-policy processes serialize first boot', async () => {
  const fixture = signingFixture('mixed-private-state-source');
  const root = tempDir('mixed-private-state-race');
  const sharedDir = path.join(root, 'data');
  const cachePath = path.join(sharedDir, 'lkg.json');
  const bundleFile = path.join(fixture.dir, 'bundle.json');
  const publicKeyPath = path.join(fixture.dir, 'policy-public.pem');
  fs.writeFileSync(bundleFile, JSON.stringify(fixture.bundle));
  fs.writeFileSync(publicKeyPath, fixture.publicKey, { mode: 0o600 });

  const results = await Promise.all([
    ...Array.from({ length: 3 }, () => runAuthWorker(sharedDir)),
    ...Array.from({ length: 3 }, () => runKeyWorker(sharedDir)),
    ...Array.from({ length: 2 }, () => runCacheWorker(bundleFile, publicKeyPath, cachePath)),
  ]);
  const authResults = results.slice(0, 3);
  const keyResults = results.slice(3, 6);
  const cacheResults = results.slice(6);
  const secret = fs.readFileSync(path.join(sharedDir, '.session-secret'), 'utf8');

  assert.ok(authResults.every((result) => result.secret === secret && result.source === 'file'));
  const expectedLiveKey = crypto.createHash('sha256').update(`bootstrap-stress:${secret}`).digest('hex');
  assert.ok(authResults.every((result) => result.liveKey === expectedLiveKey));
  assert.strictEqual(new Set(keyResults).size, 1);
  assert.ok(cacheResults.every((result) => result.ok));
  signedPolicy._resetForTest();
  assert.strictEqual(signedPolicy.readCachedSignedPolicy({
    policyPublicKeyPath: publicKeyPath,
    policyCachePath: cachePath,
    sensorId: 'mixed-private-state',
  }).ok, true);
  if (process.platform === 'win32') {
    assert.doesNotThrow(() => privatePaths.assertPrivatePath(sharedDir, {
      directory: true,
      label: 'shared private-state directory',
    }));
    for (const [file, label] of [
      [path.join(sharedDir, '.session-secret'), 'session secret'],
      [path.join(sharedDir, '.policy-bundle-key.pem'), 'policy signing key'],
      [cachePath, 'signed policy cache'],
    ]) assert.doesNotThrow(() => privatePaths.assertPrivatePath(file, { label }));
  } else {
    assert.strictEqual(fs.statSync(sharedDir).mode & 0o077, 0);
    for (const file of [
      path.join(sharedDir, '.session-secret'),
      path.join(sharedDir, '.policy-bundle-key.pem'),
      cachePath,
    ]) assert.strictEqual(fs.statSync(file).mode & 0o077, 0);
  }
  assert.deepStrictEqual(fs.readdirSync(sharedDir).filter((name) => (
    name.endsWith('.tmp') || name.endsWith('.lock')
  )), []);
});

test('signed-policy cache startup reclaims a crashed directory-bootstrap lock', async () => {
  const fixture = signingFixture('policy-cache-crash');
  const bundleFile = path.join(fixture.dir, 'bundle.json');
  const publicKeyPath = path.join(fixture.dir, 'policy-public.pem');
  const bootstrapTarget = privatePaths.privateDirectoryLockTarget(fixture.dir);
  const lockPath = fileMutationLock.lockPathFor(bootstrapTarget);
  const targetLockPath = fileMutationLock.lockPathFor(fixture.cachePath);
  fs.writeFileSync(bundleFile, JSON.stringify(fixture.bundle));
  fs.writeFileSync(publicKeyPath, fixture.publicKey, { mode: 0o600 });

  await crashPrivateInitialization(fixture.dir, fixture.cachePath);
  assert.strictEqual(fs.existsSync(lockPath), true);
  assert.strictEqual(fs.existsSync(targetLockPath), true);
  const result = await runCacheWorker(bundleFile, publicKeyPath, fixture.cachePath);
  assert.strictEqual(result.ok, true);
  assert.strictEqual(fs.existsSync(lockPath), false);
  assert.strictEqual(fs.existsSync(targetLockPath), false);
  assert.strictEqual(signedPolicy.readCachedSignedPolicy({
    policyPublicKeyPath: publicKeyPath,
    policyCachePath: fixture.cachePath,
    sensorId: 'crash-restart',
  }).ok, true);
});

test('signed policy cache publication uses the shared verified Windows ACL contract', () => {
  const fixture = signingFixture('policy-cache-acl');
  const cacheDir = path.join(fixture.dir, 'cache');
  const cachePath = path.join(cacheDir, 'lkg.json');
  const principal = 'TEST\\sensor-user';
  const privatePathSecurity = {
    platform: 'win32',
    principal,
    ownerIdentity: TEST_OWNER_IDENTITY,
    privateLockRoot: path.join(fixture.dir, 'locks'),
  };
  const directoryLockPath = fileMutationLock.lockPathFor(
    privatePaths.privateDirectoryLockTarget(cacheDir, privatePathSecurity),
  );
  const calls = [];
  let cacheDirectorySecured = false;
  const options = {
    policyPublicKey: fixture.publicKey,
    policyCachePath: cachePath,
    sensorId: 'acl',
    privatePathSecurity: {
      ...privatePathSecurity,
      spawn(command, args, options) {
        calls.push({ command, args, options });
        if (args[0] === cacheDir && args.includes('/grant:r')) {
          assert.strictEqual(fs.existsSync(fileMutationLock.lockPathFor(cachePath)), false);
          assert.strictEqual(fs.existsSync(directoryLockPath), true);
          cacheDirectorySecured = true;
        }
        if (/\.tmp$/.test(args[0]) && args.includes('/grant:r')) {
          assert.strictEqual(fs.existsSync(fileMutationLock.lockPathFor(cachePath)), true);
          assert.strictEqual(fs.existsSync(directoryLockPath), true);
        }
        const target = args[0];
        return args.length === 1 ? {
          status: 0,
          stdout: target === cacheDir && !cacheDirectorySecured
            ? `${target} ${principal}:(F)\r\n          BUILTIN\\Users:(R)\r\n          NT AUTHORITY\\SYSTEM:(F)`
            : `${target} ${principal}:(F)\r\n          NT AUTHORITY\\SYSTEM:(F)\r\nSuccessfully processed 1 files`,
        } : { status: 0, stdout: 'processed 1 file' };
      },
    },
  };
  const accepted = signedPolicy.acceptSignedPolicyBundle(fixture.bundle, options);
  assert.strictEqual(accepted.ok, true);
  assert.strictEqual(accepted.persisted, true);
  assert.strictEqual(fs.existsSync(fileMutationLock.lockPathFor(cachePath)), false);
  assert.strictEqual(fs.existsSync(directoryLockPath), false);
  assert.ok(calls.some((call) => /\.tmp$/.test(call.args[0]) && call.args.includes('/grant:r')));
  assert.strictEqual(signedPolicy.readCachedSignedPolicy(options).ok, true);
  assert.ok(calls.some((call) => call.args.length === 1 && call.args[0] === cachePath));

  const persisted = fs.readFileSync(cachePath);
  const newer = policyBundle.buildBundle({ ...fixture.bundle.policy, enforcementMode: 'warn' }, {
    keyFile: fixture.keyFile,
    now: new Date(Date.now() + 1000).toISOString(),
  });
  const aclFailure = {
    ...options,
    privatePathSecurity: {
      ...options.privatePathSecurity,
      spawn(command, args, spawnOptions) {
        if (/\.tmp$/.test(args[0]) && args.includes('/grant:r')) {
          return { status: 1, stderr: 'simulated ACL denial' };
        }
        return options.privatePathSecurity.spawn(command, args, spawnOptions);
      },
    },
  };
  assert.deepStrictEqual(signedPolicy.acceptSignedPolicyBundle(newer, aclFailure), {
    ok: false,
    reason: 'policy_cache_unavailable',
  });
  assert.deepStrictEqual(fs.readFileSync(cachePath), persisted);
});

test('packaged sensors never fall back to the legacy unsigned policy route', async () => {
  const runtimeFiles = [
    'sensors/endpoint-agent/agent.js',
    'sensors/endpoint-agent/collectors/protected-upload.js',
    'sensors/mcp-guard/guard.js',
    'sensors/agent-hooks/hook.js',
    'sensors/browser-extension/background.js',
  ];
  for (const relative of runtimeFiles) {
    const source = fs.readFileSync(path.join(__dirname, '..', relative), 'utf8');
    assert.strictEqual(source.includes("'/api/v1/policy'"), false, relative);
    assert.strictEqual(source.includes('"/api/v1/policy"'), false, relative);
  }

  const fixture = signingFixture('policy-no-legacy-fallback');
  const urls = [];
  const result = await endpoint.fetchPolicy({
    server: 'https://redactwall.test',
    key: 'unit-key',
    policyPublicKey: fixture.publicKey,
    policyCachePath: path.join(fixture.dir, 'missing-cache.json'),
    silent: true,
    fetchImpl: async (url) => {
      urls.push(url);
      return response({ enforcementMode: 'warn' }, 503);
    },
  });
  assert.strictEqual(result, null);
  assert.deepStrictEqual(urls, ['https://redactwall.test/api/v1/policy/bundle']);
});

test('endpoint accepts only a pinned signed bundle and uses a fresh LKG offline', async () => {
  const fixture = signingFixture('endpoint-policy');
  const options = {
    server: 'https://redactwall.test', key: 'unit-key', policyPublicKey: fixture.publicKey,
    policyCachePath: fixture.cachePath, silent: true,
  };
  const fresh = await endpoint.fetchPolicy({ ...options, fetchImpl: async () => response(fixture.bundle) });
  assert.strictEqual(fresh.enforcementMode, 'block');
  const offline = await endpoint.fetchPolicy({ ...options, fetchImpl: async () => { throw new Error('offline'); } });
  assert.deepStrictEqual(offline, fresh);

  const other = signingFixture('endpoint-wrong-key');
  const expired = policyBundle.buildBundle(fixture.bundle.policy, {
    keyFile: fixture.keyFile, now: '2020-01-01T00:00:00.000Z', ttlMs: 1000,
  });
  const invalid = [
    other.bundle,
    { ...fixture.bundle, policy: { enforcementMode: 'warn' } },
    expired,
    { version: 1, policy: {}, signature: 'bad' },
  ];
  for (let index = 0; index < invalid.length; index += 1) {
    const rejected = await endpoint.fetchPolicy({
      ...options,
      policyCachePath: path.join(fixture.dir, `empty-cache-${index}.json`),
      fetchImpl: async () => response(invalid[index]),
    });
    assert.strictEqual(rejected, null);
  }
  assert.strictEqual(await endpoint.fetchPolicy({
    ...options, policyPublicKey: '', policyCachePath: path.join(fixture.dir, 'no-pin.json'),
    fetchImpl: async () => response(fixture.bundle),
  }), null);
});

test('MCP denies before handler on fresh outage, but the Node test runner can install an inline fixture', async () => {
  const fixture = signingFixture('mcp-policy');
  mcp._resetPolicyTrustForTest();
  let calls = 0;
  const denied = mcp.wrapTool(async () => { calls += 1; return 'unsafe'; }, { tool: 'drive.read' }, {
    server: 'https://redactwall.test', key: 'unit-key', policyPublicKey: fixture.publicKey,
    policyCachePath: path.join(fixture.dir, 'missing-cache.json'),
    fetchImpl: async () => { throw new Error('offline'); }, silentPolicyRefresh: true,
  });
  assert.match(await denied({}), /BLOCKED.*trusted signed MCP policy/i);
  assert.strictEqual(calls, 0);

  const explicit = mcp.wrapTool(async () => { calls += 1; return 'clean'; }, { tool: 'drive.read' }, { policy: {} });
  assert.strictEqual(await explicit({}), 'clean');
  assert.strictEqual(calls, 1);
});

test('production MCP and endpoint processes reject unsigned inline policy objects', async () => {
  const script = String.raw`
    const fs = require('node:fs');
    const os = require('node:os');
    const path = require('node:path');
    const mcp = require('./sensors/mcp-guard/guard');
    const endpoint = require('./sensors/endpoint-agent/agent');
    (async () => {
      let calls = 0;
      const wrapped = mcp.wrapTool(async () => { calls += 1; return 'unsafe'; },
        { tool: 'drive.read' }, { policy: {} });
      const mcpResult = await wrapped({});
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-policy-boundary-'));
      const file = path.join(dir, 'member.txt');
      fs.writeFileSync(file, 'synthetic SSN 123-45-6789');
      const endpointResult = await endpoint.scanAbsoluteFile(file, {
        policy: { enforcementMode: 'warn', alwaysBlock: [] },
        report: async () => ({ id: 'recorded' }),
      });
      fs.rmSync(dir, { recursive: true, force: true });
      process.stdout.write(JSON.stringify({ mcpResult, calls, endpointResult }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `;
  const result = await runProductionScript(script);
  assert.match(result.mcpResult, /BLOCKED.*trusted signed MCP policy/i);
  assert.strictEqual(result.calls, 0);
  assert.strictEqual(result.endpointResult.decision, 'block');
  assert.strictEqual(result.endpointResult.status, 'policy_unavailable');
});

test('MCP installs a valid signed policy and uses its fresh LKG during an outage', async () => {
  const fixture = signingFixture('mcp-lkg');
  const options = {
    server: 'https://redactwall.test', key: 'unit-key', policyPublicKey: fixture.publicKey,
    policyCachePath: fixture.cachePath, silent: true,
  };
  mcp._resetPolicyTrustForTest();
  await mcp.refreshPolicy({ ...options, fetchImpl: async () => response(fixture.bundle) });
  assert.strictEqual(mcp.policyTrustState().trusted, true);
  mcp._resetPolicyTrustForTest();
  await mcp.refreshPolicy({ ...options, fetchImpl: async () => { throw new Error('offline'); } });
  assert.strictEqual(mcp.policyTrustState().trusted, true);
});

test('MCP rejects tampered, expired, wrong-key, malformed, and unpinned bundles', async () => {
  const fixture = signingFixture('mcp-invalid');
  const other = signingFixture('mcp-invalid-other');
  const expired = policyBundle.buildBundle(fixture.bundle.policy, {
    keyFile: fixture.keyFile, now: '2020-01-01T00:00:00.000Z', ttlMs: 1000,
  });
  const invalid = [
    other.bundle,
    { ...fixture.bundle, policy: { mcpAllowedTools: ['*'] } },
    expired,
    { version: 1, policy: {}, signature: 'bad' },
  ];
  for (let index = 0; index < invalid.length; index += 1) {
    const result = await mcp.fetchPolicy({
      server: 'https://redactwall.test', key: 'unit-key', policyPublicKey: fixture.publicKey,
      policyCachePath: path.join(fixture.dir, `empty-${index}.json`), silent: true,
      fetchImpl: async () => response(invalid[index]),
    });
    assert.strictEqual(result, null);
  }
  assert.strictEqual(await mcp.fetchPolicy({
    server: 'https://redactwall.test', key: 'unit-key', policyPublicKey: '',
    policyCachePath: path.join(fixture.dir, 'no-pin.json'), silent: true,
    fetchImpl: async () => response(fixture.bundle),
  }), null);
});

test('browser WebCrypto verifier accepts the pinned bundle and rejects tamper, expiry, and wrong key', async () => {
  const fixture = signingFixture('browser-policy');
  const code = fs.readFileSync(path.join(__dirname, '..', 'sensors', 'browser-extension', 'lib', 'policy-bundle.js'), 'utf8');
  const context = {
    self: {},
    crypto: crypto.webcrypto,
    TextEncoder,
    atob: (value) => Buffer.from(value, 'base64').toString('binary'),
    Date,
    Uint8Array,
    Array,
    JSON,
  };
  vm.runInNewContext(code, context);
  const verifier = context.self.RedactWallPolicyTrust;
  assert.strictEqual((await verifier.verifyBundle(fixture.bundle, fixture.publicKey)).ok, true);
  assert.strictEqual((await verifier.verifyBundle({ ...fixture.bundle, policy: {} }, fixture.publicKey)).ok, false);
  const wrong = signingFixture('browser-wrong-key').publicKey;
  assert.strictEqual((await verifier.verifyBundle(fixture.bundle, wrong)).ok, false);
  const expired = { ...fixture.bundle, expiresAt: '2020-01-01T00:00:00.000Z' };
  assert.strictEqual((await verifier.verifyBundle(expired, fixture.publicKey)).ok, false);
  assert.strictEqual((await verifier.verifyBundle({ version: 1, policy: {}, signature: 'bad' }, fixture.publicKey)).ok, false);
  assert.strictEqual((await verifier.verifyBundle(fixture.bundle, '')).reason, 'missing_pin');
});
