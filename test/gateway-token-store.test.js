'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn, spawnSync } = require('node:child_process');
const tokens = require('../gateway/tokens');
const fileMutationLock = require('../server/file-mutation-lock');
const privatePaths = require('../server/private-path');

const TOKEN_MODULE = path.join(__dirname, '..', 'gateway', 'tokens.js');

function tempStore(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-gateway-tokens-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return path.join(dir, 'tokens.json');
}

function writeLockOwner(lockPath, fields) {
  const owner = { ...fields, token: crypto.randomBytes(24).toString('hex') };
  const ownerName = fileMutationLock._internal.ownerFileName(owner.token);
  const ownerPath = path.join(lockPath, ownerName);
  fs.mkdirSync(lockPath, { mode: 0o700 });
  fs.writeFileSync(ownerPath, `${JSON.stringify(owner)}\n`, { mode: 0o600 });
  return { ownerPath };
}

function childOperation(store, operation, value = '') {
  const source = `
    const tokens = require(process.env.TOKEN_MODULE);
    const store = process.env.TOKEN_STORE;
    const op = process.env.TOKEN_OP;
    const result = op === 'mint'
      ? tokens.mintToken({ user: process.env.TOKEN_VALUE + '@example.test' }, store)
      : { revoked: tokens.revokeToken(process.env.TOKEN_VALUE, store) };
    process.stdout.write(JSON.stringify(result));
  `;
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['-e', source], {
      env: {
        ...process.env,
        TOKEN_MODULE,
        TOKEN_STORE: store,
        TOKEN_OP: operation,
        TOKEN_VALUE: value,
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
      if (code !== 0) return reject(new Error(`token child failed (${code}): ${stderr}`));
      try { resolve(JSON.parse(stdout)); } catch (err) { reject(err); }
    });
  });
}

function crashDirectoryBootstrap(store) {
  const source = `
    const path = require('node:path');
    const privatePaths = require(process.env.PRIVATE_PATH_MODULE);
    privatePaths.withPrivateDirectoryMutationLockSync(path.dirname(process.env.TOKEN_STORE), () => process.exit(17));
  `;
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['-e', source], {
      env: {
        ...process.env,
        PRIVATE_PATH_MODULE: path.join(__dirname, '..', 'server', 'private-path.js'),
        TOKEN_STORE: store,
      },
      stdio: ['ignore', 'ignore', 'pipe'],
      windowsHide: true,
    });
    let stderr = '';
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.once('error', reject);
    child.once('exit', (code) => code === 17 ? resolve() : reject(new Error(stderr || `bootstrap crash worker exited ${code}`)));
  });
}

test('gateway token store preserves concurrent process mints and revocations atomically', async (t) => {
  const store = tempStore(t);
  const minted = await Promise.all(Array.from({ length: 12 }, (_, index) => childOperation(store, 'mint', `agent-${index}`)));
  const afterMint = tokens.listTokens(store);
  assert.strictEqual(afterMint.length, 12);
  assert.strictEqual(new Set(afterMint.map((entry) => entry.id)).size, 12);
  for (const item of minted) assert.ok(tokens.resolveToken(item.token, store));

  await Promise.all([
    ...afterMint.slice(0, 6).map((entry) => childOperation(store, 'revoke', entry.id)),
    ...Array.from({ length: 6 }, (_, index) => childOperation(store, 'mint', `late-${index}`)),
  ]);
  const finalStore = JSON.parse(fs.readFileSync(store, 'utf8'));
  assert.strictEqual(finalStore.tokens.length, 18);
  assert.strictEqual(finalStore.tokens.filter((entry) => entry.revoked).length, 6);
  assert.strictEqual(fs.existsSync(fileMutationLock.lockPathFor(store)), false);
  assert.deepStrictEqual(fs.readdirSync(path.dirname(store)).filter((name) => name.endsWith('.tmp')), []);
  if (process.platform !== 'win32') assert.strictEqual(fs.statSync(store).mode & 0o777, 0o600);
});

test('gateway token store rejects attacker state planted before Windows directory trust', {
  skip: process.platform !== 'win32' && 'Windows ACL bootstrap is Windows-specific',
}, (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-gateway-planted-'));
  const dir = path.join(root, 'data');
  const store = path.join(dir, 'tokens.json');
  fs.mkdirSync(dir);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const planted = Buffer.from('{"tokens":[{"id":"attacker","hash":"known","revoked":false}]}\n');
  fs.writeFileSync(store, planted);
  const broadGrant = spawnSync('icacls.exe', [dir, '/grant', '*S-1-5-32-545:(OI)(CI)(M)', '/q'], {
    encoding: 'utf8',
    windowsHide: true,
  });
  assert.strictEqual(broadGrant.status, 0, broadGrant.stderr);

  assert.throws(() => tokens.listTokens(store), /before its permissions were trusted/);
  assert.deepStrictEqual(fs.readFileSync(store), planted);
});

test('eight gateway processes recover a crashed Windows bootstrap and preserve every first-boot mint', {
  timeout: 120_000,
  skip: process.platform !== 'win32' && 'Windows ACL bootstrap is Windows-specific',
}, async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-gateway-bootstrap-race-'));
  const store = path.join(root, 'data', 'tokens.json');
  const directory = path.dirname(store);
  const bootstrapLock = fileMutationLock.lockPathFor(privatePaths.privateDirectoryLockTarget(directory));
  t.after(() => {
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(bootstrapLock, { recursive: true, force: true });
  });

  await crashDirectoryBootstrap(store);
  assert.strictEqual(fs.existsSync(bootstrapLock), true);
  const minted = await Promise.all(Array.from({ length: 8 }, (_, index) => childOperation(store, 'mint', `bootstrap-${index}`)));

  assert.strictEqual(fs.existsSync(bootstrapLock), false);
  assert.strictEqual(tokens.listTokens(store).length, 8);
  for (const item of minted) assert.ok(tokens.resolveToken(item.token, store));
});

test('gateway token mutation rejects directory-fsync EIO and restores the exact store', (t) => {
  const store = tempStore(t);
  tokens.mintToken({ user: 'baseline@example.test' }, store);
  const baseline = fs.readFileSync(store);
  const originalFsync = fs.fsyncSync;
  fs.fsyncSync = (fd) => {
    if (fs.fstatSync(fd).isDirectory()) {
      const error = new Error('synthetic token-store directory fsync EIO');
      error.code = 'EIO';
      throw error;
    }
    return originalFsync(fd);
  };
  try {
    assert.throws(
      () => tokens.mintToken({ user: 'must-not-persist@example.test' }, store),
      /synthetic token-store directory fsync EIO/,
    );
  } finally {
    fs.fsyncSync = originalFsync;
  }
  assert.deepStrictEqual(fs.readFileSync(store), baseline);
  assert.deepStrictEqual(
    fs.readdirSync(path.dirname(store)).filter((name) => name.includes('.tmp') || name.includes('.rollback.')),
    [],
  );
});

test('gateway token mutation reclaims a crashed reused-PID lock through the shared helper', (t) => {
  const store = tempStore(t);
  privatePaths.withPrivateDirectoryMutationLockSync(path.dirname(store), () => {});
  const lockPath = fileMutationLock.lockPathFor(store);
  writeLockOwner(lockPath, {
    version: 2,
    pid: process.pid,
    hostname: os.hostname(),
    processStart: '1',
  });

  const minted = tokens.mintToken({ user: 'recovered@example.test' }, store);

  assert.ok(tokens.resolveToken(minted.token, store));
  assert.strictEqual(fs.existsSync(lockPath), false);
});

test('gateway token lock release cannot unlink a replacement owner', (t) => {
  const store = tempStore(t);
  const lock = tokens._internal.acquireStoreLock(store);
  fs.closeSync(lock.fd);
  fs.unlinkSync(lock.ownerPath);
  fs.rmdirSync(lock.lockPath);
  const replacement = tokens._internal.acquireStoreLock(store);

  tokens._internal.releaseStoreLock(lock);

  assert.strictEqual(fs.readFileSync(replacement.ownerPath, 'utf8'), replacement.contents);
  tokens._internal.releaseStoreLock(replacement);
});

test('gateway token ACL contract removes inheritance and grants owner plus LocalSystem', (t) => {
  const store = tempStore(t);
  fs.writeFileSync(store, '{"tokens":[]}');
  const calls = [];
  tokens._internal.restrictPrivatePath(store, {
    platform: 'win32',
    directory: false,
    principal: 'TEST\\gateway-user',
    ownerIdentity: { processSid: 'S-1-5-21-1-2-3-1001', ownerSid: 'S-1-5-21-1-2-3-1001' },
    spawn(command, args, options) {
      calls.push({ command, args, options });
      return { status: 0, stdout: 'processed 1 file' };
    },
  });
  assert.deepStrictEqual(calls.map((entry) => entry.command), ['icacls.exe', 'icacls.exe']);
  assert.deepStrictEqual(calls.map((entry) => entry.args), [
    [store, '/reset', '/q'],
    [store, '/inheritance:r', '/grant:r', 'TEST\\gateway-user:(F)', '*S-1-5-18:(F)', '/q'],
  ]);
  assert.ok(calls.every((entry) => entry.options.windowsHide === true));
});

test('gateway token ACL hardening fails closed', (t) => {
  const store = tempStore(t);
  fs.writeFileSync(store, '{"tokens":[]}');
  let calls = 0;
  assert.throws(() => tokens._internal.restrictPrivatePath(store, {
    platform: 'win32',
    directory: false,
    principal: 'TEST\\gateway-user',
    ownerIdentity: { processSid: 'S-1-5-21-1-2-3-1001', ownerSid: 'S-1-5-21-1-2-3-1001' },
    spawn() {
      calls += 1;
      return calls === 1 ? { status: 0 } : { status: 5, stderr: 'access denied' };
    },
  }), /failed to secure the gateway token store/);
});

test('gateway ACL-ready validation accepts only explicit owner and LocalSystem full control', () => {
  const exact = [
    'C:\\tokens TEST\\gateway-user:(OI)(CI)(F)',
    '          NT AUTHORITY\\SYSTEM:(OI)(CI)(F)',
    'Successfully processed 1 files',
  ].join('\r\n');
  const inherited = exact.replace('(OI)(CI)(F)', '(I)(OI)(CI)(F)');
  const broad = exact.replace(
    'Successfully processed 1 files',
    '          BUILTIN\\Users:(RX)\r\nSuccessfully processed 1 files',
  );

  assert.strictEqual(tokens._internal.privateAclListing(exact, 'TEST\\gateway-user'), true);
  assert.strictEqual(tokens._internal.privateAclListing(inherited, 'TEST\\gateway-user'), false);
  assert.strictEqual(tokens._internal.privateAclListing(broad, 'TEST\\gateway-user'), false);
});

test('gateway token directory and store have a protected two-principal Windows DACL', {
  skip: process.platform !== 'win32',
}, (t) => {
  const store = tempStore(t);
  const dir = path.dirname(store);
  const broadGrant = spawnSync('icacls.exe', [dir, '/grant', '*S-1-5-32-545:(OI)(CI)(M)', '/q'], {
    encoding: 'utf8',
    windowsHide: true,
  });
  assert.strictEqual(broadGrant.status, 0, broadGrant.stderr);

  tokens.mintToken({ user: 'acl-proof@example.test' }, store);
  const owner = String(spawnSync('whoami.exe', [], { encoding: 'utf8', windowsHide: true }).stdout || '').trim().toLowerCase();
  for (const target of [dir, store]) {
    const acl = spawnSync('icacls.exe', [target], {
      encoding: 'utf8',
      windowsHide: true,
    });
    assert.strictEqual(acl.status, 0, acl.stderr);
    const listing = String(acl.stdout || '').toLowerCase();
    assert.strictEqual((listing.match(/\(f\)/g) || []).length, 2, listing);
    assert.match(listing, /nt authority\\system/);
    assert.ok(listing.includes(owner), listing);
    assert.ok(!listing.includes('(i)'), listing);
    assert.ok(!listing.includes('builtin\\users'), listing);
    assert.ok(!listing.includes('codexsandboxusers'), listing);
  }
});

test('gateway token reads and mutations reject a store DACL widened after cache warmup', {
  skip: process.platform !== 'win32',
}, (t) => {
  const store = tempStore(t);
  const minted = tokens.mintToken({ user: 'acl-cache@example.test' }, store);
  assert.ok(tokens.resolveToken(minted.token, store), 'warm the parsed and ACL caches');
  const widened = spawnSync('icacls.exe', [store, '/grant', '*S-1-5-32-545:(R)', '/q'], {
    encoding: 'utf8',
    windowsHide: true,
  });
  assert.strictEqual(widened.status, 0, widened.stderr);

  assert.throws(() => tokens.resolveToken(minted.token, store), /ACL verification failed/);
  assert.throws(() => tokens.revokeToken(minted.id, store), /ACL verification failed/);
});

test('gateway token reads and mutations reject a parent DACL widened after cache warmup', {
  skip: process.platform !== 'win32',
}, (t) => {
  const store = tempStore(t);
  const minted = tokens.mintToken({ user: 'directory-acl-cache@example.test' }, store);
  assert.ok(tokens.resolveToken(minted.token, store), 'warm the parsed and ACL caches');
  const widened = spawnSync('icacls.exe', [path.dirname(store), '/grant', '*S-1-5-32-545:(OI)(CI)(R)', '/q'], {
    encoding: 'utf8',
    windowsHide: true,
  });
  assert.strictEqual(widened.status, 0, widened.stderr);

  assert.throws(() => tokens.resolveToken(minted.token, store), /ACL verification failed/);
  assert.throws(() => tokens.revokeToken(minted.id, store), /ACL verification failed/);
});
