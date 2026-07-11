'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');
const Database = require('better-sqlite3');
const { openStore, _internal } = require('../server/storage');
const privatePaths = require('../server/private-path');
const fileMutationLock = require('../server/file-mutation-lock');

const STORAGE_MODULE = path.join(__dirname, '..', 'server', 'storage', 'index.js');
const TEST_OWNER_IDENTITY = Object.freeze({
  processSid: 'S-1-5-21-100-200-300-1001',
  ownerSid: 'S-1-5-21-100-200-300-1001',
});

function seedV7AdminDatabase(dbPath) {
  const db = new Database(dbPath);
  try {
    db.exec(require('../server/storage/migrations').MIGRATIONS.find((migration) => migration.version === 7).sqlite);
    db.exec('CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, appliedAt TEXT NOT NULL)');
    db.prepare('INSERT INTO schema_migrations VALUES (?, ?, ?)').run(7, 'administration-users-and-licensing', '2026-07-10T00:00:00.000Z');
    const admin = {
      id: 'admin-planted-v7',
      orgId: 'credit-union',
      userName: 'admin@example.test',
      displayName: 'Planted Admin',
      role: 'security_admin',
      active: 1,
      createdAt: '2026-07-10T00:00:00.000Z',
      updatedAt: '2026-07-10T00:00:00.000Z',
    };
    db.prepare('INSERT INTO admin_users (id, orgId, userName, displayName, role, active, createdAt, updatedAt, data) VALUES (@id, @orgId, @userName, @displayName, @role, @active, @createdAt, @updatedAt, @data)')
      .run({ ...admin, data: JSON.stringify(admin) });
  } finally {
    db.close();
  }
}

function sqliteOpenWorker(dbPath, index) {
  const source = `
    const storage = require(process.env.STORAGE_MODULE);
    const store = storage.openStore({
      env: { NODE_ENV: 'production', REDACTWALL_DB_DRIVER: 'sqlite', REDACTWALL_DB_PATH: process.env.SQLITE_PATH },
      dataDir: require('node:path').dirname(process.env.SQLITE_PATH),
    });
    store.driver.close();
    process.stdout.write(process.env.WORKER_ID);
  `;
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['-e', source], {
      env: { ...process.env, STORAGE_MODULE, SQLITE_PATH: dbPath, WORKER_ID: String(index) },
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.once('error', reject);
    child.once('exit', (code) => code === 0 ? resolve(stdout) : reject(new Error(`SQLite worker ${index} failed (${code}): ${stderr}`)));
  });
}

function unusableDatabasePath(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-sqlite-fail-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const parentFile = path.join(root, 'not-a-directory');
  fs.writeFileSync(parentFile, 'occupied');
  return path.join(parentFile, 'redactwall.db');
}

test('SQLite evidence files use owner-only modes on POSIX systems', {
  skip: process.platform === 'win32' && 'POSIX file modes are not meaningful on Windows',
}, (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-sqlite-mode-'));
  const dbPath = path.join(root, 'private', 'redactwall.db');
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const store = openStore({
    env: { REDACTWALL_DB_DRIVER: 'sqlite', REDACTWALL_DB_PATH: dbPath },
    dataDir: root,
  });
  try {
    assert.strictEqual(fs.statSync(path.dirname(dbPath)).mode & 0o777, 0o700);
    const journal = `${dbPath}-journal`;
    fs.writeFileSync(journal, 'synthetic rollback journal', { mode: 0o666 });
    _internal.restrictSqliteArtifacts(dbPath, { platform: process.platform });
    const files = _internal.sqliteArtifactPaths(dbPath).filter(fs.existsSync);
    assert.ok(files.length >= 1);
    for (const file of files) {
      assert.strictEqual(fs.statSync(file).mode & 0o777, 0o600, file);
    }
  } finally {
    store.driver.close();
  }
});

test('SQLite ACL contract covers the directory and db, WAL, shared-memory, and rollback-journal artifacts', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-sqlite-acl-contract-'));
  const dbPath = path.join(root, 'redactwall.db');
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const artifact of _internal.sqliteArtifactPaths(dbPath)) fs.writeFileSync(artifact, 'synthetic');

  const calls = [];
  _internal.restrictPrivatePath(root, {
    platform: 'win32',
    directory: true,
    principal: 'TEST\\sqlite-user',
    ownerIdentity: TEST_OWNER_IDENTITY,
    spawn(command, args, options) {
      calls.push({ command, args, options });
      return { status: 0, stdout: 'processed 1 file' };
    },
  });
  _internal.restrictSqliteArtifacts(dbPath, {
    platform: 'win32',
    principal: 'TEST\\sqlite-user',
    ownerIdentity: TEST_OWNER_IDENTITY,
    spawn(command, args, options) {
      calls.push({ command, args, options });
      return { status: 0, stdout: 'processed 1 file' };
    },
  });

  const artifacts = _internal.sqliteArtifactPaths(dbPath);
  assert.deepStrictEqual(artifacts, [dbPath, `${dbPath}-wal`, `${dbPath}-shm`, `${dbPath}-journal`]);
  assert.deepStrictEqual(calls.map((call) => call.command), Array(10).fill('icacls.exe'));
  assert.deepStrictEqual(calls[0].args, [root, '/reset', '/q']);
  assert.deepStrictEqual(calls[1].args, [
    root, '/inheritance:r', '/grant:r',
    'TEST\\sqlite-user:(OI)(CI)(F)', '*S-1-5-18:(OI)(CI)(F)', '/q',
  ]);
  for (let index = 0; index < artifacts.length; index += 1) {
    const offset = 2 + (index * 2);
    assert.deepStrictEqual(calls[offset].args, [artifacts[index], '/reset', '/q']);
    assert.deepStrictEqual(calls[offset + 1].args, [
      artifacts[index], '/inheritance:r', '/grant:r',
      'TEST\\sqlite-user:(F)', '*S-1-5-18:(F)', '/q',
    ]);
  }
  assert.ok(calls.every((call) => call.options.windowsHide === true));
});

test('production SQLite startup fails closed when an icacls command cannot protect the store', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-sqlite-acl-fail-'));
  const dbPath = path.join(root, 'private', 'redactwall.db');
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  assert.throws(() => openStore({
    env: {
      NODE_ENV: 'production',
      REDACTWALL_DB_DRIVER: 'sqlite',
      REDACTWALL_DB_PATH: dbPath,
    },
    dataDir: root,
    sqliteSecurity: {
      platform: 'win32',
      principal: 'TEST\\sqlite-user',
      ownerIdentity: TEST_OWNER_IDENTITY,
      privateLockRoot: path.join(root, 'locks'),
      spawn() { return { status: 5, stderr: 'access denied' }; },
    },
  }), (error) => error?.code === 'REDACTWALL_SQLITE_UNUSABLE' &&
    /failed to secure.*icacls: access denied/i.test(error.cause?.message || ''));
});

test('production SQLite startup fails closed and restores umask when the Windows command adapter fails', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-sqlite-owner-fail-'));
  const dbPath = path.join(root, 'private', 'redactwall.db');
  const umask = process.umask();
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  assert.throws(() => openStore({
    env: {
      NODE_ENV: 'production',
      REDACTWALL_DB_DRIVER: 'sqlite',
      REDACTWALL_DB_PATH: dbPath,
    },
    dataDir: root,
    sqliteSecurity: {
      platform: 'win32',
      privateLockRoot: path.join(root, 'locks'),
      spawn(command) {
        assert.strictEqual(command, 'whoami.exe');
        throw new Error('adapter unavailable');
      },
    },
  }), (error) => error?.code === 'REDACTWALL_SQLITE_UNUSABLE' &&
    /failed to identify.*whoami: adapter unavailable/i.test(error.cause?.message || ''));
  assert.strictEqual(process.umask(), umask);
});

test('in-memory SQLite bypasses filesystem ACL commands outside production and is rejected in production', () => {
  const store = openStore({
    env: { REDACTWALL_DB_DRIVER: 'sqlite', REDACTWALL_DB_PATH: ':memory:' },
    dataDir: process.cwd(),
    sqliteSecurity: {
      platform: 'win32',
      spawn() { throw new Error('filesystem ACL command must not run'); },
    },
  });
  store.driver.close();
  assert.throws(() => openStore({
    env: {
      NODE_ENV: 'production',
      REDACTWALL_DB_DRIVER: 'sqlite',
      REDACTWALL_DB_PATH: ':memory:',
    },
    dataDir: process.cwd(),
  }), (error) => error?.code === 'REDACTWALL_SQLITE_UNUSABLE' &&
    /in-memory SQLite is not durable/i.test(error.cause?.message || ''));
});

test('SQLite directory and live artifacts have a protected two-principal Windows DACL', {
  skip: process.platform !== 'win32',
}, (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-sqlite-real-acl-'));
  const dbDir = path.join(root, 'data');
  const dbPath = path.join(dbDir, 'redactwall.db');
  fs.mkdirSync(dbDir);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const broadGrant = spawnSync('icacls.exe', [dbDir, '/grant', '*S-1-5-32-545:(OI)(CI)(R)', '/q'], {
    encoding: 'utf8',
    windowsHide: true,
  });
  assert.strictEqual(broadGrant.status, 0, broadGrant.stderr);

  const store = openStore({
    env: {
      NODE_ENV: 'production',
      REDACTWALL_DB_DRIVER: 'sqlite',
      REDACTWALL_DB_PATH: dbPath,
    },
    dataDir: root,
  });
  try {
    const owner = String(spawnSync('whoami.exe', [], {
      encoding: 'utf8',
      windowsHide: true,
    }).stdout || '').trim().toLowerCase();
    const targets = [dbDir, ..._internal.sqliteArtifactPaths(dbPath).filter(fs.existsSync)];
    assert.ok(targets.length >= 2, 'database artifact must exist');
    for (const target of targets) {
      const acl = spawnSync('icacls.exe', [target], { encoding: 'utf8', windowsHide: true });
      assert.strictEqual(acl.status, 0, acl.stderr);
      const listing = String(acl.stdout || '').toLowerCase();
      assert.strictEqual((listing.match(/\(f\)/g) || []).length, 2, listing);
      assert.match(listing, /nt authority\\system/);
      assert.ok(listing.includes(owner), listing);
      assert.ok(!listing.includes('(i)'), listing);
      assert.ok(!listing.includes('builtin\\users'), listing);
      assert.ok(!listing.includes('codexsandboxusers'), listing);
    }
  } finally {
    store.driver.close();
  }
});

test('production SQLite rejects a v7 admin database planted before Windows directory trust', {
  skip: process.platform !== 'win32' && 'Windows ACL bootstrap is Windows-specific',
}, (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-sqlite-planted-v7-'));
  const dbDir = path.join(root, 'data');
  const dbPath = path.join(dbDir, 'redactwall.db');
  fs.mkdirSync(dbDir);
  seedV7AdminDatabase(dbPath);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const before = fs.readFileSync(dbPath);
  const broadGrant = spawnSync('icacls.exe', [dbDir, '/grant', '*S-1-5-32-545:(OI)(CI)(M)', '/q'], {
    encoding: 'utf8',
    windowsHide: true,
  });
  assert.strictEqual(broadGrant.status, 0, broadGrant.stderr);

  assert.throws(() => openStore({
    env: { NODE_ENV: 'production', REDACTWALL_DB_DRIVER: 'sqlite', REDACTWALL_DB_PATH: dbPath },
    dataDir: root,
  }), (error) => error?.code === 'REDACTWALL_SQLITE_UNUSABLE'
    && /before its permissions were trusted/.test(error.cause?.message || ''));
  assert.deepStrictEqual(fs.readFileSync(dbPath), before);
});

test('production SQLite preserves a v7 admin database that was created in a trusted Windows directory', {
  skip: process.platform !== 'win32' && 'Windows ACL bootstrap is Windows-specific',
}, (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-sqlite-trusted-v7-'));
  const dbDir = path.join(root, 'data');
  const dbPath = path.join(dbDir, 'redactwall.db');
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  privatePaths.withPrivateDirectoryMutationLockSync(dbDir, () => {});
  seedV7AdminDatabase(dbPath);

  const store = openStore({
    env: { NODE_ENV: 'production', REDACTWALL_DB_DRIVER: 'sqlite', REDACTWALL_DB_PATH: dbPath },
    dataDir: root,
  });
  try {
    assert.deepStrictEqual(store.driver.prepare('SELECT id, userName, role FROM admin_users').get(), {
      id: 'admin-planted-v7',
      userName: 'admin@example.test',
      role: 'security_admin',
    });
  } finally {
    store.driver.close();
  }
});

test('eight production SQLite processes serialize Windows first boot through the trusted-profile lock', {
  timeout: 120_000,
  skip: process.platform !== 'win32' && 'Windows ACL bootstrap is Windows-specific',
}, async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-sqlite-bootstrap-race-'));
  const dbDir = path.join(root, 'data');
  const dbPath = path.join(dbDir, 'redactwall.db');
  const bootstrapLock = fileMutationLock.lockPathFor(privatePaths.privateDirectoryLockTarget(dbDir));
  t.after(() => {
    const cleanup = { recursive: true, force: true, maxRetries: 5, retryDelay: 100 };
    fs.rmSync(root, cleanup);
    fs.rmSync(bootstrapLock, cleanup);
  });

  const settled = await Promise.allSettled(
    Array.from({ length: 8 }, (_, index) => sqliteOpenWorker(dbPath, index)),
  );
  const outcomes = settled.map((result) => (
    result.status === 'fulfilled'
      ? result.value
      : `${result.reason?.code || 'ERROR'}: ${result.reason?.message || result.reason}`
  ));
  assert.deepStrictEqual(outcomes, Array.from({ length: 8 }, (_, index) => String(index)));
  assert.strictEqual(fs.existsSync(bootstrapLock), false);
  assert.ok(fs.existsSync(dbPath));
});

test('production SQLite selection fails closed when the configured store is unusable', (t) => {
  const dbPath = unusableDatabasePath(t);
  assert.throws(
    () => openStore({
      env: {
        NODE_ENV: 'production',
        REDACTWALL_DB_DRIVER: 'sqlite',
        REDACTWALL_DB_PATH: dbPath,
      },
      dataDir: path.dirname(dbPath),
    }),
    (error) => error && error.code === 'REDACTWALL_SQLITE_UNUSABLE' &&
      /production startup aborted to preserve audit durability/.test(error.message),
  );
});

test('production application startup never falls back to a temporary SQLite store', (t) => {
  const dbPath = unusableDatabasePath(t);
  const result = spawnSync(process.execPath, ['-e', "require('./server/app')"], {
    cwd: path.join(__dirname, '..'),
    env: {
      ...process.env,
      NODE_ENV: 'production',
      REDACTWALL_ENV_PATH: path.join(path.dirname(dbPath), 'missing.env'),
      REDACTWALL_DB_DRIVER: 'sqlite',
      REDACTWALL_DB_PATH: dbPath,
    },
    encoding: 'utf8',
    timeout: 15000,
  });

  assert.notStrictEqual(result.status, 0, 'startup must fail rather than use an ephemeral store');
  const output = `${result.stdout}\n${result.stderr}`;
  assert.match(output, /production startup aborted to preserve audit durability/);
  assert.doesNotMatch(output, /falling back to/i);
});
