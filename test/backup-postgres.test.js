'use strict';
/**
 * Postgres mode for backup-store/backup-drill. Helper + failure-path tests
 * always run; the live end-to-end test needs REDACTWALL_TEST_PG_URL plus
 * pg_dump/pg_restore on PATH and skips cleanly otherwise.
 */
const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-pg-backup-test-'));
process.env.REDACTWALL_ENV_PATH = path.join(tempRoot, 'no.env');

const backup = require('../scripts/backup-store');
const backupDrill = require('../scripts/backup-drill');
const auditIntegrity = require('../server/audit-integrity');
const auditAnchor = require('../server/audit-anchor')._internal;

const REPO_ROOT = path.join(__dirname, '..');
const ADMIN_URL = process.env.REDACTWALL_TEST_PG_URL || '';
const HAS_PG_TOOLS = spawnSync('pg_dump', ['--version']).status === 0
  && spawnSync('pg_restore', ['--version']).status === 0;
const LIVE_SKIP = !ADMIN_URL ? 'REDACTWALL_TEST_PG_URL not set'
  : (!HAS_PG_TOOLS ? 'pg_dump/pg_restore not on PATH' : false);
const SECRET = '524-71-9043';
const liveAuditDirs = new Map();

function fileDescriptor(file) {
  const bytes = fs.statSync(file).size;
  const sha256 = crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
  return { file: path.basename(file), bytes, sha256 };
}

function writeAuthenticatedPgFixture(dumpPath, { embedded = false } = {}) {
  const env = embedded ? {} : { REDACTWALL_AUDIT_KEY: 'unit-pg-backup-manifest-key' };
  const key = embedded ? Buffer.alloc(32, 0x5a) : auditAnchor.configuredKey(env);
  const statePath = `${dumpPath}.audit-state.json`;
  const checkpointPath = `${dumpPath}.audit-checkpoint.json`;
  const manifestPath = `${dumpPath}.manifest.json`;
  const checkpoint = auditIntegrity.createCheckpoint(0, auditIntegrity.ZERO, key, 0);
  fs.writeFileSync(statePath, JSON.stringify(auditAnchor.signedState(key, true, embedded)), { mode: 0o600 });
  fs.writeFileSync(checkpointPath, JSON.stringify(checkpoint), { mode: 0o600 });
  const artifacts = {
    database: fileDescriptor(dumpPath),
    auditState: fileDescriptor(statePath),
    auditCheckpoint: fileDescriptor(checkpointPath),
  };
  const body = {
    schemaVersion: 2,
    driver: 'postgres',
    format: 'pg_dump-custom',
    backupFile: artifacts.database.file,
    backupBytes: artifacts.database.bytes,
    backupSha256: artifacts.database.sha256,
    artifacts,
    checkpoint,
    sourceIntegrity: { ok: true, count: 0 },
    backupIntegrity: { ok: true, count: 0 },
  };
  const manifest = {
    ...body,
    manifestAuthentication: {
      version: 1,
      algorithm: 'hmac-sha256',
      mac: auditIntegrity.hmac(key, auditIntegrity.canonical(body)),
    },
  };
  fs.writeFileSync(manifestPath, JSON.stringify(manifest), { mode: 0o600 });
  const principal = 'TEST\\backup-owner';
  const spawn = (command, args) => {
    assert.strictEqual(command, 'icacls.exe');
    return {
      status: 0,
      stdout: [
        `${path.resolve(args[0])} ${principal}:(F)`,
        '                    NT AUTHORITY\\SYSTEM:(F)',
        'Successfully processed 1 files',
      ].join('\r\n'),
    };
  };
  return {
    manifestPath,
    env,
    security: {
      privatePathSecurity: {
        platform: 'win32',
        principal,
        spawn,
        ownerIdentity: { processSid: 'S-1-5-21-1000', ownerSid: 'S-1-5-21-1000' },
      },
    },
    key,
  };
}

function restoreStagingEntries(directory) {
  return fs.readdirSync(directory).filter((name) => name.startsWith('.redactwall-backup-'));
}

function liveAuditDir(databaseUrl) {
  const key = crypto.createHash('sha256').update(databaseUrl).digest('hex').slice(0, 16);
  if (!liveAuditDirs.has(key)) {
    const directory = path.join(tempRoot, `audit-${key}`);
    fs.mkdirSync(directory, { recursive: true });
    liveAuditDirs.set(key, directory);
  }
  return liveAuditDirs.get(key);
}

function withEnv(overrides, fn) {
  const previous = {};
  for (const [key, value] of Object.entries(overrides)) {
    previous[key] = process.env[key];
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  return Promise.resolve()
    .then(fn)
    .finally(() => {
      for (const [key, value] of Object.entries(previous)) {
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      }
    });
}

test('pgConnectionEnv routes credentials through libpq env vars, never argv', () => {
  const env = backup.pgConnectionEnv('postgresql://app%40acme:s3cr%23t@db.internal:6543/redactwall?sslmode=require');
  assert.strictEqual(env.PGHOST, 'db.internal');
  assert.strictEqual(env.PGPORT, '6543');
  assert.strictEqual(env.PGUSER, 'app@acme');
  assert.strictEqual(env.PGPASSWORD, 's3cr#t');
  assert.strictEqual(env.PGDATABASE, 'redactwall');
  assert.strictEqual(env.PGSSLMODE, 'require');

  const socket = backup.pgConnectionEnv('postgresql:///redactwall?host=/var/run/postgresql&user=app');
  assert.strictEqual(socket.PGHOST, '/var/run/postgresql');
  assert.strictEqual(socket.PGUSER, 'app');
  assert.strictEqual(socket.PGDATABASE, 'redactwall');
});

test('pgConnectionEnv matches node-postgres endpoint, database, and credential resolution', () => {
  const connectionString =
    'postgresql://path-user:path-password@path-host:5432/path-db' +
    '?host=query-host&port=6543&user=query-user&password=query-password' +
    '&sslmode=verify-full&application_name=redactwall-backup';
  const nodeConfig = require('pg-connection-string').parse(connectionString);
  const env = backup.pgConnectionEnv(connectionString);

  assert.deepStrictEqual({
    host: env.PGHOST,
    port: env.PGPORT,
    user: env.PGUSER,
    password: env.PGPASSWORD,
    database: env.PGDATABASE,
  }, {
    host: nodeConfig.host,
    port: nodeConfig.port,
    user: nodeConfig.user,
    password: nodeConfig.password,
    database: nodeConfig.database,
  });
  assert.strictEqual(env.PGSSLMODE, 'verify-full');
  assert.strictEqual(env.PGAPPNAME, 'redactwall-backup');
});

test('pgConnectionEnv retains only TLS files understood by node-postgres and libpq', () => {
  const env = backup.pgConnectionEnv(
    'postgresql://path-user:path-password@path-host:5432/path-db' +
    '?sslmode=verify-full' +
    '&sslcert=C%3A%5Cprivate%5Cclient.crt&sslkey=C%3A%5Cprivate%5Cclient.key' +
    '&sslrootcert=C%3A%5Cprivate%5Croot.crt',
  );
  assert.strictEqual(env.PGSSLMODE, 'verify-full');
  assert.strictEqual(env.PGSSLCERT, 'C:\\private\\client.crt');
  assert.strictEqual(env.PGSSLKEY, 'C:\\private\\client.key');
  assert.strictEqual(env.PGSSLROOTCERT, 'C:\\private\\root.crt');
  assert.strictEqual(env.PGPASSFILE, undefined);
  assert.strictEqual(env.PGSSLCRL, undefined);
});

test('sanitizeDatabaseUrl strips hierarchical, named, and fragment credential material', () => {
  const secretValues = ['hierarchy-secret', 'query-secret', 'ssl-secret', 'fragment-secret', 'C:\\private\\pgpass.conf', 'C:\\private\\client.key'];
  const sanitized = backup.sanitizeDatabaseUrl(
    'postgresql://app:hierarchy-secret@db:5432/redactwall' +
    '?password=query-secret&sslpassword=ssl-secret' +
    '&passfile=C%3A%5Cprivate%5Cpgpass.conf&sslkey=C%3A%5Cprivate%5Cclient.key' +
    '&sslcert=C%3A%5Cprivate%5Cclient.crt&sslrootcert=C%3A%5Cprivate%5Croot.crt' +
    '&sslmode=verify-full#fragment-secret',
  );
  for (const secret of secretValues) assert.ok(!decodeURIComponent(sanitized).includes(secret));
  const url = new URL(sanitized);
  for (const key of ['password', 'sslpassword', 'passfile', 'sslkey', 'sslcert', 'sslrootcert']) {
    assert.strictEqual(url.searchParams.has(key), false, `${key} is removed from returned URLs`);
  }
  assert.strictEqual(url.searchParams.get('sslmode'), 'verify-full');
  assert.strictEqual(url.hash, '');
});

test('shared Postgres URL contract rejects fragments, duplicates, and backup-only overrides', () => {
  const cases = [
    'postgresql://app:private@db.internal/redactwall?sslmode=require#bearer-secret',
    'postgresql://app@db.internal/redactwall?sslmode=require&password=first&password=second',
    'postgresql://app@db.internal/redactwall?sslmode=require&hostaddr=203.0.113.44',
    'postgresql://app@db.internal/path-db?sslmode=require&dbname=other-db',
    'postgresql://app@db.internal/redactwall?sslmode=require&passfile=C%3A%5Cprivate%5Cpgpass.conf',
  ];
  for (const connectionString of cases) {
    assert.throws(
      () => backup.assertPostgresConnectionUrl(connectionString),
      (error) => !error.message.includes('bearer-secret') && !error.message.includes('first'),
      connectionString,
    );
    assert.throws(() => backup.pgConnectionEnv(connectionString), undefined, connectionString);
  }
});

test('pgConnectionEnv rejects unsupported sslpassword without echoing the secret', () => {
  const secret = 'private-key-passphrase';
  assert.throws(
    () => backup.pgConnectionEnv(`postgresql://app@db/redactwall?sslmode=require&sslpassword=${secret}`),
    (error) => /invalid|ambiguous|unsupported/i.test(error.message) && !error.message.includes(secret),
  );
});

test('sanitizeDatabaseUrl strips the password and deriveDatabaseUrl swaps databases', () => {
  const sanitized = backup.sanitizeDatabaseUrl('postgresql://app:supersecretpw@db:5432/redactwall');
  assert.strictEqual(sanitized, 'postgresql://app@db:5432/redactwall');
  assert.ok(!sanitized.includes('supersecretpw'));

  const derived = backup.deriveDatabaseUrl('postgresql://app:pw@db:5432/redactwall', 'redactwall_drill_ab12');
  assert.strictEqual(new URL(derived).pathname, '/redactwall_drill_ab12');
  assert.strictEqual(new URL(derived).password, 'pw');

  const pathSource = 'postgresql://app:pw@db:5432/path-source?sslmode=require';
  const scratch = backup.deriveDatabaseUrl(pathSource, 'redactwall_drill_named');
  assert.strictEqual(backup._internal.pgDatabaseName(scratch), 'redactwall_drill_named');
  assert.strictEqual(backup.pgConnectionEnv(scratch).PGDATABASE, 'redactwall_drill_named');

  const passthrough = backup.deriveDatabaseUrl('postgresql://app:pw@db:5432/redactwall', 'postgresql://other@host2/db2');
  assert.strictEqual(new URL(passthrough).hostname, 'host2');
});

test('isPgDumpFile recognizes the PGDMP magic and tolerates missing files', () => {
  const dumpish = path.join(tempRoot, 'archive.dump');
  fs.writeFileSync(dumpish, 'PGDMP' + '\0rest-of-archive');
  const sqliteish = path.join(tempRoot, 'store.db');
  fs.writeFileSync(sqliteish, 'SQLite format 3\0');

  assert.strictEqual(backup.isPgDumpFile(dumpish), true);
  assert.strictEqual(backup.isPgDumpFile(sqliteish), false);
  assert.strictEqual(backup.isPgDumpFile(path.join(tempRoot, 'nope.dump')), false);
});

test('Postgres snapshot verification rejects a rehashed entry with an invalid HMAC', async () => {
  const key = Buffer.alloc(32, 7);
  const checkpoint = auditIntegrity.createCheckpoint(0, auditIntegrity.ZERO, key, 0);
  const original = auditIntegrity.authenticatedEntry(
    auditIntegrity.ZERO,
    { id: 'a_authenticated', action: 'BLOCKED' },
    key,
  );
  const { hash: _hash, mac, ...tamperedBody } = original;
  tamperedBody.action = 'ALLOWED';
  const forged = {
    ...tamperedBody,
    hash: auditIntegrity.sha(auditIntegrity.canonical(tamperedBody)),
    mac,
  };
  const client = {
    async query(sql) {
      assert.match(sql, /^SELECT (?:seq, )?entry FROM audit ORDER BY seq ASC$/);
      return { rows: [{ seq: 1, entry: forged }] };
    },
  };

  assert.strictEqual(auditIntegrity.validAuthenticatedEntry(forged, key), false);
  assert.deepStrictEqual(
    await backup._internal.verifyPgSnapshotIntegrity(client, { key, checkpoint }),
    { ok: false, count: 1, brokenAt: 'a_authenticated', reason: 'entry-authentication' },
  );
});

test('Postgres restore is one transaction and retains clean/if-exists on forced replacement', () => {
  const dumpPath = path.join(tempRoot, 'transactional-restore.dump');
  fs.writeFileSync(dumpPath, Buffer.from('PGDMP\0transactional-test'));
  const fixture = writeAuthenticatedPgFixture(dumpPath);
  const fixtureVerification = backup.verifyBackup({
    file: dumpPath,
    manifestFile: fixture.manifestPath,
    env: fixture.env,
    security: fixture.security,
  });
  assert.strictEqual(fixtureVerification.ok, true, JSON.stringify(fixtureVerification));
  const calls = [];

  const restored = backup._internal.restorePgBackup({
    file: dumpPath,
    to: 'redactwall_restore_target',
    manifestFile: fixture.manifestPath,
    force: true,
    env: fixture.env,
    security: fixture.security,
  }, {
    connectionString: 'postgresql://app:private@db.internal/source?sslmode=require',
    runPgTool: (tool, args, connectionString) => calls.push({ tool, args, connectionString }),
    verifyRestoredPgDatabase: () => ({
      auditIntegrity: { ok: true, count: 4 },
      queryCount: 3,
      auditCount: 4,
    }),
  });

  assert.strictEqual(restored.ok, true);
  assert.strictEqual(calls.length, 1);
  assert.strictEqual(calls[0].tool, 'pg_restore');
  for (const flag of ['--exit-on-error', '--single-transaction', '--clean', '--if-exists']) {
    assert.ok(calls[0].args.includes(flag), flag);
  }
  assert.ok(!JSON.stringify(calls[0].args).includes('private'));
});

test('Postgres restore uses an authenticated private snapshot when the source is swapped at tool launch', () => {
  const restoreDir = path.join(tempRoot, 'restore-snapshot-swap');
  fs.mkdirSync(restoreDir);
  const dumpPath = path.join(restoreDir, 'snapshot.dump');
  const authenticatedBytes = Buffer.from('PGDMP\0authenticated-restore-snapshot');
  const replacementBytes = Buffer.from('PGDMP\0attacker-controlled-replacement');
  fs.writeFileSync(dumpPath, authenticatedBytes);
  const fixture = writeAuthenticatedPgFixture(dumpPath);
  let toolArchive;
  let toolBytes;

  const restored = backup._internal.restorePgBackup({
    file: dumpPath,
    to: 'redactwall_restore_snapshot_target',
    manifestFile: fixture.manifestPath,
    env: fixture.env,
    security: { ...fixture.security, platform: 'linux' },
  }, {
    connectionString: 'postgresql://app:private@db.internal/source?sslmode=require',
    restoreStagingParent: restoreDir,
    runPgTool: (_tool, args) => {
      fs.writeFileSync(dumpPath, replacementBytes);
      toolArchive = args.at(-1);
      toolBytes = fs.readFileSync(toolArchive);
    },
    verifyRestoredPgDatabase: () => ({
      auditIntegrity: { ok: true, count: 0 },
      queryCount: 0,
      auditCount: 0,
    }),
  });

  assert.strictEqual(restored.ok, true);
  assert.notStrictEqual(path.resolve(toolArchive), path.resolve(dumpPath));
  assert.deepStrictEqual(toolBytes, authenticatedBytes);
  assert.strictEqual(fs.existsSync(toolArchive), false, 'the private restore snapshot is removed after verification');
  assert.deepStrictEqual(fs.readFileSync(dumpPath), replacementBytes, 'the source swap occurred deterministically');
});

test('Postgres restore removes the private snapshot when post-restore verification throws', () => {
  const restoreDir = path.join(tempRoot, 'restore-snapshot-cleanup');
  fs.mkdirSync(restoreDir);
  const dumpPath = path.join(restoreDir, 'cleanup.dump');
  fs.writeFileSync(dumpPath, Buffer.from('PGDMP\0cleanup-after-verification-error'));
  const fixture = writeAuthenticatedPgFixture(dumpPath);
  let stagedArchive;

  assert.throws(() => backup._internal.restorePgBackup({
    file: dumpPath,
    to: 'redactwall_restore_cleanup_target',
    manifestFile: fixture.manifestPath,
    env: fixture.env,
    security: { ...fixture.security, platform: 'linux' },
  }, {
    connectionString: 'postgresql://app:private@db.internal/source?sslmode=require',
    restoreStagingParent: restoreDir,
    runPgTool: (_tool, args) => {
      stagedArchive = args.at(-1);
      assert.strictEqual(fs.existsSync(stagedArchive), true);
    },
    verifyRestoredPgDatabase: () => {
      assert.strictEqual(fs.existsSync(stagedArchive), true, 'snapshot lives through post-restore verification');
      throw new Error('synthetic post-restore verification failure');
    },
  }), /synthetic post-restore verification failure/);

  assert.strictEqual(fs.existsSync(stagedArchive), false);
  assert.deepStrictEqual(restoreStagingEntries(restoreDir), []);
});

test('Postgres restore aborts before pg_restore and cleans staging when file fsync fails', () => {
  const restoreDir = path.join(tempRoot, 'restore-snapshot-fsync');
  fs.mkdirSync(restoreDir);
  const dumpPath = path.join(restoreDir, 'fsync.dump');
  fs.writeFileSync(dumpPath, Buffer.from('PGDMP\0fsync-failure'));
  const fixture = writeAuthenticatedPgFixture(dumpPath);
  const originalFsync = fs.fsyncSync;
  let failNextFileFsync = true;
  let toolCalls = 0;
  fs.fsyncSync = (fd) => {
    if (failNextFileFsync && fs.fstatSync(fd).isFile()) {
      failNextFileFsync = false;
      const error = new Error('synthetic restore snapshot fsync EIO');
      error.code = 'EIO';
      throw error;
    }
    return originalFsync(fd);
  };
  try {
    assert.throws(() => backup._internal.restorePgBackup({
      file: dumpPath,
      to: 'redactwall_restore_fsync_target',
      manifestFile: fixture.manifestPath,
      env: fixture.env,
      security: { ...fixture.security, platform: 'linux' },
    }, {
      connectionString: 'postgresql://app:private@db.internal/source?sslmode=require',
      restoreStagingParent: restoreDir,
      runPgTool: () => { toolCalls += 1; },
    }), /synthetic restore snapshot fsync EIO/);
  } finally {
    fs.fsyncSync = originalFsync;
  }

  assert.strictEqual(toolCalls, 0);
  assert.strictEqual(failNextFileFsync, false, 'the injected file fsync boundary was reached');
  assert.deepStrictEqual(restoreStagingEntries(restoreDir), []);
});

test('Postgres restore rejects a staging-directory fsync failure and removes the snapshot', () => {
  const restoreDir = path.join(tempRoot, 'restore-snapshot-directory-fsync');
  fs.mkdirSync(restoreDir);
  const dumpPath = path.join(restoreDir, 'directory-fsync.dump');
  fs.writeFileSync(dumpPath, Buffer.from('PGDMP\0directory-fsync-failure'));
  const fixture = writeAuthenticatedPgFixture(dumpPath);
  const originalFsync = fs.fsyncSync;
  let failedDirectoryFsync = false;
  let toolCalls = 0;
  fs.fsyncSync = (fd) => {
    if (!failedDirectoryFsync && fs.fstatSync(fd).isDirectory()) {
      failedDirectoryFsync = true;
      const error = new Error('synthetic restore staging directory fsync EIO');
      error.code = 'EIO';
      throw error;
    }
    return originalFsync(fd);
  };
  try {
    assert.throws(() => backup._internal.restorePgBackup({
      file: dumpPath,
      to: 'redactwall_restore_directory_fsync_target',
      manifestFile: fixture.manifestPath,
      env: fixture.env,
      security: { ...fixture.security, platform: 'linux' },
    }, {
      connectionString: 'postgresql://app:private@db.internal/source?sslmode=require',
      restoreStagingParent: restoreDir,
      runPgTool: () => { toolCalls += 1; },
    }), /synthetic restore staging directory fsync EIO/);
  } finally {
    fs.fsyncSync = originalFsync;
  }

  assert.strictEqual(toolCalls, 0);
  assert.strictEqual(failedDirectoryFsync, true);
  assert.deepStrictEqual(restoreStagingEntries(restoreDir), []);
});

test('Postgres restore rejects a missing authenticated manifest with --force before pg_restore', () => {
  const dumpPath = path.join(tempRoot, 'missing-manifest-force.dump');
  fs.writeFileSync(dumpPath, Buffer.from('PGDMP\0missing-manifest-force'));
  const fixture = writeAuthenticatedPgFixture(dumpPath);
  fs.rmSync(fixture.manifestPath);
  const calls = [];

  assert.throws(() => backup._internal.restorePgBackup({
    file: dumpPath,
    to: 'redactwall_restore_target',
    force: true,
    env: fixture.env,
    security: fixture.security,
  }, {
    connectionString: 'postgresql://app:private@db.internal/source?sslmode=require',
    runPgTool: (...args) => calls.push(args),
    verifyRestoredPgDatabase: () => { throw new Error('restore verification must not run'); },
  }), /authenticated manifest/i);
  assert.strictEqual(calls.length, 0, 'pg_restore must not run for an unauthenticated artifact set');
});

test('Postgres rejects a manifest forged with the embedded key packaged beside the dump', () => {
  const dumpPath = path.join(tempRoot, 'embedded-manifest-key.dump');
  fs.writeFileSync(dumpPath, Buffer.from('PGDMP\0embedded-manifest-key'));
  const fixture = writeAuthenticatedPgFixture(dumpPath, { embedded: true });
  const packagedState = JSON.parse(fs.readFileSync(`${dumpPath}.audit-state.json`, 'utf8'));
  assert.strictEqual(packagedState.key, fixture.key.toString('base64'), 'the attacker can read the bundled key');

  const verification = backup.verifyBackup({
    file: dumpPath,
    manifestFile: fixture.manifestPath,
    env: fixture.env,
    security: fixture.security,
  });
  assert.strictEqual(verification.ok, false);
  assert.strictEqual(verification.manifestOk, false);
  assert.strictEqual(verification.manifestReason, 'manifest-authentication-key');

  const calls = [];
  assert.throws(() => backup._internal.restorePgBackup({
    file: dumpPath,
    to: 'redactwall_restore_target',
    force: true,
    env: fixture.env,
    security: fixture.security,
  }, {
    connectionString: 'postgresql://app:private@db.internal/source?sslmode=require',
    runPgTool: (...args) => calls.push(args),
  }), /does not verify/i);
  assert.strictEqual(calls.length, 0, 'pg_restore must not run when the MAC key is bundled with the backup');
});

test('postgres createBackup without pg_dump on PATH fails with an install hint', async () => {
  const emptyBin = fs.mkdtempSync(path.join(tempRoot, 'empty-bin-'));
  await withEnv({ PATH: emptyBin }, async () => {
    await assert.rejects(() => backup.createBackup({
      outDir: path.join(tempRoot, 'pg-missing-tool'),
      dbModule: { _driverKind: 'postgres', verifyAuditChain: () => ({ ok: true, count: 0 }), stats: () => ({ total: 0 }) },
      connectionString: 'postgresql://redactwall_app@127.0.0.1:5432/redactwall',
      // This test isolates pg_dump discovery; ACL behavior has dedicated tests.
      security: { platform: 'linux' },
    }), /pg_dump not found on PATH.*postgresql-client/s);
  });
});

test('postgres createBackup requires a connection string and refuses unknown drivers', async () => {
  await withEnv({ REDACTWALL_DATABASE_URL: undefined, DATABASE_URL: undefined }, async () => {
    await assert.rejects(() => backup.createBackup({
      dbModule: { _driverKind: 'postgres', verifyAuditChain: () => ({ ok: true, count: 0 }) },
    }), /require REDACTWALL_DATABASE_URL/);
  });
  await assert.rejects(() => backup.createBackup({
    dbModule: { _driverKind: 'mysql' },
  }), /unsupported driver: mysql/);
});

test('Postgres backup TLS policy permits only an explicit non-production loopback exception', () => {
  const loopback = 'postgresql://app:private@127.0.0.1:5432/redactwall?sslmode=disable';
  assert.doesNotThrow(() => backup.assertPostgresConnectionUrl(loopback, { env: { NODE_ENV: 'test' } }));
  assert.throws(
    () => backup.assertPostgresConnectionUrl(loopback, { env: { NODE_ENV: 'production' } }),
    /sslmode=require/,
  );
  assert.throws(
    () => backup.assertPostgresConnectionUrl('postgresql://app:private@db.internal/redactwall?sslmode=disable', { env: { NODE_ENV: 'test' } }),
    /sslmode=require/,
  );
  assert.throws(
    () => backup.assertPostgresConnectionUrl(
      'postgresql://app:private@127.0.0.1/redactwall?hostaddr=203.0.113.44&sslmode=disable',
      { env: { NODE_ENV: 'test' } },
    ),
    /invalid|ambiguous|unsupported/,
  );

  const previousHostAddress = process.env.PGHOSTADDR;
  const previousService = process.env.PGSERVICE;
  const previousNodeEnv = process.env.NODE_ENV;
  process.env.PGHOSTADDR = '203.0.113.44';
  process.env.PGSERVICE = 'unsafe-inherited-service';
  process.env.NODE_ENV = 'test';
  try {
    const cleanEnv = backup.pgConnectionEnv(loopback);
    assert.strictEqual(cleanEnv.PGHOSTADDR, undefined);
    assert.strictEqual(cleanEnv.PGSERVICE, undefined);
    assert.strictEqual(cleanEnv.PGHOST, '127.0.0.1');
  } finally {
    if (previousHostAddress === undefined) delete process.env.PGHOSTADDR;
    else process.env.PGHOSTADDR = previousHostAddress;
    if (previousService === undefined) delete process.env.PGSERVICE;
    else process.env.PGSERVICE = previousService;
    if (previousNodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = previousNodeEnv;
  }
});

test('Postgres backup create, restore target, and drill reject remote plaintext before tools or clients receive credentials', async () => {
  const credential = 'backup-transport-secret';
  const insecure = `postgresql://app:${credential}@db.internal/redactwall?sslmode=disable`;
  let snapshots = 0;
  let tools = 0;
  await assert.rejects(
    () => backup.createBackup({
      outDir: path.join(tempRoot, 'unsafe-create'),
      dbModule: { _driverKind: 'postgres', verifyAuditChain: () => ({ ok: true, count: 0 }) },
      connectionString: insecure,
      withPgSnapshot: async () => { snapshots += 1; },
      runPgTool: () => { tools += 1; },
    }),
    (error) => /sslmode=require/.test(error.message) && !error.message.includes(credential),
  );
  assert.deepStrictEqual({ snapshots, tools }, { snapshots: 0, tools: 0 });

  const dumpPath = path.join(tempRoot, 'unsafe-target.dump');
  fs.writeFileSync(dumpPath, Buffer.from('PGDMP\0unsafe-target'));
  const fixture = writeAuthenticatedPgFixture(dumpPath);
  let verifies = 0;
  assert.throws(
    () => backup._internal.restorePgBackup({
      file: dumpPath,
      to: insecure,
      manifestFile: fixture.manifestPath,
      env: fixture.env,
      security: fixture.security,
    }, {
      connectionString: 'postgresql://app:private@source.internal/redactwall?sslmode=require',
      runPgTool: () => { tools += 1; },
      verifyRestoredPgDatabase: () => { verifies += 1; },
    }),
    (error) => /sslmode=require/.test(error.message) && !error.message.includes(credential),
  );
  assert.deepStrictEqual({ tools, verifies }, { tools: 0, verifies: 0 });

  let creates = 0;
  await withEnv({ NODE_ENV: 'production', REDACTWALL_DATABASE_URL: insecure, DATABASE_URL: undefined }, async () => {
    await assert.rejects(
      () => backupDrill.runDrill({
        dbModule: { _driverKind: 'postgres' },
        createBackup: async () => { creates += 1; },
      }),
      (error) => /sslmode=require/.test(error.message) && !error.message.includes(credential),
    );
  });
  assert.strictEqual(creates, 0, 'drill refuses the URL before creating an artifact or opening a client');

  const childEnv = {
    ...process.env,
    NODE_ENV: 'test',
    REDACTWALL_DB_DRIVER: 'postgres',
    REDACTWALL_DATABASE_URL: insecure,
    DATABASE_URL: insecure,
    REDACTWALL_ENV_PATH: path.join(tempRoot, 'no-child.env'),
  };
  for (const args of [
    [path.join(REPO_ROOT, 'scripts', 'backup-store.js'), 'create', path.join(tempRoot, 'unsafe-cli-create')],
    [path.join(REPO_ROOT, 'scripts', 'backup-drill.js')],
  ]) {
    const child = spawnSync(process.execPath, args, {
      cwd: REPO_ROOT,
      env: childEnv,
      encoding: 'utf8',
      timeout: 10_000,
    });
    assert.notStrictEqual(child.status, 0, args[0]);
    assert.match(child.stderr, /sslmode=require/, args[0]);
    assert.ok(!child.stderr.includes(credential), 'CLI error does not echo the rejected connection credential');
  }
});

// ---- Live end-to-end (needs REDACTWALL_TEST_PG_URL + pg_dump/pg_restore) --------

// Synthetic credential for the drill role; a password in the URL lets the
// no-leak assertions run for real (ignored where the server uses trust auth).
const BACKUP_ROLE_PASSWORD = 'redactwall-backup-test-pw';

/**
 * pg_dump refuses servers newer than itself; skip (not fail) when the
 * runner's client tools trail the service container (e.g. pg_dump 16 vs a
 * postgres:17 CI lane).
 */
async function pgToolsTooOld(t) {
  // e.g. "pg_dump (PostgreSQL) 16.13 (Ubuntu 16.13-0ubuntu0.24.04.1)"
  const clientMajor = Number((spawnSync('pg_dump', ['--version'], { encoding: 'utf8' })
    .stdout.match(/\(PostgreSQL\)\s+(\d+)/) || [])[1]);
  const { Client } = require('pg');
  const admin = new Client({ connectionString: ADMIN_URL });
  await admin.connect();
  const serverMajor = Math.floor(Number((await admin.query('SHOW server_version_num')).rows[0].server_version_num) / 10000);
  await admin.end();
  if (clientMajor >= serverMajor) return false;
  t.skip(`pg_dump ${clientMajor} cannot dump a v${serverMajor} server`);
  return true;
}

async function createFreshDatabase() {
  const { Client } = require('pg');
  const admin = new Client({ connectionString: ADMIN_URL });
  await admin.connect();
  const name = 'redactwall_bk_' + crypto.randomBytes(5).toString('hex');
  // The drill restores into a scratch database, so the role needs CREATEDB
  // (unlike the plain app role) — mirrors the maintenance-role guidance in
  // docs/deployment/MANAGED_POSTGRES.md.
  await admin.query(`
    DO $$ BEGIN
      IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'redactwall_backup') THEN
        CREATE ROLE redactwall_backup LOGIN;
      END IF;
    END $$;
  `);
  await admin.query(`ALTER ROLE redactwall_backup LOGIN CREATEDB PASSWORD '${BACKUP_ROLE_PASSWORD}'`);
  await admin.query(`CREATE DATABASE ${name} OWNER redactwall_backup`);
  await admin.end();
  const url = new URL(ADMIN_URL);
  url.username = 'redactwall_backup';
  url.password = BACKUP_ROLE_PASSWORD;
  url.pathname = '/' + name;
  return url.toString();
}

function childEnv(databaseUrl) {
  return {
    ...process.env,
    NODE_ENV: 'test',
    REDACTWALL_ENV_PATH: path.join(tempRoot, 'no.env'),
    REDACTWALL_DB_DRIVER: 'postgres',
    REDACTWALL_DATABASE_URL: databaseUrl,
    REDACTWALL_AUDIT_DIR: liveAuditDir(databaseUrl),
    REDACTWALL_AUDIT_STATE_PATH: '',
    REDACTWALL_AUDIT_CHECKPOINT_PATH: '',
    REDACTWALL_SECRET: 'unit-secret-stable',
    REDACTWALL_DATA_KEY: 'unit-data-key-stable',
  };
}

function runNode(args, env) {
  const result = spawnSync(process.execPath, args, { cwd: REPO_ROOT, env, encoding: 'utf8', timeout: 90000 });
  return result;
}

function assertNoSecrets(output, databaseUrl) {
  assert.ok(!output.includes(SECRET), 'output must not leak prompt PII');
  assert.ok(!output.includes(databaseUrl), 'output must not leak the connection string');
  const password = new URL(databaseUrl).password;
  if (password) assert.ok(!output.includes(password), 'output must not leak the DB password');
}

test('postgres backup, verify, and drill restore into a scratch database', { skip: LIVE_SKIP }, async (t) => {
  if (await pgToolsTooOld(t)) return;
  const databaseUrl = await createFreshDatabase();
  const env = childEnv(databaseUrl);

  const seed = runNode(['-e', `
    const db = require('./server/db');
    const q = db.createQuery({
      status: 'pending', user: 'analyst@example.test', redactedPrompt: 'Member [US_SSN]',
      _rawPrompt: 'Member SSN ${SECRET}', findings: [{ type: 'US_SSN', masked: '***-**-9043' }],
    });
    db.appendAudit({ action: 'BLOCKED', queryId: q.id, actor: 'analyst@example.test', detail: 'structured pii detected' });
    db._db.close();
  `], env);
  assert.strictEqual(seed.status, 0, seed.stderr);

  const outDir = path.join(tempRoot, 'pg-backups');
  const createRun = runNode([path.join(REPO_ROOT, 'scripts', 'backup-store.js'), 'create', outDir], env);
  assert.strictEqual(createRun.status, 0, createRun.stderr);
  const created = JSON.parse(createRun.stdout);
  assert.strictEqual(created.ok, true);
  assert.strictEqual(created.driver, 'postgres');
  assert.match(path.basename(created.file), /^redactwall-.*\.dump$/);
  assert.strictEqual(fs.readFileSync(created.file).subarray(0, 5).toString('latin1'), 'PGDMP');
  assert.strictEqual(created.manifest.sourceIntegrity.ok, true);
  assert.strictEqual(created.manifest.stats.total, 1);
  assert.strictEqual(created.manifest.rawPromptBodiesIncluded, false);
  assertNoSecrets(createRun.stdout, databaseUrl);

  const verifyRun = runNode([path.join(REPO_ROOT, 'scripts', 'backup-store.js'), 'verify', created.file], env);
  assert.strictEqual(verifyRun.status, 0, verifyRun.stderr);
  const verified = JSON.parse(verifyRun.stdout);
  assert.strictEqual(verified.ok, true);
  assert.strictEqual(verified.driver, 'postgres');
  assert.strictEqual(verified.manifestOk, true);

  const drillDir = path.join(tempRoot, 'pg-drill');
  const drillRun = runNode([path.join(REPO_ROOT, 'scripts', 'backup-drill.js'), '--backup-dir', drillDir, '--keep'], env);
  assert.strictEqual(drillRun.status, 0, drillRun.stderr);
  const report = JSON.parse(drillRun.stdout);
  assert.strictEqual(report.result, 'PASS');
  assert.strictEqual(report.driver, 'postgres');
  assert.ok(report.checks.length >= 7);
  assert.ok(report.checks.every((c) => c.ok === true), JSON.stringify(report.checks));
  assert.strictEqual(report.restored.queryCount, 1);
  assert.strictEqual(report.restored.auditCount, 1);
  assert.strictEqual(report.restored.auditChainOk, true);
  assert.match(report.restored.scratchDatabase, /^redactwall_drill_[0-9a-f]{10}$/);
  assert.deepStrictEqual(report.artifacts, { keptAt: drillDir });
  assert.ok(fs.readdirSync(drillDir).some((name) => name.endsWith('.dump')));
  assertNoSecrets(drillRun.stdout, databaseUrl);

  // The scratch database is always dropped, --keep or not.
  const { Client } = require('pg');
  const admin = new Client({ connectionString: ADMIN_URL });
  await admin.connect();
  const leftovers = await admin.query('SELECT datname FROM pg_database WHERE datname = $1', [report.restored.scratchDatabase]);
  await admin.end();
  assert.strictEqual(leftovers.rowCount, 0, 'scratch database must be dropped');
});

test('postgres drill fails loudly on a tampered evidence store', { skip: LIVE_SKIP }, async (t) => {
  if (await pgToolsTooOld(t)) return;
  const databaseUrl = await createFreshDatabase();
  const env = childEnv(databaseUrl);

  const seed = runNode(['-e', `
    const db = require('./server/db');
    const q = db.createQuery({ status: 'allowed', redactedPrompt: 'benign', findings: [] });
    db.appendAudit({ action: 'ALLOWED', queryId: q.id, actor: 'drill-test' });
    // Editing evidence after the fact must break the chain's content binding.
    db._db.prepare("UPDATE queries SET data = replace(data, 'benign', 'tampered') WHERE id = ?").run(q.id);
    db._db.close();
  `], env);
  assert.strictEqual(seed.status, 0, seed.stderr);

  const failRun = runNode([path.join(REPO_ROOT, 'scripts', 'backup-drill.js'), '--backup-dir', path.join(tempRoot, 'pg-drill-fail')], env);
  assert.notStrictEqual(failRun.status, 0);
  assert.match(failRun.stderr, /broken audit integrity/);
  assertNoSecrets(failRun.stdout + failRun.stderr, databaseUrl);
});

test.after(() => {
  fs.rmSync(tempRoot, { recursive: true, force: true });
});
