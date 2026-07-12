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
const UNIT_TARGET_DATABASE_SCOPE = 'd'.repeat(64);
const TEST_PG_DATABASE_DEFINITION = Object.freeze({
  serverMajor: 17,
  encoding: 'UTF8',
  localeProvider: 'libc',
  lcCollate: 'C',
  lcCtype: 'C',
  locale: null,
  icuRules: null,
});
function mockPgRestoreControl(overrides = {}) {
  const identity = { datname: 'redactwall_restore_target', oid: '90001', owner_oid: '90002' };
  const guard = { kind: 'mock-guard' };
  return {
    preflight: () => ({ targetServerMajor: 17 }),
    createStaging: () => ({ ...identity, datname: 'redactwall_restore_stage' }),
    openGuard: () => guard,
    guardDriver: () => guard,
    assertOnlyGuard: () => {},
    freeze: () => {},
    closeGuardAndAssertNoConnections: () => {},
    rename: () => identity,
    enable: () => identity,
    reconcileRename: () => 'staging',
    cleanupOwnedStaging: () => {},
    close: () => {},
    ...overrides,
  };
}
const EMPTY_PG_TARGET = {
  inspectPgRestoreTarget: () => ({ empty: true, objectCount: 0 }),
  targetPgDatabaseScope: () => UNIT_TARGET_DATABASE_SCOPE,
  createPgRestoreControl: () => mockPgRestoreControl(),
};

const backup = require('../scripts/backup-store');
const backupDrill = require('../scripts/backup-drill');
const auditIntegrity = require('../server/audit-integrity');
const auditAnchor = require('../server/audit-anchor')._internal;
const privatePaths = require('../server/private-path');

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

function writeAuthenticatedPgFixture(dumpPath, { embedded = false, databaseScope = null } = {}) {
  const env = embedded ? {} : { REDACTWALL_AUDIT_KEY: 'unit-pg-backup-manifest-key' };
  const key = embedded ? Buffer.alloc(32, 0x5a) : auditAnchor.configuredKey(env);
  const statePath = `${dumpPath}.audit-state.json`;
  const checkpointPath = `${dumpPath}.audit-checkpoint.json`;
  const manifestPath = `${dumpPath}.manifest.json`;
  const checkpoint = auditIntegrity.createCheckpoint(0, auditIntegrity.ZERO, key, 0);
  fs.writeFileSync(
    statePath,
    JSON.stringify(auditAnchor.signedState(key, true, embedded, true, databaseScope)),
    { mode: 0o600 },
  );
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
    sourceDatabaseDefinition: TEST_PG_DATABASE_DEFINITION,
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

function restoreAuditDirectory(label) {
  return path.join(tempRoot, `${label}-parent`, 'audit');
}

function writePgDrillArtifacts(directory, label) {
  fs.mkdirSync(directory, { recursive: true });
  const file = path.join(directory, `${label}.dump`);
  const auditStateFile = `${file}.audit-state.json`;
  const auditCheckpointFile = `${file}.audit-checkpoint.json`;
  const manifestFile = `${file}.manifest.json`;
  for (const artifact of [file, auditStateFile, auditCheckpointFile, manifestFile]) {
    fs.writeFileSync(artifact, path.basename(artifact));
  }
  return {
    file,
    auditStateFile,
    auditCheckpointFile,
    manifestFile,
    bytes: fs.statSync(file).size,
    backupSha256: crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'),
    manifest: {
      sourceIntegrity: { ok: true, count: 0 },
      stats: { total: 0 },
    },
  };
}

function createPgDrillArtifacts(label, capture = () => {}) {
  return async ({ outDir }) => {
    const created = writePgDrillArtifacts(outDir, label);
    capture(created);
    return created;
  };
}

function pgDrillRestoreResult(databaseName, overrides = {}) {
  return {
    ok: true,
    queryCount: 0,
    auditCount: 0,
    auditIntegrity: { ok: true, count: 0 },
    databaseIdentity: { name: databaseName, oid: '70101', ownerOid: '70102' },
    ...overrides,
  };
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

async function withOneFailedPrivateStagingRemoval(cleanupParent, callback) {
  const originalRmSync = fs.rmSync;
  const expectedParent = path.resolve(cleanupParent);
  let retainedPath = '';
  fs.rmSync = function failOneCommittedStagingRemoval(target, options) {
    const candidate = String(target);
    if (!retainedPath && path.basename(candidate).includes('.cleanup-')
        && path.resolve(path.dirname(candidate)) === expectedParent
        && fs.existsSync(candidate) && fs.statSync(candidate).isDirectory()) {
      retainedPath = candidate;
      const error = new Error('synthetic committed Postgres staging cleanup failure');
      error.code = 'EIO';
      throw error;
    }
    return originalRmSync.call(fs, target, options);
  };
  try {
    const result = await callback();
    return { result, retainedPath };
  } finally {
    fs.rmSync = originalRmSync;
  }
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

test('Postgres snapshot client authority ignores hostile inherited PG settings', async () => {
  await withEnv({
    PGHOST: 'attacker.internal',
    PGPORT: '6543',
    PGUSER: 'attacker',
    PGPASSWORD: 'inherited-password',
    PGDATABASE: 'attacker_database',
    PGOPTIONS: '-c search_path=attacker',
    PGAPPNAME: 'attacker-client',
    PGSSLMODE: 'disable',
  }, async () => {
    const connectionString = 'postgresql://url-user@db.internal/url-db?sslmode=require';
    let received;
    await assert.rejects(
      backup._internal.withPgSnapshot(connectionString, async () => {}, {
        createClient(config) {
          received = config;
          throw new Error('captured explicit snapshot config');
        },
      }),
      /captured explicit snapshot config/,
    );

    assert.strictEqual(received.host, 'db.internal');
    assert.strictEqual(received.port, 5432);
    assert.strictEqual(received.user, 'url-user');
    assert.strictEqual(received.database, 'url-db');
    assert.strictEqual(received.password(), '');
    assert.strictEqual(received.options, '-c client_min_messages=notice');
    assert.strictEqual(received.application_name, 'redactwall-backup-snapshot');
    assert.notStrictEqual(received.ssl, false);
    assert.strictEqual(Object.keys(received).includes('password'), false, 'password provider stays non-enumerable');

    const { Client } = require('pg');
    const client = new Client(received);
    assert.strictEqual(client.connectionParameters.host, 'db.internal');
    assert.strictEqual(client.connectionParameters.port, 5432);
    assert.strictEqual(client.connectionParameters.user, 'url-user');
    assert.strictEqual(client.connectionParameters.database, 'url-db');
    assert.strictEqual(client.connectionParameters.options, '-c client_min_messages=notice');
    assert.strictEqual(typeof client.connectionParameters.password, 'function');
  });
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

test('guarded restore planning selects the correct maintenance authority', () => {
  const randomBytes = () => Buffer.alloc(12, 0x3a);
  const source = 'postgresql://backup:private@source.internal:5432/source_db?sslmode=require';
  const bare = backup._internal.pgRestoreDatabasePlan(source, 'final_target', {}, randomBytes);
  assert.strictEqual(bare.maintenanceUrl, source);
  assert.strictEqual(bare.targetDatabase, 'final_target');
  assert.strictEqual(bare.stagingDatabase, 'redactwall_restore_' + '3a'.repeat(12));
  assert.strictEqual(new URL(bare.stagingUrl).hostname, 'source.internal');

  const full = backup._internal.pgRestoreDatabasePlan(
    source,
    'postgresql://other:secret@target.internal:6432/final_target?sslmode=verify-full',
    { REDACTWALL_PG_MAINTENANCE_DATABASE: 'maintenance_db' },
    randomBytes,
  );
  const maintenance = new URL(full.maintenanceUrl);
  assert.strictEqual(maintenance.hostname, 'target.internal');
  assert.strictEqual(maintenance.port, '6432');
  assert.strictEqual(maintenance.username, 'other');
  assert.strictEqual(maintenance.pathname, '/maintenance_db');
  assert.strictEqual(maintenance.searchParams.get('sslmode'), 'verify-full');
  assert.throws(() => backup._internal.pgRestoreDatabasePlan(source, 'bad-name', {}, randomBytes), /restore target name/i);
});

test('guarded restore rejects superusers and roles without CREATEDB', () => {
  const driverFor = (row) => ({ prepare: () => ({ get: () => row }) });
  const valid = {
    role_name: 'backup', owner_oid: '12', role_super: false, role_createdb: true,
    session_role_name: 'backup', session_owner_oid: '12', session_super: false,
    session_createdb: true, granted_member_count: 0,
  };
  assert.throws(
    () => backup._internal.pgRestoreRole(driverFor({ ...valid, session_role_name: 'postgres', session_owner_oid: '10', session_super: true })),
    /directly authenticated non-superuser CREATEDB role/,
  );
  assert.throws(
    () => backup._internal.pgRestoreRole(driverFor({ ...valid, role_createdb: false, session_createdb: false })),
    /directly authenticated non-superuser CREATEDB role/,
  );
  assert.throws(
    () => backup._internal.pgRestoreRole(driverFor({ ...valid, granted_member_count: 1 })),
    /no granted members/,
  );
  assert.deepStrictEqual(
    backup._internal.pgRestoreRole(driverFor(valid)),
    { name: 'backup', oid: '12' },
  );
});

test('authenticated PG16 and PG17 database definitions produce explicit template0 clauses', () => {
  const libc = backup._internal.pgDatabaseDefinitionClauses(TEST_PG_DATABASE_DEFINITION, 17).join(' ');
  assert.match(libc, /ENCODING 'UTF8'/);
  assert.match(libc, /LOCALE_PROVIDER libc/);
  assert.match(libc, /LC_COLLATE 'C'/);
  const icu16 = backup._internal.pgDatabaseDefinitionClauses({
    ...TEST_PG_DATABASE_DEFINITION,
    serverMajor: 16,
    localeProvider: 'icu',
    locale: 'en-US',
    icuRules: '&a<b',
  }, 16).join(' ');
  assert.match(icu16, /ICU_LOCALE 'en-US'/);
  assert.match(icu16, /ICU_RULES '&a<b'/);
  const builtin17 = backup._internal.pgDatabaseDefinitionClauses({
    ...TEST_PG_DATABASE_DEFINITION,
    localeProvider: 'builtin',
    locale: 'C.UTF-8',
  }, 17).join(' ');
  assert.match(builtin17, /BUILTIN_LOCALE 'C.UTF-8'/);
  assert.throws(
    () => backup._internal.pgDatabaseDefinitionClauses({ ...TEST_PG_DATABASE_DEFINITION, localeProvider: 'builtin', locale: 'C' }, 16),
    /cannot reproduce/,
  );
});

test('guarded restore cleanup drops only the exact owned database without force', () => {
  const target = 'redactwall_cleanup_exact';
  const identity = { name: target, oid: '90101', ownerOid: '90102' };
  const catalogRows = [
    {
      oid: identity.oid, owner_oid: identity.ownerOid, datname: target,
      datallowconn: true, datconnlimit: -1, datistemplate: false,
    },
    {
      oid: identity.oid, owner_oid: identity.ownerOid, datname: target,
      datallowconn: false, datconnlimit: -1, datistemplate: false,
    },
    {
      oid: identity.oid, owner_oid: identity.ownerOid, datname: target,
      datallowconn: false, datconnlimit: -1, datistemplate: false,
    },
    null,
  ];
  const statements = [];
  let connectedTo = null;
  let closed = false;
  let sessionReads = 0;
  const driver = {
    prepare(sql) {
      if (/FROM pg_catalog\.pg_roles/.test(sql)) {
        return { get: () => ({
          role_name: 'restore_role', owner_oid: identity.ownerOid,
          role_super: false, role_createdb: true,
          session_role_name: 'restore_role', session_owner_oid: identity.ownerOid,
          session_super: false, session_createdb: true, granted_member_count: 0,
        }) };
      }
      if (/FROM pg_catalog\.pg_database/.test(sql)) return { get: () => catalogRows.shift() };
      if (/FROM pg_catalog\.pg_stat_activity/.test(sql)) {
        return { all: () => (++sessionReads === 1 ? [{ pid: 44, backend_start: 'synthetic' }] : []) };
      }
      throw new Error(`unexpected SQL: ${sql}`);
    },
    exec(sql) { statements.push(sql); },
    close() { closed = true; },
  };

  const result = backup.cleanupPgRestoreDatabase({
    connectionString: 'postgresql://restore_role@db.internal/source?sslmode=require',
    databaseIdentity: identity,
  }, {
    createPgDriver(url) { connectedTo = url; return driver; },
  });

  assert.strictEqual(connectedTo, 'postgresql://restore_role@db.internal/source?sslmode=require');
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.alreadyAbsent, false);
  assert.strictEqual(closed, true);
  assert.strictEqual(sessionReads, 2, 'cleanup waits for a just-closed session to drain');
  assert.strictEqual(statements.length, 3);
  assert.match(statements[0], /ALTER DATABASE "redactwall_cleanup_exact" WITH ALLOW_CONNECTIONS false/);
  assert.match(statements[1], /ALTER DATABASE "redactwall_cleanup_exact" WITH CONNECTION LIMIT -1/);
  assert.match(statements[2], /DROP DATABASE "redactwall_cleanup_exact"/);
  assert.ok(statements.every((sql) => !/FORCE/i.test(sql)));
});

test('guarded restore reconciles a lost enable response from the exact catalog identity', () => {
  const identity = {
    datname: 'redactwall_enable_reconcile', oid: '90201', owner_oid: '90202',
    datallowconn: false, datconnlimit: -1, datistemplate: false,
  };
  const transport = new Error('synthetic enable response loss');
  transport.code = '08006';
  const driver = {
    exec() { throw transport; },
    prepare(sql) {
      assert.match(sql, /FROM pg_catalog\.pg_database/);
      return { get: () => ({ ...identity, datallowconn: true }) };
    },
  };
  assert.deepStrictEqual(
    backup._internal.enablePgRestoreTarget(driver, identity.datname, identity),
    { ...identity, datallowconn: true },
  );

  const unreadable = {
    exec() { throw transport; },
    prepare() { return { get: () => { throw new Error('catalog unavailable'); } }; },
  };
  assert.throws(
    () => backup._internal.enablePgRestoreTarget(unreadable, identity.datname, identity),
    (error) => error.pgEnableOutcome === 'ambiguous' && /outcome is uncertain/.test(error.message),
  );
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

test('Postgres dump excludes the per-database audit scope identity', () => {
  const args = backup._internal.pgDumpArgs(
    '00000003-0000001B-1',
    'postgresql://app:private@db.internal/redactwall?sslmode=require',
    path.join(tempRoot, 'scope-excluded.dump'),
  );
  assert.ok(args.includes('--exclude-table=public.redactwall_audit_scope'));
  assert.strictEqual(args.filter((arg) => arg.includes('redactwall_audit_scope')).length, 1);
  assert.ok(!JSON.stringify(args).includes('private'));
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

test('Postgres snapshot verification rejects every query without content-hash audit evidence', async () => {
  const key = Buffer.alloc(32, 0x17);
  const checkpoint = auditIntegrity.createCheckpoint(0, auditIntegrity.ZERO, key, 0);
  const queries = [];
  const client = {
    async query(sql) {
      queries.push(sql);
      if (sql === 'SELECT seq, entry FROM audit ORDER BY seq ASC') return { rows: [] };
      if (sql === 'SELECT id FROM queries ORDER BY id ASC') {
        return { rows: [{ id: 'q_unanchored' }] };
      }
      throw new Error(`unexpected SQL: ${sql}`);
    },
  };

  assert.deepStrictEqual(
    await backup._internal.verifyPgSnapshotIntegrity(client, { key, checkpoint }),
    { ok: false, count: 0, reason: 'evidence-unanchored', queryId: 'q_unanchored' },
  );
  assert.deepStrictEqual(queries, [
    'SELECT seq, entry FROM audit ORDER BY seq ASC',
    'SELECT id FROM queries ORDER BY id ASC',
  ]);
});

test('Postgres restore is one transaction and refuses in-place forced replacement', () => {
  const dumpPath = path.join(tempRoot, 'transactional-restore.dump');
  fs.writeFileSync(dumpPath, Buffer.from('PGDMP\0transactional-test'));
  const fixture = writeAuthenticatedPgFixture(dumpPath, { databaseScope: 'c'.repeat(64) });
  const fixtureVerification = backup.verifyBackup({
    file: dumpPath,
    manifestFile: fixture.manifestPath,
    env: fixture.env,
    security: fixture.security,
  });
  assert.strictEqual(fixtureVerification.ok, true, JSON.stringify(fixtureVerification));
  const calls = [];
  const auditDirectory = restoreAuditDirectory('transactional-restore-runtime');

  const restored = backup._internal.restorePgBackup({
    file: dumpPath,
    to: 'redactwall_restore_target',
    manifestFile: fixture.manifestPath,
    auditDir: auditDirectory,
    env: fixture.env,
    security: fixture.security,
  }, {
    ...EMPTY_PG_TARGET,
    connectionString: 'postgresql://app:private@db.internal/source?sslmode=require',
    runPgTool: (tool, args, connectionString) => calls.push({ tool, args, connectionString }),
    verifyRestoredPgDatabase: () => ({
      auditIntegrity: { ok: true, count: 4 },
      queryCount: 3,
      auditCount: 4,
    }),
  });

  assert.strictEqual(restored.ok, true);
  assert.strictEqual(restored.auditDirectory, auditDirectory);
  assert.strictEqual(restored.auditStateFile, path.join(auditDirectory, '.audit-integrity-state.json'));
  assert.strictEqual(restored.auditCheckpointFile, path.join(auditDirectory, '.audit-integrity-checkpoint.json'));
  assert.strictEqual(restored.auditPendingFile, path.join(auditDirectory, '.audit-integrity-pending.json'));
  assert.strictEqual(fs.existsSync(restored.auditStateFile), true);
  assert.strictEqual(fs.existsSync(restored.auditCheckpointFile), true);
  assert.strictEqual(fs.existsSync(restored.auditPendingFile), false);
  const portableState = JSON.parse(fs.readFileSync(`${dumpPath}.audit-state.json`, 'utf8'));
  const reboundState = JSON.parse(fs.readFileSync(restored.auditStateFile, 'utf8'));
  assert.strictEqual(portableState.databaseScope, 'c'.repeat(64));
  assert.strictEqual(reboundState.databaseScope, UNIT_TARGET_DATABASE_SCOPE);
  assert.notDeepStrictEqual(reboundState, portableState);
  assert.deepStrictEqual(
    JSON.parse(fs.readFileSync(`${dumpPath}.audit-checkpoint.json`, 'utf8')),
    JSON.parse(fs.readFileSync(restored.auditCheckpointFile, 'utf8')),
    'runtime rebind changes only the staged state, never the checkpoint',
  );
  assert.strictEqual(calls.length, 1);
  assert.strictEqual(calls[0].tool, 'pg_restore');
  for (const flag of ['--exit-on-error', '--single-transaction']) {
    assert.ok(calls[0].args.includes(flag), flag);
  }
  assert.strictEqual(calls[0].args.includes('--clean'), false);
  assert.strictEqual(calls[0].args.includes('--if-exists'), false);
  assert.ok(!JSON.stringify(calls[0].args).includes('private'));

  assert.throws(() => backup._internal.restorePgBackup({
    file: dumpPath,
    to: 'redactwall_restore_force_target',
    manifestFile: fixture.manifestPath,
    force: true,
    auditDir: restoreAuditDirectory('transactional-restore-force-runtime'),
    env: fixture.env,
    security: fixture.security,
  }, {
    ...EMPTY_PG_TARGET,
    connectionString: 'postgresql://app:private@db.internal/source?sslmode=require',
    runPgTool: (tool, args, connectionString) => calls.push({ tool, args, connectionString }),
  }), /does not support --force/i);
  assert.strictEqual(calls.length, 1, 'forced replacement is rejected before pg_restore');
});

test('Postgres restore inventory counts every supported database-local object class', () => {
  const rows = backup._internal.PG_RESTORE_INVENTORY_NAMES.map((name) => ({ name, n: '1' }));
  let inventorySql = '';
  let closed = false;
  const driver = {
    prepare(sql) {
      if (/server_version_num/.test(sql)) return { get: () => ({ n: '170010' }) };
      inventorySql = sql;
      return { all: () => rows };
    },
    close() { closed = true; },
  };

  const result = backup._internal.inspectEmptyPgRestoreTarget(
    'postgresql://app@db.internal/fresh_target?sslmode=require',
    { createPgDriver: () => driver },
  );
  assert.strictEqual(result.empty, false);
  assert.strictEqual(result.objectCount, rows.length);
  assert.strictEqual(result.serverVersionNum, 170010);
  assert.strictEqual(closed, true);
  assert.strictEqual(
    backup._internal.pgRestoreInventorySql(160000),
    inventorySql,
    'the explicit inventory contract is reviewed for both supported PG16 and PG17',
  );
  const guardedSql = backup._internal.pgRestoreInventorySql(170000, {
    expectedDatabaseConnectionLimit: 2,
    expectedDatabaseOwnerOnlyAcl: true,
  });
  assert.match(guardedSql, /datacl IS NOT NULL/);
  assert.match(guardedSql, /current_database_acl/);
  assert.match(guardedSql, /privilege_type IN \('CREATE', 'CONNECT', 'TEMPORARY'\)/);
  for (const catalog of [
    'pg_ts_config', 'pg_ts_dict', 'pg_ts_parser', 'pg_ts_template',
    'pg_opclass', 'pg_opfamily', 'pg_statistic_ext', 'pg_subscription',
    'pg_default_acl', 'pg_db_role_setting', 'pg_foreign_data_wrapper',
    'pg_foreign_server', 'pg_user_mappings', 'pg_largeobject_metadata',
    'pg_cast', 'pg_am', 'pg_language', 'pg_seclabel', 'pg_shseclabel',
  ]) assert.match(inventorySql, new RegExp(`\\b${catalog}\\b`), catalog);
});

test('Postgres restore inventory fails closed on an unreviewed server major', () => {
  let closed = false;
  const driver = {
    prepare(sql) {
      assert.match(sql, /server_version_num/);
      return { get: () => ({ n: '180000' }) };
    },
    close() { closed = true; },
  };
  assert.throws(() => backup._internal.inspectEmptyPgRestoreTarget(
    'postgresql://app@db.internal/future_target?sslmode=require',
    { createPgDriver: () => driver },
  ), /inventory is unsupported for this server version/);
  assert.strictEqual(closed, true);
});

test('Postgres restore rejects an existing requested target before CREATE', () => {
  const dumpPath = path.join(tempRoot, 'nonempty-target.dump');
  fs.writeFileSync(dumpPath, Buffer.from('PGDMP\0nonempty-target'));
  const fixture = writeAuthenticatedPgFixture(dumpPath);
  let toolCalls = 0;
  let createCalls = 0;
  assert.throws(() => backup._internal.restorePgBackup({
    file: dumpPath,
    to: 'redactwall_restore_nonempty_target',
    manifestFile: fixture.manifestPath,
    auditDir: restoreAuditDirectory('nonempty-target-runtime'),
    env: fixture.env,
    security: fixture.security,
  }, {
    connectionString: 'postgresql://app:private@db.internal/source?sslmode=require',
    createPgRestoreControl: () => mockPgRestoreControl({
      preflight() { throw new Error('Postgres restore target database already exists: redactwall_restore_nonempty_target'); },
      createStaging() { createCalls += 1; },
    }),
    runPgTool: () => { toolCalls += 1; },
  }), /target database already exists/i);
  assert.strictEqual(createCalls, 0);
  assert.strictEqual(toolCalls, 0);
});

test('Postgres restore rejects DDL injected before guarded inventory', () => {
  const dumpPath = path.join(tempRoot, 'target-became-nonempty.dump');
  fs.writeFileSync(dumpPath, Buffer.from('PGDMP\0target-became-nonempty'));
  const fixture = writeAuthenticatedPgFixture(dumpPath);
  const auditDirectory = restoreAuditDirectory('target-became-nonempty-runtime');
  let inventoryCalls = 0;
  let toolCalls = 0;
  let cleanupCalls = 0;

  assert.throws(() => backup._internal.restorePgBackup({
    file: dumpPath,
    to: 'redactwall_restore_target_became_nonempty',
    manifestFile: fixture.manifestPath,
    auditDir: auditDirectory,
    env: fixture.env,
    security: fixture.security,
  }, {
    connectionString: 'postgresql://app:private@db.internal/source?sslmode=require',
    createPgRestoreControl: () => mockPgRestoreControl({
      cleanupOwnedStaging() { cleanupCalls += 1; },
    }),
    inspectPgRestoreTarget() {
      inventoryCalls += 1;
      return { empty: false, objectCount: 1, inventory: { publications: 1 } };
    },
    runPgTool: () => { toolCalls += 1; },
  }), /staging database is not fresh and empty/i);

  assert.strictEqual(inventoryCalls, 1, 'inventory runs only after the guard is established');
  assert.strictEqual(cleanupCalls, 1, 'the conclusively owned staging database is cleaned');
  assert.strictEqual(toolCalls, 0, 'pg_restore is never launched into a nonempty staging database');
  assert.strictEqual(fs.existsSync(auditDirectory), false);
  assert.deepStrictEqual(restoreStagingEntries(path.dirname(auditDirectory)), []);
});

test('Postgres guarded restore orders create, guard, restore, freeze, rename, publish, and enable', () => {
  const dumpPath = path.join(tempRoot, 'guarded-order.dump');
  fs.writeFileSync(dumpPath, Buffer.from('PGDMP\0guarded-order'));
  const fixture = writeAuthenticatedPgFixture(dumpPath);
  const events = [];
  const guard = { kind: 'guarded-order-driver' };
  const identity = { datname: 'redactwall_guarded_order', oid: '91001', owner_oid: '91002' };
  let toolDatabase = null;

  const result = backup._internal.restorePgBackup({
    file: dumpPath,
    to: 'redactwall_guarded_order',
    manifestFile: fixture.manifestPath,
    auditDir: restoreAuditDirectory('guarded-order-runtime'),
    env: fixture.env,
    security: fixture.security,
  }, {
    connectionString: 'postgresql://app:private@db.internal/source?sslmode=require',
    randomBytes: () => Buffer.alloc(12, 0xab),
    createPgRestoreControl: () => mockPgRestoreControl({
      preflight() { events.push('preflight'); return { targetServerMajor: 17 }; },
      createStaging() { events.push('create'); },
      openGuard() { events.push('open-guard'); return guard; },
      guardDriver() { return guard; },
      assertOnlyGuard() { events.push('assert-only-guard'); },
      freeze() { events.push('freeze'); },
      closeGuardAndAssertNoConnections() { events.push('close-guard'); },
      rename() { events.push('rename'); return identity; },
      enable() { events.push('enable'); return identity; },
      close() { events.push('close-control'); throw new Error('synthetic post-enable close failure'); },
    }),
    beforeGuardInventory() { events.push('before-inventory'); },
    inspectPgRestoreTarget(url, options) {
      events.push('inventory');
      assert.match(url, /redactwall_restore_(?:ab){12}/);
      assert.strictEqual(options.expectedDatabaseConnectionLimit, 2);
      assert.strictEqual(options.expectedDatabaseOwnerOnlyAcl, true);
      return { empty: true, objectCount: 0 };
    },
    runPgTool(_tool, args) {
      events.push('pg-restore');
      toolDatabase = args.find((arg) => arg.startsWith('--dbname=')).slice('--dbname='.length);
      assert.ok(args.includes('--single-transaction'));
    },
    verifyRestoredPgDatabase(_url, _anchor, receivedGuard) {
      events.push('verify');
      assert.strictEqual(receivedGuard, guard);
      return { auditIntegrity: { ok: true, count: 0 }, queryCount: 0, auditCount: 0 };
    },
    targetPgDatabaseScope(_url, receivedGuard) {
      events.push('scope');
      assert.strictEqual(receivedGuard, guard);
      return UNIT_TARGET_DATABASE_SCOPE;
    },
    publishPgRuntimeAuditDirectory() { events.push('publish'); },
    cleanupPgRestoreStaging(paths) {
      events.push('staging-cleanup');
      for (const staging of paths.filter(Boolean)) backup._internal.cleanupPrivateStagingDirectory(staging);
    },
  });

  assert.strictEqual(toolDatabase, 'redactwall_restore_' + 'ab'.repeat(12));
  assert.notStrictEqual(toolDatabase, 'redactwall_guarded_order');
  assert.deepStrictEqual(events, [
    'preflight', 'create', 'open-guard', 'before-inventory', 'inventory', 'assert-only-guard',
    'pg-restore', 'assert-only-guard', 'freeze', 'verify', 'scope',
    'assert-only-guard', 'close-guard', 'rename', 'publish', 'staging-cleanup', 'enable', 'close-control',
  ]);
  assert.deepStrictEqual(result.databaseIdentity, {
    name: identity.datname,
    oid: identity.oid,
    ownerOid: identity.owner_oid,
  });
});

test('Postgres guarded restore retains an uncertain CREATE outcome without DROP', () => {
  const dumpPath = path.join(tempRoot, 'guarded-create-uncertain.dump');
  fs.writeFileSync(dumpPath, Buffer.from('PGDMP\0guarded-create-uncertain'));
  const fixture = writeAuthenticatedPgFixture(dumpPath);
  let cleanupCalls = 0;
  const stagingName = 'redactwall_restore_' + 'cd'.repeat(12);

  assert.throws(() => backup._internal.restorePgBackup({
    file: dumpPath,
    to: 'redactwall_guarded_create_target',
    manifestFile: fixture.manifestPath,
    auditDir: restoreAuditDirectory('guarded-create-uncertain-runtime'),
    env: fixture.env,
    security: fixture.security,
  }, {
    connectionString: 'postgresql://app:private@db.internal/source?sslmode=require',
    randomBytes: () => Buffer.alloc(12, 0xcd),
    createPgRestoreControl: () => mockPgRestoreControl({
      createStaging() { throw new Error('synthetic CREATE response lost'); },
      cleanupOwnedStaging() { cleanupCalls += 1; },
    }),
  }), (error) => (
    /CREATE response lost/.test(error.message)
      && error.message.includes(stagingName)
      && /outcome is uncertain.*remove neither/i.test(error.message)
  ));
  assert.strictEqual(cleanupCalls, 0, 'an uncertain CREATE is never dropped by guessed pathname');
});

test('Postgres final-name collision preserves the foreign target and cleans only exact staging', () => {
  const dumpPath = path.join(tempRoot, 'guarded-rename-collision.dump');
  fs.writeFileSync(dumpPath, Buffer.from('PGDMP\0guarded-rename-collision'));
  const fixture = writeAuthenticatedPgFixture(dumpPath);
  let cleanupCalls = 0;
  let enableCalls = 0;

  assert.throws(() => backup._internal.restorePgBackup({
    file: dumpPath,
    to: 'redactwall_guarded_collision_target',
    manifestFile: fixture.manifestPath,
    auditDir: restoreAuditDirectory('guarded-rename-collision-runtime'),
    env: fixture.env,
    security: fixture.security,
  }, {
    ...EMPTY_PG_TARGET,
    connectionString: 'postgresql://app:private@db.internal/source?sslmode=require',
    createPgRestoreControl: () => mockPgRestoreControl({
      rename() { throw new Error('foreign final target appeared before rename'); },
      reconcileRename() { return 'staging'; },
      cleanupOwnedStaging() { cleanupCalls += 1; },
      enable() { enableCalls += 1; },
    }),
    runPgTool: () => {},
    verifyRestoredPgDatabase: () => ({ auditIntegrity: { ok: true, count: 0 }, queryCount: 0, auditCount: 0 }),
  }), /foreign final target appeared before rename/);

  assert.strictEqual(cleanupCalls, 1, 'only the exact staging identity is cleaned');
  assert.strictEqual(enableCalls, 0);
});

test('Postgres publication failure retains the renamed target frozen and never enables it', () => {
  const dumpPath = path.join(tempRoot, 'guarded-publication-failure.dump');
  fs.writeFileSync(dumpPath, Buffer.from('PGDMP\0guarded-publication-failure'));
  const fixture = writeAuthenticatedPgFixture(dumpPath);
  let enableCalls = 0;
  let cleanupCalls = 0;

  assert.throws(() => backup._internal.restorePgBackup({
    file: dumpPath,
    to: 'redactwall_guarded_frozen_target',
    manifestFile: fixture.manifestPath,
    auditDir: restoreAuditDirectory('guarded-publication-failure-runtime'),
    env: fixture.env,
    security: fixture.security,
  }, {
    ...EMPTY_PG_TARGET,
    connectionString: 'postgresql://app:private@db.internal/source?sslmode=require',
    createPgRestoreControl: () => mockPgRestoreControl({
      enable() { enableCalls += 1; },
      cleanupOwnedStaging() { cleanupCalls += 1; },
    }),
    runPgTool: () => {},
    verifyRestoredPgDatabase: () => ({ auditIntegrity: { ok: true, count: 0 }, queryCount: 0, auditCount: 0 }),
    publishPgRuntimeAuditDirectory() { throw new Error('synthetic audit publication failure'); },
  }), /target redactwall_guarded_frozen_target was retained.*non-connectable/i);

  assert.strictEqual(enableCalls, 0);
  assert.strictEqual(cleanupCalls, 0, 'a renamed target is never dropped after publication starts');
});

test('Postgres staging cleanup is fallible only before the final enable step', () => {
  const dumpPath = path.join(tempRoot, 'guarded-pre-enable-cleanup.dump');
  fs.writeFileSync(dumpPath, Buffer.from('PGDMP\0guarded-pre-enable-cleanup'));
  const fixture = writeAuthenticatedPgFixture(dumpPath);
  let enableCalls = 0;

  assert.throws(() => backup._internal.restorePgBackup({
    file: dumpPath,
    to: 'redactwall_guarded_cleanup_target',
    manifestFile: fixture.manifestPath,
    auditDir: restoreAuditDirectory('guarded-pre-enable-cleanup-runtime'),
    env: fixture.env,
    security: fixture.security,
  }, {
    ...EMPTY_PG_TARGET,
    connectionString: 'postgresql://app:private@db.internal/source?sslmode=require',
    createPgRestoreControl: () => mockPgRestoreControl({
      enable() { enableCalls += 1; },
    }),
    runPgTool: () => {},
    verifyRestoredPgDatabase: () => ({ auditIntegrity: { ok: true, count: 0 }, queryCount: 0, auditCount: 0 }),
    publishPgRuntimeAuditDirectory: () => {},
    cleanupPgRestoreStaging() { throw new Error('synthetic staging cleanup failure'); },
  }), /phase pre-enable-staging-cleanup.*staging cleanup failure.*target redactwall_guarded_cleanup_target was retained.*non-connectable/is);

  assert.strictEqual(enableCalls, 0, 'no fallible operation may run after the final enable');
});

test('Postgres ambiguous enable outcome reports that the retained target may be connectable', () => {
  const dumpPath = path.join(tempRoot, 'guarded-enable-uncertain.dump');
  fs.writeFileSync(dumpPath, Buffer.from('PGDMP\0guarded-enable-uncertain'));
  const fixture = writeAuthenticatedPgFixture(dumpPath);
  const enableError = new Error('synthetic enable response and readback loss');
  enableError.pgEnableOutcome = 'ambiguous';

  assert.throws(() => backup._internal.restorePgBackup({
    file: dumpPath,
    to: 'redactwall_guarded_enable_uncertain',
    manifestFile: fixture.manifestPath,
    auditDir: restoreAuditDirectory('guarded-enable-uncertain-runtime'),
    env: fixture.env,
    security: fixture.security,
  }, {
    ...EMPTY_PG_TARGET,
    connectionString: 'postgresql://app:private@db.internal/source?sslmode=require',
    createPgRestoreControl: () => mockPgRestoreControl({ enable() { throw enableError; } }),
    runPgTool: () => {},
    verifyRestoredPgDatabase: () => ({ auditIntegrity: { ok: true, count: 0 }, queryCount: 0, auditCount: 0 }),
    publishPgRuntimeAuditDirectory: () => {},
    cleanupPgRestoreStaging: () => {},
  }), /enable response and readback loss.*may already be connectable.*disable connections/is);
});

test('Postgres restore refuses an existing target audit directory before pg_restore', () => {
  const dumpPath = path.join(tempRoot, 'existing-runtime-audit.dump');
  fs.writeFileSync(dumpPath, Buffer.from('PGDMP\0existing-runtime-audit'));
  const fixture = writeAuthenticatedPgFixture(dumpPath);
  const auditDirectory = restoreAuditDirectory('existing-runtime-audit-target');
  fs.mkdirSync(path.dirname(auditDirectory));
  fs.mkdirSync(auditDirectory);
  const sentinel = path.join(auditDirectory, 'operator-owned');
  fs.writeFileSync(sentinel, 'preserve');
  let toolCalls = 0;

  assert.throws(() => backup._internal.restorePgBackup({
    file: dumpPath,
    to: 'redactwall_restore_existing_audit_target',
    auditDir: auditDirectory,
    force: true,
    manifestFile: fixture.manifestPath,
    env: fixture.env,
    security: fixture.security,
  }, {
    connectionString: 'postgresql://app:private@db.internal/source?sslmode=require',
    runPgTool: () => { toolCalls += 1; },
  }), /audit directory already exists/i);

  assert.strictEqual(toolCalls, 0);
  assert.strictEqual(fs.readFileSync(sentinel, 'utf8'), 'preserve');
});

test('Postgres restore requires an explicit target audit directory before pg_restore', () => {
  const dumpPath = path.join(tempRoot, 'missing-runtime-audit-dir.dump');
  fs.writeFileSync(dumpPath, Buffer.from('PGDMP\0missing-runtime-audit-dir'));
  const fixture = writeAuthenticatedPgFixture(dumpPath);
  let toolCalls = 0;

  assert.throws(() => backup._internal.restorePgBackup({
    file: dumpPath,
    to: 'redactwall_restore_missing_audit_dir',
    manifestFile: fixture.manifestPath,
    env: fixture.env,
    security: fixture.security,
  }, {
    connectionString: 'postgresql://app:private@db.internal/source?sslmode=require',
    runPgTool: () => { toolCalls += 1; },
  }), /requires an explicit new --audit-dir/);
  assert.strictEqual(toolCalls, 0);
});

test('Postgres restore rolls back a target audit directory when durable publication fails', () => {
  const dumpPath = path.join(tempRoot, 'runtime-audit-publication-failure.dump');
  fs.writeFileSync(dumpPath, Buffer.from('PGDMP\0runtime-audit-publication-failure'));
  const fixture = writeAuthenticatedPgFixture(dumpPath);
  const auditDirectory = restoreAuditDirectory('runtime-audit-publication-failure');
  const originalFsyncDirectory = privatePaths.fsyncDirectory;
  let toolCalls = 0;
  let injected = false;
  privatePaths.fsyncDirectory = (directory, options) => {
    if (!injected && path.resolve(directory) === path.resolve(auditDirectory)) {
      injected = true;
      const error = new Error('synthetic runtime audit directory fsync EIO');
      error.code = 'EIO';
      throw error;
    }
    return originalFsyncDirectory(directory, options);
  };
  try {
    assert.throws(() => backup._internal.restorePgBackup({
      file: dumpPath,
      to: 'redactwall_restore_publication_failure',
      auditDir: auditDirectory,
      manifestFile: fixture.manifestPath,
      env: fixture.env,
      security: fixture.security,
    }, {
      ...EMPTY_PG_TARGET,
      connectionString: 'postgresql://app:private@db.internal/source?sslmode=require',
      runPgTool: () => { toolCalls += 1; },
      verifyRestoredPgDatabase: () => ({
        auditIntegrity: { ok: true, count: 0 },
        queryCount: 0,
        auditCount: 0,
      }),
    }), /synthetic runtime audit directory fsync EIO/);
  } finally {
    privatePaths.fsyncDirectory = originalFsyncDirectory;
  }

  assert.strictEqual(toolCalls, 1);
  assert.strictEqual(injected, true);
  assert.strictEqual(fs.existsSync(auditDirectory), false);
});

test('Postgres restore never deletes a replacement audit directory during failed publication cleanup', () => {
  const dumpPath = path.join(tempRoot, 'runtime-audit-replacement-race.dump');
  fs.writeFileSync(dumpPath, Buffer.from('PGDMP\0runtime-audit-replacement-race'));
  const fixture = writeAuthenticatedPgFixture(dumpPath);
  const auditDirectory = restoreAuditDirectory('runtime-audit-replacement-race');
  const movedPublished = `${auditDirectory}-moved`;
  const replacementSentinel = path.join(auditDirectory, 'replacement-owned');
  const originalFsyncDirectory = privatePaths.fsyncDirectory;
  let swapped = false;
  privatePaths.fsyncDirectory = (directory, options) => {
    if (!swapped && path.resolve(directory) === path.resolve(auditDirectory)) {
      swapped = true;
      fs.renameSync(auditDirectory, movedPublished);
      fs.mkdirSync(auditDirectory);
      fs.writeFileSync(replacementSentinel, 'preserve replacement');
      const error = new Error('synthetic publication race EIO');
      error.code = 'EIO';
      throw error;
    }
    return originalFsyncDirectory(directory, options);
  };
  try {
    assert.throws(() => backup._internal.restorePgBackup({
      file: dumpPath,
      to: 'redactwall_restore_replacement_race',
      auditDir: auditDirectory,
      manifestFile: fixture.manifestPath,
      env: fixture.env,
      security: fixture.security,
    }, {
      ...EMPTY_PG_TARGET,
      connectionString: 'postgresql://app:private@db.internal/source?sslmode=require',
      runPgTool: () => {},
      verifyRestoredPgDatabase: () => ({
        auditIntegrity: { ok: true, count: 0 },
        queryCount: 0,
        auditCount: 0,
      }),
    }), /refusing to remove a changed replacement directory/);
  } finally {
    privatePaths.fsyncDirectory = originalFsyncDirectory;
  }

  assert.strictEqual(swapped, true);
  assert.strictEqual(fs.readFileSync(replacementSentinel, 'utf8'), 'preserve replacement');
  assert.strictEqual(fs.existsSync(path.join(movedPublished, '.audit-integrity-state.json')), true);
  fs.rmSync(auditDirectory, { recursive: true, force: true });
  fs.rmSync(movedPublished, { recursive: true, force: true });
});

test('Postgres failed publication quarantines before checking cleanup identity', () => {
  const dumpPath = path.join(tempRoot, 'runtime-audit-cleanup-check-race.dump');
  fs.writeFileSync(dumpPath, Buffer.from('PGDMP\0runtime-audit-cleanup-check-race'));
  const fixture = writeAuthenticatedPgFixture(dumpPath);
  const auditDirectory = restoreAuditDirectory('runtime-audit-cleanup-check-race');
  const movedPublished = `${auditDirectory}-moved`;
  const replacementSentinel = path.join(auditDirectory, 'replacement-owned');
  const originalFsyncDirectory = privatePaths.fsyncDirectory;
  const originalRenameSync = fs.renameSync;
  let publicationFailed = false;
  let cleanupRaceInjected = false;
  privatePaths.fsyncDirectory = (directory, options) => {
    if (!publicationFailed && path.resolve(directory) === path.resolve(auditDirectory)) {
      publicationFailed = true;
      const error = new Error('synthetic publication cleanup-check race EIO');
      error.code = 'EIO';
      throw error;
    }
    return originalFsyncDirectory(directory, options);
  };
  fs.renameSync = (source, target) => {
    if (publicationFailed && !cleanupRaceInjected && path.resolve(source) === path.resolve(auditDirectory)) {
      cleanupRaceInjected = true;
      originalRenameSync(auditDirectory, movedPublished);
      fs.mkdirSync(auditDirectory);
      fs.writeFileSync(replacementSentinel, 'preserve cleanup-race replacement');
    }
    return originalRenameSync(source, target);
  };
  try {
    assert.throws(() => backup._internal.restorePgBackup({
      file: dumpPath,
      to: 'redactwall_restore_cleanup_check_race',
      auditDir: auditDirectory,
      manifestFile: fixture.manifestPath,
      env: fixture.env,
      security: fixture.security,
    }, {
      ...EMPTY_PG_TARGET,
      connectionString: 'postgresql://app:private@db.internal/source?sslmode=require',
      runPgTool: () => {},
      verifyRestoredPgDatabase: () => ({
        auditIntegrity: { ok: true, count: 0 },
        queryCount: 0,
        auditCount: 0,
      }),
    }), /refusing to remove a changed replacement directory/);
  } finally {
    fs.renameSync = originalRenameSync;
    privatePaths.fsyncDirectory = originalFsyncDirectory;
  }

  assert.strictEqual(publicationFailed, true);
  assert.strictEqual(cleanupRaceInjected, true);
  assert.strictEqual(fs.readFileSync(replacementSentinel, 'utf8'), 'preserve cleanup-race replacement');
  assert.strictEqual(fs.existsSync(path.join(movedPublished, '.audit-integrity-state.json')), true);
  fs.rmSync(auditDirectory, { recursive: true, force: true });
  fs.rmSync(movedPublished, { recursive: true, force: true });
});

test('Postgres restore uses an authenticated private snapshot when the source is swapped at tool launch', () => {
  const restoreDir = path.join(tempRoot, 'restore-snapshot-swap');
  fs.mkdirSync(restoreDir);
  const dumpPath = path.join(restoreDir, 'snapshot.dump');
  const authenticatedBytes = Buffer.from('PGDMP\0authenticated-restore-snapshot');
  const replacementBytes = Buffer.from('PGDMP\0attacker-controlled-replacement');
  fs.writeFileSync(dumpPath, authenticatedBytes);
  const fixture = writeAuthenticatedPgFixture(dumpPath);
  const portableState = fs.readFileSync(`${dumpPath}.audit-state.json`);
  const auditDirectory = restoreAuditDirectory('snapshot-swap');
  let toolArchive;
  let toolBytes;

  const restored = backup._internal.restorePgBackup({
    file: dumpPath,
    to: 'redactwall_restore_snapshot_target',
    auditDir: auditDirectory,
    manifestFile: fixture.manifestPath,
    env: fixture.env,
    security: { ...fixture.security, platform: 'linux' },
  }, {
    ...EMPTY_PG_TARGET,
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
  assert.deepStrictEqual(restoreStagingEntries(restoreDir), []);
  const runtimeState = JSON.parse(fs.readFileSync(restored.auditStateFile, 'utf8'));
  assert.strictEqual(runtimeState.version, 3);
  assert.strictEqual(runtimeState.databaseScope, UNIT_TARGET_DATABASE_SCOPE);
  assert.deepStrictEqual(
    fs.readFileSync(`${dumpPath}.audit-state.json`),
    portableState,
    'portable source state remains unchanged after runtime rebind',
  );
  assert.deepStrictEqual(
    fs.readFileSync(restored.auditCheckpointFile),
    fs.readFileSync(`${dumpPath}.audit-checkpoint.json`),
    'runtime checkpoint remains after restore snapshot cleanup',
  );
  assert.strictEqual(restored.auditDirectory, auditDirectory);
  assert.strictEqual(fs.existsSync(restored.auditPendingFile), false);
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
    auditDir: restoreAuditDirectory('snapshot-cleanup'),
    manifestFile: fixture.manifestPath,
    env: fixture.env,
    security: { ...fixture.security, platform: 'linux' },
  }, {
    ...EMPTY_PG_TARGET,
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
  // A distinctive byte length lets the fault injection target only the staged
  // snapshot copy: lock acquisition also fsyncs small owner files, and firing
  // there would test the lock path instead of the snapshot boundary.
  const dumpBytes = Buffer.concat([Buffer.from('PGDMP\0fsync-failure\0'), Buffer.alloc(493, 0x78)]);
  fs.writeFileSync(dumpPath, dumpBytes);
  const fixture = writeAuthenticatedPgFixture(dumpPath);
  const originalFsync = fs.fsyncSync;
  let failNextFileFsync = true;
  let toolCalls = 0;
  fs.fsyncSync = (fd) => {
    const stat = fs.fstatSync(fd);
    if (failNextFileFsync && stat.isFile() && stat.size === dumpBytes.length) {
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
      auditDir: restoreAuditDirectory('snapshot-fsync'),
      manifestFile: fixture.manifestPath,
      env: fixture.env,
      security: { ...fixture.security, platform: 'linux' },
    }, {
      ...EMPTY_PG_TARGET,
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
  const originalFsyncDirectory = privatePaths.fsyncDirectory;
  let failedDirectoryFsync = false;
  let toolCalls = 0;
  privatePaths.fsyncDirectory = (directory, options) => {
    const resolved = path.resolve(directory);
    if (!failedDirectoryFsync && path.dirname(resolved) === path.resolve(restoreDir)
        && path.basename(resolved).startsWith('.redactwall-backup-')) {
      failedDirectoryFsync = true;
      const error = new Error('synthetic restore staging directory fsync EIO');
      error.code = 'EIO';
      throw error;
    }
    return originalFsyncDirectory(directory, options);
  };
  try {
    assert.throws(() => backup._internal.restorePgBackup({
      file: dumpPath,
      to: 'redactwall_restore_directory_fsync_target',
      auditDir: restoreAuditDirectory('snapshot-directory-fsync'),
      manifestFile: fixture.manifestPath,
      env: fixture.env,
      security: { ...fixture.security, platform: 'linux' },
    }, {
      ...EMPTY_PG_TARGET,
      connectionString: 'postgresql://app:private@db.internal/source?sslmode=require',
      restoreStagingParent: restoreDir,
      runPgTool: () => { toolCalls += 1; },
    }), /synthetic restore staging directory fsync EIO/);
  } finally {
    privatePaths.fsyncDirectory = originalFsyncDirectory;
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
    auditDir: restoreAuditDirectory('missing-manifest-force'),
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
    auditDir: restoreAuditDirectory('embedded-manifest-key'),
    force: true,
    env: fixture.env,
    security: fixture.security,
  }, {
    connectionString: 'postgresql://app:private@db.internal/source?sslmode=require',
    runPgTool: (...args) => calls.push(args),
  }), /does not verify/i);
  assert.strictEqual(calls.length, 0, 'pg_restore must not run when the MAC key is bundled with the backup');
});

test('successful mocked Postgres backup reports committed staging cleanup degradation', async () => {
  const sourceFixturePath = path.join(tempRoot, 'pg-create-cleanup-source.dump');
  fs.writeFileSync(sourceFixturePath, Buffer.from('PGDMP\0source-anchor'));
  const fixture = writeAuthenticatedPgFixture(sourceFixturePath);
  if (process.platform === 'win32') {
    privatePaths.securePrivatePath(`${sourceFixturePath}.audit-state.json`, {
      label: 'mock Postgres source audit state',
    });
    privatePaths.securePrivatePath(`${sourceFixturePath}.audit-checkpoint.json`, {
      label: 'mock Postgres source audit checkpoint',
    });
  }
  const checkpoint = JSON.parse(fs.readFileSync(`${sourceFixturePath}.audit-checkpoint.json`, 'utf8'));
  const hookWarnings = [];
  const outDir = path.join(tempRoot, 'pg-create-cleanup-output');
  privatePaths._resetCommittedCleanupHealthForTest();

  const { result, retainedPath } = await withOneFailedPrivateStagingRemoval(outDir, () => backup.createBackup({
    outDir,
    dbModule: {
      _driverKind: 'postgres',
      _auditAnchorPaths: {
        statePath: `${sourceFixturePath}.audit-state.json`,
        checkpointPath: `${sourceFixturePath}.audit-checkpoint.json`,
      },
      verifyAuditChain: () => ({ ok: true, count: 0 }),
    },
    connectionString: 'postgresql://backup:private@db.internal/source?sslmode=require',
    env: fixture.env,
    security: {
      ...fixture.security.privatePathSecurity,
      privatePathSecurity: fixture.security.privatePathSecurity,
      onCommittedCleanupWarning: (warning) => hookWarnings.push(warning),
    },
    runPgTool(_tool, args) {
      const output = args.find((arg) => arg.startsWith('--file=')).slice('--file='.length);
      fs.writeFileSync(output, Buffer.from('PGDMP\0mocked-backup'));
    },
    withPgSnapshot: async (_connectionString, callback) => callback({
      snapshotId: '000003A1-1',
      sourceIntegrity: { ok: true, count: 0 },
      exactCheckpoint: checkpoint,
      stats: { total: 0 },
      databaseDefinition: TEST_PG_DATABASE_DEFINITION,
    }),
  }));

  assert.doesNotThrow(() => auditAnchor.loadState(
    result.auditStateFile,
    auditAnchor.configuredKey(fixture.env),
    { privatePathSecurity: fixture.security.privatePathSecurity },
  ));
  assert.strictEqual(result.ok, true, JSON.stringify(result, null, 2));
  assert.strictEqual(result.cleanupDegraded, true);
  assert.strictEqual(result.cleanupWarnings.length, 1);
  assert.strictEqual(result.cleanupWarnings[0].component, 'postgres-backup');
  assert.strictEqual(result.cleanupWarnings[0].phase, 'private-staging-cleanup');
  assert.deepStrictEqual(result.cleanupWarnings[0].recovery.paths, [path.resolve(retainedPath)]);
  assert.strictEqual(hookWarnings.length, 1);
  assert.strictEqual(privatePaths.committedCleanupHealth().ok, false);
  assert.strictEqual(backup.verifyBackup({
    file: result.file,
    manifestFile: result.manifestFile,
    env: fixture.env,
    security: fixture.security,
  }).ok, true);

  fs.rmSync(retainedPath, { recursive: true, force: true });
  privatePaths._resetCommittedCleanupHealthForTest();
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

test('Postgres drill never guesses ownership after restore failure and preserves recovery state', async () => {
  const drillDir = path.join(tempRoot, 'pg-drill-restore-failure');
  let created;
  let cleanupCalls = 0;
  await withEnv({
    NODE_ENV: 'test',
    REDACTWALL_DATABASE_URL: 'postgresql://app:private@127.0.0.1:5432/redactwall?sslmode=disable',
  }, async () => {
    await assert.rejects(() => backupDrill.runDrill({
      backupDir: drillDir,
      dbModule: { _driverKind: 'postgres' },
      createBackup: createPgDrillArtifacts('restore-failure', (value) => { created = value; }),
      verifyBackup: () => ({ ok: true, manifestOk: true }),
      restoreBackup: ({ auditDir }) => {
        fs.mkdirSync(auditDir, { recursive: true });
        fs.writeFileSync(path.join(auditDir, 'staged-runtime'), 'sensitive');
        throw new Error('synthetic restore failure');
      },
      cleanupPgRestoreDatabase: () => { cleanupCalls += 1; },
    }), /synthetic restore failure.*private recovery workspace retained at/s);
  });

  assert.strictEqual(cleanupCalls, 0, 'no exact restore identity means no automatic database cleanup');
  for (const artifact of [created.file, created.auditStateFile, created.auditCheckpointFile, created.manifestFile]) {
    assert.strictEqual(fs.existsSync(artifact), true, 'private recovery artifacts are retained');
  }
  assert.strictEqual(fs.readdirSync(drillDir).length, 1);
  fs.rmSync(drillDir, { recursive: true, force: true });
});

test('Postgres drill requires the exact guarded restore identity before cleanup', async () => {
  const drillDir = path.join(tempRoot, 'pg-drill-missing-identity');
  let cleanupCalls = 0;
  await withEnv({
    NODE_ENV: 'test',
    REDACTWALL_DATABASE_URL: 'postgresql://app:private@127.0.0.1:5432/redactwall?sslmode=disable',
  }, async () => {
    await assert.rejects(() => backupDrill.runDrill({
      backupDir: drillDir,
      dbModule: { _driverKind: 'postgres' },
      createBackup: createPgDrillArtifacts('missing-identity'),
      verifyBackup: () => ({ ok: true, manifestOk: true }),
      restoreBackup: ({ auditDir }) => {
        fs.mkdirSync(auditDir);
        return { ok: true, auditIntegrity: { ok: true, count: 0 }, queryCount: 0, auditCount: 0 };
      },
      cleanupPgRestoreDatabase: () => { cleanupCalls += 1; },
    }), /did not return the exact identity.*automatic database cleanup was skipped.*recovery workspace retained/s);
  });

  assert.strictEqual(cleanupCalls, 0);
  assert.strictEqual(fs.readdirSync(drillDir).length, 1);
  fs.rmSync(drillDir, { recursive: true, force: true });
});

test('Postgres drill preserves runtime evidence when exact database cleanup fails', async () => {
  const drillDir = path.join(tempRoot, 'pg-drill-cleanup-failure');
  let created;
  let runtimeRoot;
  let cleanupIdentity = null;
  await withEnv({
    NODE_ENV: 'test',
    REDACTWALL_DATABASE_URL: 'postgresql://app:private@127.0.0.1:5432/redactwall?sslmode=disable',
  }, async () => {
    await assert.rejects(() => backupDrill.runDrill({
      backupDir: drillDir,
      dbModule: { _driverKind: 'postgres' },
      createBackup: createPgDrillArtifacts('cleanup-failure', (value) => { created = value; }),
      verifyBackup: () => ({ ok: true, manifestOk: true }),
      restoreBackup: ({ auditDir, to }) => {
        runtimeRoot = path.dirname(auditDir);
        fs.mkdirSync(auditDir, { recursive: true });
        fs.writeFileSync(path.join(auditDir, 'runtime-state'), 'sensitive');
        return pgDrillRestoreResult(to);
      },
      cleanupPgRestoreDatabase: ({ databaseIdentity }) => {
        cleanupIdentity = databaseIdentity;
        throw new Error('synthetic exact cleanup failure');
      },
    }), /guarded scratch database cleanup.*synthetic exact cleanup failure.*recovery workspace retained/s);
  });

  assert.match(cleanupIdentity.name, /^redactwall_drill_[0-9a-f]{10}$/);
  assert.strictEqual(cleanupIdentity.oid, '70101');
  assert.strictEqual(fs.existsSync(runtimeRoot), true);
  for (const artifact of [created.file, created.auditStateFile, created.auditCheckpointFile, created.manifestFile]) {
    assert.strictEqual(fs.existsSync(artifact), true);
  }
  assert.strictEqual(fs.readdirSync(drillDir).length, 1);
  fs.rmSync(drillDir, { recursive: true, force: true });
});

test('Postgres drill --keep retains the unique private workspace, not the operator directory', async () => {
  const drillDir = path.join(tempRoot, 'pg-drill-keep');
  const cleanupCalls = [];
  let report;
  await withEnv({
    NODE_ENV: 'test',
    REDACTWALL_DATABASE_URL: 'postgresql://app:private@127.0.0.1:5432/redactwall?sslmode=disable',
  }, async () => {
    report = await backupDrill.runDrill({
      backupDir: drillDir,
      keep: true,
      dbModule: { _driverKind: 'postgres' },
      createBackup: createPgDrillArtifacts('keep'),
      verifyBackup: () => ({ ok: true, manifestOk: true }),
      restoreBackup: ({ auditDir, to, manifestFile }) => {
        assert.match(to, /^redactwall_drill_[0-9a-f]{10}$/);
        assert.match(manifestFile, /keep\.dump\.manifest\.json$/);
        fs.mkdirSync(auditDir);
        fs.writeFileSync(path.join(auditDir, 'runtime-state'), 'retained sensitive state');
        return pgDrillRestoreResult(to);
      },
      cleanupPgRestoreDatabase: (options) => { cleanupCalls.push(options); return { ok: true }; },
    });
  });

  assert.strictEqual(report.pass, true);
  assert.strictEqual(path.dirname(report.artifacts.keptAt), drillDir);
  assert.match(path.basename(report.artifacts.keptAt), /^\.redactwall-drill-/);
  assert.strictEqual(cleanupCalls.length, 1);
  assert.deepStrictEqual(cleanupCalls[0].databaseIdentity, {
    name: report.restored.scratchDatabase, oid: '70101', ownerOid: '70102',
  });
  assert.strictEqual(fs.existsSync(report.artifacts.keptAt), true);
  assert.strictEqual(fs.readdirSync(drillDir).length, 1);
  fs.rmSync(drillDir, { recursive: true, force: true });
});

test('Postgres drill preserves a replaced runtime directory instead of recursively deleting it', async () => {
  const drillDir = path.join(tempRoot, 'pg-drill-runtime-replacement');
  let workspace;
  let movedRuntime;
  let replacementSentinel;
  await withEnv({
    NODE_ENV: 'test',
    REDACTWALL_DATABASE_URL: 'postgresql://app:private@127.0.0.1:5432/redactwall?sslmode=disable',
  }, async () => {
    await assert.rejects(() => backupDrill.runDrill({
      backupDir: drillDir,
      dbModule: { _driverKind: 'postgres' },
      createBackup: createPgDrillArtifacts('runtime-replacement'),
      verifyBackup: () => ({ ok: true, manifestOk: true }),
      restoreBackup: ({ auditDir, to }) => {
        fs.mkdirSync(auditDir);
        fs.writeFileSync(path.join(auditDir, 'runtime-state'), 'owned sensitive state');
        return pgDrillRestoreResult(to);
      },
      cleanupPgRestoreDatabase: () => ({ ok: true }),
      beforeWorkspaceCleanup: ({ workDir, runtimeRoot }) => {
        workspace = workDir.dir;
        movedRuntime = `${runtimeRoot}-owned`;
        fs.renameSync(runtimeRoot, movedRuntime);
        fs.mkdirSync(runtimeRoot);
        replacementSentinel = path.join(runtimeRoot, 'replacement-owned');
        fs.writeFileSync(replacementSentinel, 'preserve runtime replacement');
      },
    }), /changed workspace or artifacts retained at/);
  });

  assert.strictEqual(fs.readFileSync(replacementSentinel, 'utf8'), 'preserve runtime replacement');
  assert.strictEqual(fs.readFileSync(path.join(movedRuntime, 'audit', 'runtime-state'), 'utf8'), 'owned sensitive state');
  assert.strictEqual(fs.existsSync(workspace), true);
  fs.rmSync(drillDir, { recursive: true, force: true });
});

test('Postgres drill preserves a replacement installed at the workspace path before cleanup', async () => {
  const drillDir = path.join(tempRoot, 'pg-drill-workspace-replacement');
  let workspace;
  let movedWorkspace;
  let replacementSentinel;
  await withEnv({
    NODE_ENV: 'test',
    REDACTWALL_DATABASE_URL: 'postgresql://app:private@127.0.0.1:5432/redactwall?sslmode=disable',
  }, async () => {
    await assert.rejects(() => backupDrill.runDrill({
      backupDir: drillDir,
      dbModule: { _driverKind: 'postgres' },
      createBackup: createPgDrillArtifacts('workspace-replacement'),
      verifyBackup: () => ({ ok: true, manifestOk: true }),
      restoreBackup: ({ auditDir, to }) => {
        fs.mkdirSync(auditDir);
        return pgDrillRestoreResult(to);
      },
      cleanupPgRestoreDatabase: () => ({ ok: true }),
      beforeWorkspaceCleanup: ({ workDir }) => {
        workspace = workDir.dir;
        movedWorkspace = `${workspace}-owned`;
        fs.renameSync(workspace, movedWorkspace);
        fs.mkdirSync(workspace);
        replacementSentinel = path.join(workspace, 'replacement-owned');
        fs.writeFileSync(replacementSentinel, 'preserve workspace replacement');
      },
    }), /changed workspace or artifacts retained at/);
  });

  assert.strictEqual(fs.readFileSync(replacementSentinel, 'utf8'), 'preserve workspace replacement');
  assert.strictEqual(fs.existsSync(movedWorkspace), true);
  assert.strictEqual(fs.existsSync(workspace), true);
  fs.rmSync(drillDir, { recursive: true, force: true });
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
      auditDir: restoreAuditDirectory('insecure-target'),
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

test('Postgres restore freshness rejects database-local configuration outside ordinary schemas', {
  skip: !ADMIN_URL && 'REDACTWALL_TEST_PG_URL not set',
  timeout: 60000,
}, async (t) => {
  const databaseUrl = await createFreshDatabase();
  const databaseName = new URL(databaseUrl).pathname.slice(1);
  const adminTarget = new URL(ADMIN_URL);
  adminTarget.pathname = `/${databaseName}`;
  const { Client } = require('pg');
  const admin = new Client({ connectionString: adminTarget.toString() });
  await admin.connect();
  try {
    await admin.query(
      'CREATE TEXT SEARCH CONFIGURATION public.rw_restore_probe (COPY = pg_catalog.english)',
    );
    await admin.query(
      'ALTER DEFAULT PRIVILEGES FOR ROLE redactwall_backup GRANT SELECT ON TABLES TO PUBLIC',
    );
    await admin.query('CREATE PUBLICATION rw_restore_publication FOR ALL TABLES');
    await admin.query('GRANT CREATE ON SCHEMA public TO PUBLIC');
    await admin.query(`COMMENT ON DATABASE ${databaseName} IS 'nonempty restore target metadata'`);
    await admin.query(`ALTER DATABASE ${databaseName} SET session_replication_role = replica`);
  } finally {
    await admin.end();
  }
  t.after(async () => {
    const cleanup = new Client({ connectionString: ADMIN_URL });
    await cleanup.connect();
    try { await cleanup.query(`DROP DATABASE IF EXISTS ${databaseName} WITH (FORCE)`); }
    finally { await cleanup.end(); }
  });

  const result = backup._internal.inspectEmptyPgRestoreTarget(databaseUrl);
  assert.strictEqual(result.empty, false);
  assert.ok(result.inventory.text_search_configurations >= 1);
  assert.ok(result.inventory.default_acls >= 1);
  assert.ok(result.inventory.publications >= 1);
  assert.strictEqual(result.inventory.public_schema_metadata, 1);
  assert.strictEqual(result.inventory.current_database_metadata, 1);
  assert.ok(result.inventory.database_role_settings >= 1);
});

test('Postgres restore freshness rejects a target owned by a different durable role', {
  skip: !ADMIN_URL && 'REDACTWALL_TEST_PG_URL not set',
  timeout: 60000,
}, async (t) => {
  const databaseUrl = await createFreshDatabase();
  const databaseName = new URL(databaseUrl).pathname.slice(1);
  const { Client } = require('pg');
  const admin = new Client({ connectionString: ADMIN_URL });
  await admin.connect();
  try {
    await admin.query(`ALTER DATABASE ${databaseName} OWNER TO postgres`);
  } finally {
    await admin.end();
  }
  t.after(async () => {
    const cleanup = new Client({ connectionString: ADMIN_URL });
    await cleanup.connect();
    try { await cleanup.query(`DROP DATABASE IF EXISTS ${databaseName} WITH (FORCE)`); }
    finally { await cleanup.end(); }
  });

  const result = backup._internal.inspectEmptyPgRestoreTarget(databaseUrl);
  assert.strictEqual(result.empty, false);
  assert.strictEqual(result.inventory.current_database_metadata, 1);
  assert.deepStrictEqual(
    Object.entries(result.inventory).filter(([, count]) => count !== 0),
    [['current_database_metadata', 1]],
  );
});

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
  const archiveList = spawnSync('pg_restore', ['--list', created.file], { encoding: 'utf8' });
  assert.strictEqual(archiveList.status, 0, archiveList.stderr);
  assert.ok(!archiveList.stdout.includes('redactwall_audit_scope'), 'portable dump excludes database-local audit scope');

  const verifyRun = runNode([path.join(REPO_ROOT, 'scripts', 'backup-store.js'), 'verify', created.file], env);
  assert.strictEqual(verifyRun.status, 0, verifyRun.stderr);
  const verified = JSON.parse(verifyRun.stdout);
  assert.strictEqual(verified.ok, true);
  assert.strictEqual(verified.driver, 'postgres');
  assert.strictEqual(verified.manifestOk, true);

  const superuserTarget = 'redactwall_superuser_refused_' + crypto.randomBytes(5).toString('hex');
  const superuserAuditDir = path.join(tempRoot, `${superuserTarget}-runtime`, 'audit');
  const superuserRestore = runNode([
    path.join(REPO_ROOT, 'scripts', 'backup-store.js'),
    'restore',
    created.file,
    superuserTarget,
    '--manifest',
    created.manifestFile,
    '--audit-dir',
    superuserAuditDir,
  ], {
    ...env,
    REDACTWALL_DATABASE_URL: ADMIN_URL,
    DATABASE_URL: ADMIN_URL,
  });
  assert.notStrictEqual(superuserRestore.status, 0);
  assert.match(superuserRestore.stderr, /directly authenticated non-superuser CREATEDB role/i);
  const superuserCheck = new (require('pg').Client)({ connectionString: ADMIN_URL });
  await superuserCheck.connect();
  assert.strictEqual(
    (await superuserCheck.query('SELECT 1 FROM pg_database WHERE datname = $1', [superuserTarget])).rowCount,
    0,
  );
  await superuserCheck.end();
  assert.strictEqual(fs.existsSync(superuserAuditDir), false);

  const setRoleTarget = 'redactwall_setrole_refused_' + crypto.randomBytes(5).toString('hex');
  const setRoleAuditDir = path.join(tempRoot, `${setRoleTarget}-runtime`, 'audit');
  const setRoleUrl = new URL(ADMIN_URL);
  setRoleUrl.searchParams.set('options', '-c role=redactwall_backup');
  const setRoleRestore = runNode([
    path.join(REPO_ROOT, 'scripts', 'backup-store.js'),
    'restore', created.file, setRoleTarget,
    '--manifest', created.manifestFile,
    '--audit-dir', setRoleAuditDir,
  ], {
    ...env,
    REDACTWALL_DATABASE_URL: setRoleUrl.toString(),
    DATABASE_URL: setRoleUrl.toString(),
  });
  assert.notStrictEqual(setRoleRestore.status, 0);
  assert.match(setRoleRestore.stderr, /directly authenticated non-superuser CREATEDB role/i);
  const setRoleCheck = new (require('pg').Client)({ connectionString: ADMIN_URL });
  await setRoleCheck.connect();
  assert.strictEqual(
    (await setRoleCheck.query('SELECT 1 FROM pg_database WHERE datname = $1', [setRoleTarget])).rowCount,
    0,
  );
  await setRoleCheck.end();
  assert.strictEqual(fs.existsSync(setRoleAuditDir), false);

  const nonemptyDatabase = 'redactwall_nonempty_' + crypto.randomBytes(5).toString('hex');
  const { Client } = require('pg');
  const nonemptyAdmin = new Client({ connectionString: ADMIN_URL });
  await nonemptyAdmin.connect();
  await nonemptyAdmin.query(`CREATE DATABASE ${nonemptyDatabase} OWNER redactwall_backup`);
  await nonemptyAdmin.end();
  t.after(async () => {
    const cleanup = new Client({ connectionString: ADMIN_URL });
    await cleanup.connect();
    await cleanup.query(`DROP DATABASE IF EXISTS ${nonemptyDatabase} WITH (FORCE)`);
    await cleanup.end();
  });
  const nonemptyUrl = new URL(databaseUrl);
  nonemptyUrl.pathname = `/${nonemptyDatabase}`;
  const nonemptyClient = new Client({ connectionString: nonemptyUrl.toString() });
  await nonemptyClient.connect();
  await nonemptyClient.query('CREATE TABLE target_only_table (value text NOT NULL)');
  await nonemptyClient.query("INSERT INTO target_only_table (value) VALUES ('must survive refused restore')");
  await nonemptyClient.end();
  const refusedAuditDir = path.join(tempRoot, `${nonemptyDatabase}-runtime`, 'audit');
  const refusedRestore = runNode([
    path.join(REPO_ROOT, 'scripts', 'backup-store.js'),
    'restore',
    created.file,
    nonemptyDatabase,
    '--manifest',
    created.manifestFile,
    '--audit-dir',
    refusedAuditDir,
  ], env);
  assert.notStrictEqual(refusedRestore.status, 0);
  assert.match(refusedRestore.stderr, /target database already exists/i);
  assert.strictEqual(fs.existsSync(refusedAuditDir), false);
  const preservedClient = new Client({ connectionString: nonemptyUrl.toString() });
  await preservedClient.connect();
  assert.strictEqual(
    (await preservedClient.query('SELECT value FROM target_only_table')).rows[0].value,
    'must survive refused restore',
  );
  await preservedClient.end();

  const observerRole = 'redactwall_restore_observer';
  const observerPassword = 'redactwall-restore-observer-test-pw';
  const observerAdmin = new Client({ connectionString: ADMIN_URL });
  await observerAdmin.connect();
  await observerAdmin.query(`
    DO $$ BEGIN
      IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${observerRole}') THEN
        CREATE ROLE ${observerRole} LOGIN;
      END IF;
    END $$
  `);
  await observerAdmin.query(
    `ALTER ROLE ${observerRole} LOGIN NOSUPERUSER NOCREATEDB PASSWORD '${observerPassword}'`,
  );
  await observerAdmin.end();

  const injectedTarget = 'redactwall_injected_' + crypto.randomBytes(5).toString('hex');
  const injectedRuntimeRoot = path.join(tempRoot, `${injectedTarget}-runtime`);
  const injectedAuditDir = path.join(injectedRuntimeRoot, 'audit');
  let injectedStaging = null;
  t.after(() => fs.rmSync(injectedRuntimeRoot, { recursive: true, force: true }));
  assert.throws(() => backup._internal.restorePgBackup({
    file: created.file,
    to: injectedTarget,
    manifestFile: created.manifestFile,
    auditDir: injectedAuditDir,
    env,
  }, {
    connectionString: databaseUrl,
    beforeGuardInventory({ databasePlan }) {
      injectedStaging = databasePlan.stagingDatabase;
      const observerAttempt = runNode(['-e', `
        const { Client } = require('pg');
        (async () => {
          const url = new URL(process.env.RW_STAGING_URL);
          url.username = process.env.RW_OBSERVER_ROLE;
          url.password = process.env.RW_OBSERVER_PASSWORD;
          const client = new Client({ connectionString: url.toString() });
          let denied = false;
          try { await client.connect(); }
          catch (error) { if (error.code === '42501') denied = true; else throw error; }
          if (!denied) {
            const largeObject = await client.query('SELECT lo_create(0) AS oid');
            await client.query('SELECT lo_unlink($1)', [largeObject.rows[0].oid]);
            await client.end();
            throw new Error('observer unexpectedly connected to guarded staging');
          }
        })().catch((error) => { console.error(error.code || error.message); process.exit(1); });
      `], {
        ...env,
        RW_STAGING_URL: databasePlan.stagingUrl,
        RW_OBSERVER_ROLE: observerRole,
        RW_OBSERVER_PASSWORD: observerPassword,
      });
      assert.strictEqual(observerAttempt.status, 0, observerAttempt.stderr);

      const ownerInjection = runNode(['-e', `
        const { Client } = require('pg');
        (async () => {
          const client = new Client({ connectionString: process.env.RW_STAGING_URL });
          await client.connect();
          await client.query('CREATE TABLE public.redactwall_guard_injected (value integer)');
          await client.end();
        })().catch((error) => { console.error(error.code || error.message); process.exit(1); });
      `], { ...env, RW_STAGING_URL: databasePlan.stagingUrl });
      assert.strictEqual(ownerInjection.status, 0, ownerInjection.stderr);
    },
  }), /staging database is not fresh and empty/i);
  assert.ok(injectedStaging, 'the guarded staging database was created');
  const injectedCheck = new Client({ connectionString: ADMIN_URL });
  await injectedCheck.connect();
  assert.strictEqual((await injectedCheck.query(
    'SELECT datname FROM pg_database WHERE datname = ANY($1::text[])',
    [[injectedTarget, injectedStaging]],
  )).rowCount, 0, 'conclusively owned pre-rename staging is removed');
  await injectedCheck.end();
  assert.strictEqual(fs.existsSync(injectedAuditDir), false);

  const frozenTarget = 'redactwall_frozen_' + crypto.randomBytes(5).toString('hex');
  const frozenRuntimeRoot = path.join(tempRoot, `${frozenTarget}-runtime`);
  const frozenAuditDir = path.join(frozenRuntimeRoot, 'audit');
  t.after(async () => {
    const cleanup = new Client({ connectionString: ADMIN_URL });
    await cleanup.connect();
    await cleanup.query(`DROP DATABASE IF EXISTS ${frozenTarget} WITH (FORCE)`);
    await cleanup.end();
    fs.rmSync(frozenRuntimeRoot, { recursive: true, force: true });
  });
  assert.throws(() => backup._internal.restorePgBackup({
    file: created.file,
    to: frozenTarget,
    manifestFile: created.manifestFile,
    auditDir: frozenAuditDir,
    env,
  }, {
    connectionString: databaseUrl,
    publishPgRuntimeAuditDirectory() { throw new Error('injected runtime publication failure'); },
  }), /Target .* was retained.*keep it non-connectable/i);
  const frozenCheck = new Client({ connectionString: ADMIN_URL });
  await frozenCheck.connect();
  const frozenRow = (await frozenCheck.query(`
    SELECT oid::text AS oid, datdba::text AS owner_oid, datallowconn, datconnlimit
      FROM pg_database WHERE datname = $1
  `, [frozenTarget])).rows[0];
  assert.ok(frozenRow, 'publication failure retains the renamed target');
  assert.strictEqual(frozenRow.datallowconn, false);
  assert.strictEqual(frozenRow.datconnlimit, -1);
  assert.strictEqual(fs.existsSync(frozenAuditDir), false);
  const cleanedFrozen = backup.cleanupPgRestoreDatabase({
    connectionString: databaseUrl,
    databaseIdentity: { name: frozenTarget, oid: frozenRow.oid, ownerOid: frozenRow.owner_oid },
    env,
  });
  assert.strictEqual(cleanedFrozen.ok, true);
  assert.strictEqual((await frozenCheck.query(
    'SELECT 1 FROM pg_database WHERE datname = $1', [frozenTarget],
  )).rowCount, 0, 'exact-identity cleanup removes the retained frozen target');
  await frozenCheck.end();

  const restoredDatabase = 'redactwall_restore_' + crypto.randomBytes(5).toString('hex');
  const runtimeRoot = path.join(tempRoot, `${restoredDatabase}-runtime`);
  const restoreAuditDir = path.join(runtimeRoot, 'audit');
  t.after(async () => {
    const cleanup = new Client({ connectionString: ADMIN_URL });
    await cleanup.connect();
    await cleanup.query(`DROP DATABASE IF EXISTS ${restoredDatabase} WITH (FORCE)`);
    await cleanup.end();
    fs.rmSync(runtimeRoot, { recursive: true, force: true });
  });

  const restoreRun = runNode([
    path.join(REPO_ROOT, 'scripts', 'backup-store.js'),
    'restore',
    created.file,
    restoredDatabase,
    '--manifest',
    created.manifestFile,
    '--audit-dir',
    restoreAuditDir,
  ], env);
  assert.strictEqual(restoreRun.status, 0, restoreRun.stderr);
  const restored = JSON.parse(restoreRun.stdout);
  assert.strictEqual(restored.ok, true);
  assert.strictEqual(restored.auditDirectory, restoreAuditDir);
  assert.strictEqual(fs.existsSync(restored.auditStateFile), true);
  assert.strictEqual(fs.existsSync(restored.auditCheckpointFile), true);
  assert.strictEqual(fs.existsSync(restored.auditPendingFile), false);
  assertNoSecrets(restoreRun.stdout, databaseUrl);

  const restoredUrl = new URL(databaseUrl);
  restoredUrl.pathname = `/${restoredDatabase}`;
  const bootEnv = {
    ...childEnv(restoredUrl.toString()),
    REDACTWALL_AUDIT_DIR: restoreAuditDir,
  };
  const cleanBoot = runNode(['-e', `
    const db = require('./server/db');
    const result = db.verifyAuditChain();
    console.log(JSON.stringify(result));
    db._db.close();
    if (!result.ok) process.exit(1);
  `], bootEnv);
  assert.strictEqual(cleanBoot.status, 0, cleanBoot.stderr || cleanBoot.stdout);
  assert.strictEqual(JSON.parse(cleanBoot.stdout).ok, true);

  const cloneDatabase = 'redactwall_clone_' + crypto.randomBytes(5).toString('hex');
  const cloneRuntimeRoot = path.join(tempRoot, `${cloneDatabase}-runtime`);
  const cloneAuditDir = path.join(cloneRuntimeRoot, 'audit');
  t.after(async () => {
    const cleanup = new Client({ connectionString: ADMIN_URL });
    await cleanup.connect();
    await cleanup.query(`DROP DATABASE IF EXISTS ${cloneDatabase} WITH (FORCE)`);
    await cleanup.end();
    fs.rmSync(cloneRuntimeRoot, { recursive: true, force: true });
  });

  const cloneRestore = runNode([
    path.join(REPO_ROOT, 'scripts', 'backup-store.js'),
    'restore',
    created.file,
    cloneDatabase,
    '--manifest',
    created.manifestFile,
    '--audit-dir',
    cloneAuditDir,
  ], env);
  assert.strictEqual(cloneRestore.status, 0, cloneRestore.stderr);
  const cloneUrl = new URL(databaseUrl);
  cloneUrl.pathname = `/${cloneDatabase}`;
  const scopeFor = async (url) => {
    const client = new Client({ connectionString: url });
    await client.connect();
    try {
      return (await client.query(
        'SELECT scope_id::text AS scope_id FROM redactwall_audit_scope WHERE singleton = 1',
      )).rows[0].scope_id;
    } finally {
      await client.end();
    }
  };
  const [sourceScope, restoredScope, cloneScope] = await Promise.all([
    scopeFor(databaseUrl),
    scopeFor(restoredUrl.toString()),
    scopeFor(cloneUrl.toString()),
  ]);
  assert.strictEqual(new Set([sourceScope, restoredScope, cloneScope]).size, 3,
    'source and both restored clones receive distinct database-local scopes');

  const cloneBootEnv = {
    ...childEnv(cloneUrl.toString()),
    REDACTWALL_AUDIT_DIR: cloneAuditDir,
  };
  const cloneCleanBoot = runNode(['-e', `
    const db = require('./server/db');
    const result = db.verifyAuditChain();
    console.log(JSON.stringify(result));
    db._db.close();
    if (!result.ok) process.exit(1);
  `], cloneBootEnv);
  assert.strictEqual(cloneCleanBoot.status, 0, cloneCleanBoot.stderr || cloneCleanBoot.stdout);
  assert.strictEqual(JSON.parse(cloneCleanBoot.stdout).ok, true);

  const sharedAnchorBoot = runNode(['-e', "require('./server/db')"], {
    ...cloneBootEnv,
    REDACTWALL_AUDIT_DIR: restoreAuditDir,
  });
  assert.notStrictEqual(sharedAnchorBoot.status, 0, 'a second restored database cannot share the first runtime anchor');
  assert.match(sharedAnchorBoot.stderr, /audit integrity state database scope mismatch/);
  assertNoSecrets(sharedAnchorBoot.stderr, cloneUrl.toString());

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
  assert.strictEqual(path.dirname(report.artifacts.keptAt), drillDir);
  assert.match(path.basename(report.artifacts.keptAt), /^\.redactwall-drill-/);
  assert.ok(fs.readdirSync(report.artifacts.keptAt).some((name) => name.endsWith('.dump')));
  assertNoSecrets(drillRun.stdout, databaseUrl);

  // The scratch database is always dropped, --keep or not.
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
