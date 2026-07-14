'use strict';

/**
 * Live direct-owner Postgres acceptance for the connected heartbeat boundary.
 * The production db singleton runs in short-lived children so restart and
 * fail-closed recovery use the real driver, migrations, audit anchor, and RLS.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { fork } = require('node:child_process');
const { MIGRATIONS } = require('../server/storage/migrations');

const ADMIN_URL = process.env.REDACTWALL_TEST_PG_URL || '';
const CUSTOMER_ID = 'customer_pg_connected_lifecycle';
const DEPLOYMENT_ID = 'dep_abcdefabcdefabcdefabcdefabcdefab';
const WORKER_PATH = path.join(__dirname, 'support', 'connected-heartbeat-postgres-lifecycle-worker.js');
const ROOT_PREFIX = 'redactwall-connected-pg-lifecycle-';
const CONNECTED_TABLES = Object.freeze([
  'connected_entitlement_state',
  'connected_ack_outbox',
  'connected_online_registry_state',
  'connected_ack_health',
  'connected_ack_archive',
  'connected_ack_archive_mutations',
]);

function quotedIdentifier(value) {
  assert.match(value, /^[a-z][a-z0-9_]+$/);
  return `"${value}"`;
}

function fixtureName(prefix) {
  return `${prefix}_${crypto.randomBytes(6).toString('hex')}`;
}

function pgClient(connectionString) {
  const { Client } = require('pg');
  return new Client({
    connectionString,
    connectionTimeoutMillis: 5_000,
    statement_timeout: 60_000,
    query_timeout: 65_000,
    application_name: 'redactwall_connected_lifecycle_test',
  });
}

async function roleIdentity(client, role) {
  const { rows } = await client.query(
    'SELECT oid::text AS oid FROM pg_catalog.pg_roles WHERE rolname = $1', [role],
  );
  return rows[0] || null;
}

async function databaseIdentity(client, database) {
  const { rows } = await client.query(`SELECT d.oid::text AS oid, d.datdba::text AS owner_oid
    FROM pg_catalog.pg_database d WHERE d.datname = $1`, [database]);
  return rows[0] || null;
}

function targetDatabaseUrl(database, credentials = null) {
  const url = new URL(ADMIN_URL);
  url.pathname = `/${database}`;
  if (credentials) {
    url.username = credentials.role;
    url.password = credentials.password;
  }
  return url.toString();
}

async function configureHostileSearchPath(admin, fixture) {
  await admin.query(`ALTER ROLE ${quotedIdentifier(fixture.role)}
    IN DATABASE ${quotedIdentifier(fixture.database)}
    SET search_path TO attacker, pg_temp, public`);
  const targetOwner = pgClient(targetDatabaseUrl(fixture.database, fixture));
  await targetOwner.connect();
  try {
    await targetOwner.query(`CREATE SCHEMA attacker AUTHORIZATION ${quotedIdentifier(fixture.role)}`);
    await targetOwner.query(`CREATE TABLE attacker.schema_migrations (
      version INTEGER PRIMARY KEY, name TEXT NOT NULL, "appliedAt" TEXT NOT NULL
    )`);
    await targetOwner.query(`INSERT INTO attacker.schema_migrations
      (version, name, "appliedAt") VALUES (8, 'forged-v8-bootstrap', $1)`,
    [new Date().toISOString()]);
  } finally {
    await targetOwner.end();
  }
}

async function provisionDatabase() {
  const fixture = {
    role: fixtureName('rw_conn_lifecycle_owner'),
    database: fixtureName('rw_conn_lifecycle_db'),
    password: crypto.randomBytes(24).toString('hex'),
    roleOid: null,
    databaseOid: null,
  };
  const admin = pgClient(ADMIN_URL);
  await admin.connect();
  try {
    await admin.query(`CREATE ROLE ${quotedIdentifier(fixture.role)} LOGIN
      PASSWORD '${fixture.password}' NOSUPERUSER NOBYPASSRLS CREATEDB NOCREATEROLE NOINHERIT`);
    fixture.roleOid = (await roleIdentity(admin, fixture.role)).oid;
    await admin.query(`CREATE DATABASE ${quotedIdentifier(fixture.database)}
      OWNER ${quotedIdentifier(fixture.role)}`);
    const database = await databaseIdentity(admin, fixture.database);
    fixture.databaseOid = database.oid;
    assert.equal(database.owner_oid, fixture.roleOid);
    await configureHostileSearchPath(admin, fixture);
  } catch (error) {
    await cleanupWithAdmin(admin, fixture).catch((cleanupError) => { error.cleanupError = cleanupError; });
    throw error;
  } finally {
    await admin.end();
  }
  fixture.applicationUrl = targetDatabaseUrl(fixture.database, fixture);
  return fixture;
}

async function cleanupDatabaseWithAdmin(admin, fixture) {
  const database = await databaseIdentity(admin, fixture.database);
  if (!database) return;
  assert.equal(database.oid, fixture.databaseOid, 'database cleanup identity changed');
  assert.equal(database.owner_oid, fixture.roleOid, 'database cleanup owner changed');
  await admin.query(`DROP DATABASE ${quotedIdentifier(fixture.database)} WITH (FORCE)`);
}

async function cleanupRoleWithAdmin(admin, fixture) {
  const role = await roleIdentity(admin, fixture.role);
  if (!role) return;
  assert.equal(role.oid, fixture.roleOid, 'role cleanup identity changed');
  const { rows } = await admin.query(
    'SELECT datname FROM pg_catalog.pg_database WHERE datdba = $1::oid', [fixture.roleOid],
  );
  assert.deepEqual(rows, [], 'refusing to drop a role that still owns a database');
  await admin.query(`DROP ROLE ${quotedIdentifier(fixture.role)}`);
}

async function cleanupWithAdmin(admin, fixture) {
  if (fixture.databaseOid) await cleanupDatabaseWithAdmin(admin, fixture);
  if (fixture.roleOid) await cleanupRoleWithAdmin(admin, fixture);
}

async function destroyDatabase(fixture) {
  const admin = pgClient(ADMIN_URL);
  await admin.connect();
  try { await cleanupWithAdmin(admin, fixture); }
  finally { await admin.end(); }
}

function exactPathIdentity(target) {
  const stat = fs.lstatSync(target, { bigint: true });
  assert.equal(stat.isDirectory(), true);
  assert.notEqual(stat.dev, 0n);
  assert.notEqual(stat.ino, 0n);
  return { dev: stat.dev, ino: stat.ino, birthtimeNs: stat.birthtimeNs };
}

function samePathIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino
    && left.birthtimeNs === right.birthtimeNs;
}

function createPrivateRoot() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), ROOT_PREFIX));
  fs.chmodSync(root, 0o700);
  const auditDir = path.join(root, 'audit');
  fs.mkdirSync(auditDir, { mode: 0o700 });
  fs.chmodSync(auditDir, 0o700);
  return { root, auditDir, identity: exactPathIdentity(root) };
}

function removePrivateRoot(record) {
  const resolved = path.resolve(record.root);
  assert.equal(path.dirname(resolved), path.resolve(os.tmpdir()));
  assert.equal(path.basename(resolved).startsWith(ROOT_PREFIX), true);
  assert.equal(samePathIdentity(exactPathIdentity(resolved), record.identity), true);
  const quarantine = `${resolved}.delete-${crypto.randomBytes(6).toString('hex')}`;
  fs.renameSync(resolved, quarantine);
  assert.equal(samePathIdentity(exactPathIdentity(quarantine), record.identity), true);
  fs.rmSync(quarantine, { recursive: true, force: false, maxRetries: 3, retryDelay: 100 });
}

function publicPem(key) {
  return key.export({ type: 'spki', format: 'pem' }).toString();
}

function privateKeyB64(key) {
  const pem = key.export({ type: 'pkcs8', format: 'pem' }).toString();
  return Buffer.from(pem, 'utf8').toString('base64');
}

function entitlementKeyId(key) {
  const der = key.export({ type: 'spki', format: 'der' });
  return `rw-entitlement-${crypto.createHash('sha256').update(der).digest('hex')}`;
}

function workerEnvironment(fixture, privateRoot) {
  const entitlementKeys = crypto.generateKeyPairSync('ed25519');
  const verdictKeys = crypto.generateKeyPairSync('ed25519');
  const offlineKeys = crypto.generateKeyPairSync('ed25519');
  return {
    ...process.env,
    NODE_ENV: 'test',
    REDACTWALL_DB_DRIVER: 'postgres',
    REDACTWALL_DATABASE_URL: fixture.applicationUrl,
    REDACTWALL_AUDIT_DIR: privateRoot.auditDir,
    REDACTWALL_AUDIT_STATE_PATH: '',
    REDACTWALL_AUDIT_CHECKPOINT_PATH: '',
    REDACTWALL_AUDIT_PENDING_PATH: '',
    REDACTWALL_AUDIT_KEY: crypto.randomBytes(32).toString('hex'),
    REDACTWALL_SECRET: crypto.randomBytes(32).toString('hex'),
    REDACTWALL_DATA_KEY: crypto.randomBytes(32).toString('hex'),
    ADMIN_PASSWORD: crypto.randomBytes(24).toString('hex'),
    REDACTWALL_TENANT_ID: CUSTOMER_ID,
    REDACTWALL_CONNECTED_DEPLOYMENT_ID: DEPLOYMENT_ID,
    REDACTWALL_ENTITLEMENT_PUBLIC_KEY: publicPem(entitlementKeys.publicKey),
    REDACTWALL_ENTITLEMENT_KEY_ID: entitlementKeyId(entitlementKeys.publicKey),
    REDACTWALL_LICENSE_VERDICT_PUBLIC_KEY: publicPem(verdictKeys.publicKey),
    REDACTWALL_LICENSE_PUBLIC_KEY: publicPem(offlineKeys.publicKey),
    REDACTWALL_PG_CONNECT_ATTEMPTS: '2',
    REDACTWALL_PG_CONNECT_TIMEOUT_MS: '5000',
    REDACTWALL_PG_STATEMENT_TIMEOUT_MS: '60000',
    RW_TEST_ENTITLEMENT_PRIVATE_KEY_B64: privateKeyB64(entitlementKeys.privateKey),
    RW_TEST_VERDICT_PRIVATE_KEY_B64: privateKeyB64(verdictKeys.privateKey),
  };
}

function sanitizedWorkerError(stderr, env) {
  if (stderr === undefined || stderr === null || stderr === '') return '';
  let value = String(stderr || '');
  const secrets = [
    env.REDACTWALL_DATABASE_URL,
    env.REDACTWALL_AUDIT_KEY,
    env.REDACTWALL_SECRET,
    env.REDACTWALL_DATA_KEY,
    env.ADMIN_PASSWORD,
    env.RW_TEST_ENTITLEMENT_PRIVATE_KEY_B64,
    env.RW_TEST_VERDICT_PRIVATE_KEY_B64,
  ].filter(Boolean);
  for (const secret of secrets) value = value.replaceAll(secret, '[redacted]');
  return value.slice(-2000);
}

function runWorker(mode, env, timeoutMs = 120_000) {
  return new Promise((resolve, reject) => {
    const child = fork(WORKER_PATH, [mode], {
      cwd: path.join(__dirname, '..'), env, stdio: ['ignore', 'ignore', 'pipe', 'ipc'],
    });
    let message = null;
    let stderr = '';
    let timedOut = false;
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('message', (value) => {
      message = value && typeof value === 'object'
        ? { ...value, message: sanitizedWorkerError(value.message, env) } : value;
    });
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill();
    }, timeoutMs);
    child.once('error', (error) => { clearTimeout(timer); reject(error); });
    child.once('exit', (code) => {
      clearTimeout(timer);
      if (timedOut) return reject(new Error(`Postgres lifecycle worker timed out in ${mode}`));
      if (code !== 0 || !message) {
        return reject(new Error(`Postgres lifecycle worker exited ${code}: ${sanitizedWorkerError(stderr, env)}`));
      }
      return resolve(message);
    });
  });
}

async function assertDirectOwner(fixture) {
  const client = pgClient(fixture.applicationUrl);
  await client.connect();
  try {
    const { rows } = await client.query(`SELECT current_user AS current_role,
      session_user AS session_role, pg_get_userbyid(d.datdba) AS database_owner,
      d.oid::text AS database_oid, r.oid::text AS role_oid,
      r.rolsuper, r.rolbypassrls, r.rolcreatedb, r.rolcreaterole,
      current_setting('search_path') AS search_path
      FROM pg_catalog.pg_database d JOIN pg_catalog.pg_roles r ON r.rolname = current_user
      WHERE d.datname = current_database()`);
    assert.deepEqual(rows, [{
      current_role: fixture.role, session_role: fixture.role, database_owner: fixture.role,
      database_oid: fixture.databaseOid, role_oid: fixture.roleOid,
      rolsuper: false, rolbypassrls: false, rolcreatedb: true, rolcreaterole: false,
      search_path: 'attacker, pg_temp, public',
    }]);
  } finally { await client.end(); }
}

async function assertPreexistingAttackerLedger(fixture) {
  const client = pgClient(fixture.applicationUrl);
  await client.connect();
  try {
    const attacker = await client.query(`SELECT version, name
      FROM attacker.schema_migrations ORDER BY version`);
    assert.deepEqual(attacker.rows, [{ version: 8, name: 'forged-v8-bootstrap' }]);
    const authority = await client.query(`SELECT
      pg_catalog.to_regclass('public.schema_migrations')::text AS public_ledger,
      pg_catalog.to_regclass('public.redactwall_audit_scope')::text AS public_audit_scope`);
    assert.deepEqual(authority.rows, [{ public_ledger: null, public_audit_scope: null }]);
  } finally {
    await client.end();
  }
}

async function withOwner(fixture, callback) {
  const client = pgClient(fixture.applicationUrl);
  await client.connect();
  try {
    await client.query("SELECT set_config('redactwall.org_id', $1, false)", [CUSTOMER_ID]);
    return await callback(client);
  } finally { await client.end(); }
}

async function tamperAuthorityState(fixture) {
  return withOwner(fixture, async (client) => {
    const { rows } = await client.query(`SELECT state_json FROM public.connected_entitlement_state
      WHERE customer_id = $1 AND deployment_id = $2`, [CUSTOMER_ID, DEPLOYMENT_ID]);
    assert.equal(rows.length, 1);
    const original = rows[0].state_json;
    const changed = JSON.parse(original);
    assert.equal(changed.entitlement.status, 'revoked');
    changed.entitlement.status = 'active';
    const tampered = JSON.stringify(changed);
    const result = await client.query(`UPDATE public.connected_entitlement_state SET state_json = $1
      WHERE customer_id = $2 AND deployment_id = $3 AND state_json = $4`,
    [tampered, CUSTOMER_ID, DEPLOYMENT_ID, original]);
    assert.equal(result.rowCount, 1);
    return { original, tampered };
  });
}

async function restoreAuthorityState(fixture, snapshot) {
  await withOwner(fixture, async (client) => {
    const restored = await client.query(`UPDATE public.connected_entitlement_state SET state_json = $1
      WHERE customer_id = $2 AND deployment_id = $3 AND state_json = $4`,
    [snapshot.original, CUSTOMER_ID, DEPLOYMENT_ID, snapshot.tampered]);
    assert.equal(restored.rowCount, 1);
    const { rows } = await client.query(`SELECT state_json FROM public.connected_entitlement_state
      WHERE customer_id = $1 AND deployment_id = $2`, [CUSTOMER_ID, DEPLOYMENT_ID]);
    assert.equal(rows[0].state_json, snapshot.original);
  });
}

async function tamperAuditState(fixture) {
  await withOwner(fixture, async (client) => {
    await assert.rejects(
      client.query('UPDATE public.audit SET actor = actor WHERE seq = (SELECT MAX(seq) FROM public.audit)'),
      (error) => error && error.code === 'P0001',
      'the direct owner must first be blocked by the append-only trigger',
    );
    await client.query('DROP TRIGGER audit_append_only_guard ON public.audit');
    const result = await client.query(`UPDATE public.audit
      SET entry = jsonb_set(entry::jsonb, '{actor}', to_jsonb('tampered'::text), true)::text
      WHERE seq = (SELECT MAX(seq) FROM public.audit)`);
    assert.equal(result.rowCount, 1);
  });
}

function assertZeroConnectedCounts(counts) {
  for (const table of CONNECTED_TABLES) assert.equal(counts[table], 0, table);
}

function assertLifecycleEvidence(message) {
  assert.equal(message.ok, true, `${message.code || ''} ${message.message || ''}`.trim());
  const value = message.value;
  assert.equal(value.driverKind, 'postgres');
  assertAtomicAndReplayEvidence(value);
  assertAcknowledgementEvidence(value);
  assertRestrictionAndArchiveEvidence(value);
  assert.equal(value.chain.ok, true);
}

function assertAtomicAndReplayEvidence(value) {
  assert.match(String(value.rollback.code), /invalid_signature/);
  assertZeroConnectedCounts(value.rollback.counts);
  assert.equal(value.rollback.audit, 0);
  assert.equal(value.first.registryGeneration, 41);
  assert.equal(value.first.entitlementVersion, 1);
  assert.equal(value.first.contactAdvanced, true);
  assert.equal(value.replay.contactAdvanced, false);
  assert.equal(value.replay.registryContactAdvanced, false);
  assert.equal(value.replay.entitlementIdempotent, true);
  assert.equal(value.replayMutationFree, true);
  assert.equal(value.replay.registryLastContactAt, value.first.registryLastContactAt);
  assert.equal(value.replay.entitlementLastContactAt, value.first.entitlementLastContactAt);
  assert.equal(value.second.registryGeneration, 41);
  assert.equal(value.second.entitlementVersion, 2);
  assert.equal(value.second.registryContactAdvanced, false);
}

function assertAcknowledgementEvidence(value) {
  assert.deepEqual(value.firstAckRows.map((row) => row.lifecycle_stage), ['delivered', 'applied']);
  assert.deepEqual(value.firstAckRows.map((row) => row.status), ['pending', 'pending']);
  assert.deepEqual(value.secondAckRows.map((row) => row.lifecycle_stage), ['delivered', 'applied']);
  assert.equal(value.marking.premature, null);
  assert.equal(value.marking.prematureMutationFree, true);
  assert.equal(value.marking.deliveredStatus, 'acknowledged');
  assert.deepEqual(value.marking.exposedStages, ['applied']);
  assert.equal(value.marking.appliedStatus, 'acknowledged');
}

function assertRestrictionAndArchiveEvidence(value) {
  assert.equal(value.paused.entitlementStatus, 'paused');
  assert.equal(value.revoked.entitlementStatus, 'revoked');
  assert.equal(value.paused.registryContactAdvanced, false);
  assert.equal(value.revoked.registryContactAdvanced, false);
  assert.equal(value.pausedDisposition.protectedEgress, 'block');
  assert.equal(value.revokedDisposition.protectedEgress, 'block');
  assert.deepEqual(value.pendingVersions, [
    { target_version: 34, count: 2 },
    { target_version: 35, count: 2 },
    { target_version: 36, count: 2 },
  ]);
  assert.equal(value.counts.connected_ack_outbox, 6);
  assert.equal(value.counts.connected_ack_archive, 64);
  assert.equal(value.ledger.pendingCount, 6);
  assert.ok(value.ledger.archivedPrefixCount > 0);
  assert.equal(value.counts.connected_ack_archive,
    value.ledger.archivedCount - value.ledger.archivedPrefixCount);
  assert.equal(value.counts.connected_ack_archive_mutations,
    value.ledger.archiveMutationCount - value.ledger.archiveMutationPrefixCount);
}

function assertRestartEvidence(message, fixture) {
  assert.equal(message.ok, true, `${message.code || ''} ${message.message || ''}`.trim());
  const value = message.value;
  assert.deepEqual(value.identity, {
    current_role: fixture.role, session_role: fixture.role, database_owner: fixture.role,
    rolsuper: false, rolbypassrls: false, rolcreatedb: true, rolcreaterole: false,
    search_path: 'attacker, pg_temp, public',
  });
  assert.equal(value.entitlementVersion, 36);
  assert.equal(value.entitlementStatus, 'revoked');
  assert.equal(value.registryGeneration, 41);
  assert.equal(value.disposition.protectedEgress, 'block');
  assert.deepEqual(value.health, { ok: true });
  assert.equal(value.counts.connected_ack_archive, 64);
  assert.ok(value.ledger.archivedPrefixCount > 0);
  assert.equal(value.chain.ok, true);
  assertMigrationAuthorityEvidence(value.migrations);
  assert.equal(value.postShadowEntitlementVersion, 36);
  assertSearchPathEvidence(value.searchPath);
  assertRlsEvidence(value.rls);
}

function assertMigrationAuthorityEvidence(value) {
  const expectedPublic = MIGRATIONS.map(({ version, name }) => ({ version, name }));
  assert.deepEqual(value.publicBefore, expectedPublic);
  assert.deepEqual(value.publicAfter, expectedPublic);
  assert.deepEqual(value.attackerBefore, [{ version: 8, name: 'forged-v8-bootstrap' }]);
  assert.deepEqual(value.attackerAfter, value.attackerBefore);
  assert.deepEqual(value.tempAfter, [{ version: 999, name: 'temp-shadow' }]);
  assert.deepEqual(value.appliedBefore, { publicVersion8: true, tempOnlyVersion999: false });
  assert.deepEqual(value.appliedAfter, value.appliedBefore);
  assert.deepEqual(value.runResult, []);
}

function assertSearchPathEvidence(value) {
  assert.deepEqual(value.relations, [
    { schema_name: 'public', relname: 'connected_ack_archive' },
    { schema_name: 'public', relname: 'connected_ack_archive_mutations' },
    { schema_name: 'public', relname: 'connected_ack_health' },
    { schema_name: 'public', relname: 'connected_ack_outbox' },
    { schema_name: 'public', relname: 'connected_entitlement_state' },
    { schema_name: 'public', relname: 'connected_online_registry_state' },
    { schema_name: 'public', relname: 'redactwall_audit_scope' },
    { schema_name: 'public', relname: 'schema_migrations' },
  ]);
  assert.deepEqual(value.attackerRelations, [
    { relname: 'schema_migrations', relkind: 'r' },
    { relname: 'schema_migrations_pkey', relkind: 'i' },
  ]);
  assert.deepEqual(value.attackerRoutines, []);
}

function assertRlsEvidence(value) {
  assert.equal(value.crossInsert.ok, false);
  assert.equal(value.crossInsert.code, '42501');
  assertZeroConnectedCounts(value.hiddenCounts);
  assert.equal(value.hiddenUpdate, 0);
  assert.ok(value.ownCounts.connected_entitlement_state > 0);
}

function assertAuthorityTamperProbe(message) {
  assert.equal(message.ok, true, message.message);
  assert.equal(message.value.chain.ok, true);
  assert.equal(message.value.chain.value.ok, true);
  for (const key of ['state', 'disposition']) {
    const result = message.value[key];
    assert.equal(result.ok, false, key);
    assert.match(`${result.code || ''} ${result.message || ''}`, /integrity/i, key);
  }
}

function assertAuditTamperProbe(message) {
  if (!message.ok) {
    assert.match(`${message.code || ''} ${message.message || ''}`, /audit|integrity|checkpoint|chain/i);
    return;
  }
  const chain = message.value.chain;
  assert.equal(chain.ok ? chain.value.ok : false, false);
  assert.equal(message.value.state.ok, false);
  assert.equal(message.value.disposition.ok, false);
}

function assertPrivateAuditState(privateRoot) {
  const expected = [
    '.audit-integrity-state.json',
    '.audit-integrity-checkpoint.json',
  ];
  for (const file of expected) assert.equal(fs.existsSync(path.join(privateRoot.auditDir, file)), true, file);
  assert.equal(fs.existsSync(path.join(privateRoot.auditDir, '.audit-integrity-pending.json')), false);
}

test('live Postgres composite heartbeat preserves two high-waters, ACK lifecycle, and fail-closed authority', {
  skip: !ADMIN_URL && 'REDACTWALL_TEST_PG_URL not set',
  timeout: 360_000,
}, async () => {
  let fixture = null;
  let privateRoot = null;
  let failure = null;
  try {
    fixture = await provisionDatabase();
    privateRoot = createPrivateRoot();
    await assertDirectOwner(fixture);
    await assertPreexistingAttackerLedger(fixture);
    const env = workerEnvironment(fixture, privateRoot);
    const lifecycle = await runWorker('exercise', env, 180_000);
    assertLifecycleEvidence(lifecycle);
    assertPrivateAuditState(privateRoot);
    const restart = await runWorker('restart', env, 120_000);
    assertRestartEvidence(restart, fixture);
    const authoritySnapshot = await tamperAuthorityState(fixture);
    assertAuthorityTamperProbe(await runWorker('probe-integrity', env, 120_000));
    await restoreAuthorityState(fixture, authoritySnapshot);
    await tamperAuditState(fixture);
    assertAuditTamperProbe(await runWorker('probe-integrity', env, 120_000));
  } catch (error) {
    failure = error;
  } finally {
    try { if (fixture) await destroyDatabase(fixture); }
    catch (error) { failure ||= error; if (failure !== error) failure.cleanupError = error; }
    try { if (privateRoot) removePrivateRoot(privateRoot); }
    catch (error) { failure ||= error; if (failure !== error) failure.cleanupPathError = error; }
  }
  if (failure) throw failure;
});
