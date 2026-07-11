'use strict';
/**
 * Full db.js contract against a real Postgres via the sync worker bridge.
 * Runs when REDACTWALL_TEST_PG_URL points at a reachable Postgres superuser-ish
 * connection (a fresh database is created per run); skips cleanly otherwise.
 */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFileSync, fork } = require('node:child_process');
const { openStore } = require('../server/storage');
const { MIGRATIONS } = require('../server/storage/migrations');
const { hash32 } = require('../server/storage/pg-driver');

const ADMIN_URL = process.env.REDACTWALL_TEST_PG_URL || '';
const auditDirs = [];

function freshAuditDir() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-pg-audit-'));
  auditDirs.push(directory);
  return directory;
}

test.after(() => auditDirs.forEach((directory) => fs.rmSync(directory, { recursive: true, force: true })));

test('storage selection accepts explicit SQLite aliases and rejects unknown drivers', () => {
  for (const requested of ['', 'sqlite', 'sqlite3']) {
    const store = openStore({
      env: { REDACTWALL_DB_DRIVER: requested, REDACTWALL_DB_PATH: ':memory:' },
      dataDir: process.cwd(),
    });
    try {
      assert.strictEqual(store.kind, 'sqlite', requested || 'default');
    } finally {
      store.driver.close();
    }
  }

  assert.throws(
    () => openStore({
      env: { REDACTWALL_DB_DRIVER: 'postgress', REDACTWALL_DB_PATH: ':memory:' },
      dataDir: process.cwd(),
    }),
    /unsupported REDACTWALL_DB_DRIVER/i,
  );
});

test('production storage rejects insecure Postgres before creating a driver', () => {
  let attempts = 0;
  const createPgDriver = () => {
    attempts += 1;
    return { close() {} };
  };
  assert.throws(
    () => openStore({
      env: {
        NODE_ENV: 'production',
        REDACTWALL_DB_DRIVER: 'postgres',
        REDACTWALL_DATABASE_URL: 'postgresql://user:secret@db.internal/redactwall?sslmode=disable',
      },
      createPgDriver,
    }),
    (error) => error && error.code === 'REDACTWALL_POSTGRES_TLS_REQUIRED',
  );
  assert.strictEqual(attempts, 0, 'no connection or migration may precede the TLS boundary check');

  const secure = openStore({
    env: {
      NODE_ENV: 'production',
      REDACTWALL_DB_DRIVER: 'postgres',
      REDACTWALL_DATABASE_URL: 'postgresql://user:secret@db.internal/redactwall?sslmode=verify-full',
    },
    createPgDriver,
  });
  assert.strictEqual(secure.kind, 'postgres');
  assert.strictEqual(attempts, 1);
});

test('storage rejects ambiguous Postgres URLs before creating a driver', () => {
  const rejected = [
    'postgresql://user:secret@db.internal/redactwall?sslmode=require#credential',
    'postgresql://user@db.internal/redactwall?sslmode=require&password=first&password=second',
    'postgresql://user@db.internal/redactwall?sslmode=require&hostaddr=203.0.113.8',
    'postgresql://user@db.internal/path-db?sslmode=require&dbname=other-db',
    'postgresql://user@db.internal/redactwall?sslmode=require&passfile=%2Fprivate%2Fpgpass',
  ];
  let attempts = 0;
  for (const connectionString of rejected) {
    assert.throws(
      () => openStore({
        env: {
          NODE_ENV: 'production',
          REDACTWALL_DB_DRIVER: 'postgres',
          REDACTWALL_DATABASE_URL: connectionString,
        },
        createPgDriver: () => { attempts += 1; return { close() {} }; },
      }),
      (error) => error && error.code === 'REDACTWALL_POSTGRES_URL_INVALID',
      connectionString,
    );
  }
  assert.strictEqual(attempts, 0, 'the driver is never created for an ambiguous connection URL');
});

async function createFreshDatabase() {
  const { Client } = require('pg');
  const admin = new Client({ connectionString: ADMIN_URL });
  await admin.connect();
  const name = 'redactwall_t_' + crypto.randomBytes(5).toString('hex');
  const appPassword = crypto.randomBytes(24).toString('hex');
  // Superusers bypass row-level security, so run the battery as the same kind
  // of unprivileged application role a production deployment would use.
  await admin.query(`
    DO $$ BEGIN
      IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'redactwall_app') THEN
        CREATE ROLE redactwall_app LOGIN;
      END IF;
    END $$;
  `);
  await admin.query(`ALTER ROLE redactwall_app PASSWORD '${appPassword}'`);
  await admin.query(`CREATE DATABASE ${name} OWNER redactwall_app`);
  await admin.end();
  const url = new URL(ADMIN_URL);
  url.username = 'redactwall_app';
  url.password = appPassword;
  url.pathname = '/' + name;
  return url.toString();
}

async function startIdentityWorker(databaseUrl, auditDir) {
  const child = fork(path.join(__dirname, 'support', 'pg-identity-worker.js'), [], {
    cwd: path.join(__dirname, '..'),
    env: {
      ...process.env,
      REDACTWALL_DB_DRIVER: 'postgres',
      REDACTWALL_DATABASE_URL: databaseUrl,
      REDACTWALL_AUDIT_DIR: auditDir,
      REDACTWALL_AUDIT_STATE_PATH: '',
      REDACTWALL_AUDIT_CHECKPOINT_PATH: '',
      REDACTWALL_SECRET: 'unit-secret-stable',
      REDACTWALL_DATA_KEY: 'unit-data-key-stable',
      ADMIN_PASSWORD: 'unit-pass',
    },
    stdio: ['ignore', 'ignore', 'pipe', 'ipc'],
  });
  const pending = new Map();
  let nextId = 1;
  let stderr = '';
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  child.on('message', (message) => {
    if (message.ready) {
      const request = pending.get('ready');
      pending.delete('ready');
      request?.resolve();
      return;
    }
    const request = pending.get(message.id);
    if (!request) return;
    pending.delete(message.id);
    if (message.ok) request.resolve(message.value);
    else request.reject(Object.assign(new Error(message.message), { code: message.code }));
  });
  child.on('exit', (code) => {
    const error = new Error(`Postgres identity worker exited ${code}: ${stderr}`);
    for (const request of pending.values()) request.reject(error);
    pending.clear();
  });
  const ready = new Promise((resolve, reject) => pending.set('ready', { resolve, reject }));
  await ready;
  return {
    call(method, payload) {
      const id = nextId++;
      const result = new Promise((resolve, reject) => pending.set(id, { resolve, reject }));
      child.send({ id, method, payload });
      return result;
    },
    async close() {
      if (child.connected) await this.call('close');
    },
  };
}

async function holdIdentityRowLock(databaseUrl, key) {
  const { Client } = require('pg');
  const client = new Client({ connectionString: databaseUrl });
  const lockHash = hash32(String(key));
  await client.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock($1, $2)', [4021991, lockHash]);
  } catch (error) {
    await client.end().catch(() => {});
    throw error;
  }
  return {
    async waitForWaiters(minimum, timeoutMs = 5000) {
      const deadline = Date.now() + timeoutMs;
      do {
        const result = await client.query(
          "SELECT count(*)::int AS count FROM pg_locks WHERE locktype = 'advisory' AND classid = $1::oid AND objid = $2::oid AND granted = false",
          [4021991, lockHash >>> 0],
        );
        const count = Number(result.rows[0] && result.rows[0].count || 0);
        if (count >= minimum) return count;
        await new Promise((resolve) => setTimeout(resolve, 25));
      } while (Date.now() < deadline);
      throw new Error(`expected ${minimum} blocked advisory-lock waiter(s) for ${key}`);
    },
    async release() {
      try {
        await client.query('ROLLBACK');
      } finally {
        await client.end();
      }
    },
  };
}

test('db.js contract holds on Postgres (migrations, RLS, immutability, chain)', { skip: !ADMIN_URL && 'REDACTWALL_TEST_PG_URL not set' }, async () => {
  const databaseUrl = await createFreshDatabase();
  const auditDir = freshAuditDir();
  const output = execFileSync(process.execPath, [path.join(__dirname, 'support', 'pg-battery.js')], {
    cwd: path.join(__dirname, '..'),
    env: {
      ...process.env,
      REDACTWALL_DB_DRIVER: 'postgres',
      REDACTWALL_DATABASE_URL: databaseUrl,
      REDACTWALL_AUDIT_DIR: auditDir,
      REDACTWALL_AUDIT_STATE_PATH: '',
      REDACTWALL_AUDIT_CHECKPOINT_PATH: '',
      REDACTWALL_SECRET: 'unit-secret-stable',
      REDACTWALL_DATA_KEY: 'unit-data-key-stable',
      ADMIN_PASSWORD: 'unit-pass',
    },
    encoding: 'utf8',
    timeout: 60000,
  });
  const results = JSON.parse(output);
  const failed = Object.entries(results).filter(([, r]) => !r.ok);
  assert.deepStrictEqual(failed, [], `battery steps failed: ${JSON.stringify(failed)}`);

  assert.strictEqual(results.driverKind.value, 'postgres');
  assert.deepStrictEqual(results.migrations.value.map((m) => m.version), MIGRATIONS.map((migration) => migration.version));
  assert.strictEqual(results.queryCrud.value.updatedStatus, 'approved');
  assert.strictEqual(results.queryCrud.value.risk, 42);
  assert.deepStrictEqual(results.decisionCas.value, {
    winner: 'updated',
    loser: 'conflict',
    finalStatus: 'approved',
    auditActions: ['APPROVED'],
    chainOk: true,
  });
  assert.strictEqual(results.auditChain.value.ok, true);
  assert.ok(results.auditChain.value.count >= 2);
  assert.deepStrictEqual(results.auditPendingBatch.value, {
    exactEntry: true,
    exactHead: true,
    countAdvanced: true,
    cleared: true,
    chainOk: true,
  });
  assert.deepStrictEqual(results.vendorHeartbeatCas.value, {
    newerApplied: true,
    olderApplied: false,
    status: 'revoked',
    issuedAt: 3000,
    chainOk: true,
  });
  assert.strictEqual(results.auditImmutable.value.blocked, true, 'audit UPDATE must be refused on Postgres');
  assert.deepStrictEqual(results.tenantScoping.value, { alphaOnly: true, betaOnly: true });
  assert.deepStrictEqual(results.rowLevelSecurity.value, {
    betaOnly: true,
    crossTenantInsertBlocked: true,
    allVisible: true,
  }, 'forced row-level security isolates tenants');
  assert.deepStrictEqual(results.transactionsNest.value, { rolledBack: true, chainOk: true });
  assert.deepStrictEqual(results.scimAndLifecycle.value, { inactive: true, revoked: true });
  assert.deepStrictEqual(results.deliveriesAndApps.value, { delivered: true, app: true });
  assert.deepStrictEqual(results.useCases.value, { rows: 2, reviewed: true, ownerKept: true, unknownIsNull: true });
  assert.deepStrictEqual(results.incidents.value, { created: true, orgNormalized: true, reported: true, listed: true, unknownIsNull: true });
  assert.deepStrictEqual(results.statsAndSeats.value, { total: true, seatUsers: true });
  assert.deepStrictEqual(results.seatWindow.value, { windowed: 1, lifetime: 2 });
  assert.deepStrictEqual(results.mfaRecovery.value, { first: true, second: false, used: true });
  assert.deepStrictEqual(results.administration.value, { user: true, invite: true, seat: true, renewal: true });
});

test('independent Postgres replicas share the vendor verdict high-water and status', {
  skip: !ADMIN_URL && 'REDACTWALL_TEST_PG_URL not set',
  timeout: 60000,
}, async () => {
  const databaseUrl = await createFreshDatabase();
  const auditDir = freshAuditDir();
  const [first, second] = await Promise.all([
    startIdentityWorker(databaseUrl, auditDir),
    startIdentityWorker(databaseUrl, auditDir),
  ]);
  const customerId = 'cu-pg-replica-vendor';
  const customerRef = 'license_' + crypto.createHash('sha256').update(customerId).digest('base64url').slice(0, 24);
  const record = (issuedAt, status) => {
    const state = { customerId, issuedAt, contactAt: issuedAt, status };
    return {
      ...state,
      customerRef,
      audits: [{
        action: 'VENDOR_HEARTBEAT_OK', actor: 'vendor',
        detail: JSON.stringify({ customerRef, issuedAt, contactAt: issuedAt, status }),
      }],
    };
  };
  try {
    const [newer, older] = await Promise.all([
      first.call('applyVendorHeartbeat', record(5000, 'revoked')),
      second.call('applyVendorHeartbeat', record(4000, 'active')),
    ]);
    assert.strictEqual(newer.applied, true);
    assert.ok(typeof older.applied === 'boolean');
    assert.deepStrictEqual(await first.call('lastVendorHeartbeat', { customerId, customerRef }), {
      issuedAt: 5000, contactAt: 5000, status: 'revoked',
    });
    assert.deepStrictEqual(await second.call('lastVendorHeartbeat', { customerId, customerRef }), {
      issuedAt: 5000, contactAt: 5000, status: 'revoked',
    });
    const evidence = await first.call('vendorHeartbeatEvidence');
    assert.deepStrictEqual(evidence, older.applied ? [5000, 4000] : [5000],
      'an older heartbeat may commit first, but never after the newer verdict');
    assert.strictEqual((await first.call('verifyAudit')).ok, true);
  } finally {
    await Promise.allSettled([first.close(), second.close()]);
  }
});

test('independent Postgres processes commit one native ingest query, audit, and mapping', {
  skip: !ADMIN_URL && 'REDACTWALL_TEST_PG_URL not set',
  timeout: 60000,
}, async () => {
  const databaseUrl = await createFreshDatabase();
  const auditDir = freshAuditDir();
  const [first, second] = await Promise.all([
    startIdentityWorker(databaseUrl, auditDir),
    startIdentityWorker(databaseUrl, auditDir),
  ]);
  const orgId = 'cu-pg-native-idempotency';
  const user = 'native-race@example.test';
  const idempotency = { scope: 'native_handoff_v1', key: crypto.randomBytes(32).toString('hex') };
  const payload = (label) => ({
    idempotency,
    query: {
      status: 'pending',
      mode: 'block',
      orgId,
      user,
      source: 'endpoint_agent',
      channel: 'file_upload',
      redactedPrompt: `[native race ${label}]`,
      findings: [{ type: 'US_SSN', masked: '***-**-9043' }],
    },
    audit: { action: 'NATIVE_IDEMPOTENCY_RACE', actor: user, detail: 'sanitized native race' },
  });
  try {
    const [left, right] = await Promise.all([
      first.call('createIdempotentIngest', payload('left')),
      second.call('createIdempotentIngest', payload('right')),
    ]);
    assert.strictEqual(left.row.id, right.row.id, 'both replicas return the same committed query');
    assert.deepStrictEqual([left.replayed, right.replayed].sort(), [false, true]);
    assert.deepStrictEqual([left.audits.length, right.audits.length].sort(), [0, 1]);

    const evidence = await first.call('idempotentIngestEvidence', { idempotency, orgId, user });
    assert.deepStrictEqual(evidence.queryIds, [left.row.id]);
    assert.deepStrictEqual(evidence.auditActions, ['NATIVE_IDEMPOTENCY_RACE']);
    assert.strictEqual(evidence.mappings, 1);
    assert.strictEqual(evidence.row.id, left.row.id);

    const deleted = await first.call('deleteIdempotentMapping', { idempotency, orgId });
    assert.strictEqual(deleted.changes, 1);
    const afterDeletion = await second.call('createIdempotentIngest', payload('after-delete'));
    assert.strictEqual(afterDeletion.replayed, true);
    assert.strictEqual(afterDeletion.row.id, left.row.id,
      'an independent replica recovers the original record from indexed authenticated audit evidence');
    assert.deepStrictEqual(afterDeletion.audits, []);
    const recovered = await first.call('idempotentIngestEvidence', { idempotency, orgId, user });
    assert.deepStrictEqual(recovered.queryIds, [left.row.id]);
    assert.deepStrictEqual(recovered.auditActions, ['NATIVE_IDEMPOTENCY_RACE']);
    assert.strictEqual(recovered.mappings, 0,
      'audit recovery does not trust or silently recreate a deleted mutable mapping');
    assert.strictEqual((await second.call('verifyAudit')).ok, true);
  } finally {
    await Promise.allSettled([first.close(), second.close()]);
  }
});

test('independent Postgres processes serialize identity privilege and source writes', {
  skip: !ADMIN_URL && 'REDACTWALL_TEST_PG_URL not set',
  timeout: 60000,
}, async () => {
  const databaseUrl = await createFreshDatabase();
  const auditDir = freshAuditDir();
  const [first, second] = await Promise.all([
    startIdentityWorker(databaseUrl, auditDir),
    startIdentityWorker(databaseUrl, auditDir),
  ]);
  try {
    const created = await first.call('saveAdmin', {
      userName: 'pg-cas-local@example.test',
      displayName: 'Postgres CAS Local',
      role: 'security_admin',
      active: true,
    });
    const stale = await second.call('getAdmin', created.id);
    const demoted = await first.call('saveAdmin', { ...created, role: 'auditor' });
    await assert.rejects(
      second.call('saveAdmin', { ...stale, displayName: 'Stale Display Edit' }),
      (error) => error && error.code === 'IDENTITY_WRITE_CONFLICT',
    );
    const final = await second.call('getAdmin', created.id);
    assert.strictEqual(final.role, 'auditor');
    assert.strictEqual(final.version, demoted.version);

    const userName = 'pg-cross-source@example.test';
    const results = await Promise.allSettled([
      first.call('saveAdmin', { userName, role: 'auditor', active: true }),
      second.call('saveScim', { userName, role: 'auditor', active: true }),
    ]);
    assert.strictEqual(results.filter((result) => result.status === 'fulfilled').length, 1);
    const rejected = results.find((result) => result.status === 'rejected');
    assert.strictEqual(rejected.reason.code, 'IDENTITY_ALREADY_EXISTS');

    const groupUser = await first.call('saveScim', {
      userName: 'pg-stale-group@example.test',
      role: '',
      active: true,
    });
    const group = await first.call('saveGroup', {
      displayName: 'RedactWall Security Admins',
      members: [{ value: groupUser.id }],
    });
    const staleGroup = await second.call('getGroup', group.id);
    const heldGroupLock = await holdIdentityRowLock(databaseUrl, `scim-group:${group.id}`);
    const deleteGroup = first.call('deleteGroup', group.id);
    try {
      const waiters = await heldGroupLock.waitForWaiters(1);
      assert.ok(waiters >= 1, 'group delete blocks on the stable group-id advisory lock');
    } finally {
      await heldGroupLock.release();
    }
    await deleteGroup;
    await assert.rejects(
      second.call('saveGroup', { ...staleGroup, displayName: 'Resurrected Security Admins' }),
      (error) => error && error.code === 'IDENTITY_WRITE_CONFLICT',
    );
    assert.strictEqual(await second.call('getGroup', group.id), null);

    const acceptedTokenHash = crypto.createHash('sha256').update('pg-accepted-token').digest('base64url');
    const acceptedInvite = await first.call('saveInvite', {
      userName: 'pg-accepted-invite@example.test',
      role: 'auditor',
      status: 'pending',
      tokenHash: acceptedTokenHash,
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
    });
    const staleInvite = await second.call('getInvite', acceptedInvite.id);
    const accepted = await first.call('acceptInvite', {
      tokenHash: acceptedTokenHash,
      passwordRecord: { salt: 'pg-salt', hash: 'pg-hash', algorithm: 'scrypt' },
    });
    assert.strictEqual(accepted.invitation.status, 'accepted');
    await assert.rejects(
      second.call('saveInvite', {
        ...staleInvite,
        status: 'revoked',
        expectedVersion: staleInvite.version,
        expectedStatus: 'pending',
        expectedTokenHash: acceptedTokenHash,
      }),
      (error) => error && error.code === 'IDENTITY_WRITE_CONFLICT',
    );
    assert.strictEqual((await second.call('getInvite', acceptedInvite.id)).status, 'accepted');

    const raceTokenHash = crypto.createHash('sha256').update('pg-race-token').digest('base64url');
    const raceInvite = await first.call('saveInvite', {
      userName: 'pg-race-invite@example.test',
      role: 'auditor',
      status: 'pending',
      tokenHash: raceTokenHash,
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
    });
    const staleRaceInvite = await second.call('getInvite', raceInvite.id);
    const heldInviteLock = await holdIdentityRowLock(databaseUrl, `admin-invitation:${raceInvite.id}`);
    const acceptRaceInvite = first.call('acceptInviteWithAudit', {
      tokenHash: raceTokenHash,
      passwordRecord: { salt: 'pg-race-salt', hash: 'pg-race-hash', algorithm: 'scrypt' },
    });
    const revokeRaceInvite = second.call('saveInviteWithAudit', {
      action: 'ADMIN_USER_INVITE_REVOKED',
      record: {
        ...staleRaceInvite,
        status: 'revoked',
        expectedVersion: staleRaceInvite.version,
        expectedStatus: 'pending',
        expectedTokenHash: raceTokenHash,
      },
    });
    try {
      const waiters = await heldInviteLock.waitForWaiters(2);
      assert.ok(waiters >= 2, 'accept and revoke block on the same stable invitation-id advisory lock');
    } finally {
      await heldInviteLock.release();
    }
    const raceResults = await Promise.allSettled([acceptRaceInvite, revokeRaceInvite]);
    const finalRaceInvite = await first.call('getInvite', raceInvite.id);
    const raceUser = await second.call('getAdminByUserName', raceInvite.userName);
    assert.ok(['accepted', 'revoked'].includes(finalRaceInvite.status));
    assert.strictEqual(!!raceUser, finalRaceInvite.status === 'accepted', 'accepted user and invitation state agree');
    const expectedAuditAction = finalRaceInvite.status === 'accepted'
      ? 'ADMIN_USER_INVITE_ACCEPTED'
      : 'ADMIN_USER_INVITE_REVOKED';
    assert.deepStrictEqual(await second.call('listAuditActions'), [expectedAuditAction]);
    assert.strictEqual((await first.call('verifyAudit')).ok, true);
    for (const result of raceResults.filter((entry) => entry.status === 'rejected')) {
      assert.strictEqual(result.reason.code, 'IDENTITY_WRITE_CONFLICT');
    }
  } finally {
    await Promise.allSettled([first.close(), second.close()]);
  }
});
