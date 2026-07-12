'use strict';
/**
 * Regression coverage for the server-data audit fixes, run against the SQLite
 * path (Postgres unavailable in the gate). Isolate the DB before requiring the
 * module — it opens the store at load time.
 */
const test = require('node:test');
const assert = require('node:assert');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('node:child_process');

process.env.REDACTWALL_DB_PATH = path.join(os.tmpdir(), 'ps-sd-test-' + crypto.randomBytes(6).toString('hex') + '.db');
const db = require('../server/db');
const { wireTenantContext } = db._internal;

function createQuery(query) {
  return db.createQueryWithAudit(query, {
    action: 'TEST_QUERY_CREATED', actor: 'db-server-test', detail: 'transactional fixture',
  }).row;
}

test('wireTenantContext pins the RLS tenant GUC only when a valid silo tenant is configured', () => {
  const calls = [];
  const driver = { setTenantContext: (org) => calls.push(org) };

  assert.strictEqual(wireTenantContext(driver, { tenantId: 'cu-acme', tenantIdValid: true }), 'cu-acme');
  assert.deepStrictEqual(calls, ['cu-acme'], 'configured silo tenant is wired onto the driver');

  assert.strictEqual(wireTenantContext(driver, { tenantId: '', tenantIdValid: true }), null);
  assert.strictEqual(wireTenantContext(driver, { tenantId: 'BAD ORG', tenantIdValid: false }), null);
  assert.deepStrictEqual(calls, ['cu-acme'], 'no tenant / invalid tenant must NOT wire a context');
});

test('wireTenantContext is a no-op on a driver without setTenantContext (SQLite)', () => {
  assert.strictEqual(wireTenantContext({}, { tenantId: 'cu-acme', tenantIdValid: true }), null);
});

test('wireTenantContext aborts unscoped SaaS and production Postgres startup', () => {
  const driver = { setTenantContext() {} };
  assert.throws(
    () => wireTenantContext(driver, { saasMode: true, tenantId: '', tenantIdValid: true }, {
      driverKind: 'postgres', env: { NODE_ENV: 'test' },
    }),
    (error) => error.code === 'REDACTWALL_TENANT_CONTEXT_REQUIRED',
  );
  assert.throws(
    () => wireTenantContext(driver, { saasMode: false, tenantId: '', tenantIdValid: true }, {
      driverKind: 'postgres', env: { NODE_ENV: 'production' },
    }),
    (error) => error.code === 'REDACTWALL_TENANT_CONTEXT_REQUIRED',
  );
  assert.throws(
    () => wireTenantContext({}, { saasMode: true, tenantId: 'cu-acme', tenantIdValid: true }, {
      driverKind: 'postgres', env: { NODE_ENV: 'production' },
    }),
    (error) => error.code === 'REDACTWALL_TENANT_CONTEXT_UNAVAILABLE',
  );
  assert.strictEqual(wireTenantContext({}, { saasMode: false, tenantId: '', tenantIdValid: true }, {
    driverKind: 'sqlite', env: { NODE_ENV: 'production' },
  }), null);
});

test('configured Postgres tenant-context failure aborts datastore initialization', () => {
  const child = spawnSync(process.execPath, ['-e', `
    const crypto = require('crypto');
    const storage = require('./server/storage');
    // The stub must satisfy the Postgres audit database-scope and append-lock
    // contract so initialization reaches tenant-context wiring, which is the
    // boundary under test.
    storage.openStore = () => ({
      driver: {
        setTenantContext() { throw new Error('synthetic tenant context failure'); },
        auditDatabaseScope: () => crypto.createHash('sha256').update('synthetic-test-scope').digest('hex'),
        withAuditAppendLock: (callback) => callback(),
        auditAppendLockHeld: () => false,
      },
      kind: 'postgres',
      dbPath: 'postgres',
    });
    storage.migrationApplied = () => false;
    storage.runMigrations = () => {};
    try {
      require('./server/db');
      process.exit(2);
    } catch (error) {
      if (!/synthetic tenant context failure/.test(error.message || '')) process.exit(3);
    }
  `], {
    cwd: path.resolve(__dirname, '..'),
    env: {
      ...process.env,
      REDACTWALL_TENANT_ID: 'cu-acme',
      REDACTWALL_AUDIT_DIR: path.join(os.tmpdir(), 'ps-sd-tenant-failure-' + crypto.randomBytes(6).toString('hex')),
    },
    encoding: 'utf8',
  });
  assert.strictEqual(child.status, 0, child.stderr || child.stdout);
});

test('posture action state persists across heavy unrelated audit traffic', () => {
  const actionId = 'pa_' + crypto.randomBytes(4).toString('hex');
  db.appendAudit({
    action: db._internal.POSTURE_ACTION_AUDIT,
    actor: 'admin@example.test',
    detail: JSON.stringify({ id: actionId, status: 'resolved', note: 'handled' }),
  });
  // Bury the resolution under far more than any bounded listAudit() window.
  for (let i = 0; i < 1200; i++) db.appendAudit({ action: 'INGEST', actor: 'sensor', detail: 'n' + i });

  const states = db.postureActionStates();
  assert.ok(states[actionId], 'resolved action must not be evicted by newer audit traffic');
  assert.strictEqual(states[actionId].status, 'resolved');
});

test('seatStats counts unique billable users via SQL aggregation, excluding blocked + unknown', () => {
  const org = 'cu-seat-' + crypto.randomBytes(3).toString('hex');
  createQuery({ status: 'allowed', orgId: org, user: 'Casey@Example.Test', redactedPrompt: 'ok' });
  createQuery({ status: 'pending', orgId: org, user: 'casey@example.test', redactedPrompt: 'held' });
  createQuery({ status: 'allowed', orgId: org, user: 'dana@example.test', redactedPrompt: 'ok' });
  createQuery({ status: 'seat_limit_blocked', orgId: org, user: 'blocked@example.test', redactedPrompt: 'x' });
  createQuery({ status: 'allowed', orgId: org, user: 'unknown', redactedPrompt: 'ok' });

  const seats = db.seatStats({ orgId: org });
  assert.strictEqual(seats.seatsUsed, 2);
  assert.deepStrictEqual(seats.users.map((u) => u.user), ['casey@example.test', 'dana@example.test']);
  const casey = seats.users.find((u) => u.user === 'casey@example.test');
  assert.strictEqual(casey.events, 2, 'case-folded duplicate users collapse into one seat');
  assert.ok(seats.users.every((u) => u.orgId === org));
});

test('verifyAuditChain still holds after the batched evidence check', () => {
  const q = createQuery({ status: 'pending', user: 'evidence@example.test', findings: [{ type: 'US_SSN' }] });
  db.appendAudit({ action: 'BLOCKED', queryId: q.id, actor: 'sensor', detail: 'ssn' });
  db.updateQuery(q.id, { status: 'approved', decisionNote: 'ok' });
  db.appendAudit({ action: 'APPROVED', queryId: q.id, actor: 'admin', detail: 'ok' });
  assert.strictEqual(db.verifyAuditChain().ok, true);
});
