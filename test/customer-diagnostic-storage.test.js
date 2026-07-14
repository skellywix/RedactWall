'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const Database = require('better-sqlite3');
const { MIGRATIONS } = require('../server/storage/migrations');
const auditIntegrity = require('../server/audit-integrity');
const { createCustomerDiagnosticStorage } = require('../server/customer-diagnostic-storage');
const {
  createCustomerDiagnosticIntegrityAuthority,
} = require('../server/customer-diagnostic-integrity');
const {
  createCustomerDiagnosticOutbox,
} = require('../server/customer-diagnostic-outbox');

const CUSTOMER_A = 'customer_diagnostic_alpha';
const CUSTOMER_B = 'customer_diagnostic_beta';
const DEPLOYMENT_A = 'dep_11111111111111111111111111111111';
const DEPLOYMENT_B = 'dep_22222222222222222222222222222222';
const START = Date.parse('2026-07-13T12:00:00.000Z');
const ZERO = '0'.repeat(64);
const TEST_AUDIT_KEY = Buffer.alloc(32, 0x27);
function diagnostic(customerId, deploymentId, nowMs, overrides = {}) {
  return {
    schemaVersion: 1,
    messageId: crypto.randomUUID(),
    customerId,
    deploymentId,
    kind: 'diagnostic.event.v1',
    correlationId: crypto.randomUUID(),
    component: 'connector',
    code: 'CONNECTOR_TIMEOUT',
    severity: 'warning',
    outcome: 'retrying',
    countBucket: '1',
    sizeBucket: 'none',
    durationBucket: '1-5s',
    retryState: 'scheduled',
    componentVersion: '1.2.3',
    occurredAt: new Date(nowMs).toISOString(),
    ...overrides,
  };
}

function migratedSqlite() {
  const driver = new Database(':memory:');
  driver.pragma('foreign_keys = ON');
  driver.exec(MIGRATIONS.find(({ version }) => version === 1).sqlite);
  driver.exec(MIGRATIONS.find(({ version }) => version === 2).sqlite);
  for (const version of [14, 16]) {
    const migration = MIGRATIONS.find((candidate) => candidate.version === version);
    assert.ok(migration, `migration ${version} is required`);
    driver.exec(migration.sqlite);
  }
  return driver;
}

function mainAuditHarness(driver) {
  let healthy = true;
  let minimumCount = 0;
  const reference = ({ customerId, deploymentId }) => `diagnostic_checkpoint_${crypto
    .createHmac('sha256', TEST_AUDIT_KEY)
    .update(`${customerId}\0${deploymentId}`)
    .digest('hex').slice(0, 48)}`;
  const verify = () => {
    if (!healthy) return { ok: false, reason: 'checkpoint-truncated' };
    const rows = driver.prepare('SELECT seq, entry FROM main.audit ORDER BY seq').all();
    if (rows.length < minimumCount) return { ok: false, reason: 'checkpoint-truncated' };
    let previous = ZERO;
    for (const row of rows) {
      let entry;
      try { entry = JSON.parse(row.entry); } catch { return { ok: false, reason: 'chain' }; }
      if (entry.prevHash !== previous
          || !auditIntegrity.validAuthenticatedEntry(entry, TEST_AUDIT_KEY)) {
        return { ok: false, reason: 'chain' };
      }
      previous = entry.hash;
    }
    return { ok: true, count: rows.length };
  };
  const append = (event) => {
    const last = driver.prepare('SELECT hash FROM main.audit ORDER BY seq DESC LIMIT 1').get();
    const prevHash = last ? last.hash : ZERO;
    const body = {
      id: `a_${crypto.randomUUID()}`,
      ts: new Date(START + minimumCount).toISOString(),
      prevHash,
      action: event.action,
      queryId: '',
      actor: event.actor,
      detail: event.detail,
      diagnosticCheckpointRef: event.diagnosticCheckpointRef,
    };
    const entry = auditIntegrity.authenticatedEntry(prevHash, body, TEST_AUDIT_KEY);
    driver.prepare(`INSERT INTO main.audit
      (id, ts, action, queryId, actor, prevHash, hash, entry)
      VALUES (@id, @ts, @action, NULL, @actor, @prevHash, @hash, @entry)`).run({
      ...body,
      hash: entry.hash,
      entry: JSON.stringify(entry),
    });
    minimumCount += 1;
    return entry;
  };
  return {
    options: {
      checkpointReference: reference,
      verifyMainAudit: verify,
      loadMainAuditCheckpoint({ checkpointRef }) {
        const row = driver.prepare(`SELECT entry FROM main.audit
          WHERE diagnostic_checkpoint_ref = ? ORDER BY seq DESC LIMIT 1`).get(checkpointRef);
        return row ? JSON.parse(row.entry) : null;
      },
      appendMainAudit: append,
      verifyMainAuditEntry: (entry) => auditIntegrity.validAuthenticatedEntry(entry, TEST_AUDIT_KEY),
    },
    setHealthy(value) { healthy = value; },
    setMinimumCount(value) { minimumCount = value; },
  };
}

function fixture(storageOptions = {}) {
  const driver = migratedSqlite();
  const mainAudit = mainAuditHarness(driver);
  const storage = createCustomerDiagnosticStorage({
    driver,
    driverKind: 'sqlite',
    ...mainAudit.options,
    ...storageOptions,
  });
  const authority = createCustomerDiagnosticIntegrityAuthority({
    secret: Buffer.alloc(32, 0x62).toString('base64'), env: {},
  });
  let now = START;
  const queue = (customerId, deploymentId) => createCustomerDiagnosticOutbox({
    storage,
    integrityAuthority: authority,
    customerId,
    deploymentId,
    clock: () => now,
    leaseMs: 5_000,
    maxItems: 2,
    tombstoneRetentionMs: 5_000,
  });
  return {
    driver, storage, authority, mainAudit, queue,
    now: () => now,
    advance: (ms) => { now += ms; },
  };
}

test('adapter pins SQLite state to main and ignores hostile TEMP relation shadows', (t) => {
  const driver = migratedSqlite();
  t.after(() => driver.close());
  driver.exec(`
    CREATE TEMP TABLE customer_diagnostic_outbox AS
      SELECT * FROM main.customer_diagnostic_outbox WHERE 0;
    CREATE TEMP TABLE customer_diagnostic_time_high_water AS
      SELECT * FROM main.customer_diagnostic_time_high_water WHERE 0;
    CREATE TEMP TABLE customer_diagnostic_audit AS
      SELECT * FROM main.customer_diagnostic_audit WHERE 0;
  `);
  const audit = mainAuditHarness(driver);
  const storage = createCustomerDiagnosticStorage({
    driver,
    driverKind: 'sqlite',
    ...audit.options,
  });
  const authority = createCustomerDiagnosticIntegrityAuthority({
    secret: Buffer.alloc(32, 0x52).toString('base64'), env: {},
  });
  const queue = createCustomerDiagnosticOutbox({
    storage,
    integrityAuthority: authority,
    customerId: CUSTOMER_A,
    deploymentId: DEPLOYMENT_A,
    clock: () => START,
  });
  queue.enqueue(diagnostic(CUSTOMER_A, DEPLOYMENT_A, START));
  assert.equal(driver.prepare('SELECT COUNT(*) AS count FROM main.customer_diagnostic_outbox').get().count, 1);
  assert.equal(driver.prepare('SELECT COUNT(*) AS count FROM temp.customer_diagnostic_outbox').get().count, 0);
  assert.equal(driver.prepare('SELECT COUNT(*) AS count FROM main.customer_diagnostic_audit').get().count, 1);
  assert.equal(driver.prepare('SELECT COUNT(*) AS count FROM temp.customer_diagnostic_audit').get().count, 0);
});

test('adapter rejects a caller-spoofed driver kind', (t) => {
  const driver = migratedSqlite();
  t.after(() => driver.close());
  assert.throws(
    () => createCustomerDiagnosticStorage({ driver, driverKind: 'postgres' }),
    (error) => error && error.code === 'CUSTOMER_DIAGNOSTIC_STORAGE_FAILED',
  );
});

test('hostile pg_temp/search_path cannot redirect Postgres diagnostic runtime relations', () => {
  const sql = [];
  const driver = {
    kind: 'postgres',
    prepare(statement) {
      sql.push(statement);
      return {
        get: () => statement.includes("current_setting('server_version_num')")
          ? { version: '160004' }
          : undefined,
        all: () => [],
        run: () => ({ changes: 0 }),
      };
    },
    transaction: (callback) => callback,
  };
  createCustomerDiagnosticStorage({
    driver,
    driverKind: 'postgres',
    appendMainAudit: () => null,
    checkpointReference: () => 'diagnostic_checkpoint_1111111111111111',
    loadMainAuditCheckpoint: () => null,
    verifyMainAudit: () => ({ ok: true }),
    verifyMainAuditEntry: () => true,
  });
  const runtime = sql.filter((statement) => statement.includes('customer_diagnostic_')).join('\n');
  assert.match(runtime, /public\.customer_diagnostic_outbox/);
  assert.match(runtime, /public\.customer_diagnostic_time_high_water/);
  assert.match(runtime, /public\.customer_diagnostic_audit/);
  assert.match(runtime, /public\.customer_diagnostic_checkpoint/);
  assert.doesNotMatch(runtime, /\b(?:FROM|INTO|UPDATE|DELETE FROM)\s+customer_diagnostic_/);
  assert.doesNotMatch(runtime, /\b(?:FROM|INTO|UPDATE|DELETE FROM)\s+pg_temp\./);
});

test('migrations 14 and 16 create indexed diagnostics state and a main-audit checkpoint', (t) => {
  const env = fixture();
  t.after(() => env.driver.close());
  const tables = env.driver.prepare(`SELECT name FROM sqlite_master
    WHERE type = 'table' AND name LIKE 'customer_diagnostic_%' ORDER BY name`).all()
    .map(({ name }) => name);
  assert.deepEqual(tables, [
    'customer_diagnostic_audit',
    'customer_diagnostic_checkpoint',
    'customer_diagnostic_outbox',
    'customer_diagnostic_time_high_water',
  ]);
  const indexes = env.driver.prepare(`SELECT name FROM sqlite_master
    WHERE type = 'index' AND name LIKE 'idx_customer_diagnostic_%' ORDER BY name`).all()
    .map(({ name }) => name);
  assert.deepEqual(indexes, [
    'idx_customer_diagnostic_audit_message',
    'idx_customer_diagnostic_ready',
    'idx_customer_diagnostic_tombstone',
  ]);
  const mainIndexes = env.driver.prepare(`SELECT name FROM sqlite_master
    WHERE type = 'index' AND name = 'idx_audit_diagnostic_checkpoint'`).all();
  assert.deepEqual(mainIndexes, [{ name: 'idx_audit_diagnostic_checkpoint' }]);
});

test('Postgres migration enforces the same scope, append-only audit, and forced RLS boundary', () => {
  const sql = [14, 16].map((version) => {
    const migration = MIGRATIONS.find((candidate) => candidate.version === version);
    assert.ok(migration, `migration ${version} is required`);
    return migration.postgres;
  }).join('\n');
  for (const table of [
    'customer_diagnostic_outbox',
    'customer_diagnostic_time_high_water',
    'customer_diagnostic_audit',
    'customer_diagnostic_checkpoint',
  ]) {
    assert.match(sql, new RegExp(`CREATE TABLE public\\.${table}`));
    assert.match(sql, new RegExp(`ALTER TABLE public\\.${table} FORCE ROW LEVEL SECURITY`));
  }
  assert.match(sql, /customer_id = current_setting\('redactwall\.org_id', true\)/g);
  assert.match(sql, /customer diagnostic audit is append-only/);
  assert.match(sql, /BEFORE UPDATE ON public\.customer_diagnostic_audit/);
  assert.match(sql, /BEFORE DELETE ON public\.customer_diagnostic_audit/);
});

test('main-store adapter survives restart, preserves replay tombstones, and isolates two scopes', (t) => {
  const env = fixture();
  t.after(() => env.driver.close());
  const alpha = env.queue(CUSTOMER_A, DEPLOYMENT_A);
  const beta = env.queue(CUSTOMER_B, DEPLOYMENT_B);
  const alphaEvent = diagnostic(CUSTOMER_A, DEPLOYMENT_A, env.now());
  const betaEvent = diagnostic(CUSTOMER_B, DEPLOYMENT_B, env.now());
  const alphaAccepted = alpha.enqueue(alphaEvent);
  beta.enqueue(betaEvent);
  assert.equal(alpha.pendingCount(), 1);
  assert.equal(beta.pendingCount(), 1);

  const [lease] = alpha.leaseReady({ limit: 1 });
  assert.deepEqual(lease.event, alphaEvent);
  env.advance(1_000);
  assert.equal(alpha.recordDelivery({
    messageId: lease.messageId,
    payloadDigest: lease.payloadDigest,
    leaseId: lease.leaseId,
    accepted: true,
  }).delivered, true);

  const restartedAlpha = env.queue(CUSTOMER_A, DEPLOYMENT_A);
  assert.deepEqual(restartedAlpha.enqueue({ ...alphaEvent }), {
    accepted: false, duplicate: true, digest: alphaAccepted.digest,
  });
  assert.equal(restartedAlpha.pendingCount(), 0);
  assert.equal(beta.pendingCount(), 1);
  const betaRows = env.driver.prepare(`SELECT customer_id, deployment_id, message_id
    FROM customer_diagnostic_outbox WHERE customer_id = ?`).all(CUSTOMER_B);
  assert.deepEqual(betaRows, [{
    customer_id: CUSTOMER_B, deployment_id: DEPLOYMENT_B, message_id: betaEvent.messageId,
  }]);
});

test('CAS and lease loss fail closed without deleting or cross-releasing the event', (t) => {
  const env = fixture();
  t.after(() => env.driver.close());
  const alpha = env.queue(CUSTOMER_A, DEPLOYMENT_A);
  const event = diagnostic(CUSTOMER_A, DEPLOYMENT_A, env.now());
  alpha.enqueue(event);
  const first = alpha.leaseReady({ limit: 1 })[0];
  env.advance(5_000);
  assert.throws(() => alpha.recordDelivery({
    messageId: first.messageId,
    payloadDigest: first.payloadDigest,
    leaseId: first.leaseId,
    accepted: true,
  }), (error) => error && error.code === 'diagnostic_delivery_not_current');
  const second = alpha.leaseReady({ limit: 1 })[0];
  assert.notEqual(second.leaseId, first.leaseId);
  assert.equal(alpha.recordDelivery({
    messageId: second.messageId,
    payloadDigest: second.payloadDigest,
    leaseId: second.leaseId,
    accepted: true,
  }).delivered, true);
});

test('authenticated clock rollback and audit mutation are detected or database-blocked', (t) => {
  const env = fixture();
  t.after(() => env.driver.close());
  const alpha = env.queue(CUSTOMER_A, DEPLOYMENT_A);
  const event = diagnostic(CUSTOMER_A, DEPLOYMENT_A, env.now());
  alpha.enqueue(event);
  assert.throws(
    () => env.driver.prepare('UPDATE customer_diagnostic_audit SET action = ?').run('ALTERED'),
    /append-only/,
  );
  assert.throws(
    () => env.driver.prepare('DELETE FROM customer_diagnostic_audit').run(),
    /append-only/,
  );
  env.driver.prepare(`UPDATE customer_diagnostic_time_high_water
    SET observed_at = ? WHERE customer_id = ? AND deployment_id = ?`)
    .run(new Date(env.now() + 1).toISOString(), CUSTOMER_A, DEPLOYMENT_A);
  assert.throws(
    () => alpha.pendingCount(),
    (error) => error && error.code === 'diagnostic_storage_failed',
  );
});

test('checkpoint rejects local state deletion and local audit guard removal', (t) => {
  const env = fixture();
  t.after(() => env.driver.close());
  const alpha = env.queue(CUSTOMER_A, DEPLOYMENT_A);
  alpha.enqueue(diagnostic(CUSTOMER_A, DEPLOYMENT_A, env.now()));
  env.driver.prepare(`DELETE FROM main.customer_diagnostic_outbox
    WHERE customer_id = ? AND deployment_id = ?`).run(CUSTOMER_A, DEPLOYMENT_A);
  env.driver.exec('DROP TRIGGER main.customer_diagnostic_audit_no_delete');
  env.driver.prepare(`DELETE FROM main.customer_diagnostic_audit
    WHERE customer_id = ? AND deployment_id = ?`).run(CUSTOMER_A, DEPLOYMENT_A);
  assert.throws(
    () => alpha.pendingCount(),
    (error) => error && error.code === 'diagnostic_storage_failed',
  );
});

test('checkpoint rejects a validly authenticated local time rewind', (t) => {
  const env = fixture();
  t.after(() => env.driver.close());
  const alpha = env.queue(CUSTOMER_A, DEPLOYMENT_A);
  alpha.pendingCount();
  const prior = env.driver.prepare(`SELECT observed_at, state_key_id, state_mac
    FROM main.customer_diagnostic_time_high_water
    WHERE customer_id = ? AND deployment_id = ?`).get(CUSTOMER_A, DEPLOYMENT_A);
  env.advance(1_000);
  alpha.pendingCount();
  env.driver.prepare(`UPDATE main.customer_diagnostic_time_high_water
    SET observed_at = ?, state_key_id = ?, state_mac = ?
    WHERE customer_id = ? AND deployment_id = ?`).run(
    prior.observed_at,
    prior.state_key_id,
    prior.state_mac,
    CUSTOMER_A,
    DEPLOYMENT_A,
  );
  assert.throws(
    () => alpha.pendingCount(),
    (error) => error && error.code === 'diagnostic_storage_failed',
  );
});

test('every transaction fails closed when the externally checkpointed main audit is unhealthy', (t) => {
  let healthy = true;
  const env = fixture({
    verifyMainAudit: () => ({ ok: healthy, reason: healthy ? null : 'checkpoint-truncated' }),
  });
  t.after(() => env.driver.close());
  const alpha = env.queue(CUSTOMER_A, DEPLOYMENT_A);
  alpha.pendingCount();
  healthy = false;
  assert.throws(
    () => alpha.pendingCount(),
    (error) => error && error.code === 'diagnostic_storage_failed',
  );
});

test('unhealthy main audit prevents the transaction callback and every diagnostic write', (t) => {
  const driver = migratedSqlite();
  t.after(() => driver.close());
  const mainAudit = mainAuditHarness(driver);
  mainAudit.setHealthy(false);
  const storage = createCustomerDiagnosticStorage({
    driver,
    driverKind: 'sqlite',
    ...mainAudit.options,
  });
  let called = false;
  assert.throws(
    () => storage.transaction(() => { called = true; }),
    (error) => error && error.code === 'CUSTOMER_DIAGNOSTIC_STORAGE_FAILED',
  );
  assert.equal(called, false);
  for (const table of [
    'customer_diagnostic_outbox',
    'customer_diagnostic_time_high_water',
    'customer_diagnostic_audit',
    'customer_diagnostic_checkpoint',
    'audit',
  ]) {
    assert.equal(driver.prepare(`SELECT COUNT(*) AS count FROM main.${table}`).get().count, 0);
  }
});

test('checkpoint append failure rolls back diagnostic and main-audit mutations together', (t) => {
  const driver = migratedSqlite();
  t.after(() => driver.close());
  const mainAudit = mainAuditHarness(driver);
  const storage = createCustomerDiagnosticStorage({
    driver,
    driverKind: 'sqlite',
    ...mainAudit.options,
    appendMainAudit(event) {
      mainAudit.options.appendMainAudit(event);
      throw new Error('injected post-append failure');
    },
  });
  const authority = createCustomerDiagnosticIntegrityAuthority({
    secret: Buffer.alloc(32, 0x32).toString('base64'), env: {},
  });
  const queue = createCustomerDiagnosticOutbox({
    storage,
    integrityAuthority: authority,
    customerId: CUSTOMER_A,
    deploymentId: DEPLOYMENT_A,
    clock: () => START,
  });
  assert.throws(
    () => queue.enqueue(diagnostic(CUSTOMER_A, DEPLOYMENT_A, START)),
    (error) => error && error.code === 'diagnostic_storage_failed',
  );
  for (const table of [
    'customer_diagnostic_outbox',
    'customer_diagnostic_time_high_water',
    'customer_diagnostic_audit',
    'customer_diagnostic_checkpoint',
    'audit',
  ]) {
    assert.equal(driver.prepare(`SELECT COUNT(*) AS count FROM main.${table}`).get().count, 0);
  }
});

test('restart requires exact checkpoint and authenticated main-audit continuity', (t) => {
  const env = fixture();
  t.after(() => env.driver.close());
  const event = diagnostic(CUSTOMER_A, DEPLOYMENT_A, env.now());
  env.queue(CUSTOMER_A, DEPLOYMENT_A).enqueue(event);
  const restartedStorage = createCustomerDiagnosticStorage({
    driver: env.driver,
    driverKind: 'sqlite',
    ...env.mainAudit.options,
  });
  const restarted = createCustomerDiagnosticOutbox({
    storage: restartedStorage,
    integrityAuthority: env.authority,
    customerId: CUSTOMER_A,
    deploymentId: DEPLOYMENT_A,
    clock: env.now,
  });
  assert.equal(restarted.pendingCount(), 1);
  env.driver.prepare(`DELETE FROM main.customer_diagnostic_checkpoint
    WHERE customer_id = ? AND deployment_id = ?`).run(CUSTOMER_A, DEPLOYMENT_A);
  assert.throws(
    () => restarted.pendingCount(),
    (error) => error && error.code === 'diagnostic_storage_failed',
  );
});

test('older authenticated checkpoint replay cannot rewind the per-scope version', (t) => {
  const env = fixture();
  t.after(() => env.driver.close());
  const alpha = env.queue(CUSTOMER_A, DEPLOYMENT_A);
  alpha.pendingCount();
  env.driver.exec(`CREATE TEMP TABLE saved_diagnostic_checkpoint AS
    SELECT * FROM main.customer_diagnostic_checkpoint`);
  const priorVersion = env.driver.prepare(`SELECT checkpoint_version AS version
    FROM main.customer_diagnostic_checkpoint`).get().version;
  alpha.enqueue(diagnostic(CUSTOMER_A, DEPLOYMENT_A, env.now()));
  const currentVersion = env.driver.prepare(`SELECT checkpoint_version AS version
    FROM main.customer_diagnostic_checkpoint`).get().version;
  assert.equal(currentVersion, priorVersion + 1);
  env.driver.exec(`
    DELETE FROM main.customer_diagnostic_checkpoint;
    INSERT INTO main.customer_diagnostic_checkpoint
      SELECT * FROM temp.saved_diagnostic_checkpoint;
  `);
  assert.throws(
    () => alpha.pendingCount(),
    (error) => error && error.code === 'diagnostic_storage_failed',
  );
});

test('main-audit rollback is rejected before diagnostic state can mutate', (t) => {
  const env = fixture();
  t.after(() => env.driver.close());
  const alpha = env.queue(CUSTOMER_A, DEPLOYMENT_A);
  alpha.enqueue(diagnostic(CUSTOMER_A, DEPLOYMENT_A, env.now()));
  const before = env.driver.prepare(`SELECT checkpoint_digest FROM main.customer_diagnostic_checkpoint
    WHERE customer_id = ? AND deployment_id = ?`).get(CUSTOMER_A, DEPLOYMENT_A);
  env.driver.exec(`
    DROP TRIGGER main.audit_append_only_delete;
    DELETE FROM main.audit;
  `);
  assert.throws(
    () => alpha.pendingCount(),
    (error) => error && error.code === 'diagnostic_storage_failed',
  );
  assert.deepEqual(env.driver.prepare(`SELECT checkpoint_digest FROM main.customer_diagnostic_checkpoint
    WHERE customer_id = ? AND deployment_id = ?`).get(CUSTOMER_A, DEPLOYMENT_A), before);
});

test('checkpoint preserves purge and tombstone disposition across restart', (t) => {
  const env = fixture();
  t.after(() => env.driver.close());
  const alpha = env.queue(CUSTOMER_A, DEPLOYMENT_A);
  const queued = diagnostic(CUSTOMER_A, DEPLOYMENT_A, env.now());
  alpha.enqueue(queued);
  const lease = alpha.leaseReady({ limit: 1 })[0];
  env.advance(1_000);
  alpha.recordDelivery({
    messageId: lease.messageId,
    payloadDigest: lease.payloadDigest,
    leaseId: lease.leaseId,
    accepted: true,
  });
  env.advance(5_001);
  assert.equal(alpha.pendingCount(), 0);
  const checkpoint = env.driver.prepare(`SELECT row_count, tombstone_count, purge_count, purge_head
    FROM main.customer_diagnostic_checkpoint
    WHERE customer_id = ? AND deployment_id = ?`).get(CUSTOMER_A, DEPLOYMENT_A);
  assert.equal(checkpoint.row_count, 0);
  assert.equal(checkpoint.tombstone_count, 0);
  assert.equal(checkpoint.purge_count, 1);
  assert.notEqual(checkpoint.purge_head, ZERO);
  env.driver.exec(`
    DROP TRIGGER main.customer_diagnostic_audit_no_delete;
    DELETE FROM main.customer_diagnostic_audit
      WHERE action = 'DIAGNOSTIC_TOMBSTONE_PURGED';
    CREATE TRIGGER main.customer_diagnostic_audit_no_delete
      BEFORE DELETE ON customer_diagnostic_audit
      BEGIN
        SELECT RAISE(ABORT, 'customer diagnostic audit is append-only');
      END;
  `);
  assert.throws(
    () => alpha.pendingCount(),
    (error) => error && error.code === 'diagnostic_storage_failed',
  );
});

test('checkpoint rejects replay of an older valid row snapshot', (t) => {
  const env = fixture();
  t.after(() => env.driver.close());
  const alpha = env.queue(CUSTOMER_A, DEPLOYMENT_A);
  alpha.enqueue(diagnostic(CUSTOMER_A, DEPLOYMENT_A, env.now()));
  env.driver.exec(`CREATE TEMP TABLE saved_diagnostic_row AS
    SELECT * FROM main.customer_diagnostic_outbox`);
  alpha.leaseReady({ limit: 1 });
  env.driver.exec(`
    DELETE FROM main.customer_diagnostic_outbox;
    INSERT INTO main.customer_diagnostic_outbox
      SELECT * FROM temp.saved_diagnostic_row;
  `);
  assert.throws(
    () => alpha.pendingCount(),
    (error) => error && error.code === 'diagnostic_storage_failed',
  );
});

test('main audit receives only the opaque checkpoint reference and digest envelope', (t) => {
  const env = fixture();
  t.after(() => env.driver.close());
  env.queue(CUSTOMER_A, DEPLOYMENT_A).pendingCount();
  const checkpoint = env.driver.prepare(`SELECT checkpoint_ref, checkpoint_version, checkpoint_digest,
      main_audit_id, main_audit_hash
    FROM main.customer_diagnostic_checkpoint
    WHERE customer_id = ? AND deployment_id = ?`).get(CUSTOMER_A, DEPLOYMENT_A);
  const row = env.driver.prepare('SELECT id, hash, entry FROM main.audit WHERE id = ?')
    .get(checkpoint.main_audit_id);
  const entry = JSON.parse(row.entry);
  assert.equal(entry.diagnosticCheckpointRef, checkpoint.checkpoint_ref);
  assert.equal(entry.hash, checkpoint.main_audit_hash);
  assert.deepEqual(JSON.parse(entry.detail), {
    checkpointDigest: checkpoint.checkpoint_digest,
    checkpointVersion: checkpoint.checkpoint_version,
    schemaVersion: 1,
  });
  assert.equal(row.id, checkpoint.main_audit_id);
  assert.equal(row.hash, checkpoint.main_audit_hash);
  assert.equal(row.entry.includes(CUSTOMER_A), false);
  assert.equal(row.entry.includes(DEPLOYMENT_A), false);
});

test('forged main-audit binding fields fail reads and mutations without laundering', (t) => {
  const env = fixture();
  t.after(() => env.driver.close());
  const alpha = env.queue(CUSTOMER_A, DEPLOYMENT_A);
  alpha.pendingCount();
  const forged = {
    id: 'a_ffffffffffffffff',
    hash: 'f'.repeat(64),
    updatedAt: '2026-07-13T13:00:00.000Z',
  };
  env.driver.prepare(`UPDATE main.customer_diagnostic_checkpoint
    SET main_audit_id = @id, main_audit_hash = @hash, updated_at = @updatedAt
    WHERE customer_id = @customerId AND deployment_id = @deploymentId`).run({
    ...forged,
    customerId: CUSTOMER_A,
    deploymentId: DEPLOYMENT_A,
  });
  const before = {
    checkpoint: env.driver.prepare(`SELECT checkpoint_version, checkpoint_digest,
        main_audit_id, main_audit_hash, updated_at
      FROM main.customer_diagnostic_checkpoint
      WHERE customer_id = ? AND deployment_id = ?`).get(CUSTOMER_A, DEPLOYMENT_A),
    localAuditCount: env.driver.prepare(`SELECT COUNT(*) AS count
      FROM main.customer_diagnostic_audit`).get().count,
    mainAuditCount: env.driver.prepare('SELECT COUNT(*) AS count FROM main.audit').get().count,
    rowCount: env.driver.prepare(`SELECT COUNT(*) AS count
      FROM main.customer_diagnostic_outbox`).get().count,
  };
  assert.throws(
    () => alpha.pendingCount(),
    (error) => error && error.code === 'diagnostic_storage_failed',
  );
  assert.throws(
    () => alpha.enqueue(diagnostic(CUSTOMER_A, DEPLOYMENT_A, env.now())),
    (error) => error && error.code === 'diagnostic_storage_failed',
  );
  assert.deepEqual(env.driver.prepare(`SELECT checkpoint_version, checkpoint_digest,
      main_audit_id, main_audit_hash, updated_at
    FROM main.customer_diagnostic_checkpoint
    WHERE customer_id = ? AND deployment_id = ?`).get(CUSTOMER_A, DEPLOYMENT_A), before.checkpoint);
  assert.equal(env.driver.prepare(`SELECT COUNT(*) AS count
    FROM main.customer_diagnostic_audit`).get().count, before.localAuditCount);
  assert.equal(env.driver.prepare('SELECT COUNT(*) AS count FROM main.audit').get().count,
    before.mainAuditCount);
  assert.equal(env.driver.prepare(`SELECT COUNT(*) AS count
    FROM main.customer_diagnostic_outbox`).get().count, before.rowCount);
});
