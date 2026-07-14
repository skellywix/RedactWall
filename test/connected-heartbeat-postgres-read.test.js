'use strict';

/**
 * Optional live PostgreSQL proof for the combined connected-license read
 * boundary. The reader and writer use independent pg-driver connections.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const path = require('node:path');
const { Worker } = require('node:worker_threads');
const { Client } = require('pg');
const { createPgDriver } = require('../server/storage/pg-driver');
const {
  createConnectedHeartbeatApplyStore,
  createConnectedHeartbeatTransactionCoordinator,
} = require('../server/connected-heartbeat-apply-store');
const {
  createConnectedAcknowledgedAuthorityStore,
} = require('../server/connected-acknowledged-authority-store');

const ADMIN_URL = process.env.REDACTWALL_TEST_PG_URL || '';
const liveTest = ADMIN_URL ? test : test.skip;
const CUSTOMER_ID = 'customer-postgres-combined-read';
const DEPLOYMENT_ID = `dep_${'a'.repeat(32)}`;
const OLD_PAIR = Object.freeze({ entitlement: 'active', registry: 'revoked' });
const NEW_PAIR = Object.freeze({ entitlement: 'paused', registry: 'active' });
const STAGE = Object.freeze({
  ready: 1,
  start: 2,
  attempting: 3,
  committed: 4,
  failed: 5,
});
const WAIT_MS = 10_000;
const BLOCK_PROOF_MS = 300;

function probeTable(prefix) {
  return `${prefix}_${crypto.randomBytes(6).toString('hex')}`;
}

function quotedIdentifier(value) {
  assert.match(value, /^[a-z][a-z0-9_]+$/);
  return `"${value}"`;
}

function waitForStage(state, expected, timeoutMs = WAIT_MS) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const current = Atomics.load(state, 0);
    if (current === STAGE.failed) throw new Error('PostgreSQL writer probe failed');
    if (current >= expected) return current;
    const remaining = deadline - Date.now();
    if (remaining <= 0) throw new Error(`PostgreSQL writer probe timed out at stage ${current}`);
    Atomics.wait(state, 0, current, Math.min(remaining, 100));
  }
}

function workerCompletion(worker, timeoutMs = WAIT_MS) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('PostgreSQL writer worker timed out')), timeoutMs);
    worker.once('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
    worker.once('exit', (code) => {
      clearTimeout(timer);
      if (code === 0) resolve();
      else reject(new Error(`PostgreSQL writer worker exited with code ${code}`));
    });
  });
}

function startWriter({ entitlementTable, registryTable, signal }) {
  const driverPath = path.resolve(__dirname, '../server/storage/pg-driver.js');
  return new Worker(`
    'use strict';
    const { workerData } = require('node:worker_threads');
    const { createPgDriver } = require(workerData.driverPath);
    const state = new Int32Array(workerData.signal);
    const STAGE = workerData.stages;
    let driver;
    const publish = (stage) => {
      Atomics.store(state, 0, stage);
      Atomics.notify(state, 0);
    };
    try {
      if (!/^[a-z][a-z0-9_]+$/.test(workerData.entitlementTable)
          || !/^[a-z][a-z0-9_]+$/.test(workerData.registryTable)) {
        throw new Error('invalid probe table');
      }
      driver = createPgDriver(workerData.url);
      driver.prepare('SELECT 1 AS ready').get();
      publish(STAGE.ready);
      const waitResult = Atomics.wait(state, 0, STAGE.ready, workerData.waitMs);
      if (waitResult === 'timed-out' || Atomics.load(state, 0) !== STAGE.start) {
        throw new Error('writer start timed out');
      }
      driver.transaction(() => {
        publish(STAGE.attempting);
        driver.lockAuditAppend();
        driver.prepare(
          'UPDATE "' + workerData.entitlementTable + '" SET status = ?'
        ).run(workerData.newPair.entitlement);
        driver.prepare(
          'UPDATE "' + workerData.registryTable + '" SET status = ?'
        ).run(workerData.newPair.registry);
      })();
      publish(STAGE.committed);
    } catch {
      publish(STAGE.failed);
    } finally {
      try { driver?.close(); } catch {}
    }
  `, {
    eval: true,
    workerData: {
      driverPath,
      entitlementTable,
      registryTable,
      signal,
      stages: STAGE,
      waitMs: WAIT_MS,
      url: ADMIN_URL,
      newPair: NEW_PAIR,
    },
  });
}

function entitlementMethods(overrides) {
  return {
    applyEntitlement() {},
    assertExactReplay() {},
    recordFailure() {},
    getState: overrides.getState,
    disposition: overrides.disposition,
    listPendingAcknowledgements() { return []; },
    acknowledgementHealth() { return { healthy: true }; },
    recordAckResult() {},
    assertAcknowledgementLineages() { return []; },
  };
}

function acknowledgedAuthorityMethods() {
  return {
    stagePair() {},
    recordAcknowledgementResult() {},
    getState() { return null; },
    constrainDisposition(input) { return input.currentDisposition; },
  };
}

function registryMethods(overrides) {
  return {
    applyVerdict() {},
    getState: overrides.getState,
    registryGeneration() { return 0; },
    disposition: overrides.disposition,
  };
}

function authorityCatalogProbe(driver) {
  return createConnectedAcknowledgedAuthorityStore({
    customerId: 'customer_catalog_probe',
    deploymentId: DEPLOYMENT_ID,
    driver,
    entitlementStore: { assertAcknowledgementLineages() { return []; } },
    appendAudit() {},
    authorityReference() { return `connected_${'a'.repeat(32)}`; },
    ackReference() { return `connected_ack_${'b'.repeat(32)}`; },
    verifyAuditState() { return { ok: true }; },
    verifyAuditEntry() { return true; },
    compositeCoordinator: createConnectedHeartbeatTransactionCoordinator(),
  });
}

async function runCombinedRead(method) {
  const entitlementTable = probeTable('rw_entitlement_read_probe');
  const registryTable = probeTable('rw_registry_read_probe');
  const entitlementSql = quotedIdentifier(entitlementTable);
  const registrySql = quotedIdentifier(registryTable);
  const reader = createPgDriver(ADMIN_URL);
  const signalBuffer = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT);
  const signal = new Int32Array(signalBuffer);
  let writer;
  let writerDone;

  try {
    reader.exec(`
      CREATE TABLE ${entitlementSql} (status TEXT NOT NULL);
      CREATE TABLE ${registrySql} (status TEXT NOT NULL);
      INSERT INTO ${entitlementSql} VALUES ('${OLD_PAIR.entitlement}');
      INSERT INTO ${registrySql} VALUES ('${OLD_PAIR.registry}');
    `);
    writer = startWriter({ entitlementTable, registryTable, signal: signalBuffer });
    writerDone = workerCompletion(writer);
    writerDone.catch(() => {});
    assert.equal(waitForStage(signal, STAGE.ready), STAGE.ready);

    let writerStarted = false;
    const triggerWriter = () => {
      if (writerStarted) return;
      writerStarted = true;
      assert.equal(
        Atomics.compareExchange(signal, 0, STAGE.ready, STAGE.start),
        STAGE.ready,
      );
      Atomics.notify(signal, 0);
      assert.equal(waitForStage(signal, STAGE.attempting), STAGE.attempting);
    };
    const proveWriterBlocked = () => {
      assert.equal(Atomics.load(signal, 0), STAGE.attempting);
      const waitResult = Atomics.wait(
        signal,
        0,
        STAGE.attempting,
        BLOCK_PROOF_MS,
      );
      assert.equal(waitResult, 'timed-out', 'writer committed between authority reads');
      assert.equal(Atomics.load(signal, 0), STAGE.attempting);
    };

    const entitlementStore = entitlementMethods({
      getState() {
        const status = reader.prepare(`SELECT status FROM ${entitlementSql}`).get().status;
        triggerWriter();
        return { status };
      },
      disposition() {
        const status = reader.prepare(`SELECT status FROM ${entitlementSql}`).get().status;
        triggerWriter();
        return { status, protectedEgress: status === 'active' ? 'allow' : 'block' };
      },
    });
    const registryStore = registryMethods({
      getState() {
        proveWriterBlocked();
        return { status: reader.prepare(`SELECT status FROM ${registrySql}`).get().status };
      },
      disposition(_customerId, _deploymentId, entitlement) {
        proveWriterBlocked();
        const status = reader.prepare(`SELECT status FROM ${registrySql}`).get().status;
        return {
          ...entitlement,
          registryStatus: status,
          protectedEgress: status === 'active' ? entitlement.protectedEgress : 'block',
        };
      },
    });

    const store = createConnectedHeartbeatApplyStore({
      driver: reader,
      entitlementStore,
      registryStore,
      acknowledgedAuthorityStore: acknowledgedAuthorityMethods(),
      verifyAuditState: () => ({ ok: true }),
      coordinator: createConnectedHeartbeatTransactionCoordinator(),
    });

    const result = method === 'getState'
      ? store.getState(CUSTOMER_ID, DEPLOYMENT_ID)
      : store.disposition(CUSTOMER_ID, DEPLOYMENT_ID, { nowMs: Date.now() });
    if (method === 'getState') {
      assert.deepEqual(result, {
        entitlement: { status: OLD_PAIR.entitlement },
        registry: { status: OLD_PAIR.registry },
        acknowledgedAuthority: null,
      });
    } else {
      assert.deepEqual(result, {
        status: OLD_PAIR.entitlement,
        protectedEgress: 'block',
        registryStatus: OLD_PAIR.registry,
      });
    }

    assert.equal(waitForStage(signal, STAGE.committed, 2_000), STAGE.committed);
    await writerDone;
    assert.deepEqual({
      entitlement: reader.prepare(`SELECT status FROM ${entitlementSql}`).get().status,
      registry: reader.prepare(`SELECT status FROM ${registrySql}`).get().status,
    }, NEW_PAIR);
  } finally {
    if (writer && Atomics.load(signal, 0) < STAGE.committed) {
      await writer.terminate().catch(() => {});
      if (writerDone) await writerDone.catch(() => {});
    } else if (writerDone) {
      await writerDone.catch(() => {});
    }
    try { reader.exec(`DROP TABLE IF EXISTS ${registrySql}; DROP TABLE IF EXISTS ${entitlementSql};`); }
    finally { reader.close(); }
  }
}

liveTest('PostgreSQL combined connected-license reads exclude a coordinated writer', {
  timeout: 60_000,
}, async (t) => {
  await t.test('getState returns one old pair before the writer commits', () => (
    runCombinedRead('getState')
  ));
  await t.test('disposition returns one old pair before the writer commits', () => (
    runCombinedRead('disposition')
  ));
});

liveTest('PostgreSQL authority mutation lock closes the trigger replacement race', {
  timeout: 30_000,
}, async () => {
  const suffix = crypto.randomBytes(6).toString('hex');
  const stateTable = `rw_authority_state_${suffix}`;
  const lineageTable = `rw_authority_lineage_${suffix}`;
  const deletionTable = `rw_authority_deletion_${suffix}`;
  const functionName = `rw_authority_delete_${suffix}`;
  const reader = new Client({
    connectionString: ADMIN_URL,
    connectionTimeoutMillis: 5_000,
    statement_timeout: 5_000,
    query_timeout: 6_000,
  });
  const attacker = new Client({
    connectionString: ADMIN_URL,
    connectionTimeoutMillis: 5_000,
    statement_timeout: 5_000,
    query_timeout: 6_000,
  });
  const tables = [stateTable, lineageTable, deletionTable].map(quotedIdentifier);
  const quotedFunction = quotedIdentifier(functionName);
  await reader.connect();
  await attacker.connect();
  try {
    await reader.query(`CREATE TABLE ${tables[0]} (id bigint PRIMARY KEY);
      CREATE TABLE ${tables[1]} (id bigint PRIMARY KEY);
      CREATE TABLE ${tables[2]} (id bigint PRIMARY KEY);
      CREATE FUNCTION ${quotedFunction}() RETURNS trigger LANGUAGE plpgsql
        SET search_path = pg_catalog AS $fn$ BEGIN RETURN OLD; END; $fn$;`);
    const originalDefinition = (await attacker.query(`SELECT pg_catalog.pg_get_functiondef(
      'public.${functionName}()'::pg_catalog.regprocedure) AS ddl`)).rows[0].ddl;
    const identity = async () => (await reader.query(`SELECT p.oid::text AS oid,
      p.xmin::text AS xmin, p.prosrc, COALESCE(p.proconfig, ARRAY[]::text[]) AS config
      FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = 'public' AND p.proname = $1`, [functionName])).rows[0];

    await reader.query('BEGIN');
    await reader.query(`LOCK TABLE ${tables.join(', ')} IN SHARE ROW EXCLUSIVE MODE`);
    const before = await identity();
    await attacker.query(`CREATE OR REPLACE FUNCTION ${quotedFunction}()
      RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog
      AS $fn$ BEGIN RETURN NULL; END; $fn$;`);
    await attacker.query(originalDefinition);
    const after = await identity();
    assert.equal(after.oid, before.oid);
    assert.notEqual(after.xmin, before.xmin,
      'restoring exact function source must not restore the pre-operation identity');
    assert.equal(after.prosrc, before.prosrc);
    assert.deepEqual(after.config, before.config);

    await attacker.query('SET statement_timeout = 750');
    await assert.rejects(
      attacker.query(`UPDATE ${tables[2]} SET id = id WHERE false`),
      (error) => error?.code === '57014',
    );
    await reader.query('ROLLBACK');
    await attacker.query('SET statement_timeout = 5000');
    await attacker.query(`UPDATE ${tables[2]} SET id = id WHERE false`);
  } finally {
    await reader.query('ROLLBACK').catch(() => {});
    await attacker.query('SET statement_timeout = 5000').catch(() => {});
    await attacker.query(`DROP FUNCTION IF EXISTS ${quotedFunction}();
      DROP TABLE IF EXISTS ${tables.reverse().join(', ')}`).catch(() => {});
    await Promise.allSettled([reader.end(), attacker.end()]);
  }
});

liveTest('PostgreSQL authority catalog pins the exact UTC tombstone function', {
  timeout: 30_000,
}, () => {
  const driver = createPgDriver(ADMIN_URL);
  const store = authorityCatalogProbe(driver);
  const rollback = new Error('rollback catalog mutation');
  try {
    assert.equal(driver.transaction(() => store.getState(
      'customer_catalog_probe', DEPLOYMENT_ID,
    ))(), null);
    assert.throws(() => driver.transaction(() => {
      const original = driver.prepare(`SELECT pg_catalog.pg_get_functiondef(
        'public.record_connected_authority_pair_delete()'::pg_catalog.regprocedure
      ) AS ddl`).get().ddl;
      assert.match(original, /clock_timestamp\(\) AT TIME ZONE 'UTC'/);
      const mutated = original.replace(" AT TIME ZONE 'UTC'", '');
      assert.notEqual(mutated, original);
      driver.exec(mutated);
      assert.throws(
        () => store.getState('customer_catalog_probe', DEPLOYMENT_ID),
        (error) => error?.code === 'CONNECTED_ACKNOWLEDGED_AUTHORITY_INTEGRITY',
      );
      throw rollback;
    })(), (error) => error === rollback);
    assert.equal(driver.transaction(() => store.getState(
      'customer_catalog_probe', DEPLOYMENT_ID,
    ))(), null, 'rollback restores the exact accepted catalog');
  } finally { driver.close(); }
});
