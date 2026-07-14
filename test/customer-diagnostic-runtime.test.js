'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const Database = require('better-sqlite3');
const { MIGRATIONS } = require('../server/storage/migrations');
const auditIntegrity = require('../server/audit-integrity');
const { createCustomerDiagnosticStorage } = require('../server/customer-diagnostic-storage');
const { createCustomerDiagnosticIntegrityAuthority } = require('../server/customer-diagnostic-integrity');
const { createCustomerDiagnosticRuntime } = require('../server/customer-diagnostic-runtime');

const CUSTOMER_ID = 'customer_runtime';
const DEPLOYMENT_ID = 'dep_33333333333333333333333333333333';
const NOW = Date.parse('2026-07-13T12:00:00.000Z');
const ZERO = '0'.repeat(64);
const TEST_AUDIT_KEY = Buffer.alloc(32, 0x29);

function diagnosticStorage(driver) {
  const checkpointRef = 'diagnostic_checkpoint_33333333333333333333333333333333';
  const lookup = driver.prepare(`SELECT entry FROM audit
    WHERE diagnostic_checkpoint_ref = ? ORDER BY seq DESC LIMIT 1`);
  return createCustomerDiagnosticStorage({
    driver,
    driverKind: 'sqlite',
    checkpointReference: () => checkpointRef,
    verifyMainAudit: () => true,
    loadMainAuditCheckpoint({ checkpointRef: value }) {
      const row = lookup.get(value);
      return row ? JSON.parse(row.entry) : null;
    },
    appendMainAudit(event) {
      const last = driver.prepare('SELECT hash FROM audit ORDER BY seq DESC LIMIT 1').get();
      const prevHash = last ? last.hash : ZERO;
      const body = {
        id: `a_${crypto.randomUUID()}`,
        ts: new Date(NOW).toISOString(),
        prevHash,
        action: event.action,
        queryId: '',
        actor: event.actor,
        detail: event.detail,
        diagnosticCheckpointRef: event.diagnosticCheckpointRef,
      };
      const entry = auditIntegrity.authenticatedEntry(prevHash, body, TEST_AUDIT_KEY);
      driver.prepare(`INSERT INTO audit
        (id, ts, action, queryId, actor, prevHash, hash, entry)
        VALUES (@id, @ts, @action, NULL, @actor, @prevHash, @hash, @entry)`).run({
        ...body, hash: entry.hash, entry: JSON.stringify(entry),
      });
      return entry;
    },
    verifyMainAuditEntry: (entry) => auditIntegrity.validAuthenticatedEntry(
      entry, TEST_AUDIT_KEY,
    ),
  });
}

function runtime(options = {}) {
  const driver = new Database(':memory:');
  for (const version of [1, 2, 14, 16]) {
    const migration = MIGRATIONS.find((candidate) => candidate.version === version);
    assert.ok(migration, `migration ${version} is required`);
    driver.exec(migration.sqlite);
  }
  const storage = diagnosticStorage(driver);
  const authority = createCustomerDiagnosticIntegrityAuthority({
    secret: Buffer.alloc(32, 0x73).toString('base64'), env: {},
  });
  let now = NOW;
  const timers = [];
  const value = createCustomerDiagnosticRuntime({
    consent: true,
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    storage,
    integrityAuthority: authority,
    componentVersion: '1.2.3',
    clock: () => now,
    randomUUID: crypto.randomUUID,
    setTimeout: (callback, delay) => {
      const timer = { callback, delay, unref() {}, cleared: false };
      timers.push(timer);
      return timer;
    },
    clearTimeout: (timer) => { timer.cleared = true; },
    random: () => 0,
    ...options,
  });
  return {
    driver, storage, authority, value, timers,
    advance: (ms) => { now += ms; },
  };
}

test('consent off creates a no-op runtime and never touches storage or delivery', async () => {
  let storageCalls = 0;
  let senderCalls = 0;
  const value = createCustomerDiagnosticRuntime({
    consent: false,
    storage: { transaction() { storageCalls += 1; } },
    sender: async () => { senderCalls += 1; return true; },
  });
  assert.deepEqual(value.status(), {
    enabled: false,
    state: 'disabled',
    queued: 0,
    degraded: false,
    failureCode: null,
    workerRunning: false,
  });
  assert.deepEqual(value.connectorFailure('timeout'), {
    accepted: false, reason: 'diagnostic_consent_required',
  });
  assert.deepEqual(await value.drain(), { ok: true, enabled: false, processed: 0 });
  assert.equal(storageCalls, 0);
  assert.equal(senderCalls, 0);
});

test('fixed producers accept only closed enums and never persist caller text', () => {
  const env = runtime();
  try {
    assert.equal(env.value.connectorFailure('timeout').accepted, true);
    assert.equal(env.value.connectorFailure('authentication').accepted, true);
    assert.equal(env.value.connectorFailure('protocol').accepted, true);
    assert.equal(env.value.entitlementRejected().accepted, true);
    assert.equal(env.value.queueBacklog('21-100').accepted, true);
    assert.equal(env.value.recovery('connector').accepted, true);
    for (const input of [
      'prompt=123-45-6789',
      'https://member.example/private',
      'canary_token_001',
      { toString: () => 'timeout', prompt: '4111111111111111' },
    ]) {
      assert.throws(
        () => env.value.connectorFailure(input),
        (error) => error && error.code === 'diagnostic_producer_input_invalid'
          && !String(error.message).includes('123-45-6789')
          && !String(error.message).includes('canary_token_001'),
      );
    }
    const payloads = env.driver.prepare(`SELECT payload_json FROM customer_diagnostic_outbox
      ORDER BY created_at, message_id`).all().map(({ payload_json }) => payload_json);
    assert.equal(payloads.length, 6);
    const joined = payloads.join('\n');
    for (const forbidden of [
      '123-45-6789', 'member.example', 'canary_token_001', '4111111111111111',
      '"prompt":', '"url":', '"host":', '"user":', '"file":', '"stack":', '"error":',
    ]) assert.equal(joined.includes(forbidden), false, forbidden);
  } finally { env.driver.close(); }
});

test('default delivery is disabled until an injected adapter proves durable acceptance', async () => {
  const env = runtime();
  try {
    env.value.connectorFailure('timeout');
    assert.deepEqual(env.value.start(), { ok: true, enabled: true });
    const result = await env.value.drain();
    assert.deepEqual(result, {
      ok: false, enabled: true, processed: 0, reason: 'diagnostic_delivery_contract_unavailable',
    });
    assert.equal(env.driver.prepare(`SELECT status FROM customer_diagnostic_outbox`).get().status, 'pending');
    const status = env.value.status();
    assert.deepEqual(Object.keys(status), [
      'enabled', 'state', 'queued', 'degraded', 'failureCode', 'workerRunning',
    ]);
    assert.equal(status.queued, 1);
    assert.equal(status.degraded, true);
    assert.equal(JSON.stringify(status).includes('CONNECTOR_TIMEOUT'), false);
    await env.value.stop();
  } finally { env.driver.close(); }
});

test('enabled startup fails closed when the authenticated scope checkpoint is missing or corrupt', () => {
  for (const damage of ['missing', 'corrupt']) {
    const env = runtime({ sender: async () => false });
    try {
      env.value.connectorFailure('timeout');
      if (damage === 'missing') {
        env.driver.prepare(`DELETE FROM customer_diagnostic_checkpoint
          WHERE customer_id = ? AND deployment_id = ?`).run(CUSTOMER_ID, DEPLOYMENT_ID);
      } else {
        env.driver.prepare(`UPDATE customer_diagnostic_checkpoint
          SET checkpoint_digest = ?
          WHERE customer_id = ? AND deployment_id = ?`)
          .run('f'.repeat(64), CUSTOMER_ID, DEPLOYMENT_ID);
      }
      assert.deepEqual(env.value.start(), {
        ok: false,
        enabled: true,
        reason: 'diagnostic_storage_failed',
      }, damage);
      assert.equal(env.value.status().workerRunning, false, damage);
      assert.equal(env.timers.length, 0, damage);
    } finally { env.driver.close(); }
  }
});

test('worker retries the same opaque event and deletes payload only after literal true receipt proof', async () => {
  const deliveries = [];
  const env = runtime({
    sender: async (event) => {
      deliveries.push(event);
      return deliveries.length > 1;
    },
  });
  try {
    env.value.connectorFailure('timeout');
    const first = await env.value.drain();
    assert.equal(first.ok, false);
    assert.equal(first.processed, 1);
    assert.equal(env.driver.prepare(`SELECT status FROM customer_diagnostic_outbox`).get().status, 'pending');
    env.advance(5_000);
    const second = await env.value.drain();
    assert.equal(second.ok, true);
    assert.equal(second.processed, 1);
    assert.equal(deliveries.length, 2);
    assert.deepEqual(deliveries[1], deliveries[0]);
    const row = env.driver.prepare(`SELECT status, payload_json FROM customer_diagnostic_outbox`).get();
    assert.deepEqual(row, { status: 'delivered', payload_json: null });
  } finally { env.driver.close(); }
});

test('stop waits for an active delivery and prevents later scheduling', async () => {
  let release;
  const env = runtime({
    sender: () => new Promise((resolve) => { release = resolve; }),
  });
  try {
    env.value.connectorFailure('timeout');
    env.value.start();
    const active = env.value.drain();
    const stopping = env.value.stop();
    let stopped = false;
    stopping.then(() => { stopped = true; });
    await Promise.resolve();
    assert.equal(stopped, false);
    release(true);
    assert.equal((await active).ok, true);
    assert.deepEqual(await stopping, { ok: true, enabled: true });
    assert.equal(env.value.status().workerRunning, false);
    assert.deepEqual(env.value.start(), {
      ok: false, enabled: true, reason: 'diagnostic_runtime_stopped',
    });
  } finally { env.driver.close(); }
});
