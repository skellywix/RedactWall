'use strict';

const crypto = require('node:crypto');
const test = require('node:test');
const assert = require('node:assert/strict');
const protocol = require('../server/vendor-control-protocol');
const {
  createCustomerDiagnosticOutbox,
  RETRY_BASE_MS,
} = require('../server/customer-diagnostic-outbox');

const CUSTOMER_ID = 'customer_alpha';
const DEPLOYMENT_ID = 'dep_88888888888888888888888888888888';
const NOW = Date.parse('2026-07-12T12:00:00.000Z');
const KEY = Buffer.alloc(32, 0x5a);

function diagnostic(overrides = {}) {
  return {
    schemaVersion: 1,
    messageId: crypto.randomUUID(),
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    kind: protocol.CHANNEL_KINDS.DIAGNOSTIC,
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
    occurredAt: new Date(NOW).toISOString(),
    ...overrides,
  };
}

function createAuthority(key = KEY, keyId = 'diagnostic-test-v1') {
  return Object.freeze({
    sign(message) {
      return Object.freeze({ keyId, mac: hmac(key, message) });
    },
    verify(message, proof) {
      if (!proof || proof.keyId !== keyId || !/^[a-f0-9]{64}$/.test(String(proof.mac || ''))) {
        return false;
      }
      const expected = Buffer.from(hmac(key, message), 'hex');
      const actual = Buffer.from(proof.mac, 'hex');
      return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
    },
  });
}

function mutableClock(start = NOW) {
  let now = start;
  return Object.freeze({
    clock: () => now,
    get: () => now,
    set: (value) => { now = value; },
    advance: (value) => { now += value; },
  });
}

function createStorage() {
  const data = {
    rows: new Map(),
    audits: [],
    timeByScope: new Map(),
    rejectAudit: null,
    transactionCalls: 0,
    readDiagnosticCalls: 0,
  };
  const behavior = {
    transactionMode: null,
    compareReturnCurrent: false,
    compareMiss: false,
    countAsString: false,
    appendReturnAltered: false,
  };
  return {
    data,
    behavior,
    transaction(callback) {
      data.transactionCalls += 1;
      const staged = stagedData(data);
      const tx = transactionApi(staged, behavior, data);
      if (behavior.transactionMode === 'double_callback') {
        callback(tx);
        callback(tx);
        throw new Error('unreachable double callback');
      }
      const result = callback(tx);
      if (behavior.transactionMode === 'substitute') {
        return Object.freeze([{ event: Object.freeze({ detail: '123-45-6789' }) }]);
      }
      if (behavior.transactionMode === 'clone_result') return clone(result);
      if (behavior.transactionMode === 'thenable') return Promise.resolve(result);
      commit(data, staged);
      return result;
    },
  };
}

function transactionApi(data, behavior, counters) {
  return {
    readDiagnostic(query) {
      counters.readDiagnosticCalls += 1;
      return clone(data.rows.get(rowKey(query)));
    },
    countPendingDiagnostics(query) {
      const count = matching(data, query)
        .filter((row) => row.status === 'pending' || row.status === 'leased').length;
      return behavior.countAsString ? String(count) : count;
    },
    countDiagnosticRecords(query) {
      const count = matching(data, query).length;
      return behavior.countAsString ? String(count) : count;
    },
    insertDiagnostic(row) {
      const key = rowKey(row);
      if (data.rows.has(key)) throw new Error('duplicate diagnostic row');
      data.rows.set(key, clone(row));
      return clone(row);
    },
    listReadyDiagnostics(query) {
      return matching(data, query)
        .filter((row) => row.status === 'pending'
          ? row.nextAttemptAt <= query.now
          : row.status === 'leased' && row.leaseUntil <= query.now)
        .sort(compareRows)
        .slice(0, query.limit)
        .map(clone);
    },
    compareAndSwapDiagnostic(input) {
      if (behavior.compareMiss) return null;
      const key = rowKey(input);
      const current = data.rows.get(key);
      if (!current || current.stateMac !== input.expectedStateMac
          || current.auditAnchor !== input.expectedAuditAnchor
          || current.stateVersion !== input.expectedStateVersion) return null;
      data.rows.set(key, clone(input.nextRow));
      return clone(behavior.compareReturnCurrent ? current : input.nextRow);
    },
    listExpiredDiagnosticTombstones(query) {
      return matching(data, query)
        .filter((row) => ['delivered', 'expired', 'dead_letter'].includes(row.status)
          && row.retainUntil <= query.before)
        .sort(compareRows)
        .slice(0, query.limit)
        .map(clone);
    },
    deleteDiagnosticTombstone(input) {
      const key = rowKey(input);
      const current = data.rows.get(key);
      if (!current || current.stateMac !== input.expectedStateMac
          || current.auditAnchor !== input.expectedAuditAnchor
          || current.stateVersion !== input.expectedStateVersion
          || current.retainUntil !== input.expectedRetainUntil) return null;
      data.rows.delete(key);
      return clone(current);
    },
    appendDiagnosticAudit(event) {
      if (data.rejectAudit === event.action) throw new Error('forced audit failure with canary_token_001');
      data.audits.push(clone(event));
      return behavior.appendReturnAltered ? { ...clone(event), action: 'ALTERED' } : clone(event);
    },
    readDiagnosticTimeHighWater(query) {
      return clone(data.timeByScope.get(scopeKey(query)));
    },
    readLatestDiagnosticAudit(query) {
      for (let index = data.audits.length - 1; index >= 0; index -= 1) {
        const event = data.audits[index];
        if (event.customerId === query.customerId && event.deploymentId === query.deploymentId
            && event.messageId === query.messageId) return clone(event);
      }
      return null;
    },
    advanceDiagnosticTimeHighWater(input) {
      const key = scopeKey(input);
      const current = data.timeByScope.get(key);
      if ((current ? current.stateMac : null) !== input.expectedStateMac
          || (current ? current.observedAt : null) !== input.expectedObservedAt) return null;
      data.timeByScope.set(key, clone(input.nextRecord));
      return clone(input.nextRecord);
    },
  };
}

function stagedData(data) {
  return {
    rows: new Map([...data.rows].map(([key, value]) => [key, clone(value)])),
    audits: clone(data.audits),
    timeByScope: new Map([...data.timeByScope].map(([key, value]) => [key, clone(value)])),
    rejectAudit: data.rejectAudit,
  };
}

function commit(data, staged) {
  data.rows = staged.rows;
  data.audits = staged.audits;
  data.timeByScope = staged.timeByScope;
}

function matching(data, query) {
  return [...data.rows.values()].filter((row) => row.customerId === query.customerId
    && row.deploymentId === query.deploymentId);
}

function compareRows(left, right) {
  return left.createdAt.localeCompare(right.createdAt) || left.messageId.localeCompare(right.messageId);
}

function rowKey(value) {
  return `${value.customerId}\0${value.deploymentId}\0${value.messageId}`;
}

function scopeKey(value) {
  return `${value.customerId}\0${value.deploymentId}`;
}

function outbox(storage = createStorage(), options = {}) {
  const clock = options.clockControl || mutableClock();
  const authority = options.integrityAuthority || createAuthority();
  const queue = createCustomerDiagnosticOutbox({
    storage,
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    maxItems: 2,
    leaseMs: 5_000,
    clock: clock.clock,
    integrityAuthority: authority,
    ...options,
    clockControl: undefined,
  });
  return { storage, queue, clock, authority };
}

function deliveryReceipt(lease, accepted) {
  return {
    messageId: lease.messageId,
    payloadDigest: lease.payloadDigest,
    leaseId: lease.leaseId,
    accepted,
  };
}

test('durably queues, leases, compacts delivery, and remembers an authenticated replay', () => {
  const env = outbox();
  const event = diagnostic();
  const accepted = env.queue.enqueue(event);
  assert.equal(env.queue.pendingCount(), 1);
  const [lease] = env.queue.leaseReady({ limit: 1 });
  assert.deepEqual(lease.event, event);
  assert.equal(lease.payloadDigest, accepted.digest);
  assert.equal(lease.attempts, 1);
  env.clock.advance(1_000);
  assert.equal(env.queue.recordDelivery(deliveryReceipt(lease, true)).delivered, true);
  assert.equal(env.queue.pendingCount(), 0);

  const row = [...env.storage.data.rows.values()][0];
  assert.equal(row.status, 'delivered');
  assert.equal(row.payloadJson, null);
  assert.match(row.stateMac, /^[a-f0-9]{64}$/);
  assert.match(row.auditAnchor, /^[a-f0-9]{64}$/);

  const restarted = outbox(env.storage, {
    clockControl: env.clock,
    integrityAuthority: env.authority,
  }).queue;
  assert.equal(restarted.enqueue({ ...event }).duplicate, true);
  assert.deepEqual(env.storage.data.audits.map((entry) => entry.action), [
    'DIAGNOSTIC_QUEUED', 'DIAGNOSTIC_LEASED', 'DIAGNOSTIC_DELIVERED',
  ]);
});

test('sensitive or unknown metadata is never persisted or echoed into authenticated audit evidence', () => {
  const env = outbox();
  const canary = '123-45-6789';
  assert.throws(
    () => env.queue.enqueue(diagnostic({ detail: canary })),
    (error) => error.code === 'diagnostic_schema_rejected'
      && error.auditRecorded === true && !error.message.includes(canary),
  );
  assert.equal(env.storage.data.rows.size, 0);
  const serialized = JSON.stringify(env.storage.data.audits);
  assert.equal(serialized.includes(canary), false);
  assert.equal(env.storage.data.audits[0].action, 'DIAGNOSTIC_REJECTED');
  assert.equal(env.storage.data.audits[0].reasonCode, 'schema_rejected');
  assert.match(env.storage.data.audits[0].auditAnchor, /^[a-f0-9]{64}$/);
});

test('exact idempotency, pending pressure, and total history pressure fail closed', () => {
  const pendingEnv = outbox(undefined, { maxItems: 1, maxRecords: 2 });
  const first = diagnostic();
  pendingEnv.queue.enqueue(first);
  assert.throws(
    () => pendingEnv.queue.enqueue({ ...first, severity: 'critical' }),
    (error) => error.code === 'diagnostic_idempotency_conflict' && error.auditRecorded === true,
  );
  assert.throws(
    () => pendingEnv.queue.enqueue(diagnostic()),
    (error) => error.code === 'diagnostic_queue_full' && error.auditRecorded === true,
  );

  const historyEnv = outbox(undefined, { maxItems: 1, maxRecords: 1 });
  const event = diagnostic();
  historyEnv.queue.enqueue(event);
  const lease = historyEnv.queue.leaseReady()[0];
  historyEnv.queue.recordDelivery(deliveryReceipt(lease, true));
  assert.throws(
    () => historyEnv.queue.enqueue(diagnostic()),
    (error) => error.code === 'diagnostic_history_full' && error.auditRecorded === true,
  );
});

test('expired leases are fenced and a replacement lease advances the bounded attempt', () => {
  let nextId = 0;
  const env = outbox(undefined, {
    randomUUID: () => `00000000-0000-4000-8000-${String(++nextId).padStart(12, '0')}`,
  });
  env.queue.enqueue(diagnostic());
  const first = env.queue.leaseReady()[0];
  env.clock.advance(4_999);
  assert.equal(env.queue.leaseReady().length, 0);
  env.clock.advance(1);
  assert.throws(
    () => env.queue.recordDelivery(deliveryReceipt(first, true)),
    (error) => error.code === 'diagnostic_delivery_not_current',
  );
  const second = env.queue.leaseReady()[0];
  assert.notEqual(second.leaseId, first.leaseId);
  assert.equal(second.attempts, 2);
  const retry = env.queue.recordDelivery(deliveryReceipt(second, false));
  assert.equal(retry.delivered, false);
  assert.equal(retry.nextAttemptAt, new Date(env.clock.get() + (RETRY_BASE_MS * 2)).toISOString());
});

test('audit failure rolls back mutations and preserves a sanitized rejection disposition', () => {
  const env = outbox();
  env.storage.data.rejectAudit = 'DIAGNOSTIC_QUEUED';
  assert.throws(
    () => env.queue.enqueue(diagnostic()),
    (error) => error.code === 'diagnostic_storage_failed'
      && !error.message.includes('canary_token_001'),
  );
  assert.equal(env.storage.data.rows.size, 0);
  env.storage.data.rejectAudit = null;

  env.queue.enqueue(diagnostic());
  env.storage.data.rejectAudit = 'DIAGNOSTIC_LEASED';
  assert.throws(
    () => env.queue.leaseReady(),
    (error) => error.code === 'diagnostic_storage_failed',
  );
  assert.equal([...env.storage.data.rows.values()][0].status, 'pending');
  env.storage.data.rejectAudit = null;

  const lease = env.queue.leaseReady()[0];
  env.storage.data.rejectAudit = 'DIAGNOSTIC_DELIVERED';
  assert.throws(
    () => env.queue.recordDelivery(deliveryReceipt(lease, true)),
    (error) => error.code === 'diagnostic_storage_failed',
  );
  assert.equal([...env.storage.data.rows.values()][0].status, 'leased');

  env.storage.data.rejectAudit = 'DIAGNOSTIC_REJECTED';
  const canary = 'canary_token_DO_NOT_ECHO';
  assert.throws(
    () => env.queue.enqueue(diagnostic({ detail: canary })),
    (error) => error.code === 'diagnostic_schema_rejected'
      && error.auditRecorded === false
      && error.auditFailureCode === 'diagnostic_rejection_audit_failed'
      && !error.message.includes(canary),
  );
});

test('a recomputed payload digest cannot bypass customer-local state authentication', () => {
  const env = outbox();
  env.queue.enqueue(diagnostic());
  const row = [...env.storage.data.rows.values()][0];
  const originalAuditDigest = env.storage.data.audits[0].payloadDigest;
  row.payloadJson = row.payloadJson.replace('"warning"', '"critical"');
  row.payloadDigest = crypto.createHash('sha256').update(row.payloadJson).digest('hex');
  assert.notEqual(row.payloadDigest, originalAuditDigest);
  assert.throws(
    () => env.queue.leaseReady(),
    (error) => error.code === 'diagnostic_integrity_failed',
  );
});

test('a valid older signed row cannot roll back the latest authenticated audit head', () => {
  const restored = outbox();
  const event = diagnostic();
  restored.queue.enqueue(event);
  const key = rowKey(event);
  const queuedSnapshot = clone(restored.storage.data.rows.get(key));
  const lease = restored.queue.leaseReady()[0];
  restored.queue.recordDelivery(deliveryReceipt(lease, true));
  restored.storage.data.rows.set(key, queuedSnapshot);
  assert.throws(
    () => restored.queue.leaseReady(),
    (error) => error.code === 'diagnostic_audit_anchor_mismatch',
  );

  const deleted = outbox();
  const deletedEvent = diagnostic();
  deleted.queue.enqueue(deletedEvent);
  const deletedLease = deleted.queue.leaseReady()[0];
  deleted.queue.recordDelivery(deliveryReceipt(deletedLease, true));
  deleted.storage.data.rows.delete(rowKey(deletedEvent));
  assert.throws(
    () => deleted.queue.enqueue({ ...deletedEvent }),
    (error) => error.code === 'diagnostic_audit_anchor_mismatch',
  );
});

test('a missing latest audit head fails closed before a queued diagnostic can be released', () => {
  const env = outbox();
  env.queue.enqueue(diagnostic());
  env.storage.data.audits.length = 0;
  assert.throws(
    () => env.queue.leaseReady(),
    (error) => error.code === 'diagnostic_audit_anchor_mismatch',
  );
});

test('transaction callbacks are one-shot and transaction results are identity-bound', () => {
  for (const mode of ['double_callback', 'substitute', 'clone_result', 'thenable']) {
    const env = outbox();
    env.queue.enqueue(diagnostic());
    const auditsBefore = env.storage.data.audits.length;
    env.storage.behavior.transactionMode = mode;
    assert.throws(
      () => env.queue.leaseReady(),
      (error) => error.code === 'diagnostic_storage_invalid'
        || error.code === 'diagnostic_storage_failed',
    );
    assert.equal(env.storage.data.audits.length, auditsBefore);
    assert.equal([...env.storage.data.rows.values()][0].status, 'pending');
  }
});

test('storage transition and audit return values must reconcile exactly', () => {
  const transitionEnv = outbox();
  transitionEnv.queue.enqueue(diagnostic());
  transitionEnv.storage.behavior.compareReturnCurrent = true;
  assert.throws(
    () => transitionEnv.queue.leaseReady(),
    (error) => error.code === 'diagnostic_integrity_failed',
  );
  assert.equal([...transitionEnv.storage.data.rows.values()][0].status, 'pending');

  const auditEnv = outbox();
  auditEnv.storage.behavior.appendReturnAltered = true;
  assert.throws(
    () => auditEnv.queue.enqueue(diagnostic()),
    (error) => error.code === 'diagnostic_integrity_failed',
  );
  assert.equal(auditEnv.storage.data.rows.size, 0);
  assert.equal(auditEnv.storage.data.audits.length, 0);

  const missingTransition = outbox();
  missingTransition.queue.enqueue(diagnostic());
  missingTransition.storage.behavior.compareMiss = true;
  assert.throws(
    () => missingTransition.queue.leaseReady(),
    (error) => error.code === 'diagnostic_state_conflict',
  );
  assert.equal([...missingTransition.storage.data.rows.values()][0].status, 'pending');
});

test('the construction-time clock uses an authenticated durable monotonic high-water', () => {
  const env = outbox();
  env.queue.enqueue(diagnostic());
  const highWater = env.storage.data.timeByScope.get(scopeKey({
    customerId: CUSTOMER_ID, deploymentId: DEPLOYMENT_ID,
  }));
  assert.equal(highWater.observedAt, new Date(NOW).toISOString());

  env.clock.set(NOW - 60_000);
  const lease = env.queue.leaseReady()[0];
  assert.equal(lease.leaseUntil, new Date(NOW + 5_000).toISOString());
  assert.throws(
    () => env.queue.leaseReady({ nowMs: NOW + 100_000 }),
    (error) => error.code === 'diagnostic_limit_invalid',
  );

  env.storage.data.timeByScope.get(scopeKey({
    customerId: CUSTOMER_ID, deploymentId: DEPLOYMENT_ID,
  })).observedAt = new Date(NOW + 1).toISOString();
  assert.throws(
    () => env.queue.pendingCount(),
    (error) => error.code === 'diagnostic_integrity_failed',
  );
});

test('stale diagnostics retain safe payload until an authenticated local retention purge', () => {
  const env = outbox(undefined, { eventMaxAgeMs: 1_000, tombstoneRetentionMs: 5_000 });
  env.queue.enqueue(diagnostic());
  env.clock.advance(1_001);
  assert.deepEqual(env.queue.leaseReady(), []);
  const row = [...env.storage.data.rows.values()][0];
  assert.equal(row.status, 'expired');
  assert.equal(typeof row.payloadJson, 'string');
  assert.equal(env.queue.pendingCount(), 0);
  assert.equal(env.storage.data.audits.at(-1).action, 'DIAGNOSTIC_EXPIRED');
  env.clock.advance(5_000);
  assert.equal(env.queue.pendingCount(), 0);
  assert.equal(env.storage.data.rows.size, 0);
  assert.equal(env.storage.data.audits.at(-1).action, 'DIAGNOSTIC_TOMBSTONE_PURGED');
});

test('failed delivery and lease-crash churn both reach a bounded dead letter', () => {
  const rejected = outbox(undefined, { maxAttempts: 2 });
  rejected.queue.enqueue(diagnostic());
  const first = rejected.queue.leaseReady()[0];
  const retry = rejected.queue.recordDelivery(deliveryReceipt(first, false));
  assert.equal(retry.terminal, false);
  rejected.clock.advance(RETRY_BASE_MS);
  const second = rejected.queue.leaseReady()[0];
  const terminal = rejected.queue.recordDelivery(deliveryReceipt(second, false));
  assert.equal(terminal.terminalStatus, 'dead_letter');
  assert.equal(typeof [...rejected.storage.data.rows.values()][0].payloadJson, 'string');

  const crashed = outbox(undefined, { maxAttempts: 2 });
  crashed.queue.enqueue(diagnostic());
  crashed.queue.leaseReady();
  crashed.clock.advance(5_000);
  crashed.queue.leaseReady();
  crashed.clock.advance(5_000);
  assert.deepEqual(crashed.queue.leaseReady(), []);
  const row = [...crashed.storage.data.rows.values()][0];
  assert.equal(row.status, 'dead_letter');
  assert.equal(row.attempts, 2);
});

test('bounded tombstone retention purges by authenticated CAS before admitting new work', () => {
  const env = outbox(undefined, {
    maxItems: 1,
    maxRecords: 1,
    tombstoneRetentionMs: 5_000,
  });
  const first = diagnostic();
  env.queue.enqueue(first);
  const lease = env.queue.leaseReady()[0];
  env.queue.recordDelivery(deliveryReceipt(lease, true));
  assert.throws(
    () => env.queue.enqueue(diagnostic()),
    (error) => error.code === 'diagnostic_history_full',
  );
  env.clock.advance(5_000);
  assert.equal(env.queue.enqueue({ ...first }).accepted, true);
  assert.equal(env.storage.data.rows.size, 1);
  assert.equal(env.storage.data.audits.some((entry) => entry.action === 'DIAGNOSTIC_TOMBSTONE_PURGED'), true);
});

test('delivery receipts are closed, bounded, and validated before lookup', () => {
  const env = outbox();
  const readsBefore = env.storage.data.readDiagnosticCalls;
  assert.throws(
    () => env.queue.recordDelivery({
      messageId: 'x'.repeat(2_000_000),
      payloadDigest: 'y'.repeat(2_000_000),
      leaseId: 'z'.repeat(2_000_000),
      accepted: true,
    }),
    (error) => error.code === 'diagnostic_delivery_invalid',
  );
  assert.equal(env.storage.data.readDiagnosticCalls, readsBefore);
  const hiddenField = {
    messageId: crypto.randomUUID(),
    payloadDigest: 'a'.repeat(64),
    leaseId: crypto.randomUUID(),
    accepted: true,
  };
  Object.defineProperty(hiddenField, 'detail', { value: 'canary_token_001' });
  assert.throws(
    () => env.queue.recordDelivery(hiddenField),
    (error) => error.code === 'diagnostic_delivery_invalid',
  );
  assert.equal(env.storage.data.readDiagnosticCalls, readsBefore);
  assert.throws(
    () => env.queue.recordDelivery({
      messageId: crypto.randomUUID(),
      payloadDigest: 'a'.repeat(64),
      leaseId: crypto.randomUUID(),
      accepted: true,
      nowMs: NOW,
    }),
    (error) => error.code === 'diagnostic_delivery_invalid',
  );

  env.clock.set(Number.MAX_SAFE_INTEGER);
  assert.throws(
    () => env.queue.pendingCount(),
    (error) => error.code === 'diagnostic_time_invalid'
      && error.name === 'Error' && !/Invalid time value/.test(error.message),
  );
});

test('a deleted leased row cannot turn a delivery receipt into a silent miss', () => {
  const env = outbox();
  const event = diagnostic();
  env.queue.enqueue(event);
  const lease = env.queue.leaseReady()[0];
  env.storage.data.rows.delete(rowKey(event));
  assert.throws(
    () => env.queue.recordDelivery(deliveryReceipt(lease, true)),
    (error) => error.code === 'diagnostic_audit_anchor_mismatch',
  );
});

test('delivered replay receipts require the exact authenticated lease identity', () => {
  const env = outbox();
  env.queue.enqueue(diagnostic());
  const lease = env.queue.leaseReady()[0];
  env.queue.recordDelivery(deliveryReceipt(lease, true));
  assert.equal(env.queue.recordDelivery(deliveryReceipt(lease, true)).duplicate, true);
  assert.throws(
    () => env.queue.recordDelivery({
      ...deliveryReceipt(lease, true), leaseId: crypto.randomUUID(),
    }),
    (error) => error.code === 'diagnostic_delivery_not_current',
  );
});

test('wrong integrity authority cannot release rows after restart', () => {
  const env = outbox();
  env.queue.enqueue(diagnostic());
  const restarted = outbox(env.storage, {
    clockControl: env.clock,
    integrityAuthority: createAuthority(Buffer.alloc(32, 0x33), 'other-key-v1'),
  }).queue;
  assert.throws(
    () => restarted.leaseReady(),
    (error) => error.code === 'diagnostic_integrity_failed',
  );
});

test('configuration requires a real integrity authority and exact storage transaction contract', () => {
  const storage = createStorage();
  assert.throws(
    () => createCustomerDiagnosticOutbox(null),
    (error) => error.code === 'diagnostic_configuration_invalid',
  );
  assert.throws(
    () => createCustomerDiagnosticOutbox({
      storage,
      customerId: CUSTOMER_ID,
      deploymentId: DEPLOYMENT_ID,
      clock: () => NOW,
    }),
    (error) => error.code === 'diagnostic_configuration_invalid',
  );
  const badAuthority = {
    sign: () => ({ keyId: 'bad-v1', mac: 'a'.repeat(64) }),
    verify: () => true,
  };
  assert.throws(
    () => createCustomerDiagnosticOutbox({
      storage,
      customerId: CUSTOMER_ID,
      deploymentId: DEPLOYMENT_ID,
      clock: () => NOW,
      integrityAuthority: badAuthority,
    }),
    (error) => error.code === 'diagnostic_configuration_invalid',
  );

  const stringClock = outbox(createStorage(), { clock: () => String(NOW) });
  assert.throws(
    () => stringClock.queue.enqueue(diagnostic()),
    (error) => error.code === 'diagnostic_time_invalid',
  );

  const stringCount = outbox();
  stringCount.storage.behavior.countAsString = true;
  assert.throws(
    () => stringCount.queue.enqueue(diagnostic()),
    (error) => error.code === 'diagnostic_integrity_failed',
  );
});

function hmac(key, message) {
  return crypto.createHmac('sha256', key).update(message, 'utf8').digest('hex');
}

function clone(value) {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}
