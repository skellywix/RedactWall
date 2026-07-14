'use strict';

const crypto = require('node:crypto');
const test = require('node:test');
const assert = require('node:assert/strict');
const protocol = require('../server/vendor-control-protocol');
const {
  CUSTOMER_POLICY_PACKAGE_BOUNDARY,
  MAX_OUTBOX_ATTEMPTS,
  OUTBOX_LEASE_MS,
  createPolicyOutboxWorker,
  openConnectedPolicyStore,
} = require('../server/connected-policy-store');

const NOW = Date.parse('2026-07-13T12:00:00.000Z');
const CUSTOMER_ID = 'cu-policy-store';
const DEPLOYMENT_ID = 'dep_11111111111111111111111111111111';
const INTEGRITY = Object.freeze({
  keyId: 'rw-policy-customer-integrity-v1',
  secret: Buffer.alloc(32, 0x75),
});

function openStore() {
  return openConnectedPolicyStore({
    driver: 'sqlite',
    path: ':memory:',
    integrityAuthority: INTEGRITY,
  });
}

function acknowledgement(messageId = crypto.randomUUID()) {
  return protocol.assertChannel({
    schemaVersion: protocol.PROTOCOL_VERSION,
    messageId,
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    kind: protocol.CHANNEL_KINDS.ACKNOWLEDGEMENT,
    targetKind: protocol.CHANNEL_KINDS.POLICY_DESIRED_STATE,
    targetVersion: 1,
    targetDigest: '1'.repeat(64),
    lifecycleStage: 'applied',
    outcome: 'success',
    reasonCode: 'applied',
    recordedAt: new Date(NOW).toISOString(),
  }, protocol.CHANNEL_KINDS.ACKNOWLEDGEMENT);
}

function validationReceipt(messageId = crypto.randomUUID()) {
  return {
    schemaVersion: 1,
    kind: 'policy.cached-validation-receipt.v1',
    messageId,
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    targetVersion: 1,
    targetDigest: '2'.repeat(64),
    deliveryDigest: '3'.repeat(64),
    lifecycleStage: 'cached',
    outcome: 'validated',
    candidateDigest: '4'.repeat(64),
    recordedAt: new Date(NOW).toISOString(),
  };
}

test('customer policy state and local override are independently MACed and CAS protected', () => {
  const store = openStore();
  try {
    const changed = store.setLocalOverride(CUSTOMER_ID, DEPLOYMENT_ID, 0, {
      expectedRevision: 0,
      override: { alwaysBlockAdd: ['CUSTOMER_LOCAL_SECRET'] },
      updatedAt: new Date(NOW).toISOString(),
    }, { nowMs: NOW });
    assert.equal(changed.revision, 1);
    assert.equal(changed.state.localOverrideRevision, 1);
    assert.deepEqual(store.load(CUSTOMER_ID, DEPLOYMENT_ID), changed);
    assert.throws(() => store.setLocalOverride(CUSTOMER_ID, DEPLOYMENT_ID, 0, {
      expectedRevision: 1,
      override: {},
      updatedAt: new Date(NOW + 1).toISOString(),
    }, { nowMs: NOW + 1 }), (error) => error.code === 'connected_policy_revision_conflict');

    store.database.prepare(
      "UPDATE connected_policy_override SET override_mac = ?",
    ).run('0'.repeat(64));
    assert.throws(
      () => store.load(CUSTOMER_ID, DEPLOYMENT_ID),
      (error) => error.code === 'connected_policy_override_invalid',
    );
  } finally {
    store.close();
  }
});

test('customer policy store rejects a legacy broad deployment id without persisting rows', () => {
  const store = openStore();
  try {
    assert.throws(() => store.setLocalOverride(
      CUSTOMER_ID,
      'deployment_policy_store',
      0,
      {
        expectedRevision: 0,
        override: { alwaysBlockAdd: ['CUSTOMER_LOCAL_SECRET'] },
        updatedAt: new Date(NOW).toISOString(),
      },
      { nowMs: NOW },
    ), (error) => error.code === 'connected_policy_scope_invalid');
    assert.throws(() => store.enqueue({
      ...acknowledgement(),
      deploymentId: 'deployment_policy_store',
    }, 'acknowledgement', new Date(NOW).toISOString()),
    (error) => error.code === 'channel_schema_invalid');
    for (const table of [
      'connected_policy_state', 'connected_policy_override', 'connected_policy_audit',
      'connected_policy_outbox',
    ]) {
      assert.equal(store.database.prepare(`SELECT COUNT(*) AS count FROM ${table}`).get().count, 0);
    }
  } finally {
    store.close();
  }
});

test('outbox uses strict separate receipt types, exact idempotency, leases, and crash recovery', async () => {
  const store = openStore();
  try {
    const ack = acknowledgement();
    const queued = store.enqueue(ack, 'acknowledgement', new Date(NOW).toISOString());
    assert.equal(queued.replay, false);
    assert.deepEqual(store.enqueue(ack, 'acknowledgement', new Date(NOW).toISOString()), {
      ...queued,
      replay: true,
    });
    assert.throws(() => store.enqueue({
      ...ack,
      outcome: 'rejected',
      reasonCode: 'internal_failure',
    }, 'acknowledgement', new Date(NOW).toISOString()),
    (error) => error.code === 'connected_policy_outbox_conflict');

    const receipt = validationReceipt();
    assert.equal(store.enqueue(
      receipt, 'validation_receipt', new Date(NOW).toISOString(),
    ).replay, false);
    assert.throws(() => store.enqueue({ ...validationReceipt(), prompt: 'forbidden' },
      'validation_receipt', new Date(NOW).toISOString()),
    (error) => error.code === 'connected_policy_outbox_invalid');
    assert.throws(() => store.enqueue(receipt, 'acknowledgement', new Date(NOW).toISOString()),
      (error) => error.code === 'channel_kind_invalid');

    const firstClaim = store.claimOutbox(1, new Date(NOW).toISOString())[0];
    assert.match(firstClaim.claimToken, /^[0-9a-f-]{36}$/i);
    const reclaimed = store.claimOutbox(
      1,
      new Date(NOW + OUTBOX_LEASE_MS + 1).toISOString(),
    )[0];
    assert.equal(reclaimed.messageId, firstClaim.messageId);
    assert.notEqual(reclaimed.claimToken, firstClaim.claimToken);
    assert.equal(store.markOutboxDelivered(
      firstClaim.messageId,
      firstClaim.documentDigest,
      new Date(NOW + OUTBOX_LEASE_MS + 2).toISOString(),
      firstClaim.claimToken,
    ), false);
    assert.equal(store.markOutboxDelivered(
      reclaimed.messageId,
      reclaimed.documentDigest,
      new Date(NOW + OUTBOX_LEASE_MS + 2).toISOString(),
      reclaimed.claimToken,
    ), true);
  } finally {
    store.close();
  }
});

test('outbox worker retries exact documents, requires bound receipts, and blocks readiness at cap', async () => {
  const store = openStore();
  let now = NOW;
  let attempts = 0;
  try {
    const ack = acknowledgement();
    store.enqueue(ack, 'acknowledgement', new Date(now).toISOString());
    const worker = createPolicyOutboxWorker({
      store,
      clock: () => now,
      async send(request) {
        attempts += 1;
        if (attempts === 1) {
          const error = new Error('offline');
          error.code = 'network_outage';
          throw error;
        }
        return {
          accepted: true,
          messageId: request.messageId,
          documentDigest: request.documentDigest,
        };
      },
    });
    assert.deepEqual(await worker.runOnce(), [{
      messageId: ack.messageId,
      status: 'retrying',
      reasonCode: 'network_outage',
    }]);
    now += 2_001;
    assert.deepEqual(await worker.runOnce(), [{ messageId: ack.messageId, status: 'delivered' }]);

    const blockedAck = acknowledgement();
    store.enqueue(blockedAck, 'acknowledgement', new Date(now).toISOString());
    store.database.prepare(`
      UPDATE connected_policy_outbox SET status = 'sending', attempts = ?,
        next_attempt_at = ?, claim_token = ? WHERE message_id = ?
    `).run(MAX_OUTBOX_ATTEMPTS, new Date(now).toISOString(), crypto.randomUUID(), blockedAck.messageId);
    assert.deepEqual(store.claimOutbox(1, new Date(now).toISOString()), []);
    const readiness = store.readiness(new Date(now).toISOString());
    assert.equal(readiness.ready, false);
    assert.equal(readiness.outboxBlocked, 1);
  } finally {
    store.close();
  }
});

test('customer package boundary excludes vendor authority and Postgres fails explicitly', () => {
  assert.equal(CUSTOMER_POLICY_PACKAGE_BOUNDARY.includes.includes('connected-policy-store'), true);
  assert.equal(CUSTOMER_POLICY_PACKAGE_BOUNDARY.includes.includes('deployment-identity'), true);
  assert.equal(CUSTOMER_POLICY_PACKAGE_BOUNDARY.excludes.includes('vendor-policy-authority'), true);
  assert.equal(CUSTOMER_POLICY_PACKAGE_BOUNDARY.excludes.includes('vendor signing private keys'), true);
  assert.throws(() => openConnectedPolicyStore({
    driver: 'postgres', integrityAuthority: INTEGRITY,
  }), (error) => error.code === 'connected_policy_postgres_adapter_not_implemented');
  assert.throws(() => openConnectedPolicyStore({
    driver: 'mysql', integrityAuthority: INTEGRITY,
  }), (error) => error.code === 'connected_policy_storage_driver_invalid');
});
