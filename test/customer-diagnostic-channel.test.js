'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const protocol = require('../server/vendor-control-protocol');
const { CustomerDiagnosticChannel } = require('../server/customer-diagnostic-channel');

const CUSTOMER_ID = 'customer_alpha';
const DEPLOYMENT_ID = 'dep_88888888888888888888888888888888';
const SIBLING_DEPLOYMENT_ID = 'dep_99999999999999999999999999999999';

function diagnostic(overrides = {}) {
  return {
    schemaVersion: protocol.PROTOCOL_VERSION,
    messageId: crypto.randomUUID(),
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    kind: protocol.CHANNEL_KINDS.DIAGNOSTIC,
    correlationId: crypto.randomUUID(),
    component: 'connector',
    code: 'CONNECTOR_TIMEOUT',
    severity: 'warning',
    outcome: 'retrying',
    countBucket: '2-5',
    sizeBucket: '<1kb',
    durationBucket: '1-5s',
    retryState: 'scheduled',
    componentVersion: '1.2.3',
    occurredAt: '2026-07-12T12:00:00.000Z',
    ...overrides,
  };
}

function expectCode(fn, code) {
  assert.throws(fn, (error) => error && error.code === code);
}

test('queues only strictly allowlisted diagnostics for the configured silo', () => {
  const channel = new CustomerDiagnosticChannel({
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    maxItems: 2,
  });
  const event = diagnostic();
  const accepted = channel.accept(event);
  assert.equal(accepted.accepted, true);
  const snapshot = channel.snapshot();
  assert.equal(snapshot.capacity, 2);
  assert.equal(snapshot.size, 1);
  assert.deepEqual(snapshot.items[0].event, event);
  assert.equal(Object.isFrozen(snapshot.items[0].event), true);
  assert.equal(Object.isFrozen(snapshot.items), true);
});

test('rejects unknown fields and exact customer or deployment mismatches', () => {
  const channel = new CustomerDiagnosticChannel({ customerId: CUSTOMER_ID, deploymentId: DEPLOYMENT_ID });
  expectCode(() => channel.accept(diagnostic({ detail: 'free text is forbidden' })), 'diagnostic_schema_rejected');
  expectCode(() => channel.accept(diagnostic({ customerId: 'customer_beta' })), 'diagnostic_customer_mismatch');
  expectCode(() => channel.accept(diagnostic({ deploymentId: SIBLING_DEPLOYMENT_ID })), 'diagnostic_deployment_mismatch');
  assert.equal(channel.snapshot().size, 0);
});

test('rejects synthetic PII, secret, and canary markers without echoing them', () => {
  const samples = [
    { customerId: '123-45-6789' },
    { customerId: 'canary_token_001' },
    { customerId: 'secret_key' },
  ];
  for (const sample of samples) {
    const channel = new CustomerDiagnosticChannel({
      customerId: sample.customerId || CUSTOMER_ID,
      deploymentId: sample.deploymentId || DEPLOYMENT_ID,
    });
    assert.throws(() => channel.accept(diagnostic(sample)), (error) => {
      assert.equal(error.code, 'diagnostic_sensitive_metadata');
      for (const value of Object.values(sample)) assert.equal(error.message.includes(value), false);
      return true;
    });
    assert.equal(channel.snapshot().size, 0);
  }
});

test('does not classify opaque protocol UUIDs as payment-card metadata', () => {
  const channel = new CustomerDiagnosticChannel({ customerId: CUSTOMER_ID, deploymentId: DEPLOYMENT_ID });
  const event = diagnostic({
    messageId: '41111111-1111-4111-8111-111111111111',
    correlationId: '40000000-0000-4000-8000-000000000000',
  });
  assert.equal(channel.accept(event).accepted, true);
  assert.deepEqual(channel.snapshot().items[0].event, event);
});

test('is idempotent for exact replay and rejects message-id collisions', () => {
  const channel = new CustomerDiagnosticChannel({ customerId: CUSTOMER_ID, deploymentId: DEPLOYMENT_ID });
  const event = diagnostic();
  channel.accept(event);
  const replay = channel.accept({ ...event });
  assert.deepEqual(replay, {
    accepted: false,
    duplicate: true,
    digest: protocol.payloadDigest(event, protocol.CHANNEL_KINDS.DIAGNOSTIC),
  });
  expectCode(() => channel.accept({ ...event, severity: 'critical' }), 'diagnostic_idempotency_conflict');
  assert.equal(channel.snapshot().size, 1);
});

test('fails closed when the bounded queue is full', () => {
  const channel = new CustomerDiagnosticChannel({
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    maxItems: 1,
  });
  channel.accept(diagnostic());
  expectCode(() => channel.accept(diagnostic()), 'diagnostic_queue_full');
  assert.equal(channel.snapshot().size, 1);
});

test('delivery completion is exact, retry-safe, and frees bounded queue capacity', () => {
  const channel = new CustomerDiagnosticChannel({
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    maxItems: 1,
  });
  const first = diagnostic();
  const accepted = channel.accept(first);
  expectCode(
    () => channel.recordDelivery(first.messageId, '0'.repeat(64), true),
    'diagnostic_delivery_not_current',
  );
  assert.deepEqual(channel.recordDelivery(first.messageId, accepted.digest, false), {
    removed: false, duplicate: false,
  });
  assert.equal(channel.snapshot().size, 1);
  assert.deepEqual(channel.recordDelivery(first.messageId, accepted.digest, true), {
    removed: true, duplicate: false,
  });
  assert.deepEqual(channel.recordDelivery(first.messageId, accepted.digest, true), {
    removed: false, duplicate: true,
  });
  assert.equal(channel.accept(diagnostic()).accepted, true);
});

test('bounded in-memory history fails closed instead of forgetting replay tombstones', () => {
  const channel = new CustomerDiagnosticChannel({
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    maxItems: 1,
  });
  let first;
  let firstDigest;
  for (let index = 0; index < 256; index += 1) {
    const event = diagnostic();
    const accepted = channel.accept(event);
    if (index === 0) {
      first = event;
      firstDigest = accepted.digest;
    }
    channel.recordDelivery(event.messageId, accepted.digest, true);
  }
  expectCode(() => channel.accept(diagnostic()), 'diagnostic_history_full');
  assert.deepEqual(channel.accept({ ...first }), {
    accepted: false,
    duplicate: true,
    digest: firstDigest,
  });
});

test('rejects invalid queue limits', () => {
  for (const maxItems of [0, 1_001, 1.5, '10']) {
    expectCode(() => new CustomerDiagnosticChannel({
      customerId: CUSTOMER_ID,
      deploymentId: DEPLOYMENT_ID,
      maxItems,
    }), 'diagnostic_configuration_invalid');
  }
});
