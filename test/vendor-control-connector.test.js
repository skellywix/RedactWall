'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  createVendorControlConnector,
  retryDelayMs,
} = require('../server/vendor-control-connector');
const protocol = require('../server/vendor-control-protocol');
const {
  installAuditTransactionProtocol,
  isAuditCommitUncertainError,
} = require('../server/storage');

const CUSTOMER_ID = 'customer_connector';
const DEPLOYMENT_ID = 'dep_0123456789abcdef0123456789abcdef';
const NOW = Date.parse('2026-07-12T12:00:00.000Z');

function snapshot(overrides = {}) {
  return {
    plan: 'standard',
    seatsUsed: 4,
    seatLimit: 10,
    version: '1.2.3',
    lastAppliedPolicyVersion: 2,
    lastAppliedCatalogVersion: 3,
    ...overrides,
  };
}

function acknowledgement(lifecycleStage) {
  return {
    schemaVersion: 1,
    messageId: lifecycleStage === 'delivered'
      ? '45389fce-c93e-41c0-94c6-6870c25835e4'
      : '55389fce-c93e-41c0-94c6-6870c25835e4',
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    kind: protocol.CHANNEL_KINDS.ACKNOWLEDGEMENT,
    targetKind: protocol.CHANNEL_KINDS.ENTITLEMENT,
    targetVersion: 1,
    targetDigest: 'a'.repeat(64),
    lifecycleStage,
    outcome: 'success',
    reasonCode: lifecycleStage,
    recordedAt: '2026-07-12T12:00:00.000Z',
  };
}

function harness(overrides = {}) {
  const events = [];
  let state = { entitlement: null, registry: null };
  let firstApply = true;
  let pendingStage = 'delivered';
  const store = {
    getState: () => state,
    applyHeartbeatResponse: (input) => {
      events.push(['apply', input]);
      const applied = firstApply;
      firstApply = false;
      state = {
        entitlement: {
          connectedEver: true,
          entitlementVersion: 1,
          lastContactAt: '2026-07-12T12:00:00.000Z',
        },
        registry: {
          connectedEver: true,
          registryGeneration: 9,
          lastContactAt: '2026-07-12T12:00:00.000Z',
        },
      };
      return { applied, contactAdvanced: applied };
    },
    entitlementVersion: () => state.entitlement?.entitlementVersion || 0,
    registryGeneration: () => state.registry?.registryGeneration || 0,
    recordFailure: (input) => { events.push(['failure', input]); return input; },
    acknowledgementHealth: () => ({ ok: true }),
    listPendingAcknowledgements: (input) => {
      events.push(['list', input]);
      if (!pendingStage) return [];
      const ack = acknowledgement(pendingStage);
      return [{
        id: `ack-${pendingStage}`,
        customerId: CUSTOMER_ID,
        deploymentId: DEPLOYMENT_ID,
        payloadDigest: pendingStage === 'delivered' ? 'b'.repeat(64) : 'c'.repeat(64),
        acknowledgement: ack,
      }];
    },
    recordAckResult: (input) => {
      events.push(['ack-result', input]);
      if (input.accepted) pendingStage = pendingStage === 'delivered' ? 'applied' : null;
      return input;
    },
    disposition: () => ({
      protectedEgress: 'allow', mode: 'connected', reason: null,
      authority: { plan: 'standard', seats: 10, features: [] },
      onlineRegistryGeneration: 9, onlineRegistryStateDigest: '9'.repeat(64),
    }),
    ...overrides.store,
  };
  const heartbeats = [];
  const client = {
    heartbeat: async (payload) => {
      heartbeats.push(payload);
      return {
        ok: true,
        requestMessageId: payload.messageId,
        signedOnlineRegistryVerdict: 'signed-registry-verdict',
        verifiedOnlineRegistryVerdict: { ignored: true },
        signedEntitlementArtifact: { keyId: 'current', payload: {}, signature: 'signed' },
        verifiedEntitlementArtifact: { ignored: true },
      };
    },
    acknowledge: async (payload) => {
      events.push(['ack-send', payload]);
      return { ok: true, accepted: true };
    },
    sendDiagnostic: async () => ({ ok: true }),
    sendShadowCandidate: async () => ({ ok: true }),
    close: async () => ({ ok: true }),
    ...overrides.client,
  };
  const connector = createVendorControlConnector({
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    client,
    store,
    safeSnapshot: overrides.safeSnapshot || (() => snapshot()),
    now: overrides.now || (() => NOW),
    randomUUID: overrides.randomUUID || (() => {
      let index = 0;
      const ids = [
        '1ae82809-8407-47b4-89b6-5e49bd3df74e',
        'bb64eaa9-7543-4be6-8887-2acb3cd095b0',
      ];
      return () => ids[index++] || ids[1];
    })(),
    randomBytes: overrides.randomBytes || (() => Buffer.alloc(24, 7)),
    random: overrides.random,
    offlineLicenseText: overrides.offlineLicenseText,
    setTimeout: overrides.setTimeout,
    clearTimeout: overrides.clearTimeout,
    diagnosticsEnabled: overrides.diagnosticsEnabled ?? true,
    shadowIntelligenceEnabled: overrides.shadowIntelligenceEnabled ?? true,
  });
  return { connector, events, heartbeats, store };
}

function commitUncertainError() {
  const driver = {
    transaction(callback) {
      return () => {
        callback();
        throw new Error('commit response lost');
      };
    },
  };
  const record = installAuditTransactionProtocol(driver, {
    prepareTransactionCommit() {},
    transactionCommitted() {},
    transactionCommitUncertain() {},
  });
  try { driver.transaction(() => record({ id: 'connected-composite' }))(); }
  catch (error) { return error; }
  throw new Error('commit uncertainty fixture did not fail');
}

test('synchronization atomically applies both raw artifacts and reports both high-waters', async () => {
  const env = harness();
  const result = await env.connector.synchronize();
  assert.deepEqual(result, {
    ok: true, applied: true, entitlementVersion: 1, registryGeneration: 9,
  });
  assert.equal(env.heartbeats.length, 2);
  assert.equal(env.heartbeats[0].lastAppliedEntitlementVersion, 0);
  assert.equal(env.heartbeats[0].lastAppliedRegistryGeneration, 0);
  assert.equal(env.heartbeats[1].lastAppliedEntitlementVersion, 1);
  assert.equal(env.heartbeats[1].lastAppliedRegistryGeneration, 9);
  assert.equal(env.events.filter(([kind]) => kind === 'apply').length, 2);
  assert.deepEqual(
    env.events.filter(([kind]) => kind === 'ack-send')
      .map(([, value]) => value.lifecycleStage),
    ['delivered', 'applied'],
  );
  assert.equal(env.connector.readiness().ok, true);
});

test('synchronization reports both high-waters from one combined state snapshot', async () => {
  let stateReads = 0;
  const env = harness({
    store: {
      getState: () => {
        stateReads += 1;
        return stateReads === 1
          ? { entitlement: null, registry: null }
          : {
            entitlement: { connectedEver: true, entitlementVersion: 7 },
            registry: { connectedEver: true, registryGeneration: 19 },
          };
      },
      applyHeartbeatResponse: () => ({ applied: false }),
      entitlementVersion: () => { throw new Error('split entitlement read'); },
      registryGeneration: () => { throw new Error('split registry read'); },
      listPendingAcknowledgements: () => [],
    },
  });

  assert.deepEqual(await env.connector.synchronize(), {
    ok: true, applied: false, entitlementVersion: 7, registryGeneration: 19,
  });
  assert.equal(stateReads, 3);
});

test('confirmation upgrades return final high-waters and drain each ordered ACK pair', async () => {
  let applyCount = 0;
  let state = { entitlement: null, registry: null };
  const pending = [];
  const ids = {
    '1-delivered': '15389fce-c93e-41c0-94c6-6870c25835e4',
    '1-applied': '25389fce-c93e-41c0-94c6-6870c25835e4',
    '2-delivered': '35389fce-c93e-41c0-94c6-6870c25835e4',
    '2-applied': '45389fce-c93e-41c0-94c6-6870c25835e4',
  };
  const queueVersion = (version) => {
    for (const lifecycleStage of ['delivered', 'applied']) {
      const payload = protocol.assertChannel({
        ...acknowledgement(lifecycleStage),
        messageId: ids[`${version}-${lifecycleStage}`],
        targetVersion: version,
        targetDigest: String(version).repeat(64),
      }, protocol.CHANNEL_KINDS.ACKNOWLEDGEMENT);
      pending.push({
        id: payload.messageId,
        customerId: CUSTOMER_ID,
        deploymentId: DEPLOYMENT_ID,
        payloadDigest: lifecycleStage === 'delivered'
          ? `${version}`.repeat(64) : `${version + 2}`.repeat(64),
        acknowledgement: payload,
        accepted: false,
      });
    }
  };
  const env = harness({
    store: {
      getState: () => state,
      applyHeartbeatResponse: () => {
        applyCount += 1;
        const version = applyCount;
        state = {
          entitlement: { connectedEver: true, entitlementVersion: version },
          registry: {
            connectedEver: true,
            registryGeneration: version === 1 ? 9 : 10,
            lastContactAt: '2026-07-12T12:00:00.000Z',
          },
        };
        queueVersion(version);
        return { applied: true };
      },
      entitlementVersion: () => state.entitlement?.entitlementVersion || 0,
      registryGeneration: () => state.registry?.registryGeneration || 0,
      listPendingAcknowledgements: () => pending.filter((item) => !item.accepted
        && (item.acknowledgement.lifecycleStage === 'delivered'
          || pending.some((candidate) => candidate.accepted
            && candidate.acknowledgement.targetVersion === item.acknowledgement.targetVersion
            && candidate.acknowledgement.lifecycleStage === 'delivered'))),
      recordAckResult: (input) => {
        const item = pending.find((candidate) => candidate.id === input.id);
        if (!item) return null;
        item.accepted = input.accepted;
        return input;
      },
    },
  });
  assert.deepEqual(await env.connector.synchronize(), {
    ok: true, applied: true, entitlementVersion: 2, registryGeneration: 10,
  });
  assert.deepEqual(env.events.filter(([kind]) => kind === 'ack-send')
    .map(([, value]) => [value.targetVersion, value.lifecycleStage]), [
    [1, 'delivered'], [1, 'applied'], [2, 'delivered'], [2, 'applied'],
  ]);
});

test('connector passes only raw signed fields into the composite transaction', async () => {
  const env = harness();
  await env.connector.synchronize();
  const input = env.events.find(([kind]) => kind === 'apply')[1];
  assert.equal(input.signedOnlineRegistryVerdict, 'signed-registry-verdict');
  assert.deepEqual(input.signedEntitlementArtifact, {
    keyId: 'current', payload: {}, signature: 'signed',
  });
  assert.equal(Object.hasOwn(input, 'verifiedOnlineRegistryVerdict'), false);
  assert.equal(Object.hasOwn(input, 'verifiedEntitlementArtifact'), false);
});

test('all client failure classes are persisted without accepting authority', async () => {
  for (const failureClass of protocol.FAILURE_CLASSES) {
    const env = harness({ client: { heartbeat: async () => ({ ok: false, failureClass }) } });
    assert.deepEqual(await env.connector.synchronize(), { ok: false, reason: failureClass });
    assert.equal(env.events.some(([kind]) => kind === 'apply'), false);
    assert.equal(env.events.find(([kind]) => kind === 'failure')[1].failureClass, failureClass);
  }
});

test('missing, uncorrelated, or malformed signed response fields fail closed', async () => {
  for (const response of [
    { ok: true },
    {
      ok: true, requestMessageId: 'e2a461b7-09c2-4e25-a8ad-b07c5d8d408b',
      signedOnlineRegistryVerdict: 'signed', signedEntitlementArtifact: null,
    },
    {
      ok: true, requestMessageId: '1ae82809-8407-47b4-89b6-5e49bd3df74e',
      signedOnlineRegistryVerdict: null, signedEntitlementArtifact: null,
    },
  ]) {
    const env = harness({ client: { heartbeat: async () => response } });
    assert.deepEqual(await env.connector.synchronize(), { ok: false, reason: 'invalid_schema' });
    assert.equal(env.events.find(([kind]) => kind === 'failure')[1].failureClass, 'invalid_schema');
  }
});

test('composite rejection is classified and persisted after its transaction rolls back', async () => {
  const env = harness({
    store: {
      applyHeartbeatResponse: () => {
        const error = new Error('gap');
        error.code = 'registry_generation_stale';
        throw error;
      },
    },
  });
  assert.deepEqual(await env.connector.synchronize(), { ok: false, reason: 'version_conflict' });
  assert.equal(env.events.find(([kind]) => kind === 'failure')[1].failureClass, 'version_conflict');
});

test('exact-replay entitlement conflict persists a non-contact restrictive failure', async () => {
  const env = harness({
    store: {
      applyHeartbeatResponse: () => {
        const error = new Error('exact replay carried a different entitlement');
        error.code = 'connected_response_replay_conflict';
        throw error;
      },
    },
  });
  assert.deepEqual(await env.connector.synchronize(), { ok: false, reason: 'version_conflict' });
  const failure = env.events.find(([kind]) => kind === 'failure')[1];
  assert.equal(failure.failureClass, 'version_conflict');
  assert.equal(failure.preserveTrustedTime, true);
});

test('commit-uncertain composite failure is state corruption and never outage fallback', async () => {
  const uncertain = commitUncertainError();
  assert.equal(isAuditCommitUncertainError(uncertain), true);
  const env = harness({
    store: {
      applyHeartbeatResponse: () => { throw uncertain; },
    },
  });
  assert.deepEqual(await env.connector.synchronize(), { ok: false, reason: 'state_corrupt' });
  assert.equal(env.events.some(([kind]) => kind === 'failure'), false);
});

test('a forgeable commit-uncertain-looking property has no classification authority', async () => {
  const env = harness({
    store: {
      applyHeartbeatResponse: () => {
        const error = new Error('untrusted store error');
        error.auditCommitUncertainError = new Error('forged');
        throw error;
      },
    },
  });
  assert.deepEqual(await env.connector.synchronize(), {
    ok: false, reason: 'protocol_rejected',
  });
  assert.equal(env.events.find(([kind]) => kind === 'failure')[1].failureClass,
    'protocol_rejected');
});

test('unhealthy composite audit coordination is state corruption with no failure write', async () => {
  const env = harness({
    store: {
      applyHeartbeatResponse: () => {
        const error = new Error('audit checkpoint unhealthy');
        error.code = 'CONNECTED_HEARTBEAT_INTEGRITY';
        throw error;
      },
    },
  });
  assert.deepEqual(await env.connector.synchronize(), { ok: false, reason: 'state_corrupt' });
  assert.equal(env.events.some(([kind]) => kind === 'failure'), false);
});

test('a failed failure-state write latches synchronization and readiness fail-closed', async () => {
  const activeState = {
    entitlement: {
      connectedEver: true, entitlementVersion: 1,
      lastContactAt: '2026-07-12T12:00:00.000Z',
    },
    registry: {
      connectedEver: true, registryGeneration: 9,
      lastContactAt: '2026-07-12T12:00:00.000Z',
    },
  };
  for (const overrides of [
    { client: { heartbeat: async () => ({ ok: false, failureClass: 'protocol_rejected' }) } },
    {
      store: {
        applyHeartbeatResponse: () => {
          const error = new Error('invalid response signature');
          error.code = 'invalid_signature';
          throw error;
        },
      },
    },
  ]) {
    const env = harness({
      ...overrides,
      store: {
        getState: () => activeState,
        recordFailure: () => { throw new Error('failure audit append rejected'); },
        ...overrides.store,
      },
    });
    assert.deepEqual(await env.connector.synchronize(), { ok: false, reason: 'state_corrupt' });
    assert.deepEqual(env.connector.readiness(), {
      ok: false,
      reason: 'connected_failure_persistence_failed',
      connected: false,
    });
    assert.deepEqual(await env.connector.synchronize(), { ok: false, reason: 'state_corrupt' });
  }
});

test('injected callbacks never receive the connector context as their receiver', async () => {
  const receivers = [];
  const scheduled = [];
  const capture = (name, value) => function callback(...args) {
    receivers.push([name, this]);
    return typeof value === 'function' ? value(...args) : value;
  };
  let uuidIndex = 0;
  const ids = [
    '1ae82809-8407-47b4-89b6-5e49bd3df74e',
    'bb64eaa9-7543-4be6-8887-2acb3cd095b0',
  ];
  const env = harness({
    safeSnapshot: capture('safeSnapshot', snapshot()),
    now: capture('now', NOW),
    randomUUID: capture('randomUUID', () => ids[uuidIndex++] || ids[1]),
    randomBytes: capture('randomBytes', Buffer.alloc(24, 7)),
    random: capture('random', 0.5),
    offlineLicenseText: capture('offlineLicenseText', null),
    setTimeout: capture('setTimeout', (callback) => {
      scheduled.push(callback);
      return scheduled.length;
    }),
    clearTimeout: capture('clearTimeout', undefined),
  });
  env.connector.start();
  await scheduled.shift()();
  env.connector.readiness();
  env.connector.stop();
  assert.deepEqual(new Set(receivers.map(([name]) => name)), new Set([
    'safeSnapshot', 'now', 'randomUUID', 'randomBytes', 'random',
    'offlineLicenseText', 'setTimeout', 'clearTimeout',
  ]));
  assert.equal(receivers.every(([, receiver]) => receiver === undefined), true);
});

test('heartbeat snapshot is an exact safe shape and identifiers are connector-generated', async () => {
  let calls = 0;
  const env = harness({
    safeSnapshot: () => snapshot({ prompt: '123-45-6789' }),
    client: { heartbeat: async () => { calls += 1; return { ok: false }; } },
  });
  await assert.rejects(() => env.connector.synchronize(), (error) => error.code === 'heartbeat_snapshot_invalid');
  assert.equal(calls, 0);
});

test('only one synchronization may run at a time', async () => {
  let release;
  const blocked = new Promise((resolve) => { release = resolve; });
  const env = harness({ client: { heartbeat: async () => blocked } });
  const first = env.connector.synchronize();
  assert.deepEqual(await env.connector.synchronize(), { ok: false, reason: 'synchronization_in_progress' });
  release({ ok: false, failureClass: 'transport_unavailable' });
  assert.deepEqual(await first, { ok: false, reason: 'transport_unavailable' });
});

test('stop cancels and drains an active synchronization without persisting an outage', async () => {
  let requestStarted;
  const started = new Promise((resolve) => { requestStarted = resolve; });
  let release;
  const blocked = new Promise((resolve) => { release = resolve; });
  let closes = 0;
  const env = harness({
    client: {
      heartbeat: async () => {
        requestStarted();
        return blocked;
      },
      close: async () => {
        closes += 1;
        release({ ok: false, failureClass: 'shutdown_cancelled' });
        return { ok: true };
      },
    },
  });

  const active = env.connector.synchronize();
  await started;
  assert.deepEqual(await env.connector.stop(), { ok: true });
  assert.deepEqual(await active, { ok: false, reason: 'connector_stopped' });
  assert.equal(closes, 1);
  assert.equal(env.events.some(([kind]) => kind === 'failure'), false);
  assert.equal(env.events.some(([kind]) => kind === 'list'), false);
  assert.deepEqual(await env.connector.synchronize(), { ok: false, reason: 'connector_stopped' });
});

test('stop during acknowledgement delivery preserves the exact queued ACK for restart', async () => {
  let acknowledgementStarted;
  const started = new Promise((resolve) => { acknowledgementStarted = resolve; });
  let release;
  const blocked = new Promise((resolve) => { release = resolve; });
  const env = harness({
    client: {
      acknowledge: async () => {
        acknowledgementStarted();
        return blocked;
      },
      close: async () => {
        release({ ok: false, failureClass: 'shutdown_cancelled' });
        return { ok: true };
      },
    },
  });

  const active = env.connector.synchronize();
  await started;
  assert.deepEqual(await env.connector.stop(), { ok: true });
  assert.deepEqual(await active, { ok: false, reason: 'connector_stopped' });
  assert.equal(env.events.some(([kind]) => kind === 'ack-result'), false);
  assert.equal(env.events.some(([kind]) => kind === 'failure'), false);
});

test('registry-only and restricted states remain unready', () => {
  const never = harness({
    store: { getState: () => ({ entitlement: null, registry: null }) },
  });
  assert.deepEqual(never.connector.readiness(), {
    ok: false, reason: 'connected_enrollment_required', connected: false,
  });
  const noEntitlement = harness({
    store: {
      getState: () => ({
        entitlement: null,
        registry: { connectedEver: true, registryGeneration: 4, lastContactAt: new Date(NOW).toISOString() },
      }),
    },
  });
  assert.equal(noEntitlement.connector.readiness().ok, false);
  assert.equal(noEntitlement.connector.readiness().reason, 'connected_entitlement_required');
  const restricted = harness({
    store: {
      getState: () => ({
        entitlement: { connectedEver: true, entitlementVersion: 4 },
        registry: { connectedEver: true, registryGeneration: 8, lastContactAt: new Date(NOW).toISOString() },
      }),
      disposition: () => ({ mode: 'revoked', reason: 'vendor_registry_revoked' }),
    },
  });
  assert.equal(restricted.connector.readiness().ok, false);
  assert.equal(restricted.connector.readiness().mode, 'revoked');
});

test('readiness converts disposition and offline-reader failures into fail-closed state', () => {
  const state = {
    entitlement: { connectedEver: true, entitlementVersion: 1 },
    registry: {
      connectedEver: true, registryGeneration: 9,
      lastContactAt: '2026-07-12T12:00:00.000Z',
    },
  };
  const dispositionFailure = harness({
    store: {
      getState: () => state,
      disposition: () => { throw new Error('state unavailable'); },
    },
  });
  assert.deepEqual(dispositionFailure.connector.readiness(), {
    ok: false, reason: 'connected_state_invalid', connected: false,
  });
  const offlineFailure = harness({
    store: { getState: () => state },
    offlineLicenseText: () => { throw new Error('offline read failed'); },
  });
  assert.deepEqual(offlineFailure.connector.readiness(), {
    ok: false, reason: 'connected_state_invalid', connected: false,
  });
});

test('ACK persistence failures latch readiness while later heartbeats can recover', async () => {
  const state = {
    entitlement: { connectedEver: true, entitlementVersion: 1 },
    registry: {
      connectedEver: true, registryGeneration: 9,
      lastContactAt: '2026-07-12T12:00:00.000Z',
    },
  };
  const item = {
    id: 'ack-delivered',
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    payloadDigest: 'b'.repeat(64),
    acknowledgement: acknowledgement('delivered'),
  };
  let pending = true;
  let failResult = true;
  let acknowledgements = 0;
  const env = harness({
    store: {
      getState: () => state,
      applyHeartbeatResponse: () => ({ applied: false }),
      entitlementVersion: () => 1,
      registryGeneration: () => 9,
      listPendingAcknowledgements: () => (pending ? [item] : []),
      recordAckResult: (input) => {
        if (failResult) {
          failResult = false;
          throw new Error('ACK audit append rejected');
        }
        pending = false;
        return input;
      },
    },
    client: {
      acknowledge: async () => { acknowledgements += 1; return { ok: true, accepted: true }; },
    },
  });
  assert.deepEqual(await env.connector.synchronize(), {
    ok: false, reason: 'connected_ack_persistence_failed',
  });
  assert.equal(env.connector.readiness().reason, 'connected_ack_persistence_failed');
  assert.deepEqual(await env.connector.synchronize(), {
    ok: true, applied: false, entitlementVersion: 1, registryGeneration: 9,
  });
  assert.equal(acknowledgements, 2);
  assert.equal(env.connector.readiness().ok, true);
});

test('pending ACK enumeration and null local completion fail readiness closed', async () => {
  for (const store of [
    {
      applyHeartbeatResponse: () => ({ applied: false }),
      listPendingAcknowledgements: () => { throw new Error('historical ACK anchor invalid'); },
    },
    {
      applyHeartbeatResponse: () => ({ applied: false }),
      listPendingAcknowledgements: () => [{
        id: 'ack-delivered',
        customerId: CUSTOMER_ID,
        deploymentId: DEPLOYMENT_ID,
        payloadDigest: 'b'.repeat(64),
        acknowledgement: acknowledgement('delivered'),
      }],
      recordAckResult: () => null,
    },
  ]) {
    const env = harness({ store });
    assert.deepEqual(await env.connector.synchronize(), {
      ok: false, reason: 'connected_ack_persistence_failed',
    });
    assert.equal(env.connector.readiness().reason, 'connected_ack_persistence_failed');
    assert.equal(env.events.some(([kind]) => kind === 'apply'), false);
  }
});

test('terminal ACK failures are persisted, stop redelivery, and do not block a later heartbeat apply', async () => {
  const state = {
    entitlement: { connectedEver: true, entitlementVersion: 1 },
    registry: {
      connectedEver: true, registryGeneration: 9,
      lastContactAt: '2026-07-12T12:00:00.000Z',
    },
  };
  const item = {
    id: 'ack-delivered',
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    payloadDigest: 'b'.repeat(64),
    acknowledgement: acknowledgement('delivered'),
  };
  for (const scenario of [
    { failureClass: 'authentication_rejected' },
    { failureClass: 'version_conflict' },
    { failureClass: 'protocol_rejected' },
    { failureClass: 'invalid_schema' },
    { failureClass: 'protocol_rejected', throws: true },
  ]) {
    let terminal = null;
    let ackSends = 0;
    let heartbeatApplies = 0;
    const recorded = [];
    const env = harness({
      store: {
        getState: () => state,
        applyHeartbeatResponse: () => {
          heartbeatApplies += 1;
          return { applied: false };
        },
        entitlementVersion: () => 1,
        registryGeneration: () => 9,
        acknowledgementHealth: () => (terminal
          ? { ok: false, failureClass: terminal.failureClass } : { ok: true }),
        listPendingAcknowledgements: () => (terminal ? [] : [item]),
        recordAckResult: (input) => {
          recorded.push(input);
          terminal = input;
          return input;
        },
      },
      client: {
        acknowledge: async () => {
          ackSends += 1;
          if (scenario.throws) throw new Error('local ACK response validation failed');
          return { ok: false, failureClass: scenario.failureClass };
        },
      },
    });
    assert.deepEqual(await env.connector.synchronize(), {
      ok: false,
      reason: 'connected_ack_terminal_failure',
      failureClass: scenario.failureClass,
    });
    assert.equal(recorded[0].accepted, false);
    assert.equal(recorded[0].failureClass, scenario.failureClass);
    assert.equal(heartbeatApplies, 1);
    assert.equal(ackSends, 1);
    assert.equal(env.connector.readiness().reason, 'connected_ack_terminal_failure');

    assert.deepEqual(await env.connector.synchronize(), {
      ok: false,
      reason: 'connected_ack_terminal_failure',
      failureClass: scenario.failureClass,
    });
    assert.equal(heartbeatApplies, 2);
    assert.equal(ackSends, 1);
  }
});

test('only retryable ACK failure classes remain queued without poisoning readiness', async () => {
  const state = {
    entitlement: { connectedEver: true, entitlementVersion: 1 },
    registry: {
      connectedEver: true, registryGeneration: 9,
      lastContactAt: '2026-07-12T12:00:00.000Z',
    },
  };
  const item = {
    id: 'ack-delivered',
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    payloadDigest: 'b'.repeat(64),
    acknowledgement: acknowledgement('delivered'),
  };
  for (const failureClass of [
    'transport_unavailable', 'transport_ambiguous', 'rate_limited',
  ]) {
    let pendingRead = 0;
    let recorded = null;
    const env = harness({
      store: {
        getState: () => state,
        applyHeartbeatResponse: () => ({ applied: false }),
        entitlementVersion: () => 1,
        registryGeneration: () => 9,
        listPendingAcknowledgements: () => (pendingRead++ === 0 ? [item] : []),
        recordAckResult: (input) => {
          recorded = input;
          return { ...input, status: 'pending' };
        },
      },
      client: {
        acknowledge: async () => ({ ok: false, failureClass }),
      },
    });
    assert.deepEqual(await env.connector.synchronize(), {
      ok: true,
      applied: false,
      entitlementVersion: 1,
      registryGeneration: 9,
    });
    assert.equal(recorded.accepted, false);
    assert.equal(recorded.failureClass, failureClass);
    assert.equal(env.connector.readiness().ok, true);
  }
});

test('capacity-blocked apply still drains authenticated backlog and retries the heartbeat', async () => {
  const state = {
    entitlement: { connectedEver: true, entitlementVersion: 1 },
    registry: {
      connectedEver: true, registryGeneration: 9,
      lastContactAt: '2026-07-12T12:00:00.000Z',
    },
  };
  const item = {
    id: 'ack-delivered',
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    payloadDigest: 'b'.repeat(64),
    acknowledgement: acknowledgement('delivered'),
  };
  let pending = true;
  let applyCalls = 0;
  let ackSends = 0;
  const env = harness({
    store: {
      getState: () => state,
      applyHeartbeatResponse: () => {
        applyCalls += 1;
        if (applyCalls === 1) {
          const error = new Error('connected ACK capacity reached');
          error.code = 'connected_ack_capacity';
          throw error;
        }
        return { applied: false };
      },
      entitlementVersion: () => 1,
      registryGeneration: () => 9,
      acknowledgementHealth: () => (pending ? {
        ok: false,
        reason: 'connected_ack_backlog',
        pendingCount: 1000,
      } : { ok: true }),
      listPendingAcknowledgements: () => (pending ? [item] : []),
      recordAckResult: (input) => {
        pending = false;
        return input;
      },
    },
    client: {
      acknowledge: async () => {
        ackSends += 1;
        return { ok: true, accepted: true };
      },
    },
  });
  assert.deepEqual(env.connector.readiness(), {
    ok: false,
    reason: 'connected_ack_backlog',
    pendingCount: 1000,
    connected: true,
  });
  assert.deepEqual(await env.connector.synchronize(), {
    ok: false,
    reason: 'connected_ack_capacity',
  });
  assert.equal(ackSends, 1);
  assert.equal(env.events.find(([kind]) => kind === 'failure')[1].failureClass,
    'protocol_rejected');
  assert.deepEqual(await env.connector.synchronize(), {
    ok: true,
    applied: false,
    entitlementVersion: 1,
    registryGeneration: 9,
  });
  assert.equal(applyCalls, 2);
  assert.equal(env.connector.readiness().ok, true);
});

test('diagnostics and candidates remain exact-scope typed channels', async () => {
  const env = harness();
  const diagnostic = {
    schemaVersion: 1,
    messageId: 'af7984df-2b52-4a45-836a-9b4d5d1889cb',
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    kind: protocol.CHANNEL_KINDS.DIAGNOSTIC,
    correlationId: '780cc8de-447e-4921-9868-0fec01c56ab8',
    component: 'connector', code: 'CONNECTOR_TIMEOUT', severity: 'warning',
    outcome: 'retrying', countBucket: '1', sizeBucket: 'none', durationBucket: '5-30s',
    retryState: 'scheduled', componentVersion: '1.2.3', occurredAt: '2026-07-12T12:00:00.000Z',
  };
  assert.deepEqual(await env.connector.sendDiagnostic(diagnostic), { ok: true });
  await assert.rejects(
    () => env.connector.sendDiagnostic({ ...diagnostic, customerId: 'customer_other' }),
    (error) => error.code === 'customer_mismatch',
  );
  await assert.rejects(
    () => env.connector.sendShadowCandidate(diagnostic),
    (error) => error.code === 'channel_kind_invalid',
  );
});

test('optional metadata channels require explicit independent customer consent', () => {
  const env = harness({ diagnosticsEnabled: false, shadowIntelligenceEnabled: false });
  const diagnostic = {
    schemaVersion: 1,
    messageId: 'af7984df-2b52-4a45-836a-9b4d5d1889cb',
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    kind: protocol.CHANNEL_KINDS.DIAGNOSTIC,
    correlationId: '780cc8de-447e-4921-9868-0fec01c56ab8',
    component: 'connector', code: 'CONNECTOR_TIMEOUT', severity: 'warning',
    outcome: 'retrying', countBucket: '1', sizeBucket: 'none', durationBucket: '5-30s',
    retryState: 'scheduled', componentVersion: '1.2.3', occurredAt: '2026-07-12T12:00:00.000Z',
  };
  assert.throws(
    () => env.connector.sendDiagnostic(diagnostic),
    (error) => error.code === 'diagnostic_consent_required',
  );
  assert.throws(
    () => env.connector.sendShadowCandidate({
      schemaVersion: 1,
      messageId: '02815769-c0ac-477e-856b-7585fbb9151d',
      customerId: CUSTOMER_ID,
      deploymentId: DEPLOYMENT_ID,
      kind: protocol.CHANNEL_KINDS.SHADOW_CANDIDATE,
      candidateId: '76aa038c-adb4-4cde-b5d7-aed3f6a008cc',
      registrableDomain: 'example.ai',
      sourceType: 'browser_destination', firstSeenDay: '2026-07-12',
      observationCountBucket: '1', confidenceBps: 8000,
      localClassification: 'unknown', localOutcome: 'observed',
    }),
    (error) => error.code === 'shadow_ai_consent_required',
  );
});

test('heartbeat and retry delays stay jittered and bounded', () => {
  const ctx = { heartbeatIntervalMs: 60_000, random: () => 0.5 };
  assert.equal(retryDelayMs(ctx, 0), 60_000);
  assert.equal(retryDelayMs(ctx, 1), 5_000);
  assert.equal(retryDelayMs(ctx, 8), 60_000);
});
