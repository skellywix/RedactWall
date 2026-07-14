'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const onlineVerdict = require('../server/connected-online-verdict');
const {
  connectedLicenseMode,
  createConnectedLicenseRuntime,
  createConnectedLicenseRuntimeFromEnvironment,
} = require('../server/connected-license-runtime');

const CUSTOMER_ID = 'customer_runtime';
const DEPLOYMENT_ID = 'dep_0123456789abcdef0123456789abcdef';
const NOW = Date.parse('2026-07-13T15:00:00.000Z');
const EFFECTIVE_PAIR_DIGEST = 'd'.repeat(64);

function connectedState(overrides = {}) {
  return {
    entitlement: {
      connectedEver: true,
      entitlementVersion: 4,
      lastContactAt: '2026-07-13T14:59:00.000Z',
      entitlement: {
        status: 'active',
        plan: 'enterprise',
        seats: 7,
        features: ['ncua_readiness', 'policy_distribution'],
      },
    },
    registry: {
      connectedEver: true,
      registryGeneration: 9,
      lastContactAt: '2026-07-13T14:59:00.000Z',
    },
    acknowledgedAuthority: {
      acknowledged: {
        pairDigest: EFFECTIVE_PAIR_DIGEST,
        entitlementVersion: 4,
        registryGeneration: 9,
      },
    },
    ...overrides,
  };
}

function allowed(overrides = {}) {
  return {
    protectedEgress: 'allow',
    mode: 'connected',
    reason: null,
    fallbackDeadline: '2026-07-16T15:00:00.000Z',
    authority: {
      plan: 'enterprise',
      seats: 7,
      features: ['ncua_readiness', 'policy_distribution'],
    },
    onlineRegistryGeneration: 9,
    onlineRegistryStateDigest: 'a'.repeat(64),
    ...overrides,
  };
}

function harness(overrides = {}) {
  const calls = [];
  let disposition = overrides.disposition || allowed();
  let state = overrides.state || connectedState();
  const store = {
    getState: () => {
      calls.push('state');
      if (overrides.stateError) throw new Error('state corrupt');
      return state;
    },
    disposition: (_customerId, _deploymentId, input) => {
      calls.push(['disposition', input]);
      if (overrides.dispositionError) throw new Error('audit unavailable');
      return disposition;
    },
  };
  const connector = {
    start: () => { calls.push('start'); },
    stop: async () => { calls.push('stop'); return { ok: true }; },
    synchronize: async () => { calls.push('synchronize'); return { ok: true }; },
    readiness: () => ({ ok: true, connected: true, mode: 'connected' }),
    sendDiagnostic: async (value) => { calls.push(['diagnostic', value]); return { ok: true }; },
    sendShadowCandidate: async (value) => { calls.push(['shadow', value]); return { ok: true }; },
    ...overrides.connector,
  };
  const runtime = createConnectedLicenseRuntime({
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    store,
    connector,
    now: () => NOW,
    offlineLicenseText: () => 'offline-artifact',
    seatsUsed: () => 3,
    packageVersion: '2.4.6',
    policyVersion: () => 5,
    catalogVersion: () => 8,
  });
  return {
    runtime,
    calls,
    setDisposition: (value) => { disposition = value; },
    setState: (value) => { state = value; },
  };
}

test('runtime publishes sanitized signed authority and the exact prompt-free heartbeat snapshot', () => {
  const env = harness();
  assert.deepEqual(env.runtime.configurationHealth(), { ok: true, connected: true });
  assert.equal(env.runtime.featureEnabled('ncua_readiness'), true);
  assert.equal(env.runtime.featureEnabled('unpublished_feature'), false);
  assert.deepEqual(env.runtime.seatAuthority(), {
    configured: true, seatLimit: 7, source: 'connected_entitlement',
  });
  assert.deepEqual(env.runtime.safeHeartbeatSnapshot(), {
    plan: 'enterprise',
    seatsUsed: 3,
    seatLimit: 7,
    version: '2.4.6',
    lastAppliedPolicyVersion: 5,
    lastAppliedCatalogVersion: 8,
  });

  const status = env.runtime.publicStatus();
  assert.deepEqual(status, {
    state: 'active',
    connected: true,
    managedExternally: true,
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    plan: 'enterprise',
    seats: 7,
    features: ['ncua_readiness', 'policy_distribution'],
    entitlementVersion: 4,
    registryGeneration: 9,
    appliedEntitlementVersion: 4,
    appliedRegistryGeneration: 9,
    effectivePairDigest: EFFECTIVE_PAIR_DIGEST,
    lastContactAt: '2026-07-13T14:59:00.000Z',
    fallbackUntil: '2026-07-16T15:00:00.000Z',
    reason: null,
  });
  assert.equal(JSON.stringify(status).includes('offline-artifact'), false);
  assert.equal(JSON.stringify(status).includes('onlineRegistryStateDigest'), false);
});

test('every authorization performs a fresh combined read and corruption fails closed', () => {
  const env = harness();
  assert.equal(env.runtime.protectedEgressAllowed(), true);
  env.setDisposition({
    protectedEgress: 'block', mode: 'paused', reason: 'vendor_paused',
    authority: { plan: 'enterprise', seats: 7, features: ['ncua_readiness'] },
    onlineRegistryGeneration: 9,
    onlineRegistryStateDigest: 'b'.repeat(64),
  });
  assert.equal(env.runtime.protectedEgressAllowed(), false);
  assert.equal(env.runtime.ordinaryLicensedActionAllowed(), false);
  assert.equal(env.calls.filter((item) => Array.isArray(item) && item[0] === 'disposition').length, 3);

  const corrupt = harness({ dispositionError: true });
  assert.deepEqual(corrupt.runtime.disposition(), {
    protectedEgress: 'block',
    mode: 'blocked',
    reason: 'connected_state_invalid',
    authority: null,
  });
  assert.deepEqual(corrupt.runtime.seatAuthority(), {
    configured: true, seatLimit: 0, source: 'connected_entitlement',
  });
  assert.equal(corrupt.runtime.readiness().ok, false);
});

test('runtime rejects contradictory dispositions, unknown fields, and oversized authority', () => {
  const contradictory = harness({
    disposition: allowed({
      mode: 'revoked',
      fallbackDeadline: null,
      privateProjection: 'must-not-escape',
    }),
  });
  assert.deepEqual(contradictory.runtime.disposition(), {
    protectedEgress: 'block',
    mode: 'blocked',
    reason: 'connected_state_invalid',
    authority: null,
  });
  assert.equal(contradictory.runtime.protectedEgressAllowed(), false);

  const oversized = harness({
    disposition: allowed({
      authority: { plan: 'enterprise', seats: 1_000_001, features: [] },
    }),
  });
  assert.equal(oversized.runtime.protectedEgressAllowed(), false);

  const clean = harness({ disposition: allowed({ privateProjection: 'must-not-escape' }) });
  assert.deepEqual(clean.runtime.disposition(), {
    protectedEgress: 'allow',
    mode: 'connected',
    reason: null,
    fallbackDeadline: '2026-07-16T15:00:00.000Z',
    authority: {
      plan: 'enterprise',
      seats: 7,
      features: ['ncua_readiness', 'policy_distribution'],
    },
  });
});

test('effective fallback authority clamps feature, seat, and public status surfaces', () => {
  const env = harness({
    disposition: allowed({
      mode: 'degraded_fallback',
      reason: 'vendor_unreachable',
      authority: { plan: 'standard', seats: 2, features: ['ncua_readiness'] },
    }),
  });

  assert.equal(env.runtime.featureEnabled('policy_distribution'), false);
  assert.equal(env.runtime.featureEnabled('ncua_readiness'), true);
  assert.deepEqual(env.runtime.seatAuthority(), {
    configured: true, seatLimit: 2, source: 'connected_entitlement',
  });
  assert.deepEqual(env.runtime.publicStatus(), {
    state: 'degraded_fallback',
    connected: true,
    managedExternally: true,
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    plan: 'standard',
    seats: 2,
    features: ['ncua_readiness'],
    entitlementVersion: 4,
    registryGeneration: 9,
    appliedEntitlementVersion: 4,
    appliedRegistryGeneration: 9,
    effectivePairDigest: EFFECTIVE_PAIR_DIGEST,
    lastContactAt: '2026-07-13T14:59:00.000Z',
    fallbackUntil: '2026-07-16T15:00:00.000Z',
    reason: 'vendor_unreachable',
  });
});

test('write and protected-egress middleware fail closed with sanitized reasons', () => {
  const env = harness({
    disposition: {
      protectedEgress: 'block', mode: 'revoked', reason: 'vendor_registry_revoked',
      authority: null, onlineRegistryGeneration: 9,
      onlineRegistryStateDigest: 'c'.repeat(64),
    },
  });
  const responses = [];
  const res = {
    status(code) { responses.push(['status', code]); return this; },
    json(body) { responses.push(['json', body]); return this; },
  };
  let nextCalls = 0;
  env.runtime.requireWritable({ path: '/api/policy', method: 'POST' }, res, () => { nextCalls += 1; });
  env.runtime.requireProtectedEgress({}, res, () => { nextCalls += 1; });
  assert.equal(nextCalls, 0);
  assert.deepEqual(responses, [
    ['status', 403],
    ['json', { error: 'license_restricted', reason: 'vendor_registry_revoked' }],
    ['status', 403],
    ['json', { error: 'license_restricted', reason: 'vendor_registry_revoked' }],
  ]);
});

test('service readiness keeps DLP online for valid restrictions and rejects integrity failures', () => {
  const paused = harness({
    disposition: {
      protectedEgress: 'block', mode: 'paused', reason: 'vendor_paused',
      fallbackDeadline: '2026-07-16T15:00:00.000Z',
      authority: { plan: 'enterprise', seats: 7, features: ['ncua_readiness'] },
    },
  });
  assert.deepEqual(paused.runtime.serviceReadiness(), {
    ok: false,
    connected: true,
    mode: 'paused',
    reason: 'vendor_paused',
    serviceReady: true,
  });

  const expired = harness({
    disposition: {
      protectedEgress: 'block', mode: 'blocked', reason: 'fallback_expired',
      fallbackDeadline: '2026-07-13T14:00:00.000Z',
      authority: { plan: 'standard', seats: 2, features: [] },
    },
  });
  assert.equal(expired.runtime.serviceReadiness().serviceReady, true);

  const corrupt = harness({ dispositionError: true });
  assert.equal(corrupt.runtime.serviceReadiness().serviceReady, false);

  const neverEnrolled = harness({
    connector: {
      readiness: () => ({
        ok: false, connected: false, reason: 'connected_enrollment_required',
      }),
    },
  });
  assert.equal(neverEnrolled.runtime.serviceReadiness().serviceReady, false);
});

test('runtime delegates connector lifecycle and metadata channels without adding authority', async () => {
  const env = harness();
  assert.deepEqual(env.runtime.start(), { ok: true });
  assert.deepEqual(await env.runtime.synchronize(), { ok: true });
  assert.deepEqual(await env.runtime.sendDiagnostic({ safe: true }), { ok: true });
  assert.deepEqual(await env.runtime.sendShadowCandidate({ candidate: true }), { ok: true });
  assert.deepEqual(await env.runtime.stop(), { ok: true });
  assert.deepEqual(await env.runtime.stop(), { ok: true });
  assert.deepEqual(env.calls.filter((item) => ['start', 'stop', 'synchronize'].includes(item)), [
    'start', 'synchronize', 'stop',
  ]);
});

test('concurrent stop callers await and share the exact connector result', async () => {
  let release;
  const stopped = new Promise((resolve) => { release = resolve; });
  let stopCalls = 0;
  const env = harness({
    connector: {
      stop: () => {
        stopCalls += 1;
        return stopped;
      },
    },
  });
  const first = env.runtime.stop();
  const second = env.runtime.stop();
  let secondSettled = false;
  second.finally(() => { secondSettled = true; });
  await Promise.resolve();
  assert.equal(stopCalls, 1);
  assert.equal(secondSettled, false);
  const result = { ok: false, reason: 'connector_stop_failed' };
  release(result);
  assert.strictEqual(await first, result);
  assert.strictEqual(await second, result);
  assert.strictEqual(await env.runtime.stop(), result);
});

test('environment factory wires exact channel credentials and purpose-separated keyrings', () => {
  const offline = crypto.generateKeyPairSync('ed25519').publicKey;
  const verdict = crypto.generateKeyPairSync('ed25519').publicKey;
  const entitlement = crypto.generateKeyPairSync('ed25519').publicKey;
  const fingerprint = (key) => crypto.createHash('sha256')
    .update(key.export({ type: 'spki', format: 'der' })).digest('hex');
  const entitlementId = `rw-entitlement-${fingerprint(entitlement)}`;
  const env = {
    REDACTWALL_LICENSE_MODE: 'connected',
    REDACTWALL_LICENSE_SERVER_URL: 'https://license.vendor.example/',
    REDACTWALL_TENANT_ID: CUSTOMER_ID,
    REDACTWALL_CONNECTED_DEPLOYMENT_ID: DEPLOYMENT_ID,
    REDACTWALL_VENDOR_CONTROL_HEARTBEAT_TOKEN: 'runtime_heartbeat_0123456789abcdef01234567',
    REDACTWALL_VENDOR_CONTROL_ACKNOWLEDGEMENT_TOKEN: 'runtime_acknowledgement_0123456789abcdef0',
    REDACTWALL_VENDOR_CONTROL_DIAGNOSTICS_ENABLED: 'false',
    REDACTWALL_VENDOR_CONTROL_SHADOW_INTELLIGENCE_ENABLED: 'false',
    REDACTWALL_VENDOR_CONTROL_HEARTBEAT_INTERVAL_MS: '60000',
    REDACTWALL_VENDOR_CONTROL_TIMEOUT_MS: '8000',
    REDACTWALL_LICENSE_PUBLIC_KEY: offline.export({ type: 'spki', format: 'pem' }),
    REDACTWALL_LICENSE_VERDICT_PUBLIC_KEY: verdict.export({ type: 'spki', format: 'pem' }),
    REDACTWALL_ENTITLEMENT_PUBLIC_KEY: entitlement.export({ type: 'spki', format: 'pem' }),
    REDACTWALL_ENTITLEMENT_KEY_ID: entitlementId,
  };
  const state = connectedState();
  const db = {
    applyConnectedHeartbeatResponse() {},
    recordConnectedEntitlementFailure() {},
    connectedHeartbeatState: () => state,
    connectedLicensingDisposition: () => allowed(),
    pendingConnectedAcknowledgements: () => [],
    connectedAcknowledgementHealth: () => ({ ok: true }),
    recordConnectedAcknowledgementResult: () => ({}),
    seatStats: () => ({ seatsUsed: 2 }),
  };
  let clientConfig;
  let connectorConfig;
  const fakeConnector = {
    start() {}, stop: async () => ({ ok: true }), synchronize: async () => ({ ok: true }),
    readiness: () => ({ ok: true }), sendDiagnostic: async () => ({ ok: true }),
    sendShadowCandidate: async () => ({ ok: true }),
  };
  const runtime = createConnectedLicenseRuntimeFromEnvironment({
    env,
    db,
    packageVersion: '3.2.1',
    offlineLicenseText: () => 'signed-offline-fallback',
    clientFactory: (value) => {
      clientConfig = value;
      return { heartbeat() {}, acknowledge() {}, close() {} };
    },
    connectorFactory: (value) => {
      connectorConfig = value;
      return fakeConnector;
    },
  });

  assert.equal(connectedLicenseMode(env), true);
  assert.equal(connectedLicenseMode({ REDACTWALL_LICENSE_MODE: 'offline' }), false);
  assert.equal(clientConfig.baseUrl, env.REDACTWALL_LICENSE_SERVER_URL);
  assert.deepEqual(clientConfig.tokens, {
    heartbeat: env.REDACTWALL_VENDOR_CONTROL_HEARTBEAT_TOKEN,
    acknowledgement: env.REDACTWALL_VENDOR_CONTROL_ACKNOWLEDGEMENT_TOKEN,
  });
  assert.deepEqual([...clientConfig.onlineVerdictPublicKeys.keys()], [
    onlineVerdict.keyIdForPublicKey(verdict),
  ]);
  assert.deepEqual(Object.keys(clientConfig.entitlementPublicKeys), [entitlementId]);
  assert.equal(clientConfig.offlineKeyFingerprint, fingerprint(offline));
  assert.equal(clientConfig.timeoutMs, 8000);
  assert.equal(connectorConfig.heartbeatIntervalMs, '60000');
  assert.equal(connectorConfig.diagnosticsEnabled, false);
  assert.equal(connectorConfig.shadowIntelligenceEnabled, false);
  assert.deepEqual(connectorConfig.safeSnapshot(), {
    plan: 'enterprise', seatsUsed: 2, seatLimit: 7, version: '3.2.1',
    lastAppliedPolicyVersion: 0, lastAppliedCatalogVersion: 0,
  });
  assert.equal(runtime.publicStatus().customerId, CUSTOMER_ID);
});

test('environment heartbeat rejects malformed or out-of-range seat statistics without coercion', () => {
  const offline = crypto.generateKeyPairSync('ed25519').publicKey;
  const verdict = crypto.generateKeyPairSync('ed25519').publicKey;
  const entitlement = crypto.generateKeyPairSync('ed25519').publicKey;
  const fingerprint = (key) => crypto.createHash('sha256')
    .update(key.export({ type: 'spki', format: 'der' })).digest('hex');
  const env = {
    REDACTWALL_LICENSE_MODE: 'connected',
    REDACTWALL_LICENSE_SERVER_URL: 'https://license.vendor.example/',
    REDACTWALL_TENANT_ID: CUSTOMER_ID,
    REDACTWALL_CONNECTED_DEPLOYMENT_ID: DEPLOYMENT_ID,
    REDACTWALL_VENDOR_CONTROL_HEARTBEAT_TOKEN: 'runtime_heartbeat_0123456789abcdef01234567',
    REDACTWALL_VENDOR_CONTROL_ACKNOWLEDGEMENT_TOKEN: 'runtime_acknowledgement_0123456789abcdef0',
    REDACTWALL_VENDOR_CONTROL_DIAGNOSTICS_ENABLED: 'false',
    REDACTWALL_VENDOR_CONTROL_SHADOW_INTELLIGENCE_ENABLED: 'false',
    REDACTWALL_LICENSE_PUBLIC_KEY: offline.export({ type: 'spki', format: 'pem' }),
    REDACTWALL_LICENSE_VERDICT_PUBLIC_KEY: verdict.export({ type: 'spki', format: 'pem' }),
    REDACTWALL_ENTITLEMENT_PUBLIC_KEY: entitlement.export({ type: 'spki', format: 'pem' }),
    REDACTWALL_ENTITLEMENT_KEY_ID: `rw-entitlement-${fingerprint(entitlement)}`,
  };
  let seatStats = { seatsUsed: 0 };
  const db = {
    applyConnectedHeartbeatResponse() {},
    recordConnectedEntitlementFailure() {},
    connectedHeartbeatState: () => connectedState(),
    connectedLicensingDisposition: () => allowed(),
    pendingConnectedAcknowledgements: () => [],
    connectedAcknowledgementHealth: () => ({ ok: true }),
    recordConnectedAcknowledgementResult: () => ({}),
    seatStats: () => seatStats,
  };
  const runtime = createConnectedLicenseRuntimeFromEnvironment({
    env,
    db,
    packageVersion: '3.2.1',
    offlineLicenseText: () => 'signed-offline-fallback',
    clientFactory: () => ({ heartbeat() {}, acknowledge() {}, close() {} }),
    connectorFactory: () => ({
      start() {}, stop: async () => ({ ok: true }), synchronize: async () => ({ ok: true }),
      readiness: () => ({ ok: true }), sendDiagnostic: async () => ({ ok: true }),
      sendShadowCandidate: async () => ({ ok: true }),
    }),
  });

  assert.equal(runtime.safeHeartbeatSnapshot().seatsUsed, 0);
  for (const invalid of [
    { seatsUsed: '0' },
    { seatsUsed: 1_000_001 },
    {},
    null,
  ]) {
    seatStats = invalid;
    assert.throws(() => runtime.safeHeartbeatSnapshot(), /seat count is invalid/);
  }
});
