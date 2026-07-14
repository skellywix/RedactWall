'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const state = require('../server/connected-online-registry-state');

const CUSTOMER_ID = 'customer_alpha';
const DEPLOYMENT_ID = 'dep_0123456789abcdef0123456789abcdef';
const NOW = Date.parse('2026-07-12T12:00:00.000Z');
const KEY_ID = `rw-online-verdict-${'c'.repeat(64)}`;

function payload(overrides = {}) {
  return {
    kind: state.VERDICT_DOMAIN,
    status: 'active',
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    keyId: KEY_ID,
    issuedAt: '2026-07-12T12:00:00.000Z',
    registryGeneration: 7,
    registryStateDigest: 'a'.repeat(64),
    ...overrides,
  };
}

function verified(overrides = {}) {
  const candidate = payload(overrides.payload || {});
  return {
    payload: candidate,
    signedEnvelopeDigest: overrides.signedEnvelopeDigest || 'b'.repeat(64),
    signingKeyId: overrides.signingKeyId || KEY_ID,
    signingKeyFingerprint: overrides.signingKeyFingerprint || 'c'.repeat(64),
    signatureDomain: overrides.signatureDomain || state.VERDICT_DOMAIN,
  };
}

function apply(current, candidate = verified(), nowMs = NOW) {
  return state.applyVerifiedRegistryVerdict(current, candidate, { nowMs });
}

function expectCode(callback, code) {
  assert.throws(callback, (error) => error && error.code === code);
}

test('first verified verdict establishes a deployment-bound registry high-water', () => {
  const result = apply(state.initialState(CUSTOMER_ID, DEPLOYMENT_ID));
  assert.equal(result.idempotent, false);
  assert.equal(result.contactAdvanced, true);
  assert.equal(result.state.registryGeneration, 7);
  assert.equal(result.state.registryStateDigest, 'a'.repeat(64));
  assert.equal(result.state.status, 'active');
  assert.equal(result.state.signingKeyId, KEY_ID);
  assert.equal(result.auditAction, 'CONNECTED_REGISTRY_VERDICT_APPLIED');
  assert.equal(state.registryGenerationForHeartbeat(result.state), 7);
});

test('customer, deployment, signature metadata, time, and exact schema fail closed', () => {
  const initial = state.initialState(CUSTOMER_ID, DEPLOYMENT_ID);
  expectCode(() => apply(initial, verified({ payload: { customerId: 'customer_beta' } })),
    'registry_customer_mismatch');
  expectCode(() => apply(initial, verified({ payload: {
    deploymentId: 'dep_ffffffffffffffffffffffffffffffff',
  } })), 'registry_deployment_mismatch');
  expectCode(() => apply(initial, verified({ signingKeyId: 'rw-entitlement-2026' })),
    'registry_verification_invalid');
  expectCode(() => apply(initial, verified({ signatureDomain: 'redactwall.vendor-entitlement.v1' })),
    'registry_verification_invalid');
  expectCode(() => apply(initial, verified({ payload: { issuedAt: '2026-07-12T12:05:00.001Z' } })),
    'registry_clock_skew');
  expectCode(() => apply(initial, verified({ payload: { prompt: 'must never be accepted' } })),
    'registry_payload_invalid');
});

test('same-generation refresh uses stable state identity while exact replay is not fresh contact', () => {
  const first = apply(state.initialState(CUSTOMER_ID, DEPLOYMENT_ID)).state;
  const replay = apply(first);
  assert.equal(replay.idempotent, true);
  assert.equal(replay.contactAdvanced, false);
  assert.deepEqual(replay.state, first);

  const refreshed = apply(first, verified({
    payload: { issuedAt: '2026-07-12T12:00:01.000Z' },
    signedEnvelopeDigest: 'd'.repeat(64),
  }), NOW + 1000);
  assert.equal(refreshed.idempotent, true);
  assert.equal(refreshed.contactAdvanced, true);
  assert.equal(refreshed.state.registryGeneration, first.registryGeneration);
  assert.equal(refreshed.state.registryStateDigest, first.registryStateDigest);
  assert.equal(refreshed.state.signedEnvelopeDigest, 'd'.repeat(64));

  expectCode(() => apply(first, verified({ payload: {
    registryStateDigest: 'e'.repeat(64),
  } })), 'registry_generation_conflict');
  expectCode(() => apply(first, verified({ payload: { status: 'revoked' } })),
    'registry_generation_conflict');
  expectCode(() => apply(first, verified({
    signedEnvelopeDigest: 'f'.repeat(64),
  })), 'registry_generation_conflict');
});

test('lower generations reject and only a higher generation can change revoked state', () => {
  const first = apply(state.initialState(CUSTOMER_ID, DEPLOYMENT_ID)).state;
  expectCode(() => apply(first, verified({ payload: {
    registryGeneration: 6,
    registryStateDigest: '6'.repeat(64),
  } })), 'registry_generation_stale');
  const revoked = apply(first, verified({
    payload: {
      status: 'revoked', registryGeneration: 8,
      registryStateDigest: '8'.repeat(64), issuedAt: '2026-07-12T12:00:02.000Z',
    },
    signedEnvelopeDigest: '8'.repeat(64),
  }), NOW + 2000).state;
  assert.equal(revoked.status, 'revoked');
  expectCode(() => apply(revoked, verified({ payload: {
    registryGeneration: 8,
    registryStateDigest: '8'.repeat(64),
    issuedAt: '2026-07-12T12:00:03.000Z',
  }, signedEnvelopeDigest: '9'.repeat(64) }), NOW + 3000), 'registry_generation_conflict');
  const restored = apply(revoked, verified({
    payload: {
      registryGeneration: 9,
      registryStateDigest: '9'.repeat(64),
      issuedAt: '2026-07-12T12:00:04.000Z',
    },
    signedEnvelopeDigest: '0'.repeat(64),
  }), NOW + 4000);
  assert.equal(restored.state.status, 'active');
  assert.equal(restored.restored, true);
});

test('issued-time and trusted-time rollback cannot refresh or advance registry authority', () => {
  const first = apply(state.initialState(CUSTOMER_ID, DEPLOYMENT_ID)).state;
  expectCode(() => apply(first, verified({
    payload: { issuedAt: '2026-07-12T11:59:59.999Z' },
    signedEnvelopeDigest: '1'.repeat(64),
  })), 'registry_verdict_replay');
  expectCode(() => apply(first, verified({
    payload: {
      registryGeneration: 8,
      registryStateDigest: '8'.repeat(64),
      issuedAt: '2026-07-12T11:59:59.999Z',
    },
    signedEnvelopeDigest: '2'.repeat(64),
  })), 'registry_verdict_replay');
  expectCode(() => apply(first, verified({
    payload: { issuedAt: '2026-07-12T12:00:01.000Z' },
    signedEnvelopeDigest: '3'.repeat(64),
  }), first.trustedTimeMs - state.MAX_CLOCK_SKEW_MS - 1), 'registry_clock_rollback');
});

test('registry and entitlement combine by most restrictive valid authority', () => {
  const active = apply(state.initialState(CUSTOMER_ID, DEPLOYMENT_ID)).state;
  const allowed = state.combineConnectedDisposition(active, {
    protectedEgress: 'allow', mode: 'connected', reason: null,
    authority: { plan: 'enterprise', seats: 40, features: ['shadow-ai'] },
  });
  assert.equal(allowed.protectedEgress, 'allow');
  assert.equal(allowed.onlineRegistryGeneration, 7);

  const paused = state.combineConnectedDisposition(active, {
    protectedEgress: 'block', mode: 'paused', reason: 'vendor_paused', authority: null,
  });
  assert.deepEqual(paused, {
    protectedEgress: 'block', mode: 'paused', reason: 'vendor_paused', authority: null,
    onlineRegistryGeneration: 7, onlineRegistryStateDigest: 'a'.repeat(64),
  });

  const revoked = apply(active, verified({
    payload: {
      status: 'revoked', registryGeneration: 8,
      registryStateDigest: '8'.repeat(64), issuedAt: '2026-07-12T12:00:02.000Z',
    }, signedEnvelopeDigest: '8'.repeat(64),
  }), NOW + 2000).state;
  const registryBlocked = state.combineConnectedDisposition(revoked, {
    protectedEgress: 'allow', mode: 'connected', reason: null, authority: { seats: 40 },
  });
  assert.equal(registryBlocked.protectedEgress, 'block');
  assert.equal(registryBlocked.reason, 'vendor_registry_revoked');

  const missing = state.combineConnectedDisposition(
    state.initialState(CUSTOMER_ID, DEPLOYMENT_ID),
    { protectedEgress: 'allow', mode: 'connected', reason: null, authority: {} },
  );
  assert.equal(missing.reason, 'registry_enrollment_required');
  assert.equal(state.combineConnectedDisposition(
    { ...active, registryStateDigest: 'f'.repeat(64) },
    { protectedEgress: 'allow', mode: 'connected', reason: null, authority: {} },
  ).reason, 'registry_state_invalid');
  assert.equal(state.combineConnectedDisposition(active, {
    protectedEgress: 'allow', mode: 'connected', reason: null,
    authority: { plan: 'standard', seats: 1, features: [] },
    prompt: 'must not cross the disposition boundary',
  }).reason, 'entitlement_state_invalid');
});

test('restore rejects state tamper and heartbeat generation fails closed on corrupt state', () => {
  const accepted = apply(state.initialState(CUSTOMER_ID, DEPLOYMENT_ID)).state;
  assert.deepEqual(state.restoreState(JSON.parse(JSON.stringify(accepted)), {
    customerId: CUSTOMER_ID, deploymentId: DEPLOYMENT_ID,
  }), accepted);
  expectCode(() => state.restoreState({ ...accepted, registryGeneration: 6 }),
    'registry_state_high_water_invalid');
  expectCode(() => state.restoreState({ ...accepted, extra: true }), 'registry_state_unknown_field');
  expectCode(() => state.registryGenerationForHeartbeat({ ...accepted, status: 'revoked' }),
    'registry_state_high_water_invalid');
});
