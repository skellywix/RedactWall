'use strict';

const crypto = require('node:crypto');
const test = require('node:test');
const assert = require('node:assert/strict');
const stateEngine = require('../server/connected-entitlement-state');
const protocol = require('../server/vendor-control-protocol');

const CUSTOMER_ID = 'cu-state-1';
const DEPLOYMENT_ID = 'dep_11111111111111111111111111111111';
const SIBLING_DEPLOYMENT_ID = 'dep_22222222222222222222222222222222';
const OTHER_DEPLOYMENT_ID = 'dep_33333333333333333333333333333333';
const NOW = Date.parse('2026-07-12T12:01:00.000Z');
const KEY_ID = `rw-entitlement-${'3'.repeat(64)}`;
const offlineKeys = crypto.generateKeyPairSync('ed25519');
const OFFLINE_TRUST = Object.freeze({
  offlinePublicKey: () => offlineKeys.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
});

function entitlement(overrides = {}) {
  return {
    schemaVersion: 1,
    messageId: '87969bd6-d22c-4612-a024-ea3c02bea5ae',
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    status: 'active',
    kind: protocol.CHANNEL_KINDS.ENTITLEMENT,
    status: 'active',
    plan: 'enterprise',
    seats: 50,
    features: ['catalog', 'policy'],
    entitlementVersion: 1,
    previousVersion: 0,
    issuedAt: '2026-07-12T12:00:00.000Z',
    expiresAt: '2026-07-12T12:05:00.000Z',
    fallbackUntil: '2026-07-15T12:00:00.000Z',
    reasonCode: 'billing_active',
    ...overrides,
  };
}

function apply(first = entitlement(), nowMs = NOW) {
  return stateEngine.applyEntitlement(
    stateEngine.initialState(CUSTOMER_ID, DEPLOYMENT_ID),
    first,
    { nowMs, keyId: KEY_ID, randomUUID: () => '1545401b-acff-4bf1-af0f-83337cbe779e' },
  );
}

function offlineLicense(overrides = {}, signingKeys = offlineKeys) {
  const payload = {
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    status: 'active',
    plan: 'enterprise',
    seats: 80,
    features: ['catalog', 'extra'],
    expires: '2026-07-20T00:00:00.000Z',
    graceDays: 0,
    ...overrides,
  };
  const encoded = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64');
  const signature = crypto.sign(null, Buffer.from(encoded, 'utf8'), signingKeys.privateKey).toString('base64');
  return {
    text: `${encoded}.${signature}`,
    publicKeyPem: signingKeys.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  };
}

test('first signed entitlement establishes connected high-water and ACK only after apply', () => {
  const result = apply();
  assert.equal(result.state.connectedEver, true);
  assert.equal(result.state.entitlementVersion, 1);
  assert.equal(result.state.failureClass, null);
  assert.equal(result.acknowledgement.targetVersion, 1);
  assert.equal(result.acknowledgement.targetDigest, result.state.entitlementDigest);
  assert.equal(result.acknowledgement.lifecycleStage, 'applied');
  assert.deepEqual(result.auditActions, [
    'CONNECTED_ENTITLEMENT_APPLIED',
    'CONNECTED_ENTITLEMENT_ACK_QUEUED',
  ]);
});

test('deployment and customer binding are exact', () => {
  const state = stateEngine.initialState(CUSTOMER_ID, DEPLOYMENT_ID);
  assert.throws(
    () => stateEngine.applyEntitlement(state, entitlement({ customerId: 'cu-state-2' }), { nowMs: NOW, keyId: KEY_ID }),
    (error) => error.code === 'customer_mismatch',
  );
  assert.throws(
    () => stateEngine.applyEntitlement(state, entitlement({ deploymentId: SIBLING_DEPLOYMENT_ID }), { nowMs: NOW, keyId: KEY_ID }),
    (error) => error.code === 'deployment_mismatch',
  );
});

test('local connected state rejects every non-canonical deployment identity', () => {
  const invalidDeploymentIds = [
    ['legacy broad', 'deployment_state_001'],
    ['uppercase', `dep_${'A'.repeat(32)}`],
    ['null', null],
    ['missing', undefined],
  ];
  for (const [label, deploymentId] of invalidDeploymentIds) {
    assert.throws(
      () => stateEngine.initialState(CUSTOMER_ID, deploymentId),
      (error) => error.code === 'deployment_invalid',
      label,
    );
  }
});

test('same-version redelivery re-ACKs, while conflict and replay fail closed', () => {
  const first = apply();
  const duplicate = stateEngine.applyEntitlement(first.state, entitlement(), {
    nowMs: NOW + 1000,
    keyId: KEY_ID,
    randomUUID: () => '4bba2559-39c7-4bdc-bfab-4eac2484001a',
  });
  assert.equal(duplicate.idempotent, true);
  assert.equal(duplicate.acknowledgement.reasonCode, 'already_applied');
  assert.throws(
    () => stateEngine.applyEntitlement(first.state, entitlement({ seats: 49 }), { nowMs: NOW + 1000, keyId: KEY_ID }),
    (error) => error.code === 'version_conflict',
  );
  assert.throws(
    () => stateEngine.applyEntitlement(first.state, entitlement({ entitlementVersion: 0, previousVersion: 0 }), { nowMs: NOW + 1000, keyId: KEY_ID }),
    (error) => error.code === 'channel_schema_invalid',
  );
});

test('linked versions cannot skip a withheld pause or revoke release', () => {
  const first = apply();
  assert.throws(
    () => stateEngine.applyEntitlement(first.state, entitlement({
      entitlementVersion: 3,
      previousVersion: 2,
    }), { nowMs: NOW + 1000, keyId: KEY_ID }),
    (error) => error.code === 'version_gap',
  );
  assert.equal(first.state.entitlementVersion, 1);
});

test('pause and revoke latch above fallback until a newer authorized restore', () => {
  const first = apply();
  const paused = stateEngine.applyEntitlement(first.state, entitlement({
    status: 'paused', entitlementVersion: 2, previousVersion: 1,
    fallbackUntil: null, reasonCode: 'manual_pause',
  }), { nowMs: NOW + 1000, keyId: KEY_ID });
  assert.equal(stateEngine.disposition(paused.state, { nowMs: NOW + 2000 }).mode, 'paused');
  assert.equal(stateEngine.recordFailure(paused.state, 'transport_unavailable', { nowMs: NOW + 2000 }).failureClass, 'transport_unavailable');
  assert.equal(stateEngine.disposition(
    stateEngine.recordFailure(paused.state, 'transport_unavailable', { nowMs: NOW + 2000 }),
    { nowMs: NOW + 3000 },
  ).protectedEgress, 'block');

  assert.throws(
    () => stateEngine.applyEntitlement(paused.state, entitlement({
      entitlementVersion: 3, previousVersion: 2, reasonCode: 'billing_active',
    }), { nowMs: NOW + 3000, keyId: KEY_ID }),
    (error) => error.code === 'explicit_restriction_latched',
  );
  const restored = stateEngine.applyEntitlement(paused.state, entitlement({
    entitlementVersion: 3, previousVersion: 2, reasonCode: 'manual_restore',
  }), { nowMs: NOW + 3000, keyId: KEY_ID });
  assert.equal(stateEngine.disposition(restored.state, { nowMs: NOW + 4000 }).mode, 'connected');
});

test('a newly signed active offline artifact cannot clear a durable pause or revoke after restart', () => {
  const restrictions = [
    ['paused', 'manual_pause', 'vendor_paused'],
    ['revoked', 'manual_revoke', 'vendor_revoked'],
  ];
  for (const [status, reasonCode, dispositionReason] of restrictions) {
    const first = apply();
    const restricted = stateEngine.applyEntitlement(first.state, entitlement({
      messageId: crypto.randomUUID(),
      status,
      reasonCode,
      entitlementVersion: 2,
      previousVersion: 1,
      fallbackUntil: null,
    }), { nowMs: NOW + 1000, keyId: KEY_ID }).state;

    const restarted = stateEngine.restoreState(JSON.parse(JSON.stringify(restricted)), {
      customerId: CUSTOMER_ID,
      deploymentId: DEPLOYMENT_ID,
    });
    const outage = stateEngine.recordFailure(restarted, 'transport_unavailable', {
      nowMs: NOW + 2000,
    });
    const signedAfterRestriction = offlineLicense();
    const stillRestricted = stateEngine.disposition(outage, {
      nowMs: Date.parse('2026-07-13T12:00:00.000Z'),
      offlineLicenseText: signedAfterRestriction.text,
    }, OFFLINE_TRUST);
    assert.equal(stillRestricted.protectedEgress, 'block');
    assert.equal(stillRestricted.reason, dispositionReason);
    assert.equal(stillRestricted.mode, status);

    assert.throws(() => stateEngine.applyEntitlement(restarted, entitlement({
      messageId: crypto.randomUUID(),
      entitlementVersion: 3,
      previousVersion: 2,
      reasonCode: 'billing_active',
    }), { nowMs: NOW + 3000, keyId: KEY_ID }), (error) => (
      error.code === 'explicit_restriction_latched'
    ));
    const restored = stateEngine.applyEntitlement(restarted, entitlement({
      messageId: crypto.randomUUID(),
      entitlementVersion: 3,
      previousVersion: 2,
      reasonCode: 'manual_restore',
    }), { nowMs: NOW + 3000, keyId: KEY_ID }).state;
    assert.equal(stateEngine.disposition(restored, { nowMs: NOW + 4000 }).mode, 'connected');
  }
});

test('restriction ordering permits escalation but rejects revoked to paused after restart', () => {
  const first = apply();
  const revoked = stateEngine.applyEntitlement(first.state, entitlement({
    messageId: crypto.randomUUID(),
    status: 'revoked',
    reasonCode: 'manual_revoke',
    entitlementVersion: 2,
    previousVersion: 1,
    fallbackUntil: null,
  }), { nowMs: NOW + 1000, keyId: KEY_ID }).state;
  const restartedRevoked = stateEngine.restoreState(JSON.parse(JSON.stringify(revoked)), {
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
  });
  assert.throws(() => stateEngine.applyEntitlement(restartedRevoked, entitlement({
    messageId: crypto.randomUUID(),
    status: 'paused',
    reasonCode: 'manual_pause',
    entitlementVersion: 3,
    previousVersion: 2,
    fallbackUntil: null,
  }), { nowMs: NOW + 2000, keyId: KEY_ID }), (error) => (
    error.code === 'explicit_restriction_latched'
  ));

  const outage = stateEngine.recordFailure(restartedRevoked, 'transport_unavailable', {
    nowMs: NOW + 2000,
  });
  const signedAfterRestart = offlineLicense();
  const stillRevoked = stateEngine.disposition(outage, {
    nowMs: Date.parse('2026-07-13T12:00:00.000Z'),
    offlineLicenseText: signedAfterRestart.text,
  }, OFFLINE_TRUST);
  assert.equal(stillRevoked.mode, 'revoked');
  assert.equal(stillRevoked.reason, 'vendor_revoked');

  const manuallyRestored = stateEngine.applyEntitlement(restartedRevoked, entitlement({
    messageId: crypto.randomUUID(),
    reasonCode: 'manual_restore',
    entitlementVersion: 3,
    previousVersion: 2,
  }), { nowMs: NOW + 2000, keyId: KEY_ID }).state;
  assert.equal(stateEngine.disposition(manuallyRestored, { nowMs: NOW + 3000 }).mode, 'connected');

  const paused = stateEngine.applyEntitlement(first.state, entitlement({
    messageId: crypto.randomUUID(),
    status: 'paused',
    reasonCode: 'manual_pause',
    entitlementVersion: 2,
    previousVersion: 1,
    fallbackUntil: null,
  }), { nowMs: NOW + 1000, keyId: KEY_ID }).state;
  const escalated = stateEngine.applyEntitlement(paused, entitlement({
    messageId: crypto.randomUUID(),
    status: 'revoked',
    reasonCode: 'manual_revoke',
    entitlementVersion: 3,
    previousVersion: 2,
    fallbackUntil: null,
  }), { nowMs: NOW + 2000, keyId: KEY_ID }).state;
  assert.equal(stateEngine.disposition(escalated, { nowMs: NOW + 3000 }).mode, 'revoked');
});

test('every paused or revoked reason requires an explicit manual restore', () => {
  const restrictions = [
    ['paused', 'manual_pause'],
    ['paused', 'payment_past_due'],
    ['revoked', 'manual_revoke'],
    ['revoked', 'subscription_ended'],
    ['revoked', 'emergency_revoke'],
  ];
  for (const [status, reasonCode] of restrictions) {
    const first = apply();
    const restricted = stateEngine.applyEntitlement(first.state, entitlement({
      messageId: crypto.randomUUID(), status, reasonCode,
      entitlementVersion: 2, previousVersion: 1, fallbackUntil: null,
    }), { nowMs: NOW + 1000, keyId: KEY_ID }).state;
    for (const automaticReason of ['billing_active', 'trial_active']) {
      assert.throws(() => stateEngine.applyEntitlement(restricted, entitlement({
        messageId: crypto.randomUUID(), reasonCode: automaticReason,
        entitlementVersion: 3, previousVersion: 2,
      }), { nowMs: NOW + 2000, keyId: KEY_ID }), (error) => (
        error.code === 'explicit_restriction_latched'
      ));
    }
    assert.equal(stateEngine.applyEntitlement(restricted, entitlement({
      messageId: crypto.randomUUID(), reasonCode: 'manual_restore',
      entitlementVersion: 3, previousVersion: 2,
    }), { nowMs: NOW + 2000, keyId: KEY_ID }).state.entitlement.status, 'active');
  }
});

test('never-connected, invalid response, missing high-water, and clock rollback cannot fall back', () => {
  const never = stateEngine.initialState(CUSTOMER_ID, DEPLOYMENT_ID);
  assert.equal(stateEngine.disposition(never, { nowMs: NOW }).reason, 'connected_enrollment_required');

  const first = apply();
  const invalid = stateEngine.recordFailure(first.state, 'invalid_signature', { nowMs: NOW + 1000 });
  assert.equal(stateEngine.disposition(invalid, { nowMs: NOW + 2000 }).reason, 'fallback_failure_not_transport');

  const missing = { ...first.state, highWaterIntact: false };
  assert.equal(stateEngine.disposition(missing, { nowMs: NOW + 2000 }).reason, 'connected_state_invalid');

  const futureAnchor = { ...first.state, trustedTimeMs: NOW + 24 * 60 * 60 * 1000 };
  assert.equal(stateEngine.disposition(futureAnchor, { nowMs: NOW }).reason, 'clock_rollback');
});

test('monotonic elapsed time and boot identity bound fallback when wall time freezes', () => {
  const bootId = 'a'.repeat(32);
  const first = stateEngine.applyEntitlement(
    stateEngine.initialState(CUSTOMER_ID, DEPLOYMENT_ID),
    entitlement(),
    { nowMs: NOW, keyId: KEY_ID, clock: { bootId, nowMs: 1000 } },
  );
  const outage = stateEngine.recordFailure(first.state, 'transport_unavailable', { nowMs: NOW + 1000 });
  const offline = offlineLicense();
  assert.equal(stateEngine.disposition(outage, {
    nowMs: NOW + 6 * 60 * 1000,
    clock: { bootId, nowMs: 8 * 24 * 60 * 60 * 1000 },
    offlineLicenseText: offline.text,
  }, OFFLINE_TRUST).reason, 'fallback_expired_monotonic');
  assert.equal(stateEngine.disposition(outage, {
    nowMs: NOW + 6 * 60 * 1000,
    clock: { bootId: 'b'.repeat(32), nowMs: 2000 },
    offlineLicenseText: offline.text,
  }, OFFLINE_TRUST).reason, 'connected_boot_changed');
});

test('verified redelivery advances trusted wall and monotonic contact anchors', () => {
  const bootId = 'c'.repeat(32);
  const first = stateEngine.applyEntitlement(
    stateEngine.initialState(CUSTOMER_ID, DEPLOYMENT_ID),
    entitlement(),
    { nowMs: NOW, keyId: KEY_ID, clock: { bootId, nowMs: 1000 } },
  );
  const duplicate = stateEngine.applyEntitlement(first.state, entitlement(), {
    nowMs: NOW + 1000,
    keyId: KEY_ID,
    clock: { bootId, nowMs: 2000 },
  });
  assert.equal(duplicate.state.trustedTimeMs, NOW + 1000);
  assert.equal(duplicate.state.monotonicContactMs, 2000);
  assert.equal(stateEngine.disposition(duplicate.state, {
    nowMs: NOW + 1000,
    clock: { bootId, nowMs: 1999 },
  }).reason, 'monotonic_clock_rollback');
});

test('every client failure class is durable and only proven unavailability qualifies for fallback', () => {
  const first = apply();
  for (const failureClass of protocol.FAILURE_CLASSES) {
    const failed = stateEngine.recordFailure(first.state, failureClass, { nowMs: NOW + 1000 });
    assert.equal(failed.failureClass, failureClass);
    const result = stateEngine.disposition(failed, { nowMs: NOW + 2000 });
    if (failureClass === 'transport_unavailable') {
      assert.equal(result.reason, 'offline_fallback_unavailable');
    } else {
      assert.equal(result.reason, 'fallback_failure_not_transport');
    }
  }
});

test('genuine outage enters bounded degraded fallback and clamps offline authority', () => {
  const first = apply();
  const outage = stateEngine.recordFailure(first.state, 'transport_unavailable', { nowMs: NOW + 1000 });
  assert.equal(
    stateEngine.disposition(outage, { nowMs: Date.parse('2026-07-13T12:00:00.000Z') }).reason,
    'offline_fallback_unavailable',
  );
  const degraded = stateEngine.disposition(outage, {
    nowMs: Date.parse('2026-07-13T12:00:00.000Z'),
    offlineLicenseText: offlineLicense().text,
  }, OFFLINE_TRUST);
  assert.equal(degraded.mode, 'degraded_fallback');
  assert.deepEqual(degraded.authority, { plan: 'enterprise', seats: 50, features: ['catalog'] });

  const expired = stateEngine.disposition(outage, { nowMs: Date.parse('2026-07-15T12:00:00.001Z') });
  assert.equal(expired.protectedEgress, 'block');
  assert.equal(expired.reason, 'fallback_expired');
});

test('offline fallback rejects forged, expired, non-active, and cross-scope artifacts', () => {
  const outage = stateEngine.recordFailure(apply().state, 'transport_unavailable', { nowMs: NOW + 1000 });
  const at = Date.parse('2026-07-13T12:00:00.000Z');
  assert.equal(stateEngine.disposition(outage, { nowMs: at, offlineLicenseText: '' }, OFFLINE_TRUST).protectedEgress, 'block');
  assert.equal(stateEngine.disposition(outage, {
    nowMs: at,
    offlineLicenseText: offlineLicense({ expires: '2026-07-12T00:00:00.000Z' }).text,
  }, OFFLINE_TRUST).protectedEgress, 'block');
  assert.equal(stateEngine.disposition(outage, {
    nowMs: at,
    offlineLicenseText: offlineLicense({ deploymentId: SIBLING_DEPLOYMENT_ID }).text,
  }, OFFLINE_TRUST).protectedEgress, 'block');
  for (const deploymentId of [
    'deployment_state_001',
    `dep_${'A'.repeat(32)}`,
    null,
    undefined,
  ]) {
    assert.equal(stateEngine.disposition(outage, {
      nowMs: at,
      offlineLicenseText: offlineLicense({ deploymentId }).text,
    }, OFFLINE_TRUST).protectedEgress, 'block');
  }
  for (const status of [undefined, 'paused', 'revoked']) {
    assert.equal(stateEngine.disposition(outage, {
      nowMs: at,
      offlineLicenseText: offlineLicense({ status }).text,
    }, OFFLINE_TRUST).protectedEgress, 'block');
  }
  assert.equal(stateEngine.disposition(outage, {
    nowMs: at,
    offlineLicenseText: offlineLicense({ customerId: 'cu-state-2' }).text,
  }, OFFLINE_TRUST).protectedEgress, 'block');
  const forged = offlineLicense();
  const [payload, signature] = forged.text.split('.');
  forged.text = `${payload[0] === 'A' ? 'B' : 'A'}${payload.slice(1)}.${signature}`;
  assert.equal(stateEngine.disposition(outage, { nowMs: at, offlineLicenseText: forged.text }, OFFLINE_TRUST).protectedEgress, 'block');
  const attackerKeys = crypto.generateKeyPairSync('ed25519');
  const selfSigned = offlineLicense({}, attackerKeys);
  assert.equal(stateEngine.disposition(outage, {
    nowMs: at,
    offlineLicenseText: selfSigned.text,
    offlinePublicKey: () => selfSigned.publicKeyPem,
  }, OFFLINE_TRUST).protectedEgress, 'block');
});

test('offline authority can never expand the last connected plan, seats, or features', () => {
  const connected = entitlement({ plan: 'standard', seats: 20, features: ['catalog'] });
  assert.deepEqual(
    stateEngine.clampOfflineAuthority(connected, {
      plan: 'enterprise', seats: 200, features: ['catalog', 'policy', 'unbounded'],
    }),
    { plan: 'standard', seats: 20, features: ['catalog'] },
  );
  assert.deepEqual(
    stateEngine.clampOfflineAuthority(connected, { plan: 'standard', seats: 10, features: [] }),
    { plan: 'standard', seats: 10, features: [] },
  );
});

test('state restore rejects digest tamper, unknown fields, and cross-deployment reuse', () => {
  const first = apply();
  assert.throws(
    () => stateEngine.restoreState({ ...first.state, entitlementDigest: '0'.repeat(64) }),
    (error) => error.code === 'state_high_water_invalid',
  );
  assert.throws(
    () => stateEngine.restoreState({ ...first.state, prompt: 'must not be stored' }),
    (error) => error.code === 'state_unknown_field',
  );
  assert.throws(
    () => stateEngine.restoreState(first.state, { deploymentId: OTHER_DEPLOYMENT_ID }),
    (error) => error.code === 'deployment_mismatch',
  );
});
