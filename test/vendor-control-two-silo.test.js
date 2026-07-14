'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const assert = require('node:assert/strict');

const ORIGINAL_NODE_ENV = process.env.NODE_ENV;
process.env.NODE_ENV = 'test';
test.after(() => {
  if (ORIGINAL_NODE_ENV === undefined) delete process.env.NODE_ENV;
  else process.env.NODE_ENV = ORIGINAL_NODE_ENV;
});

const Database = require('better-sqlite3');
const protocol = require('../server/vendor-control-protocol');
const policyState = require('../server/connected-policy-state');
const onlineVerdict = require('../server/connected-online-verdict');
const { MIGRATIONS } = require('../server/storage/migrations');
const { createConnectedEntitlementStore } = require('../server/connected-entitlement-store');
const { createConnectedOnlineRegistryStore } = require('../server/connected-online-registry-store');
const { createReferenceShadowAiCatalogState } = require('../server/shadow-ai-catalog-state');
const {
  createReferenceMonotonicAnchorAuthority,
  createReferenceMonotonicAnchorStorage,
} = require('../server/monotonic-anchor-authority');
const { CustomerDiagnosticChannel } = require('../server/customer-diagnostic-channel');
const {
  CustomerAuditSupportBroker,
  createReferenceAuditSummaryProvider,
  createReferenceLocalAuditAdminAuthorizer,
} = require('../server/customer-audit-support-broker');
const {
  createReferenceAuditAcknowledgementRegistry,
  createReferenceAuditAcknowledgementSigner,
} = require('../server/audit-support-acknowledgement');
const {
  REQUEST_SIGNATURE_DOMAIN,
  payloadDigest: auditSupportPayloadDigest,
  signAuditSupportRequest,
} = require('../server/audit-support-control-artifacts');
const {
  createCustomerAuditResponseKeyRegistry,
  createCustomerAuditResponseSigner,
  verifyCustomerAuditResponse,
} = require('../server/customer-audit-response');
const {
  createReferenceCustomerAuditIntegrityAuthority,
  createReferenceCustomerAuditWitnessAuthority,
  openCustomerAuditSupportSqlite,
} = require('../server/customer-audit-support-store');
const {
  AUTHORITY_DEFINITIONS,
  KEY_PURPOSES,
  createAuthorityRegistry,
  keyFingerprint,
} = require('../server/vendor-signed-artifact');

const NOW = Date.parse('2026-07-12T12:01:00.000Z');
const ZERO_HASH = '0'.repeat(64);
const SCOPE_A = Object.freeze({
  customerId: 'customer_alpha',
  deploymentId: 'dep_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
});
const SCOPE_B = Object.freeze({
  customerId: 'customer_beta',
  deploymentId: 'dep_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
});
const SCOPE_A_SIBLING = Object.freeze({
  customerId: SCOPE_A.customerId,
  deploymentId: 'dep_cccccccccccccccccccccccccccccccc',
});
const SCOPE_B_SIBLING = Object.freeze({
  customerId: SCOPE_B.customerId,
  deploymentId: 'dep_dddddddddddddddddddddddddddddddd',
});
const purposeKeys = Object.freeze({
  onlineVerdict: crypto.generateKeyPairSync('ed25519'),
  entitlement: crypto.generateKeyPairSync('ed25519'),
  catalogGlobal: crypto.generateKeyPairSync('ed25519'),
  catalogDistribution: crypto.generateKeyPairSync('ed25519'),
  policy: crypto.generateKeyPairSync('ed25519'),
  auditRequest: crypto.generateKeyPairSync('ed25519'),
  offlineCommercial: crypto.generateKeyPairSync('ed25519'),
});
const KEY_IDS = Object.freeze({
  onlineVerdict: onlineVerdict.keyIdForPublicKey(purposeKeys.onlineVerdict.publicKey),
  entitlement: `rw-entitlement-${keyFingerprint(purposeKeys.entitlement.publicKey)}`,
  catalogGlobal: 'rw-catalog-global-2026',
  catalogDistribution: 'rw-catalog-distribution-2026',
  policy: 'rw-policy-2026',
  auditRequest: 'rw-audit-request-2026',
});
const ACK_CYCLE = Object.freeze([
  'CONNECTED_ENTITLEMENT_APPLIED',
  'CONNECTED_ENTITLEMENT_ACK_QUEUED',
  'CONNECTED_ENTITLEMENT_ACK_QUEUED',
  'CONNECTED_ENTITLEMENT_ACK_LEDGER_UPDATED',
  'CONNECTED_ENTITLEMENT_ACKNOWLEDGED',
  'CONNECTED_ENTITLEMENT_ACK_LEDGER_UPDATED',
  'CONNECTED_ENTITLEMENT_ACKNOWLEDGED',
  'CONNECTED_ENTITLEMENT_ACK_LEDGER_UPDATED',
]);
const ACK_LEDGER_ACTION = 'CONNECTED_ENTITLEMENT_ACK_LEDGER_UPDATED';

test('commercial offline and connected vendor purpose keys are distinct', () => {
  const fingerprints = Object.values(purposeKeys).map((pair) => keyFingerprint(pair.publicKey));
  assert.equal(new Set(fingerprints).size, fingerprints.length);
  assert.equal(new Set(Object.values(KEY_IDS)).size, Object.keys(KEY_IDS).length);
  assert.equal(protocol.DEFAULT_FALLBACK_WINDOW_MS, 72 * 60 * 60 * 1000);
  assert.equal(protocol.MAX_FALLBACK_WINDOW_MS, 7 * 24 * 60 * 60 * 1000);
});

test('separate SQLite licensing authorities isolate restriction, fallback, and applied ACK completion', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-two-silo-'));
  const siloA = createEntitlementHarness(
    path.join(directory, 'alpha.sqlite'), SCOPE_A, purposeKeys.offlineCommercial, 11,
  );
  const siloB = createEntitlementHarness(
    path.join(directory, 'beta.sqlite'), SCOPE_B, purposeKeys.offlineCommercial, 29,
  );
  try {
    proveConnectedEntitlementIsolation(siloA, siloB);
  } finally {
    siloA.close();
    siloB.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('strict v2 online registry high-waters stay independent and combine restrictively', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-two-registry-'));
  const siloA = createEntitlementHarness(
    path.join(directory, 'alpha.sqlite'), SCOPE_A, purposeKeys.offlineCommercial, 41,
  );
  const siloB = createEntitlementHarness(
    path.join(directory, 'beta.sqlite'), SCOPE_B, purposeKeys.offlineCommercial, 61,
  );
  try {
    proveConnectedRegistryIsolation(siloA, siloB);
  } finally {
    siloA.close();
    siloB.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('Shadow AI and signed policy state remain silo-local under cross-bound delivery', () => {
  const shadowA = createShadowHarness(SCOPE_A, purposeKeys.offlineCommercial);
  const shadowB = createShadowHarness(SCOPE_B, purposeKeys.offlineCommercial);
  proveShadowIsolation(shadowA, shadowB);
  provePolicyIsolation();
});

test('diagnostic and governed audit-support channels reject cross-bound or sensitive residue', () => {
  proveDiagnosticIsolation();
  const events = proveAuditSupportIsolation();
  for (const event of events.flat()) assertSafeAuditEvent(event);
});

function proveConnectedEntitlementIsolation(siloA, siloB) {
  const firstA = applyEntitlement(siloA, entitlement(SCOPE_A, 1), NOW);
  const firstB = applyEntitlement(siloB, entitlement(SCOPE_B, 1), NOW);
  assert.equal(siloA.file === siloB.file, false);
  assertCrossBoundEntitlementRejected(siloA, siloB, firstA, firstB);
  acknowledge(siloA, firstA, NOW + 1_000);
  acknowledge(siloB, firstB, NOW + 1_000);

  siloB.store.recordFailure({ ...SCOPE_B, failureClass: 'transport_unavailable', nowMs: NOW + 2_000 });
  const stableB = siloB.store.getState(SCOPE_B.customerId, SCOPE_B.deploymentId);
  const stablePersistenceB = entitlementPersistence(siloB);
  proveRestrictionLifecycle(siloA, siloB, stableB);
  proveBoundedFallback(siloA, siloB);
  assert.deepEqual(siloB.store.getState(SCOPE_B.customerId, SCOPE_B.deploymentId), stableB);
  assert.deepEqual(entitlementPersistence(siloB), stablePersistenceB);
  assertHealthySilo(siloA);
  assertHealthySilo(siloB);
  assertAuditEvidence(siloA, [
    ...ACK_CYCLE,
    ...ACK_CYCLE,
    'CONNECTED_ENTITLEMENT_FAILURE_RECORDED',
    ...ACK_CYCLE,
    ...ACK_CYCLE,
    'CONNECTED_ENTITLEMENT_FAILURE_RECORDED',
  ], ['active', 'paused', 'revoked', 'active']);
  assertAuditEvidence(
    siloB,
    [...ACK_CYCLE, 'CONNECTED_ENTITLEMENT_FAILURE_RECORDED'],
    ['active'],
  );
  const bEntry = JSON.parse(siloB.db.prepare('SELECT entry FROM audit ORDER BY seq DESC LIMIT 1').pluck().get());
  const aEntry = JSON.parse(siloA.db.prepare('SELECT entry FROM audit ORDER BY seq DESC LIMIT 1').pluck().get());
  assert.equal(siloA.audit.verifyEntry(bEntry), false);
  assert.equal(siloB.audit.verifyEntry(aEntry), false);
}

function proveConnectedRegistryIsolation(siloA, siloB) {
  applyEntitlement(siloA, entitlement(SCOPE_A, 1), NOW);
  applyEntitlement(siloB, entitlement(SCOPE_B, 1), NOW);
  applyRegistryVerdict(siloA, registryVerdict(SCOPE_A, 7, 'active', NOW), NOW);
  applyRegistryVerdict(siloB, registryVerdict(SCOPE_B, 19, 'active', NOW), NOW);

  assert.notEqual(siloA.file, siloB.file);
  assert.equal(siloA.registryStore.registryGeneration(
    SCOPE_A.customerId, SCOPE_A.deploymentId,
  ), 7);
  assert.equal(siloB.registryStore.registryGeneration(
    SCOPE_B.customerId, SCOPE_B.deploymentId,
  ), 19);
  assert.equal(siloA.db.prepare(
    'SELECT COUNT(*) FROM connected_online_registry_state',
  ).pluck().get(), 1);
  assert.equal(siloB.db.prepare(
    'SELECT COUNT(*) FROM connected_online_registry_state',
  ).pluck().get(), 1);

  const stableA = clone(siloA.registryStore.getState(SCOPE_A.customerId, SCOPE_A.deploymentId));
  const stableB = clone(siloB.registryStore.getState(SCOPE_B.customerId, SCOPE_B.deploymentId));
  expectCode(() => applyRegistryVerdict(
    siloA, registryVerdict(SCOPE_B, 20, 'active', NOW + 100), NOW + 100,
  ), 'registry_customer_mismatch');
  expectCode(() => applyRegistryVerdict(
    siloA, registryVerdict(SCOPE_A_SIBLING, 8, 'active', NOW + 150), NOW + 150,
  ), 'registry_deployment_mismatch');
  expectCode(() => applyRegistryVerdict(
    siloA, registryVerdict(SCOPE_A, 6, 'active', NOW + 200), NOW + 200,
  ), 'registry_generation_stale');
  expectCode(() => applyRegistryVerdict(
    siloA, registryVerdict(SCOPE_A, 7, 'revoked', NOW + 300), NOW + 300,
  ), 'registry_generation_conflict');
  assert.deepEqual(
    siloA.registryStore.getState(SCOPE_A.customerId, SCOPE_A.deploymentId), stableA,
  );
  assert.deepEqual(
    siloB.registryStore.getState(SCOPE_B.customerId, SCOPE_B.deploymentId), stableB,
  );

  applyRegistryVerdict(siloA, registryVerdict(SCOPE_A, 8, 'revoked', NOW + 1_000), NOW + 1_000);
  assert.deepEqual(
    siloB.registryStore.getState(SCOPE_B.customerId, SCOPE_B.deploymentId), stableB,
  );
  const registryRestricted = siloA.registryStore.disposition(
    SCOPE_A.customerId,
    SCOPE_A.deploymentId,
    disposition(siloA, NOW + 1_100),
  );
  assert.equal(registryRestricted.protectedEgress, 'block');
  assert.equal(registryRestricted.reason, 'vendor_registry_revoked');

  applyEntitlement(siloB, entitlement(SCOPE_B, 2, {
    status: 'paused', reasonCode: 'manual_pause', fallbackUntil: null,
  }), NOW + 2_000);
  const entitlementRestricted = siloB.registryStore.disposition(
    SCOPE_B.customerId,
    SCOPE_B.deploymentId,
    disposition(siloB, NOW + 2_100),
  );
  assert.equal(entitlementRestricted.protectedEgress, 'block');
  assert.equal(entitlementRestricted.reason, 'vendor_paused');
  assert.equal(entitlementRestricted.onlineRegistryGeneration, 19);

  const heartbeatA = heartbeatFor(siloA, NOW + 2_500);
  const heartbeatB = heartbeatFor(siloB, NOW + 2_500);
  assert.deepEqual([
    heartbeatA.lastAppliedEntitlementVersion,
    heartbeatA.lastAppliedRegistryGeneration,
  ], [1, 8]);
  assert.deepEqual([
    heartbeatB.lastAppliedEntitlementVersion,
    heartbeatB.lastAppliedRegistryGeneration,
  ], [2, 19]);
  assert.notEqual(
    heartbeatA.lastAppliedEntitlementVersion,
    heartbeatA.lastAppliedRegistryGeneration,
  );
  assert.notEqual(
    heartbeatB.lastAppliedEntitlementVersion,
    heartbeatB.lastAppliedRegistryGeneration,
  );
  const combinedAudit = JSON.stringify([
    ...siloA.db.prepare('SELECT entry FROM audit ORDER BY seq').all(),
    ...siloB.db.prepare('SELECT entry FROM audit ORDER BY seq').all(),
  ]);
  assert.equal(combinedAudit.includes('prompt'), false);
  assert.equal(combinedAudit.includes('canary_token'), false);
  assert.equal(siloA.verifyAuditChain(), true);
  assert.equal(siloB.verifyAuditChain(), true);
  assert.equal(siloA.db.prepare('PRAGMA integrity_check').pluck().get(), 'ok');
  assert.equal(siloB.db.prepare('PRAGMA integrity_check').pluck().get(), 'ok');
}

function assertCrossBoundEntitlementRejected(siloA, siloB, firstA, firstB) {
  const beforeA = entitlementPersistence(siloA);
  const beforeB = entitlementPersistence(siloB);
  const artifactA = signed(entitlement(SCOPE_A, 2), 'entitlement');
  const artifactB = signed(entitlement(SCOPE_B, 2), 'entitlement');
  const siblingArtifact = signed(entitlement(SCOPE_A_SIBLING, 2), 'entitlement');
  expectCode(() => siloA.applyArtifact(artifactB, NOW + 400), 'customer_mismatch');
  expectCode(() => siloA.store.applyEntitlement({
    ...SCOPE_B,
    signedArtifact: artifactA,
    nowMs: NOW + 500,
    clock: siloA.clock(NOW + 500),
  }), 'customer_mismatch');
  expectCode(() => siloA.applyArtifact(siblingArtifact, NOW + 550), 'deployment_mismatch');
  expectCode(() => siloA.store.applyEntitlement({
    ...SCOPE_A_SIBLING,
    signedArtifact: artifactA,
    nowMs: NOW + 575,
    clock: siloA.clock(NOW + 575),
  }), 'deployment_mismatch');
  expectCode(() => siloA.applyArtifact(
    signed(entitlement(SCOPE_A, 2), 'catalogGlobal'), NOW + 600,
  ), 'unknown_signing_key');
  const overCap = entitlement(SCOPE_A, 2, {
    fallbackUntil: '2026-07-19T12:00:01.001Z',
  });
  expectCode(() => siloA.applyArtifact(unvalidatedSigned(overCap, 'entitlement'), NOW + 625),
    'channel_schema_invalid');
  expectCode(() => siloA.store.recordAckResult({
    id: firstA.outbox.id,
    ...SCOPE_B,
    payloadDigest: firstA.outbox.payloadDigest,
    accepted: true,
    nowMs: NOW + 750,
  }), 'customer_mismatch');
  expectCode(() => siloB.store.recordAckResult({
    id: firstB.outbox.id,
    ...SCOPE_A,
    payloadDigest: firstB.outbox.payloadDigest,
    accepted: true,
    nowMs: NOW + 750,
  }), 'customer_mismatch');
  expectCode(() => siloA.store.recordAckResult({
    id: firstA.outbox.id,
    ...SCOPE_A_SIBLING,
    payloadDigest: firstA.outbox.payloadDigest,
    accepted: true,
    nowMs: NOW + 750,
  }), 'deployment_mismatch');
  assert.equal(siloA.store.recordAckResult({
    id: firstB.outbox.id,
    ...SCOPE_A,
    payloadDigest: firstB.outbox.payloadDigest,
    accepted: true,
    nowMs: NOW + 750,
  }), null);
  assert.deepEqual(entitlementPersistence(siloA), beforeA);
  assert.deepEqual(entitlementPersistence(siloB), beforeB);
  assert.equal(pending(siloA, NOW + 750).length, 1);
  assert.equal(pending(siloB, NOW + 750).length, 1);
  assert.equal(firstA.state.customerId, SCOPE_A.customerId);
}

function entitlementPersistence(silo) {
  return {
    state: silo.db.prepare(`SELECT customer_id, deployment_id, authority_ref,
      entitlement_version, entitlement_digest, state_json, updated_at
      FROM connected_entitlement_state ORDER BY customer_id, deployment_id`).all(),
    outbox: silo.db.prepare(`SELECT id, customer_id, deployment_id, target_kind,
      target_version, target_digest, lifecycle_stage, payload_json, payload_digest,
      status, attempts, next_attempt_at, created_at, updated_at
      FROM connected_ack_outbox ORDER BY id`).all(),
    audit: silo.db.prepare('SELECT seq, action, entry FROM audit ORDER BY seq').all(),
  };
}

function proveRestrictionLifecycle(siloA, siloB, stableB) {
  const paused = applyEntitlement(siloA, entitlement(SCOPE_A, 2, {
    status: 'paused', reasonCode: 'manual_pause', fallbackUntil: null,
  }), NOW + 3_000);
  acknowledge(siloA, paused, NOW + 3_100);
  siloA.store.recordFailure({ ...SCOPE_A, failureClass: 'transport_unavailable', nowMs: NOW + 3_200 });
  assert.equal(disposition(siloA, NOW + 6 * 60_000).reason, 'vendor_paused');

  const revoked = applyEntitlement(siloA, entitlement(SCOPE_A, 3, {
    status: 'revoked', reasonCode: 'manual_revoke', fallbackUntil: null,
  }), NOW + 4_000);
  acknowledge(siloA, revoked, NOW + 4_100);
  assert.equal(disposition(siloA, NOW + 6 * 60_000).reason, 'vendor_revoked');
  assert.deepEqual(siloB.store.getState(SCOPE_B.customerId, SCOPE_B.deploymentId), stableB);

  const restored = applyEntitlement(siloA, entitlement(SCOPE_A, 4, {
    reasonCode: 'manual_restore',
  }), NOW + 5_000);
  acknowledge(siloA, restored, NOW + 5_100);
  assert.equal(disposition(siloA, NOW + 5_200).mode, 'connected');
}

function proveBoundedFallback(siloA, siloB) {
  const offlineA = offlineLicenseText(SCOPE_A, purposeKeys.offlineCommercial);
  const offlineB = offlineLicenseText(SCOPE_B, purposeKeys.offlineCommercial);
  const offlineSiblingB = offlineLicenseText(SCOPE_B_SIBLING, purposeKeys.offlineCommercial);
  assert.notEqual(offlineA, offlineB);
  const afterOnlineExpiry = Date.parse('2026-07-12T12:06:00.000Z');
  const stateB = siloB.store.getState(SCOPE_B.customerId, SCOPE_B.deploymentId);
  const fallbackDeadline = Date.parse(stateB.entitlement.fallbackUntil);
  assert.equal(fallbackDeadline - Date.parse(stateB.entitlement.issuedAt), protocol.DEFAULT_FALLBACK_WINDOW_MS);
  assert.equal(siloB.store.disposition(SCOPE_B.customerId, SCOPE_B.deploymentId, {
    nowMs: afterOnlineExpiry,
    clock: siloB.clock(afterOnlineExpiry),
    offlineLicenseText: offlineB,
  }).mode, 'degraded_fallback');
  assert.equal(siloB.store.disposition(SCOPE_B.customerId, SCOPE_B.deploymentId, {
    nowMs: afterOnlineExpiry,
    clock: siloB.clock(afterOnlineExpiry),
    offlineLicenseText: offlineA,
  }).reason, 'offline_fallback_unavailable');
  assert.equal(siloB.store.disposition(SCOPE_B.customerId, SCOPE_B.deploymentId, {
    nowMs: afterOnlineExpiry,
    clock: siloB.clock(afterOnlineExpiry),
    offlineLicenseText: offlineSiblingB,
  }).reason, 'offline_fallback_unavailable');
  assert.equal(siloB.store.disposition(SCOPE_B.customerId, SCOPE_B.deploymentId, {
    nowMs: fallbackDeadline,
    clock: siloB.clock(fallbackDeadline),
    offlineLicenseText: offlineB,
  }).mode, 'degraded_fallback');
  assert.equal(siloB.store.disposition(SCOPE_B.customerId, SCOPE_B.deploymentId, {
    nowMs: fallbackDeadline + 1,
    clock: siloB.clock(fallbackDeadline + 1),
    offlineLicenseText: offlineB,
  }).reason, 'fallback_expired');
  assert.equal(siloB.store.disposition(SCOPE_B.customerId, SCOPE_B.deploymentId, {
    nowMs: afterOnlineExpiry,
    clock: { ...siloB.clock(afterOnlineExpiry), nowMs: stateB.monotonicFallbackDeadlineMs + 1 },
    offlineLicenseText: offlineB,
  }).reason, 'fallback_expired_monotonic');
  assert.equal(siloB.store.disposition(SCOPE_B.customerId, SCOPE_B.deploymentId, {
    nowMs: afterOnlineExpiry,
    clock: { bootId: 'f'.repeat(32), nowMs: afterOnlineExpiry },
    offlineLicenseText: offlineB,
  }).reason, 'connected_boot_changed');
  const rolledBack = stateB.trustedTimeMs - (5 * 60_000) - 1;
  assert.equal(siloB.store.disposition(SCOPE_B.customerId, SCOPE_B.deploymentId, {
    nowMs: rolledBack,
    clock: siloB.clock(rolledBack),
    offlineLicenseText: offlineB,
  }).reason, 'clock_rollback');
  assert.throws(
    () => protocol.fallbackWindowMs(protocol.MAX_FALLBACK_WINDOW_MS + 1),
    RangeError,
  );
  assert.equal(disposition(siloA, NOW + 5_200).mode, 'connected');
  siloA.store.recordFailure({ ...SCOPE_A, failureClass: 'invalid_signature', nowMs: NOW + 6_000 });
  assert.equal(siloA.store.disposition(SCOPE_A.customerId, SCOPE_A.deploymentId, {
    nowMs: afterOnlineExpiry,
    clock: siloA.clock(afterOnlineExpiry),
    offlineLicenseText: offlineA,
  }).reason, 'fallback_failure_not_transport');
}

function assertHealthySilo(silo) {
  assert.equal(silo.verifyAuditChain(), true);
  assert.equal(pending(silo, Date.parse('2026-07-20T00:00:00.000Z')).length, 0);
  assert.equal(silo.db.prepare('PRAGMA integrity_check').pluck().get(), 'ok');
  const state = silo.store.getState(silo.scope.customerId, silo.scope.deploymentId);
  assert.equal(state.customerId, silo.scope.customerId);
  assert.equal(state.deploymentId, silo.scope.deploymentId);
  const outbox = acknowledgementEvidenceRows(silo);
  assert.equal(outbox.length, state.entitlementVersion * 2);
  assert.deepEqual(
    outbox.map((row) => row.lifecycle_stage),
    Array.from({ length: state.entitlementVersion }, () => ['delivered', 'applied']).flat(),
  );
  for (const row of outbox) {
    assert.equal(row.status, 'acknowledged');
    assert.equal(row.payload_digest, sha256(row.payload_json));
    const payload = protocol.assertChannel(JSON.parse(row.payload_json), protocol.CHANNEL_KINDS.ACKNOWLEDGEMENT);
    assert.equal(payload.customerId, row.customer_id);
    assert.equal(payload.deploymentId, row.deployment_id);
    assert.equal(payload.customerId, silo.scope.customerId);
    assert.equal(payload.deploymentId, silo.scope.deploymentId);
    assert.equal(payload.targetKind, row.target_kind);
    assert.equal(payload.targetVersion, Number(row.target_version));
    assert.equal(payload.targetDigest, row.target_digest);
    assert.equal(payload.lifecycleStage, row.lifecycle_stage);
  }
  assertAuditTamperRejected(silo);
  assert.equal(silo.store.getState(silo.scope.customerId, silo.scope.deploymentId).entitlementVersion,
    state.entitlementVersion);
}

function assertAuditEvidence(silo, expectedActions, expectedStatuses) {
  const rows = silo.db.prepare('SELECT seq, action, entry FROM audit ORDER BY seq').all();
  assert.deepEqual(rows.map((row) => row.action), expectedActions);
  const serialized = rows.map((row) => row.entry).join('\n');
  for (const forbidden of [silo.scope.customerId, silo.scope.deploymentId, 'prompt', 'canary_token']) {
    assert.equal(serialized.includes(forbidden), false);
  }
  const entries = rows.map((row) => JSON.parse(row.entry));
  const outbox = acknowledgementEvidenceRows(silo);
  const outboxByVersion = new Map();
  for (const row of outbox) {
    const version = Number(row.target_version);
    const pair = outboxByVersion.get(version) || {};
    pair[row.lifecycle_stage] = row;
    outboxByVersion.set(version, pair);
  }
  assert.deepEqual([...outboxByVersion.keys()], expectedStatuses.map((_, index) => index + 1));
  for (const pair of outboxByVersion.values()) assert.deepEqual(Object.keys(pair), ['delivered', 'applied']);
  for (const entry of entries) {
    if (entry.action.startsWith('CONNECTED_ENTITLEMENT_ACK_')
        && entry.action !== ACK_LEDGER_ACTION) {
      assert.match(entry.connectedAckRef, /^ack_[A-Za-z0-9_-]{24}$/);
    } else {
      assert.match(entry.connectedAuthorityRef, /^connected_[A-Za-z0-9_-]{24}$/);
    }
  }
  const applied = entries.filter((entry) => entry.action === 'CONNECTED_ENTITLEMENT_APPLIED');
  assert.equal(applied.length, expectedStatuses.length);
  assert.deepEqual(
    applied.map((entry) => JSON.parse(entry.detail).entitlementVersion),
    expectedStatuses.map((_, index) => index + 1),
  );
  const ledgerEntries = entries.filter(
    (entry) => entry.action === ACK_LEDGER_ACTION,
  ).map((entry) => JSON.parse(entry.detail));
  assert.equal(ledgerEntries.at(-1).archivedCount, Math.max(0, expectedStatuses.length - 1) * 2);
  assert.equal(ledgerEntries.every((detail, index) => (
    index === 0 || detail.archivedCount >= ledgerEntries[index - 1].archivedCount
  )), true);
  for (let index = 0; index < applied.length; index += 1) {
    const entry = applied[index];
    const detail = JSON.parse(entry.detail);
    const ack = outboxByVersion.get(detail.entitlementVersion)?.applied;
    assert.ok(ack);
    assert.equal(detail.signingKeyId, KEY_IDS.entitlement);
    assert.equal(detail.digest, ack.target_digest);
    assert.equal(detail.status, expectedStatuses[index]);
    assert.equal(entry.connectedAuthorityRef, silo.authorityReference());
  }
  assertAckAuditBindings(silo, entries, outboxByVersion);
  assertPerVersionAuditLifecycle(entries, outboxByVersion);
}

function acknowledgementEvidenceRows(silo) {
  const columns = `id, customer_id, deployment_id, target_kind, target_version,
    target_digest, lifecycle_stage, payload_json, payload_digest, status`;
  const rows = [
    ...silo.db.prepare(`SELECT ${columns} FROM connected_ack_archive`).all(),
    ...silo.db.prepare(`SELECT ${columns} FROM connected_ack_outbox`).all(),
  ];
  rows.sort((left, right) => Number(left.target_version) - Number(right.target_version)
    || (left.lifecycle_stage === right.lifecycle_stage
      ? left.id.localeCompare(right.id)
      : (left.lifecycle_stage === 'delivered' ? -1 : 1)));
  assert.equal(new Set(rows.map((row) => row.id)).size, rows.length);
  return rows;
}

function assertPerVersionAuditLifecycle(entries, outboxByVersion) {
  for (const version of outboxByVersion.keys()) {
    const actions = entries.filter((entry) => {
      if (!entry.action.startsWith('CONNECTED_ENTITLEMENT_')) return false;
      if (entry.action === 'CONNECTED_ENTITLEMENT_FAILURE_RECORDED') return false;
      return JSON.parse(entry.detail).entitlementVersion === version;
    }).map((entry) => entry.action);
    assert.deepEqual(actions, ACK_CYCLE);
  }
}

function assertAckAuditBindings(silo, entries, outboxByVersion) {
  const ackEntries = entries.filter((entry) => (
    entry.action.startsWith('CONNECTED_ENTITLEMENT_ACK_')
    && entry.action !== ACK_LEDGER_ACTION
  ));
  for (const entry of ackEntries) {
    const detail = JSON.parse(entry.detail);
    const pair = outboxByVersion.get(detail.entitlementVersion);
    const ack = pair && Object.values(pair).find(
      (row) => silo.ackReference(row.id) === entry.connectedAckRef,
    );
    assert.ok(ack);
    const ackRef = silo.ackReference(ack.id);
    assert.equal(entry.connectedAckRef, ackRef);
    assert.equal(detail.ackRef, ackRef);
    assert.equal(detail.digest, ack.target_digest);
    assert.equal(detail.payloadDigest, ack.payload_digest);
    assert.equal(ack.target_kind, protocol.CHANNEL_KINDS.ENTITLEMENT);
    const expectedStatus = entry.action === 'CONNECTED_ENTITLEMENT_ACK_QUEUED'
      ? 'pending' : 'acknowledged';
    assert.equal(detail.status, expectedStatus);
  }
}

function assertAuditTamperRejected(silo) {
  const rows = silo.db.prepare('SELECT seq, action, entry FROM audit ORDER BY seq').all();
  const row = rows[rows.length - 1];
  const mutations = [
    (entry) => { entry.mac = ZERO_HASH; },
    (entry) => { entry.hash = ZERO_HASH; },
    (entry) => { entry.sequence += 1; },
    (entry) => { entry.previousHash = ZERO_HASH; },
  ];
  for (const mutate of mutations) {
    const tampered = JSON.parse(row.entry);
    mutate(tampered);
    silo.db.prepare('UPDATE audit SET entry = ? WHERE seq = ?').run(JSON.stringify(tampered), row.seq);
    assert.equal(silo.verifyAuditChain(), false);
    silo.db.prepare('UPDATE audit SET entry = ? WHERE seq = ?').run(row.entry, row.seq);
  }
  silo.db.prepare('DELETE FROM audit WHERE seq = ?').run(row.seq);
  assert.equal(silo.verifyAuditChain(), false);
  restoreAuditRows(silo.db, [row]);
  silo.db.prepare('DELETE FROM audit').run();
  assert.equal(silo.verifyAuditChain(), false);
  restoreAuditRows(silo.db, rows);
  assert.equal(silo.verifyAuditChain(), true);
}

function restoreAuditRows(db, rows) {
  const insert = db.prepare('INSERT INTO audit (seq, action, entry) VALUES (?, ?, ?)');
  for (const row of rows) insert.run(row.seq, row.action, row.entry);
}

function createEntitlementHarness(file, scope, offlineKeys, keyByte) {
  const db = new Database(file);
  const auditKey = Buffer.alloc(32, keyByte);
  const referenceKey = Buffer.alloc(32, keyByte + 1);
  db.pragma('foreign_keys = ON');
  db.exec('CREATE TABLE audit (seq INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL, entry TEXT NOT NULL)');
  db.exec(MIGRATIONS.find((migration) => migration.version === 11).sqlite);
  db.exec(MIGRATIONS.find((migration) => migration.version === 12).sqlite);
  db.exec(MIGRATIONS.find((migration) => migration.version === 13).sqlite);
  const audit = authenticatedAudit(db, auditKey);
  const reference = (kind, value) => opaqueReference(referenceKey, kind, value);
  const authorityReference = () => reference(
    'connected', `${scope.customerId}\0${scope.deploymentId}`,
  );
  const ackReference = (ackId) => reference('ack', ackId);
  const store = createConnectedEntitlementStore({
    ...scope,
    driver: db,
    appendAudit: audit.append,
    authorityReference: (customerId, deploymentId) => reference('connected', `${customerId}\0${deploymentId}`),
    ackReference,
    verifyAuditState: () => ({ ok: audit.verifyChain() }),
    verifyAuditEntry: audit.verifyEntry,
    verificationKeys: () => ({
      publicKeys: { [KEY_IDS.entitlement]: purposeKeys.entitlement.publicKey },
      offlineKeyFingerprint: keyFingerprint(offlineKeys.publicKey),
      forbiddenPublicKeyFingerprints: [
        onlineVerdict.keyFingerprint(purposeKeys.onlineVerdict.publicKey),
      ],
    }),
    offlinePublicKey: () => publicPem(offlineKeys),
  });
  const registryStore = createConnectedOnlineRegistryStore({
    ...scope,
    driver: db,
    appendAudit: audit.append,
    registryReference: (customerId, deploymentId) => reference(
      'connected_registry', `${customerId}\0${deploymentId}`,
    ),
    verifyAuditState: () => ({ ok: audit.verifyChain() }),
    verifyAuditEntry: audit.verifyEntry,
    verifyVerdict: (text) => onlineVerdict.verifySignedOnlineVerdict(
      text,
      new Map([[KEY_IDS.onlineVerdict, purposeKeys.onlineVerdict.publicKey]]),
      {
        forbiddenPublicKeyFingerprints: [
          keyFingerprint(offlineKeys.publicKey),
          keyFingerprint(purposeKeys.entitlement.publicKey),
        ],
      },
    ),
  });
  return entitlementHarnessView({
    file, scope, db, store, registryStore, audit, offlineKeys, authorityReference, ackReference,
  });
}

function entitlementHarnessView(input) {
  const bootId = sha256(input.file).slice(0, 32);
  const clock = (nowMs) => ({ bootId, nowMs });
  return {
    ...input,
    clock,
    offlineLicenseText: offlineLicenseText(input.scope, input.offlineKeys),
    applyArtifact: (artifact, nowMs) => input.store.applyEntitlement({
      ...input.scope,
      signedArtifact: artifact,
      nowMs,
      clock: clock(nowMs),
    }),
    verifyAuditChain: input.audit.verifyChain,
    close: () => input.db.close(),
  };
}

function authenticatedAudit(db, key) {
  const verifyEntry = (entry) => verifyAuditEntry(entry, key);
  const checkpointKey = crypto.createHmac('sha256', key)
    .update('redactwall.synthetic-audit-checkpoint.v1', 'utf8').digest();
  let checkpoint = authenticatedCheckpoint(checkpointKey, 0, ZERO_HASH);
  const verifyChain = () => {
    let previousHash = ZERO_HASH;
    try {
      if (!verifyCheckpoint(checkpointKey, checkpoint)) return false;
      const rows = db.prepare('SELECT seq, action, entry FROM audit ORDER BY seq').all();
      if (rows.length !== checkpoint.count) return false;
      for (const row of rows) {
        const entry = JSON.parse(row.entry);
        if (entry.sequence !== row.seq || entry.action !== row.action
            || entry.previousHash !== previousHash || !verifyEntry(entry)) return false;
        previousHash = entry.hash;
      }
      return previousHash === checkpoint.headHash;
    } catch { return false; }
  };
  return {
    verifyEntry,
    verifyChain,
    append: (event) => {
      const entry = appendAuthenticatedAudit(db, key, event);
      checkpoint = authenticatedCheckpoint(checkpointKey, entry.sequence, entry.hash);
      return entry;
    },
  };
}

function authenticatedCheckpoint(key, count, headHash) {
  const body = { count, headHash };
  return { ...body, mac: hmac(key, protocol.canonicalJson(body)) };
}

function verifyCheckpoint(key, checkpoint) {
  if (!checkpoint || !Number.isSafeInteger(checkpoint.count) || checkpoint.count < 0
      || !/^[a-f0-9]{64}$/.test(String(checkpoint.headHash || ''))) return false;
  const body = { count: checkpoint.count, headHash: checkpoint.headHash };
  return safeHexEqual(checkpoint.mac, hmac(key, protocol.canonicalJson(body)));
}

function appendAuthenticatedAudit(db, key, event) {
  const last = db.prepare('SELECT seq, entry FROM audit ORDER BY seq DESC LIMIT 1').get();
  const sequence = last ? Number(last.seq) + 1 : 1;
  const previousHash = last ? JSON.parse(last.entry).hash : ZERO_HASH;
  const body = auditBody(event, sequence, previousHash);
  const hash = sha256(protocol.canonicalJson(body));
  const authenticated = { ...body, hash };
  const entry = { ...authenticated, mac: hmac(key, protocol.canonicalJson(authenticated)) };
  const result = db.prepare('INSERT INTO audit (action, entry) VALUES (?, ?)')
    .run(event.action, JSON.stringify(entry));
  assert.equal(Number(result.lastInsertRowid), sequence);
  return entry;
}

function auditBody(event, sequence, previousHash) {
  return {
    sequence,
    previousHash,
    action: event.action,
    actor: event.actor,
    detail: event.detail,
    ...(event.connectedAuthorityRef ? { connectedAuthorityRef: event.connectedAuthorityRef } : {}),
    ...(event.connectedAckRef ? { connectedAckRef: event.connectedAckRef } : {}),
  };
}

function verifyAuditEntry(entry, key) {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return false;
  const { mac, hash, ...body } = entry;
  if (hash !== sha256(protocol.canonicalJson(body))) return false;
  return safeHexEqual(mac, hmac(key, protocol.canonicalJson({ ...body, hash })));
}

function entitlement(scope, version, overrides = {}) {
  const status = overrides.status || 'active';
  const issuedMs = Date.parse('2026-07-12T12:00:00.000Z') + ((version - 1) * 1_000);
  const reasonCode = overrides.reasonCode || reasonFor(status);
  return {
    schemaVersion: protocol.PROTOCOL_VERSION,
    messageId: crypto.randomUUID(),
    ...scope,
    kind: protocol.CHANNEL_KINDS.ENTITLEMENT,
    status,
    plan: 'enterprise',
    seats: 50,
    features: ['catalog', 'policy'],
    entitlementVersion: version,
    previousVersion: version - 1,
    issuedAt: new Date(issuedMs).toISOString(),
    expiresAt: new Date(issuedMs + 5 * 60_000).toISOString(),
    fallbackUntil: status === 'active' ? new Date(issuedMs + 72 * 60 * 60 * 1000).toISOString() : null,
    reasonCode,
    ...overrides,
  };
}

function reasonFor(status) {
  if (status === 'paused') return 'manual_pause';
  if (status === 'revoked') return 'manual_revoke';
  return 'billing_active';
}

function applyEntitlement(silo, payload, nowMs) {
  return silo.applyArtifact(signed(payload, 'entitlement'), nowMs);
}

function registryVerdict(scope, generation, status, issuedAtMs) {
  return {
    kind: onlineVerdict.VERDICT_DOMAIN,
    keyId: KEY_IDS.onlineVerdict,
    status,
    customerId: scope.customerId,
    deploymentId: scope.deploymentId,
    issuedAt: new Date(issuedAtMs).toISOString(),
    registryGeneration: generation,
    registryStateDigest: sha256(protocol.canonicalJson({
      customerId: scope.customerId,
      deploymentId: scope.deploymentId,
      generation,
      status,
    })),
  };
}

function signedRegistryVerdict(payload) {
  const payloadBase64 = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64');
  const signature = crypto.sign(
    null,
    Buffer.from(`${onlineVerdict.VERDICT_DOMAIN}\0${payloadBase64}`, 'utf8'),
    purposeKeys.onlineVerdict.privateKey,
  ).toString('base64');
  return `${payloadBase64}.${signature}`;
}

function applyRegistryVerdict(silo, payload, nowMs) {
  return silo.registryStore.applyVerdict({
    ...silo.scope,
    signedVerdict: signedRegistryVerdict(payload),
    nowMs,
  });
}

function heartbeatFor(silo, nowMs) {
  const entitlementState = silo.store.getState(
    silo.scope.customerId, silo.scope.deploymentId,
  );
  return protocol.assertChannel({
    schemaVersion: protocol.PROTOCOL_VERSION,
    messageId: crypto.randomUUID(),
    ...silo.scope,
    kind: protocol.CHANNEL_KINDS.HEARTBEAT,
    heartbeatNonce: crypto.createHash('sha256')
      .update(`${silo.scope.customerId}\0${nowMs}`, 'utf8').digest('base64url'),
    plan: 'enterprise',
    seatsUsed: 1,
    seatLimit: 50,
    version: '1.0.0',
    sentAt: new Date(nowMs).toISOString(),
    lastAppliedEntitlementVersion: entitlementState?.entitlementVersion || 0,
    lastAppliedRegistryGeneration: silo.registryStore.registryGeneration(
      silo.scope.customerId, silo.scope.deploymentId,
    ),
    lastAppliedPolicyVersion: 0,
    lastAppliedCatalogVersion: 0,
  }, protocol.CHANNEL_KINDS.HEARTBEAT);
}

function acknowledge(silo, result, nowMs) {
  const delivered = silo.store.recordAckResult({
    id: result.outboxes.delivered.id,
    ...silo.scope,
    payloadDigest: result.outboxes.delivered.payloadDigest,
    accepted: true,
    nowMs,
  });
  assert.equal(delivered.status, 'acknowledged');
  const acknowledged = silo.store.recordAckResult({
    id: result.outboxes.applied.id,
    ...silo.scope,
    payloadDigest: result.outboxes.applied.payloadDigest,
    accepted: true,
    nowMs: nowMs + 1,
  });
  assert.equal(acknowledged.status, 'acknowledged');
  return acknowledged;
}

function pending(silo, nowMs) {
  return silo.store.listPendingAcknowledgements({ ...silo.scope, nowMs });
}

function disposition(silo, nowMs) {
  return silo.store.disposition(silo.scope.customerId, silo.scope.deploymentId, {
    nowMs,
    clock: silo.clock(nowMs),
    offlineLicenseText: silo.offlineLicenseText,
  });
}

function offlineLicenseText(scope, keys) {
  const payload = {
    ...scope,
    status: 'active',
    plan: 'enterprise',
    seats: 50,
    features: ['catalog', 'policy'],
    expires: '2026-07-20T00:00:00.000Z',
    graceDays: 0,
  };
  const encoded = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64');
  const signature = crypto.sign(null, Buffer.from(encoded), keys.privateKey).toString('base64');
  return `${encoded}.${signature}`;
}

function proveShadowIsolation(shadowA, shadowB) {
  const recordsV1 = [catalogRecord('shared-ai', 'sharedai.com', 'generative_ai')];
  const appliedA = shadowA.catalog.applySignedRelease(catalogRelease(SCOPE_A, 1, 0, recordsV1));
  const appliedB = shadowB.catalog.applySignedRelease(catalogRelease(SCOPE_B, 1, 0, recordsV1));
  const snapshotA = catalogSnapshot(shadowA.storage);
  const initialB = catalogSnapshot(shadowB.storage);
  expectCode(() => shadowA.catalog.applySignedRelease(catalogRelease(SCOPE_B, 2, 1, [])), 'customer_mismatch');
  expectCode(() => shadowA.catalog.applySignedRelease(
    catalogRelease(SCOPE_A_SIBLING, 2, 1, []),
  ), 'deployment_mismatch');
  expectCode(() => shadowA.catalog.applySignedRelease(catalogRelease(
    SCOPE_A, 2, 1, [], { signingPurpose: 'entitlement' },
  )), 'unknown_signing_key');
  assert.deepEqual(catalogSnapshot(shadowA.storage), snapshotA);
  assert.deepEqual(catalogSnapshot(shadowB.storage), initialB);
  assert.equal(shadowA.storage.data.overrides.size + shadowA.storage.data.observations.size, 0);

  putShadowLocalState(shadowA.catalog, 'warn', 'alphatool.com');
  putShadowLocalState(shadowB.catalog, 'allow', 'betatool.com');
  const stableB = catalogSnapshot(shadowB.storage);
  assert.equal(shadowA.catalog.readEffectiveCatalog(catalogExpectation(appliedA.state))
    .records[0].disposition, 'warn');
  assert.equal(shadowB.catalog.readEffectiveCatalog(catalogExpectation(appliedB.state))
    .records[0].disposition, 'allow');
  assert.deepEqual(shadowA.catalog.readLocalObservations().map((item) => item.registrableDomain), ['alphatool.com']);
  assert.deepEqual(shadowB.catalog.readLocalObservations().map((item) => item.registrableDomain), ['betatool.com']);
  assert.equal(JSON.stringify(shadowA.storage.data.current).includes('alphatool.com'), false);
  assert.equal(JSON.stringify(shadowB.storage.data.current).includes('betatool.com'), false);

  shadowA.catalog.applySignedRelease(catalogRelease(SCOPE_A, 2, 1, [
    catalogRecord('shared-ai', 'sharedai.com', 'not_ai'),
  ]));
  const beforeInvalidRollback = catalogSnapshot(shadowA.storage);
  expectCode(() => shadowA.catalog.applySignedRelease(catalogRelease(
    SCOPE_A, 3, 2, [], { rollbackOfVersion: 1 },
  )), 'rollback_content_mismatch');
  assert.deepEqual(catalogSnapshot(shadowA.storage), beforeInvalidRollback);
  const v1Digest = shadowA.storage.data.distributions.get(1).value.recordsDigest;
  const rolled = shadowA.catalog.applySignedRelease(catalogRelease(
    SCOPE_A, 3, 2, recordsV1, { rollbackOfVersion: 1 },
  ));
  assert.equal(shadowA.catalog.readEffectiveCatalog(catalogExpectation(rolled.state))
    .records[0].disposition, 'warn');
  assert.equal(shadowA.storage.data.current.globalArtifact.payload.rollbackOfGlobalVersion, 1);
  assert.equal(shadowA.storage.data.current.recordsDigest, v1Digest);
  assert.equal(shadowA.storage.data.distributions.has(2), true);
  assert.equal(shadowA.storage.data.distributions.size, 3);
  assert.equal(shadowB.catalog.readEffectiveCatalog(catalogExpectation(appliedB.state))
    .globalVersion, 1);
  assert.deepEqual(catalogSnapshot(shadowB.storage), stableB);
}

function catalogExpectation(state) {
  return {
    distributionSequence: state.distributionSequence,
    globalReleaseId: state.globalReleaseId,
    globalVersion: state.globalVersion,
    globalArtifactDigest: state.globalArtifactDigest,
    recordsDigest: state.recordsDigest,
  };
}

function createShadowHarness(scope, offlineKeys) {
  const storage = createCatalogStorage();
  const anchorStorage = createReferenceMonotonicAnchorStorage();
  Object.defineProperty(storage, 'anchorStorage', { value: anchorStorage });
  const catalog = createReferenceShadowAiCatalogState({
    storage,
    allowTestWitness: true,
    anchorAuthority: createReferenceMonotonicAnchorAuthority({
      storage: anchorStorage,
      keyId: `rw-anchor-catalog-${scope.customerId}`,
      secret: crypto.createHash('sha256')
        .update(`catalog-anchor\0${scope.customerId}\0${scope.deploymentId}`, 'utf8').digest(),
      purpose: 'customer_catalog_witness',
      storageContext: `reference:customer-catalog:${scope.customerId}:${scope.deploymentId}`,
      storageIdentity: sha256(
        `catalog-anchor-storage\0${scope.customerId}\0${scope.deploymentId}`,
      ),
    }),
    ...scope,
    globalPublicKeys: {
      [KEY_IDS.catalogGlobal]: purposeKeys.catalogGlobal.publicKey,
    },
    distributionPublicKeys: {
      [KEY_IDS.catalogDistribution]: purposeKeys.catalogDistribution.publicKey,
    },
    forbiddenPublicKeyFingerprints: [keyFingerprint(offlineKeys.publicKey)],
    stateIntegrityAuthority: {
      keyId: `rw-catalog-state-integrity-${scope.customerId}`,
      secret: crypto.createHash('sha256')
        .update(`catalog-state\0${scope.customerId}\0${scope.deploymentId}`, 'utf8').digest(),
    },
  });
  return { storage, anchorStorage, catalog };
}

function createCatalogStorage() {
  let data = newCatalogData();
  let version = 0;
  const storage = {};
  Object.defineProperty(storage, 'data', { get: () => data });
  storage.transaction = (callback) => {
    const baseVersion = version;
    const working = copyCatalogData(data);
    const result = callback(catalogTransaction(working));
    if (result && typeof result.then === 'function') throw new Error('async catalog transaction');
    if (baseVersion !== version) throw new Error('catalog serialization conflict');
    data = working;
    version += 1;
    return result;
  };
  return storage;
}

function catalogTransaction(data) {
  const eventMap = (namespace) => {
    if (!data.auditEvents.has(namespace)) data.auditEvents.set(namespace, new Map());
    return data.auditEvents.get(namespace);
  };
  return {
    readCurrentCatalog: () => clone(data.current),
    compareAndSetCurrentCatalog: (expected, value) => {
      if ((data.current?.distributionSequence || 0) !== expected) return false;
      data.current = clone(value);
      return true;
    },
    readActiveCatalog: () => clone(data.active),
    compareAndSetActiveCatalog: (expected, value) => {
      if ((data.active?.distributionSequence || 0) !== expected) return false;
      data.active = clone(value);
      return true;
    },
    readGlobalCatalogArtifact: (id) => clone(data.globals.get(id)?.artifact),
    listGlobalCatalogArtifacts: () => [...data.globals].map(([globalReleaseId, row]) => ({
      globalReleaseId,
      globalVersion: row.globalVersion,
      globalArtifactDigest: row.artifactDigest,
      artifact: clone(row.artifact),
    })),
    insertGlobalCatalogArtifact: (id, globalVersion, artifactDigest, artifact) => {
      if (data.globals.has(id)) return false;
      data.globals.set(id, { globalVersion, artifactDigest, artifact: clone(artifact) });
      return true;
    },
    deleteGlobalCatalogArtifact: (id, artifactDigest) => {
      const row = data.globals.get(id);
      if (!row || row.artifactDigest !== artifactDigest) return false;
      data.globals.delete(id);
      return true;
    },
    readCatalogDistribution: (sequence) => clone(data.distributions.get(sequence)?.value),
    insertCatalogDistribution: (sequence, distributionDigest, value) => {
      if (data.distributions.has(sequence)) return false;
      data.distributions.set(sequence, { distributionDigest, value: clone(value) });
      return true;
    },
    listCatalogDistributions: () => [...data.distributions].map(([sequence, row]) => ({
      distributionSequence: sequence,
      distributionDigest: row.distributionDigest,
      value: clone(row.value),
    })),
    deleteCatalogDistribution: (sequence, distributionDigest) => {
      const row = data.distributions.get(sequence);
      if (!row || row.distributionDigest !== distributionDigest) return false;
      data.distributions.delete(sequence);
      return true;
    },
    writeCatalogTombstone: (sequence, distributionDigest, wrapped) => {
      if (data.tombstones.has(sequence)) return false;
      data.tombstones.set(sequence, { distributionDigest, wrapped: clone(wrapped) });
      return true;
    },
    deleteCatalogTombstone: (sequence, distributionDigest, wrappedDigest) => {
      const row = data.tombstones.get(sequence);
      if (!row || row.distributionDigest !== distributionDigest
          || digest(row.wrapped) !== wrappedDigest) return false;
      data.tombstones.delete(sequence);
      return true;
    },
    listCatalogTombstones: () => [...data.tombstones.values()]
      .map((row) => clone(row.wrapped)),
    readCatalogHistoryCheckpoint: () => clone(data.historyCheckpoint),
    compareAndSetCatalogHistoryCheckpoint: (expectedSequence, wrapped) => {
      if ((data.historyCheckpoint?.payload?.throughSequence || 0) !== expectedSequence) return false;
      data.historyCheckpoint = clone(wrapped);
      return true;
    },
    readCatalogIntegrityHead: (namespace) => clone(data.heads.get(namespace)),
    compareAndSetCatalogIntegrityHead: (namespace, expected, wrapped) => {
      if ((data.heads.get(namespace)?.payload?.revision || 0) !== expected) return false;
      data.heads.set(namespace, clone(wrapped));
      return true;
    },
    readCatalogPendingWitness: (namespace) => clone(data.pending.get(namespace)),
    writeCatalogPendingWitness: (namespace, expected, wrapped) => {
      if (data.pending.has(namespace)
          || (data.current?.distributionSequence || 0) !== expected) return false;
      data.pending.set(namespace, clone(wrapped));
      return true;
    },
    clearCatalogPendingWitness: (namespace, digestValue) => {
      const wrapped = data.pending.get(namespace);
      if (!wrapped || sha256(protocol.canonicalJson(wrapped)) !== digestValue) return false;
      data.pending.delete(namespace);
      return true;
    },
    readCatalogAuditCheckpoint: (namespace) => clone(data.auditCheckpoints.get(namespace)),
    compareAndSetCatalogAuditCheckpoint: (namespace, expectedSequence, wrapped) => {
      if ((data.auditCheckpoints.get(namespace)?.payload?.sequence || 0)
          !== expectedSequence) return false;
      data.auditCheckpoints.set(namespace, clone(wrapped));
      return true;
    },
    listCatalogAuditEvents: (namespace) => [...eventMap(namespace)]
      .sort(([left], [right]) => left - right).map(([, wrapped]) => clone(wrapped)),
    appendCatalogAuditEvent: (namespace, sequence, digestValue, wrapped) => {
      const events = eventMap(namespace);
      if (events.has(sequence) || wrapped.payload.eventDigest !== digestValue) return false;
      events.set(sequence, clone(wrapped));
      return true;
    },
    deleteCatalogAuditEvent: (namespace, sequence, digestValue) => {
      const events = eventMap(namespace);
      const wrapped = events.get(sequence);
      if (!wrapped || sha256(protocol.canonicalJson(wrapped)) !== digestValue) return false;
      events.delete(sequence);
      return true;
    },
    readTenantOverride: (id) => clone(data.overrides.get(id)),
    compareAndSetTenantOverride: (id, expectedRevision, wrapped) => {
      if ((data.overrides.get(id)?.payload?.revision || 0) !== expectedRevision) return false;
      data.overrides.set(id, clone(wrapped));
      return true;
    },
    listTenantOverrides: (limit) => [...data.overrides]
      .sort(([left], [right]) => left.localeCompare(right)).slice(0, limit)
      .map(([, wrapped]) => clone(wrapped)),
    readTenantOverrideHead: () => clone(data.overrideHead),
    compareAndSetTenantOverrideHead: (expectedRevision, wrapped) => {
      if ((data.overrideHead?.payload?.revision || 0) !== expectedRevision) return false;
      data.overrideHead = clone(wrapped);
      return true;
    },
    readLocalObservation: (domain) => clone(data.observations.get(domain)),
    writeLocalObservation: (value) => { data.observations.set(value.registrableDomain, clone(value)); },
    listLocalObservations: () => [...data.observations.values()].map(clone),
    readCatalogAcknowledgementTransition: (key) => clone(
      data.acknowledgementTransitions.get(key)?.row,
    ),
    listCatalogAcknowledgementTransitions: () => [...data.acknowledgementTransitions]
      .map(([transitionKey, value]) => ({
        transitionKey,
        acknowledgementDigest: value.digest,
        row: clone(value.row),
      })),
    insertCatalogAcknowledgementTransition: (key, digest, row) => {
      if (data.acknowledgementTransitions.has(key)) return false;
      data.acknowledgementTransitions.set(key, { digest, row: clone(row) });
      return true;
    },
  };
}

function newCatalogData() {
  return {
    current: null,
    active: null,
    globals: new Map(),
    distributions: new Map(),
    tombstones: new Map(),
    historyCheckpoint: null,
    heads: new Map(),
    pending: new Map(),
    auditCheckpoints: new Map(),
    auditEvents: new Map(),
    overrides: new Map(),
    overrideHead: null,
    observations: new Map(),
    acknowledgementTransitions: new Map(),
  };
}

function copyCatalogData(data) {
  return {
    current: clone(data.current),
    active: clone(data.active),
    globals: cloneMap(data.globals),
    distributions: cloneMap(data.distributions),
    tombstones: cloneMap(data.tombstones),
    historyCheckpoint: clone(data.historyCheckpoint),
    heads: cloneMap(data.heads),
    pending: cloneMap(data.pending),
    auditCheckpoints: cloneMap(data.auditCheckpoints),
    auditEvents: new Map([...data.auditEvents]
      .map(([key, value]) => [key, cloneMap(value)])),
    overrides: cloneMap(data.overrides),
    overrideHead: clone(data.overrideHead),
    observations: cloneMap(data.observations),
    acknowledgementTransitions: cloneMap(data.acknowledgementTransitions),
  };
}

function catalogSnapshot(storage) {
  const data = storage.data;
  return JSON.parse(JSON.stringify({
    current: data.current,
    active: data.active,
    globals: [...data.globals],
    distributions: [...data.distributions],
    tombstones: [...data.tombstones],
    historyCheckpoint: data.historyCheckpoint,
    heads: [...data.heads],
    anchors: [...storage.anchorStorage.snapshot()],
    pending: [...data.pending],
    auditCheckpoints: [...data.auditCheckpoints],
    auditEvents: [...data.auditEvents].map(([key, value]) => [key, [...value]]),
    overrides: [...data.overrides],
    overrideHead: data.overrideHead,
    observations: [...data.observations],
    acknowledgementTransitions: [...data.acknowledgementTransitions],
  }));
}

function cloneMap(value) {
  return new Map([...value].map(([key, item]) => [key, clone(item)]));
}

function putShadowLocalState(catalog, dispositionValue, domain) {
  catalog.putTenantOverride({
    catalogId: 'shared-ai',
    revision: 1,
    classification: null,
    riskTier: null,
    disposition: dispositionValue,
    updatedAt: '2026-07-12T12:01:00.000Z',
  });
  catalog.putLocalObservation({
    registrableDomain: domain,
    revision: 1,
    firstSeenDay: '2026-07-12',
    lastSeenDay: '2026-07-12',
    observationCountBucket: '1',
    sourceTypes: ['browser_destination'],
    localClassification: 'unknown',
    localOutcome: 'observed',
    updatedAt: '2026-07-12T12:01:00.000Z',
  });
}

function catalogRecord(catalogId, registrableDomain, classification) {
  return {
    catalogId,
    registrableDomain,
    aliases: [],
    classification,
    riskTier: classification === 'not_ai' ? 'low' : 'high',
    analystState: 'approved',
    evidenceClass: 'vendor_validation',
    confidenceBps: 9500,
  };
}

function catalogRelease(scope, version, previousVersion, records, overrides = {}) {
  const issuedAt = new Date(NOW + version * 1_000).toISOString();
  const recordsDigest = protocol.catalogRecordsDigest(records);
  const globalPayload = {
    schemaVersion: protocol.PROTOCOL_VERSION,
    messageId: crypto.randomUUID(),
    kind: protocol.CHANNEL_KINDS.GLOBAL_CATALOG_RELEASE,
    authorityManifestGeneration: 1,
    authorityManifestKeySlot: 'current',
    globalReleaseId: crypto.randomUUID(),
    globalVersion: version,
    previousGlobalVersion: previousVersion,
    rollbackOfGlobalVersion: overrides.rollbackOfVersion ?? null,
    issuedAt,
    recordsDigest,
    records,
  };
  const globalArtifact = signed(globalPayload,
    overrides.signingPurpose || 'catalogGlobal');
  const distributionPayload = {
    schemaVersion: protocol.PROTOCOL_VERSION,
    messageId: crypto.randomUUID(),
    ...scope,
    kind: protocol.CHANNEL_KINDS.CATALOG_DISTRIBUTION,
    authorityManifestGeneration: 1,
    authorityManifestKeySlot: 'current',
    distributionSequence: version,
    previousDistributionSequence: previousVersion,
    globalReleaseId: globalPayload.globalReleaseId,
    globalVersion: version,
    globalArtifactDigest: sha256(protocol.canonicalJson(globalArtifact)),
    recordsDigest,
    rollout: { mode: 'required', cohortBps: 10_000 },
    issuedAt,
  };
  return {
    globalArtifact,
    distributionArtifact: signed(distributionPayload, 'catalogDistribution'),
  };
}

function provePolicyIsolation() {
  const bundleA = policyBundle('vendor-alpha');
  const bundleB = policyBundle('vendor-beta');
  const desiredA = policyDesiredState(SCOPE_A, 1, bundleA);
  const desiredB = policyDesiredState(SCOPE_B, 1, bundleB);
  const initialA = policyState.initialState(SCOPE_A.customerId, SCOPE_A.deploymentId);
  const initialB = policyState.initialState(SCOPE_B.customerId, SCOPE_B.deploymentId);
  const initialSnapshotA = clone(initialA);
  expectCode(() => applyPolicy(
    initialA, signed(desiredB, 'policy'), bundleB, {}, purposeKeys.offlineCommercial,
  ), 'customer_mismatch');
  const desiredSibling = policyDesiredState(SCOPE_A_SIBLING, 1, bundleA);
  expectCode(() => applyPolicy(
    initialA, signed(desiredSibling, 'policy'), bundleA, {}, purposeKeys.offlineCommercial,
  ), 'deployment_mismatch');
  expectCode(() => applyPolicy(
    initialA, signed(desiredA, 'catalogGlobal'), bundleA, {}, purposeKeys.offlineCommercial,
  ), 'unknown_signing_key');
  expectCode(() => applyPolicy(
    initialA, signed(desiredA, 'policy'), bundleA, {}, purposeKeys.policy,
  ), 'vendor_key_identity_reused');
  assert.deepEqual(initialA, initialSnapshotA);

  const resultA = applyPolicy(initialA, signed(desiredA, 'policy'), bundleA, {
    alwaysBlockAdd: ['CUSTOM_SECRET_A'],
  }, purposeKeys.offlineCommercial);
  const resultB = applyPolicy(initialB, signed(desiredB, 'policy'), bundleB, {
    alwaysBlockAdd: ['CUSTOM_SECRET_B'],
  }, purposeKeys.offlineCommercial);
  assert.equal(resultA.effectivePolicy.alwaysBlock.includes('CUSTOM_SECRET_A'), true);
  assert.equal(resultA.effectivePolicy.alwaysBlock.includes('CUSTOM_SECRET_B'), false);
  assert.equal(resultB.effectivePolicy.alwaysBlock.includes('CUSTOM_SECRET_B'), true);
  assert.equal(resultB.effectivePolicy.alwaysBlock.includes('CUSTOM_SECRET_A'), false);
  assert.equal(resultA.state.customerId, SCOPE_A.customerId);
  assert.equal(resultB.state.customerId, SCOPE_B.customerId);
}

function applyPolicy(state, artifact, bundle, tenantLocalOverride, offlineKeys) {
  return policyState.applySignedPolicy(state, artifact, {
    publicKeys: { [KEY_IDS.policy]: purposeKeys.policy.publicKey },
    offlineKeyFingerprint: keyFingerprint(offlineKeys.publicKey),
    forbiddenPublicKeyFingerprints: [
      purposeKeys.entitlement,
      purposeKeys.catalogGlobal,
      purposeKeys.catalogDistribution,
      purposeKeys.auditRequest,
    ].map((keys) => keyFingerprint(keys.publicKey)),
    vendorBundle: bundle,
    tenantLocalOverride,
    nowMs: NOW,
  });
}

function policyBundle(name) {
  return {
    enforcementMode: 'block',
    blockMinSeverity: 2,
    blockRiskScore: 70,
    alwaysBlock: [...policyState.MANDATORY_ALWAYS_BLOCK],
    blockedDestinations: [`${name}.example`],
    blockedFileUploadDestinations: [],
    mcpBlockedTools: [],
    mcpApprovalRequiredTools: [],
    blockUnapprovedAiDestinations: true,
    responseScanMode: 'block',
    unmanagedInstalls: 'block',
    licensing: { failClosed: true },
    audit: { required: true },
  };
}

function policyDesiredState(scope, version, bundle) {
  return {
    schemaVersion: protocol.PROTOCOL_VERSION,
    messageId: crypto.randomUUID(),
    ...scope,
    kind: protocol.CHANNEL_KINDS.POLICY_DESIRED_STATE,
    policyVersion: version,
    previousVersion: version - 1,
    rollbackOfVersion: null,
    bundleDigest: policyState.digestPolicyDocument(bundle),
    mandatoryControlsDigest: policyState.MANDATORY_CONTROLS_DIGEST,
    issuedAt: '2026-07-12T12:00:00.000Z',
    expiresAt: '2026-07-12T12:10:00.000Z',
    rollout: 'required',
  };
}

function proveDiagnosticIsolation() {
  const channelA = new CustomerDiagnosticChannel({ ...SCOPE_A, maxItems: 2 });
  const channelB = new CustomerDiagnosticChannel({ ...SCOPE_B, maxItems: 2 });
  const eventA = diagnostic(SCOPE_A);
  const eventB = diagnostic(SCOPE_B);
  const emptyA = clone(channelA.snapshot());
  expectCode(() => channelA.accept(eventB), 'diagnostic_customer_mismatch');
  expectCode(() => channelA.accept(diagnostic(SCOPE_A_SIBLING)), 'diagnostic_deployment_mismatch');
  assert.deepEqual(channelA.snapshot(), emptyA);
  const captured = captureConsole(() => {
    expectCodeNoEcho(
      () => channelA.accept({ ...eventA, prompt: 'canary_token=DO_NOT_PERSIST' }),
      'diagnostic_schema_rejected',
      'DO_NOT_PERSIST',
    );
    expectCodeNoEcho(
      () => channelA.accept({ ...eventA, detail: 'canary_token_001' }),
      'diagnostic_schema_rejected',
      'canary_token_001',
    );
  });
  const capturedExposure = deepExposure(captured);
  assert.equal(capturedExposure.includes('DO_NOT_PERSIST'), false);
  assert.equal(capturedExposure.includes('canary_token_001'), false);
  assert.deepEqual(channelA.snapshot(), emptyA);
  assert.equal(JSON.stringify(channelA.snapshot()).includes('DO_NOT_PERSIST'), false);

  const acceptedA = channelA.accept(eventA);
  const acceptedB = channelB.accept(eventB);
  assert.equal(channelA.snapshot().items[0].event.customerId, SCOPE_A.customerId);
  assert.equal(channelB.snapshot().items[0].event.customerId, SCOPE_B.customerId);
  const beforeCrossReceiptA = clone(channelA.snapshot());
  const beforeCrossReceiptB = clone(channelB.snapshot());
  expectCode(
    () => channelA.recordDelivery(eventB.messageId, acceptedB.digest, true),
    'diagnostic_delivery_not_current',
  );
  assert.deepEqual(channelA.snapshot(), beforeCrossReceiptA);
  assert.deepEqual(channelB.snapshot(), beforeCrossReceiptB);
  assert.deepEqual(channelA.recordDelivery(eventA.messageId, acceptedA.digest, true), { removed: true, duplicate: false });
  assert.deepEqual(channelB.recordDelivery(eventB.messageId, acceptedB.digest, true), { removed: true, duplicate: false });
  assert.equal(channelA.snapshot().size + channelB.snapshot().size, 0);
}

function diagnostic(scope) {
  return {
    schemaVersion: protocol.PROTOCOL_VERSION,
    messageId: crypto.randomUUID(),
    ...scope,
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
  };
}

function proveAuditSupportIsolation() {
  const requestA = auditRequest(SCOPE_A);
  const requestB = auditRequest(SCOPE_B);
  const requestSibling = auditRequest(SCOPE_A_SIBLING);
  const customerA = auditBroker(SCOPE_A, requestA, 'approve');
  const customerB = auditBroker(SCOPE_B, requestB, 'deny');
  try {
    assert.notEqual(customerA.store.database, customerB.store.database);
    const badSignature = signAuditSupportRequest(requestA, {
      keyId: KEY_IDS.auditRequest,
      privateKey: purposeKeys.policy.privateKey,
    });
    expectCode(() => customerA.broker.receive(badSignature), 'invalid_signature');
    expectCode(
      () => customerA.broker.receive(signedAuditRequest(requestB)),
      'audit_customer_mismatch',
    );
    expectCode(
      () => customerA.broker.receive(signedAuditRequest(requestSibling)),
      'audit_deployment_mismatch',
    );
    assert.equal(customerA.broker.auditEvents().items.length, 0);
    assert.equal(customerA.broker.getState(requestB.requestId), null);
    assert.equal(customerA.broker.getState(requestSibling.requestId), null);

    const receivedA = customerA.broker.receive(signedAuditRequest(requestA));
    const receivedB = customerB.broker.receive(signedAuditRequest(requestB));
    assert.equal(customerA.acknowledgementRegistry.verify(receivedA.receipt).customerId,
      SCOPE_A.customerId);
    assert.equal(customerB.acknowledgementRegistry.verify(receivedB.receipt).customerId,
      SCOPE_B.customerId);
    expectCode(
      () => customerA.acknowledgementRegistry.verify(receivedB.receipt),
      'audit_acknowledgement_unknown_key',
    );

    customerA.broker.decide({
      action: 'approve',
      authorizationId: customerA.authorization.authorizationId,
      requestId: requestA.requestId,
      requestVersion: 1,
    });
    customerB.broker.decide({
      action: 'deny',
      authorizationId: customerB.authorization.authorizationId,
      requestId: requestB.requestId,
      requestVersion: 1,
    });
    const responseA = customerA.broker.respond({
      requestId: requestA.requestId,
      requestVersion: 1,
    });
    const responseB = customerB.broker.respond({
      requestId: requestB.requestId,
      requestVersion: 1,
    });
    assert.equal(responseA.payload.customerId, SCOPE_A.customerId);
    assert.equal(responseB.payload.customerId, SCOPE_B.customerId);
    assert.equal(responseA.payload.status, 'completed');
    assert.equal(responseB.payload.status, 'denied');
    assert.equal(customerA.summaryProvider.calls(), 1);
    assert.equal(customerB.summaryProvider.calls(), 0);
    assert.equal(verifyCustomerAuditResponse(
      responseA, customerA.responseRegistry,
    ).payload.customerId, SCOPE_A.customerId);
    assert.equal(verifyCustomerAuditResponse(
      responseB, customerB.responseRegistry,
    ).payload.customerId, SCOPE_B.customerId);
    expectCode(
      () => verifyCustomerAuditResponse(responseA, customerB.responseRegistry),
      'customer_response_signature_invalid',
    );
    assert.equal(customerA.broker.getState(requestA.requestId).status, 'completed');
    assert.equal(customerB.broker.getState(requestB.requestId).status, 'denied');
    const events = [
      customerA.broker.auditEvents().items,
      customerB.broker.auditEvents().items,
    ];
    const evidence = JSON.stringify({ events, responseA, responseB });
    assert.equal(evidence.includes('prompt'), false);
    assert.equal(evidence.includes('canary_token'), false);
    return events;
  } finally {
    customerA.close();
    customerB.close();
  }
}

function auditBroker(scope, request, action) {
  const requestDigest = auditSupportPayloadDigest(request, REQUEST_SIGNATURE_DOMAIN);
  const authorization = localAuditAuthorization(scope, request, requestDigest, action);
  const store = openCustomerAuditSupportSqlite({
    integrityAuthority: createReferenceCustomerAuditIntegrityAuthority({
      keyId: `customer-audit-${scope.customerId}`,
      secret: purposeSecret('audit-integrity', scope),
    }),
    witnessAuthority: createReferenceCustomerAuditWitnessAuthority({
      keyId: `customer-audit-witness-${scope.customerId}`,
      secret: purposeSecret('audit-witness', scope),
    }),
    anchorAuthority: referenceAnchorAuthority('customer_audit_support', scope),
    anchorNamespace: `audit-support:${scope.customerId}:${scope.deploymentId}`,
  });
  const responseKeys = crypto.generateKeyPairSync('ed25519');
  const responseKeyId = `rw-customer-audit-response-${scope.customerId}-current`;
  const responseRegistry = createCustomerAuditResponseKeyRegistry({
    integrityKey: purposeSecret('audit-response-registry', scope),
    anchorAuthority: referenceAnchorAuthority('customer_audit_response_registry', scope),
    anchorNamespace: `audit-response-registry:${scope.customerId}:${scope.deploymentId}`,
    now: () => NOW,
    entries: [{
      ...scope,
      current: {
        keyId: responseKeyId,
        publicKey: publicPem(responseKeys),
        validFrom: new Date(NOW - 60_000).toISOString(),
      },
      next: null,
      verifyOnly: [],
    }],
  });
  const acknowledgementRecord = {
    ...scope,
    keyId: `rw-audit-ack-${scope.customerId}`,
    secret: purposeSecret('audit-acknowledgement', scope),
  };
  const acknowledgementRegistry = createReferenceAuditAcknowledgementRegistry({
    records: [acknowledgementRecord],
  });
  const summaryProvider = createReferenceAuditSummaryProvider({
    summaries: [integritySummary()],
  });
  const authorityRegistry = completeAuthorityManifestRegistry();
  assert.equal(Object.keys(AUTHORITY_DEFINITIONS).length, 20);
  for (const purpose of Object.keys(AUTHORITY_DEFINITIONS)) {
    assert.ok(authorityRegistry.get(purpose));
  }
  const broker = new CustomerAuditSupportBroker({
    ...scope,
    authorityRegistry,
    store,
    localAdminAuthorizer: createReferenceLocalAuditAdminAuthorizer({
      events: [authorization],
    }),
    summaryProvider,
    responseSigner: createCustomerAuditResponseSigner({
      ...scope,
      keyId: responseKeyId,
      privateKey: responseKeys.privateKey,
    }),
    acknowledgementSigner: createReferenceAuditAcknowledgementSigner(
      acknowledgementRecord,
    ),
    now: () => NOW,
    messageId: crypto.randomUUID,
  });
  return {
    acknowledgementRegistry,
    authorization,
    broker,
    responseRegistry,
    store,
    summaryProvider,
    close() {
      responseRegistry.close();
      store.close();
    },
  };
}

function auditRequest(scope) {
  return {
    schemaVersion: protocol.PROTOCOL_VERSION,
    messageId: crypto.randomUUID(),
    ...scope,
    kind: protocol.CHANNEL_KINDS.AUDIT_REQUEST,
    requestId: crypto.randomUUID(),
    requestVersion: 1,
    requestType: 'integrity_status',
    purposeCode: 'customer_support',
    issuedAt: '2026-07-12T12:00:00.000Z',
    notBefore: '2026-07-12T12:00:00.000Z',
    expiresAt: '2026-07-12T13:00:00.000Z',
    maxRecords: 1,
    fields: ['integrity_status'],
  };
}

function integritySummary() {
  return {
    field: 'integrity_status',
    valueCode: 'intact',
    version: null,
    coarseTimestamp: null,
    count: 1,
  };
}

function assertSafeAuditEvent(event) {
  assert.deepEqual(Object.keys(event).sort(), [
    'authorizationRef', 'count', 'eventDigest', 'eventType', 'occurredAt',
    'outcome', 'previousDigest', 'requestDigest', 'requestVersion',
    'schemaVersion', 'sequence',
  ]);
  assert.equal(event.schemaVersion, 1);
  assert.ok(Number.isSafeInteger(event.sequence) && event.sequence > 0);
  assert.match(event.previousDigest, /^[a-f0-9]{64}$/);
  assert.match(event.eventDigest, /^[a-f0-9]{64}$/);
  const serialized = JSON.stringify(event);
  assert.equal(serialized.includes(SCOPE_A.customerId), false);
  assert.equal(serialized.includes(SCOPE_B.customerId), false);
  assert.equal(serialized.includes('prompt'), false);
}

function signedAuditRequest(payload) {
  return signAuditSupportRequest(payload, {
    keyId: KEY_IDS.auditRequest,
    privateKey: purposeKeys.auditRequest.privateKey,
  });
}

function localAuditAuthorization(scope, request, requestDigest, action) {
  return {
    action,
    auditRef: `local_audit_${crypto.createHash('sha256')
      .update(`${scope.customerId}\0${request.requestId}\0${action}`, 'utf8')
      .digest('base64url').slice(0, 32)}`,
    authEventId: crypto.randomUUID(),
    authenticatedAt: new Date(NOW - 1_000).toISOString(),
    authorizationId: crypto.randomUUID(),
    ...scope,
    purposeCode: request.purposeCode,
    requestDigest,
    requestId: request.requestId,
    requestVersion: request.requestVersion,
    role: 'security_admin',
    stepUpAt: new Date(NOW - 2_000).toISOString(),
  };
}

function referenceAnchorAuthority(purpose, scope) {
  const storage = createReferenceMonotonicAnchorStorage();
  const storageContext = `reference:${purpose}:${scope.customerId}:${scope.deploymentId}`;
  return createReferenceMonotonicAnchorAuthority({
    storage,
    keyId: `rw-anchor-${purpose.replaceAll('_', '-')}-${scope.customerId}`,
    purpose,
    secret: purposeSecret(`anchor:${purpose}`, scope),
    storageContext,
    storageIdentity: sha256(`two-silo-anchor-storage\0${storageContext}`),
  });
}

function purposeSecret(purpose, scope) {
  return crypto.createHash('sha256')
    .update(`redactwall.two-silo.v1\0${purpose}\0${scope.customerId}\0${scope.deploymentId}`, 'utf8')
    .digest();
}

function completeAuthorityManifestRegistry() {
  const records = {};
  const publicKeys = new Map();
  for (const [purpose, definition] of Object.entries(AUTHORITY_DEFINITIONS)) {
    const pair = authorityPair(purpose);
    const keyId = authorityKeyId(purpose, definition, pair);
    const identity = pair
      ? keyFingerprint(pair.publicKey)
      : sha256(`redactwall.two-silo.manifest.v1\0${purpose}`);
    records[purpose] = { keyId, identity };
    if (pair) publicKeys.set(purpose, { keyId, publicKey: pair.publicKey });
  }
  const manifest = createAuthorityRegistry(records);
  const keyFor = (purpose, keyId) => {
    const record = publicKeys.get(purpose);
    if (!record || record.keyId !== keyId) {
      const error = new Error('manifest public key missing');
      error.code = 'authority_manifest_public_key_required';
      throw error;
    }
    return record;
  };
  return Object.freeze({
    get: (purpose) => manifest.get(purpose),
    activePublicKeys: (purpose) => {
      const record = publicKeys.get(purpose);
      return record ? new Map([[record.keyId, record.publicKey]]) : new Map();
    },
    verificationPublicKey: (purpose, keyId) => {
      const record = keyFor(purpose, keyId);
      return new Map([[record.keyId, record.publicKey]]);
    },
    assertPublicKey: (purpose, keyId, fingerprint) => {
      manifest.assertPublicKey(purpose, keyId, fingerprint);
    },
    assertHistoricalPublicKey: (purpose, keyId, fingerprint) => {
      manifest.assertPublicKey(purpose, keyId, fingerprint);
    },
  });
}

function authorityPair(purpose) {
  const pairs = {
    [KEY_PURPOSES.OFFLINE_LICENSE]: purposeKeys.offlineCommercial,
    [KEY_PURPOSES.ONLINE_VERDICT]: purposeKeys.onlineVerdict,
    [KEY_PURPOSES.ENTITLEMENT]: purposeKeys.entitlement,
    [KEY_PURPOSES.AUDIT_REQUEST]: purposeKeys.auditRequest,
    [KEY_PURPOSES.POLICY]: purposeKeys.policy,
    [KEY_PURPOSES.CATALOG_GLOBAL]: purposeKeys.catalogGlobal,
    [KEY_PURPOSES.CATALOG_DISTRIBUTION]: purposeKeys.catalogDistribution,
  };
  if (pairs[purpose]) return pairs[purpose];
  if (AUTHORITY_DEFINITIONS[purpose].identityType !== 'ed25519_public') return null;
  return crypto.generateKeyPairSync('ed25519');
}

function authorityKeyId(purpose, definition, pair) {
  const configured = {
    [KEY_PURPOSES.ONLINE_VERDICT]: KEY_IDS.onlineVerdict,
    [KEY_PURPOSES.ENTITLEMENT]: KEY_IDS.entitlement,
    [KEY_PURPOSES.AUDIT_REQUEST]: KEY_IDS.auditRequest,
    [KEY_PURPOSES.POLICY]: KEY_IDS.policy,
    [KEY_PURPOSES.CATALOG_GLOBAL]: KEY_IDS.catalogGlobal,
    [KEY_PURPOSES.CATALOG_DISTRIBUTION]: KEY_IDS.catalogDistribution,
  }[purpose];
  if (configured) return configured;
  if (purpose === KEY_PURPOSES.OFFLINE_LICENSE) return 'rw-offline-license-test-current';
  if (pair && purpose === KEY_PURPOSES.OWNER_ATTESTATION) {
    return 'rw-owner-attestation-test-current';
  }
  return `${definition.keyPrefix}test-current`;
}

function signed(payload, purpose) {
  const keyId = KEY_IDS[purpose];
  const keys = purposeKeys[purpose];
  return {
    keyId,
    payload,
    signature: crypto.sign(null, protocol.signingInput(payload, keyId), keys.privateKey).toString('base64'),
  };
}

function unvalidatedSigned(payload, purpose) {
  const keyId = KEY_IDS[purpose];
  const keys = purposeKeys[purpose];
  const domain = protocol.SIGNATURE_DOMAINS[payload.kind];
  const input = Buffer.from(`${domain}\0${keyId}\0${protocol.canonicalJson(payload)}`, 'utf8');
  return {
    keyId,
    payload,
    signature: crypto.sign(null, input, keys.privateKey).toString('base64'),
  };
}

function publicPem(keys) {
  return keys.publicKey.export({ type: 'spki', format: 'pem' }).toString();
}

function opaqueReference(key, kind, value) {
  return `${kind}_${crypto.createHmac('sha256', key).update(String(value)).digest('base64url').slice(0, 24)}`;
}

function sha256(value) {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

function hmac(key, value) {
  return crypto.createHmac('sha256', key).update(value, 'utf8').digest('hex');
}

function safeHexEqual(left, right) {
  if (!/^[a-f0-9]{64}$/.test(String(left || '')) || !/^[a-f0-9]{64}$/.test(String(right || ''))) return false;
  return crypto.timingSafeEqual(Buffer.from(left, 'hex'), Buffer.from(right, 'hex'));
}

function clone(value) {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}

function expectCode(callback, code) {
  assert.throws(callback, (error) => error && error.code === code);
}

function expectCodeNoEcho(callback, code, sensitiveValue) {
  assert.throws(callback, (error) => {
    const exposed = deepExposure(error);
    return error && error.code === code && !exposed.includes(sensitiveValue);
  });
}

function captureConsole(callback) {
  const methods = ['debug', 'error', 'info', 'log', 'warn'];
  const originals = new Map(methods.map((method) => [method, console[method]]));
  const records = [];
  try {
    for (const method of methods) console[method] = (...args) => records.push({ method, args });
    callback();
    return records;
  } finally {
    for (const [method, original] of originals) console[method] = original;
  }
}

function deepExposure(value, seen = new Set(), depth = 0) {
  if (value === null || value === undefined || typeof value !== 'object') return String(value);
  if (seen.has(value) || depth > 8) return '[bounded]';
  seen.add(value);
  const output = [];
  for (const key of Reflect.ownKeys(value)) {
    output.push(String(key));
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor && Object.hasOwn(descriptor, 'value')) {
      output.push(deepExposure(descriptor.value, seen, depth + 1));
    } else if (descriptor) {
      output.push(String(descriptor.get), String(descriptor.set));
    }
  }
  seen.delete(value);
  return output.join('\n');
}
