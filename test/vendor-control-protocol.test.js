'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const protocol = require('../server/vendor-control-protocol');

const {
  CHANNEL_KINDS,
  DEFAULT_FALLBACK_WINDOW_MS,
  DEFAULT_HEARTBEAT_INTERVAL_MS,
  MAX_FALLBACK_WINDOW_MS,
} = protocol;

const IDS = Object.freeze({
  schemaVersion: 1,
  messageId: '12e5ad65-7d8f-42c2-b7af-5e89b2836e19',
  customerId: 'cu-protocol-1',
  deploymentId: 'dep_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
});

const GLOBAL_IDS = Object.freeze({
  schemaVersion: 1,
  messageId: '12e5ad65-7d8f-42c2-b7af-5e89b2836e19',
});

function globalCatalog(overrides = {}) {
  const records = overrides.records || [{
    catalogId: 'example-ai', registrableDomain: 'example.ai', aliases: ['example.com'],
    classification: 'generative_ai', riskTier: 'moderate', analystState: 'approved',
    evidenceClass: 'public_documentation', confidenceBps: 9000,
  }];
  return {
    ...GLOBAL_IDS,
    kind: CHANNEL_KINDS.GLOBAL_CATALOG_RELEASE,
    authorityManifestGeneration: 1,
    authorityManifestKeySlot: 'current',
    globalReleaseId: '0fd7dc3a-c301-4f78-93a9-237ff8ebebf8',
    globalVersion: 4,
    previousGlobalVersion: 3,
    rollbackOfGlobalVersion: null,
    issuedAt: '2026-07-12T12:00:00.000Z',
    recordsDigest: protocol.catalogRecordsDigest(records),
    records,
    ...overrides,
  };
}

function catalogDistribution(overrides = {}) {
  return {
    ...IDS,
    kind: CHANNEL_KINDS.CATALOG_DISTRIBUTION,
    authorityManifestGeneration: 1,
    authorityManifestKeySlot: 'current',
    distributionSequence: 2,
    previousDistributionSequence: 1,
    globalReleaseId: '0fd7dc3a-c301-4f78-93a9-237ff8ebebf8',
    globalVersion: 57,
    globalArtifactDigest: 'a'.repeat(64),
    recordsDigest: 'b'.repeat(64),
    rollout: { mode: 'required', cohortBps: 10_000 },
    issuedAt: '2026-07-12T12:00:00.000Z',
    ...overrides,
  };
}

function heartbeat(overrides = {}) {
  return {
    ...IDS,
    kind: CHANNEL_KINDS.HEARTBEAT,
    heartbeatNonce: 'R4ndomHeartbeatNonce_1234567890',
    plan: 'standard',
    seatsUsed: 12,
    seatLimit: 25,
    version: '1.2.3',
    sentAt: '2026-07-12T12:00:00.000Z',
    lastAppliedEntitlementVersion: 7,
    lastAppliedRegistryGeneration: 8,
    lastAppliedPolicyVersion: 4,
    lastAppliedCatalogVersion: 9,
    ...overrides,
  };
}

function entitlement(overrides = {}) {
  return {
    ...IDS,
    kind: CHANNEL_KINDS.ENTITLEMENT,
    status: 'active',
    plan: 'enterprise',
    seats: 75,
    features: ['ncua-readiness', 'shadow-ai'],
    entitlementVersion: 8,
    previousVersion: 7,
    issuedAt: '2026-07-12T12:00:00.000Z',
    expiresAt: '2026-07-12T12:05:00.000Z',
    fallbackUntil: '2026-07-15T12:00:00.000Z',
    reasonCode: 'billing_active',
    ...overrides,
  };
}

test('heartbeat is a strict prompt-free business envelope', () => {
  assert.equal(protocol.parseChannel(heartbeat()).ok, true);
  const missingRegistryGeneration = heartbeat();
  delete missingRegistryGeneration.lastAppliedRegistryGeneration;
  assert.equal(protocol.parseChannel(missingRegistryGeneration).ok, false);
  assert.equal(protocol.parseChannel(heartbeat({ lastAppliedRegistryGeneration: -1 })).ok, false);
  for (const forbidden of [
    { prompt: 'synthetic secret' },
    { rawText: '123-45-6789' },
    { fileName: 'member-123.pdf' },
    { url: 'https://member.example/private' },
    { diagnostics: { error: 'stack' } },
  ]) {
    const result = protocol.parseChannel({ ...heartbeat(), ...forbidden });
    assert.deepEqual(result, { ok: false, error: 'channel_schema_invalid', issueCount: 1 });
  }
});

test('legacy broad deployment identities are rejected by every tenant channel', () => {
  assert.equal(protocol.parseChannel(heartbeat({
    deploymentId: 'deployment_alpha_001',
  })).ok, false);
});

test('separate typed channels reject cross-channel field smuggling', () => {
  const diagnostic = {
    ...IDS,
    kind: CHANNEL_KINDS.DIAGNOSTIC,
    correlationId: '150949ef-ddff-4bf9-803c-f4353f66dc36',
    component: 'connector',
    code: 'CONNECTOR_TIMEOUT',
    severity: 'warning',
    outcome: 'retrying',
    countBucket: '1',
    sizeBucket: 'none',
    durationBucket: '5-30s',
    retryState: 'scheduled',
    componentVersion: '1.2.3',
    occurredAt: '2026-07-12T12:00:00.000Z',
  };
  assert.equal(protocol.parseChannel(diagnostic, CHANNEL_KINDS.DIAGNOSTIC).ok, true);
  assert.equal(protocol.parseChannel({ ...diagnostic, seatsUsed: 12 }).ok, false);
  assert.equal(protocol.parseChannel(diagnostic, CHANNEL_KINDS.HEARTBEAT).error, 'channel_kind_invalid');
});

test('entitlement binds authority and enforces bounded fallback semantics', () => {
  assert.equal(protocol.parseChannel(entitlement()).ok, true);
  assert.equal(protocol.parseChannel(entitlement({ fallbackUntil: '2026-07-19T12:00:00.001Z' })).ok, false);
  assert.equal(protocol.parseChannel(entitlement({ previousVersion: 8 })).ok, false);
  assert.equal(protocol.parseChannel(entitlement({ status: 'paused', fallbackUntil: null, reasonCode: 'manual_pause' })).ok, true);
  assert.equal(protocol.parseChannel(entitlement({ status: 'paused' })).ok, false);
  assert.equal(protocol.parseChannel(entitlement({ status: 'revoked', fallbackUntil: null, reasonCode: 'manual_revoke' })).ok, true);
});

test('policy rollback is explicit, linked, and always names an older version', () => {
  const policy = {
    ...IDS,
    kind: CHANNEL_KINDS.POLICY_DESIRED_STATE,
    policyVersion: 3,
    previousVersion: 2,
    rollbackOfVersion: 1,
    bundleDigest: 'a'.repeat(64),
    mandatoryControlsDigest: 'b'.repeat(64),
    issuedAt: '2026-07-12T12:00:00.000Z',
    expiresAt: '2026-07-13T12:00:00.000Z',
    rollout: 'required',
  };
  assert.equal(protocol.parseChannel(policy).ok, true);
  assert.equal(protocol.parseChannel({ ...policy, rollbackOfVersion: 3 }).ok, false);
  assert.equal(protocol.parseChannel({ ...policy, rollbackOfVersion: null }).ok, true);
});

test('canonical signing input is property-order independent and domain separated', () => {
  const first = entitlement();
  const second = Object.fromEntries(Object.entries(first).reverse());
  assert.equal(protocol.payloadDigest(first), protocol.payloadDigest(second));
  assert.deepEqual(
    protocol.signingInput(first, 'entitlement-2026-01'),
    protocol.signingInput(second, 'entitlement-2026-01'),
  );
  assert.match(
    protocol.signingInput(first, 'entitlement-2026-01').toString('utf8'),
    /^redactwall\.vendor-entitlement\.v1\0entitlement-2026-01\0/,
  );
  assert.notDeepEqual(
    protocol.signingInput(first, 'entitlement-2026-01'),
    protocol.signingInput(first, 'entitlement-2026-02'),
  );
  assert.throws(
    () => protocol.signingInput(heartbeat(), 'entitlement-2026-01'),
    (error) => error.code === 'channel_not_signed',
  );
});

test('calendar times, canonical sets, and aggregate domains reject covert metadata', () => {
  assert.equal(protocol.parseChannel(entitlement({ issuedAt: '2026-99-12T12:00:00.000Z' })).ok, false);
  assert.equal(protocol.parseChannel(heartbeat({ version: '1.2.3-secret' })).ok, false);
  assert.equal(protocol.parseChannel(entitlement({ features: ['shadow-ai', 'ncua-readiness'] })).ok, false);
  const candidate = {
    ...IDS,
    kind: CHANNEL_KINDS.SHADOW_CANDIDATE,
    candidateId: '76aa038c-adb4-4cde-b5d7-aed3f6a008cc',
    registrableDomain: 'example.ai', sourceType: 'browser_destination',
    firstSeenDay: '2026-07-12', observationCountBucket: '1', confidenceBps: 8000,
    localClassification: 'unknown', localOutcome: 'observed',
  };
  assert.equal(protocol.parseChannel(candidate).ok, true);
  assert.equal(protocol.parseChannel({ ...candidate, registrableDomain: 'member-123.example.ai' }).ok, false);
  assert.equal(protocol.parseChannel({ ...candidate, registrableDomain: 'ssn-123456789.example' }).ok, false);
  assert.equal(protocol.parseChannel({ ...candidate, registrableDomain: 'john-smith.internal' }).ok, false);
  assert.equal(protocol.parseChannel({ ...candidate, sourceType: 'dns_import' }).ok, false);
  assert.equal(protocol.parseChannel({ ...candidate, firstSeenDay: '2026-02-30' }).ok, false);
});

test('monotonic entitlement decision rejects replay and same-version conflict', () => {
  const original = entitlement();
  const accepted = protocol.entitlementDecision(original);
  assert.equal(accepted.action, 'apply');

  const current = { version: original.entitlementVersion, digest: accepted.digest };
  assert.equal(protocol.entitlementDecision(original, current).action, 'acknowledge');
  assert.deepEqual(
    protocol.entitlementDecision(entitlement({ seats: 74 }), current),
    { action: 'reject', reason: 'version_conflict' },
  );
  assert.deepEqual(
    protocol.entitlementDecision(entitlement({ entitlementVersion: 7, previousVersion: 6 }), current),
    { action: 'reject', reason: 'stale_version' },
  );
});

test('delivery lifecycle cannot skip or regress acknowledgement stages', () => {
  assert.deepEqual(protocol.lifecycleTransition('requested', 'issued'), { ok: true, idempotent: false });
  assert.deepEqual(protocol.lifecycleTransition('issued', 'issued'), { ok: true, idempotent: true });
  assert.deepEqual(protocol.lifecycleTransition('issued', 'applied'), { ok: false, reason: 'stage_skipped' });
  assert.deepEqual(protocol.lifecycleTransition('acknowledged', 'applied'), { ok: false, reason: 'stage_regression' });
});

test('heartbeat and outage fallback configuration are bounded, never silently clamped', () => {
  assert.equal(protocol.heartbeatIntervalMs(), DEFAULT_HEARTBEAT_INTERVAL_MS);
  assert.equal(protocol.heartbeatIntervalMs(30_000), 30_000);
  assert.equal(protocol.heartbeatIntervalMs(300_000), 300_000);
  assert.throws(() => protocol.heartbeatIntervalMs(29_999), RangeError);
  assert.throws(() => protocol.heartbeatIntervalMs(300_001), RangeError);

  assert.equal(protocol.fallbackWindowMs(), DEFAULT_FALLBACK_WINDOW_MS);
  assert.equal(protocol.fallbackWindowMs(MAX_FALLBACK_WINDOW_MS), MAX_FALLBACK_WINDOW_MS);
  assert.throws(() => protocol.fallbackWindowMs(MAX_FALLBACK_WINDOW_MS + 1), RangeError);
});

test('fallback is automatic only for a proven active connection and genuine outage', () => {
  const entitlementValue = entitlement();
  const state = {
    connectedEver: true,
    highWaterIntact: true,
    entitlement: entitlementValue,
    failureClass: 'transport_unavailable',
    trustedTimeMs: Date.parse(entitlementValue.issuedAt),
  };
  assert.equal(
    protocol.fallbackDisposition(state, Date.parse('2026-07-13T12:00:00.000Z')).mode,
    'degraded_fallback',
  );
  assert.equal(protocol.fallbackDisposition({ ...state, connectedEver: false }).reason, 'connected_state_missing');
  assert.equal(protocol.fallbackDisposition({ ...state, highWaterIntact: false }).reason, 'connected_state_missing');
  assert.equal(protocol.fallbackDisposition({ ...state, failureClass: 'invalid_signature' }).reason, 'fallback_failure_not_transport');
  assert.equal(protocol.fallbackDisposition({ ...state, entitlement: entitlement({ status: 'paused', fallbackUntil: null, reasonCode: 'manual_pause' }) }).reason, 'vendor_state_blocks_fallback');
  assert.equal(protocol.fallbackDisposition(state, Date.parse('2026-07-15T12:00:00.001Z')).reason, 'fallback_expired');
  assert.equal(protocol.fallbackDisposition({ ...state, trustedTimeMs: Date.parse('2026-07-14T12:00:00.000Z') }, Date.parse('2026-07-12T12:00:00.000Z')).reason, 'clock_rollback');
});

test('shadow AI, catalog, policy, audit, and ACK channels stay bounded and strict', () => {
  const samples = [
    {
      ...IDS, kind: CHANNEL_KINDS.SHADOW_CANDIDATE,
      candidateId: '76aa038c-adb4-4cde-b5d7-aed3f6a008cc',
      registrableDomain: 'example.ai', sourceType: 'browser_destination',
      firstSeenDay: '2026-07-12', observationCountBucket: '2-5', confidenceBps: 8500,
      localClassification: 'generative_ai', localOutcome: 'blocked',
    },
    globalCatalog(),
    catalogDistribution(),
    {
      ...IDS, kind: CHANNEL_KINDS.POLICY_DESIRED_STATE,
      policyVersion: 3, previousVersion: 2, rollbackOfVersion: null, bundleDigest: 'a'.repeat(64),
      mandatoryControlsDigest: 'b'.repeat(64), issuedAt: '2026-07-12T12:00:00.000Z',
      expiresAt: '2026-07-13T12:00:00.000Z', rollout: 'staged',
    },
    {
      ...IDS, kind: CHANNEL_KINDS.AUDIT_REQUEST,
      requestId: '989b520d-23a3-48ea-af30-c601e809e5de', requestVersion: 1,
      requestType: 'integrity_status', purposeCode: 'customer_support',
      notBefore: '2026-07-12T12:00:00.000Z', expiresAt: '2026-07-12T13:00:00.000Z',
      maxRecords: 1, fields: ['integrity_status'],
    },
    {
      ...IDS, kind: CHANNEL_KINDS.AUDIT_RESPONSE,
      requestId: '989b520d-23a3-48ea-af30-c601e809e5de', requestVersion: 1,
      status: 'completed', reasonCode: 'completed', respondedAt: '2026-07-12T12:30:00.000Z',
      summaries: [{
        field: 'integrity_status', valueCode: 'intact', version: null,
        coarseTimestamp: null, count: 1,
      }],
    },
    {
      ...IDS, kind: CHANNEL_KINDS.ACKNOWLEDGEMENT,
      targetKind: CHANNEL_KINDS.ENTITLEMENT, targetVersion: 8,
      targetDigest: 'c'.repeat(64), lifecycleStage: 'applied', outcome: 'success',
      reasonCode: 'applied', recordedAt: '2026-07-12T12:00:00.000Z',
    },
  ];
  for (const sample of samples) {
    assert.equal(protocol.parseChannel(sample).ok, true, sample.kind);
    assert.equal(protocol.parseChannel({ ...sample, note: 'free-form text is forbidden' }).ok, false, sample.kind);
  }
});

test('rejected analyst records can never enter a signed global catalog release', () => {
  const release = globalCatalog({
    globalVersion: 1,
    previousGlobalVersion: 0,
    records: [{
      catalogId: 'example-ai', registrableDomain: 'example.ai', aliases: [],
      classification: 'generative_ai', riskTier: 'high', analystState: 'rejected',
      evidenceClass: 'customer_aggregate', confidenceBps: 9000,
    }],
  });
  release.recordsDigest = protocol.catalogRecordsDigest(release.records);
  assert.equal(protocol.parseChannel(release).ok, false);
  release.records[0].analystState = 'approved';
  release.recordsDigest = protocol.catalogRecordsDigest(release.records);
  assert.equal(protocol.parseChannel(release).ok, true);
});

test('catalog releases reject every duplicate primary or alias claim', () => {
  const release = globalCatalog({
    globalVersion: 1,
    previousGlobalVersion: 0,
    records: [
      {
        catalogId: 'alpha-ai', registrableDomain: 'alpha.ai', aliases: ['shared.ai'],
        classification: 'generative_ai', riskTier: 'high', analystState: 'approved',
        evidenceClass: 'public_documentation', confidenceBps: 9000,
      },
      {
        catalogId: 'beta-ai', registrableDomain: 'beta.ai', aliases: ['shared.ai'],
        classification: 'generative_ai', riskTier: 'moderate', analystState: 'approved',
        evidenceClass: 'vendor_validation', confidenceBps: 8000,
      },
    ],
  });
  release.recordsDigest = protocol.catalogRecordsDigest(release.records);
  assert.equal(protocol.parseChannel(release).ok, false);
  release.records[1].aliases = ['unique.ai'];
  release.recordsDigest = protocol.catalogRecordsDigest(release.records);
  assert.equal(protocol.parseChannel(release).ok, true);
  release.records[1].registrableDomain = 'shared.ai';
  release.recordsDigest = protocol.catalogRecordsDigest(release.records);
  assert.equal(protocol.parseChannel(release).ok, false);
});

test('global catalog version and deployment distribution sequence are independent', () => {
  assert.throws(
    () => protocol.assertChannel(
      globalCatalog({ authorityManifestGeneration: 0 }),
      CHANNEL_KINDS.GLOBAL_CATALOG_RELEASE,
    ),
    { code: 'channel_schema_invalid' },
  );
  assert.throws(
    () => protocol.assertChannel(
      catalogDistribution({ authorityManifestGeneration: 0 }),
      CHANNEL_KINDS.CATALOG_DISTRIBUTION,
    ),
    { code: 'channel_schema_invalid' },
  );
  assert.equal(protocol.parseChannel(catalogDistribution({
    distributionSequence: 1,
    previousDistributionSequence: 0,
    globalVersion: 57,
  })).ok, true);
  assert.equal(protocol.parseChannel(catalogDistribution({
    distributionSequence: 2,
    previousDistributionSequence: 0,
  })).ok, false);
  const release = globalCatalog();
  release.recordsDigest = '0'.repeat(64);
  assert.equal(protocol.parseChannel(release).ok, false);
});

test('customer ACK and audit response matrices reject contradictory states', () => {
  const ack = {
    ...IDS, kind: CHANNEL_KINDS.ACKNOWLEDGEMENT,
    targetKind: CHANNEL_KINDS.ENTITLEMENT, targetVersion: 8,
    targetDigest: 'c'.repeat(64), lifecycleStage: 'applied', outcome: 'success',
    reasonCode: 'applied', recordedAt: '2026-07-12T12:00:00.000Z',
  };
  assert.equal(protocol.parseChannel(ack).ok, true);
  assert.equal(protocol.parseChannel({ ...ack, lifecycleStage: 'acknowledged' }).ok, false);
  assert.equal(protocol.parseChannel({ ...ack, outcome: 'rejected' }).ok, false);
  assert.equal(protocol.parseChannel({ ...ack, lifecycleStage: 'delivered' }).ok, false);
  assert.equal(protocol.parseChannel({ ...ack, lifecycleStage: 'delivered', reasonCode: 'delivered' }).ok, true);
  assert.equal(protocol.parseChannel({ ...ack, outcome: 'rejected', reasonCode: 'invalid_signature' }).ok, true);

  const catalogAck = {
    ...ack,
    targetKind: CHANNEL_KINDS.CATALOG_DISTRIBUTION,
    targetVersion: 2,
    targetGlobalReleaseId: '0fd7dc3a-c301-4f78-93a9-237ff8ebebf8',
    targetGlobalVersion: 57,
    targetGlobalArtifactDigest: 'a'.repeat(64),
  };
  assert.equal(protocol.parseChannel(catalogAck).ok, true);
  assert.equal(protocol.parseChannel({ ...catalogAck, targetGlobalReleaseId: undefined }).ok, false);
  assert.equal(protocol.parseChannel({ ...ack, targetGlobalVersion: 57 }).ok, false);

  const response = {
    ...IDS, kind: CHANNEL_KINDS.AUDIT_RESPONSE,
    requestId: '989b520d-23a3-48ea-af30-c601e809e5de', requestVersion: 1,
    status: 'completed', reasonCode: 'completed', respondedAt: '2026-07-12T12:30:00.000Z',
    summaries: [],
  };
  assert.equal(protocol.parseChannel(response).ok, true);
  assert.equal(protocol.parseChannel({ ...response, status: 'approved' }).ok, false);
  assert.equal(protocol.parseChannel({ ...response, status: 'approved', reasonCode: 'customer_approved' }).ok, true);
  assert.equal(protocol.parseChannel({ ...response, status: 'denied', reasonCode: 'customer_denied' }).ok, true);
  assert.equal(protocol.parseChannel({ ...response, status: 'denied', reasonCode: 'completed' }).ok, false);
});

test('channel parsing validates one immutable JSON snapshot', () => {
  let reads = 0;
  const value = heartbeat();
  Object.defineProperty(value, 'kind', {
    enumerable: true,
    get() {
      reads += 1;
      return reads === 1 ? CHANNEL_KINDS.HEARTBEAT : CHANNEL_KINDS.DIAGNOSTIC;
    },
  });
  const parsed = protocol.parseChannel(value, CHANNEL_KINDS.HEARTBEAT);
  assert.equal(parsed.ok, true);
  assert.equal(reads, 1);
  assert.equal(parsed.value.kind, CHANNEL_KINDS.HEARTBEAT);
});
