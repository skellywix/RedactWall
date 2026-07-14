'use strict';

const crypto = require('node:crypto');
const test = require('node:test');
const assert = require('node:assert/strict');

const ORIGINAL_NODE_ENV = process.env.NODE_ENV;
process.env.NODE_ENV = 'test';
test.after(() => {
  if (ORIGINAL_NODE_ENV === undefined) delete process.env.NODE_ENV;
  else process.env.NODE_ENV = ORIGINAL_NODE_ENV;
});

const protocol = require('../server/vendor-control-protocol');
const {
  createReferenceMonotonicAnchorAuthority,
  createReferenceMonotonicAnchorStorage,
} = require('../server/monotonic-anchor-authority');
const {
  AUTHORITY_DEFINITIONS,
  KEY_PURPOSES,
  keyFingerprint,
} = require('../server/vendor-signed-artifact');
const {
  INTEGRITY_DOMAINS,
  GLOBAL_ROLLBACK_WINDOW,
  DISTRIBUTION_ROLLBACK_WINDOW,
  MAX_GLOBAL_HISTORY_TOMBSTONES,
  MAX_ACTIVE_AUDIT_EVENTS,
  MAX_CLASSIFICATIONS,
  MAX_DISTRIBUTIONS_PER_DEPLOYMENT,
  MAX_GLOBAL_RELEASES,
  MAX_OBSERVATIONS_PER_SCOPE,
  MAX_PAGE_SIZE,
  OBSERVATION_RETENTION_MS,
  createVendorShadowAiIntelligence,
} = require('../server/vendor-shadow-ai-intelligence');

const NOW = Date.parse('2026-07-12T20:00:00.000Z');
const SCOPE_A = Object.freeze({
  customerId: 'customer_alpha', deploymentId: 'dep_88888888888888888888888888888888',
});
const SCOPE_B = Object.freeze({
  customerId: 'customer_beta', deploymentId: 'dep_99999999999999999999999999999999',
});
const CONSENT_A = '00000000-0000-4000-8000-0000000000a1';
const CONSENT_B = '00000000-0000-4000-8000-0000000000b1';
const currentKeys = crypto.generateKeyPairSync('ed25519');
const nextKeys = crypto.generateKeyPairSync('ed25519');
const archiveOnlyKeys = crypto.generateKeyPairSync('ed25519');
const distributionCurrentKeys = crypto.generateKeyPairSync('ed25519');
const distributionNextKeys = crypto.generateKeyPairSync('ed25519');
const distributionArchiveKeys = crypto.generateKeyPairSync('ed25519');
const forbiddenKeys = Array.from({ length: 5 }, () => crypto.generateKeyPairSync('ed25519'));

function createHarness(options = {}) {
  const storage = options.storage || new MemoryIntelligenceStorage();
  const time = options.time || { now: NOW };
  const integritySecret = options.integritySecret || Buffer.alloc(32, 0x5a);
  const auditSecret = options.auditSecret || Buffer.alloc(32, 0x5b);
  const commandSecret = options.commandSecret || Buffer.alloc(32, 0x5c);
  const paginationSecret = options.paginationSecret || Buffer.alloc(32, 0x5d);
  const anchorStorage = options.anchorStorage || createReferenceMonotonicAnchorStorage();
  const archivedPublicKeys = options.archivedPublicKeys || new Map([
    ['rw-catalog-global-current', currentKeys.publicKey],
    ['rw-catalog-global-next', nextKeys.publicKey],
    ['rw-catalog-global-archive', archiveOnlyKeys.publicKey],
  ]);
  const distributionArchivedPublicKeys = options.distributionArchivedPublicKeys || new Map([
    ['rw-catalog-distribution-current', distributionCurrentKeys.publicKey],
    ['rw-catalog-distribution-next', distributionNextKeys.publicKey],
    ['rw-catalog-distribution-archive', distributionArchiveKeys.publicKey],
  ]);
  const forbiddenPublicKeyFingerprints = options.forbiddenPublicKeyFingerprints || {
    offline_license: keyFingerprint(forbiddenKeys[0].publicKey),
    online_verdict: keyFingerprint(forbiddenKeys[1].publicKey),
    entitlement: keyFingerprint(forbiddenKeys[2].publicKey),
    policy: keyFingerprint(forbiddenKeys[3].publicKey),
    audit_request: keyFingerprint(forbiddenKeys[4].publicKey),
  };
  const catalogKeyAuthority = options.catalogKeyAuthority || (() => ({
    global: {
      current: { keyId: 'rw-catalog-global-current', privateKey: currentKeys.privateKey },
      next: { keyId: 'rw-catalog-global-next', privateKey: nextKeys.privateKey },
      archivedPublicKeys,
    },
    distribution: {
      current: { keyId: 'rw-catalog-distribution-current',
        privateKey: distributionCurrentKeys.privateKey },
      next: { keyId: 'rw-catalog-distribution-next',
        privateKey: distributionNextKeys.privateKey },
      archivedPublicKeys: distributionArchivedPublicKeys,
    },
    forbiddenPublicKeyFingerprints,
  }));
  const anchorAuthority = createReferenceMonotonicAnchorAuthority({
    storage: anchorStorage,
    keyId: 'rw-anchor-shadow-vendor',
    secret: options.anchorSecret || Buffer.alloc(32, 0x6a),
    purpose: 'owner_catalog_witness',
  });
  const intelligence = createVendorShadowAiIntelligence({
    storage: options.transactionStorage || storage,
    allowTestWitness: true,
    clock: () => time.now,
    randomUUID: crypto.randomUUID,
    catalogIntegrityAuthority: {
      keyId: 'rw-catalog-integrity-test', secret: integritySecret,
    },
    platformAuditAuthority: {
      keyId: 'rw-platform-audit-test', secret: auditSecret,
    },
    commandIdempotencyAuthority: {
      keyId: 'rw-command-idempotency-test', secret: commandSecret,
    },
    paginationCursorAuthority: {
      keyId: 'rw-pagination-cursor-test', secret: paginationSecret,
    },
    anchorAuthority,
    catalogKeyAuthority,
    authorityManifest: options.authorityManifest,
  });
  seedConsent(storage, CONSENT_A, SCOPE_A, time.now);
  seedConsent(storage, CONSENT_B, SCOPE_B, time.now);
  return { storage, anchorStorage, anchorAuthority, time, intelligence, catalogKeyAuthority,
    forbiddenPublicKeyFingerprints };
}

function seedConsent(storage, consentId, scope, now) {
  storage.consents.set(consentId, {
    schemaVersion: 1,
    consentId,
    ...scope,
    scope: 'shadow_ai_candidates',
    status: 'granted',
    revision: 1,
    grantedAt: new Date(now - 24 * 60 * 60 * 1000).toISOString(),
    revokedAt: null,
  });
}

function testAuthorityManifest(overrides = {}) {
  const publicPurposeKeys = {
    [KEY_PURPOSES.OFFLINE_LICENSE]: forbiddenKeys[0].publicKey,
    [KEY_PURPOSES.ONLINE_VERDICT]: forbiddenKeys[1].publicKey,
    [KEY_PURPOSES.ENTITLEMENT]: forbiddenKeys[2].publicKey,
    [KEY_PURPOSES.POLICY]: forbiddenKeys[3].publicKey,
    [KEY_PURPOSES.AUDIT_REQUEST]: forbiddenKeys[4].publicKey,
  };
  const records = Object.fromEntries(Object.entries(AUTHORITY_DEFINITIONS)
    .map(([purpose, definition]) => [purpose, [{
      purpose,
      slot: 'current',
      keyId: `${definition.keyPrefix}test-manifest`,
      identity: publicPurposeKeys[purpose]
        ? keyFingerprint(publicPurposeKeys[purpose]) : digestText(`manifest:${purpose}`),
    }]]));
  records[KEY_PURPOSES.PLATFORM_AUDIT] = [{
    purpose: KEY_PURPOSES.PLATFORM_AUDIT,
    slot: 'current',
    keyId: 'rw-platform-audit-test',
    identity: digestBytes(Buffer.alloc(32, 0x5b)),
  }];
  records[KEY_PURPOSES.COMMAND_IDEMPOTENCY] = [{
    purpose: KEY_PURPOSES.COMMAND_IDEMPOTENCY,
    slot: 'current',
    keyId: 'rw-command-idempotency-test',
    identity: digestBytes(Buffer.alloc(32, 0x5c)),
  }];
  records[KEY_PURPOSES.PAGINATION_CURSOR] = [{
    purpose: KEY_PURPOSES.PAGINATION_CURSOR,
    slot: 'current',
    keyId: 'rw-pagination-cursor-test',
    identity: digestBytes(Buffer.alloc(32, 0x5d)),
  }];
  records[KEY_PURPOSES.CATALOG_GLOBAL] = [
    { purpose: KEY_PURPOSES.CATALOG_GLOBAL, slot: 'current',
      keyId: 'rw-catalog-global-current', identity: keyFingerprint(currentKeys.publicKey) },
    { purpose: KEY_PURPOSES.CATALOG_GLOBAL, slot: 'next',
      keyId: 'rw-catalog-global-next', identity: keyFingerprint(nextKeys.publicKey) },
    { purpose: KEY_PURPOSES.CATALOG_GLOBAL, slot: 'verifyOnly',
      keyId: 'rw-catalog-global-archive', identity: keyFingerprint(archiveOnlyKeys.publicKey) },
  ];
  records[KEY_PURPOSES.CATALOG_DISTRIBUTION] = [
    { purpose: KEY_PURPOSES.CATALOG_DISTRIBUTION, slot: 'current',
      keyId: 'rw-catalog-distribution-current',
      identity: keyFingerprint(distributionCurrentKeys.publicKey) },
    { purpose: KEY_PURPOSES.CATALOG_DISTRIBUTION, slot: 'next',
      keyId: 'rw-catalog-distribution-next',
      identity: keyFingerprint(distributionNextKeys.publicKey) },
    { purpose: KEY_PURPOSES.CATALOG_DISTRIBUTION, slot: 'verifyOnly',
      keyId: 'rw-catalog-distribution-archive',
      identity: keyFingerprint(distributionArchiveKeys.publicKey) },
  ];
  for (const [purpose, patch] of Object.entries(overrides)) {
    records[purpose] = records[purpose].map((record, index) =>
      index === 0 ? { ...record, ...patch } : record);
  }
  const registry = Object.freeze({
    generation: 7,
    get(purpose) { return cloneValue(records[purpose]?.[0] || null); },
    list(purpose) { return cloneValue(records[purpose] || []); },
  });
  return Object.freeze({
    reconcile: () => ({ action: 'none' }),
    registry: () => registry,
  });
}

function mutableVendorAuthority() {
  const base = testAuthorityManifest().registry();
  let rotated = false;
  const globalArchive = new Map([
    ['rw-catalog-global-current', currentKeys.publicKey],
    ['rw-catalog-global-next', nextKeys.publicKey],
    ['rw-catalog-global-archive', archiveOnlyKeys.publicKey],
  ]);
  const distributionArchive = new Map([
    ['rw-catalog-distribution-current', distributionCurrentKeys.publicKey],
    ['rw-catalog-distribution-next', distributionNextKeys.publicKey],
    ['rw-catalog-distribution-archive', distributionArchiveKeys.publicKey],
  ]);
  const promotedRecords = (purpose, currentId, currentKey, priorId, priorKey, archiveId,
    archiveKey) => [
    { purpose, slot: 'current', keyId: currentId, identity: keyFingerprint(currentKey) },
    { purpose, slot: 'verifyOnly', keyId: priorId, identity: keyFingerprint(priorKey) },
    { purpose, slot: 'verifyOnly', keyId: archiveId, identity: keyFingerprint(archiveKey) },
  ];
  const manifest = Object.freeze({
    reconcile: () => ({ action: 'none' }),
    registry: () => {
      const global = rotated ? promotedRecords(
        KEY_PURPOSES.CATALOG_GLOBAL,
        'rw-catalog-global-next', nextKeys.publicKey,
        'rw-catalog-global-current', currentKeys.publicKey,
        'rw-catalog-global-archive', archiveOnlyKeys.publicKey,
      ) : base.list(KEY_PURPOSES.CATALOG_GLOBAL);
      const distribution = rotated ? promotedRecords(
        KEY_PURPOSES.CATALOG_DISTRIBUTION,
        'rw-catalog-distribution-next', distributionNextKeys.publicKey,
        'rw-catalog-distribution-current', distributionCurrentKeys.publicKey,
        'rw-catalog-distribution-archive', distributionArchiveKeys.publicKey,
      ) : base.list(KEY_PURPOSES.CATALOG_DISTRIBUTION);
      const entries = new Map([
        [KEY_PURPOSES.CATALOG_GLOBAL, global],
        [KEY_PURPOSES.CATALOG_DISTRIBUTION, distribution],
      ]);
      return Object.freeze({
        generation: rotated ? 8 : 7,
        get(purpose) { return cloneValue((entries.get(purpose) || base.list(purpose))[0]); },
        list(purpose) { return cloneValue(entries.get(purpose) || base.list(purpose)); },
      });
    },
  });
  const catalogKeyAuthority = () => ({
    global: {
      current: rotated
        ? { keyId: 'rw-catalog-global-next', privateKey: nextKeys.privateKey }
        : { keyId: 'rw-catalog-global-current', privateKey: currentKeys.privateKey },
      next: rotated ? null
        : { keyId: 'rw-catalog-global-next', privateKey: nextKeys.privateKey },
      archivedPublicKeys: globalArchive,
    },
    distribution: {
      current: rotated
        ? { keyId: 'rw-catalog-distribution-next', privateKey: distributionNextKeys.privateKey }
        : { keyId: 'rw-catalog-distribution-current',
          privateKey: distributionCurrentKeys.privateKey },
      next: rotated ? null
        : { keyId: 'rw-catalog-distribution-next',
          privateKey: distributionNextKeys.privateKey },
      archivedPublicKeys: distributionArchive,
    },
    forbiddenPublicKeyFingerprints: {
      offline_license: keyFingerprint(forbiddenKeys[0].publicKey),
      online_verdict: keyFingerprint(forbiddenKeys[1].publicKey),
      entitlement: keyFingerprint(forbiddenKeys[2].publicKey),
      policy: keyFingerprint(forbiddenKeys[3].publicKey),
      audit_request: keyFingerprint(forbiddenKeys[4].publicKey),
    },
  });
  return { manifest, catalogKeyAuthority, rotate: () => { rotated = true; } };
}

function digestBytes(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function authorize(storage, purpose, role, scope = null, overrides = {}) {
  const authEventId = crypto.randomUUID();
  storage.authorizations.set(authEventId, {
    schemaVersion: 1,
    authEventId,
    actorRole: role,
    customerId: scope?.customerId || null,
    deploymentId: scope?.deploymentId || null,
    authenticatedAt: new Date(NOW - 60_000).toISOString(),
    stepUpAt: needsStepUp(purpose) ? new Date(NOW - 30_000).toISOString() : null,
    expiresAt: new Date(NOW + 60 * 60_000).toISOString(),
    purposes: [purpose],
    ...overrides,
  });
  return authEventId;
}

function needsStepUp(purpose) {
  return ['analyst_review', 'global_publish', 'global_rollback',
    'distribution_create', 'distribution_deliver'].includes(purpose);
}

function confirm(storage, authEventId, purpose, operationDigest, overrides = {}) {
  const confirmationId = crypto.randomUUID();
  storage.confirmations.set(confirmationId, {
    schemaVersion: 1,
    confirmationId,
    authEventId,
    purpose,
    operationDigest,
    confirmedAt: new Date(NOW - 10_000).toISOString(),
    expiresAt: new Date(NOW + 290_000).toISOString(),
    ...overrides,
  });
  return confirmationId;
}

function candidate(scope, domain, overrides = {}) {
  return {
    schemaVersion: protocol.PROTOCOL_VERSION,
    messageId: crypto.randomUUID(),
    ...scope,
    kind: protocol.CHANNEL_KINDS.SHADOW_CANDIDATE,
    candidateId: crypto.randomUUID(),
    registrableDomain: domain,
    sourceType: 'browser_destination',
    firstSeenDay: '2026-07-12',
    observationCountBucket: '2-5',
    confidenceBps: 8000,
    localClassification: 'unknown',
    localOutcome: 'observed',
    ...overrides,
  };
}

function catalogRecord(catalogId, domain, overrides = {}) {
  return {
    catalogId,
    registrableDomain: domain,
    aliases: [],
    classification: 'generative_ai',
    riskTier: 'high',
    analystState: 'approved',
    evidenceClass: 'customer_aggregate',
    confidenceBps: 9000,
    ...overrides,
  };
}

async function ingest(harness, scope, consentId, domain, idempotencyKey, overrides = {}) {
  const authEventId = authorize(harness.storage, 'connector_ingest', 'customer_connector', scope);
  return harness.intelligence.ingestCandidate({
    authEventId,
    consentId,
    idempotencyKey: opaqueId(idempotencyKey),
    candidate: candidate(scope, domain),
    ...overrides,
  });
}

function reviewCommand(harness, observation, record, idempotencyKey, overrides = {}) {
  const authEventId = authorize(harness.storage, 'analyst_review', 'shadow_ai_analyst');
  const current = record ? harness.storage.classifications.get(record.catalogId)?.payload : null;
  return {
    authEventId,
    customerId: observation.customerId,
    deploymentId: observation.deploymentId,
    observationId: observation.observationId,
    expectedCandidateDigest: observation.candidateDigest,
    idempotencyKey: opaqueId(idempotencyKey),
    decision: record ? 'approve' : 'reject',
    reasonCode: record ? 'approved' : 'insufficient_evidence',
    catalogRecord: record,
    expectedClassificationRevision: current?.revision || null,
    expectedClassificationDigest: current?.recordDigest || null,
    domainOverrideConfirmationId: null,
    ...overrides,
  };
}

async function approve(harness, observation, record, idempotencyKey, overrides = {}) {
  return harness.intelligence.reviewCandidate(reviewCommand(
    harness, observation, record, idempotencyKey, overrides,
  ));
}

function publishCommand(harness, expectedGlobalVersion, idempotencyKey, keySlot = 'current') {
  const authEventId = authorize(harness.storage, 'global_publish', 'vendor_owner');
  const current = storedGlobal(harness, expectedGlobalVersion);
  const partial = {
    expectedGlobalVersion,
    expectedGlobalReleaseId: current?.globalReleaseId || null,
    expectedGlobalArtifactDigest: current?.artifactDigest || null,
    expectedGlobalRecordsDigest: current?.recordsDigest || null,
    idempotencyKey: opaqueId(idempotencyKey),
    keySlot,
  };
  const opDigest = digest({ ...partial, operation: 'publish' });
  return { authEventId, confirmationId: confirm(harness.storage, authEventId,
    'global_publish', opDigest), ...partial };
}

function rollbackCommand(harness, expectedGlobalVersion, targetVersion, idempotencyKey) {
  const authEventId = authorize(harness.storage, 'global_rollback', 'vendor_owner');
  const current = storedGlobal(harness, expectedGlobalVersion);
  const target = storedGlobal(harness, targetVersion);
  const partial = {
    expectedGlobalVersion,
    expectedGlobalReleaseId: current?.globalReleaseId || null,
    expectedGlobalArtifactDigest: current?.artifactDigest || null,
    expectedGlobalRecordsDigest: current?.recordsDigest || null,
    idempotencyKey: opaqueId(idempotencyKey),
    keySlot: 'current',
    operation: 'rollback',
    targetVersion,
    targetReleaseId: target?.globalReleaseId,
    targetArtifactDigest: target?.artifactDigest,
    targetRecordsDigest: target?.recordsDigest,
  };
  const opDigest = digest(partial);
  delete partial.operation;
  return { authEventId, confirmationId: confirm(harness.storage, authEventId,
    'global_rollback', opDigest), ...partial };
}

function distributionCommand(harness, scope, globalVersion, expectedDistributionSequence,
  idempotencyKey, rollout = { mode: 'staged', cohortBps: 2500 }) {
  const authEventId = authorize(harness.storage, 'distribution_create', 'catalog_publisher');
  const global = storedGlobal(harness, globalVersion);
  const partial = { ...scope, expectedDistributionSequence,
    globalReleaseId: global?.globalReleaseId,
    globalVersion,
    globalArtifactDigest: global?.artifactDigest,
    recordsDigest: global?.recordsDigest,
    idempotencyKey: opaqueId(idempotencyKey), keySlot: 'current', rollout };
  return { authEventId, confirmationId: confirm(harness.storage, authEventId,
    'distribution_create', digest(partial)), ...partial };
}

function storedGlobal(harness, version) {
  if (version === 0) return null;
  return harness.storage.globalReleases.get(version)?.payload || null;
}

function deliveryCommand(harness, distribution, expectedRevision) {
  const authEventId = authorize(harness.storage, 'distribution_deliver', 'catalog_publisher');
  const partial = { customerId: distribution.customerId,
    deploymentId: distribution.deploymentId, expectedRevision,
    distributionSequence: distribution.distributionSequence,
    globalReleaseId: distribution.globalReleaseId,
    globalVersion: distribution.globalVersion,
    globalArtifactDigest: distribution.globalArtifactDigest,
    recordsDigest: distribution.recordsDigest };
  const opDigest = digest({ ...partial, operation: 'mark_delivered' });
  return { authEventId, confirmationId: confirm(harness.storage, authEventId,
    'distribution_deliver', opDigest), ...partial };
}

function acknowledgement(distribution, outcome = 'success', overrides = {}) {
  return {
    schemaVersion: protocol.PROTOCOL_VERSION,
    messageId: crypto.randomUUID(),
    customerId: distribution.customerId,
    deploymentId: distribution.deploymentId,
    kind: protocol.CHANNEL_KINDS.ACKNOWLEDGEMENT,
    targetKind: protocol.CHANNEL_KINDS.CATALOG_DISTRIBUTION,
    targetVersion: distribution.distributionSequence,
    targetDigest: distribution.payloadDigest,
    targetGlobalReleaseId: distribution.globalReleaseId,
    targetGlobalVersion: distribution.globalVersion,
    targetGlobalArtifactDigest: distribution.globalArtifactDigest,
    lifecycleStage: 'applied',
    outcome,
    reasonCode: outcome === 'success' ? 'applied' : 'invalid_signature',
    recordedAt: new Date(NOW + 1_000).toISOString(),
    ...overrides,
  };
}

function acknowledgementCommand(harness, distribution, expectedRevision, value) {
  return {
    authEventId: authorize(harness.storage, 'customer_ack', 'customer_connector', {
      customerId: distribution.customerId, deploymentId: distribution.deploymentId,
    }),
    customerId: distribution.customerId,
    deploymentId: distribution.deploymentId,
    distributionSequence: distribution.distributionSequence,
    globalReleaseId: distribution.globalReleaseId,
    globalVersion: distribution.globalVersion,
    globalArtifactDigest: distribution.globalArtifactDigest,
    recordsDigest: distribution.recordsDigest,
    expectedRevision,
    acknowledgement: value,
  };
}

function statusCommand(authEventId, distribution) {
  return {
    authEventId,
    customerId: distribution.customerId,
    deploymentId: distribution.deploymentId,
    distributionSequence: distribution.distributionSequence,
    globalReleaseId: distribution.globalReleaseId,
    globalVersion: distribution.globalVersion,
    globalArtifactDigest: distribution.globalArtifactDigest,
    recordsDigest: distribution.recordsDigest,
  };
}

function digest(value) {
  return crypto.createHash('sha256').update(protocol.canonicalJson(value), 'utf8').digest('hex');
}

function digestText(value) {
  return crypto.createHash('sha256').update(String(value), 'utf8').digest('hex');
}

function sealIntegrity(domain, payload, secret = Buffer.alloc(32, 0x5b),
  keyId = 'rw-platform-audit-test') {
  return {
    integrityVersion: 1,
    keyId,
    domain,
    payload: cloneValue(payload),
    mac: crypto.createHmac('sha256', secret).update(Buffer.from(
      `${domain}\0${keyId}\0${protocol.canonicalJson(payload)}`, 'utf8',
    )).digest('hex'),
  };
}

function extendAuditChain(harness, count) {
  const { storage, anchorAuthority } = harness;
  const currentSequence = storage.auditHighWater?.payload.sequence || 0;
  let previousDigest = storage.auditHighWater?.payload.headDigest || '0'.repeat(64);
  const recordedAt = new Date(NOW).toISOString();
  for (let sequence = currentSequence + 1; sequence <= count; sequence += 1) {
    const descriptor = {
      schemaVersion: 1,
      sequence,
      action: 'shadow_seed_event',
      outcome: 'success',
      authorizationLinkId: 'a'.repeat(64),
      scopeDigest: 'b'.repeat(64),
      referenceDigest: digest({ sequence, purpose: 'audit-compaction-test' }),
      version: null,
      recordedAt,
    };
    const eventDigest = digestText(
      `${previousDigest}\0${protocol.canonicalJson(descriptor)}`,
    );
    const event = { ...descriptor, previousDigest, eventDigest };
    storage.audits.set(sequence, {
      digest: eventDigest,
      record: sealIntegrity(INTEGRITY_DOMAINS.AUDIT_EVENT, event),
    });
    const transition = {
      namespace: 'shadow-audit',
      expectedRevision: sequence - 1,
      expectedDigest: previousDigest,
      targetRevision: sequence,
      targetDigest: eventDigest,
      witnessDigest: digest(storage.audits.get(sequence).record),
    };
    anchorAuthority.prepare(transition);
    anchorAuthority.finalize(transition);
    previousDigest = eventDigest;
  }
  storage.auditHighWater = sealIntegrity(INTEGRITY_DOMAINS.AUDIT_HIGH_WATER, {
    schemaVersion: 1,
    sequence: count,
    count,
    headDigest: previousDigest,
    recordedAt,
  });
  storage.auditAnchor = { sequence: count, count, headDigest: previousDigest };
}

function opaqueId(value) {
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
    .test(value)) return value.toLowerCase();
  const bytes = crypto.createHash('sha256').update(String(value), 'utf8').digest().subarray(0, 16);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

async function expectCode(promise, code) {
  await assert.rejects(promise, (error) => error && error.code === code);
}

test('connected authority, consent revision, prompt-free schema, scope, and integrity are fail closed', async () => {
  const harness = createHarness();
  const alpha = await ingest(harness, SCOPE_A, CONSENT_A, 'alphaai.com', 'shadow-ingest-alpha-0001');
  const beta = await ingest(harness, SCOPE_B, CONSENT_B, 'betaai.com', 'shadow-ingest-beta-00001');
  assert.equal(JSON.stringify(harness.storage.observations).includes('prompt'), false);
  const listAuthA = authorize(harness.storage, 'customer_observation_read',
    'customer_security_admin', SCOPE_A);
  const pageA = await harness.intelligence.listCustomerObservations({
    authEventId: listAuthA, ...SCOPE_A, cursor: null, limit: 10,
  });
  assert.deepEqual(pageA.items.map((item) => item.observationId), [alpha.observationId]);
  assert.notEqual(alpha.observationId, beta.observationId);
  assert.equal(harness.storage.observations.values().next().value.domain,
    INTEGRITY_DOMAINS.OBSERVATION);

  const badAuth = authorize(harness.storage, 'connector_ingest', 'customer_connector', SCOPE_A,
    { expiresAt: new Date(NOW).toISOString() });
  await expectCode(harness.intelligence.ingestCandidate({
    authEventId: badAuth, consentId: CONSENT_A,
    idempotencyKey: opaqueId('shadow-ingest-alpha-0002'),
    candidate: candidate(SCOPE_A, 'expiredai.com'),
  }), 'authorization_invalid');
  const goodAuth = authorize(harness.storage, 'connector_ingest', 'customer_connector', SCOPE_A);
  await expectCode(harness.intelligence.ingestCandidate({
    authEventId: goodAuth, consentId: CONSENT_A,
    idempotencyKey: opaqueId('shadow-ingest-alpha-0003'),
    candidate: candidate(SCOPE_A, 'callerclock.com'), nowMs: NOW,
  }), 'ingest_command_invalid');
  await expectCode(harness.intelligence.ingestCandidate({
    authEventId: goodAuth, consentId: CONSENT_A,
    idempotencyKey: opaqueId('shadow-ingest-alpha-0004'),
    candidate: candidate(SCOPE_A, 'callerrole.com'), actorRole: 'vendor_owner',
  }), 'ingest_command_invalid');

  const wrapperKey = [...harness.storage.observations.keys()]
    .find((key) => key.includes(alpha.observationId));
  harness.storage.observations.get(wrapperKey).payload.candidate.registrableDomain = 'tamperedai.com';
  const tamperAuth = authorize(harness.storage, 'customer_observation_read',
    'customer_security_admin', SCOPE_A);
  await expectCode(harness.intelligence.listCustomerObservations({
    authEventId: tamperAuth, ...SCOPE_A, cursor: null, limit: 10,
  }), 'integrity_state_invalid');

  const badConsentHarness = createHarness();
  badConsentHarness.storage.consents.get(CONSENT_A).consentId = 'descriptive-consent-id';
  const badConsentAuth = authorize(badConsentHarness.storage, 'customer_observation_read',
    'customer_security_admin', SCOPE_A);
  await expectCode(badConsentHarness.intelligence.listCustomerObservations({
    authEventId: badConsentAuth, ...SCOPE_A, cursor: null, limit: 10,
  }), 'candidate_consent_invalid');
});

test('catalog, audit, command, and pagination domains use distinct authorities', async () => {
  assert.throws(() => createVendorShadowAiIntelligence({
    storage: new MemoryIntelligenceStorage(),
    integrityAuthority: { keyId: 'shadow-integrity-legacy', secret: Buffer.alloc(32, 0x5a) },
  }), { code: 'integrity_authority_split_required' });
  assert.throws(() => createHarness({ auditSecret: Buffer.alloc(32, 0x5a) }), {
    code: 'integrity_authority_identity_reused',
  });

  const harness = createHarness();
  await ingest(harness, SCOPE_A, CONSENT_A, 'domain-router-one.ai',
    'shadow-ingest-domain-router-001');
  await ingest(harness, SCOPE_A, CONSENT_A, 'domain-router-two.ai',
    'shadow-ingest-domain-router-002');
  assert.equal(harness.storage.observations.values().next().value.keyId,
    'rw-catalog-integrity-test');
  assert.equal(harness.storage.authorizationLinks.values().next().value.keyId,
    'rw-command-idempotency-test');
  assert.equal(harness.storage.audits.values().next().value.record.keyId,
    'rw-platform-audit-test');

  const readAuth = authorize(harness.storage, 'customer_observation_read',
    'customer_security_admin', SCOPE_A);
  const page = await harness.intelligence.listCustomerObservations({
    authEventId: readAuth, ...SCOPE_A, cursor: null, limit: 1,
  });
  assert.ok(page.nextCursor);
  assert.equal(harness.storage.pageSnapshots.values().next().value.pages[0].descriptor.keyId,
    'rw-pagination-cursor-test');
  const encodedCursor = JSON.parse(Buffer.from(page.nextCursor, 'base64url').toString('utf8'));
  assert.equal(encodedCursor.keyId, 'rw-pagination-cursor-test');
});

test('manifest generation and exact current or next slots bind every new catalog signature', async () => {
  const harness = createHarness({ authorityManifest: testAuthorityManifest() });
  const current = await harness.intelligence.publishGlobalCatalog(
    publishCommand(harness, 0, 'shadow-publish-manifest-current'),
  );
  assert.equal(current.artifact.payload.authorityManifestGeneration, 7);
  assert.equal(current.artifact.payload.authorityManifestKeySlot, 'current');
  const next = await harness.intelligence.publishGlobalCatalog(
    publishCommand(harness, 1, 'shadow-publish-manifest-next', 'next'),
  );
  assert.equal(next.artifact.payload.authorityManifestGeneration, 7);
  assert.equal(next.artifact.payload.authorityManifestKeySlot, 'next');
  const distribution = await harness.intelligence.createDistribution(distributionCommand(
    harness, SCOPE_A, 2, 0, 'shadow-distribute-manifest-current',
  ));
  assert.equal(distribution.distributionArtifact.payload.authorityManifestGeneration, 7);
  assert.equal(distribution.distributionArtifact.payload.authorityManifestKeySlot, 'current');

  const wrongAudit = createHarness({
    authorityManifest: testAuthorityManifest({
      [KEY_PURPOSES.PLATFORM_AUDIT]: { identity: 'e'.repeat(64) },
    }),
  });
  await expectCode(wrongAudit.intelligence.publishGlobalCatalog(
    publishCommand(wrongAudit, 0, 'shadow-publish-manifest-bad-audit'),
  ), 'catalog_key_authority_invalid');
  const wrongOffline = createHarness({
    authorityManifest: testAuthorityManifest({
      [KEY_PURPOSES.OFFLINE_LICENSE]: { identity: 'd'.repeat(64) },
    }),
  });
  await expectCode(wrongOffline.intelligence.publishGlobalCatalog(
    publishCommand(wrongOffline, 0, 'shadow-publish-manifest-bad-offline'),
  ), 'catalog_key_authority_invalid');
});

test('distribution creation requires a current-generation global republish after rotation', async () => {
  const authority = mutableVendorAuthority();
  const harness = createHarness({
    authorityManifest: authority.manifest,
    catalogKeyAuthority: authority.catalogKeyAuthority,
  });
  const first = await harness.intelligence.publishGlobalCatalog(
    publishCommand(harness, 0, 'shadow-publish-before-manifest-rotation'),
  );
  assert.equal(first.artifact.payload.authorityManifestGeneration, 7);
  authority.rotate();
  await expectCode(harness.intelligence.createDistribution(distributionCommand(
    harness, SCOPE_A, 1, 0, 'shadow-distribute-stale-global-generation',
  )), 'global_release_authority_stale');

  const republished = await harness.intelligence.publishGlobalCatalog(
    publishCommand(harness, 1, 'shadow-republish-after-manifest-rotation'),
  );
  assert.equal(republished.artifact.payload.authorityManifestGeneration, 8);
  const distribution = await harness.intelligence.createDistribution(distributionCommand(
    harness, SCOPE_A, 2, 0, 'shadow-distribute-current-global-generation',
  ));
  assert.equal(distribution.globalArtifact.payload.authorityManifestGeneration, 8);
  assert.equal(distribution.distributionArtifact.payload.authorityManifestGeneration, 8);
});

test('opaque references and recursive canary scanning keep prompt material out of commands, state, and audit', async () => {
  const commandHarness = createHarness();
  await expectCode(ingest(commandHarness, SCOPE_A, CONSENT_A, 'prompt-canary.com',
    'shadow-ingest-canary-command'), 'sensitive_metadata_forbidden');
  await expectCode(commandHarness.intelligence.ingestCandidate({
    authEventId: authorize(commandHarness.storage, 'connector_ingest',
      'customer_connector', SCOPE_A),
    consentId: CONSENT_A,
    idempotencyKey: 'descriptive-idempotency-key',
    candidate: candidate(SCOPE_A, 'opaque.com'),
  }), 'ingest_command_invalid');

  const stateHarness = createHarness();
  const observation = await ingest(stateHarness, SCOPE_A, CONSENT_A, 'opaquestate.com',
    'shadow-ingest-canary-state');
  const stored = stateHarness.storage.observations.get(
    scopedKey(SCOPE_A.customerId, SCOPE_A.deploymentId, observation.observationId));
  stored.payload.candidate.registrableDomain = 'sensitive-canary.com';
  reseal(stored, Buffer.alloc(32, 0x5a));
  const readAuth = authorize(stateHarness.storage, 'customer_observation_read',
    'customer_security_admin', SCOPE_A);
  await expectCode(stateHarness.intelligence.listCustomerObservations({
    authEventId: readAuth, ...SCOPE_A, cursor: null, limit: 10,
  }), 'sensitive_metadata_forbidden');

  const auditHarness = createHarness();
  await ingest(auditHarness, SCOPE_A, CONSENT_A, 'opaqueaudit.com',
    'shadow-ingest-canary-audit');
  auditHarness.storage.audits.get(1).record.payload.action = 'prompt-canary';
  reseal(auditHarness.storage.audits.get(1).record, Buffer.alloc(32, 0x5b));
  const auditReadAuth = authorize(auditHarness.storage, 'global_catalog_read', 'vendor_owner');
  await expectCode(auditHarness.intelligence.listGlobalClassifications({
    authEventId: auditReadAuth, cursor: null, limit: 10,
  }), 'sensitive_metadata_forbidden');
});

test('trusted customer-scoped vendor authority cannot cross tenants or exercise global authority', async () => {
  const reviewHarness = createHarness();
  const observation = await ingest(reviewHarness, SCOPE_B, CONSENT_B, 'scopedreview.com',
    'shadow-ingest-beta-scope01');
  const review = reviewCommand(reviewHarness, observation,
    catalogRecord('scoped-review', 'scopedreview.com'), 'shadow-review-beta-scope01');
  const reviewAuthority = reviewHarness.storage.authorizations.get(review.authEventId);
  reviewAuthority.customerId = SCOPE_A.customerId;
  reviewAuthority.deploymentId = SCOPE_A.deploymentId;
  await expectCode(reviewHarness.intelligence.reviewCandidate(review),
    'authorization_scope_invalid');

  const publishHarness = createHarness();
  const publish = publishCommand(publishHarness, 0, 'shadow-publish-global-scope1');
  const publishAuthority = publishHarness.storage.authorizations.get(publish.authEventId);
  publishAuthority.customerId = SCOPE_A.customerId;
  publishAuthority.deploymentId = SCOPE_A.deploymentId;
  await expectCode(publishHarness.intelligence.publishGlobalCatalog(publish),
    'authorization_scope_invalid');

  const distributionHarness = createHarness();
  await distributionHarness.intelligence.publishGlobalCatalog(
    publishCommand(distributionHarness, 0, 'shadow-publish-global-scope2'),
  );
  const distribution = distributionCommand(distributionHarness, SCOPE_B, 1, 0,
    'shadow-distribute-beta-scope1');
  const distributionAuthority = distributionHarness.storage.authorizations
    .get(distribution.authEventId);
  distributionAuthority.customerId = SCOPE_A.customerId;
  distributionAuthority.deploymentId = SCOPE_A.deploymentId;
  await expectCode(distributionHarness.intelligence.createDistribution(distribution),
    'authorization_scope_invalid');
});

test('analyst approval keeps customer evidence local, merges global intelligence, and governs domain overrides', async () => {
  const harness = createHarness();
  const alpha = await ingest(harness, SCOPE_A, CONSENT_A, 'sharedai.com', 'shadow-ingest-alpha-0101');
  const beta = await ingest(harness, SCOPE_B, CONSENT_B, 'sharedai.com', 'shadow-ingest-beta-00101');
  const analystQueueAuth = authorize(harness.storage, 'customer_observation_read',
    'shadow_ai_analyst');
  const analystQueue = await harness.intelligence.listCustomerObservations({
    authEventId: analystQueueAuth, ...SCOPE_A, cursor: null, limit: 10,
  });
  assert.deepEqual(analystQueue.items.map((item) => item.observationId), [alpha.observationId]);
  const first = await approve(harness, alpha, catalogRecord('shared-ai', 'sharedai.com'),
    'shadow-review-alpha-0101');
  const merged = await approve(harness, beta, catalogRecord('shared-ai', 'sharedai.com'),
    'shadow-review-beta-00101', { expectedClassificationRevision: 1 });
  assert.equal(first.classificationAction, 'created');
  assert.equal(merged.classificationAction, 'merged');
  const listAuth = authorize(harness.storage, 'global_catalog_read', 'shadow_ai_analyst');
  const global = await harness.intelligence.listGlobalClassifications({
    authEventId: listAuth, cursor: null, limit: 10,
  });
  assert.deepEqual(global.items, [catalogRecord('shared-ai', 'sharedai.com')]);
  assert.equal(JSON.stringify(global).includes('customer_alpha'), false);
  assert.equal(JSON.stringify(global).includes(alpha.observationId), false);

  const mismatch = await ingest(harness, SCOPE_A, CONSENT_A, 'localname.com',
    'shadow-ingest-alpha-0102');
  const noOverride = reviewCommand(harness, mismatch,
    catalogRecord('governed-name', 'globalname.com'), 'shadow-review-alpha-0102',
    { reasonCode: 'verified_override' });
  await expectCode(harness.intelligence.reviewCandidate(noOverride), 'classification_domain_mismatch');
  const overrideOp = digest({
    catalogRecord: noOverride.catalogRecord,
    customerId: noOverride.customerId,
    decision: noOverride.decision,
    deploymentId: noOverride.deploymentId,
    expectedCandidateDigest: noOverride.expectedCandidateDigest,
    expectedClassificationDigest: noOverride.expectedClassificationDigest,
    expectedClassificationRevision: noOverride.expectedClassificationRevision,
    idempotencyKey: noOverride.idempotencyKey,
    observationId: noOverride.observationId,
    reasonCode: noOverride.reasonCode,
  });
  noOverride.domainOverrideConfirmationId = confirm(harness.storage, noOverride.authEventId,
    'shadow_domain_override', overrideOp);
  assert.equal((await harness.intelligence.reviewCandidate(noOverride)).classificationAction, 'created');

  const aliasObservation = await ingest(harness, SCOPE_A, CONSENT_A, 'aliasprimary.com',
    'shadow-ingest-alpha-0103');
  const ungovernedAlias = reviewCommand(harness, aliasObservation,
    catalogRecord('alias-primary', 'aliasprimary.com', { aliases: ['aliasextra.com'] }),
    'shadow-review-alpha-0103');
  await expectCode(harness.intelligence.reviewCandidate(ungovernedAlias),
    'classification_domain_mismatch');

  const revoked = await ingest(harness, SCOPE_B, CONSENT_B, 'revokedai.com',
    'shadow-ingest-beta-00102');
  harness.storage.consents.get(CONSENT_B).status = 'revoked';
  harness.storage.consents.get(CONSENT_B).revokedAt = new Date(NOW).toISOString();
  harness.storage.consents.get(CONSENT_B).revision = 2;
  await expectCode(approve(harness, revoked, catalogRecord('revoked-ai', 'revokedai.com'),
    'shadow-review-beta-00102'), 'consent_revoked');
});

test('consent is prospective: revocation or deletion purges local observations but preserves de-linked global intelligence', async () => {
  const harness = createHarness();
  const approvedObservation = await ingest(harness, SCOPE_A, CONSENT_A,
    'prospectiveai.com', 'shadow-ingest-consent-001');
  const approvedRecord = catalogRecord('prospective-ai', 'prospectiveai.com');
  await approve(harness, approvedObservation, approvedRecord, 'shadow-review-consent-001');
  await ingest(harness, SCOPE_A, CONSENT_A, 'localonlyai.com',
    'shadow-ingest-consent-002');

  const consent = harness.storage.consents.get(CONSENT_A);
  consent.status = 'revoked';
  consent.revokedAt = new Date(NOW).toISOString();
  consent.revision = 2;
  const readAuth = authorize(harness.storage, 'customer_observation_read',
    'customer_security_admin', SCOPE_A);
  await expectCode(harness.intelligence.listCustomerObservations({
    authEventId: readAuth, ...SCOPE_A, cursor: null, limit: 10,
  }), 'consent_revoked');
  assert.equal([...harness.storage.observations.values()].filter((wrapped) =>
    wrapped.payload.customerId === SCOPE_A.customerId
      && wrapped.payload.deploymentId === SCOPE_A.deploymentId).length, 0);
  await expectCode(ingest(harness, SCOPE_A, CONSENT_A, 'blockedafterrevoke.com',
    'shadow-ingest-consent-003'), 'consent_revoked');

  const globalReadAuth = authorize(harness.storage, 'global_catalog_read', 'vendor_owner');
  const global = await harness.intelligence.listGlobalClassifications({
    authEventId: globalReadAuth, cursor: null, limit: 10,
  });
  assert.deepEqual(global.items, [approvedRecord]);
  const revokedPurge = [...harness.storage.audits.values()]
    .map((row) => row.record.payload)
    .find((event) => event.action === 'shadow_consent_local_data_purged'
      && event.outcome === 'revoked');
  assert.ok(revokedPurge);

  harness.storage.consents.delete(CONSENT_A);
  const deletedReadAuth = authorize(harness.storage, 'customer_observation_read',
    'customer_security_admin', SCOPE_A);
  await expectCode(harness.intelligence.listCustomerObservations({
    authEventId: deletedReadAuth, ...SCOPE_A, cursor: null, limit: 10,
  }), 'consent_deleted');
  const deletedPurge = [...harness.storage.audits.values()]
    .map((row) => row.record.payload)
    .find((event) => event.action === 'shadow_consent_local_data_purged'
      && event.outcome === 'deleted');
  assert.ok(deletedPurge);
});

test('consent epochs purge scope snapshots and permanently invalidate pre-revocation cursors', async () => {
  const harness = createHarness();
  await ingest(harness, SCOPE_A, CONSENT_A, 'cursorone.ai', 'shadow-ingest-cursor-001');
  await ingest(harness, SCOPE_A, CONSENT_A, 'cursortwo.ai', 'shadow-ingest-cursor-002');
  const firstAuth = authorize(harness.storage, 'customer_observation_read',
    'customer_security_admin', SCOPE_A);
  const first = await harness.intelligence.listCustomerObservations({
    authEventId: firstAuth, ...SCOPE_A, cursor: null, limit: 1,
  });
  assert.ok(first.nextCursor);
  assert.equal(harness.storage.pageSnapshots.size, 1);
  const originalEpoch = harness.storage.consentEpochs.values().next().value.payload.epoch;

  const consent = harness.storage.consents.get(CONSENT_A);
  consent.status = 'revoked';
  consent.revokedAt = new Date(NOW).toISOString();
  consent.revision = 2;
  const revokeAuth = authorize(harness.storage, 'customer_observation_read',
    'customer_security_admin', SCOPE_A);
  await expectCode(harness.intelligence.listCustomerObservations({
    authEventId: revokeAuth, ...SCOPE_A, cursor: null, limit: 1,
  }), 'consent_revoked');
  assert.equal(harness.storage.pageSnapshots.size, 0);

  consent.status = 'granted';
  consent.revokedAt = null;
  consent.revision = 3;
  const regrantAuth = authorize(harness.storage, 'customer_observation_read',
    'customer_security_admin', SCOPE_A);
  await expectCode(harness.intelligence.listCustomerObservations({
    authEventId: regrantAuth, ...SCOPE_A, cursor: first.nextCursor, limit: 1,
  }), 'page_cursor_invalid');
  const currentEpoch = harness.storage.consentEpochs.values().next().value.payload.epoch;
  assert.ok(currentEpoch > originalEpoch);
});

test('an unseen revoke and regrant cannot expose observations from the prior consent binding', async () => {
  const harness = createHarness();
  const idempotencyLabel = 'shadow-ingest-unseen-regrant-001';
  const prior = await ingest(harness, SCOPE_A, CONSENT_A, 'priorgrant.ai',
    idempotencyLabel);
  assert.equal(harness.storage.observations.size, 1);

  // The consent authority advances through revoke and regrant without a Shadow AI call in between.
  const consent = harness.storage.consents.get(CONSENT_A);
  consent.revision = 3;
  consent.grantedAt = new Date(NOW - 1_000).toISOString();
  consent.revokedAt = null;
  consent.status = 'granted';

  const readAuth = authorize(harness.storage, 'customer_observation_read',
    'customer_security_admin', SCOPE_A);
  const page = await harness.intelligence.listCustomerObservations({
    authEventId: readAuth, ...SCOPE_A, cursor: null, limit: 10,
  });
  assert.deepEqual(page.items, []);
  assert.equal(harness.storage.observations.size, 0);
  assert.equal(harness.storage.observationIdempotency.size, 0);
  const epoch = harness.storage.consentEpochs.values().next().value.payload;
  assert.equal(epoch.status, 'granted');
  assert.equal(epoch.consentRevision, 3);

  const replacement = await ingest(harness, SCOPE_A, CONSENT_A, 'newgrant.ai',
    idempotencyLabel);
  assert.notEqual(replacement.observationId, prior.observationId);
  assert.equal(replacement.candidate.registrableDomain, 'newgrant.ai');
});

test('the consent transition hook durably purges and witnesses a superseded grant', async () => {
  const harness = createHarness();
  await ingest(harness, SCOPE_A, CONSENT_A, 'hookprior.ai',
    'shadow-ingest-consent-hook-001');
  const consent = harness.storage.consents.get(CONSENT_A);
  consent.revision = 3;
  consent.grantedAt = new Date(NOW - 1_000).toISOString();

  const transition = await harness.intelligence.applyConsentTransition(SCOPE_A);
  assert.equal(transition.status, 'granted');
  assert.equal(transition.consentRevision, 3);
  assert.equal(harness.storage.observations.size, 0);
  const purge = [...harness.storage.audits.values()]
    .map((row) => row.record.payload)
    .find((event) => event.action === 'shadow_consent_local_data_purged'
      && event.outcome === 'superseded');
  assert.ok(purge);
});

test('atomic normalized-domain ownership rejects concurrent competing catalog identities', async () => {
  const harness = createHarness();
  const alpha = await ingest(harness, SCOPE_A, CONSENT_A, 'raceai.com', 'shadow-ingest-alpha-0201');
  const beta = await ingest(harness, SCOPE_B, CONSENT_B, 'raceai.com', 'shadow-ingest-beta-00201');
  const results = await Promise.allSettled([
    approve(harness, alpha, catalogRecord('race-one', 'raceai.com'), 'shadow-review-alpha-0201'),
    approve(harness, beta, catalogRecord('race-two', 'raceai.com'), 'shadow-review-beta-00201'),
  ]);
  assert.equal(results.filter((item) => item.status === 'fulfilled').length, 1);
  assert.equal(results.find((item) => item.status === 'rejected').reason.code,
    'classification_domain_conflict');
  assert.equal(harness.storage.domains.get('raceai.com').catalogId,
    results.find((item) => item.status === 'fulfilled').value.catalogId);
});

test('domain ownership adapter contract is global across independent transaction handles', async () => {
  const storage = new MemoryIntelligenceStorage();
  const left = storage.adapter();
  const right = storage.adapter();
  let release;
  const barrier = new Promise((resolve) => { release = resolve; });
  const common = { expectedRevision: 0, domains: ['atomicai.com'],
    recordDigest: 'a'.repeat(64), sealedClaim: { proof: 'adapter-contract' } };
  const claims = [
    barrier.then(() => left.claimClassificationDomains({ ...common, catalogId: 'atomic-left' })),
    barrier.then(() => right.claimClassificationDomains({ ...common, catalogId: 'atomic-right' })),
  ];
  release();
  const results = await Promise.all(claims);
  assert.deepEqual([...results].sort(), ['claimed', 'conflict']);
  assert.equal(storage.domains.get('atomicai.com').catalogId,
    results[0] === 'claimed' ? 'atomic-left' : 'atomic-right');
});

test('one immutable global release is signed, monotonic, purpose-bound, and rollback republishes exact content', async () => {
  const harness = createHarness();
  const firstObservation = await ingest(harness, SCOPE_A, CONSENT_A, 'rollbackone.com',
    'shadow-ingest-alpha-0301');
  await approve(harness, firstObservation, catalogRecord('rollback-one', 'rollbackone.com'),
    'shadow-review-alpha-0301');
  const publishV1 = publishCommand(harness, 0, 'shadow-publish-global-0001');
  const v1 = await harness.intelligence.publishGlobalCatalog(publishV1);
  assert.deepEqual(await harness.intelligence.publishGlobalCatalog(publishV1), v1);
  assert.equal(v1.globalVersion, 1);
  assert.equal(v1.artifact.keyId, 'rw-catalog-global-current');
  assert.equal(JSON.stringify(v1).includes(SCOPE_A.customerId), false);
  const publishAudit = harness.storage.audits
    .get(harness.storage.auditHighWater.payload.sequence).record.payload;
  const publishAuthorityLink = harness.storage.authorizationLinks
    .get(publishAudit.authorizationLinkId).payload;
  assert.equal(publishAuthorityLink.confirmationId, publishV1.confirmationId);
  assert.equal(publishAuthorityLink.parentAuthorizationLinkId.length, 64);

  const secondObservation = await ingest(harness, SCOPE_B, CONSENT_B, 'rollbacktwo.com',
    'shadow-ingest-beta-00301');
  await approve(harness, secondObservation, catalogRecord('rollback-two', 'rollbacktwo.com'),
    'shadow-review-beta-00301');
  const v2 = await harness.intelligence.publishGlobalCatalog(
    publishCommand(harness, 1, 'shadow-publish-global-0002', 'next'),
  );
  assert.equal(v2.globalVersion, 2);
  assert.equal(v2.artifact.keyId, 'rw-catalog-global-next');
  const rolled = await harness.intelligence.rollbackGlobalCatalog(
    rollbackCommand(harness, 2, 1, 'shadow-rollback-global-001'),
  );
  assert.equal(rolled.globalVersion, 3);
  assert.equal(rolled.previousVersion, 2);
  assert.equal(rolled.rollbackOfVersion, 1);
  assert.deepEqual(rolled.artifact.payload.records, v1.artifact.payload.records);
  assert.notEqual(rolled.artifactDigest, v1.artifactDigest);
});

test('archived Map keys are fully checked and offline or cross-purpose key reuse fails closed', async () => {
  const mapHarness = createHarness();
  const release = await mapHarness.intelligence.publishGlobalCatalog(
    publishCommand(mapHarness, 0, 'shadow-publish-map-canary1'),
  );
  assert.equal(release.artifact.keyId, 'rw-catalog-global-current');

  const invalidArchive = new Map([
    ['rw-catalog-global-current', currentKeys.publicKey],
    ['rw-catalog-global-next', nextKeys.publicKey],
    ['rw-catalog-global-invalid', {}],
  ]);
  const invalidMapHarness = createHarness({ archivedPublicKeys: invalidArchive });
  await expectCode(invalidMapHarness.intelligence.publishGlobalCatalog(
    publishCommand(invalidMapHarness, 0, 'shadow-publish-map-canary2'),
  ), 'catalog_key_authority_invalid');

  const reusedForbidden = {
    offline_license: keyFingerprint(currentKeys.publicKey),
    online_verdict: keyFingerprint(forbiddenKeys[1].publicKey),
    entitlement: keyFingerprint(forbiddenKeys[2].publicKey),
    policy: keyFingerprint(forbiddenKeys[3].publicKey),
    audit_request: keyFingerprint(forbiddenKeys[4].publicKey),
  };
  const reusedHarness = createHarness({ forbiddenPublicKeyFingerprints: reusedForbidden });
  await expectCode(reusedHarness.intelligence.publishGlobalCatalog(
    publishCommand(reusedHarness, 0, 'shadow-publish-key-reuse001'),
  ), 'vendor_key_identity_reused');

  const purposeHarness = createHarness({ catalogKeyAuthority: () => ({
    global: {
      current: { keyId: 'rw-entitlement-current', privateKey: currentKeys.privateKey },
      next: null,
      archivedPublicKeys: new Map([['rw-entitlement-current', currentKeys.publicKey]]),
    },
    distribution: {
      current: { keyId: 'rw-catalog-distribution-current',
        privateKey: distributionCurrentKeys.privateKey },
      next: null,
      archivedPublicKeys: new Map([
        ['rw-catalog-distribution-current', distributionCurrentKeys.publicKey],
      ]),
    },
    forbiddenPublicKeyFingerprints: mapHarness.forbiddenPublicKeyFingerprints,
  }) });
  await expectCode(purposeHarness.intelligence.publishGlobalCatalog(
    publishCommand(purposeHarness, 0, 'shadow-publish-key-purpose01'),
  ), 'vendor_key_purpose_mismatch');
});

test('catalog verifier registry rejects private PEM, PKCS8 wrappers, and private KeyObjects', async () => {
  const privatePem = currentKeys.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const privateDer = currentKeys.privateKey.export({ type: 'pkcs8', format: 'der' });
  const candidates = [
    privatePem,
    { key: privateDer, format: 'der', type: 'pkcs8' },
    currentKeys.privateKey,
  ];
  for (const [index, publicKey] of candidates.entries()) {
    const archivedPublicKeys = new Map([
      ['rw-catalog-global-current', publicKey],
      ['rw-catalog-global-next', nextKeys.publicKey],
      ['rw-catalog-global-archive', archiveOnlyKeys.publicKey],
    ]);
    const harness = createHarness({ archivedPublicKeys });
    await expectCode(harness.intelligence.publishGlobalCatalog(
      publishCommand(harness, 0, `shadow-publish-private-key-${index + 1}`),
    ), 'catalog_key_authority_invalid');
  }
});

test('customer distributions are scoped views of one global release and delayed distribution cannot diverge', async () => {
  const harness = createHarness();
  const observation = await ingest(harness, SCOPE_A, CONSENT_A, 'publishai.com',
    'shadow-ingest-alpha-0401');
  await approve(harness, observation, catalogRecord('publish-ai', 'publishai.com'),
    'shadow-review-alpha-0401');
  const global = await harness.intelligence.publishGlobalCatalog(
    publishCommand(harness, 0, 'shadow-publish-global-0401'),
  );
  const alpha = await harness.intelligence.createDistribution(distributionCommand(
    harness, SCOPE_A, 1, 0, 'shadow-distribute-alpha-001',
  ));
  harness.time.now += 4 * 60 * 1000;
  const beta = await harness.intelligence.createDistribution(distributionCommand(
    harness, SCOPE_B, 1, 0, 'shadow-distribute-beta-0001', { mode: 'preview', cohortBps: 0 },
  ));
  assert.equal(alpha.globalArtifactDigest, global.artifactDigest);
  assert.equal(beta.globalArtifactDigest, global.artifactDigest);
  assert.equal(alpha.recordsDigest, global.recordsDigest);
  assert.equal(beta.recordsDigest, global.recordsDigest);
  assert.deepEqual(alpha.globalArtifact.payload.records, beta.globalArtifact.payload.records);
  assert.deepEqual(alpha.globalArtifact.payload.records, global.artifact.payload.records);
  assert.equal(alpha.distributionSequence, 1);
  assert.equal(alpha.distributionArtifact.payload.kind,
    protocol.CHANNEL_KINDS.CATALOG_DISTRIBUTION);
  await expectCode(harness.intelligence.createDistribution({
    ...distributionCommand(harness, SCOPE_A, 1, 0, 'shadow-distribute-alpha-stale'),
  }), 'deployment_version_conflict');

  const globalV2 = await harness.intelligence.publishGlobalCatalog(
    publishCommand(harness, 1, 'shadow-publish-global-0402'),
  );
  const gammaScope = {
    customerId: 'customer_gamma', deploymentId: 'dep_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  };
  const gamma = await harness.intelligence.createDistribution(distributionCommand(
    harness, gammaScope, 2, 0, 'shadow-distribute-gamma-001',
  ));
  assert.equal(globalV2.globalVersion, 2);
  assert.equal(gamma.distributionSequence, 1);
  assert.equal(gamma.globalVersion, 2);
  assert.equal(gamma.globalArtifactDigest, globalV2.artifactDigest);

  await expectCode(harness.intelligence.createDistribution(distributionCommand(
    harness, {
      customerId: 'customer_delta', deploymentId: 'dep_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    },
    1, 0, 'shadow-distribute-delta-001',
  )), 'global_release_not_current');

  const stored = harness.storage.globalReleases.get(2);
  stored.payload.artifact.signature = flipBase64Character(stored.payload.artifact.signature);
  reseal(stored, Buffer.alloc(32, 0x5a));
  await expectCode(harness.intelligence.createDistribution(distributionCommand(
    harness, {
      customerId: 'customer_epsilon', deploymentId: 'dep_cccccccccccccccccccccccccccccccc',
    },
    2, 0, 'shadow-distribute-epsilon-001',
  )), 'global_release_signature_invalid');
});

test('vendor delivery and authenticated customer applied or rejected ACKs are separate and replay-safe', async () => {
  const harness = await harnessWithDistribution();
  const distribution = harness.distribution;
  const deliveredCommand = deliveryCommand(harness, distribution, 1);
  const delivered = await harness.intelligence.markDelivered(deliveredCommand);
  assert.equal(delivered.stage, 'delivered');
  assert.deepEqual(await harness.intelligence.markDelivered(deliveredCommand), delivered);

  const appliedAck = acknowledgement(distribution);
  const appliedCommand = acknowledgementCommand(harness, distribution, 2, appliedAck);
  const applied = await harness.intelligence.recordCustomerAcknowledgement(appliedCommand);
  assert.equal(applied.stage, 'applied');
  assert.deepEqual(await harness.intelligence.recordCustomerAcknowledgement({
    ...appliedCommand, expectedRevision: 1,
  }), applied);
  await expectCode(harness.intelligence.recordCustomerAcknowledgement(
    acknowledgementCommand(harness, distribution, 3, acknowledgement(distribution)),
  ), 'acknowledgement_reuse_conflict');
  const conflictAck = { ...appliedAck, outcome: 'rejected', reasonCode: 'invalid_signature' };
  await expectCode(harness.intelligence.recordCustomerAcknowledgement(
    acknowledgementCommand(harness, distribution, 3, conflictAck),
  ), 'acknowledgement_reuse_conflict');

  const customerDelivery = deliveryCommand(harness, distribution, 3);
  harness.storage.authorizations.get(customerDelivery.authEventId).actorRole = 'customer_connector';
  await expectCode(harness.intelligence.markDelivered(customerDelivery), 'authorization_invalid');
  const vendorAck = acknowledgementCommand(harness, distribution, 3,
    acknowledgement(distribution));
  harness.storage.authorizations.get(vendorAck.authEventId).actorRole = 'vendor_owner';
  harness.storage.authorizations.get(vendorAck.authEventId).customerId = null;
  harness.storage.authorizations.get(vendorAck.authEventId).deploymentId = null;
  await expectCode(harness.intelligence.recordCustomerAcknowledgement(vendorAck),
    'authorization_invalid');

  const rejectedHarness = await harnessWithDistribution();
  const rejectedDistribution = rejectedHarness.distribution;
  await rejectedHarness.intelligence.markDelivered(deliveryCommand(rejectedHarness,
    rejectedDistribution, 1));
  const rejected = await rejectedHarness.intelligence.recordCustomerAcknowledgement(
    acknowledgementCommand(rejectedHarness, rejectedDistribution, 2,
      acknowledgement(rejectedDistribution, 'rejected')),
  );
  assert.equal(rejected.stage, 'rejected');
  assert.equal(rejected.failures.length, 1);
  assert.deepEqual(Object.keys(rejected.failures[0]).sort(),
    ['acknowledgementDigest', 'reasonCode', 'recordedAt'].sort());
  const retried = await rejectedHarness.intelligence.markDelivered(
    deliveryCommand(rejectedHarness, rejectedDistribution, 3),
  );
  assert.equal(retried.stage, 'delivered');
  assert.equal(retried.deliveryAttempts, 2);
});

test('a rejected target transition is recorded once and cannot be multiplied after redelivery', async () => {
  const harness = await harnessWithDistribution();
  const delivered = await harness.intelligence.markDelivered(
    deliveryCommand(harness, harness.distribution, 1),
  );
  const rejected = await harness.intelligence.recordCustomerAcknowledgement(
    acknowledgementCommand(harness, harness.distribution, delivered.revision,
      acknowledgement(harness.distribution, 'rejected')),
  );
  const redelivered = await harness.intelligence.markDelivered(
    deliveryCommand(harness, harness.distribution, rejected.revision),
  );
  await expectCode(harness.intelligence.recordCustomerAcknowledgement(
    acknowledgementCommand(harness, harness.distribution, redelivered.revision,
      acknowledgement(harness.distribution, 'rejected')),
  ), 'acknowledgement_reuse_conflict');
  const statusAuth = authorize(harness.storage, 'distribution_status', 'vendor_owner');
  const status = await harness.intelligence.distributionStatus(
    statusCommand(statusAuth, harness.distribution),
  );
  assert.equal(status.adoption.stage, 'delivered');
  assert.equal(status.adoption.failures.length, 1);
});

test('authorization links, reviews, classifications, adoption, and audit high-water reject tamper', async () => {
  const authorizationHarness = createHarness();
  const authEventId = authorize(authorizationHarness.storage, 'connector_ingest',
    'customer_connector', SCOPE_A);
  const ingestCommand = { authEventId, consentId: CONSENT_A,
    idempotencyKey: opaqueId('shadow-ingest-alpha-tamper1'),
    candidate: candidate(SCOPE_A, 'authlinkai.com') };
  await authorizationHarness.intelligence.ingestCandidate(ingestCommand);
  authorizationHarness.storage.authorizationLinks.values().next().value.mac = '0'.repeat(64);
  await expectCode(authorizationHarness.intelligence.ingestCandidate(ingestCommand),
    'integrity_state_invalid');

  const stateHarness = createHarness();
  const observation = await ingest(stateHarness, SCOPE_A, CONSENT_A, 'stateai.com',
    'shadow-ingest-alpha-tamper2');
  const command = reviewCommand(stateHarness, observation, catalogRecord('state-ai', 'stateai.com'),
    'shadow-review-alpha-tamper1');
  await stateHarness.intelligence.reviewCandidate(command);
  stateHarness.storage.reviews.values().next().value.mac = '0'.repeat(64);
  await expectCode(stateHarness.intelligence.reviewCandidate(command), 'integrity_state_invalid');

  const classificationAuth = authorize(stateHarness.storage, 'global_catalog_read', 'vendor_owner');
  stateHarness.storage.classifications.values().next().value.mac = '0'.repeat(64);
  await expectCode(stateHarness.intelligence.listGlobalClassifications({
    authEventId: classificationAuth, cursor: null, limit: 10,
  }), 'integrity_state_invalid');

  const adoptionHarness = await harnessWithDistribution();
  adoptionHarness.storage.adoptions.values().next().value.mac = '0'.repeat(64);
  const statusAuth = authorize(adoptionHarness.storage, 'distribution_status', 'vendor_owner');
  await expectCode(adoptionHarness.intelligence.distributionStatus(
    statusCommand(statusAuth, adoptionHarness.distribution)), 'integrity_state_invalid');

  const auditHarness = createHarness();
  await ingest(auditHarness, SCOPE_A, CONSENT_A, 'audithead.com',
    'shadow-ingest-alpha-tamper3');
  auditHarness.storage.auditHighWater.mac = '0'.repeat(64);
  const auditAuth = authorize(auditHarness.storage, 'global_catalog_read', 'vendor_owner');
  await expectCode(auditHarness.intelligence.listGlobalClassifications({
    authEventId: auditAuth, cursor: null, limit: 10,
  }), 'integrity_state_invalid');

  const missingTailHarness = createHarness();
  await ingest(missingTailHarness, SCOPE_A, CONSENT_A, 'missingaudit.com',
    'shadow-ingest-alpha-tamper4');
  missingTailHarness.storage.audits.clear();
  const missingTailAuth = authorize(missingTailHarness.storage,
    'global_catalog_read', 'vendor_owner');
  await expectCode(missingTailHarness.intelligence.listGlobalClassifications({
    authEventId: missingTailAuth, cursor: null, limit: 10,
  }), 'audit_high_water_invalid');
});

test('authenticated monotonic heads reject valid-old replay, middle audit loss, and recover pending commits', async () => {
  const replayHarness = createHarness();
  await replayHarness.intelligence.publishGlobalCatalog(
    publishCommand(replayHarness, 0, 'shadow-publish-governance-001'),
  );
  const oldPrimarySnapshot = replayHarness.storage.snapshot();
  await replayHarness.intelligence.publishGlobalCatalog(
    publishCommand(replayHarness, 1, 'shadow-publish-governance-002'),
  );
  replayHarness.storage.restore(oldPrimarySnapshot);
  assert.deepEqual(await replayHarness.intelligence.readiness(), {
    ready: false, reason: 'governance_head_invalid', productionReady: false,
  });
  await expectCode(replayHarness.intelligence.publishGlobalCatalog(
    publishCommand(replayHarness, 1, 'shadow-publish-governance-003'),
  ), 'governance_head_invalid');

  const classificationHarness = createHarness();
  const firstObservation = await ingest(classificationHarness, SCOPE_A, CONSENT_A,
    'governedclassification.com', 'shadow-ingest-governance-001');
  const firstRecord = catalogRecord('governed-classification', 'governedclassification.com');
  await approve(classificationHarness, firstObservation, firstRecord,
    'shadow-review-governance-001');
  const classificationNamespace = [...classificationHarness.storage.governanceHeads.keys()]
    .find((value) => value.startsWith('classification:'));
  const oldClassification = cloneValue(
    classificationHarness.storage.classifications.get(firstRecord.catalogId));
  const oldClassificationHead = cloneValue(
    classificationHarness.storage.governanceHeads.get(classificationNamespace));
  const secondObservation = await ingest(classificationHarness, SCOPE_A, CONSENT_A,
    'governedclassification.com', 'shadow-ingest-governance-002');
  await approve(classificationHarness, secondObservation,
    { ...firstRecord, riskTier: 'critical' }, 'shadow-review-governance-002');
  classificationHarness.storage.classifications.set(firstRecord.catalogId, oldClassification);
  classificationHarness.storage.governanceHeads.set(
    classificationNamespace, oldClassificationHead);
  const classificationAuth = authorize(classificationHarness.storage,
    'global_catalog_read', 'vendor_owner');
  await expectCode(classificationHarness.intelligence.listGlobalClassifications({
    authEventId: classificationAuth, cursor: null, limit: 10,
  }), 'governance_head_invalid');

  const deletedAuditHarness = createHarness();
  await ingest(deletedAuditHarness, SCOPE_A, CONSENT_A, 'middledelete.com',
    'shadow-ingest-governance-003');
  await ingest(deletedAuditHarness, SCOPE_A, CONSENT_A, 'middledelete2.com',
    'shadow-ingest-governance-004');
  deletedAuditHarness.storage.audits.delete(1);
  const deletedAuditAuth = authorize(deletedAuditHarness.storage,
    'global_catalog_read', 'vendor_owner');
  await expectCode(deletedAuditHarness.intelligence.listGlobalClassifications({
    authEventId: deletedAuditAuth, cursor: null, limit: 10,
  }), 'audit_high_water_invalid');

  const reorderedAuditHarness = createHarness();
  await ingest(reorderedAuditHarness, SCOPE_A, CONSENT_A, 'middlereorder.com',
    'shadow-ingest-governance-005');
  await ingest(reorderedAuditHarness, SCOPE_A, CONSENT_A, 'middlereorder2.com',
    'shadow-ingest-governance-006');
  const firstAudit = reorderedAuditHarness.storage.audits.get(1);
  const secondAudit = reorderedAuditHarness.storage.audits.get(2);
  reorderedAuditHarness.storage.audits.set(1, secondAudit);
  reorderedAuditHarness.storage.audits.set(2, firstAudit);
  const reorderedAuditAuth = authorize(reorderedAuditHarness.storage,
    'global_catalog_read', 'vendor_owner');
  await expectCode(reorderedAuditHarness.intelligence.listGlobalClassifications({
    authEventId: reorderedAuditAuth, cursor: null, limit: 10,
  }), 'audit_high_water_invalid');

  const auditReplayHarness = createHarness();
  await ingest(auditReplayHarness, SCOPE_A, CONSENT_A, 'auditreplayone.com',
    'shadow-ingest-governance-007');
  const validOldAudits = cloneMap(auditReplayHarness.storage.audits);
  const validOldHighWater = cloneValue(auditReplayHarness.storage.auditHighWater);
  await ingest(auditReplayHarness, SCOPE_A, CONSENT_A, 'auditreplaytwo.com',
    'shadow-ingest-governance-008');
  auditReplayHarness.storage.audits = validOldAudits;
  auditReplayHarness.storage.auditHighWater = validOldHighWater;
  assert.deepEqual(await auditReplayHarness.intelligence.readiness(), {
    ready: false, reason: 'audit_anchor_invalid', productionReady: false,
  });

  const recoveryHarness = createHarness();
  recoveryHarness.storage.captureBeforeGovernanceClear = true;
  await recoveryHarness.intelligence.publishGlobalCatalog(
    publishCommand(recoveryHarness, 0, 'shadow-publish-governance-004'),
  );
  assert.ok(recoveryHarness.storage.capturedBeforeGovernanceClear);
  recoveryHarness.storage.restore(recoveryHarness.storage.capturedBeforeGovernanceClear);
  assert.deepEqual(await recoveryHarness.intelligence.readiness(), {
    ready: false, reason: 'control_plane_readiness_frozen', productionReady: false,
  });
  assert.deepEqual(await recoveryHarness.intelligence.reconcileIntegrity(), {
    finalized: 1, rolledBack: 0,
  });
  assert.deepEqual(await recoveryHarness.intelligence.readiness(), {
    ready: true, reason: 'ready', productionReady: false,
  });
});

test('audit history compacts to an authenticated checkpoint without weakening readiness', async () => {
  const harness = createHarness();
  const observation = await ingest(harness, SCOPE_A, CONSENT_A, 'compactionai.com',
    'shadow-ingest-compaction-001');
  await approve(harness, observation, catalogRecord('compaction-ai', 'compactionai.com'),
    'shadow-review-compaction-001');
  extendAuditChain(harness, MAX_ACTIVE_AUDIT_EVENTS);
  assert.deepEqual(await harness.intelligence.readiness(), {
    ready: true, reason: 'ready', productionReady: false,
  });
  for (let index = 0; index < 4; index += 1) {
    const authEventId = authorize(harness.storage, 'global_catalog_read', 'vendor_owner');
    const page = await harness.intelligence.listGlobalClassifications({
      authEventId, cursor: null, limit: 10,
    });
    assert.deepEqual(page.items.map((item) => item.catalogId), ['compaction-ai']);
    assert.equal(page.nextCursor, null);
  }
  assert.equal(harness.storage.audits.size, MAX_ACTIVE_AUDIT_EVENTS);
  assert.equal(harness.storage.audits.has(1), false);
  assert.equal(harness.storage.audits.has(4), false);
  assert.equal(harness.storage.audits.has(5), true);
  assert.equal(harness.storage.audits.has(MAX_ACTIVE_AUDIT_EVENTS + 4), true);
  assert.equal(harness.storage.auditCheckpoint.payload.sequence, 4);
  assert.equal(harness.storage.auditCheckpoint.payload.count, 4);
  assert.equal(harness.storage.auditHighWater.payload.sequence,
    MAX_ACTIVE_AUDIT_EVENTS + 4);
  assert.equal(harness.anchorAuthority.read('shadow-audit').revision,
    MAX_ACTIVE_AUDIT_EVENTS + 4);
  assert.deepEqual(await harness.intelligence.readiness(), {
    ready: true, reason: 'ready', productionReady: false,
  });

  harness.storage.auditCheckpoint.mac = '0'.repeat(64);
  assert.deepEqual(await harness.intelligence.readiness(), {
    ready: false, reason: 'integrity_state_invalid', productionReady: false,
  });
});

test('trusted archived keys reverify persisted distribution signatures and rollout metadata is authenticated', async () => {
  const harness = await harnessWithDistribution();
  const key = distributionKey(SCOPE_A, 1);
  const wrapped = harness.storage.distributions.get(key);
  wrapped.payload.rollout.cohortBps = 9999;
  const statusAuth = authorize(harness.storage, 'distribution_status', 'vendor_owner');
  await expectCode(harness.intelligence.distributionStatus(
    statusCommand(statusAuth, harness.distribution)), 'integrity_state_invalid');

  const signatureHarness = await harnessWithDistribution();
  const signed = signatureHarness.storage.distributions.get(key);
  signed.payload.distributionArtifact.signature = flipBase64Character(
    signed.payload.distributionArtifact.signature);
  reseal(signed, Buffer.alloc(32, 0x5a));
  const signatureAuth = authorize(signatureHarness.storage, 'distribution_status', 'vendor_owner');
  await expectCode(signatureHarness.intelligence.distributionStatus(
    statusCommand(signatureAuth, signatureHarness.distribution)),
  'distribution_signature_invalid');
});

test('vendor global and distribution history compacts with authenticated coverage and key references', async () => {
  const globalHarness = createHarness();
  const releases = [];
  const releaseCount = GLOBAL_ROLLBACK_WINDOW + MAX_GLOBAL_HISTORY_TOMBSTONES + 1;
  for (let version = 0; version < releaseCount; version += 1) {
    releases.push(await globalHarness.intelligence.publishGlobalCatalog(
      publishCommand(globalHarness, version, `shadow-history-global-${version + 1}`),
    ));
  }
  assert.equal(globalHarness.storage.globalReleases.size, GLOBAL_ROLLBACK_WINDOW);
  assert.equal(globalHarness.storage.globalHistoryTombstones.size,
    MAX_GLOBAL_HISTORY_TOMBSTONES);
  assert.equal(globalHarness.storage.globalHistoryCheckpoint.payload.throughSequence, 1);
  assert.deepEqual(await globalHarness.intelligence.signingKeyReferenceCounts(), {
    'rw-catalog-global-current': releaseCount,
  });
  assert.deepEqual(await globalHarness.intelligence.readiness(), {
    ready: true, reason: 'ready', productionReady: false,
  });

  const checkpoint = cloneValue(globalHarness.storage.globalHistoryCheckpoint);
  globalHarness.storage.globalHistoryCheckpoint.mac = flipHex(
    globalHarness.storage.globalHistoryCheckpoint.mac,
  );
  assert.deepEqual(await globalHarness.intelligence.readiness(), {
    ready: false, reason: 'integrity_state_invalid', productionReady: false,
  });
  globalHarness.storage.globalHistoryCheckpoint = checkpoint;
  const tombstone = cloneValue(globalHarness.storage.globalHistoryTombstones.get(2));
  globalHarness.storage.globalHistoryTombstones.delete(2);
  assert.deepEqual(await globalHarness.intelligence.readiness(), {
    ready: false, reason: 'global_history_invalid', productionReady: false,
  });
  globalHarness.storage.globalHistoryTombstones.set(2, tombstone);

  const current = releases.at(-1);
  const retired = releases[0];
  const rollbackPartial = {
    expectedGlobalVersion: current.globalVersion,
    expectedGlobalReleaseId: current.globalReleaseId,
    expectedGlobalArtifactDigest: current.artifactDigest,
    expectedGlobalRecordsDigest: current.recordsDigest,
    idempotencyKey: opaqueId('shadow-history-retired-rollback'),
    keySlot: 'current',
    targetVersion: retired.globalVersion,
    targetReleaseId: retired.globalReleaseId,
    targetArtifactDigest: retired.artifactDigest,
    targetRecordsDigest: retired.recordsDigest,
  };
  const rollbackAuth = authorize(globalHarness.storage, 'global_rollback', 'vendor_owner');
  await expectCode(globalHarness.intelligence.rollbackGlobalCatalog({
    authEventId: rollbackAuth,
    confirmationId: confirm(globalHarness.storage, rollbackAuth, 'global_rollback',
      digest({ ...rollbackPartial, operation: 'rollback' })),
    ...rollbackPartial,
  }), 'rollback_target_not_found');

  const distributionHarness = createHarness();
  await distributionHarness.intelligence.publishGlobalCatalog(
    publishCommand(distributionHarness, 0, 'shadow-history-distribution-global'),
  );
  for (let sequence = 0; sequence <= DISTRIBUTION_ROLLBACK_WINDOW; sequence += 1) {
    await distributionHarness.intelligence.createDistribution(distributionCommand(
      distributionHarness, SCOPE_A, 1, sequence, `shadow-history-distribution-${sequence + 1}`,
    ));
  }
  assert.equal(distributionHarness.storage.distributions.size, DISTRIBUTION_ROLLBACK_WINDOW);
  assert.equal(distributionHarness.storage.distributionHistoryTombstones.size, 1);
  assert.deepEqual(await distributionHarness.intelligence.signingKeyReferenceCounts(), {
    'rw-catalog-distribution-current': DISTRIBUTION_ROLLBACK_WINDOW + 1,
    'rw-catalog-global-current': DISTRIBUTION_ROLLBACK_WINDOW + 2,
  });
  assert.deepEqual(await distributionHarness.intelligence.readiness(), {
    ready: true, reason: 'ready', productionReady: false,
  });
  const distributionTombstone = cloneValue(
    distributionHarness.storage.distributionHistoryTombstones.get(
      distributionKey(SCOPE_A, 1),
    ),
  );
  distributionHarness.storage.distributionHistoryTombstones.delete(distributionKey(SCOPE_A, 1));
  assert.deepEqual(await distributionHarness.intelligence.readiness(), {
    ready: false, reason: 'distribution_history_invalid', productionReady: false,
  });
  distributionHarness.storage.distributionHistoryTombstones.set(
    distributionKey(SCOPE_A, 1), distributionTombstone,
  );
});

async function harnessWithDistribution() {
  const harness = createHarness();
  const observation = await ingest(harness, SCOPE_A, CONSENT_A, 'deliveryai.com',
    'shadow-ingest-alpha-0501');
  await approve(harness, observation, catalogRecord('delivery-ai', 'deliveryai.com'),
    'shadow-review-alpha-0501');
  await harness.intelligence.publishGlobalCatalog(
    publishCommand(harness, 0, 'shadow-publish-global-0501'),
  );
  harness.distribution = await harness.intelligence.createDistribution(distributionCommand(
    harness, SCOPE_A, 1, 0, 'shadow-distribute-alpha-501',
  ));
  return harness;
}

function reseal(wrapper, secret) {
  wrapper.mac = crypto.createHmac('sha256', secret).update(Buffer.from(
    `${wrapper.domain}\0${wrapper.keyId}\0${protocol.canonicalJson(wrapper.payload)}`, 'utf8',
  )).digest('hex');
}

function flipBase64Character(value) {
  return `${value[0] === 'A' ? 'B' : 'A'}${value.slice(1)}`;
}

function flipHex(value) {
  return `${value[0] === 'a' ? 'b' : 'a'}${value.slice(1)}`;
}

test('pagination, retention, and storage-reported quotas are bounded', async () => {
  const harness = createHarness();
  const original = [
    await ingest(harness, SCOPE_A, CONSENT_A, 'pageone.com', 'shadow-ingest-alpha-0601'),
    await ingest(harness, SCOPE_A, CONSENT_A, 'pagetwo.com', 'shadow-ingest-alpha-0602'),
    await ingest(harness, SCOPE_A, CONSENT_A, 'pagethree.com', 'shadow-ingest-alpha-0603'),
  ];
  const firstAuth = authorize(harness.storage, 'customer_observation_read',
    'customer_security_admin', SCOPE_A);
  const first = await harness.intelligence.listCustomerObservations({
    authEventId: firstAuth, ...SCOPE_A, cursor: null, limit: 2,
  });
  assert.equal(first.items.length, 2);
  assert.ok(first.nextCursor);
  const insertedAfterSnapshot = await ingest(harness, SCOPE_A, CONSENT_A,
    'pagefour.com', 'shadow-ingest-alpha-0604');
  const tamperedAuth = authorize(harness.storage, 'customer_observation_read',
    'customer_security_admin', SCOPE_A);
  await expectCode(harness.intelligence.listCustomerObservations({
    authEventId: tamperedAuth, ...SCOPE_A,
    cursor: flipBase64Character(first.nextCursor), limit: 2,
  }), 'page_cursor_invalid');
  const crossScopeAuth = authorize(harness.storage, 'customer_observation_read',
    'customer_security_admin', SCOPE_B);
  await expectCode(harness.intelligence.listCustomerObservations({
    authEventId: crossScopeAuth, ...SCOPE_B, cursor: first.nextCursor, limit: 2,
  }), 'page_cursor_invalid');
  const changedLimitAuth = authorize(harness.storage, 'customer_observation_read',
    'customer_security_admin', SCOPE_A);
  await expectCode(harness.intelligence.listCustomerObservations({
    authEventId: changedLimitAuth, ...SCOPE_A, cursor: first.nextCursor, limit: 1,
  }), 'page_cursor_invalid');
  const secondAuth = authorize(harness.storage, 'customer_observation_read',
    'customer_security_admin', SCOPE_A);
  const second = await harness.intelligence.listCustomerObservations({
    authEventId: secondAuth, ...SCOPE_A, cursor: first.nextCursor, limit: 2,
  });
  assert.equal(second.items.length, 1);
  assert.equal(second.nextCursor, null);
  assert.deepEqual(new Set([...first.items, ...second.items].map((item) => item.observationId)),
    new Set(original.map((item) => item.observationId)));
  assert.equal([...first.items, ...second.items]
    .some((item) => item.observationId === insertedAfterSnapshot.observationId), false);
  const tooLargeAuth = authorize(harness.storage, 'customer_observation_read',
    'customer_security_admin', SCOPE_A);
  await expectCode(harness.intelligence.listCustomerObservations({
    authEventId: tooLargeAuth, ...SCOPE_A, cursor: null, limit: MAX_PAGE_SIZE + 1,
  }), 'observation_list_command_invalid');

  harness.time.now += OBSERVATION_RETENTION_MS + 1;
  const retainedAuth = authorize(harness.storage, 'customer_observation_read',
    'customer_security_admin', SCOPE_A, {
      authenticatedAt: new Date(harness.time.now - 60_000).toISOString(),
      expiresAt: new Date(harness.time.now + 60_000).toISOString(),
    });
  const expired = await harness.intelligence.listCustomerObservations({
    authEventId: retainedAuth, ...SCOPE_A, cursor: null, limit: 10,
  });
  assert.deepEqual(expired.items, []);
  assert.equal(harness.storage.observations.size, 0);

  const observationQuota = createHarness();
  observationQuota.storage.countOverrides.observations = MAX_OBSERVATIONS_PER_SCOPE;
  await expectCode(ingest(observationQuota, SCOPE_A, CONSENT_A, 'quotaai.com',
    'shadow-ingest-alpha-quota1'), 'observation_quota_exceeded');

  const classificationQuota = createHarness();
  const observation = await ingest(classificationQuota, SCOPE_A, CONSENT_A,
    'classquota.com', 'shadow-ingest-alpha-quota2');
  classificationQuota.storage.countOverrides.classifications = MAX_CLASSIFICATIONS;
  await expectCode(approve(classificationQuota, observation,
    catalogRecord('class-quota', 'classquota.com'), 'shadow-review-alpha-quota1'),
  'classification_quota_exceeded');

  const releaseQuota = createHarness();
  releaseQuota.storage.countOverrides.globalReleases = MAX_GLOBAL_RELEASES + 1;
  await expectCode(releaseQuota.intelligence.publishGlobalCatalog(
    publishCommand(releaseQuota, 0, 'shadow-publish-global-quota1'),
  ), 'global_release_quota_exceeded');

  const distributionQuota = createHarness();
  await distributionQuota.intelligence.publishGlobalCatalog(
    publishCommand(distributionQuota, 0, 'shadow-publish-global-quota2'),
  );
  distributionQuota.storage.countOverrides.distributions = MAX_DISTRIBUTIONS_PER_DEPLOYMENT + 1;
  await expectCode(distributionQuota.intelligence.createDistribution(distributionCommand(
    distributionQuota, SCOPE_A, 1, 0, 'shadow-distribute-alpha-q01',
  )), 'distribution_quota_exceeded');
});

test('classification pagination authenticates an immutable snapshot across inserts, updates, and page swaps', async () => {
  const harness = createHarness();
  for (const [catalogId, domain, suffix] of [
    ['catalog-a', 'cataloga.com', 'a'],
    ['catalog-b', 'catalogb.com', 'b'],
    ['catalog-c', 'catalogc.com', 'c'],
  ]) {
    const observation = await ingest(harness, SCOPE_A, CONSENT_A, domain,
      `shadow-ingest-snapshot-${suffix}`);
    await approve(harness, observation, catalogRecord(catalogId, domain),
      `shadow-review-snapshot-${suffix}`);
  }
  const firstAuth = authorize(harness.storage, 'global_catalog_read', 'vendor_owner');
  const first = await harness.intelligence.listGlobalClassifications({
    authEventId: firstAuth, cursor: null, limit: 2,
  });
  assert.deepEqual(first.items.map((item) => item.catalogId), ['catalog-a', 'catalog-b']);

  const inserted = await ingest(harness, SCOPE_A, CONSENT_A, 'catalogd.com',
    'shadow-ingest-snapshot-d');
  await approve(harness, inserted, catalogRecord('catalog-d', 'catalogd.com'),
    'shadow-review-snapshot-d');
  const update = await ingest(harness, SCOPE_A, CONSENT_A, 'catalogc.com',
    'shadow-ingest-snapshot-c-update');
  await approve(harness, update,
    catalogRecord('catalog-c', 'catalogc.com', { riskTier: 'critical' }),
    'shadow-review-snapshot-c-update');

  const [snapshotId, snapshot] = [...harness.storage.pageSnapshots.entries()][0];
  const validSnapshot = cloneValue(snapshot);
  snapshot.pages[1].rows[0] = cloneValue(snapshot.pages[0].rows[0]);
  const tamperedAuth = authorize(harness.storage, 'global_catalog_read', 'vendor_owner');
  await expectCode(harness.intelligence.listGlobalClassifications({
    authEventId: tamperedAuth, cursor: first.nextCursor, limit: 2,
  }), 'page_snapshot_invalid');
  harness.storage.pageSnapshots.set(snapshotId, validSnapshot);

  const secondAuth = authorize(harness.storage, 'global_catalog_read', 'vendor_owner');
  const second = await harness.intelligence.listGlobalClassifications({
    authEventId: secondAuth, cursor: first.nextCursor, limit: 2,
  });
  assert.equal(second.nextCursor, null);
  assert.deepEqual(second.items, [catalogRecord('catalog-c', 'catalogc.com')]);
  assert.equal(second.items.some((item) => item.catalogId === 'catalog-d'), false);
});

test('private transaction sentinel rejects callback omission, double invocation, and result substitution', async () => {
  const omissionBase = new MemoryIntelligenceStorage();
  const omission = createHarness({ storage: omissionBase,
    transactionStorage: { transaction: async () => ({}) } });
  await expectCode(ingest(omission, SCOPE_A, CONSENT_A, 'omitai.com',
    'shadow-ingest-alpha-0701'), 'storage_contract_invalid');

  const substitutionBase = new MemoryIntelligenceStorage();
  const substitutionStorage = {
    transaction: (callback) => substitutionBase.transaction(async (tx) => {
      const result = await callback(tx);
      return JSON.parse(JSON.stringify(result));
    }),
  };
  const substitution = createHarness({ storage: substitutionBase,
    transactionStorage: substitutionStorage });
  await expectCode(ingest(substitution, SCOPE_A, CONSENT_A, 'replaceai.com',
    'shadow-ingest-alpha-0702'), 'storage_contract_invalid');

  const doubleBase = new MemoryIntelligenceStorage();
  const doubleStorage = {
    transaction: (callback) => doubleBase.transaction(async (tx) => {
      const result = await callback(tx);
      try { await callback(tx); } catch {}
      return result;
    }),
  };
  const doubled = createHarness({ storage: doubleBase, transactionStorage: doubleStorage });
  await expectCode(ingest(doubled, SCOPE_A, CONSENT_A, 'doubleai.com',
    'shadow-ingest-alpha-0703'), 'storage_contract_invalid');
});

test('audit append failure rolls back every mutation path and authenticated portal read', async (t) => {
  await t.test('ingest', async () => {
    const harness = createHarness();
    const authEventId = authorize(harness.storage, 'connector_ingest', 'customer_connector', SCOPE_A);
    const command = { authEventId, consentId: CONSENT_A,
      idempotencyKey: opaqueId('shadow-ingest-alpha-audit1'),
      candidate: candidate(SCOPE_A, 'auditingest.com') };
    await assertAuditRollback(harness, () => harness.intelligence.ingestCandidate(command));
  });
  await t.test('review', async () => {
    const harness = createHarness();
    const observation = await ingest(harness, SCOPE_A, CONSENT_A, 'auditreview.com',
      'shadow-ingest-alpha-audit2');
    const command = reviewCommand(harness, observation,
      catalogRecord('audit-review', 'auditreview.com'), 'shadow-review-alpha-audit1');
    await assertAuditRollback(harness, () => harness.intelligence.reviewCandidate(command));
  });
  await t.test('publish', async () => {
    const harness = createHarness();
    const command = publishCommand(harness, 0, 'shadow-publish-global-audit1');
    await assertAuditRollback(harness, () => harness.intelligence.publishGlobalCatalog(command));
  });
  await t.test('rollback', async () => {
    const harness = createHarness();
    await harness.intelligence.publishGlobalCatalog(
      publishCommand(harness, 0, 'shadow-publish-global-audit2'),
    );
    await harness.intelligence.publishGlobalCatalog(
      publishCommand(harness, 1, 'shadow-publish-global-audit3'),
    );
    const command = rollbackCommand(harness, 2, 1, 'shadow-rollback-global-aud1');
    await assertAuditRollback(harness, () => harness.intelligence.rollbackGlobalCatalog(command));
  });
  await t.test('distribution', async () => {
    const harness = createHarness();
    await harness.intelligence.publishGlobalCatalog(
      publishCommand(harness, 0, 'shadow-publish-global-audit4'),
    );
    const command = distributionCommand(harness, SCOPE_A, 1, 0,
      'shadow-distribute-alpha-aud1');
    await assertAuditRollback(harness, () => harness.intelligence.createDistribution(command));
  });
  await t.test('delivery', async () => {
    const harness = await harnessWithDistribution();
    const command = deliveryCommand(harness, harness.distribution, 1);
    await assertAuditRollback(harness, () => harness.intelligence.markDelivered(command));
  });
  await t.test('customer ACK', async () => {
    const harness = await harnessWithDistribution();
    await harness.intelligence.markDelivered(deliveryCommand(harness, harness.distribution, 1));
    const command = acknowledgementCommand(harness, harness.distribution, 2,
      acknowledgement(harness.distribution));
    await assertAuditRollback(harness,
      () => harness.intelligence.recordCustomerAcknowledgement(command));
  });
  await t.test('portal read', async () => {
    const harness = createHarness();
    const authEventId = authorize(harness.storage, 'global_catalog_read', 'vendor_owner');
    const command = { authEventId, cursor: null, limit: 10 };
    await assertAuditRollback(harness,
      () => harness.intelligence.listGlobalClassifications(command));
  });
  await t.test('customer observation portal read and retention purge', async () => {
    const harness = createHarness();
    await ingest(harness, SCOPE_A, CONSENT_A, 'auditportal.com',
      'shadow-ingest-alpha-audit5');
    harness.time.now += OBSERVATION_RETENTION_MS + 1;
    const authEventId = authorize(harness.storage, 'customer_observation_read',
      'customer_security_admin', SCOPE_A, {
        authenticatedAt: new Date(harness.time.now - 60_000).toISOString(),
        expiresAt: new Date(harness.time.now + 60_000).toISOString(),
      });
    const command = { authEventId, ...SCOPE_A, cursor: null, limit: 10 };
    await assertAuditRollback(harness,
      () => harness.intelligence.listCustomerObservations(command));
  });
  await t.test('distribution status portal read', async () => {
    const harness = await harnessWithDistribution();
    const authEventId = authorize(harness.storage, 'distribution_status', 'vendor_owner');
    const command = statusCommand(authEventId, harness.distribution);
    await assertAuditRollback(harness,
      () => harness.intelligence.distributionStatus(command));
  });
});

async function assertAuditRollback(harness, operation) {
  const before = harness.storage.durableState();
  harness.storage.failNextAudit = true;
  await assert.rejects(operation(), /injected audit failure/);
  assert.deepEqual(harness.storage.durableState(), before);
}

class MemoryIntelligenceStorage {
  constructor() {
    this.authorizations = new Map();
    this.confirmations = new Map();
    this.consents = new Map();
    this.consentEpochs = new Map();
    this.authorizationClaims = new Map();
    this.confirmationClaims = new Map();
    this.authorizationLinks = new Map();
    this.observations = new Map();
    this.observationIdempotency = new Map();
    this.reviews = new Map();
    this.reviewIdempotency = new Map();
    this.classifications = new Map();
    this.domains = new Map();
    this.globalReleases = new Map();
    this.globalReleaseIdempotency = new Map();
    this.currentGlobalVersion = 0;
    this.globalHistoryTombstones = new Map();
    this.globalHistoryCheckpoint = null;
    this.distributions = new Map();
    this.distributionIdempotency = new Map();
    this.currentDistributionVersions = new Map();
    this.adoptions = new Map();
    this.distributionHistoryTombstones = new Map();
    this.distributionHistoryCheckpoints = new Map();
    this.acknowledgementClaims = new Map();
    this.acknowledgementMessageClaims = new Map();
    this.audits = new Map();
    this.auditHighWater = null;
    this.auditCheckpoint = null;
    this.auditAnchor = null;
    this.governanceHeads = new Map();
    this.governanceAnchors = new Map();
    this.governancePending = new Map();
    this.pageSnapshots = new Map();
    this.countOverrides = {
      observations: null,
      classifications: null,
      globalReleases: null,
      distributions: null,
    };
    this.failNextAudit = false;
    this.captureBeforeGovernanceClear = false;
    this.capturedBeforeGovernanceClear = null;
    this.tail = Promise.resolve();
  }

  transaction(work) {
    const run = this.tail.then(async () => {
      const snapshot = this.snapshot();
      try { return await work(this.adapter()); }
      catch (error) {
        const failureFlag = this.failNextAudit;
        this.restore(snapshot);
        this.failNextAudit = failureFlag;
        throw error;
      }
    });
    this.tail = run.catch(() => undefined);
    return run;
  }

  adapter() {
    return {
      resolveAuthorization: async (id) => cloneValue(this.authorizations.get(id)),
      claimAuthorization: async (id, digestValue) => claimOpaque(
        this.authorizationClaims, id, digestValue,
      ),
      readAuthorizationLink: async (id) => cloneValue(this.authorizationLinks.get(id)),
      insertAuthorizationLink: async (id, value) => insertUnique(
        this.authorizationLinks, id, value,
      ),
      resolveConfirmation: async (id) => cloneValue(this.confirmations.get(id)),
      claimConfirmation: async (id, digestValue) => claimOpaque(
        this.confirmationClaims, id, digestValue,
      ),
      resolveConsent: async (id) => cloneValue(this.consents.get(id)),
      resolveScopeConsent: async (customerId, deploymentId) => {
        const matches = [...this.consents.values()]
          .filter((value) => value.customerId === customerId
            && value.deploymentId === deploymentId)
          .sort((left, right) => right.revision - left.revision);
        return cloneValue(matches[0] || null);
      },
      readScopeConsentEpoch: async (customerId, deploymentId) => cloneValue(
        this.consentEpochs.get(`${customerId}\0${deploymentId}`),
      ),
      compareAndSetScopeConsentEpoch: async (customerId, deploymentId,
        expectedEpoch, wrapped) => {
        const key = `${customerId}\0${deploymentId}`;
        const current = this.consentEpochs.get(key)?.payload?.epoch || 0;
        if (current !== expectedEpoch) return false;
        this.consentEpochs.set(key, cloneValue(wrapped));
        return true;
      },

      countActiveObservations: async (customerId, deploymentId, nowIso) => {
        if (this.countOverrides.observations !== null) return this.countOverrides.observations;
        return [...this.observations.values()].filter((wrapped) => {
          const value = wrapped.payload;
          return value.customerId === customerId && value.deploymentId === deploymentId
            && value.retainUntil > nowIso;
        }).length;
      },
      purgeExpiredObservations: async (customerId, deploymentId, nowIso, limit) => {
        return this.purgeObservations(customerId, deploymentId,
          (value) => value.retainUntil <= nowIso, limit);
      },
      purgeScopeObservations: async (customerId, deploymentId, limit) => {
        const purged = this.purgeObservations(customerId, deploymentId, () => true, limit);
        const remaining = [...this.observations.values()].filter((wrapped) => {
          const value = wrapped.payload;
          return value.customerId === customerId && value.deploymentId === deploymentId;
        }).length;
        return { purged, remaining };
      },
      purgeScopePageSnapshots: async (customerId, deploymentId, limit) => {
        let purged = 0;
        for (const [id, snapshot] of this.pageSnapshots) {
          if (snapshot.customerId === customerId && snapshot.deploymentId === deploymentId) {
            if (purged >= limit) break;
            this.pageSnapshots.delete(id);
            purged += 1;
          }
        }
        const remaining = [...this.pageSnapshots.values()].filter((snapshot) =>
          snapshot.customerId === customerId && snapshot.deploymentId === deploymentId).length;
        return { purged, remaining };
      },
      findObservationByIdempotency: async (customerId, deploymentId, key) => {
        const id = this.observationIdempotency.get(scopedKey(customerId, deploymentId, key));
        return id ? cloneValue(this.observations.get(scopedKey(customerId, deploymentId, id))) : null;
      },
      readObservation: async (customerId, deploymentId, id) => cloneValue(
        this.observations.get(scopedKey(customerId, deploymentId, id)),
      ),
      insertObservation: async (id, customerId, deploymentId, idempotencyKey, value) => {
        const recordKey = scopedKey(customerId, deploymentId, id);
        const idempotency = scopedKey(customerId, deploymentId, idempotencyKey);
        if (this.observations.has(recordKey) || this.observationIdempotency.has(idempotency)) return false;
        this.observations.set(recordKey, cloneValue(value));
        this.observationIdempotency.set(idempotency, id);
        return true;
      },
      listObservations: async (customerId, deploymentId, cursor, limit, nowIso) => {
        const rows = [...this.observations.values()].filter((wrapped) => {
          const value = wrapped.payload;
          return value.customerId === customerId && value.deploymentId === deploymentId
            && value.retainUntil > nowIso && (cursor === null || value.observationId > cursor);
        }).sort((left, right) => left.payload.observationId.localeCompare(right.payload.observationId));
        return rows.slice(0, limit).map(cloneValue);
      },

      findReviewByIdempotency: async (customerId, deploymentId, key) => {
        const id = this.reviewIdempotency.get(scopedKey(customerId, deploymentId, key));
        return id ? cloneValue(this.reviews.get(scopedKey(customerId, deploymentId, id))) : null;
      },
      insertReview: async (reviewId, customerId, deploymentId, observationId,
        idempotencyKey, value) => {
        const recordKey = scopedKey(customerId, deploymentId, observationId);
        const idempotency = scopedKey(customerId, deploymentId, idempotencyKey);
        if (this.reviews.has(recordKey) || this.reviewIdempotency.has(idempotency)) return false;
        this.reviews.set(recordKey, cloneValue(value));
        this.reviewIdempotency.set(idempotency, observationId);
        return true;
      },
      readClassification: async (catalogId) => cloneValue(this.classifications.get(catalogId)),
      countClassifications: async () => this.countOverrides.classifications
        ?? this.classifications.size,
      claimClassificationDomains: async (claim) => this.claimDomains(claim),
      compareAndSetClassification: async (catalogId, expectedRevision, value) => {
        const current = this.classifications.get(catalogId);
        if ((current?.payload.revision || 0) !== expectedRevision) return false;
        this.classifications.set(catalogId, cloneValue(value));
        return true;
      },
      listAllClassifications: async (limit) => [...this.classifications.values()]
        .sort((left, right) => left.payload.record.catalogId.localeCompare(right.payload.record.catalogId))
        .slice(0, limit).map(cloneValue),
      listClassifications: async (cursor, limit) => [...this.classifications.values()]
        .filter((wrapped) => cursor === null || wrapped.payload.record.catalogId > cursor)
        .sort((left, right) => left.payload.record.catalogId.localeCompare(right.payload.record.catalogId))
        .slice(0, limit).map(cloneValue),

      countGlobalReleases: async () => this.countOverrides.globalReleases
        ?? this.globalReleases.size,
      findGlobalReleaseByIdempotency: async (key) => {
        const version = this.globalReleaseIdempotency.get(key);
        return version ? cloneValue(this.globalReleases.get(version)) : null;
      },
      readCurrentGlobalRelease: async () => this.currentGlobalVersion
        ? cloneValue(this.globalReleases.get(this.currentGlobalVersion)) : null,
      readGlobalRelease: async (version) => cloneValue(this.globalReleases.get(version)),
      listGlobalReleases: async (limit) => [...this.globalReleases]
        .sort(([left], [right]) => left - right).slice(0, limit)
        .map(([version, wrapped]) => ({ version, wrapped: cloneValue(wrapped) })),
      compareAndSetGlobalRelease: async (expectedVersion, idempotencyKey, version, value) => {
        if (this.currentGlobalVersion !== expectedVersion
            || this.globalReleaseIdempotency.has(idempotencyKey)
            || this.globalReleases.has(version)) return false;
        this.currentGlobalVersion = version;
        this.globalReleases.set(version, cloneValue(value));
        this.globalReleaseIdempotency.set(idempotencyKey, version);
        return true;
      },
      deleteGlobalRelease: async (version, artifactDigest, wrappedDigest, idempotencyKey) => {
        const wrapped = this.globalReleases.get(version);
        if (!wrapped || wrapped.payload.artifactDigest !== artifactDigest
            || wrapped.payload.idempotencyKey !== idempotencyKey
            || digest(wrapped) !== wrappedDigest || version === this.currentGlobalVersion) {
          return false;
        }
        this.globalReleases.delete(version);
        this.globalReleaseIdempotency.delete(idempotencyKey);
        return true;
      },
      readGlobalHistoryCheckpoint: async () => cloneValue(this.globalHistoryCheckpoint),
      compareAndSetGlobalHistoryCheckpoint: async (expected, wrapped) => {
        if ((this.globalHistoryCheckpoint?.payload.throughSequence || 0) !== expected) return false;
        this.globalHistoryCheckpoint = cloneValue(wrapped);
        return true;
      },
      listGlobalHistoryTombstones: async (limit) => [...this.globalHistoryTombstones]
        .sort(([left], [right]) => left - right).slice(0, limit)
        .map(([, row]) => cloneValue(row.wrapped)),
      writeGlobalHistoryTombstone: async (version, artifactDigest, wrapped) => {
        if (this.globalHistoryTombstones.has(version)) return false;
        this.globalHistoryTombstones.set(version, { artifactDigest, wrapped: cloneValue(wrapped) });
        return true;
      },
      deleteGlobalHistoryTombstone: async (version, artifactDigest, wrappedDigest) => {
        const row = this.globalHistoryTombstones.get(version);
        if (!row || row.artifactDigest !== artifactDigest || digest(row.wrapped) !== wrappedDigest) {
          return false;
        }
        this.globalHistoryTombstones.delete(version);
        return true;
      },

      countDistributions: async (customerId, deploymentId) => {
        if (this.countOverrides.distributions !== null) return this.countOverrides.distributions;
        const prefix = `${scopeKey({ customerId, deploymentId })}\0`;
        return [...this.distributions.keys()].filter((key) => key.startsWith(prefix)).length;
      },
      findDistributionByIdempotency: async (customerId, deploymentId, key) => {
        const version = this.distributionIdempotency.get(scopedKey(customerId, deploymentId, key));
        return version ? cloneValue(this.distributions.get(
          distributionKey({ customerId, deploymentId }, version),
        )) : null;
      },
      readCurrentDistribution: async (customerId, deploymentId) => {
        const version = this.currentDistributionVersions.get(scopeKey({ customerId, deploymentId }));
        return version ? cloneValue(this.distributions.get(
          distributionKey({ customerId, deploymentId }, version),
        )) : null;
      },
      readDistribution: async (customerId, deploymentId, version) => cloneValue(
        this.distributions.get(distributionKey({ customerId, deploymentId }, version)),
      ),
      listDistributions: async (customerId, deploymentId, limit) => {
        const prefix = `${scopeKey({ customerId, deploymentId })}\0`;
        return [...this.distributions].filter(([key]) => key.startsWith(prefix))
          .map(([key, wrapped]) => ({ sequence: Number(key.slice(prefix.length)), wrapped }))
          .sort((left, right) => left.sequence - right.sequence).slice(0, limit)
          .map(cloneValue);
      },
      compareAndSetDistribution: async (customerId, deploymentId, expectedVersion,
        idempotencyKey, version, value) => {
        const scope = scopeKey({ customerId, deploymentId });
        const idempotency = scopedKey(customerId, deploymentId, idempotencyKey);
        if ((this.currentDistributionVersions.get(scope) || 0) !== expectedVersion
            || this.distributionIdempotency.has(idempotency)
            || this.distributions.has(distributionKey({ customerId, deploymentId }, version))) {
          return false;
        }
        this.currentDistributionVersions.set(scope, version);
        this.distributionIdempotency.set(idempotency, version);
        this.distributions.set(distributionKey({ customerId, deploymentId }, version),
          cloneValue(value));
        return true;
      },
      deleteDistributionHistory: async (customerId, deploymentId, version,
        artifactDigest, wrappedDigest, idempotencyKey, adoptionDigest) => {
        const key = distributionKey({ customerId, deploymentId }, version);
        const wrapped = this.distributions.get(key);
        const adoption = this.adoptions.get(key);
        if (!wrapped || !adoption || wrapped.payload.artifactDigest !== artifactDigest
            || wrapped.payload.idempotencyKey !== idempotencyKey
            || digest(wrapped) !== wrappedDigest || digest(adoption) !== adoptionDigest
            || version === this.currentDistributionVersions.get(scopeKey({ customerId, deploymentId }))) {
          return false;
        }
        this.distributions.delete(key);
        this.adoptions.delete(key);
        this.distributionIdempotency.delete(scopedKey(customerId, deploymentId, idempotencyKey));
        return true;
      },
      listDistributionHistoryScopes: async (limit) => [...this.currentDistributionVersions.keys()]
        .sort().slice(0, limit).map((key) => {
          const [customerId, deploymentId] = key.split('\0');
          return { customerId, deploymentId };
        }),
      readDistributionHistoryCheckpoint: async (customerId, deploymentId) => cloneValue(
        this.distributionHistoryCheckpoints.get(scopeKey({ customerId, deploymentId })),
      ),
      compareAndSetDistributionHistoryCheckpoint: async (customerId, deploymentId,
        expected, wrapped) => {
        const key = scopeKey({ customerId, deploymentId });
        if ((this.distributionHistoryCheckpoints.get(key)?.payload.throughSequence || 0)
            !== expected) return false;
        this.distributionHistoryCheckpoints.set(key, cloneValue(wrapped));
        return true;
      },
      listDistributionHistoryTombstones: async (customerId, deploymentId, limit) => {
        const prefix = `${scopeKey({ customerId, deploymentId })}\0`;
        return [...this.distributionHistoryTombstones].filter(([key]) => key.startsWith(prefix))
          .sort(([left], [right]) => left.localeCompare(right)).slice(0, limit)
          .map(([, row]) => cloneValue(row.wrapped));
      },
      writeDistributionHistoryTombstone: async (customerId, deploymentId, version,
        artifactDigest, wrapped) => {
        const key = distributionKey({ customerId, deploymentId }, version);
        if (this.distributionHistoryTombstones.has(key)) return false;
        this.distributionHistoryTombstones.set(key, { artifactDigest, wrapped: cloneValue(wrapped) });
        return true;
      },
      deleteDistributionHistoryTombstone: async (customerId, deploymentId, version,
        artifactDigest, wrappedDigest) => {
        const key = distributionKey({ customerId, deploymentId }, version);
        const row = this.distributionHistoryTombstones.get(key);
        if (!row || row.artifactDigest !== artifactDigest || digest(row.wrapped) !== wrappedDigest) {
          return false;
        }
        this.distributionHistoryTombstones.delete(key);
        return true;
      },
      readAdoption: async (customerId, deploymentId, version) => cloneValue(
        this.adoptions.get(distributionKey({ customerId, deploymentId }, version)),
      ),
      compareAndSetAdoption: async (customerId, deploymentId, version,
        expectedRevision, value) => {
        const key = distributionKey({ customerId, deploymentId }, version);
        const current = this.adoptions.get(key);
        if ((current?.payload.revision || 0) !== expectedRevision) return false;
        this.adoptions.set(key, cloneValue(value));
        return true;
      },
      claimAcknowledgementTransition: async (transitionKey, messageId, digestValue) => {
        const messageDigest = this.acknowledgementMessageClaims.get(messageId);
        if (messageDigest !== undefined && messageDigest !== digestValue) return 'conflict';
        const current = this.acknowledgementClaims.get(transitionKey);
        if (!current) {
          this.acknowledgementMessageClaims.set(messageId, digestValue);
          this.acknowledgementClaims.set(transitionKey, { digest: digestValue, record: null });
          return 'claimed';
        }
        if (current.digest !== digestValue) return 'conflict';
        if (messageDigest === undefined) this.acknowledgementMessageClaims.set(messageId, digestValue);
        return current.record
          ? { status: 'replay', record: cloneValue(current.record) } : 'claimed';
      },
      completeAcknowledgementTransition: async (transitionKey, digestValue, value) => {
        const current = this.acknowledgementClaims.get(transitionKey);
        if (!current || current.digest !== digestValue || current.record) return false;
        current.record = cloneValue(value);
        return true;
      },

      readAuditHighWater: async () => cloneValue(this.auditHighWater),
      readAuditCheckpoint: async () => cloneValue(this.auditCheckpoint),
      compareAndSetAuditCheckpoint: async (expectedSequence, value) => {
        if ((this.auditCheckpoint?.payload.sequence || 0) !== expectedSequence
            || value?.payload?.sequence !== expectedSequence + 1) return false;
        this.auditCheckpoint = cloneValue(value);
        return true;
      },
      readAuditTail: async () => {
        if (!this.audits.size) return null;
        const sequence = Math.max(...this.audits.keys());
        return cloneValue(this.audits.get(sequence).record);
      },
      readAuditEvent: async (sequence) => cloneValue(this.audits.get(sequence)?.record),
      listAuditEvents: async (startSequence, limit) => [...this.audits]
        .filter(([sequence]) => sequence >= startSequence)
        .sort(([left], [right]) => left - right)
        .slice(0, limit).map(([, row]) => cloneValue(row.record)),
      appendAudit: async (sequence, digestValue, value) => {
        if (this.failNextAudit) {
          this.failNextAudit = false;
          throw new Error('injected audit failure');
        }
        if (this.audits.has(sequence)) return false;
        this.audits.set(sequence, { digest: digestValue, record: cloneValue(value) });
        return true;
      },
      deleteAuditEvent: async (sequence, wrappedDigest) => {
        const current = this.audits.get(sequence);
        if (!current || digest(current.record) !== wrappedDigest) return false;
        this.audits.delete(sequence);
        return true;
      },
      compareAndSetAuditHighWater: async (expectedSequence, value) => {
        if ((this.auditHighWater?.payload.sequence || 0) !== expectedSequence) return false;
        this.auditHighWater = cloneValue(value);
        return true;
      },
      readAuditAnchor: async () => cloneValue(this.auditAnchor),
      advanceAuditAnchor: async (expectedSequence, sequence, count, headDigest) => {
        const currentSequence = this.auditAnchor?.sequence || 0;
        if (currentSequence !== expectedSequence || sequence !== expectedSequence + 1
            || count !== sequence || !/^[a-f0-9]{64}$/.test(headDigest)) return false;
        this.auditAnchor = { sequence, count, headDigest };
        return true;
      },
      readGovernanceHead: async (namespace) => cloneValue(this.governanceHeads.get(namespace)),
      listGovernanceHeads: async (limit) => [...this.governanceHeads]
        .sort(([left], [right]) => left.localeCompare(right)).slice(0, limit)
        .map(([namespace, wrapped]) => ({ namespace, wrapped: cloneValue(wrapped) })),
      readGovernanceAnchor: async (namespace) => cloneValue(this.governanceAnchors.get(namespace)),
      readGovernancePending: async (namespace) => cloneValue(this.governancePending.get(namespace)),
      listGovernancePending: async (limit) => [...this.governancePending]
        .slice(0, limit).map(([namespace, wrapped]) => ({ namespace, wrapped: cloneValue(wrapped) })),
      writeGovernancePending: async (namespace, expectedRevision, wrapped) => {
        const current = this.governanceHeads.get(namespace)?.payload?.revision || 0;
        if (current !== expectedRevision || this.governancePending.has(namespace)) return false;
        this.governancePending.set(namespace, cloneValue(wrapped));
        return true;
      },
      compareAndSetGovernanceHead: async (namespace, expectedRevision, wrapped) => {
        const current = this.governanceHeads.get(namespace)?.payload.revision || 0;
        if (current !== expectedRevision) return false;
        this.governanceHeads.set(namespace, cloneValue(wrapped));
        return true;
      },
      advanceGovernanceAnchor: async (namespace, expectedRevision, revision, headDigest) => {
        const current = this.governanceAnchors.get(namespace)?.revision || 0;
        if (current !== expectedRevision || revision !== expectedRevision + 1) return false;
        this.governanceAnchors.set(namespace, { revision, headDigest });
        return true;
      },
      clearGovernancePending: async (namespace, witnessDigest) => {
        const wrapped = this.governancePending.get(namespace);
        if (!wrapped || digest(wrapped) !== witnessDigest) return false;
        if (this.captureBeforeGovernanceClear && !this.capturedBeforeGovernanceClear) {
          this.capturedBeforeGovernanceClear = this.snapshot();
        }
        this.governancePending.delete(namespace);
        return true;
      },
      createPageSnapshot: async (snapshotId, expiresAt, pages, maxActive, nowIso,
        customerId, deploymentId, consentEpoch) => {
        for (const [id, snapshot] of this.pageSnapshots.entries()) {
          if (snapshot.expiresAt <= nowIso) this.pageSnapshots.delete(id);
        }
        if (this.pageSnapshots.size >= maxActive || this.pageSnapshots.has(snapshotId)) return false;
        this.pageSnapshots.set(snapshotId, {
          expiresAt,
          customerId,
          deploymentId,
          consentEpoch,
          pages: cloneValue(pages),
        });
        return true;
      },
      readPageSnapshot: async (snapshotId, pageIndex, nowIso) => {
        const snapshot = this.pageSnapshots.get(snapshotId);
        if (!snapshot || snapshot.expiresAt <= nowIso) {
          if (snapshot) this.pageSnapshots.delete(snapshotId);
          return null;
        }
        return cloneValue(snapshot.pages[pageIndex]);
      },
      releasePageSnapshot: async (snapshotId) => this.pageSnapshots.delete(snapshotId),
    };
  }

  claimDomains(claim) {
    for (const domain of claim.domains) {
      const owner = this.domains.get(domain);
      if (owner && owner.catalogId !== claim.catalogId) return 'conflict';
    }
    let created = false;
    for (const domain of claim.domains) {
      if (!this.domains.has(domain)) created = true;
      this.domains.set(domain, {
        catalogId: claim.catalogId,
        recordDigest: claim.recordDigest,
        sealedClaim: cloneValue(claim.sealedClaim),
      });
    }
    return created ? 'claimed' : 'owned';
  }

  purgeObservations(customerId, deploymentId, predicate, limit) {
    const matches = [...this.observations.entries()].filter(([, wrapped]) => {
      const value = wrapped.payload;
      return value.customerId === customerId && value.deploymentId === deploymentId
        && predicate(value);
    }).slice(0, limit);
    for (const [recordKey, wrapped] of matches) {
      const value = wrapped.payload;
      this.observations.delete(recordKey);
      this.observationIdempotency.delete(scopedKey(customerId, deploymentId,
        value.idempotencyKey));
      this.reviews.delete(scopedKey(customerId, deploymentId, value.observationId));
      for (const [key, observationId] of this.reviewIdempotency.entries()) {
        if (observationId === value.observationId
            && key.startsWith(`${scopeKey({ customerId, deploymentId })}\0`)) {
          this.reviewIdempotency.delete(key);
        }
      }
    }
    return matches.length;
  }

  snapshot() {
    return {
      authorizationClaims: cloneMap(this.authorizationClaims),
      confirmationClaims: cloneMap(this.confirmationClaims),
      authorizationLinks: cloneMap(this.authorizationLinks),
      consentEpochs: cloneMap(this.consentEpochs),
      observations: cloneMap(this.observations),
      observationIdempotency: new Map(this.observationIdempotency),
      reviews: cloneMap(this.reviews),
      reviewIdempotency: new Map(this.reviewIdempotency),
      classifications: cloneMap(this.classifications),
      domains: cloneMap(this.domains),
      globalReleases: cloneMap(this.globalReleases),
      globalReleaseIdempotency: new Map(this.globalReleaseIdempotency),
      currentGlobalVersion: this.currentGlobalVersion,
      globalHistoryTombstones: cloneMap(this.globalHistoryTombstones),
      globalHistoryCheckpoint: cloneValue(this.globalHistoryCheckpoint),
      distributions: cloneMap(this.distributions),
      distributionIdempotency: new Map(this.distributionIdempotency),
      currentDistributionVersions: new Map(this.currentDistributionVersions),
      adoptions: cloneMap(this.adoptions),
      distributionHistoryTombstones: cloneMap(this.distributionHistoryTombstones),
      distributionHistoryCheckpoints: cloneMap(this.distributionHistoryCheckpoints),
      acknowledgementClaims: cloneMap(this.acknowledgementClaims),
      acknowledgementMessageClaims: cloneMap(this.acknowledgementMessageClaims),
      audits: cloneMap(this.audits),
      auditHighWater: cloneValue(this.auditHighWater),
      auditCheckpoint: cloneValue(this.auditCheckpoint),
      auditAnchor: cloneValue(this.auditAnchor),
      governanceHeads: cloneMap(this.governanceHeads),
      governanceAnchors: cloneMap(this.governanceAnchors),
      governancePending: cloneMap(this.governancePending),
      pageSnapshots: cloneMap(this.pageSnapshots),
      failNextAudit: this.failNextAudit,
    };
  }

  restore(snapshot) {
    Object.assign(this, snapshot);
  }

  durableState() {
    const snapshot = this.snapshot();
    delete snapshot.failNextAudit;
    return stableSnapshot(snapshot);
  }
}

function claimOpaque(map, id, digestValue) {
  const current = map.get(id);
  if (current === undefined) {
    map.set(id, digestValue);
    return 'claimed';
  }
  return current === digestValue ? 'replay' : 'conflict';
}

function insertUnique(map, key, value) {
  if (map.has(key)) return false;
  map.set(key, cloneValue(value));
  return true;
}

function scopeKey(scope) {
  return `${scope.customerId}\0${scope.deploymentId}`;
}

function scopedKey(customerId, deploymentId, value) {
  return `${customerId}\0${deploymentId}\0${value}`;
}

function distributionKey(scope, version) {
  return `${scopeKey(scope)}\0${version}`;
}

function cloneMap(map) {
  return new Map([...map.entries()].map(([key, value]) => [key, cloneValue(value)]));
}

function cloneValue(value) {
  if (value === undefined) return undefined;
  return JSON.parse(JSON.stringify(value));
}

function stableSnapshot(value) {
  const output = {};
  for (const key of Object.keys(value).sort()) {
    const item = value[key];
    output[key] = item instanceof Map
      ? [...item.entries()].sort(([left], [right]) => String(left).localeCompare(String(right)))
        .map(([entryKey, entryValue]) => [entryKey, cloneValue(entryValue)])
      : cloneValue(item);
  }
  return output;
}
