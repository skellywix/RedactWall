'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const ORIGINAL_NODE_ENV = process.env.NODE_ENV;
process.env.NODE_ENV = 'test';
test.after(() => {
  if (ORIGINAL_NODE_ENV === undefined) delete process.env.NODE_ENV;
  else process.env.NODE_ENV = ORIGINAL_NODE_ENV;
});

const crypto = require('node:crypto');
const protocol = require('../server/vendor-control-protocol');
const {
  createReferenceMonotonicAnchorAuthority,
  createReferenceMonotonicAnchorStorage,
} = require('../server/monotonic-anchor-authority');
const {
  MAX_ACTIVE_AUDIT_EVENTS,
  MAX_ACTIVE_DISTRIBUTIONS,
  MAX_ARCHIVED_TOMBSTONES,
  ROLLBACK_WINDOW_DISTRIBUTIONS,
  createProductionShadowAiCatalogState,
  createReferenceShadowAiCatalogState,
  createShadowAiCatalogState,
} = require('../server/shadow-ai-catalog-state');
const { KEY_PURPOSES, keyFingerprint } = require('../server/vendor-signed-artifact');

const CUSTOMER_ID = 'customer_one';
const DEPLOYMENT_ID = 'dep_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const WRONG_DEPLOYMENT_ID = 'dep_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const SIBLING_DEPLOYMENT_ID = 'dep_cccccccccccccccccccccccccccccccc';
const GLOBAL_KEY_ID = 'rw-catalog-global-2026-01';
const DISTRIBUTION_KEY_ID = 'rw-catalog-distribution-2026-01';
const globalKeys = crypto.generateKeyPairSync('ed25519');
const distributionKeys = crypto.generateKeyPairSync('ed25519');
const rotatedGlobalKeys = crypto.generateKeyPairSync('ed25519');
const rotatedDistributionKeys = crypto.generateKeyPairSync('ed25519');
const ROTATED_GLOBAL_KEY_ID = 'rw-catalog-global-2026-02';
const ROTATED_DISTRIBUTION_KEY_ID = 'rw-catalog-distribution-2026-02';
const stateSecret = Buffer.alloc(32, 0x5a);
const anchorSecret = Buffer.alloc(32, 0x6a);

function record(catalogId, domain, classification = 'generative_ai') {
  return {
    catalogId,
    registrableDomain: domain,
    aliases: [],
    classification,
    riskTier: classification === 'not_ai' ? 'low' : 'high',
    analystState: 'approved',
    evidenceClass: 'public_documentation',
    confidenceBps: 9500,
  };
}

function signed(payload, keyId, privateKey) {
  return {
    keyId,
    payload,
    signature: crypto.sign(null, protocol.signingInput(payload, keyId), privateKey)
      .toString('base64'),
  };
}

function globalArtifact(version = 57, records = [record('alpha', 'alpha.ai')], options = {}) {
  const payload = {
    schemaVersion: 1,
    messageId: options.messageId || crypto.randomUUID(),
    kind: protocol.CHANNEL_KINDS.GLOBAL_CATALOG_RELEASE,
    authorityManifestGeneration: options.authorityManifestGeneration ?? 1,
    authorityManifestKeySlot: options.authorityManifestKeySlot || 'current',
    globalReleaseId: options.globalReleaseId || crypto.randomUUID(),
    globalVersion: version,
    previousGlobalVersion: version - 1,
    rollbackOfGlobalVersion: options.rollbackOfGlobalVersion ?? null,
    issuedAt: options.issuedAt || '2026-01-01T00:00:00.000Z',
    recordsDigest: protocol.catalogRecordsDigest(records),
    records,
  };
  return signed(payload, options.keyId || GLOBAL_KEY_ID,
    options.privateKey || globalKeys.privateKey);
}

function distributionArtifact(sequence, global, options = {}) {
  const payload = {
    schemaVersion: 1,
    messageId: options.messageId || crypto.randomUUID(),
    customerId: options.customerId || CUSTOMER_ID,
    deploymentId: options.deploymentId || DEPLOYMENT_ID,
    kind: protocol.CHANNEL_KINDS.CATALOG_DISTRIBUTION,
    authorityManifestGeneration: options.authorityManifestGeneration ?? 1,
    authorityManifestKeySlot: options.authorityManifestKeySlot || 'current',
    distributionSequence: sequence,
    previousDistributionSequence: sequence - 1,
    globalReleaseId: options.globalReleaseId || global.payload.globalReleaseId,
    globalVersion: options.globalVersion || global.payload.globalVersion,
    globalArtifactDigest: options.globalArtifactDigest
      || canonicalDigest(global),
    recordsDigest: options.recordsDigest || global.payload.recordsDigest,
    rollout: options.rollout || { mode: 'required', cohortBps: 10_000 },
    issuedAt: options.issuedAt || `2026-01-${String(Math.min(sequence, 28)).padStart(2, '0')}T01:00:00.000Z`,
  };
  return signed(payload, options.keyId || DISTRIBUTION_KEY_ID,
    options.privateKey || distributionKeys.privateKey);
}

function pair(sequence, global = globalArtifact(), options = {}) {
  return {
    globalArtifact: global,
    distributionArtifact: distributionArtifact(sequence, global, options),
  };
}

function setup(storage = new ReferenceCatalogStorage(), scope = {},
  anchorStorage = createReferenceMonotonicAnchorStorage()) {
  const anchorAuthority = createReferenceMonotonicAnchorAuthority({
    storage: anchorStorage,
    keyId: 'rw-anchor-catalog-customer',
    secret: anchorSecret,
    purpose: 'customer_catalog_witness',
  });
  return {
    storage,
    anchorStorage,
    anchorAuthority,
    catalog: createReferenceShadowAiCatalogState({
      storage,
      anchorAuthority,
      allowTestWitness: true,
      customerId: scope.customerId || CUSTOMER_ID,
      deploymentId: scope.deploymentId || DEPLOYMENT_ID,
      globalPublicKeys: { [GLOBAL_KEY_ID]: globalKeys.publicKey },
      distributionPublicKeys: { [DISTRIBUTION_KEY_ID]: distributionKeys.publicKey },
      stateIntegrityAuthority: {
        keyId: 'rw-catalog-state-integrity-customer',
        secret: stateSecret,
      },
    }),
  };
}

function setupWithManifest(storage, anchorStorage, authorityManifest, keys) {
  const anchorAuthority = createReferenceMonotonicAnchorAuthority({
    storage: anchorStorage,
    keyId: 'rw-anchor-catalog-customer',
    secret: anchorSecret,
    purpose: 'customer_catalog_witness',
  });
  return createReferenceShadowAiCatalogState({
    storage,
    anchorAuthority,
    allowTestWitness: true,
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    authorityManifest,
    globalPublicKeys: keys.global,
    distributionPublicKeys: keys.distribution,
    stateIntegrityAuthority: {
      keyId: 'rw-catalog-state-integrity-customer',
      secret: stateSecret,
    },
  });
}

function constructorOptions(storage, anchorAuthority, scope = {}) {
  return {
    storage,
    anchorAuthority,
    allowTestWitness: true,
    customerId: scope.customerId || CUSTOMER_ID,
    deploymentId: scope.deploymentId || DEPLOYMENT_ID,
    globalPublicKeys: { [GLOBAL_KEY_ID]: globalKeys.publicKey },
    distributionPublicKeys: { [DISTRIBUTION_KEY_ID]: distributionKeys.publicKey },
    stateIntegrityAuthority: {
      keyId: 'rw-catalog-state-integrity-customer',
      secret: stateSecret,
    },
  };
}

function expectation(state) {
  return {
    distributionSequence: state.distributionSequence,
    globalReleaseId: state.globalReleaseId,
    globalVersion: state.globalVersion,
    globalArtifactDigest: state.globalArtifactDigest,
    recordsDigest: state.recordsDigest,
  };
}

test('a new customer can adopt the current global catalog at distribution sequence one', () => {
  const { catalog } = setup();
  const artifacts = pair(1, globalArtifact(57));
  const applied = catalog.applySignedRelease(artifacts);
  assert.equal(applied.state.distributionSequence, 1);
  assert.equal(applied.state.globalVersion, 57);
  assert.equal(applied.acknowledgement.targetDigest,
    protocol.payloadDigest(artifacts.distributionArtifact.payload,
      protocol.CHANNEL_KINDS.CATALOG_DISTRIBUTION));
  assert.equal(applied.acknowledgement.targetDigest, applied.state.distributionPayloadDigest);
  assert.notEqual(applied.acknowledgement.targetDigest,
    applied.state.distributionArtifactDigest);
  assert.equal(catalog.createAcknowledgement(expectation(applied.state)).targetDigest,
    applied.acknowledgement.targetDigest);
  assert.equal(catalog.applySignedRelease(artifacts).action, 'acknowledge');
  const effective = catalog.readEffectiveCatalog(expectation(applied.state));
  assert.equal(effective.globalVersion, 57);
  assert.equal(effective.records[0].catalogId, 'alpha');
  assert.deepEqual(catalog.readiness(), { ready: true, reason: 'ready' });
});

test('a new customer can adopt a signed current release that republishes a rollback target', () => {
  const { catalog } = setup();
  const rollback = globalArtifact(60, [record('rollback', 'rollback.ai')], {
    rollbackOfGlobalVersion: 57,
  });
  const applied = catalog.applySignedRelease(pair(1, rollback));
  assert.equal(applied.state.distributionSequence, 1);
  assert.equal(applied.state.globalVersion, 60);
  assert.deepEqual(catalog.readEffectiveCatalog(expectation(applied.state)).records
    .map((value) => value.catalogId), ['rollback']);
});

test('preview and staged downloads remain pending until a signed required distribution activates', () => {
  const { catalog, storage } = setup();
  const preview = pair(1, globalArtifact(57), {
    rollout: { mode: 'preview', cohortBps: 0 },
  });
  const staged = catalog.applySignedRelease(preview);
  assert.equal(staged.action, 'stage');
  assert.equal(staged.state.activationStatus, 'pending');
  assert.equal(staged.acknowledgement.lifecycleStage, 'delivered');
  assert.equal(catalog.readEffectiveCatalog(expectation(staged.state)), null);
  assert.equal(catalog.readPendingCatalog(expectation(staged.state)).distributionSequence, 1);
  assert.equal(storage.data.active, null);

  const requiredArtifacts = pair(2, globalArtifact(58, [record('beta', 'beta.ai')]), {
    rollout: { mode: 'required', cohortBps: 10_000 },
  });
  const activated = catalog.applySignedRelease(requiredArtifacts);
  assert.equal(activated.action, 'apply');
  assert.equal(activated.state.activationStatus, 'active');
  assert.equal(activated.acknowledgement.lifecycleStage, 'applied');
  assert.equal(catalog.readPendingCatalog(expectation(activated.state)), null);
  assert.equal(catalog.readEffectiveCatalog(expectation(activated.state)).records[0].catalogId,
    'beta');
});

test('customer verifies two signatures, exact digest link, and exact tenant scope', () => {
  const { catalog } = setup();
  const global = globalArtifact();
  const wrongCustomer = pair(1, global, { customerId: 'customer_two' });
  assert.throws(() => catalog.applySignedRelease(wrongCustomer), { code: 'customer_mismatch' });
  const wrongDeployment = pair(1, global, { deploymentId: WRONG_DEPLOYMENT_ID });
  assert.throws(() => catalog.applySignedRelease(wrongDeployment), { code: 'deployment_mismatch' });
  const wrongLink = pair(1, global, { globalArtifactDigest: '0'.repeat(64) });
  assert.throws(() => catalog.applySignedRelease(wrongLink), { code: 'catalog_artifact_link_invalid' });
  const badGlobal = pair(1, global);
  badGlobal.globalArtifact.signature = Buffer.alloc(64).toString('base64');
  assert.throws(() => catalog.applySignedRelease(badGlobal), { code: 'invalid_signature' });
  const badDistribution = pair(1, global);
  badDistribution.distributionArtifact.signature = Buffer.alloc(64).toString('base64');
  assert.throws(() => catalog.applySignedRelease(badDistribution), { code: 'invalid_signature' });
});

test('global version and deployment distribution sequence progress independently', () => {
  const { catalog } = setup();
  const global57 = globalArtifact(57);
  const first = catalog.applySignedRelease(pair(1, global57));
  const global61 = globalArtifact(61, [record('beta', 'beta.ai')]);
  const second = catalog.applySignedRelease(pair(2, global61));
  assert.equal(second.state.distributionSequence, 2);
  assert.equal(second.state.globalVersion, 61);
  assert.throws(() => catalog.applySignedRelease(pair(4, global61)), {
    code: 'distribution_sequence_gap',
  });
  assert.throws(() => catalog.readEffectiveCatalog({
    ...expectation(second.state),
    globalVersion: first.state.globalVersion,
  }), { code: 'catalog_read_version_mismatch' });
});

test('every versioned read rejects a valid row or artifact swapped into the wrong lookup key', () => {
  const { catalog, storage } = setup();
  const first = catalog.applySignedRelease(pair(1, globalArtifact(57)));
  const second = catalog.applySignedRelease(pair(2, globalArtifact(58,
    [record('beta', 'beta.ai')])));
  storage.tamper((data) => {
    const rowOne = clone(data.distributions.get(1));
    const rowTwo = clone(data.distributions.get(2));
    data.distributions.set(1, rowTwo);
    data.distributions.set(2, rowOne);
  });
  assert.throws(() => catalog.referencedSigningKeyIds(), { code: 'catalog_history_corrupt' });
  assert.throws(() => catalog.readEffectiveCatalog(expectation(second.state)), {
    code: 'catalog_integrity_head_invalid',
  });
  assert.notEqual(first.state.globalArtifactDigest, second.state.globalArtifactDigest);
});

test('authenticated monotonic anchor rejects a complete valid old state and high-water replay', () => {
  const { catalog, storage, anchorStorage } = setup();
  const first = catalog.applySignedRelease(pair(1, globalArtifact(57)));
  const old = storage.snapshot();
  const second = catalog.applySignedRelease(pair(2, globalArtifact(58,
    [record('beta', 'beta.ai')])));
  storage.restore(old);
  assert.equal([...anchorStorage.snapshot().values()][0].payload.revision, 2);
  assert.equal(catalog.readiness().ready, false);
  assert.throws(() => catalog.readEffectiveCatalog(expectation(first.state)), {
    code: 'catalog_integrity_head_invalid',
  });
  assert.notEqual(first.state.distributionSequence, second.state.distributionSequence);
});

test('catalog witness binds ACK high-water and rejects the pre-ACK committed snapshot', () => {
  const storage = new ReferenceCatalogStorage();
  storage.captureBeforeAcknowledgementInsert = true;
  const { catalog } = setup(storage);
  const applied = catalog.applySignedRelease(pair(1, globalArtifact(57)));
  const originalBytes = protocol.canonicalJson(applied.acknowledgement);
  assert.equal(storage.capturedBeforeAcknowledgementInsert, null);
  const vulnerable = storage.snapshot();
  vulnerable.acknowledgementTransitions.clear();
  storage.restore(vulnerable);
  assert.deepEqual(catalog.readiness(), {
    ready: false,
    reason: 'catalog_integrity_head_invalid',
  });
  assert.throws(() => catalog.createAcknowledgement(expectation(applied.state)), {
    code: 'catalog_integrity_head_invalid',
  });
  assert.equal(protocol.canonicalJson(applied.acknowledgement), originalBytes);
});

test('middle audit deletion and reordering freeze readiness', () => {
  const deletion = setup();
  let latest;
  for (let sequence = 1; sequence <= 3; sequence += 1) {
    latest = deletion.catalog.applySignedRelease(pair(sequence, globalArtifact(56 + sequence)));
  }
  deletion.storage.tamper((data) => data.auditEvents.get('catalog_distribution').delete(2));
  assert.equal(deletion.catalog.readiness().ready, false);
  assert.throws(() => deletion.catalog.readEffectiveCatalog(expectation(latest.state)), {
    code: 'catalog_audit_invalid',
  });

  const reordered = setup();
  for (let sequence = 1; sequence <= 3; sequence += 1) {
    reordered.catalog.applySignedRelease(pair(sequence, globalArtifact(56 + sequence)));
  }
  reordered.storage.tamper((data) => {
    const events = data.auditEvents.get('catalog_distribution');
    const second = events.get(2);
    events.set(2, events.get(3));
    events.set(3, second);
  });
  assert.equal(reordered.catalog.readiness().ready, false);
});

test('pending witness freezes reads and deterministic reconciliation finalizes a committed mutation', () => {
  const { catalog, storage } = setup();
  storage.captureBeforePendingClear = true;
  const result = catalog.applySignedRelease(pair(1, globalArtifact(57)));
  assert.ok(storage.capturedBeforePendingClear);
  storage.restore(storage.capturedBeforePendingClear);
  assert.deepEqual(catalog.readiness(), { ready: false, reason: 'catalog_readiness_frozen' });
  assert.throws(() => catalog.readEffectiveCatalog(expectation(result.state)), {
    code: 'catalog_readiness_frozen',
  });
  assert.deepEqual(catalog.reconcile(), { action: 'finalized' });
  assert.equal(catalog.readiness().ready, true);
});

test('tenant overrides survive global changes and never enter signed global records', () => {
  const { catalog, storage } = setup();
  const first = catalog.applySignedRelease(pair(1, globalArtifact(57)));
  catalog.putTenantOverride({
    catalogId: 'alpha', revision: 1, classification: 'ai_adjacent',
    riskTier: 'moderate', disposition: 'warn', updatedAt: '2026-01-01T02:00:00.000Z',
  });
  const secondGlobal = globalArtifact(58, [record('alpha', 'alpha.ai', 'not_ai')]);
  const second = catalog.applySignedRelease(pair(2, secondGlobal));
  const effective = catalog.readEffectiveCatalog(expectation(second.state)).records[0];
  assert.equal(effective.globalClassification, 'not_ai');
  assert.equal(effective.classification, 'ai_adjacent');
  assert.equal(effective.disposition, 'warn');
  assert.equal(JSON.stringify(storage.data.current.globalArtifact).includes('ai_adjacent'), false);
  assert.equal(first.state.globalVersion, 57);
});

test('tenant override tombstones preserve monotonic revisions and allow an explicit regrant', () => {
  const { catalog, storage } = setup();
  const applied = catalog.applySignedRelease(pair(1, globalArtifact(57)));
  const first = {
    catalogId: 'alpha', revision: 1, classification: 'ai_adjacent',
    riskTier: 'moderate', disposition: 'warn', updatedAt: '2026-01-01T02:00:00.000Z',
  };
  assert.equal(catalog.putTenantOverride(first).action, 'apply');
  assert.equal(catalog.deleteTenantOverride({
    catalogId: 'alpha', revision: 2, updatedAt: '2026-01-01T03:00:00.000Z',
  }).deleted, true);
  const tombstone = storage.data.overrides.get('alpha').payload;
  assert.equal(tombstone.status, 'deleted');
  assert.equal(tombstone.record, null);
  assert.equal(catalog.readEffectiveCatalog(expectation(applied.state)).records[0].disposition,
    'inherit');
  assert.throws(() => catalog.putTenantOverride(first), { code: 'tenant_override_stale' });
  assert.equal(catalog.putTenantOverride({
    ...first, revision: 3, disposition: 'block', updatedAt: '2026-01-01T04:00:00.000Z',
  }).action, 'apply');
  const effective = catalog.readEffectiveCatalog(expectation(applied.state)).records[0];
  assert.equal(effective.disposition, 'block');
  assert.equal(effective.overrideRevision, 3);
});

test('tenant override tamper, deletion, and complete primary rewind freeze readiness', () => {
  const tampered = setup();
  tampered.catalog.putTenantOverride({
    catalogId: 'alpha', revision: 1, classification: null, riskTier: null,
    disposition: 'warn', updatedAt: '2026-01-01T02:00:00.000Z',
  });
  tampered.storage.tamper((data) => {
    data.overrides.get('alpha').mac = Buffer.alloc(32, 1).toString('base64');
  });
  assert.equal(tampered.catalog.readiness().reason, 'tenant_override_corrupt');

  const deleted = setup();
  deleted.catalog.putTenantOverride({
    catalogId: 'alpha', revision: 1, classification: null, riskTier: null,
    disposition: 'warn', updatedAt: '2026-01-01T02:00:00.000Z',
  });
  deleted.storage.tamper((data) => data.overrides.delete('alpha'));
  assert.equal(deleted.catalog.readiness().reason, 'tenant_override_integrity_invalid');

  const rewound = setup();
  rewound.catalog.putTenantOverride({
    catalogId: 'alpha', revision: 1, classification: null, riskTier: null,
    disposition: 'warn', updatedAt: '2026-01-01T02:00:00.000Z',
  });
  const oldPrimary = rewound.storage.snapshot();
  rewound.catalog.putTenantOverride({
    catalogId: 'alpha', revision: 2, classification: null, riskTier: null,
    disposition: 'block', updatedAt: '2026-01-01T03:00:00.000Z',
  });
  rewound.storage.restore(oldPrimary);
  assert.equal(rewound.catalog.readiness().reason, 'tenant_override_integrity_invalid');
});

test('local observations remain strict customer-local metadata', () => {
  const { catalog, storage } = setup();
  const input = {
    registrableDomain: 'alpha.ai', revision: 1,
    firstSeenDay: '2026-01-01', lastSeenDay: '2026-01-01',
    observationCountBucket: '1', sourceTypes: ['browser_destination'],
    localClassification: 'unknown', localOutcome: 'observed',
    updatedAt: '2026-01-01T02:00:00.000Z',
  };
  assert.equal(catalog.putLocalObservation(input).action, 'apply');
  assert.equal(catalog.putLocalObservation(input).action, 'acknowledge');
  assert.throws(() => catalog.putLocalObservation({ ...input, prompt: 'private prompt' }), {
    code: 'local_observation_invalid',
  });
  assert.deepEqual(catalog.readLocalObservations(), [input]);
  assert.equal(storage.data.current, null);
});

test('history retention creates authenticated tombstones and keeps key references', () => {
  const { catalog, storage } = setup();
  const total = MAX_ACTIVE_AUDIT_EVENTS + 1;
  const oldestRetainedTombstone = total - MAX_ACTIVE_DISTRIBUTIONS
    - MAX_ARCHIVED_TOMBSTONES + 1;
  let result;
  let historyBeforeLast;
  for (let sequence = 1; sequence <= total; sequence += 1) {
    result = catalog.applySignedRelease(pair(sequence, globalArtifact(56 + sequence)));
    if (sequence === total - 1) historyBeforeLast = storage.snapshot();
  }
  assert.equal(storage.data.distributions.size, MAX_ACTIVE_DISTRIBUTIONS);
  assert.equal(storage.data.globals.size, MAX_ACTIVE_DISTRIBUTIONS);
  assert.equal(ROLLBACK_WINDOW_DISTRIBUTIONS, MAX_ACTIVE_DISTRIBUTIONS);
  assert.equal(storage.data.tombstones.size, MAX_ARCHIVED_TOMBSTONES);
  assert.equal(storage.data.tombstones.has(oldestRetainedTombstone - 1), false);
  assert.equal(storage.data.tombstones.has(oldestRetainedTombstone), true);
  assert.equal(storage.data.historyCheckpoint.payload.throughSequence,
    oldestRetainedTombstone - 1);
  assert.equal(storage.data.auditCheckpoints.get('catalog_distribution').payload.sequence, 1);
  assert.equal(storage.data.auditEvents.get('catalog_distribution').size,
    MAX_ACTIVE_AUDIT_EVENTS);
  assert.deepEqual(catalog.referencedSigningKeyIds(), [
    DISTRIBUTION_KEY_ID,
    GLOBAL_KEY_ID,
  ].sort());
  assert.deepEqual(catalog.signingKeyReferenceCounts(), {
    [DISTRIBUTION_KEY_ID]: total,
    [GLOBAL_KEY_ID]: total,
  });
  assert.deepEqual(catalog.canRetireSigningKey(GLOBAL_KEY_ID), {
    keyId: GLOBAL_KEY_ID,
    references: total,
    canRetire: false,
  });
  assert.deepEqual(catalog.canRetireSigningKey('rw-catalog-global-retired'), {
    keyId: 'rw-catalog-global-retired', references: 0, canRetire: true,
  });
  assert.equal(catalog.readEffectiveCatalog(expectation(result.state)).globalVersion,
    56 + total);
  const stable = storage.snapshot();
  storage.tamper((data) => data.tombstones.delete(oldestRetainedTombstone));
  assert.equal(catalog.readiness().reason, 'catalog_history_corrupt');
  storage.restore(stable);
  storage.tamper((data) => {
    data.historyCheckpoint = clone(historyBeforeLast.historyCheckpoint);
    data.tombstones = cloneMap(historyBeforeLast.tombstones);
  });
  assert.equal(catalog.readiness().ready, false);
  storage.restore(stable);
  storage.data.tombstones.values().next().value.wrapped.mac = '0'.repeat(64);
  assert.deepEqual(catalog.readiness(), {
    ready: false, reason: 'catalog_history_corrupt',
  });
  assert.throws(() => catalog.signingKeyReferenceCounts(), {
    code: 'catalog_history_corrupt',
  });
});

test('more than 32 distributions retain independently verifiable global rollback proof', () => {
  const { catalog, storage } = setup();
  const firstRecords = [record('rollback-a', 'rollback-a.ai')];
  const secondRecords = [record('rollback-b', 'rollback-b.ai')];
  const firstGlobal = globalArtifact(1, firstRecords);
  const secondGlobal = globalArtifact(2, secondRecords);
  catalog.applySignedRelease(pair(1, firstGlobal));
  for (let sequence = 2; sequence <= MAX_ACTIVE_DISTRIBUTIONS + 2; sequence += 1) {
    catalog.applySignedRelease(pair(sequence, secondGlobal));
  }
  assert.equal(storage.data.distributions.has(1), false);
  const stable = storage.snapshot();
  storage.tamper((data) => data.globals.delete(firstGlobal.payload.globalReleaseId));
  assert.deepEqual(catalog.readiness(), {
    ready: false,
    reason: 'catalog_integrity_head_invalid',
  });
  storage.restore(stable);
  const rollbackGlobal = globalArtifact(3, firstRecords, {
    rollbackOfGlobalVersion: 1,
  });
  const rolledBack = catalog.applySignedRelease(pair(
    MAX_ACTIVE_DISTRIBUTIONS + 3, rollbackGlobal,
  ));
  assert.equal(rolledBack.state.globalVersion, 3);
  assert.equal(rolledBack.state.distributionSequence, MAX_ACTIVE_DISTRIBUTIONS + 3);
});

test('serializable reference adapter rolls back a commit failure and uses independent handles', () => {
  const storage = new ReferenceCatalogStorage();
  const { catalog } = setup(storage);
  storage.failNextCommit = true;
  assert.throws(() => catalog.applySignedRelease(pair(1, globalArtifact(57))), {
    code: 'reference_commit_failed',
  });
  assert.equal(storage.data.current, null);
  assert.equal(storage.data.distributions.size, 0);
  assert.deepEqual(catalog.readiness(), { ready: false, reason: 'catalog_readiness_frozen' });
  assert.deepEqual(catalog.reconcile(), { action: 'rolled_back' });
  const applied = catalog.applySignedRelease(pair(1, globalArtifact(57)));
  catalog.readEffectiveCatalog(expectation(applied.state));
  assert.notEqual(storage.handles.at(-1), storage.handles.at(-2));
});

test('rotated manifests accept only active incoming keys while verify-only keys reverify stored history', () => {
  const storage = new ReferenceCatalogStorage();
  const anchorStorage = createReferenceMonotonicAnchorStorage();
  const authorityManifest = new MutableCatalogAuthorityManifest();
  const firstCatalog = setupWithManifest(storage, anchorStorage, authorityManifest, {
    global: { [GLOBAL_KEY_ID]: globalKeys.publicKey },
    distribution: { [DISTRIBUTION_KEY_ID]: distributionKeys.publicKey },
  });
  const firstGlobal = globalArtifact(57, [record('manifest-a', 'manifest-a.ai')], {
    authorityManifestGeneration: 1,
    authorityManifestKeySlot: 'current',
  });
  const first = firstCatalog.applySignedRelease(pair(1, firstGlobal, {
    authorityManifestGeneration: 1,
    authorityManifestKeySlot: 'current',
  }));

  authorityManifest.rotate();
  const rotatedCatalog = setupWithManifest(storage, anchorStorage, authorityManifest, {
    global: { [ROTATED_GLOBAL_KEY_ID]: rotatedGlobalKeys.publicKey },
    distribution: { [ROTATED_DISTRIBUTION_KEY_ID]: rotatedDistributionKeys.publicKey },
  });
  assert.deepEqual(rotatedCatalog.readiness(), { ready: true, reason: 'ready' });
  assert.equal(rotatedCatalog.readEffectiveCatalog(expectation(first.state))
    .records[0].catalogId, 'manifest-a');

  const staleGlobal = globalArtifact(58, [record('stale-a', 'stale-a.ai')], {
    authorityManifestGeneration: 1,
    authorityManifestKeySlot: 'current',
  });
  assert.throws(() => rotatedCatalog.applySignedRelease(pair(2, staleGlobal, {
    authorityManifestGeneration: 1,
    authorityManifestKeySlot: 'current',
  })), { code: 'unknown_signing_key' });

  const currentGlobal = globalArtifact(58, [record('manifest-b', 'manifest-b.ai')], {
    keyId: ROTATED_GLOBAL_KEY_ID,
    privateKey: rotatedGlobalKeys.privateKey,
    authorityManifestGeneration: 2,
    authorityManifestKeySlot: 'current',
  });
  const current = rotatedCatalog.applySignedRelease(pair(2, currentGlobal, {
    keyId: ROTATED_DISTRIBUTION_KEY_ID,
    privateKey: rotatedDistributionKeys.privateKey,
    authorityManifestGeneration: 2,
    authorityManifestKeySlot: 'current',
  }));
  assert.equal(current.state.distributionSequence, 2);
});

test('manifest rotation between incoming verification and customer commit fails closed', () => {
  const storage = new ReferenceCatalogStorage();
  const anchorStorage = createReferenceMonotonicAnchorStorage();
  const authorityManifest = new MutableCatalogAuthorityManifest();
  const catalog = setupWithManifest(storage, anchorStorage, authorityManifest, {
    global: { [GLOBAL_KEY_ID]: globalKeys.publicKey },
    distribution: { [DISTRIBUTION_KEY_ID]: distributionKeys.publicKey },
  });
  storage.beforeTransaction = () => authorityManifest.rotate();
  const incomingGlobal = globalArtifact(57, [record('rotation-race', 'rotation-race.ai')], {
    authorityManifestGeneration: 1,
    authorityManifestKeySlot: 'current',
  });
  assert.throws(() => catalog.applySignedRelease(pair(1, incomingGlobal, {
    authorityManifestGeneration: 1,
    authorityManifestKeySlot: 'current',
  })), { code: 'authority_manifest_changed' });
  assert.equal(storage.data.current, null);
});

test('normal catalog construction rejects an unbranded generic storage adapter', () => {
  const storage = new ReferenceCatalogStorage();
  const anchorAuthority = setup().anchorAuthority;
  assert.throws(() => createShadowAiCatalogState(
    constructorOptions(storage, anchorAuthority),
  ), { code: 'shadow_ai_customer_storage_scope_required' });
});

test('reference catalog construction binds one generic adapter to one immutable scope', () => {
  assert.notStrictEqual(createReferenceShadowAiCatalogState, createShadowAiCatalogState);
  const storage = new ReferenceCatalogStorage();
  const anchorAuthority = setup().anchorAuthority;
  const options = constructorOptions(storage, anchorAuthority);
  assert.doesNotThrow(() => createReferenceShadowAiCatalogState(options));
  assert.doesNotThrow(() => createReferenceShadowAiCatalogState(options));
  assert.throws(() => createReferenceShadowAiCatalogState({
    ...options,
    deploymentId: SIBLING_DEPLOYMENT_ID,
  }), { code: 'shadow_ai_reference_storage_scope_mismatch' });
  assert.throws(() => createReferenceShadowAiCatalogState({
    ...options,
    env: { NODE_ENV: 'production' },
  }), { code: 'shadow_ai_reference_constructor_unavailable' });
  assert.throws(() => createReferenceShadowAiCatalogState({
    ...options,
    assurance: 'test_reference',
  }), { code: 'shadow_ai_reference_option_invalid' });
  assert.throws(() => createReferenceShadowAiCatalogState({
    ...options,
    productionReady: false,
  }), { code: 'shadow_ai_reference_option_invalid' });
  assert.throws(() => createProductionShadowAiCatalogState(options), {
    code: 'shadow_ai_production_adapter_required',
  });
});

test('invalid storage contracts and key-purpose reuse fail before state mutation', () => {
  const invalid = setup({ transaction: (callback) => callback({}) }).catalog;
  assert.throws(() => invalid.applySignedRelease(pair(1, globalArtifact(57))), {
    code: 'storage_invalid',
  });
  const storage = new ReferenceCatalogStorage();
  assert.throws(() => createReferenceShadowAiCatalogState({
    storage,
    anchorAuthority: setup().anchorAuthority,
    allowTestWitness: true,
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    globalPublicKeys: { [GLOBAL_KEY_ID]: globalKeys.publicKey },
    distributionPublicKeys: {
      [DISTRIBUTION_KEY_ID]: globalKeys.publicKey,
    },
    stateIntegrityAuthority: {
      keyId: 'rw-catalog-state-integrity-customer', secret: stateSecret,
    },
  }), { code: 'vendor_key_identity_reused' });
});

class MutableCatalogAuthorityManifest {
  constructor() { this.generation = 1; }

  reconcile() { return { action: 'none' }; }

  rotate() { this.generation = 2; }

  registry() {
    const generation = this.generation;
    const entries = {
      [KEY_PURPOSES.CATALOG_GLOBAL]: generation === 1
        ? [{ slot: 'current', keyId: GLOBAL_KEY_ID, key: globalKeys.publicKey }]
        : [
          { slot: 'current', keyId: ROTATED_GLOBAL_KEY_ID, key: rotatedGlobalKeys.publicKey },
          { slot: 'verifyOnly', keyId: GLOBAL_KEY_ID, key: globalKeys.publicKey },
        ],
      [KEY_PURPOSES.CATALOG_DISTRIBUTION]: generation === 1
        ? [{ slot: 'current', keyId: DISTRIBUTION_KEY_ID, key: distributionKeys.publicKey }]
        : [
          { slot: 'current', keyId: ROTATED_DISTRIBUTION_KEY_ID,
            key: rotatedDistributionKeys.publicKey },
          { slot: 'verifyOnly', keyId: DISTRIBUTION_KEY_ID, key: distributionKeys.publicKey },
        ],
    };
    const publicRecord = (record, purpose) => ({
      purpose,
      slot: record.slot,
      keyId: record.keyId,
      identity: keyFingerprint(record.key),
      identityType: 'ed25519_public',
      references: record.slot === 'verifyOnly' ? 1 : 0,
      publicKeySpki: record.key.export({ type: 'spki', format: 'der' }).toString('base64'),
    });
    return Object.freeze({
      generation,
      list(purpose) {
        return (entries[purpose] || []).map((record) => publicRecord(record, purpose));
      },
      activePublicKeys(purpose) {
        return new Map((entries[purpose] || [])
          .filter((record) => ['current', 'next'].includes(record.slot))
          .map((record) => [record.keyId, record.key]));
      },
      verificationPublicKey(purpose, keyId) {
        const record = (entries[purpose] || []).find((candidate) => candidate.keyId === keyId);
        if (!record) throw Object.assign(new Error('manifest key missing'), {
          code: 'authority_manifest_public_key_required',
        });
        return new Map([[record.keyId, record.key]]);
      },
      assertPublicKey(purpose, keyId, fingerprint) {
        const record = (entries[purpose] || []).find((candidate) =>
          ['current', 'next'].includes(candidate.slot) && candidate.keyId === keyId
            && keyFingerprint(candidate.key) === fingerprint);
        if (!record) throw Object.assign(new Error('manifest mismatch'), {
          code: 'vendor_authority_manifest_mismatch',
        });
      },
    });
  }
}

class ReferenceCatalogStorage {
  constructor() {
    this.data = newData();
    this.version = 0;
    this.handles = [];
    this.failNextCommit = false;
    this.captureBeforePendingClear = false;
    this.capturedBeforePendingClear = null;
    this.captureBeforeAcknowledgementInsert = false;
    this.capturedBeforeAcknowledgementInsert = null;
    this.beforeTransaction = null;
  }

  transaction(callback) {
    const beforeTransaction = this.beforeTransaction;
    this.beforeTransaction = null;
    if (beforeTransaction) beforeTransaction();
    const baseVersion = this.version;
    const working = copyData(this.data);
    const tx = this.#transaction(working);
    this.handles.push(tx);
    const result = callback(tx);
    if (result && typeof result.then === 'function') throw referenceError('reference_async_rejected');
    if (this.failNextCommit) {
      this.failNextCommit = false;
      throw referenceError('reference_commit_failed');
    }
    if (baseVersion !== this.version) throw referenceError('reference_serialization_conflict');
    this.data = working;
    this.version += 1;
    return result;
  }

  snapshot() { return copyData(this.data); }

  restore(value) {
    this.data = copyData(value);
    this.version += 1;
  }

  tamper(callback) {
    callback(this.data);
    this.version += 1;
  }

  #transaction(data) {
    const eventMap = (namespace) => {
      if (!data.auditEvents.has(namespace)) data.auditEvents.set(namespace, new Map());
      return data.auditEvents.get(namespace);
    };
    return {
      readCurrentCatalog: () => clone(data.current),
      compareAndSetCurrentCatalog: (expected, value) => {
        const current = data.current?.distributionSequence || 0;
        if (current !== expected) return false;
        data.current = clone(value);
        return true;
      },
      readActiveCatalog: () => clone(data.active),
      compareAndSetActiveCatalog: (expected, value) => {
        const current = data.active?.distributionSequence || 0;
        if (current !== expected) return false;
        data.active = clone(value);
        return true;
      },
      readGlobalCatalogArtifact: (id) => clone(data.globals.get(id)?.artifact),
      listGlobalCatalogArtifacts: () => [...data.globals].map(([globalReleaseId, row]) => ({
        globalReleaseId,
        globalVersion: row.version,
        globalArtifactDigest: row.digest,
        artifact: clone(row.artifact),
      })),
      insertGlobalCatalogArtifact: (id, version, digest, artifact) => {
        if (data.globals.has(id)) return false;
        data.globals.set(id, { version, digest, artifact: clone(artifact) });
        return true;
      },
      deleteGlobalCatalogArtifact: (id, digest) => {
        const row = data.globals.get(id);
        if (!row || row.digest !== digest) return false;
        data.globals.delete(id);
        return true;
      },
      readCatalogDistribution: (sequence) => clone(data.distributions.get(sequence)?.value),
      insertCatalogDistribution: (sequence, digest, value) => {
        if (data.distributions.has(sequence)) return false;
        data.distributions.set(sequence, { digest, value: clone(value) });
        return true;
      },
      listCatalogDistributions: () => [...data.distributions].map(([sequence, row]) => ({
        distributionSequence: sequence,
        distributionDigest: row.digest,
        value: clone(row.value),
      })),
      deleteCatalogDistribution: (sequence, digest) => {
        const row = data.distributions.get(sequence);
        if (!row || row.digest !== digest) return false;
        data.distributions.delete(sequence);
        return true;
      },
      writeCatalogTombstone: (sequence, digest, wrapped) => {
        if (data.tombstones.has(sequence)) return false;
        data.tombstones.set(sequence, { digest, wrapped: clone(wrapped) });
        return true;
      },
      deleteCatalogTombstone: (sequence, digest, wrappedDigest) => {
        const row = data.tombstones.get(sequence);
        if (!row || row.digest !== digest || canonicalDigest(row.wrapped) !== wrappedDigest) {
          return false;
        }
        data.tombstones.delete(sequence);
        return true;
      },
      listCatalogTombstones: () => [...data.tombstones.values()].map((row) => clone(row.wrapped)),
      readCatalogHistoryCheckpoint: () => clone(data.historyCheckpoint),
      compareAndSetCatalogHistoryCheckpoint: (expectedSequence, wrapped) => {
        if ((data.historyCheckpoint?.payload?.throughSequence || 0) !== expectedSequence) {
          return false;
        }
        data.historyCheckpoint = clone(wrapped);
        return true;
      },
      readCatalogIntegrityHead: (namespace) => clone(data.heads.get(namespace)),
      compareAndSetCatalogIntegrityHead: (namespace, expected, wrapped) => {
        const current = data.heads.get(namespace)?.payload?.revision || 0;
        if (current !== expected) return false;
        data.heads.set(namespace, clone(wrapped));
        return true;
      },
      readCatalogPendingWitness: (namespace) => clone(data.pending.get(namespace)),
      writeCatalogPendingWitness: (namespace, expected, wrapped) => {
        const current = data.current?.distributionSequence || 0;
        if (data.pending.has(namespace) || current !== expected) return false;
        data.pending.set(namespace, clone(wrapped));
        return true;
      },
      clearCatalogPendingWitness: (namespace, digest) => {
        const wrapped = data.pending.get(namespace);
        if (!wrapped || canonicalDigest(wrapped) !== digest) return false;
        if (this.captureBeforePendingClear) {
          this.capturedBeforePendingClear = copyData(data);
          this.captureBeforePendingClear = false;
        }
        data.pending.delete(namespace);
        return true;
      },
      readCatalogAuditCheckpoint: (namespace) => clone(data.auditCheckpoints.get(namespace)),
      compareAndSetCatalogAuditCheckpoint: (namespace, expectedSequence, wrapped) => {
        const current = data.auditCheckpoints.get(namespace)?.payload?.sequence || 0;
        if (current !== expectedSequence) return false;
        data.auditCheckpoints.set(namespace, clone(wrapped));
        return true;
      },
      listCatalogAuditEvents: (namespace) => [...eventMap(namespace)]
        .sort(([left], [right]) => left - right).map(([, wrapped]) => clone(wrapped)),
      appendCatalogAuditEvent: (namespace, sequence, digest, wrapped) => {
        const events = eventMap(namespace);
        if (events.has(sequence) || wrapped.payload.eventDigest !== digest) return false;
        events.set(sequence, clone(wrapped));
        return true;
      },
      deleteCatalogAuditEvent: (namespace, sequence, digest) => {
        const events = eventMap(namespace);
        const wrapped = events.get(sequence);
        if (!wrapped || canonicalDigest(wrapped) !== digest) return false;
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
      writeLocalObservation: (value) => {
        data.observations.set(value.registrableDomain, clone(value));
      },
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
        if (this.captureBeforeAcknowledgementInsert && this.data.current
            && this.data.acknowledgementTransitions.size === 0) {
          this.capturedBeforeAcknowledgementInsert = copyData(this.data);
          this.captureBeforeAcknowledgementInsert = false;
        }
        if (data.acknowledgementTransitions.has(key)) return false;
        data.acknowledgementTransitions.set(key, { digest, row: clone(row) });
        return true;
      },
    };
  }
}

function newData() {
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

function copyData(data) {
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
    auditEvents: cloneNestedMap(data.auditEvents),
    overrides: cloneMap(data.overrides),
    overrideHead: clone(data.overrideHead),
    observations: cloneMap(data.observations),
    acknowledgementTransitions: cloneMap(data.acknowledgementTransitions),
  };
}

function cloneMap(map) {
  return new Map([...map].map(([key, value]) => [key, clone(value)]));
}

function cloneNestedMap(map) {
  return new Map([...map].map(([key, value]) => [key, cloneMap(value)]));
}

function canonicalDigest(value) {
  return crypto.createHash('sha256').update(protocol.canonicalJson(value), 'utf8').digest('hex');
}

function clone(value) {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}

function referenceError(code) {
  const error = new Error('reference storage rejected');
  error.code = code;
  return error;
}
