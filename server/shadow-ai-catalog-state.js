'use strict';

const crypto = require('node:crypto');
const { z } = require('zod');
const protocol = require('./vendor-control-protocol');
const {
  assertProductionMonotonicAnchorAuthority,
  INDEPENDENT_WITNESS_ASSURANCE,
  TEST_WITNESS_ASSURANCE,
} = require('./monotonic-anchor-authority');
const {
  assertCustomerShadowAiStorageScope,
  assertProductionCustomerShadowAiStorage,
} = require('./customer-shadow-ai-storage');
const {
  KEY_PURPOSES,
  keyFingerprint,
  normalizePublicKeys,
  verifySignedArtifact,
} = require('./vendor-signed-artifact');

const STATE_VERSION = 2;
const STATE_NAMESPACE = 'catalog_distribution';
const MAX_ACTIVE_DISTRIBUTIONS = 32;
const ROLLBACK_WINDOW_DISTRIBUTIONS = MAX_ACTIVE_DISTRIBUTIONS;
const MAX_RETAINED_GLOBAL_ARTIFACTS = ROLLBACK_WINDOW_DISTRIBUTIONS + 1;
const MAX_ARCHIVED_TOMBSTONES = 128;
const MAX_ACTIVE_AUDIT_EVENTS = 256;
const MAX_TENANT_OVERRIDES = 10_000;
const KEY_ID_RE = /^rw-catalog-state-integrity-[a-z0-9][a-z0-9_.-]{0,63}$/;
const SAFE_SLUG_RE = /^[a-z0-9][a-z0-9_.-]{0,63}$/;
const SHA256_RE = /^[a-f0-9]{64}$/;
const ISO_MS_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const DAY_RE = /^\d{4}-\d{2}-\d{2}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const OBSERVATION_BUCKETS = Object.freeze(['1', '2-5', '6-20', '21-100', '100+']);
const ZERO_DIGEST = '0'.repeat(64);
const CUSTOMER_CATALOG_WITNESS_PURPOSE = 'customer_catalog_witness';
const REFERENCE_STORAGE_SCOPES = new WeakMap();
const CUSTOMER_SHADOW_AI_PACKAGE_BOUNDARY = Object.freeze({
  includes: Object.freeze([
    'shadow-ai-catalog-state', 'customer-shadow-ai-sqlite',
    'monotonic witness client', 'signed public verification',
  ]),
  excludes: Object.freeze([
    'vendor-shadow-ai-intelligence', 'vendor-authority-manifest',
    'vendor signing private keys', 'vendor ledgers', 'vendor compaction authority',
    'Owner routes', 'Owner secrets',
  ]),
});

const candidateShape = protocol.CHANNEL_SCHEMAS[protocol.CHANNEL_KINDS.SHADOW_CANDIDATE].shape;
const observationSchema = z.object({
  registrableDomain: candidateShape.registrableDomain,
  revision: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
  firstSeenDay: z.string().regex(DAY_RE).refine(canonicalDay),
  lastSeenDay: z.string().regex(DAY_RE).refine(canonicalDay),
  observationCountBucket: candidateShape.observationCountBucket,
  sourceTypes: z.array(candidateShape.sourceType).min(1).max(4).refine(sortedUnique),
  localClassification: candidateShape.localClassification,
  localOutcome: candidateShape.localOutcome,
  updatedAt: z.string().regex(ISO_MS_RE).refine(canonicalTime),
}).strict().superRefine((value, ctx) => {
  if (value.lastSeenDay < value.firstSeenDay) issue(ctx, 'lastSeenDay');
});

const overrideSchema = z.object({
  catalogId: z.string().regex(SAFE_SLUG_RE),
  revision: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
  classification: z.enum(['generative_ai', 'ai_adjacent', 'not_ai']).nullable(),
  riskTier: z.enum(['low', 'moderate', 'high', 'critical']).nullable(),
  disposition: z.enum(['inherit', 'allow', 'warn', 'block']),
  updatedAt: z.string().regex(ISO_MS_RE).refine(canonicalTime),
}).strict();
const overrideDeleteSchema = z.object({
  catalogId: z.string().regex(SAFE_SLUG_RE),
  revision: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
  updatedAt: z.string().regex(ISO_MS_RE).refine(canonicalTime),
}).strict();

function createShadowAiCatalogState(options) {
  return createCatalogApi(validateOptions(options, 'customer'));
}

function createReferenceShadowAiCatalogState(options) {
  assertReferenceConstructorOptions(options);
  return createCatalogApi(validateOptions({ ...options, allowTestWitness: true }, 'reference'));
}

function createCatalogApi(config) {
  return Object.freeze({
    applySignedRelease: (artifacts) => applySignedRelease(config, artifacts),
    createAcknowledgement: (expected) => createAcknowledgement(config, expected),
    putTenantOverride: (override) => putTenantOverride(config, override),
    deleteTenantOverride: (override) => deleteTenantOverride(config, override),
    putLocalObservation: (observation) => putLocalObservation(config, observation),
    readEffectiveCatalog: (expected) => readEffectiveCatalog(config, expected),
    readPendingCatalog: (expected) => readPendingCatalog(config, expected),
    readLocalObservations: () => readLocalObservations(config),
    readiness: () => readiness(config),
    reconcile: () => reconcile(config),
    referencedSigningKeyIds: () => referencedSigningKeyIds(config),
    signingKeyReferenceCounts: () => signingKeyReferenceCounts(config),
    canRetireSigningKey: (keyId) => canRetireSigningKey(config, keyId),
  });
}

function createProductionShadowAiCatalogState(options = {}) {
  try {
    assertProductionCustomerShadowAiStorage(options.storage);
    assertProductionMonotonicAnchorAuthority(options.anchorAuthority);
  } catch { throw stateError('shadow_ai_production_adapter_required'); }
  if (options.allowTestWitness !== undefined || options.productionReady !== undefined
      || options.assurance !== undefined) {
    throw stateError('shadow_ai_production_option_invalid');
  }
  if (!options.authorityManifest || typeof options.authorityManifest.registry !== 'function'
      || typeof options.authorityManifest.reconcile !== 'function') {
    throw stateError('authority_manifest_required');
  }
  return createShadowAiCatalogState({ ...options, allowTestWitness: false });
}

function validateOptions(options, storageMode = 'customer') {
  if (!options || typeof options !== 'object' || Array.isArray(options)) throw stateError('options_invalid');
  requireStorage(options.storage);
  validateScope(options.customerId, options.deploymentId);
  if (!['customer', 'reference'].includes(storageMode)) throw stateError('options_invalid');
  if (storageMode === 'customer') {
    assertCustomerShadowAiStorageScope(
      options.storage, options.customerId, options.deploymentId,
    );
  } else {
    assertReferenceStorageScope(options.storage, options.customerId, options.deploymentId);
  }
  const authorityManifest = normalizeAuthorityManifest(options.authorityManifest);
  const authorityRegistry = authorityManifest
    ? reconciledAuthorityRegistry(authorityManifest) : (options.authorityRegistry || null);
  const globalKeys = normalizePublicKeys(options.globalPublicKeys, {
    purpose: KEY_PURPOSES.CATALOG_GLOBAL,
    strictPurpose: true,
    authorityRegistry,
    forbiddenPublicKeyFingerprints: options.forbiddenPublicKeyFingerprints,
  });
  const distributionKeys = normalizePublicKeys(options.distributionPublicKeys, {
    purpose: KEY_PURPOSES.CATALOG_DISTRIBUTION,
    strictPurpose: true,
    authorityRegistry,
    forbiddenPublicKeyFingerprints: options.forbiddenPublicKeyFingerprints,
  });
  const globalFingerprints = new Set([...globalKeys.values()].map(keyFingerprint));
  if ([...distributionKeys.values()].some((key) => globalFingerprints.has(keyFingerprint(key)))) {
    throw stateError('vendor_key_identity_reused');
  }
  const integrity = createIntegrityAuthority(options.stateIntegrityAuthority);
  const forbiddenAnchorIdentities = new Set([
    ...globalFingerprints,
    ...[...distributionKeys.values()].map(keyFingerprint),
    integrity.identity,
  ]);
  const config = Object.freeze({
    storage: options.storage,
    anchorAuthority: requireAnchorAuthority(
      options.anchorAuthority, forbiddenAnchorIdentities, options.allowTestWitness === true,
    ),
    anchorNamespace: `catalog:${options.customerId}:${options.deploymentId}`,
    overrideAnchorNamespace: `catalog-overrides:${options.customerId}:${options.deploymentId}`,
    customerId: options.customerId,
    deploymentId: options.deploymentId,
    globalKeys,
    distributionKeys,
    authorityManifest,
    authorityRegistry,
    integrity,
    clock: typeof options.clock === 'function' ? options.clock : Date.now,
    randomUUID: typeof options.randomUUID === 'function' ? options.randomUUID : crypto.randomUUID,
  });
  if (storageMode === 'reference') bindReferenceStorageScope(
    options.storage, options.customerId, options.deploymentId,
  );
  return config;
}

function assertReferenceConstructorOptions(options) {
  if (!options || typeof options !== 'object' || Array.isArray(options)) return;
  if ('assurance' in options || 'productionReady' in options) {
    throw stateError('shadow_ai_reference_option_invalid');
  }
  const suppliedNodeEnv = options.env && typeof options.env === 'object'
    ? options.env.NODE_ENV : undefined;
  if (options.production === true
      || [process.env.NODE_ENV, suppliedNodeEnv].some((value) =>
        String(value || '').trim().toLowerCase() === 'production')) {
    throw stateError('shadow_ai_reference_constructor_unavailable');
  }
}

function bindReferenceStorageScope(storage, customerId, deploymentId) {
  const current = assertReferenceStorageScope(storage, customerId, deploymentId);
  if (!current) REFERENCE_STORAGE_SCOPES.set(storage, Object.freeze({
    customerId, deploymentId,
  }));
}

function assertReferenceStorageScope(storage, customerId, deploymentId) {
  const current = REFERENCE_STORAGE_SCOPES.get(storage);
  if (current && (current.customerId !== customerId
      || current.deploymentId !== deploymentId)) {
    throw stateError('shadow_ai_reference_storage_scope_mismatch');
  }
  return current;
}

function normalizeAuthorityManifest(value) {
  if (value === undefined) return null;
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || typeof value.registry !== 'function' || typeof value.reconcile !== 'function') {
    throw stateError('authority_manifest_invalid');
  }
  return value;
}

function reconciledAuthorityRegistry(authorityManifest) {
  try {
    authorityManifest.reconcile();
    const registry = authorityManifest.registry();
    if (!registry || typeof registry !== 'object'
        || !Number.isSafeInteger(registry.generation) || registry.generation < 1
        || typeof registry.activePublicKeys !== 'function'
        || typeof registry.verificationPublicKey !== 'function'
        || typeof registry.list !== 'function') {
      throw stateError('authority_manifest_invalid');
    }
    return registry;
  } catch (error) {
    if (error?.code === 'authority_manifest_invalid') throw error;
    throw stateError('authority_manifest_invalid');
  }
}

function requireAnchorAuthority(value, forbiddenIdentities, allowTestWitness) {
  const methods = ['abort', 'describe', 'finalize', 'prepare', 'read'];
  if (!value || typeof value !== 'object'
      || methods.some((method) => typeof value[method] !== 'function')) {
    throw stateError('anchor_authority_invalid');
  }
  const descriptor = value.describe();
  if (!descriptor || typeof descriptor !== 'object' || Array.isArray(descriptor)
      || Object.keys(descriptor).sort().join(',') !== 'assurance,identity,keyId,purpose'
      || descriptor.purpose !== CUSTOMER_CATALOG_WITNESS_PURPOSE
      || ![INDEPENDENT_WITNESS_ASSURANCE, TEST_WITNESS_ASSURANCE].includes(
        descriptor.assurance,
      )
      || (descriptor.assurance === TEST_WITNESS_ASSURANCE && !allowTestWitness)
      || !/^rw-anchor-[a-z0-9][a-z0-9_.-]{0,87}$/.test(String(descriptor.keyId || ''))
      || !SHA256_RE.test(String(descriptor.identity || ''))
      || forbiddenIdentities.has(descriptor.identity)) {
    throw stateError('anchor_authority_invalid');
  }
  return value;
}

function createIntegrityAuthority(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).sort().join(',') !== 'keyId,secret'
      || !KEY_ID_RE.test(String(value.keyId || ''))
      || !Buffer.isBuffer(value.secret) || value.secret.length !== 32) {
    throw stateError('state_integrity_authority_invalid');
  }
  const secret = Buffer.from(value.secret);
  const identity = crypto.createHash('sha256').update(secret).digest('hex');
  return Object.freeze({
    identity,
    seal(domain, payload) {
      const snapshot = clone(payload);
      return {
        integrityVersion: 1,
        keyId: value.keyId,
        domain,
        payload: snapshot,
        mac: crypto.createHmac('sha256', secret)
          .update(`${domain}\0${value.keyId}\0${protocol.canonicalJson(snapshot)}`, 'utf8')
          .digest('hex'),
      };
    },
    open(domain, wrapped, code = 'catalog_integrity_invalid') {
      if (!wrapped || typeof wrapped !== 'object' || Array.isArray(wrapped)
          || Object.keys(wrapped).sort().join(',') !== 'domain,integrityVersion,keyId,mac,payload'
          || wrapped.integrityVersion !== 1 || wrapped.keyId !== value.keyId
          || wrapped.domain !== domain || !SHA256_RE.test(String(wrapped.mac || ''))) {
        throw stateError(code);
      }
      const payload = snapshotStoredValue(wrapped.payload, code);
      const expected = crypto.createHmac('sha256', secret)
        .update(`${domain}\0${value.keyId}\0${protocol.canonicalJson(payload)}`, 'utf8').digest();
      const supplied = Buffer.from(wrapped.mac, 'hex');
      if (supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) {
        throw stateError(code);
      }
      return payload;
    },
  });
}

function applySignedRelease(config, input) {
  const artifacts = snapshotArtifactPair(input);
  const authority = incomingAuthorityContext(config);
  const global = verifySignedArtifact(artifacts.globalArtifact, authority.globalKeys,
    protocol.CHANNEL_KINDS.GLOBAL_CATALOG_RELEASE, {
      purpose: KEY_PURPOSES.CATALOG_GLOBAL, strictPurpose: true,
    });
  const distribution = verifySignedArtifact(artifacts.distributionArtifact,
    authority.distributionKeys, protocol.CHANNEL_KINDS.CATALOG_DISTRIBUTION, {
      purpose: KEY_PURPOSES.CATALOG_DISTRIBUTION, strictPurpose: true,
    });
  assertIncomingAuthorityBinding(
    authority.registry, artifacts.globalArtifact, authority.globalKeys,
    KEY_PURPOSES.CATALOG_GLOBAL,
  );
  assertIncomingAuthorityBinding(
    authority.registry, artifacts.distributionArtifact, authority.distributionKeys,
    KEY_PURPOSES.CATALOG_DISTRIBUTION,
  );
  validateArtifactLink(config, global, distribution, artifacts.globalArtifact);
  const outcome = runTransaction(config.storage, (tx) => {
    requireTransaction(tx);
    assertIncomingAuthorityUnchanged(config, authority);
    const integrityState = loadIntegrityState(tx, config, true);
    const current = readCurrent(tx, config);
    const active = readActive(tx, config);
    const decision = distributionDecision(current, distribution, artifacts);
    if (decision.action !== 'apply') return { result: decision, transition: null };
    validateGlobalProgressionAndRollback(tx, config, current, global, artifacts.globalArtifact);
    const state = buildState(global, distribution, artifacts);
    const targetActive = distribution.payload.rollout.mode === 'required' ? state : active;
    const stateDigest = canonicalDigest(state);
    const audit = nextAuditState(tx, config, integrityState.audit, {
      action: 'catalog_distribution_applied',
      referenceDigest: distribution.payloadDigest,
      revision: distribution.payload.distributionSequence,
      recordedAt: distribution.payload.issuedAt,
    });
    persistImmutableArtifacts(tx, state, artifacts);
    const acknowledgement = acknowledgementForState(tx, config, state);
    const acknowledgements = readAcknowledgementState(tx, config);
    if (tx.compareAndSetCurrentCatalog(integrityState.revision, clone(state)) !== true) {
      throw stateError('distribution_sequence_conflict');
    }
    if (distribution.payload.rollout.mode === 'required'
        && tx.compareAndSetActiveCatalog(active?.distributionSequence || 0, clone(state)) !== true) {
      throw stateError('catalog_activation_conflict');
    }
    appendAuditMutation(tx, config, audit);
    const history = compactHistory(
      tx, config, state.distributionSequence, targetActive?.distributionSequence || 0,
    );
    const globalArtifacts = readGlobalArtifactState(tx, config);
    const targetHead = {
      schemaVersion: 1,
      namespace: STATE_NAMESPACE,
      revision: distribution.payload.distributionSequence,
      stateDigest,
      auditCount: audit.count,
      auditSequence: audit.sequence,
      auditHead: audit.headDigest,
      activeDistributionSequence: targetActive?.distributionSequence || 0,
      activeStateDigest: targetActive ? canonicalDigest(targetActive) : ZERO_DIGEST,
      historyCount: history.count,
      historyHeadDigest: history.headDigest,
      historyCheckpointDigest: history.checkpointDigest,
      globalArtifactCount: globalArtifacts.count,
      globalArtifactHeadDigest: globalArtifacts.headDigest,
      acknowledgementCount: acknowledgements.count,
      acknowledgementHeadDigest: acknowledgements.headDigest,
      acknowledgementHighWater: acknowledgements.highWater,
      previousHeadDigest: integrityState.headDigest,
    };
    const targetHeadDigest = canonicalDigest(targetHead);
    const witness = {
      schemaVersion: 1,
      namespace: STATE_NAMESPACE,
      previousRevision: integrityState.revision,
      previousHeadDigest: integrityState.headDigest,
      targetRevision: targetHead.revision,
      targetHeadDigest,
      targetStateDigest: stateDigest,
      targetAuditSequence: audit.sequence,
      targetAuditHead: audit.headDigest,
    };
    const sealedWitness = config.integrity.seal('catalog.pending-witness.v1', witness);
    const witnessDigest = canonicalDigest(sealedWitness);
    const sealedHead = config.integrity.seal('catalog.state-head.v1', targetHead);
    if (tx.compareAndSetCatalogIntegrityHead(STATE_NAMESPACE, integrityState.revision,
      clone(sealedHead)) !== true) throw stateError('catalog_integrity_head_conflict');
    if (tx.writeCatalogPendingWitness(STATE_NAMESPACE, targetHead.revision,
      clone(sealedWitness)) !== true) throw stateError('catalog_pending_witness_conflict');
    assertPrimaryCommittedReadback(tx, config, state, targetActive, targetHead, witnessDigest);
    assertIncomingAuthorityUnchanged(config, authority);
    const transition = transitionFromWitness(config, witness, witnessDigest);
    assertPreparedAnchor(config.anchorAuthority.prepare(transition), transition);
    return {
      result: {
        action: distribution.payload.rollout.mode === 'required' ? 'apply' : 'stage',
        state: publicState(state),
        acknowledgement,
      },
      transition,
    };
  });
  if (outcome.transition) {
    assertFinalizedAnchor(config.anchorAuthority.finalize(outcome.transition), outcome.transition);
    runTransaction(config.storage, (tx) => {
      requireTransaction(tx);
      const wrapped = tx.readCatalogPendingWitness(STATE_NAMESPACE);
      if (!wrapped || canonicalDigest(wrapped) !== outcome.transition.witnessDigest
          || tx.clearCatalogPendingWitness(STATE_NAMESPACE,
            outcome.transition.witnessDigest) !== true) {
        throw stateError('catalog_pending_witness_clear_failed');
      }
      const integrityState = loadIntegrityState(tx, config, true);
      if (integrityState.revision !== outcome.transition.targetRevision
          || integrityState.headDigest !== outcome.transition.targetDigest) {
        throw stateError('catalog_cas_readback_failed');
      }
      return true;
    });
  }
  return withAcknowledgement(config, outcome.result);
}

function withAcknowledgement(config, result) {
  if (!result || !['apply', 'stage', 'acknowledge'].includes(result.action) || !result.state) {
    return result;
  }
  if (result.acknowledgement) return result;
  return runTransaction(config.storage, (tx) => {
    requireTransaction(tx);
    loadIntegrityState(tx, config, true);
    const state = readCurrent(tx, config);
    if (!state) throw stateError('catalog_state_missing');
    assertExpected(state, expectedState({
      distributionSequence: result.state.distributionSequence,
      globalReleaseId: result.state.globalReleaseId,
      globalVersion: result.state.globalVersion,
      globalArtifactDigest: result.state.globalArtifactDigest,
      recordsDigest: result.state.recordsDigest,
    }));
    return { ...result, acknowledgement: acknowledgementForState(tx, config, state) };
  });
}

function createAcknowledgement(config, expected) {
  return runTransaction(config.storage, (tx) => {
    requireTransaction(tx);
    loadIntegrityState(tx, config, true);
    const state = readCurrent(tx, config);
    if (!state) throw stateError('catalog_state_missing');
    assertExpected(state, expectedState(expected));
    return acknowledgementForState(tx, config, state);
  });
}

function acknowledgementForState(tx, config, state) {
  const stages = state.rollout.mode === 'required' ? ['delivered', 'applied'] : ['delivered'];
  let acknowledgement = null;
  for (const stage of stages) {
    acknowledgement = durableAcknowledgement(tx, config, state, stage, 'success', stage);
  }
  return acknowledgement;
}

function durableAcknowledgement(tx, config, state, lifecycleStage, outcome, reasonCode) {
  const identity = acknowledgementTransitionIdentity(config, state, lifecycleStage, outcome);
  const transitionKey = canonicalDigest(identity);
  const existing = tx.readCatalogAcknowledgementTransition(transitionKey);
  if (existing !== null && existing !== undefined) {
    const row = snapshotStoredValue(existing, 'acknowledgement_state_invalid');
    if (!exactKeys(row, ['acknowledgement', 'acknowledgementDigest', 'identity'])
        || canonicalDigest(row.identity) !== transitionKey
        || canonicalDigest(row.acknowledgement) !== row.acknowledgementDigest) {
      throw stateError('acknowledgement_state_invalid');
    }
    let checked;
    try {
      checked = protocol.assertChannel(row.acknowledgement,
        protocol.CHANNEL_KINDS.ACKNOWLEDGEMENT);
    } catch { throw stateError('acknowledgement_state_invalid'); }
    if (canonicalDigest(acknowledgementTransitionIdentity(
      config, state, checked.lifecycleStage, checked.outcome,
    )) !== transitionKey) throw stateError('acknowledgement_state_invalid');
    return checked;
  }
  const now = config.clock();
  const messageId = config.randomUUID();
  let recordedAt;
  try { recordedAt = new Date(now).toISOString(); } catch { throw stateError('clock_invalid'); }
  if (!Number.isSafeInteger(now) || now < 0 || !UUID_RE.test(String(messageId || ''))) {
    throw stateError('acknowledgement_source_invalid');
  }
  try {
    const checked = protocol.assertChannel({
      schemaVersion: protocol.PROTOCOL_VERSION,
      messageId,
      customerId: config.customerId,
      deploymentId: config.deploymentId,
      kind: protocol.CHANNEL_KINDS.ACKNOWLEDGEMENT,
      targetKind: protocol.CHANNEL_KINDS.CATALOG_DISTRIBUTION,
      targetVersion: state.distributionSequence,
      targetDigest: acknowledgementTargetDigest(state),
      targetGlobalReleaseId: state.globalReleaseId,
      targetGlobalVersion: state.globalVersion,
      targetGlobalArtifactDigest: state.globalArtifactDigest,
      lifecycleStage,
      outcome,
      reasonCode,
      recordedAt,
    }, protocol.CHANNEL_KINDS.ACKNOWLEDGEMENT);
    const row = {
      identity,
      acknowledgementDigest: canonicalDigest(checked),
      acknowledgement: checked,
    };
    if (tx.insertCatalogAcknowledgementTransition(transitionKey,
      row.acknowledgementDigest, clone(row)) !== true) {
      throw stateError('acknowledgement_transition_conflict');
    }
    const readback = tx.readCatalogAcknowledgementTransition(transitionKey);
    if (canonicalDigest(readback) !== canonicalDigest(row)) {
      throw stateError('acknowledgement_state_invalid');
    }
    return checked;
  } catch (error) {
    if (error && typeof error.code === 'string') throw error;
    throw stateError('acknowledgement_generation_failed');
  }
}

function acknowledgementTransitionIdentity(config, state, lifecycleStage, outcome) {
  return {
    schemaVersion: 1,
    customerId: config.customerId,
    deploymentId: config.deploymentId,
    targetKind: protocol.CHANNEL_KINDS.CATALOG_DISTRIBUTION,
    targetVersion: state.distributionSequence,
    targetDigest: acknowledgementTargetDigest(state),
    targetGlobalReleaseId: state.globalReleaseId,
    targetGlobalVersion: state.globalVersion,
    targetGlobalArtifactDigest: state.globalArtifactDigest,
    lifecycleStage,
    outcome,
  };
}

function acknowledgementChannelIdentity(config, acknowledgement) {
  return {
    schemaVersion: 1,
    customerId: acknowledgement.customerId,
    deploymentId: acknowledgement.deploymentId,
    targetKind: acknowledgement.targetKind,
    targetVersion: acknowledgement.targetVersion,
    targetDigest: acknowledgement.targetDigest,
    targetGlobalReleaseId: acknowledgement.targetGlobalReleaseId,
    targetGlobalVersion: acknowledgement.targetGlobalVersion,
    targetGlobalArtifactDigest: acknowledgement.targetGlobalArtifactDigest,
    lifecycleStage: acknowledgement.lifecycleStage,
    outcome: acknowledgement.outcome,
  };
}

function readAcknowledgementState(tx, config) {
  const values = snapshotStoredValue(tx.listCatalogAcknowledgementTransitions(),
    'acknowledgement_state_invalid');
  if (!Array.isArray(values)) throw stateError('acknowledgement_state_invalid');
  values.sort((left, right) => String(left?.transitionKey || '')
    .localeCompare(String(right?.transitionKey || '')));
  const seen = new Set();
  let headDigest = ZERO_DIGEST;
  let highWater = 0;
  for (const value of values) {
    if (!exactKeys(value, ['acknowledgementDigest', 'row', 'transitionKey'])
        || !SHA256_RE.test(String(value.transitionKey || ''))
        || !SHA256_RE.test(String(value.acknowledgementDigest || ''))
        || seen.has(value.transitionKey)) throw stateError('acknowledgement_state_invalid');
    seen.add(value.transitionKey);
    const row = snapshotStoredValue(value.row, 'acknowledgement_state_invalid');
    if (!exactKeys(row, ['acknowledgement', 'acknowledgementDigest', 'identity'])
        || row.acknowledgementDigest !== value.acknowledgementDigest
        || canonicalDigest(row.identity) !== value.transitionKey
        || canonicalDigest(row.acknowledgement) !== value.acknowledgementDigest) {
      throw stateError('acknowledgement_state_invalid');
    }
    let acknowledgement;
    try {
      acknowledgement = protocol.assertChannel(row.acknowledgement,
        protocol.CHANNEL_KINDS.ACKNOWLEDGEMENT);
    } catch { throw stateError('acknowledgement_state_invalid'); }
    if (canonicalDigest(acknowledgementChannelIdentity(config, acknowledgement))
        !== value.transitionKey) throw stateError('acknowledgement_state_invalid');
    highWater = Math.max(highWater, acknowledgement.targetVersion);
    headDigest = canonicalDigest({
      previousDigest: headDigest,
      transitionKey: value.transitionKey,
      acknowledgementDigest: value.acknowledgementDigest,
    });
  }
  return { count: values.length, headDigest, highWater };
}

function acknowledgementTargetDigest(state) {
  const value = state.distributionDigest || state.distributionPayloadDigest;
  if (!SHA256_RE.test(String(value || ''))) throw stateError('acknowledgement_state_invalid');
  return value;
}

function validateGlobalProgressionAndRollback(tx, config, current, global, globalArtifact) {
  const payload = global.payload;
  const artifactDigest = canonicalDigest(globalArtifact);
  if (current && (payload.globalVersion < current.globalVersion
      || (payload.globalVersion === current.globalVersion
        && artifactDigest !== current.globalArtifactDigest))) {
    throw stateError(payload.globalVersion < current.globalVersion
      ? 'global_version_stale' : 'global_version_conflict');
  }
  if (payload.rollbackOfGlobalVersion === null) return;
  // A first-time customer has no local history to re-prove the rollback target.
  // The vendor's signed current release is still authoritative and self-bound
  // to its complete records digest. Existing customers must additionally prove
  // the target against their own retained history.
  if (!current) return;
  const targets = readGlobalArtifactRows(tx, config).filter(
    (row) => row.globalVersion === payload.rollbackOfGlobalVersion,
  );
  if (targets.length !== 1) throw stateError(targets.length
    ? 'catalog_history_corrupt' : 'rollback_target_not_found');
  const target = targets[0];
  if (target.recordsDigest !== payload.recordsDigest
      || canonicalDigest(target.artifact.payload.records)
        !== canonicalDigest(payload.records)) throw stateError('rollback_content_mismatch');
}

function validateArtifactLink(config, global, distribution, globalArtifact) {
  const globalPayload = global.payload;
  const envelope = distribution.payload;
  if (envelope.customerId !== config.customerId) throw stateError('customer_mismatch');
  if (envelope.deploymentId !== config.deploymentId) throw stateError('deployment_mismatch');
  if (envelope.globalReleaseId !== globalPayload.globalReleaseId
      || envelope.globalVersion !== globalPayload.globalVersion
      || envelope.globalArtifactDigest !== canonicalDigest(globalArtifact)
      || envelope.recordsDigest !== globalPayload.recordsDigest
      || protocol.catalogRecordsDigest(globalPayload.records) !== envelope.recordsDigest) {
    throw stateError('catalog_artifact_link_invalid');
  }
}

function buildState(global, distribution, artifacts) {
  return {
    schemaVersion: STATE_VERSION,
    customerId: distribution.payload.customerId,
    deploymentId: distribution.payload.deploymentId,
    distributionSequence: distribution.payload.distributionSequence,
    previousDistributionSequence: distribution.payload.previousDistributionSequence,
    globalReleaseId: global.payload.globalReleaseId,
    globalVersion: global.payload.globalVersion,
    globalArtifactDigest: canonicalDigest(artifacts.globalArtifact),
    recordsDigest: global.payload.recordsDigest,
    distributionDigest: distribution.payloadDigest,
    distributionArtifactDigest: canonicalDigest(artifacts.distributionArtifact),
    globalSigningKeyId: global.keyId,
    distributionSigningKeyId: distribution.keyId,
    rollout: clone(distribution.payload.rollout),
    issuedAt: distribution.payload.issuedAt,
    globalArtifact: clone(artifacts.globalArtifact),
    distributionArtifact: clone(artifacts.distributionArtifact),
  };
}


function distributionDecision(current, distribution, artifacts) {
  const sequence = distribution.payload.distributionSequence;
  if (!current) {
    if (sequence !== 1 || distribution.payload.previousDistributionSequence !== 0) {
      throw stateError('distribution_genesis_invalid');
    }
    return { action: 'apply' };
  }
  if (sequence < current.distributionSequence) throw stateError('distribution_sequence_stale');
  if (sequence === current.distributionSequence) {
    const suppliedDigest = canonicalDigest(artifacts);
    const currentDigest = canonicalDigest({
      globalArtifact: current.globalArtifact,
      distributionArtifact: current.distributionArtifact,
    });
    if (suppliedDigest !== currentDigest) throw stateError('distribution_sequence_conflict');
    return { action: 'acknowledge', reason: 'already_applied', state: publicState(current) };
  }
  if (sequence !== current.distributionSequence + 1
      || distribution.payload.previousDistributionSequence !== current.distributionSequence) {
    throw stateError('distribution_sequence_gap');
  }
  return { action: 'apply' };
}

function persistImmutableArtifacts(tx, state, artifacts) {
  const existingGlobal = tx.readGlobalCatalogArtifact(state.globalReleaseId);
  if (existingGlobal) {
    if (canonicalDigest(existingGlobal) !== canonicalDigest(artifacts.globalArtifact)) {
      throw stateError('global_release_id_conflict');
    }
  } else if (tx.insertGlobalCatalogArtifact(state.globalReleaseId, state.globalVersion,
    state.globalArtifactDigest, clone(artifacts.globalArtifact)) !== true) {
    throw stateError('global_release_id_conflict');
  }
  const existingDistribution = tx.readCatalogDistribution(state.distributionSequence);
  if (existingDistribution) throw stateError('distribution_sequence_conflict');
  if (tx.insertCatalogDistribution(state.distributionSequence, state.distributionDigest,
    clone(state)) !== true) throw stateError('distribution_sequence_conflict');
  const globalReadback = tx.readGlobalCatalogArtifact(state.globalReleaseId);
  const distributionReadback = tx.readCatalogDistribution(state.distributionSequence);
  if (canonicalDigest(globalReadback) !== canonicalDigest(artifacts.globalArtifact)
      || canonicalDigest(distributionReadback) !== canonicalDigest(state)) {
    throw stateError('catalog_cas_readback_failed');
  }
}

function readCurrent(tx, config) {
  const value = tx.readCurrentCatalog();
  if (value === null || value === undefined) return null;
  return verifyPersistedState(tx, config, value, 'catalog_state_corrupt');
}

function readActive(tx, config) {
  const value = tx.readActiveCatalog();
  if (value === null || value === undefined) return null;
  return verifyPersistedState(tx, config, value, 'catalog_active_state_corrupt');
}

function verifyPersistedState(tx, config, value, code, expected = null) {
  const state = snapshotStoredValue(value, code);
  const expectedKeys = [
    'customerId', 'deploymentId', 'distributionArtifact', 'distributionArtifactDigest',
    'distributionDigest',
    'distributionSequence', 'distributionSigningKeyId', 'globalArtifact',
    'globalArtifactDigest', 'globalReleaseId', 'globalSigningKeyId', 'globalVersion',
    'issuedAt', 'previousDistributionSequence', 'recordsDigest', 'rollout', 'schemaVersion',
  ];
  if (!exactKeys(state, expectedKeys) || state.schemaVersion !== STATE_VERSION) throw stateError(code);
  if (expected && (state.distributionSequence !== expected.distributionSequence
      || state.distributionDigest !== expected.distributionDigest)) throw stateError(code);
  let global;
  let distribution;
  try {
    global = verifySignedArtifact(state.globalArtifact,
      persistedVerificationKeys(config, KEY_PURPOSES.CATALOG_GLOBAL,
        state.globalArtifact, config.globalKeys),
      protocol.CHANNEL_KINDS.GLOBAL_CATALOG_RELEASE, {
        purpose: KEY_PURPOSES.CATALOG_GLOBAL, strictPurpose: true,
      });
    distribution = verifySignedArtifact(state.distributionArtifact,
      persistedVerificationKeys(config, KEY_PURPOSES.CATALOG_DISTRIBUTION,
        state.distributionArtifact, config.distributionKeys),
      protocol.CHANNEL_KINDS.CATALOG_DISTRIBUTION, {
        purpose: KEY_PURPOSES.CATALOG_DISTRIBUTION, strictPurpose: true,
      });
    validateArtifactLink(config, global, distribution, state.globalArtifact);
  } catch { throw stateError(code); }
  const rebuilt = buildState(global, distribution, {
    globalArtifact: state.globalArtifact,
    distributionArtifact: state.distributionArtifact,
  });
  if (canonicalDigest(rebuilt) !== canonicalDigest(state)) throw stateError(code);
  const globalRow = tx.readGlobalCatalogArtifact(state.globalReleaseId);
  const distributionRow = tx.readCatalogDistribution(state.distributionSequence);
  if (canonicalDigest(globalRow) !== canonicalDigest(state.globalArtifact)
      || canonicalDigest(distributionRow) !== canonicalDigest(state)) throw stateError(code);
  return state;
}

function currentAuthorityRegistry(config) {
  if (config.authorityManifest) return reconciledAuthorityRegistry(config.authorityManifest);
  return config.authorityRegistry;
}

function incomingAuthorityContext(config) {
  const registry = currentAuthorityRegistry(config);
  const globalKeys = registry
    ? activeManifestKeys(registry, KEY_PURPOSES.CATALOG_GLOBAL) : config.globalKeys;
  const distributionKeys = registry
    ? activeManifestKeys(registry, KEY_PURPOSES.CATALOG_DISTRIBUTION)
    : config.distributionKeys;
  return Object.freeze({
    registry,
    globalKeys,
    distributionKeys,
    descriptorDigest: incomingAuthorityDescriptorDigest(registry, globalKeys, distributionKeys),
  });
}

function incomingAuthorityDescriptorDigest(registry, globalKeys, distributionKeys) {
  const records = (purpose, keys) => registry
    ? registry.list(purpose).filter((record) => ['current', 'next'].includes(record.slot))
      .map((record) => ({
        purpose,
        slot: record.slot,
        keyId: record.keyId,
        identity: record.identity,
      })).sort((left, right) => left.slot.localeCompare(right.slot))
    : [...keys].map(([keyId, key]) => ({
      purpose,
      slot: 'configured',
      keyId,
      identity: keyFingerprint(key),
    })).sort((left, right) => left.keyId.localeCompare(right.keyId));
  return canonicalDigest({
    generation: registry?.generation || 1,
    global: records(KEY_PURPOSES.CATALOG_GLOBAL, globalKeys),
    distribution: records(KEY_PURPOSES.CATALOG_DISTRIBUTION, distributionKeys),
  });
}

function assertIncomingAuthorityUnchanged(config, expected) {
  if (!config.authorityManifest) return;
  const current = incomingAuthorityContext(config);
  if (current.descriptorDigest !== expected.descriptorDigest) {
    throw stateError('authority_manifest_changed');
  }
}

function activeManifestKeys(registry, purpose) {
  try {
    const keys = registry.activePublicKeys(purpose);
    if (!(keys instanceof Map) || keys.size < 1 || keys.size > 2) {
      throw stateError('authority_manifest_invalid');
    }
    return keys;
  } catch (error) {
    if (error?.code === 'authority_manifest_invalid') throw error;
    throw stateError('authority_manifest_invalid');
  }
}

function assertIncomingAuthorityBinding(registry, artifact, keys, purpose) {
  const generation = artifact.payload.authorityManifestGeneration;
  const slot = artifact.payload.authorityManifestKeySlot;
  if (!registry) {
    if (generation !== 1 || !keys.has(artifact.keyId)) {
      throw stateError('artifact_authority_binding_invalid');
    }
    return;
  }
  let record;
  try {
    record = registry.list(purpose).find((candidate) => candidate.keyId === artifact.keyId);
  } catch { throw stateError('artifact_authority_binding_invalid'); }
  if (generation !== registry.generation || !record || record.slot !== slot
      || !['current', 'next'].includes(record.slot) || !keys.has(artifact.keyId)) {
    throw stateError('artifact_authority_binding_invalid');
  }
}

function persistedVerificationKeys(config, purpose, artifact, fallback) {
  const registry = currentAuthorityRegistry(config);
  if (!registry) {
    if (artifact.payload.authorityManifestGeneration !== 1 || !fallback.has(artifact.keyId)) {
      throw stateError('artifact_authority_binding_invalid');
    }
    return fallback;
  }
  if (artifact.payload.authorityManifestGeneration < 1
      || artifact.payload.authorityManifestGeneration > registry.generation) {
    throw stateError('artifact_authority_binding_invalid');
  }
  try {
    const keys = registry.verificationPublicKey(purpose, artifact.keyId);
    if (!(keys instanceof Map) || keys.size !== 1 || !keys.has(artifact.keyId)) {
      throw stateError('artifact_authority_binding_invalid');
    }
    return keys;
  } catch (error) {
    if (error?.code === 'artifact_authority_binding_invalid') throw error;
    throw stateError('artifact_authority_binding_invalid');
  }
}

function expectedState(value) {
  const keys = [
    'distributionSequence', 'globalArtifactDigest', 'globalReleaseId',
    'globalVersion', 'recordsDigest',
  ];
  if (!value || typeof value !== 'object' || Array.isArray(value) || !exactKeys(value, keys)
      || !Number.isSafeInteger(value.distributionSequence) || value.distributionSequence < 1
      || !Number.isSafeInteger(value.globalVersion) || value.globalVersion < 1
      || !UUID_RE.test(String(value.globalReleaseId || ''))
      || !SHA256_RE.test(String(value.globalArtifactDigest || ''))
      || !SHA256_RE.test(String(value.recordsDigest || ''))) {
    throw stateError('catalog_read_expectation_invalid');
  }
  return value;
}

function assertExpected(state, expected) {
  for (const key of Object.keys(expected)) {
    if (state[key] !== expected[key]) throw stateError('catalog_read_version_mismatch');
  }
}

function readEffectiveCatalog(config, expectedValue) {
  const expected = expectedState(expectedValue);
  return runTransaction(config.storage, (tx) => {
    requireTransaction(tx);
    const integrityState = loadIntegrityState(tx, config, true);
    const state = readActive(tx, config);
    if (!state) return null;
    assertExpected(state, expected);
    if (integrityState.activeDistributionSequence !== state.distributionSequence
        || integrityState.activeStateDigest !== canonicalDigest(state)) {
      throw stateError('catalog_integrity_head_invalid');
    }
    const overrides = loadOverrideIntegrityState(tx, config, true).active;
    return {
      distributionSequence: state.distributionSequence,
      globalReleaseId: state.globalReleaseId,
      globalVersion: state.globalVersion,
      globalArtifactDigest: state.globalArtifactDigest,
      recordsDigest: state.recordsDigest,
      rollout: clone(state.rollout),
      records: state.globalArtifact.payload.records.map((record) =>
        effectiveRecord(record, overrides.get(record.catalogId))),
    };
  });
}

function readPendingCatalog(config, expectedValue) {
  const expected = expectedState(expectedValue);
  return runTransaction(config.storage, (tx) => {
    requireTransaction(tx);
    const integrityState = loadIntegrityState(tx, config, true);
    const state = readCurrent(tx, config);
    if (!state || state.rollout.mode === 'required') return null;
    assertExpected(state, expected);
    if (integrityState.revision !== state.distributionSequence
        || integrityState.stateDigest !== canonicalDigest(state)) {
      throw stateError('catalog_integrity_head_invalid');
    }
    return {
      ...publicState(state),
      records: clone(state.globalArtifact.payload.records),
    };
  });
}

function loadIntegrityState(tx, config, requireReady) {
  const pending = tx.readCatalogPendingWitness(STATE_NAMESPACE);
  const anchor = config.anchorAuthority.read(config.anchorNamespace);
  if ((pending || anchor.pending) && requireReady) throw stateError('catalog_readiness_frozen');
  const primary = readPrimaryIntegrityState(tx, config);
  if (anchor.revision !== primary.revision || anchor.headDigest !== primary.headDigest) {
    throw stateError('catalog_integrity_head_invalid');
  }
  return { ...primary, anchor };
}

function readPrimaryIntegrityState(tx, config) {
  const current = tx.readCurrentCatalog();
  const activeValue = tx.readActiveCatalog();
  const wrappedHead = tx.readCatalogIntegrityHead(STATE_NAMESPACE);
  const audit = readAuditState(tx, config);
  const acknowledgements = readAcknowledgementState(tx, config);
  const globalArtifacts = readGlobalArtifactState(tx, config);
  if (!current && !wrappedHead && !activeValue) {
    if (audit.sequence !== 0 || audit.count !== 0 || acknowledgements.count !== 0
        || globalArtifacts.count !== 0) {
      throw stateError('catalog_integrity_head_invalid');
    }
    readHistoryState(tx, config, 0);
    return { revision: 0, stateDigest: ZERO_DIGEST, headDigest: ZERO_DIGEST, audit };
  }
  if (!current || !wrappedHead) throw stateError('catalog_integrity_head_invalid');
  const state = verifyPersistedState(tx, config, current, 'catalog_integrity_head_invalid');
  const active = activeValue
    ? verifyPersistedState(tx, config, activeValue, 'catalog_integrity_head_invalid') : null;
  const history = readHistoryState(tx, config, state.distributionSequence);
  const head = config.integrity.open('catalog.state-head.v1', wrappedHead,
    'catalog_integrity_head_invalid');
  validateHead(head);
  const headDigest = canonicalDigest(head);
  if (head.stateDigest !== canonicalDigest(state)
      || head.activeDistributionSequence !== (active?.distributionSequence || 0)
      || head.activeStateDigest !== (active ? canonicalDigest(active) : ZERO_DIGEST)
      || head.historyCount !== history.count || head.historyHeadDigest !== history.headDigest
      || head.historyCheckpointDigest !== history.checkpointDigest
      || head.globalArtifactCount !== globalArtifacts.count
      || head.globalArtifactHeadDigest !== globalArtifacts.headDigest
      || head.acknowledgementCount !== acknowledgements.count
      || head.acknowledgementHeadDigest !== acknowledgements.headDigest
      || head.acknowledgementHighWater !== acknowledgements.highWater
      || head.auditCount !== audit.count || head.auditSequence !== audit.sequence
      || head.auditHead !== audit.headDigest) throw stateError('catalog_integrity_head_invalid');
  return { ...head, headDigest, audit };
}

function validateHead(value) {
  const keys = [
    'acknowledgementCount', 'acknowledgementHeadDigest', 'acknowledgementHighWater',
    'activeDistributionSequence', 'activeStateDigest', 'auditCount', 'auditHead',
    'auditSequence', 'historyCheckpointDigest', 'historyCount', 'historyHeadDigest',
    'globalArtifactCount', 'globalArtifactHeadDigest',
    'namespace', 'previousHeadDigest', 'revision', 'schemaVersion', 'stateDigest',
  ];
  if (!value || typeof value !== 'object' || Array.isArray(value) || !exactKeys(value, keys)
      || value.schemaVersion !== 1 || value.namespace !== STATE_NAMESPACE
      || !Number.isSafeInteger(value.revision) || value.revision < 1
      || !Number.isSafeInteger(value.activeDistributionSequence)
      || value.activeDistributionSequence < 0
      || value.activeDistributionSequence > value.revision
      || !Number.isSafeInteger(value.acknowledgementCount)
      || value.acknowledgementCount < 1
      || !Number.isSafeInteger(value.acknowledgementHighWater)
      || value.acknowledgementHighWater !== value.revision
      || !SHA256_RE.test(value.acknowledgementHeadDigest)
      || !Number.isSafeInteger(value.globalArtifactCount)
      || value.globalArtifactCount < 1
      || value.globalArtifactCount > MAX_RETAINED_GLOBAL_ARTIFACTS
      || !SHA256_RE.test(value.globalArtifactHeadDigest)
      || !Number.isSafeInteger(value.auditSequence) || value.auditSequence < 1
      || value.auditCount !== value.auditSequence
      || !SHA256_RE.test(value.auditHead) || !SHA256_RE.test(value.activeStateDigest)
      || value.historyCount !== value.revision || !SHA256_RE.test(value.historyHeadDigest)
      || !SHA256_RE.test(value.historyCheckpointDigest)
      || !SHA256_RE.test(value.previousHeadDigest)
      || !SHA256_RE.test(value.stateDigest)) throw stateError('catalog_integrity_head_invalid');
}

function readAuditState(tx, config) {
  const wrappedCheckpoint = tx.readCatalogAuditCheckpoint(STATE_NAMESPACE);
  let count = 0;
  let sequence = 0;
  let headDigest = ZERO_DIGEST;
  if (wrappedCheckpoint) {
    const checkpoint = config.integrity.open('catalog.audit-checkpoint.v1', wrappedCheckpoint,
      'catalog_audit_invalid');
    if (!exactKeys(checkpoint, ['compactedCount', 'headDigest', 'namespace', 'sequence', 'schemaVersion'])
        || checkpoint.schemaVersion !== 1 || checkpoint.namespace !== STATE_NAMESPACE
        || !Number.isSafeInteger(checkpoint.sequence) || checkpoint.sequence < 1
        || checkpoint.compactedCount !== checkpoint.sequence
        || !SHA256_RE.test(checkpoint.headDigest)) throw stateError('catalog_audit_invalid');
    count = checkpoint.compactedCount;
    sequence = checkpoint.sequence;
    headDigest = checkpoint.headDigest;
  }
  const rows = snapshotStoredValue(tx.listCatalogAuditEvents(STATE_NAMESPACE), 'catalog_audit_invalid');
  if (!Array.isArray(rows) || rows.length > MAX_ACTIVE_AUDIT_EVENTS) throw stateError('catalog_audit_invalid');
  for (const wrapped of rows) {
    const event = config.integrity.open('catalog.audit-event.v1', wrapped, 'catalog_audit_invalid');
    const descriptor = {
      schemaVersion: event.schemaVersion,
      namespace: event.namespace,
      sequence: event.sequence,
      action: event.action,
      referenceDigest: event.referenceDigest,
      revision: event.revision,
      recordedAt: event.recordedAt,
    };
    if (!exactKeys(event, [...Object.keys(descriptor), 'eventDigest', 'previousDigest'])
        || event.schemaVersion !== 1 || event.namespace !== STATE_NAMESPACE
        || event.sequence !== sequence + 1 || event.previousDigest !== headDigest
        || event.eventDigest !== canonicalDigest({ previousDigest: headDigest, descriptor })
        || !SHA256_RE.test(event.referenceDigest) || !canonicalTime(event.recordedAt)) {
      throw stateError('catalog_audit_invalid');
    }
    sequence = event.sequence;
    headDigest = event.eventDigest;
    count += 1;
  }
  return { count, sequence, headDigest, activeRows: rows };
}

function nextAuditState(tx, config, current, input) {
  let state = current;
  let compacted = null;
  if (state.activeRows.length >= MAX_ACTIVE_AUDIT_EVENTS) {
    const firstWrapped = state.activeRows[0];
    const first = config.integrity.open('catalog.audit-event.v1', firstWrapped, 'catalog_audit_invalid');
    const checkpoint = {
      schemaVersion: 1,
      namespace: STATE_NAMESPACE,
      compactedCount: state.count - state.activeRows.length + 1,
      sequence: first.sequence,
      headDigest: first.eventDigest,
    };
    compacted = { first, firstWrapped, checkpoint };
    state = { ...state, activeRows: state.activeRows.slice(1) };
  }
  const sequence = state.sequence + 1;
  const descriptor = { schemaVersion: 1, namespace: STATE_NAMESPACE, sequence, ...input };
  const event = {
    ...descriptor,
    previousDigest: state.headDigest,
    eventDigest: canonicalDigest({ previousDigest: state.headDigest, descriptor }),
  };
  return {
    count: state.count + 1,
    sequence,
    headDigest: event.eventDigest,
    event,
    compacted,
  };
}

function appendAuditMutation(tx, config, audit) {
  if (audit.compacted) {
    const currentCheckpoint = tx.readCatalogAuditCheckpoint(STATE_NAMESPACE);
    const expectedSequence = currentCheckpoint
      ? config.integrity.open('catalog.audit-checkpoint.v1', currentCheckpoint,
        'catalog_audit_invalid').sequence : 0;
    if (tx.compareAndSetCatalogAuditCheckpoint(STATE_NAMESPACE, expectedSequence,
      config.integrity.seal('catalog.audit-checkpoint.v1', audit.compacted.checkpoint)) !== true
        || tx.deleteCatalogAuditEvent(STATE_NAMESPACE, audit.compacted.first.sequence,
          canonicalDigest(audit.compacted.firstWrapped)) !== true) {
      throw stateError('catalog_audit_compaction_failed');
    }
  }
  const wrapped = config.integrity.seal('catalog.audit-event.v1', audit.event);
  if (tx.appendCatalogAuditEvent(STATE_NAMESPACE, audit.event.sequence,
    audit.event.eventDigest, wrapped) !== true) throw stateError('catalog_audit_commit_failed');
}

function assertPrimaryCommittedReadback(tx, config, expectedStateValue, expectedActiveValue,
  expectedHead, witnessDigest) {
  const state = verifyPersistedState(tx, config, tx.readCurrentCatalog(), 'catalog_cas_readback_failed');
  const active = readActive(tx, config);
  const head = config.integrity.open('catalog.state-head.v1',
    tx.readCatalogIntegrityHead(STATE_NAMESPACE), 'catalog_cas_readback_failed');
  const pending = tx.readCatalogPendingWitness(STATE_NAMESPACE);
  if (canonicalDigest(state) !== canonicalDigest(expectedStateValue)
      || canonicalDigest(active) !== canonicalDigest(expectedActiveValue)
      || canonicalDigest(head) !== canonicalDigest(expectedHead)
      || !pending || canonicalDigest(pending) !== witnessDigest) {
    throw stateError('catalog_cas_readback_failed');
  }
}

function compactHistory(tx, config, currentSequence, activeSequence) {
  const rows = snapshotStoredValue(tx.listCatalogDistributions(), 'catalog_history_corrupt');
  if (!Array.isArray(rows)) throw stateError('catalog_history_corrupt');
  if (rows.some((row) => !exactKeys(row, ['distributionDigest', 'distributionSequence', 'value'])
      || !Number.isSafeInteger(row.distributionSequence) || row.distributionSequence < 1
      || !SHA256_RE.test(String(row.distributionDigest || '')))) {
    throw stateError('catalog_history_corrupt');
  }
  rows.sort((left, right) => left.distributionSequence - right.distributionSequence);
  while (rows.length > ROLLBACK_WINDOW_DISTRIBUTIONS) {
    const removableIndex = rows.findIndex((entry) =>
      entry.distributionSequence !== activeSequence);
    if (removableIndex < 0) throw stateError('catalog_history_retention_invalid');
    const [entry] = rows.splice(removableIndex, 1);
    const row = verifyPersistedState(tx, config, entry.value, 'catalog_history_corrupt', entry);
    if (row.distributionSequence > currentSequence - ROLLBACK_WINDOW_DISTRIBUTIONS) {
      throw stateError('catalog_history_retention_invalid');
    }
    const tombstone = config.integrity.seal('catalog.history-tombstone.v1', {
      schemaVersion: 1,
      distributionSequence: row.distributionSequence,
      distributionDigest: row.distributionDigest,
      distributionArtifactDigest: row.distributionArtifactDigest,
      globalReleaseId: row.globalReleaseId,
      globalVersion: row.globalVersion,
      globalArtifactDigest: row.globalArtifactDigest,
      recordsDigest: row.recordsDigest,
      globalSigningKeyId: row.globalSigningKeyId,
      distributionSigningKeyId: row.distributionSigningKeyId,
    });
    if (tx.writeCatalogTombstone(row.distributionSequence, row.distributionDigest,
      tombstone) !== true
        || tx.deleteCatalogDistribution(row.distributionSequence,
          row.distributionDigest) !== true) throw stateError('catalog_history_compaction_failed');
  }
  compactTombstones(tx, config);
  compactGlobalArtifactHistory(tx, config);
  return readHistoryState(tx, config, currentSequence);
}

function compactGlobalArtifactHistory(tx, config) {
  const rows = readGlobalArtifactRows(tx, config);
  const protectedIds = new Set([
    readCurrent(tx, config)?.globalReleaseId,
    readActive(tx, config)?.globalReleaseId,
  ].filter(Boolean));
  const recentIds = new Set(rows.slice(-ROLLBACK_WINDOW_DISTRIBUTIONS)
    .map((row) => row.globalReleaseId));
  const protectedOutsideWindow = [...protectedIds]
    .filter((globalReleaseId) => !recentIds.has(globalReleaseId)).length;
  const retentionLimit = ROLLBACK_WINDOW_DISTRIBUTIONS + protectedOutsideWindow;
  if (retentionLimit > MAX_RETAINED_GLOBAL_ARTIFACTS) {
    throw stateError('catalog_history_retention_invalid');
  }
  while (rows.length > retentionLimit) {
    const index = rows.findIndex((row) => !protectedIds.has(row.globalReleaseId));
    if (index < 0) throw stateError('catalog_history_retention_invalid');
    const [row] = rows.splice(index, 1);
    if (tx.deleteGlobalCatalogArtifact(row.globalReleaseId,
      row.globalArtifactDigest) !== true) throw stateError('catalog_history_compaction_failed');
  }
}

function readGlobalArtifactRows(tx, config) {
  const values = snapshotStoredValue(tx.listGlobalCatalogArtifacts(),
    'catalog_history_corrupt');
  if (!Array.isArray(values)) throw stateError('catalog_history_corrupt');
  const versions = new Set();
  return values.map((value) => {
    if (!exactKeys(value, [
      'artifact', 'globalArtifactDigest', 'globalReleaseId', 'globalVersion',
    ]) || !UUID_RE.test(String(value.globalReleaseId || ''))
        || !Number.isSafeInteger(value.globalVersion) || value.globalVersion < 1
        || !SHA256_RE.test(String(value.globalArtifactDigest || ''))
        || versions.has(value.globalVersion)) throw stateError('catalog_history_corrupt');
    versions.add(value.globalVersion);
    let artifact;
    try {
      artifact = verifySignedArtifact(value.artifact,
        persistedVerificationKeys(config, KEY_PURPOSES.CATALOG_GLOBAL,
          value.artifact, config.globalKeys),
        protocol.CHANNEL_KINDS.GLOBAL_CATALOG_RELEASE, {
          purpose: KEY_PURPOSES.CATALOG_GLOBAL, strictPurpose: true,
        });
    } catch { throw stateError('catalog_history_corrupt'); }
    if (artifact.payload.globalReleaseId !== value.globalReleaseId
        || artifact.payload.globalVersion !== value.globalVersion
        || canonicalDigest(value.artifact) !== value.globalArtifactDigest) {
      throw stateError('catalog_history_corrupt');
    }
    return {
      ...value,
      recordsDigest: artifact.payload.recordsDigest,
      artifact: clone(value.artifact),
    };
  }).sort((left, right) => left.globalVersion - right.globalVersion
    || left.globalReleaseId.localeCompare(right.globalReleaseId));
}

function readGlobalArtifactState(tx, config) {
  const rows = readGlobalArtifactRows(tx, config);
  let headDigest = ZERO_DIGEST;
  for (const row of rows) {
    headDigest = canonicalDigest({
      previousDigest: headDigest,
      globalReleaseId: row.globalReleaseId,
      globalVersion: row.globalVersion,
      globalArtifactDigest: row.globalArtifactDigest,
    });
  }
  return { count: rows.length, headDigest };
}

function compactTombstones(tx, config) {
  const { tombstones, distributions } = readHistoryRows(tx, config);
  while (tombstones.length > MAX_ARCHIVED_TOMBSTONES) {
    const oldest = tombstones.shift();
    const checkpoint = readHistoryCheckpoint(tx, config);
    const descriptors = new Map([
      ...distributions.map((row) => [row.descriptor.distributionSequence, row.descriptor]),
      ...tombstones.map((row) => [row.value.distributionSequence, row.value]),
      [oldest.value.distributionSequence, oldest.value],
    ]);
    let headDigest = checkpoint.headDigest;
    const references = new Map(Object.entries(checkpoint.keyReferences));
    for (let sequence = checkpoint.throughSequence + 1;
      sequence <= oldest.value.distributionSequence; sequence += 1) {
      const descriptor = descriptors.get(sequence);
      if (!descriptor) throw stateError('catalog_history_corrupt');
      headDigest = historyDigest(headDigest, descriptor);
      addHistoryReferences(references, descriptor);
    }
    const nextCheckpoint = {
      schemaVersion: 1,
      namespace: STATE_NAMESPACE,
      throughSequence: oldest.value.distributionSequence,
      compactedCount: oldest.value.distributionSequence,
      headDigest,
      keyReferences: sortedReferenceObject(references),
    };
    if (tx.compareAndSetCatalogHistoryCheckpoint(checkpoint.throughSequence,
      config.integrity.seal('catalog.history-checkpoint.v1', nextCheckpoint)) !== true) {
      throw stateError('catalog_history_compaction_failed');
    }
    if (tx.deleteCatalogTombstone(oldest.value.distributionSequence,
      oldest.value.distributionDigest, canonicalDigest(oldest.wrapped)) !== true) {
      throw stateError('catalog_history_compaction_failed');
    }
  }
}

function readHistoryState(tx, config, currentSequence) {
  const checkpoint = readHistoryCheckpoint(tx, config);
  if (!Number.isSafeInteger(currentSequence) || currentSequence < checkpoint.throughSequence) {
    throw stateError('catalog_history_corrupt');
  }
  const { distributions, tombstones } = readHistoryRows(tx, config);
  if (tombstones.some((row) => row.value.distributionSequence <= checkpoint.throughSequence)) {
    throw stateError('catalog_history_corrupt');
  }
  const checkpointOverlaps = distributions.filter((row) =>
    row.descriptor.distributionSequence <= checkpoint.throughSequence);
  if (checkpointOverlaps.length > 1) throw stateError('catalog_history_corrupt');
  const rows = [
    ...distributions.map((row) => row.descriptor),
    ...tombstones.map((row) => row.value),
  ].filter((row) => row.distributionSequence > checkpoint.throughSequence)
    .sort((left, right) => left.distributionSequence - right.distributionSequence);
  const seen = new Set();
  let sequence = checkpoint.throughSequence;
  let headDigest = checkpoint.headDigest;
  const references = new Map(Object.entries(checkpoint.keyReferences));
  for (const descriptor of rows) {
    if (seen.has(descriptor.distributionSequence)
        || descriptor.distributionSequence !== sequence + 1) {
      throw stateError('catalog_history_corrupt');
    }
    seen.add(descriptor.distributionSequence);
    sequence = descriptor.distributionSequence;
    headDigest = historyDigest(headDigest, descriptor);
    addHistoryReferences(references, descriptor);
  }
  if (sequence !== currentSequence) throw stateError('catalog_history_corrupt');
  return {
    count: sequence,
    headDigest,
    checkpointDigest: checkpoint.throughSequence
      ? canonicalDigest(checkpoint) : ZERO_DIGEST,
    keyReferences: sortedReferenceObject(references),
  };
}

function readHistoryRows(tx, config) {
  const rawDistributions = snapshotStoredValue(tx.listCatalogDistributions(),
    'catalog_history_corrupt');
  const rawTombstones = snapshotStoredValue(tx.listCatalogTombstones(),
    'catalog_history_corrupt');
  if (!Array.isArray(rawDistributions) || !Array.isArray(rawTombstones)) {
    throw stateError('catalog_history_corrupt');
  }
  const distributions = rawDistributions.map((row) => {
    if (!exactKeys(row, ['distributionDigest', 'distributionSequence', 'value'])) {
      throw stateError('catalog_history_corrupt');
    }
    const state = verifyPersistedState(tx, config, row.value,
      'catalog_history_corrupt', row);
    return { descriptor: historyDescriptor(state) };
  }).sort((left, right) => left.descriptor.distributionSequence
    - right.descriptor.distributionSequence);
  const tombstones = rawTombstones.map((wrapped) => ({
    wrapped,
    value: validateHistoryTombstone(config.integrity.open(
      'catalog.history-tombstone.v1', wrapped, 'catalog_history_corrupt')),
  })).sort((left, right) => left.value.distributionSequence
    - right.value.distributionSequence);
  return { distributions, tombstones };
}

function readHistoryCheckpoint(tx, config) {
  const wrapped = tx.readCatalogHistoryCheckpoint();
  if (!wrapped) {
    return {
      schemaVersion: 1,
      namespace: STATE_NAMESPACE,
      throughSequence: 0,
      compactedCount: 0,
      headDigest: ZERO_DIGEST,
      keyReferences: {},
    };
  }
  const value = config.integrity.open('catalog.history-checkpoint.v1', wrapped,
    'catalog_history_corrupt');
  if (!exactKeys(value, [
    'compactedCount', 'headDigest', 'keyReferences', 'namespace', 'schemaVersion',
    'throughSequence',
  ]) || value.schemaVersion !== 1 || value.namespace !== STATE_NAMESPACE
      || !Number.isSafeInteger(value.throughSequence) || value.throughSequence < 1
      || value.compactedCount !== value.throughSequence || !SHA256_RE.test(value.headDigest)) {
    throw stateError('catalog_history_corrupt');
  }
  const references = checkedHistoryReferenceObject(value.keyReferences);
  const totalReferences = Object.values(references).reduce((sum, count) => sum + count, 0);
  if (totalReferences !== value.compactedCount * 2) throw stateError('catalog_history_corrupt');
  value.keyReferences = references;
  return value;
}

function historyDescriptor(state) {
  return {
    schemaVersion: 1,
    distributionSequence: state.distributionSequence,
    distributionDigest: state.distributionDigest,
    distributionArtifactDigest: state.distributionArtifactDigest,
    globalReleaseId: state.globalReleaseId,
    globalVersion: state.globalVersion,
    globalArtifactDigest: state.globalArtifactDigest,
    recordsDigest: state.recordsDigest,
    globalSigningKeyId: state.globalSigningKeyId,
    distributionSigningKeyId: state.distributionSigningKeyId,
  };
}

function historyDigest(previousDigest, descriptor) {
  return canonicalDigest({ previousDigest, descriptor });
}

function addHistoryReferences(references, descriptor) {
  incrementReference(references, descriptor.globalSigningKeyId);
  incrementReference(references, descriptor.distributionSigningKeyId);
}

function sortedReferenceObject(references) {
  return Object.fromEntries([...references.entries()].filter(([, count]) => count > 0)
    .sort(([left], [right]) => left.localeCompare(right)));
}

function checkedHistoryReferenceObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw stateError('catalog_history_corrupt');
  }
  const entries = Object.entries(value);
  if (entries.some(([keyId, count]) => !SAFE_SLUG_RE.test(keyId)
      || !/^rw-catalog-(?:global|distribution)-/.test(keyId)
      || !Number.isSafeInteger(count) || count < 1)) {
    throw stateError('catalog_history_corrupt');
  }
  return Object.fromEntries(entries.sort(([left], [right]) => left.localeCompare(right)));
}

function readiness(config) {
  try {
    return runTransaction(config.storage, (tx) => {
      requireTransaction(tx);
      loadIntegrityState(tx, config, true);
      loadOverrideIntegrityState(tx, config, true);
      collectSigningKeyReferenceCounts(tx, config);
      return { ready: true, reason: 'ready' };
    });
  } catch (error) {
    return { ready: false, reason: error.code || 'catalog_state_invalid' };
  }
}

function reconcileCatalog(config) {
  const anchor = config.anchorAuthority.read(config.anchorNamespace);
  const inspection = runTransaction(config.storage, (tx) => {
    requireTransaction(tx);
    const wrapped = tx.readCatalogPendingWitness(STATE_NAMESPACE);
    const primary = readPrimaryIntegrityState(tx, config);
    if (!wrapped) return { primary, transition: null, witnessDigest: null };
    const witness = validateWitness(config.integrity.open('catalog.pending-witness.v1', wrapped,
      'catalog_pending_witness_invalid'));
    const witnessDigest = canonicalDigest(wrapped);
    return {
      primary,
      transition: transitionFromWitness(config, witness, witnessDigest),
      witnessDigest,
    };
  });
  if (!anchor.pending && !inspection.transition) return { action: 'none' };
  const transition = anchor.pending
    ? transitionFromAnchor(config, anchor)
    : inspection.transition;
  if (inspection.transition
      && canonicalDigest(inspection.transition) !== canonicalDigest(transition)) {
    throw stateError('catalog_reconciliation_required');
  }
  const committed = inspection.primary.revision === transition.targetRevision
    && inspection.primary.headDigest === transition.targetDigest;
  const rolledBack = inspection.primary.revision === transition.expectedRevision
    && inspection.primary.headDigest === transition.expectedDigest;
  if (!committed && !rolledBack) throw stateError('catalog_reconciliation_required');
  if (anchor.pending) {
    if (committed) assertFinalizedAnchor(config.anchorAuthority.finalize(transition), transition);
    else config.anchorAuthority.abort(transition);
  } else if (committed && (anchor.revision !== transition.targetRevision
      || anchor.headDigest !== transition.targetDigest)) {
    throw stateError('catalog_reconciliation_required');
  } else if (rolledBack && (anchor.revision !== transition.expectedRevision
      || anchor.headDigest !== transition.expectedDigest)) {
    throw stateError('catalog_reconciliation_required');
  }
  if (inspection.witnessDigest) {
    runTransaction(config.storage, (tx) => {
      requireTransaction(tx);
      if (tx.clearCatalogPendingWitness(STATE_NAMESPACE, inspection.witnessDigest) !== true) {
        throw stateError('catalog_pending_witness_clear_failed');
      }
      return true;
    });
  }
  return { action: committed ? 'finalized' : 'rolled_back' };
}

function reconcile(config) {
  const catalogResult = reconcileCatalog(config);
  const overrideResult = reconcileOverrideAnchor(config);
  if (overrideResult.action === 'none') return catalogResult;
  if (catalogResult.action === 'none') return { action: `override_${overrideResult.action}` };
  return {
    action: 'multiple',
    catalog: catalogResult.action,
    overrides: overrideResult.action,
  };
}

function reconcileOverrideAnchor(config) {
  const anchor = config.anchorAuthority.read(config.overrideAnchorNamespace);
  const primary = runTransaction(config.storage, (tx) => {
    requireTransaction(tx);
    return readPrimaryOverrideState(tx, config);
  });
  if (!anchor.pending) {
    if (anchor.revision !== primary.revision || anchor.headDigest !== primary.headDigest) {
      throw stateError('tenant_override_reconciliation_required');
    }
    return { action: 'none' };
  }
  const transition = transitionFromAnchor({
    anchorNamespace: config.overrideAnchorNamespace,
  }, anchor);
  const committed = primary.revision === transition.targetRevision
    && primary.headDigest === transition.targetDigest;
  const rolledBack = primary.revision === transition.expectedRevision
    && primary.headDigest === transition.expectedDigest;
  if (!committed && !rolledBack) throw stateError('tenant_override_reconciliation_required');
  if (committed) assertFinalizedAnchor(config.anchorAuthority.finalize(transition), transition);
  else config.anchorAuthority.abort(transition);
  return { action: committed ? 'finalized' : 'rolled_back' };
}

function transitionFromWitness(config, witness, witnessDigest) {
  return {
    namespace: config.anchorNamespace,
    expectedRevision: witness.previousRevision,
    expectedDigest: witness.previousHeadDigest,
    targetRevision: witness.targetRevision,
    targetDigest: witness.targetHeadDigest,
    witnessDigest,
  };
}

function transitionFromAnchor(config, anchor) {
  return {
    namespace: config.anchorNamespace,
    expectedRevision: anchor.pending.expectedRevision,
    expectedDigest: anchor.pending.expectedDigest,
    targetRevision: anchor.pending.targetRevision,
    targetDigest: anchor.pending.targetDigest,
    witnessDigest: anchor.pending.witnessDigest,
  };
}

function validateWitness(value) {
  const keys = [
    'namespace', 'previousHeadDigest', 'previousRevision', 'schemaVersion',
    'targetAuditHead', 'targetAuditSequence', 'targetHeadDigest', 'targetRevision',
    'targetStateDigest',
  ];
  if (!exactKeys(value, keys) || value.schemaVersion !== 1 || value.namespace !== STATE_NAMESPACE
      || !Number.isSafeInteger(value.previousRevision) || value.previousRevision < 0
      || value.targetRevision !== value.previousRevision + 1
      || !Number.isSafeInteger(value.targetAuditSequence) || value.targetAuditSequence < 1
      || !SHA256_RE.test(value.previousHeadDigest) || !SHA256_RE.test(value.targetHeadDigest)
      || !SHA256_RE.test(value.targetStateDigest) || !SHA256_RE.test(value.targetAuditHead)) {
    throw stateError('catalog_pending_witness_invalid');
  }
  return value;
}

function assertPreparedAnchor(anchor, transition) {
  if (!anchor.pending || anchor.revision !== transition.expectedRevision
      || anchor.headDigest !== transition.expectedDigest
      || canonicalDigest(transitionFromAnchor({ anchorNamespace: transition.namespace }, anchor))
        !== canonicalDigest(transition)) throw stateError('catalog_anchor_prepare_failed');
}

function assertFinalizedAnchor(anchor, transition) {
  if (anchor.pending || anchor.revision !== transition.targetRevision
      || anchor.headDigest !== transition.targetDigest) {
    throw stateError('catalog_anchor_finalize_failed');
  }
}

function referencedSigningKeyIds(config) {
  return Object.keys(signingKeyReferenceCounts(config)).sort();
}

function signingKeyReferenceCounts(config) {
  return runTransaction(config.storage, (tx) => {
    requireTransaction(tx);
    return collectSigningKeyReferenceCounts(tx, config);
  });
}

function collectSigningKeyReferenceCounts(tx, config) {
  const current = tx.readCurrentCatalog();
  const currentSequence = current?.distributionSequence || 0;
  return readHistoryState(tx, config, currentSequence).keyReferences;
}

function canRetireSigningKey(config, keyId) {
  if (typeof keyId !== 'string' || !/^rw-catalog-(?:global|distribution)-/.test(keyId)
      || !SAFE_SLUG_RE.test(keyId)) throw stateError('catalog_key_id_invalid');
  const references = signingKeyReferenceCounts(config)[keyId] || 0;
  return { keyId, references, canRetire: references === 0 };
}

function incrementReference(counts, keyId) {
  counts.set(keyId, (counts.get(keyId) || 0) + 1);
}

function validateHistoryTombstone(value) {
  const keys = [
    'distributionDigest', 'distributionSequence', 'distributionSigningKeyId',
    'distributionArtifactDigest',
    'globalArtifactDigest', 'globalReleaseId', 'globalSigningKeyId',
    'globalVersion', 'recordsDigest', 'schemaVersion',
  ];
  if (!exactKeys(value, keys) || value.schemaVersion !== 1
      || !Number.isSafeInteger(value.distributionSequence) || value.distributionSequence < 1
      || !Number.isSafeInteger(value.globalVersion) || value.globalVersion < 1
      || !SHA256_RE.test(value.distributionDigest)
      || !SHA256_RE.test(value.distributionArtifactDigest)
      || !SHA256_RE.test(value.globalArtifactDigest) || !SHA256_RE.test(value.recordsDigest)
      || !UUID_RE.test(String(value.globalReleaseId || ''))
      || !SAFE_SLUG_RE.test(value.globalSigningKeyId)
      || !SAFE_SLUG_RE.test(value.distributionSigningKeyId)
      || !/^rw-catalog-global-/.test(value.globalSigningKeyId)
      || !/^rw-catalog-distribution-/.test(value.distributionSigningKeyId)) {
    throw stateError('catalog_history_corrupt');
  }
  return value;
}

function loadOverrideIntegrityState(tx, config, requireReady) {
  const primary = readPrimaryOverrideState(tx, config);
  const anchor = config.anchorAuthority.read(config.overrideAnchorNamespace);
  if (anchor.pending && requireReady) throw stateError('catalog_readiness_frozen');
  if (anchor.revision !== primary.revision || anchor.headDigest !== primary.headDigest) {
    throw stateError('tenant_override_integrity_invalid');
  }
  return { ...primary, anchor };
}

function readPrimaryOverrideState(tx, config) {
  const values = snapshotStoredValue(tx.listTenantOverrides(MAX_TENANT_OVERRIDES + 1),
    'tenant_override_corrupt');
  if (!Array.isArray(values) || values.length > MAX_TENANT_OVERRIDES) {
    throw stateError('tenant_override_corrupt');
  }
  const rows = new Map();
  const active = new Map();
  for (const wrapped of values) {
    const envelope = openOverrideEnvelope(config, wrapped);
    if (rows.has(envelope.catalogId)) throw stateError('tenant_override_corrupt');
    rows.set(envelope.catalogId, envelope);
    if (envelope.status === 'active') active.set(envelope.catalogId, envelope.record);
  }
  const wrappedHead = tx.readTenantOverrideHead();
  if (!wrappedHead) {
    if (rows.size) throw stateError('tenant_override_integrity_invalid');
    return { revision: 0, headDigest: ZERO_DIGEST, rows, active };
  }
  const head = config.integrity.open('catalog.tenant-override-head.v1', wrappedHead,
    'tenant_override_integrity_invalid');
  const keys = [
    'count', 'mutationDigest', 'namespace', 'previousHeadDigest', 'recordsDigest',
    'revision', 'schemaVersion', 'updatedAt',
  ];
  if (!exactKeys(head, keys) || head.schemaVersion !== 1 || head.namespace !== 'tenant_overrides'
      || !Number.isSafeInteger(head.revision) || head.revision < 1 || head.count !== rows.size
      || !SHA256_RE.test(head.recordsDigest) || !SHA256_RE.test(head.previousHeadDigest)
      || !SHA256_RE.test(head.mutationDigest) || !canonicalTime(head.updatedAt)
      || head.recordsDigest !== overrideRowsDigest(rows)) {
    throw stateError('tenant_override_integrity_invalid');
  }
  return { ...head, headDigest: canonicalDigest(head), rows, active };
}

function openOverrideEnvelope(config, wrapped) {
  const value = config.integrity.open('catalog.tenant-override.v1', wrapped,
    'tenant_override_corrupt');
  const keys = [
    'catalogId', 'customerId', 'deploymentId', 'record', 'revision', 'schemaVersion',
    'status', 'updatedAt',
  ];
  if (!exactKeys(value, keys) || value.schemaVersion !== 1
      || value.customerId !== config.customerId || value.deploymentId !== config.deploymentId
      || !SAFE_SLUG_RE.test(String(value.catalogId || ''))
      || !Number.isSafeInteger(value.revision) || value.revision < 1
      || !['active', 'deleted'].includes(value.status) || !canonicalTime(value.updatedAt)) {
    throw stateError('tenant_override_corrupt');
  }
  if (value.status === 'active') {
    const record = parseStrict(overrideSchema, value.record, 'tenant_override_corrupt');
    if (record.catalogId !== value.catalogId || record.revision !== value.revision
        || record.updatedAt !== value.updatedAt) throw stateError('tenant_override_corrupt');
    value.record = record;
  } else if (value.record !== null) throw stateError('tenant_override_corrupt');
  return value;
}

function overrideRowsDigest(rows) {
  return canonicalDigest([...rows.values()].sort((left, right) =>
    left.catalogId.localeCompare(right.catalogId)).map((value) => ({
    catalogId: value.catalogId,
    revision: value.revision,
    status: value.status,
    recordDigest: canonicalDigest(value),
  })));
}

function putTenantOverride(config, input) {
  const next = parseStrict(overrideSchema, input, 'tenant_override_invalid');
  return mutateTenantOverride(config, next, false);
}

function deleteTenantOverride(config, input) {
  const next = parseStrict(overrideDeleteSchema, input, 'tenant_override_invalid');
  return mutateTenantOverride(config, next, true);
}

function mutateTenantOverride(config, next, deleted) {
  const outcome = runTransaction(config.storage, (tx) => {
    requireTransaction(tx);
    loadIntegrityState(tx, config, true);
    const state = loadOverrideIntegrityState(tx, config, true);
    const current = state.rows.get(next.catalogId) || null;
    const result = overrideWriteDecision(current, next, deleted);
    if (result.action !== 'apply') return { result, transition: null };
    if (!current && state.rows.size >= MAX_TENANT_OVERRIDES) {
      throw stateError('tenant_override_quota_exceeded');
    }
    const envelope = {
      schemaVersion: 1,
      customerId: config.customerId,
      deploymentId: config.deploymentId,
      catalogId: next.catalogId,
      revision: next.revision,
      status: deleted ? 'deleted' : 'active',
      record: deleted ? null : clone(next),
      updatedAt: next.updatedAt,
    };
    const wrapped = config.integrity.seal('catalog.tenant-override.v1', envelope);
    if (tx.compareAndSetTenantOverride(next.catalogId, current?.revision || 0,
      clone(wrapped)) !== true) throw stateError('tenant_override_conflict');
    const rows = new Map(state.rows);
    rows.set(next.catalogId, envelope);
    const head = {
      schemaVersion: 1,
      namespace: 'tenant_overrides',
      revision: state.revision + 1,
      count: rows.size,
      recordsDigest: overrideRowsDigest(rows),
      previousHeadDigest: state.headDigest,
      mutationDigest: canonicalDigest({
        action: deleted ? 'delete' : 'upsert',
        catalogIdDigest: canonicalDigest(next.catalogId),
        revision: next.revision,
        recordDigest: canonicalDigest(envelope),
      }),
      updatedAt: next.updatedAt,
    };
    const wrappedHead = config.integrity.seal('catalog.tenant-override-head.v1', head);
    const headDigest = canonicalDigest(head);
    if (tx.compareAndSetTenantOverrideHead(state.revision, clone(wrappedHead)) !== true) {
      throw stateError('tenant_override_head_conflict');
    }
    const readback = openOverrideEnvelope(config, tx.readTenantOverride(next.catalogId));
    if (canonicalDigest(readback) !== canonicalDigest(envelope)
        || canonicalDigest(config.integrity.open('catalog.tenant-override-head.v1',
          tx.readTenantOverrideHead(), 'tenant_override_corrupt')) !== headDigest) {
      throw stateError('tenant_override_readback_failed');
    }
    const transition = {
      namespace: config.overrideAnchorNamespace,
      expectedRevision: state.revision,
      expectedDigest: state.headDigest,
      targetRevision: head.revision,
      targetDigest: headDigest,
      witnessDigest: canonicalDigest(wrapped),
    };
    assertPreparedAnchor(config.anchorAuthority.prepare(transition), transition);
    return {
      result: deleted
        ? { action: 'apply', catalogId: next.catalogId, revision: next.revision, deleted: true }
        : { action: 'apply', value: clone(next) },
      transition,
    };
  });
  if (outcome.transition) {
    assertFinalizedAnchor(config.anchorAuthority.finalize(outcome.transition), outcome.transition);
  }
  return outcome.result;
}

function overrideWriteDecision(current, next, deleted) {
  if (!current) {
    if (deleted || next.revision !== 1) throw stateError('tenant_override_genesis_invalid');
    return { action: 'apply' };
  }
  if (next.revision < current.revision) throw stateError('tenant_override_stale');
  const supplied = deleted ? { status: 'deleted', revision: next.revision, updatedAt: next.updatedAt }
    : { status: 'active', revision: next.revision, updatedAt: next.updatedAt, record: next };
  const existing = current.status === 'deleted'
    ? { status: 'deleted', revision: current.revision, updatedAt: current.updatedAt }
    : { status: 'active', revision: current.revision, updatedAt: current.updatedAt,
      record: current.record };
  if (next.revision === current.revision) {
    if (canonicalDigest(supplied) !== canonicalDigest(existing)) {
      throw stateError('tenant_override_conflict');
    }
    return { action: 'acknowledge', reason: 'already_applied',
      value: current.record ? clone(current.record) : null };
  }
  if (next.revision !== current.revision + 1) throw stateError('tenant_override_revision_gap');
  if (next.updatedAt < current.updatedAt) throw stateError('tenant_override_time_regression');
  return { action: 'apply' };
}

function putLocalObservation(config, input) {
  const next = parseStrict(observationSchema, input, 'local_observation_invalid');
  return runTransaction(config.storage, (tx) => {
    requireTransaction(tx);
    loadIntegrityState(tx, config, true);
    const current = parseStoredOptional(observationSchema,
      tx.readLocalObservation(next.registrableDomain), 'local_observation_corrupt');
    validateObservationProgression(current, next);
    const result = localWriteDecision(current, next, 'local_observation');
    if (result.action === 'apply') tx.writeLocalObservation(clone(next));
    return result.action === 'apply' ? { ...result, value: clone(next) } : result;
  });
}

function localWriteDecision(current, next, prefix) {
  if (!current) {
    if (next.revision !== 1) throw stateError(`${prefix}_genesis_invalid`);
    return { action: 'apply' };
  }
  if (next.revision < current.revision) throw stateError(`${prefix}_stale`);
  if (next.revision === current.revision) {
    if (canonicalDigest(next) !== canonicalDigest(current)) throw stateError(`${prefix}_conflict`);
    return { action: 'acknowledge', reason: 'already_applied', value: clone(current) };
  }
  if (next.revision !== current.revision + 1) throw stateError(`${prefix}_revision_gap`);
  return { action: 'apply' };
}

function validateObservationProgression(current, next) {
  if (!current) return;
  validateUpdatedAt(current, next, 'local_observation');
  if (next.firstSeenDay !== current.firstSeenDay || next.lastSeenDay < current.lastSeenDay) {
    throw stateError('local_observation_time_regression');
  }
  if (OBSERVATION_BUCKETS.indexOf(next.observationCountBucket)
      < OBSERVATION_BUCKETS.indexOf(current.observationCountBucket)) {
    throw stateError('local_observation_count_regression');
  }
  if (current.sourceTypes.some((source) => !next.sourceTypes.includes(source))) {
    throw stateError('local_observation_source_regression');
  }
}

function validateUpdatedAt(current, next, prefix) {
  if (current && next.revision > current.revision && next.updatedAt < current.updatedAt) {
    throw stateError(`${prefix}_time_regression`);
  }
}

function effectiveRecord(record, override) {
  return {
    ...clone(record),
    globalClassification: record.classification,
    globalRiskTier: record.riskTier,
    classification: override?.classification ?? record.classification,
    riskTier: override?.riskTier ?? record.riskTier,
    disposition: override?.disposition ?? 'inherit',
    overrideRevision: override?.revision ?? null,
  };
}

function readLocalObservations(config) {
  return runTransaction(config.storage, (tx) => {
    requireTransaction(tx);
    loadIntegrityState(tx, config, true);
    const observations = snapshotStoredValue(tx.listLocalObservations(), 'local_observation_corrupt');
    if (!Array.isArray(observations)) throw stateError('local_observation_corrupt');
    return observations.map((value) => parseStrict(observationSchema, value,
      'local_observation_corrupt'));
  });
}

function parseUniqueOverrides(values) {
  const snapshot = snapshotStoredValue(values, 'tenant_override_corrupt');
  if (!Array.isArray(snapshot)) throw stateError('tenant_override_corrupt');
  const output = new Map();
  for (const value of snapshot) {
    const parsed = parseStrict(overrideSchema, value, 'tenant_override_corrupt');
    if (output.has(parsed.catalogId)) throw stateError('tenant_override_corrupt');
    output.set(parsed.catalogId, parsed);
  }
  return output;
}

function publicState(state) {
  return clone({
    customerId: state.customerId,
    deploymentId: state.deploymentId,
    distributionSequence: state.distributionSequence,
    previousDistributionSequence: state.previousDistributionSequence,
    globalReleaseId: state.globalReleaseId,
    globalVersion: state.globalVersion,
    globalArtifactDigest: state.globalArtifactDigest,
    recordsDigest: state.recordsDigest,
    distributionDigest: state.distributionDigest,
    distributionPayloadDigest: state.distributionDigest,
    distributionArtifactDigest: state.distributionArtifactDigest,
    activationStatus: state.rollout.mode === 'required' ? 'active' : 'pending',
    rollout: state.rollout,
    issuedAt: state.issuedAt,
  });
}

function snapshotArtifactPair(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || !exactKeys(value, ['distributionArtifact', 'globalArtifact'])) {
    throw stateError('invalid_schema');
  }
  return snapshotStoredValue(value, 'invalid_schema');
}

function validateScope(customerId, deploymentId) {
  const probe = {
    schemaVersion: protocol.PROTOCOL_VERSION,
    kind: protocol.CHANNEL_KINDS.HEARTBEAT,
    messageId: '00000000-0000-4000-8000-000000000000',
    customerId,
    deploymentId,
    heartbeatNonce: 'AAAAAAAAAAAAAAAAAAAAAA',
    plan: 'standard', seatsUsed: 0, seatLimit: 0, version: '0.0.0',
    sentAt: '2000-01-01T00:00:00.000Z',
    lastAppliedEntitlementVersion: 0, lastAppliedPolicyVersion: 0,
    lastAppliedCatalogVersion: 0, lastAppliedRegistryGeneration: 0,
  };
  try { protocol.assertChannel(probe, protocol.CHANNEL_KINDS.HEARTBEAT); }
  catch { throw stateError('scope_invalid'); }
}

function requireStorage(storage) {
  if (!storage || typeof storage.transaction !== 'function') throw stateError('storage_invalid');
}

function runTransaction(storage, callback) {
  let calls = 0;
  let callbackResult;
  const result = storage.transaction((tx) => {
    calls += 1;
    if (calls !== 1) throw stateError('storage_invalid');
    callbackResult = callback(tx);
    return callbackResult;
  });
  if (calls !== 1 || result !== callbackResult || (result && typeof result.then === 'function')) {
    throw stateError('storage_invalid');
  }
  return result;
}

function requireTransaction(tx) {
  const methods = [
    'appendCatalogAuditEvent', 'clearCatalogPendingWitness', 'compareAndSetActiveCatalog',
    'compareAndSetCatalogAuditCheckpoint', 'compareAndSetCatalogIntegrityHead',
    'compareAndSetCatalogHistoryCheckpoint',
    'compareAndSetTenantOverride', 'compareAndSetTenantOverrideHead',
    'compareAndSetCurrentCatalog',
    'deleteCatalogAuditEvent', 'deleteCatalogDistribution', 'deleteCatalogTombstone',
    'deleteGlobalCatalogArtifact', 'insertCatalogDistribution',
    'insertGlobalCatalogArtifact', 'listCatalogAcknowledgementTransitions',
    'listCatalogAuditEvents', 'listCatalogDistributions', 'listGlobalCatalogArtifacts',
    'listCatalogTombstones', 'listLocalObservations', 'listTenantOverrides',
    'readCatalogAcknowledgementTransition', 'readCatalogAuditCheckpoint',
    'readCatalogDistribution', 'readCatalogIntegrityHead',
    'readCatalogHistoryCheckpoint',
    'readActiveCatalog', 'readCatalogPendingWitness', 'readCurrentCatalog',
    'readGlobalCatalogArtifact', 'readLocalObservation', 'readTenantOverride',
    'readTenantOverrideHead',
    'insertCatalogAcknowledgementTransition', 'writeCatalogPendingWitness',
    'writeCatalogTombstone', 'writeLocalObservation',
  ];
  if (!tx || methods.some((name) => typeof tx[name] !== 'function')) throw stateError('storage_invalid');
}

function parseStrict(schema, value, code) {
  const parsed = schema.safeParse(value);
  if (!parsed.success) throw stateError(code);
  return parsed.data;
}

function parseStoredOptional(schema, value, code) {
  if (value === null || value === undefined) return null;
  return parseStrict(schema, snapshotStoredValue(value, code), code);
}

function snapshotStoredValue(value, code) {
  try {
    const serialized = JSON.stringify(value);
    if (serialized === undefined) throw new TypeError('missing durable value');
    return JSON.parse(serialized);
  } catch { throw stateError(code); }
}

function exactKeys(value, keys) {
  return value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
}

function canonicalTime(value) {
  const parsed = Date.parse(value);
  return typeof value === 'string' && Number.isFinite(parsed)
    && new Date(parsed).toISOString() === value;
}

function canonicalDay(value) { return canonicalTime(`${value}T00:00:00.000Z`); }

function sortedUnique(values) {
  return values.every((value, index) => index === 0 || values[index - 1].localeCompare(value) < 0);
}

function issue(ctx, path) {
  ctx.addIssue({ code: z.ZodIssueCode.custom, path: [path], message: 'invalid local metadata' });
}

function canonicalDigest(value) {
  return crypto.createHash('sha256').update(protocol.canonicalJson(value), 'utf8').digest('hex');
}

function clone(value) { return JSON.parse(JSON.stringify(value)); }

function stateError(code) {
  const error = new Error('shadow AI catalog state rejected');
  error.code = code;
  return error;
}

module.exports = {
  CUSTOMER_SHADOW_AI_PACKAGE_BOUNDARY,
  MAX_ACTIVE_AUDIT_EVENTS,
  MAX_ACTIVE_DISTRIBUTIONS,
  MAX_RETAINED_GLOBAL_ARTIFACTS,
  MAX_ARCHIVED_TOMBSTONES,
  MAX_TENANT_OVERRIDES,
  ROLLBACK_WINDOW_DISTRIBUTIONS,
  STATE_VERSION,
  createShadowAiCatalogState,
  createReferenceShadowAiCatalogState,
  createProductionShadowAiCatalogState,
};
