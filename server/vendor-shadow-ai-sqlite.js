'use strict';

const {
  REFERENCE_BLOB_ASSURANCE,
  checkedStoreId,
  clone,
  digest,
  openStateStore,
  storageError,
} = require('./shadow-ai-sqlite-core');

const VENDOR_PRODUCTION_STORES = new WeakSet();

function openVendorShadowAiSqliteStorage(options = {}) {
  if (referenceRuntimeProhibited(options)) {
    throw storageError('shadow_ai_vendor_sqlite_reference_only');
  }
  const authorityResolver = checkedAuthorityResolver(options.authorityResolver);
  return openStateStore(options, {
    storeId: checkedStoreId(options.storeId || 'vendor:shadow-ai'),
    kind: 'vendor_intelligence',
    assurance: REFERENCE_BLOB_ASSURANCE,
    productionReady: false,
    createState: vendorState,
    transactionMethods: (state) => vendorTransactionMethods(state, authorityResolver),
    asyncTransactions: true,
  });
}

function referenceRuntimeProhibited(options) {
  const actualProduction = String(process.env.NODE_ENV || '').trim().toLowerCase() === 'production';
  if (actualProduction) return true;
  const requestedProduction = String(options?.env?.NODE_ENV || '')
    .trim().toLowerCase() === 'production';
  return requestedProduction || options?.production === true;
}

function openProductionVendorShadowAiStorage() {
  throw storageError('shadow_ai_managed_postgres_adapter_unavailable');
}

function assertProductionVendorShadowAiStorage(value) {
  if (!value || !VENDOR_PRODUCTION_STORES.has(value)) {
    throw storageError('shadow_ai_production_vendor_storage_required');
  }
  return value;
}

function vendorState() {
  return {
    authorizationClaims: new Map(), confirmationClaims: new Map(), authorizationLinks: new Map(),
    consentEpochs: new Map(), observations: new Map(), observationIdempotency: new Map(),
    reviews: new Map(), reviewIdempotency: new Map(), classifications: new Map(), domains: new Map(),
    globalReleases: new Map(), globalReleaseIdempotency: new Map(), currentGlobalVersion: 0,
    globalHistoryTombstones: new Map(), globalHistoryCheckpoint: null,
    distributions: new Map(), distributionIdempotency: new Map(),
    currentDistributionVersions: new Map(), adoptions: new Map(),
    distributionHistoryTombstones: new Map(), distributionHistoryCheckpoints: new Map(),
    acknowledgementClaims: new Map(), acknowledgementMessageClaims: new Map(),
    audits: new Map(), auditHighWater: null,
    auditCheckpoint: null, governanceHeads: new Map(), governancePending: new Map(),
    pageSnapshots: new Map(),
  };
}

function vendorTransactionMethods(state, authority) {
  return {
    resolveAuthorization: async (id) => resolveAuthority(authority, 'resolveAuthorization', id),
    claimAuthorization: async (id, digestValue) => claimOpaque(
      state.authorizationClaims, id, digestValue,
    ),
    readAuthorizationLink: async (id) => clone(state.authorizationLinks.get(id)),
    insertAuthorizationLink: async (id, value) => insertUnique(state.authorizationLinks, id, value),
    resolveConfirmation: async (id) => resolveAuthority(authority, 'resolveConfirmation', id),
    claimConfirmation: async (id, digestValue) => claimOpaque(
      state.confirmationClaims, id, digestValue,
    ),
    resolveConsent: async (id) => resolveAuthority(authority, 'resolveConsent', id),
    resolveScopeConsent: async (customerId, deploymentId) => resolveAuthority(
      authority, 'resolveScopeConsent', customerId, deploymentId,
    ),
    readScopeConsentEpoch: async (customerId, deploymentId) => clone(
      state.consentEpochs.get(scopeKey({ customerId, deploymentId })),
    ),
    compareAndSetScopeConsentEpoch: async (customerId, deploymentId, expected, wrapped) => {
      const key = scopeKey({ customerId, deploymentId });
      if ((state.consentEpochs.get(key)?.payload?.epoch || 0) !== expected) return false;
      state.consentEpochs.set(key, clone(wrapped)); return true;
    },
    countActiveObservations: async (customerId, deploymentId, nowIso) =>
      [...state.observations.values()].filter((wrapped) => {
        const value = wrapped.payload;
        return value.customerId === customerId && value.deploymentId === deploymentId
          && value.retainUntil > nowIso;
      }).length,
    purgeExpiredObservations: async (customerId, deploymentId, nowIso, limit) =>
      purgeObservations(state, customerId, deploymentId,
        (value) => value.retainUntil <= nowIso, limit),
    purgeScopeObservations: async (customerId, deploymentId, limit) => {
      const purged = purgeObservations(state, customerId, deploymentId, () => true, limit);
      const remaining = [...state.observations.values()].filter((wrapped) => {
        const value = wrapped.payload;
        return value.customerId === customerId && value.deploymentId === deploymentId;
      }).length;
      return { purged, remaining };
    },
    purgeScopePageSnapshots: async (customerId, deploymentId, limit) => {
      let purged = 0;
      for (const [id, snapshot] of state.pageSnapshots) {
        if (snapshot.customerId === customerId && snapshot.deploymentId === deploymentId
            && purged < limit) {
          state.pageSnapshots.delete(id); purged += 1;
        }
      }
      const remaining = [...state.pageSnapshots.values()].filter((snapshot) =>
        snapshot.customerId === customerId && snapshot.deploymentId === deploymentId).length;
      return { purged, remaining };
    },
    findObservationByIdempotency: async (customerId, deploymentId, key) => {
      const id = state.observationIdempotency.get(scopedKey(customerId, deploymentId, key));
      return id ? clone(state.observations.get(scopedKey(customerId, deploymentId, id))) : null;
    },
    readObservation: async (customerId, deploymentId, id) => clone(
      state.observations.get(scopedKey(customerId, deploymentId, id)),
    ),
    insertObservation: async (id, customerId, deploymentId, idempotencyKey, value) => {
      const recordKey = scopedKey(customerId, deploymentId, id);
      const idemKey = scopedKey(customerId, deploymentId, idempotencyKey);
      if (state.observations.has(recordKey) || state.observationIdempotency.has(idemKey)) return false;
      state.observations.set(recordKey, clone(value));
      state.observationIdempotency.set(idemKey, id); return true;
    },
    listObservations: async (customerId, deploymentId, cursor, limit, nowIso) =>
      [...state.observations.values()].filter((wrapped) => {
        const value = wrapped.payload;
        return value.customerId === customerId && value.deploymentId === deploymentId
          && value.retainUntil > nowIso && (cursor === null || value.observationId > cursor);
      }).sort((left, right) => left.payload.observationId.localeCompare(
        right.payload.observationId,
      )).slice(0, limit).map(clone),
    findReviewByIdempotency: async (customerId, deploymentId, key) => {
      const id = state.reviewIdempotency.get(scopedKey(customerId, deploymentId, key));
      return id ? clone(state.reviews.get(scopedKey(customerId, deploymentId, id))) : null;
    },
    insertReview: async (reviewId, customerId, deploymentId, observationId,
      idempotencyKey, value) => {
      const recordKey = scopedKey(customerId, deploymentId, observationId);
      const idemKey = scopedKey(customerId, deploymentId, idempotencyKey);
      if (state.reviews.has(recordKey) || state.reviewIdempotency.has(idemKey)) return false;
      state.reviews.set(recordKey, clone(value));
      state.reviewIdempotency.set(idemKey, observationId); return true;
    },
    readClassification: async (catalogId) => clone(state.classifications.get(catalogId)),
    countClassifications: async () => state.classifications.size,
    claimClassificationDomains: async (claim) => claimDomains(state, claim),
    compareAndSetClassification: async (catalogId, expected, value) => {
      if ((state.classifications.get(catalogId)?.payload?.revision || 0) !== expected) return false;
      state.classifications.set(catalogId, clone(value)); return true;
    },
    listAllClassifications: async (limit) => [...state.classifications.values()]
      .sort((left, right) => left.payload.record.catalogId.localeCompare(
        right.payload.record.catalogId,
      )).slice(0, limit).map(clone),
    listClassifications: async (cursor, limit) => [...state.classifications.values()]
      .filter((wrapped) => cursor === null || wrapped.payload.record.catalogId > cursor)
      .sort((left, right) => left.payload.record.catalogId.localeCompare(
        right.payload.record.catalogId,
      )).slice(0, limit).map(clone),
    countGlobalReleases: async () => state.globalReleases.size,
    findGlobalReleaseByIdempotency: async (key) => {
      const version = state.globalReleaseIdempotency.get(key);
      return version ? clone(state.globalReleases.get(version)) : null;
    },
    readCurrentGlobalRelease: async () => state.currentGlobalVersion
      ? clone(state.globalReleases.get(state.currentGlobalVersion)) : null,
    readGlobalRelease: async (version) => clone(state.globalReleases.get(version)),
    listGlobalReleases: async (limit) => [...state.globalReleases]
      .sort(([left], [right]) => left - right).slice(0, limit)
      .map(([version, wrapped]) => ({ version, wrapped: clone(wrapped) })),
    compareAndSetGlobalRelease: async (expected, idempotencyKey, version, wrapped) => {
      if (state.currentGlobalVersion !== expected
          || state.globalReleaseIdempotency.has(idempotencyKey)
          || state.globalReleases.has(version)) return false;
      state.currentGlobalVersion = version;
      state.globalReleases.set(version, clone(wrapped));
      state.globalReleaseIdempotency.set(idempotencyKey, version); return true;
    },
    deleteGlobalRelease: async (version, artifactDigest, wrappedDigest, idempotencyKey) => {
      const wrapped = state.globalReleases.get(version);
      if (!wrapped || wrapped.payload.artifactDigest !== artifactDigest
          || wrapped.payload.idempotencyKey !== idempotencyKey
          || digest(wrapped) !== wrappedDigest || version === state.currentGlobalVersion) return false;
      state.globalReleases.delete(version);
      state.globalReleaseIdempotency.delete(idempotencyKey); return true;
    },
    readGlobalHistoryCheckpoint: async () => clone(state.globalHistoryCheckpoint),
    compareAndSetGlobalHistoryCheckpoint: async (expected, wrapped) => {
      if ((state.globalHistoryCheckpoint?.payload.throughSequence || 0) !== expected) return false;
      state.globalHistoryCheckpoint = clone(wrapped); return true;
    },
    listGlobalHistoryTombstones: async (limit) => [...state.globalHistoryTombstones]
      .sort(([left], [right]) => left - right).slice(0, limit)
      .map(([, row]) => clone(row.wrapped)),
    writeGlobalHistoryTombstone: async (version, artifactDigest, wrapped) => {
      if (state.globalHistoryTombstones.has(version)) return false;
      state.globalHistoryTombstones.set(version, { artifactDigest, wrapped: clone(wrapped) });
      return true;
    },
    deleteGlobalHistoryTombstone: async (version, artifactDigest, wrappedDigest) => {
      const row = state.globalHistoryTombstones.get(version);
      if (!row || row.artifactDigest !== artifactDigest || digest(row.wrapped) !== wrappedDigest) {
        return false;
      }
      state.globalHistoryTombstones.delete(version); return true;
    },
    countDistributions: async (customerId, deploymentId) => {
      const prefix = `${scopeKey({ customerId, deploymentId })}\0`;
      return [...state.distributions.keys()].filter((key) => key.startsWith(prefix)).length;
    },
    findDistributionByIdempotency: async (customerId, deploymentId, key) => {
      const version = state.distributionIdempotency.get(scopedKey(customerId, deploymentId, key));
      return version ? clone(state.distributions.get(
        distributionKey({ customerId, deploymentId }, version),
      )) : null;
    },
    readCurrentDistribution: async (customerId, deploymentId) => {
      const version = state.currentDistributionVersions.get(scopeKey({ customerId, deploymentId }));
      return version ? clone(state.distributions.get(
        distributionKey({ customerId, deploymentId }, version),
      )) : null;
    },
    readDistribution: async (customerId, deploymentId, version) => clone(
      state.distributions.get(distributionKey({ customerId, deploymentId }, version)),
    ),
    listDistributions: async (customerId, deploymentId, limit) => {
      const prefix = `${scopeKey({ customerId, deploymentId })}\0`;
      return [...state.distributions].filter(([key]) => key.startsWith(prefix))
        .map(([key, wrapped]) => ({ sequence: Number(key.slice(prefix.length)), wrapped }))
        .sort((left, right) => left.sequence - right.sequence).slice(0, limit).map(clone);
    },
    compareAndSetDistribution: async (customerId, deploymentId, expected,
      idempotencyKey, version, wrapped) => {
      const scope = scopeKey({ customerId, deploymentId });
      const idemKey = scopedKey(customerId, deploymentId, idempotencyKey);
      if ((state.currentDistributionVersions.get(scope) || 0) !== expected
          || state.distributionIdempotency.has(idemKey)
          || state.distributions.has(distributionKey({ customerId, deploymentId }, version))) {
        return false;
      }
      state.currentDistributionVersions.set(scope, version);
      state.distributionIdempotency.set(idemKey, version);
      state.distributions.set(distributionKey({ customerId, deploymentId }, version), clone(wrapped));
      return true;
    },
    deleteDistributionHistory: async (customerId, deploymentId, version,
      artifactDigest, wrappedDigest, idempotencyKey, adoptionDigest) => {
      const key = distributionKey({ customerId, deploymentId }, version);
      const wrapped = state.distributions.get(key);
      const adoption = state.adoptions.get(key);
      if (!wrapped || !adoption || wrapped.payload.artifactDigest !== artifactDigest
          || wrapped.payload.idempotencyKey !== idempotencyKey
          || digest(wrapped) !== wrappedDigest || digest(adoption) !== adoptionDigest
          || version === state.currentDistributionVersions.get(
            scopeKey({ customerId, deploymentId }),
          )) return false;
      state.distributions.delete(key); state.adoptions.delete(key);
      state.distributionIdempotency.delete(scopedKey(customerId, deploymentId, idempotencyKey));
      return true;
    },
    listDistributionHistoryScopes: async (limit) => [...state.currentDistributionVersions.keys()]
      .sort().slice(0, limit).map((key) => {
        const [customerId, deploymentId] = key.split('\0');
        return { customerId, deploymentId };
      }),
    readDistributionHistoryCheckpoint: async (customerId, deploymentId) => clone(
      state.distributionHistoryCheckpoints.get(scopeKey({ customerId, deploymentId })),
    ),
    compareAndSetDistributionHistoryCheckpoint: async (customerId, deploymentId,
      expected, wrapped) => {
      const key = scopeKey({ customerId, deploymentId });
      if ((state.distributionHistoryCheckpoints.get(key)?.payload.throughSequence || 0)
          !== expected) return false;
      state.distributionHistoryCheckpoints.set(key, clone(wrapped)); return true;
    },
    listDistributionHistoryTombstones: async (customerId, deploymentId, limit) => {
      const prefix = `${scopeKey({ customerId, deploymentId })}\0`;
      return [...state.distributionHistoryTombstones].filter(([key]) => key.startsWith(prefix))
        .map(([key, row]) => ({ sequence: Number(key.slice(prefix.length)), row }))
        .sort((left, right) => left.sequence - right.sequence).slice(0, limit)
        .map(({ row }) => clone(row.wrapped));
    },
    writeDistributionHistoryTombstone: async (customerId, deploymentId, version,
      artifactDigest, wrapped) => {
      const key = distributionKey({ customerId, deploymentId }, version);
      if (state.distributionHistoryTombstones.has(key)) return false;
      state.distributionHistoryTombstones.set(key, { artifactDigest, wrapped: clone(wrapped) });
      return true;
    },
    deleteDistributionHistoryTombstone: async (customerId, deploymentId, version,
      artifactDigest, wrappedDigest) => {
      const key = distributionKey({ customerId, deploymentId }, version);
      const row = state.distributionHistoryTombstones.get(key);
      if (!row || row.artifactDigest !== artifactDigest || digest(row.wrapped) !== wrappedDigest) {
        return false;
      }
      state.distributionHistoryTombstones.delete(key); return true;
    },
    readAdoption: async (customerId, deploymentId, version) => clone(
      state.adoptions.get(distributionKey({ customerId, deploymentId }, version)),
    ),
    compareAndSetAdoption: async (customerId, deploymentId, version, expected, wrapped) => {
      const key = distributionKey({ customerId, deploymentId }, version);
      if ((state.adoptions.get(key)?.payload.revision || 0) !== expected) return false;
      state.adoptions.set(key, clone(wrapped)); return true;
    },
    claimAcknowledgementTransition: async (transitionKey, messageId, digestValue) => {
      const messageDigest = state.acknowledgementMessageClaims.get(messageId);
      if (messageDigest !== undefined && messageDigest !== digestValue) return 'conflict';
      const current = state.acknowledgementClaims.get(transitionKey);
      if (!current) {
        state.acknowledgementMessageClaims.set(messageId, digestValue);
        state.acknowledgementClaims.set(transitionKey, { digest: digestValue, record: null });
        return 'claimed';
      }
      if (current.digest !== digestValue) return 'conflict';
      if (messageDigest === undefined) state.acknowledgementMessageClaims.set(messageId, digestValue);
      return current.record ? { status: 'replay', record: clone(current.record) } : 'claimed';
    },
    completeAcknowledgementTransition: async (transitionKey, digestValue, value) => {
      const current = state.acknowledgementClaims.get(transitionKey);
      if (!current || current.digest !== digestValue || current.record) return false;
      current.record = clone(value); return true;
    },
    readAuditHighWater: async () => clone(state.auditHighWater),
    readAuditCheckpoint: async () => clone(state.auditCheckpoint),
    compareAndSetAuditCheckpoint: async (expected, wrapped) => {
      if ((state.auditCheckpoint?.payload.sequence || 0) !== expected
          || wrapped?.payload?.sequence !== expected + 1) return false;
      state.auditCheckpoint = clone(wrapped); return true;
    },
    readAuditTail: async () => {
      if (!state.audits.size) return null;
      return clone(state.audits.get(Math.max(...state.audits.keys())).record);
    },
    readAuditEvent: async (sequence) => clone(state.audits.get(sequence)?.record),
    listAuditEvents: async (startSequence, limit) => [...state.audits]
      .filter(([sequence]) => sequence >= startSequence)
      .sort(([left], [right]) => left - right).slice(0, limit)
      .map(([, row]) => clone(row.record)),
    appendAudit: async (sequence, digestValue, wrapped) => {
      if (state.audits.has(sequence)) return false;
      state.audits.set(sequence, { digest: digestValue, record: clone(wrapped) }); return true;
    },
    deleteAuditEvent: async (sequence, wrappedDigest) => {
      const row = state.audits.get(sequence);
      if (!row || digest(row.record) !== wrappedDigest) return false;
      state.audits.delete(sequence); return true;
    },
    compareAndSetAuditHighWater: async (expected, wrapped) => {
      if ((state.auditHighWater?.payload.sequence || 0) !== expected) return false;
      state.auditHighWater = clone(wrapped); return true;
    },
    readGovernanceHead: async (namespace) => clone(state.governanceHeads.get(namespace)),
    listGovernanceHeads: async (limit) => [...state.governanceHeads]
      .sort(([left], [right]) => left.localeCompare(right)).slice(0, limit)
      .map(([namespace, wrapped]) => ({ namespace, wrapped: clone(wrapped) })),
    readGovernancePending: async (namespace) => clone(state.governancePending.get(namespace)),
    listGovernancePending: async (limit) => [...state.governancePending]
      .sort(([left], [right]) => left.localeCompare(right)).slice(0, limit)
      .map(([namespace, wrapped]) => ({ namespace, wrapped: clone(wrapped) })),
    writeGovernancePending: async (namespace, expected, wrapped) => {
      if ((state.governanceHeads.get(namespace)?.payload?.revision || 0) !== expected
          || state.governancePending.has(namespace)) return false;
      state.governancePending.set(namespace, clone(wrapped)); return true;
    },
    compareAndSetGovernanceHead: async (namespace, expected, wrapped) => {
      if ((state.governanceHeads.get(namespace)?.payload.revision || 0) !== expected) return false;
      state.governanceHeads.set(namespace, clone(wrapped)); return true;
    },
    clearGovernancePending: async (namespace, witnessDigest) => {
      const wrapped = state.governancePending.get(namespace);
      if (!wrapped || digest(wrapped) !== witnessDigest) return false;
      state.governancePending.delete(namespace); return true;
    },
    createPageSnapshot: async (snapshotId, expiresAt, pages, maxActive, nowIso,
      customerId, deploymentId, consentEpoch) => {
      for (const [id, snapshot] of state.pageSnapshots) {
        if (snapshot.expiresAt <= nowIso) state.pageSnapshots.delete(id);
      }
      if (state.pageSnapshots.size >= maxActive || state.pageSnapshots.has(snapshotId)) return false;
      state.pageSnapshots.set(snapshotId, {
        expiresAt, customerId, deploymentId, consentEpoch, pages: clone(pages),
      });
      return true;
    },
    readPageSnapshot: async (snapshotId, pageIndex, nowIso) => {
      const snapshot = state.pageSnapshots.get(snapshotId);
      if (!snapshot || snapshot.expiresAt <= nowIso) {
        if (snapshot) state.pageSnapshots.delete(snapshotId);
        return null;
      }
      return clone(snapshot.pages[pageIndex]);
    },
    releasePageSnapshot: async (snapshotId) => state.pageSnapshots.delete(snapshotId),
  };
}

function checkedAuthorityResolver(value) {
  const methods = [
    'resolveAuthorization', 'resolveConfirmation', 'resolveConsent', 'resolveScopeConsent',
  ];
  if (!value || typeof value !== 'object'
      || methods.some((method) => typeof value[method] !== 'function')) {
    throw storageError('shadow_ai_authority_resolver_invalid');
  }
  return Object.freeze(Object.fromEntries(methods.map((method) => [method, value[method].bind(value)])));
}

function resolveAuthority(authority, method, ...args) {
  const result = authority[method](...args);
  if (result && typeof result.then === 'function') {
    throw storageError('shadow_ai_authority_resolver_async_invalid');
  }
  return clone(result);
}

function claimDomains(state, claim) {
  for (const domain of claim.domains) {
    const owner = state.domains.get(domain);
    if (owner && owner.catalogId !== claim.catalogId) return 'conflict';
  }
  let created = false;
  for (const domain of claim.domains) {
    if (!state.domains.has(domain)) created = true;
    state.domains.set(domain, {
      catalogId: claim.catalogId,
      recordDigest: claim.recordDigest,
      sealedClaim: clone(claim.sealedClaim),
    });
  }
  return created ? 'claimed' : 'owned';
}

function purgeObservations(state, customerId, deploymentId, predicate, limit) {
  const matches = [...state.observations.entries()].filter(([, wrapped]) => {
    const value = wrapped.payload;
    return value.customerId === customerId && value.deploymentId === deploymentId
      && predicate(value);
  }).slice(0, limit);
  for (const [recordKey, wrapped] of matches) {
    const value = wrapped.payload;
    state.observations.delete(recordKey);
    state.observationIdempotency.delete(scopedKey(customerId, deploymentId, value.idempotencyKey));
    state.reviews.delete(scopedKey(customerId, deploymentId, value.observationId));
    for (const [key, observationId] of state.reviewIdempotency) {
      if (observationId === value.observationId
          && key.startsWith(`${scopeKey({ customerId, deploymentId })}\0`)) {
        state.reviewIdempotency.delete(key);
      }
    }
  }
  return matches.length;
}

function claimOpaque(map, id, digestValue) {
  const current = map.get(id);
  if (current === undefined) { map.set(id, digestValue); return 'claimed'; }
  return current === digestValue ? 'replay' : 'conflict';
}

function insertUnique(map, key, value) {
  if (map.has(key)) return false;
  map.set(key, clone(value)); return true;
}

function scopeKey(scope) { return `${scope.customerId}\0${scope.deploymentId}`; }
function scopedKey(customerId, deploymentId, value) {
  return `${customerId}\0${deploymentId}\0${value}`;
}
function distributionKey(scope, version) { return `${scopeKey(scope)}\0${version}`; }

module.exports = Object.freeze({
  assertProductionVendorShadowAiStorage,
  openProductionVendorShadowAiStorage,
  openVendorShadowAiSqliteStorage,
  openVendorShadowAiReferenceSqliteStorage: openVendorShadowAiSqliteStorage,
});
