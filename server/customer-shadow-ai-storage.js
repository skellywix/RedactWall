'use strict';

const {
  checkedStoreId,
  checkedStorePart,
  clone,
  digest,
  openStateStore,
  storageError,
} = require('./shadow-ai-sqlite-core');

const CUSTOMER_STORE_METADATA = new WeakMap();

function openCustomerShadowAiSqliteStorage(options = {}) {
  const customerId = checkedStorePart(options.customerId, 'customer');
  const deploymentId = checkedStorePart(options.deploymentId, 'deployment');
  return openStateStore(options, {
    storeId: `customer:${customerId}:${deploymentId}`,
    kind: 'customer_catalog',
    createState: customerState,
    transactionMethods: customerTransactionMethods,
    asyncTransactions: false,
    onOpen(storage, context) {
      CUSTOMER_STORE_METADATA.set(storage, Object.freeze({
        customerId,
        deploymentId,
        productionEligible: context.owned === true
          && context.options.testOnlyExternalDatabase !== true,
      }));
    },
  });
}

function openShadowAiAnchorSqliteStorage(options = {}) {
  const purpose = checkedStorePart(options.purpose, 'anchor purpose');
  return openStateStore(options, {
    storeId: checkedStoreId(options.storeId || `anchor:${purpose}`),
    kind: `monotonic_anchor_${purpose}`,
    assurance: 'test_reference',
    createState: () => ({ rows: new Map() }),
    transactionMethods: anchorTransactionMethods,
    asyncTransactions: false,
  });
}

function assertProductionCustomerShadowAiStorage(value) {
  if (!value || CUSTOMER_STORE_METADATA.get(value)?.productionEligible !== true) {
    throw storageError('shadow_ai_production_customer_storage_required');
  }
  return value;
}

function assertCustomerShadowAiStorageScope(value, customerId, deploymentId) {
  const metadata = CUSTOMER_STORE_METADATA.get(value);
  if (!metadata) throw storageError('shadow_ai_customer_storage_scope_required');
  if (metadata.customerId !== customerId || metadata.deploymentId !== deploymentId) {
    throw storageError('shadow_ai_customer_storage_scope_mismatch');
  }
  return value;
}

function anchorTransactionMethods(state) {
  return {
    readAnchor: (namespace) => clone(state.rows.get(namespace)),
    compareAndSetAnchor: (namespace, expectedGeneration, wrapped) => {
      if ((state.rows.get(namespace)?.payload?.generation || 0) !== expectedGeneration) return false;
      state.rows.set(namespace, clone(wrapped));
      return true;
    },
    listAnchors: (limit) => [...state.rows]
      .sort(([left], [right]) => left.localeCompare(right)).slice(0, limit)
      .map(([namespace, wrapped]) => ({ namespace, wrapped: clone(wrapped) })),
  };
}

function customerState() {
  return {
    current: null, active: null, globals: new Map(), distributions: new Map(),
    tombstones: new Map(), historyCheckpoint: null, heads: new Map(), pending: new Map(),
    auditCheckpoints: new Map(), auditEvents: new Map(), overrides: new Map(),
    overrideHead: null, observations: new Map(), acknowledgementTransitions: new Map(),
  };
}

function customerTransactionMethods(state) {
  const eventMap = (namespace) => {
    if (!state.auditEvents.has(namespace)) state.auditEvents.set(namespace, new Map());
    return state.auditEvents.get(namespace);
  };
  return {
    readCurrentCatalog: () => clone(state.current),
    compareAndSetCurrentCatalog: (expected, value) => {
      if ((state.current?.distributionSequence || 0) !== expected) return false;
      state.current = clone(value); return true;
    },
    readActiveCatalog: () => clone(state.active),
    compareAndSetActiveCatalog: (expected, value) => {
      if ((state.active?.distributionSequence || 0) !== expected) return false;
      state.active = clone(value); return true;
    },
    readGlobalCatalogArtifact: (id) => clone(state.globals.get(id)?.artifact),
    listGlobalCatalogArtifacts: () => [...state.globals].map(([globalReleaseId, row]) => ({
      globalReleaseId,
      globalVersion: row.version,
      globalArtifactDigest: row.digest,
      artifact: clone(row.artifact),
    })),
    insertGlobalCatalogArtifact: (id, version, digestValue, artifact) => {
      if (state.globals.has(id)) return false;
      state.globals.set(id, { version, digest: digestValue, artifact: clone(artifact) }); return true;
    },
    deleteGlobalCatalogArtifact: (id, digestValue) => {
      const row = state.globals.get(id);
      if (!row || row.digest !== digestValue) return false;
      state.globals.delete(id); return true;
    },
    readCatalogDistribution: (sequence) => clone(state.distributions.get(sequence)?.value),
    insertCatalogDistribution: (sequence, digestValue, value) => {
      if (state.distributions.has(sequence)) return false;
      state.distributions.set(sequence, { digest: digestValue, value: clone(value) }); return true;
    },
    listCatalogDistributions: () => [...state.distributions].map(([sequence, row]) => ({
      distributionSequence: sequence, distributionDigest: row.digest, value: clone(row.value),
    })),
    deleteCatalogDistribution: (sequence, digestValue) => {
      const row = state.distributions.get(sequence);
      if (!row || row.digest !== digestValue) return false;
      state.distributions.delete(sequence); return true;
    },
    writeCatalogTombstone: (sequence, digestValue, wrapped) => {
      if (state.tombstones.has(sequence)) return false;
      state.tombstones.set(sequence, { digest: digestValue, wrapped: clone(wrapped) }); return true;
    },
    deleteCatalogTombstone: (sequence, digestValue, wrappedDigest) => {
      const row = state.tombstones.get(sequence);
      if (!row || row.digest !== digestValue || digest(row.wrapped) !== wrappedDigest) return false;
      state.tombstones.delete(sequence); return true;
    },
    listCatalogTombstones: () => [...state.tombstones.values()].map((row) => clone(row.wrapped)),
    readCatalogHistoryCheckpoint: () => clone(state.historyCheckpoint),
    compareAndSetCatalogHistoryCheckpoint: (expected, wrapped) => {
      if ((state.historyCheckpoint?.payload?.throughSequence || 0) !== expected) return false;
      state.historyCheckpoint = clone(wrapped); return true;
    },
    readCatalogIntegrityHead: (namespace) => clone(state.heads.get(namespace)),
    compareAndSetCatalogIntegrityHead: (namespace, expected, wrapped) => {
      if ((state.heads.get(namespace)?.payload?.revision || 0) !== expected) return false;
      state.heads.set(namespace, clone(wrapped)); return true;
    },
    readCatalogPendingWitness: (namespace) => clone(state.pending.get(namespace)),
    writeCatalogPendingWitness: (namespace, expected, wrapped) => {
      if (state.pending.has(namespace) || (state.current?.distributionSequence || 0) !== expected) {
        return false;
      }
      state.pending.set(namespace, clone(wrapped)); return true;
    },
    clearCatalogPendingWitness: (namespace, digestValue) => {
      const wrapped = state.pending.get(namespace);
      if (!wrapped || digest(wrapped) !== digestValue) return false;
      state.pending.delete(namespace); return true;
    },
    readCatalogAuditCheckpoint: (namespace) => clone(state.auditCheckpoints.get(namespace)),
    compareAndSetCatalogAuditCheckpoint: (namespace, expected, wrapped) => {
      if ((state.auditCheckpoints.get(namespace)?.payload?.sequence || 0) !== expected) return false;
      state.auditCheckpoints.set(namespace, clone(wrapped)); return true;
    },
    listCatalogAuditEvents: (namespace) => [...eventMap(namespace)]
      .sort(([left], [right]) => left - right).map(([, wrapped]) => clone(wrapped)),
    appendCatalogAuditEvent: (namespace, sequence, digestValue, wrapped) => {
      const events = eventMap(namespace);
      if (events.has(sequence) || wrapped.payload.eventDigest !== digestValue) return false;
      events.set(sequence, clone(wrapped)); return true;
    },
    deleteCatalogAuditEvent: (namespace, sequence, digestValue) => {
      const events = eventMap(namespace); const wrapped = events.get(sequence);
      if (!wrapped || digest(wrapped) !== digestValue) return false;
      events.delete(sequence); return true;
    },
    readTenantOverride: (id) => clone(state.overrides.get(id)),
    compareAndSetTenantOverride: (id, expected, wrapped) => {
      if ((state.overrides.get(id)?.payload?.revision || 0) !== expected) return false;
      state.overrides.set(id, clone(wrapped)); return true;
    },
    listTenantOverrides: (limit) => [...state.overrides]
      .sort(([left], [right]) => left.localeCompare(right)).slice(0, limit)
      .map(([, wrapped]) => clone(wrapped)),
    readTenantOverrideHead: () => clone(state.overrideHead),
    compareAndSetTenantOverrideHead: (expected, wrapped) => {
      if ((state.overrideHead?.payload?.revision || 0) !== expected) return false;
      state.overrideHead = clone(wrapped); return true;
    },
    readLocalObservation: (domain) => clone(state.observations.get(domain)),
    writeLocalObservation: (value) => state.observations.set(value.registrableDomain, clone(value)),
    listLocalObservations: () => [...state.observations.values()].map(clone),
    readCatalogAcknowledgementTransition: (key) => clone(
      state.acknowledgementTransitions.get(key)?.row,
    ),
    listCatalogAcknowledgementTransitions: () => [...state.acknowledgementTransitions]
      .map(([transitionKey, value]) => ({
        transitionKey,
        acknowledgementDigest: value.digest,
        row: clone(value.row),
      })),
    insertCatalogAcknowledgementTransition: (key, digestValue, row) => {
      if (state.acknowledgementTransitions.has(key)) return false;
      state.acknowledgementTransitions.set(key, { digest: digestValue, row: clone(row) });
      return true;
    },
  };
}

module.exports = Object.freeze({
  assertCustomerShadowAiStorageScope,
  assertProductionCustomerShadowAiStorage,
  openCustomerShadowAiSqliteStorage,
  openShadowAiAnchorSqliteStorage,
});
