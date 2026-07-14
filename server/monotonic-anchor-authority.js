'use strict';

const crypto = require('node:crypto');

const ZERO_DIGEST = '0'.repeat(64);
const SHA256_RE = /^[a-f0-9]{64}$/;
const KEY_ID_RE = /^rw-anchor-[a-z0-9][a-z0-9_.-]{0,87}$/;
const PURPOSE_RE = /^[a-z][a-z0-9_]{0,63}$/;
const NAMESPACE_RE = /^[a-z0-9][a-z0-9_.:-]{0,159}$/;
const STORAGE_CONTEXT_RE = /^[a-z0-9][a-z0-9_.:/-]{0,191}$/;
const MAX_PENDING = 50_000;
const MAX_ANCESTRY_PROOF = 64;
const MAX_ABORTED_TRANSITIONS = 1_024;
const MAX_REFERENCE_WITNESS_NAMESPACES = 64;
const STATE_VERSION = 3;
const MIGRATION_ELIGIBLE_STATE_VERSIONS = Object.freeze([2]);
const UNSUPPORTED_STATE_VERSIONS = Object.freeze([1]);
const ANCHOR_STATE_MIGRATION_STATUS = Object.freeze({
  currentSchemaVersion: STATE_VERSION,
  migrationEligibleSchemaVersions: MIGRATION_ELIGIBLE_STATE_VERSIONS,
  unsupportedSchemaVersions: UNSUPPORTED_STATE_VERSIONS,
  policy: 'authenticated_v2_explicit_migration_or_reset_required',
});
const INDEPENDENT_WITNESS_ASSURANCE = 'independent_nonrewindable';
const TEST_WITNESS_ASSURANCE = 'test_reference';
const PRIVATE_RESULT = Symbol('monotonic-anchor-result');
const PRODUCTION_ANCHOR_AUTHORITIES = new WeakSet();
const REFERENCE_STORAGE_CAPABILITIES = new WeakMap();
const REFERENCE_COMMIT_RECEIPTS = new WeakMap();
const REFERENCE_OPTION_KEYS = new Set([
  'keyId', 'purpose', 'secret', 'storage', 'storageContext', 'storageIdentity',
]);
const STORAGE_METADATA_KEYS = [
  'anchorStorageContext', 'anchorStorageIdentity', 'assurance', 'kind',
  'schemaVersion', 'stateKind',
];
const REFERENCE_ENVIRONMENTS = new Set(['development', 'test']);

function createReferenceMonotonicAnchorAuthority(options = {}) {
  assertReferenceEnvironment();
  validateReferenceOptions(options);
  const storage = options.storage;
  const capability = REFERENCE_STORAGE_CAPABILITIES.get(storage);
  const metadata = captureStorageMetadata(storage);
  const binding = createReferenceBinding(options, metadata);
  const context = {
    binding,
    capability,
    identity: sha256(options.secret),
    keyId: options.keyId,
    metadata,
    secret: Buffer.from(options.secret),
    storage,
  };
  return createAuthority(context);
}

function createReferenceMonotonicAnchorStorage(options) {
  assertReferenceEnvironment();
  if (options !== undefined) throw anchorError('anchor_reference_storage_options_invalid');
  const state = {
    acceptedWitnesses: new Map(), active: false, rows: new Map(), version: 0,
  };
  const controls = {
    decorateReceipt: false,
    failCommit: false,
    loseResponse: false,
    nextCompareSubstitution: null,
    nextPostCommitMutation: null,
  };
  let capability;
  const storage = createReferenceStorageHandle(state, controls);
  capability = Object.freeze({
    transaction: referenceEnvironmentOperation((callback) => referenceTransaction(
      state, controls, capability, callback,
    )),
    verifyReceipt: referenceEnvironmentOperation(
      (receipt, token, expectedWrites) => verifyReferenceReceipt(
        state, capability, receipt, token, expectedWrites,
      ),
    ),
  });
  REFERENCE_STORAGE_CAPABILITIES.set(storage, capability);
  return storage;
}

function createProductionMonotonicAnchorAuthority() {
  // This module has no production adapter capable of minting the private brand.
  throw anchorError('production_anchor_adapter_unavailable');
}

function assertProductionMonotonicAnchorAuthority(value) {
  if (!value || !PRODUCTION_ANCHOR_AUTHORITIES.has(value)) {
    throw anchorError('production_anchor_required');
  }
  return value;
}

function createAuthority(context) {
  const invoke = (work) => run(context, work);
  return Object.freeze({
    describe: () => {
      assertReferenceEnvironment();
      return Object.freeze({
        assurance: context.binding.assurance,
        keyId: context.keyId,
        purpose: context.binding.purpose,
        identity: context.identity,
      });
    },
    read: (namespace) => invoke((tx) => readState(tx, namespace, context)),
    prepare: (request) => invoke((tx, writes) => prepare(tx, request, context, writes)),
    finalize: (request) => invoke((tx, writes) => finalize(tx, request, context, writes)),
    abort: (request) => invoke((tx, writes) => abort(tx, request, context, writes)),
    list: (limit = MAX_PENDING) => invoke((tx) => listStates(tx, limit, context)),
    listPending: (limit = MAX_PENDING) => invoke(
      (tx) => listStates(tx, limit, context).filter((state) => state.pending),
    ),
  });
}

function validateReferenceOptions(options) {
  if (!plainRecord(options)
      || Reflect.ownKeys(options).some((key) => typeof key !== 'string'
        || !REFERENCE_OPTION_KEYS.has(key)
        || !Object.prototype.hasOwnProperty.call(
          Object.getOwnPropertyDescriptor(options, key) || {}, 'value',
        ))) throw anchorError('anchor_authority_invalid');
  if (!options.storage || !REFERENCE_STORAGE_CAPABILITIES.has(options.storage)
      || !KEY_ID_RE.test(String(options.keyId || ''))
      || !PURPOSE_RE.test(String(options.purpose || ''))
      || !Buffer.isBuffer(options.secret) || options.secret.length !== 32) {
    throw anchorError('anchor_authority_invalid');
  }
}

function assertReferenceEnvironment() {
  if (!REFERENCE_ENVIRONMENTS.has(process.env.NODE_ENV)) {
    throw anchorError('reference_anchor_forbidden_in_production');
  }
}

function referenceEnvironmentOperation(callback) {
  return (...args) => {
    assertReferenceEnvironment();
    return callback(...args);
  };
}

function createReferenceStorageHandle(state, controls) {
  const handle = {
    assurance: TEST_WITNESS_ASSURANCE,
    kind: 'memory_reference',
    schemaVersion: 1,
    stateKind: 'monotonic_anchor_reference',
    snapshot: () => cloneStoredMap(state.rows),
    readRaw: (namespace) => cloneStoredValue(state.rows.get(namespace)),
    restore: (snapshot) => mutateReferenceRows(state, () => checkedStoredMap(snapshot)),
    delete: (namespace) => mutateReferenceRows(state, (rows) => {
      validateNamespace(namespace);
      rows.delete(namespace);
      return rows;
    }),
    replace: (namespace, wrapped) => mutateReferenceRows(state, (rows) => {
      validateNamespace(namespace);
      rows.set(namespace, cloneStoredValue(wrapped));
      return rows;
    }),
    tamper: (callback) => tamperReferenceRows(state, callback),
    failNextCommit: () => scheduleReferenceControl(state, () => {
      controls.failCommit = true;
    }),
    loseNextResponse: () => scheduleReferenceControl(state, () => {
      controls.loseResponse = true;
    }),
    decorateNextReceiptValue: () => scheduleReferenceControl(state, () => {
      controls.decorateReceipt = true;
    }),
    deleteAfterNextCommit: (namespace) => scheduleReferenceControl(state, () => {
      validateNamespace(namespace);
      controls.nextPostCommitMutation = { kind: 'delete', namespace };
    }),
    restoreAfterNextCommit: (snapshot) => scheduleReferenceControl(state, () => {
      controls.nextPostCommitMutation = {
        kind: 'restore', snapshot: checkedStoredMap(snapshot),
      };
    }),
    substituteBeforeNextCompare: (namespace, wrapped) => scheduleReferenceControl(
      state, () => {
        validateNamespace(namespace);
        controls.nextCompareSubstitution = {
          namespace, wrapped: cloneStoredValue(wrapped),
        };
      },
    ),
  };
  return Object.freeze(Object.fromEntries(Object.entries(handle).map(([key, value]) => [
    key, typeof value === 'function' ? referenceEnvironmentOperation(value) : value,
  ])));
}

function mutateReferenceRows(state, mutation) {
  assertReferenceStorageIdle(state);
  const rows = mutation(cloneStoredMap(state.rows));
  state.rows = checkedStoredMap(rows);
  state.version += 1;
}

function tamperReferenceRows(state, callback) {
  if (typeof callback !== 'function') throw anchorError('anchor_reference_storage_invalid');
  assertReferenceStorageIdle(state);
  const rows = cloneStoredMap(state.rows);
  const result = callback(rows);
  if (result && typeof result.then === 'function') {
    throw anchorError('anchor_reference_storage_invalid');
  }
  state.rows = cloneStoredMap(rows);
  state.version += 1;
}

function scheduleReferenceControl(state, schedule) {
  assertReferenceStorageIdle(state);
  schedule();
}

function assertReferenceStorageIdle(state) {
  if (state.active) throw anchorError('anchor_reference_storage_busy');
}

function checkedStoredMap(value) {
  if (!(value instanceof Map)) throw anchorError('anchor_reference_storage_invalid');
  return cloneStoredMap(value);
}

function referenceTransaction(state, controls, capability, callback) {
  if (state.active || typeof callback !== 'function') {
    throw anchorError('anchor_reference_storage_invalid');
  }
  assertReferenceWitnesses(state);
  state.active = true;
  const baseVersion = state.version;
  const working = cloneStoredMap(state.rows);
  const writes = new Map();
  try {
    const callbackResult = callback(referenceTransactionMethods(
      working, writes, controls,
    ));
    if (callbackResult && typeof callbackResult.then === 'function') {
      throw anchorError('anchor_reference_storage_invalid');
    }
    if (controls.failCommit) {
      controls.failCommit = false;
      throw anchorError('anchor_reference_commit_failed');
    }
    if (baseVersion !== state.version) throw anchorError('anchor_reference_conflict');
    const witnessUpdates = createReferenceWitnessUpdates(state, writes);
    state.rows = cloneStoredMap(working);
    state.version += 1;
    const receipt = createReferenceReceipt(controls);
    const record = {
      callbackResult,
      capability,
      commitVersion: state.version,
      writes: cloneStoredMap(writes),
      witnessUpdates,
    };
    REFERENCE_COMMIT_RECEIPTS.set(receipt, record);
    applyPostCommitMutation(state, controls);
    if (controls.loseResponse) {
      controls.loseResponse = false;
      REFERENCE_COMMIT_RECEIPTS.delete(receipt);
      verifyLostResponseCommit(state, record);
      throw anchorError('anchor_reference_response_lost');
    }
    return receipt;
  } finally {
    state.active = false;
  }
}

function referenceTransactionMethods(working, writes, controls) {
  return Object.freeze({
    readAnchor: (namespace) => cloneStoredValue(working.get(namespace)),
    compareAndSetAnchor: (namespace, expectedWrapped, wrapped) => {
      applyCompareSubstitution(working, controls, namespace);
      const current = working.has(namespace) ? working.get(namespace) : null;
      if (!sameStoredValue(current, expectedWrapped)) return false;
      const next = cloneStoredValue(wrapped);
      working.set(namespace, next);
      writes.set(namespace, cloneStoredValue(next));
      return true;
    },
    listAnchors: (limit) => [...working]
      .sort(([left], [right]) => left.localeCompare(right)).slice(0, limit)
      .map(([namespace, wrapped]) => ({
        namespace, wrapped: cloneStoredValue(wrapped),
      })),
  });
}

function applyCompareSubstitution(working, controls, namespace) {
  const substitution = controls.nextCompareSubstitution;
  if (!substitution || substitution.namespace !== namespace) return;
  controls.nextCompareSubstitution = null;
  working.set(namespace, cloneStoredValue(substitution.wrapped));
}

function createReferenceReceipt(controls) {
  const value = controls.decorateReceipt
    ? { value: { generation: 999, schemaVersion: 999 } } : {};
  controls.decorateReceipt = false;
  return Object.freeze(value);
}

function applyPostCommitMutation(state, controls) {
  const mutation = controls.nextPostCommitMutation;
  if (!mutation) return;
  controls.nextPostCommitMutation = null;
  if (mutation.kind === 'delete') state.rows.delete(mutation.namespace);
  else state.rows = cloneStoredMap(mutation.snapshot);
  state.version += 1;
}

function verifyReferenceReceipt(state, capability, receipt, token, expectedWrites) {
  const record = receipt && REFERENCE_COMMIT_RECEIPTS.get(receipt);
  if (receipt) REFERENCE_COMMIT_RECEIPTS.delete(receipt);
  if (!record || record.capability !== capability
      || record.callbackResult?.[PRIVATE_RESULT] !== token
      || !sameStoredMap(record.writes, expectedWrites)) {
    throw anchorError('anchor_storage_invalid');
  }
  verifyAndAcceptReferenceCommit(state, record, expectedWrites);
}

function verifyLostResponseCommit(state, record) {
  const token = record.callbackResult?.[PRIVATE_RESULT];
  if (!token || typeof token !== 'object' || !Object.isFrozen(token)) {
    throw anchorError('anchor_storage_invalid');
  }
  verifyAndAcceptReferenceCommit(state, record, record.writes);
}

function verifyAndAcceptReferenceCommit(state, record, expectedWrites) {
  if (state.version !== record.commitVersion) {
    throw anchorError('anchor_postcommit_verification_failed');
  }
  for (const [namespace, wrapped] of expectedWrites) {
    if (!state.rows.has(namespace)
        || !sameStoredValue(state.rows.get(namespace), wrapped)) {
      throw anchorError('anchor_postcommit_verification_failed');
    }
  }
  assertReferenceWitnesses(state, expectedWrites);
  for (const [namespace, witness] of record.witnessUpdates) {
    state.acceptedWitnesses.set(namespace, witness);
  }
  assertReferenceWitnesses(state);
}

function createReferenceWitnessUpdates(state, writes) {
  if (!(writes instanceof Map)) throw anchorError('anchor_storage_invalid');
  const additions = [...writes.keys()].filter(
    (namespace) => !state.acceptedWitnesses.has(namespace),
  ).length;
  if (state.acceptedWitnesses.size + additions > MAX_REFERENCE_WITNESS_NAMESPACES) {
    throw anchorError('anchor_reference_witness_capacity');
  }
  return new Map([...writes].map(([namespace, wrapped]) => [
    namespace, createReferenceWitness(namespace, wrapped),
  ]));
}

function createReferenceWitness(namespace, wrapped) {
  const material = referenceWitnessMaterial(namespace, wrapped);
  return Object.freeze({
    canonicalEnvelope: material.canonicalEnvelope,
    envelopeDigest: sha256(Buffer.from(material.canonicalEnvelope, 'utf8')),
    generation: material.generation,
    headDigest: material.headDigest,
    lineageDigest: material.lineageDigest,
    revision: material.revision,
  });
}

function assertReferenceWitnesses(state, pendingWrites = null) {
  for (const namespace of state.rows.keys()) {
    if (!state.acceptedWitnesses.has(namespace) && !pendingWrites?.has(namespace)) {
      throw anchorError('anchor_reference_witness_rewind');
    }
  }
  for (const [namespace, witness] of state.acceptedWitnesses) {
    if (pendingWrites?.has(namespace)) continue;
    const current = state.rows.get(namespace);
    if (current === undefined || !matchesReferenceWitness(namespace, current, witness)) {
      throw anchorError('anchor_reference_witness_rewind');
    }
  }
}

function matchesReferenceWitness(namespace, wrapped, witness) {
  try {
    const material = referenceWitnessMaterial(namespace, wrapped);
    return material.canonicalEnvelope === witness.canonicalEnvelope
      && sha256(Buffer.from(material.canonicalEnvelope, 'utf8')) === witness.envelopeDigest
      && material.generation === witness.generation
      && material.revision === witness.revision
      && material.headDigest === witness.headDigest
      && material.lineageDigest === witness.lineageDigest;
  } catch {
    return false;
  }
}

function referenceWitnessMaterial(namespace, wrapped) {
  validateNamespace(namespace);
  const canonicalEnvelope = safeCanonicalDataJson(wrapped);
  if (canonicalEnvelope === null || !plainRecord(wrapped)) {
    throw anchorError('anchor_storage_invalid');
  }
  const payload = checkedCanonicalDescriptor(wrapped, 'payload', true).value;
  if (!plainRecord(payload)) throw anchorError('anchor_storage_invalid');
  const field = (key) => checkedCanonicalDescriptor(payload, key, true).value;
  const material = {
    canonicalEnvelope,
    generation: field('generation'),
    headDigest: field('headDigest'),
    lineageDigest: field('lineageDigest'),
    revision: field('revision'),
  };
  if (field('namespace') !== namespace
      || !nonNegativeSafeInteger(material.generation)
      || !nonNegativeSafeInteger(material.revision)
      || !SHA256_RE.test(String(material.headDigest || ''))
      || !SHA256_RE.test(String(material.lineageDigest || ''))) {
    throw anchorError('anchor_storage_invalid');
  }
  return material;
}

function sameStoredMap(left, right) {
  if (!(left instanceof Map) || !(right instanceof Map) || left.size !== right.size) return false;
  for (const [key, value] of left) {
    if (!right.has(key) || !sameStoredValue(value, right.get(key))) return false;
  }
  return true;
}

function sameStoredValue(left, right) {
  if (left === null || left === undefined || right === null || right === undefined) {
    return left === right;
  }
  const leftCanonical = safeCanonicalDataJson(left);
  return leftCanonical !== null && leftCanonical === safeCanonicalDataJson(right);
}

function createReferenceBinding(options, metadata) {
  if (metadata.assurance.present && metadata.assurance.value !== TEST_WITNESS_ASSURANCE) {
    throw anchorError('anchor_authority_invalid');
  }
  const storageContext = selectBoundValue(options.storageContext,
    metadata.anchorStorageContext, defaultStorageContext(options, metadata),
    STORAGE_CONTEXT_RE);
  const defaultIdentity = referenceStorageIdentity(options, metadata, storageContext);
  const storageIdentity = selectBoundValue(options.storageIdentity,
    metadata.anchorStorageIdentity, defaultIdentity, SHA256_RE);
  return Object.freeze({
    assurance: TEST_WITNESS_ASSURANCE,
    keyId: options.keyId,
    purpose: options.purpose,
    storageContext,
    storageIdentity,
  });
}

function selectBoundValue(supplied, advertised, fallback, pattern) {
  if (advertised.present && supplied !== undefined && supplied !== advertised.value) {
    throw anchorError('anchor_authority_invalid');
  }
  const selected = supplied === undefined
    ? (advertised.present ? advertised.value : fallback) : supplied;
  if (typeof selected !== 'string' || !pattern.test(selected)) {
    throw anchorError('anchor_authority_invalid');
  }
  return selected;
}

function defaultStorageContext(options, metadata) {
  const part = metadata.stateKind.present ? metadata.stateKind.value : options.purpose;
  const candidate = `reference:${String(part || '')}`;
  if (!STORAGE_CONTEXT_RE.test(candidate)) throw anchorError('anchor_authority_invalid');
  return candidate;
}

function referenceStorageIdentity(options, metadata, storageContext) {
  const descriptor = {
    keyId: options.keyId,
    purpose: options.purpose,
    storageContext,
    kind: metadata.kind.present ? metadata.kind.value : null,
    schemaVersion: metadata.schemaVersion.present ? metadata.schemaVersion.value : null,
    stateKind: metadata.stateKind.present ? metadata.stateKind.value : null,
  };
  return sha256(Buffer.from(`redactwall.reference-anchor-storage.v1\0${canonicalJson(descriptor)}`));
}

function captureStorageMetadata(storage) {
  return Object.freeze(Object.fromEntries(STORAGE_METADATA_KEYS.map((key) => [
    key, Object.freeze(readDataProperty(storage, key)),
  ])));
}

function readDataProperty(object, key) {
  let cursor = object;
  while (cursor !== null) {
    const descriptor = Object.getOwnPropertyDescriptor(cursor, key);
    if (descriptor) {
      if (!Object.prototype.hasOwnProperty.call(descriptor, 'value')) {
        throw anchorError('anchor_storage_invalid');
      }
      return { present: true, value: checkedMetadataValue(key, descriptor.value) };
    }
    cursor = Object.getPrototypeOf(cursor);
  }
  return { present: false, value: null };
}

function checkedMetadataValue(key, value) {
  if (key === 'schemaVersion') {
    if (!nonNegativeSafeInteger(value)) throw anchorError('anchor_storage_invalid');
    return value;
  }
  if (typeof value !== 'string' || value.length < 1 || value.length > 256) {
    throw anchorError('anchor_storage_invalid');
  }
  return value;
}

function checkedStorageMethod(storage, key) {
  const descriptor = readMethodProperty(storage, key);
  if (!descriptor || typeof descriptor.value !== 'function') {
    throw anchorError('anchor_storage_invalid');
  }
  return descriptor.value;
}

function readMethodProperty(object, key) {
  let cursor = object;
  while (cursor !== null) {
    const descriptor = Object.getOwnPropertyDescriptor(cursor, key);
    if (descriptor) {
      if (!Object.prototype.hasOwnProperty.call(descriptor, 'value')) {
        throw anchorError('anchor_storage_invalid');
      }
      return descriptor;
    }
    cursor = Object.getPrototypeOf(cursor);
  }
  return null;
}

function assertStorageIdentity(context) {
  if (REFERENCE_STORAGE_CAPABILITIES.get(context.storage) !== context.capability
      || canonicalJson(captureStorageMetadata(context.storage))
        !== canonicalJson(context.metadata)) {
    throw anchorError('anchor_storage_identity_changed');
  }
}

function run(context, work) {
  assertReferenceEnvironment();
  assertStorageIdentity(context);
  let calls = 0;
  let result;
  const token = Object.freeze({});
  const writes = new Map();
  const returned = context.capability.transaction((tx) => {
    calls += 1;
    if (calls !== 1) throw anchorError('anchor_storage_invalid');
    const checked = requireTransaction(tx);
    result = work(checked, writes);
    if (result && typeof result.then === 'function') throw anchorError('anchor_storage_invalid');
    assertStorageIdentity(context);
    return { [PRIVATE_RESULT]: token };
  });
  if (returned && typeof returned.then === 'function') throw anchorError('anchor_storage_invalid');
  if (calls !== 1) throw anchorError('anchor_storage_invalid');
  assertStorageIdentity(context);
  context.capability.verifyReceipt(returned, token, writes);
  return clone(result);
}

function requireTransaction(tx) {
  const methods = ['compareAndSetAnchor', 'listAnchors', 'readAnchor'];
  if (!tx || (typeof tx !== 'object' && typeof tx !== 'function')) {
    throw anchorError('anchor_storage_invalid');
  }
  const captured = Object.fromEntries(methods.map((method) => [
    method, checkedStorageMethod(tx, method),
  ]));
  return Object.freeze(Object.fromEntries(methods.map((method) => [
    method, (...args) => Reflect.apply(captured[method], tx, args),
  ])));
}

function initialState(namespace, binding) {
  return {
    schemaVersion: STATE_VERSION,
    binding: clone(binding),
    namespace,
    generation: 0,
    revision: 0,
    headDigest: ZERO_DIGEST,
    lineageDigest: initialLineageDigest(binding, namespace),
    ancestry: [],
    abortedTransitionDigests: [],
    pending: null,
    lastResolution: null,
  };
}

function readState(tx, namespace, context) {
  return loadState(tx, namespace, context).state;
}

function loadState(tx, namespace, context) {
  validateNamespace(namespace);
  const wrapped = tx.readAnchor(namespace);
  if (wrapped === null || wrapped === undefined) {
    assertStoreBinding(tx, namespace, context);
    const state = initialState(namespace, context.binding);
    return { expectedWrapped: null, state };
  }
  const state = open(wrapped, namespace, context);
  return { expectedWrapped: clone(wrapped), state };
}

function assertStoreBinding(tx, missingNamespace, context) {
  const rows = checkedAnchorRows(tx.listAnchors(MAX_PENDING + 1), MAX_PENDING);
  for (const row of rows) {
    if (row.namespace === missingNamespace) throw anchorError('anchor_storage_invalid');
    open(row.wrapped, row.namespace, context);
  }
}

function prepare(tx, request, context, writes) {
  const value = validateTransitionRequest(request);
  const loaded = loadState(tx, value.namespace, context);
  const current = loaded.state;
  const pending = pendingFrom(value);
  if (current.pending) {
    if (sameTransition(current.pending, pending)) return current;
    throw anchorError('anchor_pending_conflict');
  }
  const attemptDigest = transitionDigest(pending);
  if (current.abortedTransitionDigests.includes(attemptDigest)) {
    throw anchorError('anchor_transition_reused');
  }
  if (current.abortedTransitionDigests.length >= MAX_ABORTED_TRANSITIONS) {
    throw anchorError('anchor_attempt_limit');
  }
  if (!sameCommitted(current, value.expectedRevision, value.expectedDigest)) {
    throw anchorError('anchor_revision_conflict');
  }
  const next = { ...current, generation: current.generation + 1, pending };
  publish(tx, loaded.expectedWrapped, next, context, writes);
  return next;
}

function finalize(tx, request, context, writes) {
  const value = validateTransitionRequest(request);
  const loaded = loadState(tx, value.namespace, context);
  const current = loaded.state;
  const pending = pendingFrom(value);
  if (!current.pending) return exactResolvedRetry(current, pending, 'finalized',
    'anchor_finalize_conflict');
  if (!sameTransition(current.pending, pending)
      || !sameCommitted(current, value.expectedRevision, value.expectedDigest)) {
    throw anchorError('anchor_finalize_conflict');
  }
  const generation = current.generation + 1;
  const lineage = appendLineage(current, pending);
  const next = {
    ...current,
    generation,
    revision: value.targetRevision,
    headDigest: value.targetDigest,
    lineageDigest: lineage.lineageDigest,
    ancestry: lineage.ancestry,
    abortedTransitionDigests: [],
    pending: null,
    lastResolution: resolution('finalized', generation, pending),
  };
  publish(tx, loaded.expectedWrapped, next, context, writes);
  return next;
}

function abort(tx, request, context, writes) {
  const value = validateTransitionRequest(request);
  const loaded = loadState(tx, value.namespace, context);
  const current = loaded.state;
  const pending = pendingFrom(value);
  if (!current.pending) return exactResolvedRetry(current, pending, 'aborted',
    'anchor_abort_conflict');
  if (!sameTransition(current.pending, pending)
      || !sameCommitted(current, value.expectedRevision, value.expectedDigest)) {
    throw anchorError('anchor_abort_conflict');
  }
  const generation = current.generation + 1;
  const abortedTransitionDigests = [
    ...current.abortedTransitionDigests, transitionDigest(pending),
  ];
  const next = {
    ...current,
    generation,
    abortedTransitionDigests,
    pending: null,
    lastResolution: resolution('aborted', generation, pending),
  };
  publish(tx, loaded.expectedWrapped, next, context, writes);
  return next;
}

function exactResolvedRetry(current, transition, outcome, code) {
  const last = current.lastResolution;
  if (!last || last.outcome !== outcome || last.resolvedGeneration !== current.generation
      || !sameTransition(last.transition, transition)) throw anchorError(code);
  const expected = outcome === 'finalized'
    ? [transition.targetRevision, transition.targetDigest]
    : [transition.expectedRevision, transition.expectedDigest];
  if (!sameCommitted(current, ...expected)) throw anchorError(code);
  return current;
}

function resolution(outcome, resolvedGeneration, transition) {
  return { outcome, resolvedGeneration, transition: clone(transition) };
}

function transitionDigest(transition) {
  return sha256(Buffer.from(
    `redactwall.monotonic-anchor-transition.v1\0${canonicalJson(transition)}`,
  ));
}

function initialLineageDigest(binding, namespace) {
  return lineageDigest('initial.v1', {
    binding: clone(binding),
    headDigest: ZERO_DIGEST,
    namespace,
    revision: 0,
  });
}

function appendLineage(current, transition) {
  const core = {
    headDigest: transition.targetDigest,
    parentLineageDigest: current.lineageDigest,
    revision: transition.targetRevision,
    transitionDigest: transitionDigest(transition),
  };
  const entry = {
    ...core,
    lineageDigest: committedLineageDigest(
      current.binding, current.namespace, core,
    ),
  };
  return {
    ancestry: [...current.ancestry, entry].slice(-MAX_ANCESTRY_PROOF),
    lineageDigest: entry.lineageDigest,
  };
}

function committedLineageDigest(binding, namespace, core) {
  return lineageDigest('entry.v1', {
    binding: clone(binding),
    namespace,
    ...core,
  });
}

function lineageDigest(domain, value) {
  return sha256(Buffer.from(
    `redactwall.monotonic-anchor-lineage.${domain}\0${canonicalJson(value)}`,
  ));
}

function listStates(tx, limit, context) {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_PENDING) {
    throw anchorError('anchor_limit_invalid');
  }
  const rows = checkedAnchorRows(tx.listAnchors(limit + 1), limit);
  return rows.map((row) => open(row.wrapped, row.namespace, context));
}

function checkedAnchorRows(rows, limit) {
  if (!Array.isArray(rows) || rows.length > limit) throw anchorError('anchor_storage_invalid');
  const seen = new Set();
  for (const row of rows) {
    if (!plainRecord(row) || !exactKeys(row, ['namespace', 'wrapped'])
        || seen.has(row.namespace)) throw anchorError('anchor_storage_invalid');
    validateNamespace(row.namespace);
    seen.add(row.namespace);
  }
  return rows;
}

function publish(tx, expectedWrapped, next, context, writes) {
  const wrapped = seal(next, context);
  if (tx.compareAndSetAnchor(next.namespace, expectedWrapped, wrapped) !== true) {
    throw anchorError('anchor_cas_conflict');
  }
  const readback = tx.readAnchor(next.namespace);
  if (readback === null || readback === undefined) throw anchorError('anchor_readback_failed');
  const opened = open(readback, next.namespace, context);
  if (canonicalJson(opened) !== canonicalJson(next)) throw anchorError('anchor_readback_failed');
  writes.set(next.namespace, clone(wrapped));
}

function pendingFrom(value) {
  return {
    expectedRevision: value.expectedRevision,
    expectedDigest: value.expectedDigest,
    targetRevision: value.targetRevision,
    targetDigest: value.targetDigest,
    witnessDigest: value.witnessDigest,
  };
}

function validateTransitionRequest(value) {
  const keys = [
    'expectedDigest', 'expectedRevision', 'namespace', 'targetDigest',
    'targetRevision', 'witnessDigest',
  ];
  if (!plainRecord(value) || !exactKeys(value, keys)) throw anchorError('anchor_request_invalid');
  validateNamespace(value.namespace);
  if (!validTransition(value)) throw anchorError('anchor_request_invalid');
  return clone(value);
}

function validTransition(value) {
  return nonNegativeSafeInteger(value.expectedRevision)
    && value.targetRevision === value.expectedRevision + 1
    && SHA256_RE.test(String(value.expectedDigest || ''))
    && SHA256_RE.test(String(value.targetDigest || ''))
    && value.targetDigest !== value.expectedDigest
    && SHA256_RE.test(String(value.witnessDigest || ''));
}

function validateNamespace(value) {
  if (!NAMESPACE_RE.test(String(value || ''))) throw anchorError('anchor_namespace_invalid');
}

function seal(payload, context) {
  validateState(payload);
  assertExpectedBinding(payload.binding, context.binding);
  const snapshot = clone(payload);
  return {
    schemaVersion: STATE_VERSION,
    keyId: context.keyId,
    payload: snapshot,
    mac: stateMac(snapshot, context.keyId, context.secret),
  };
}

function open(wrapped, namespace, context) {
  const legacyVersion = legacyEnvelopeVersion(wrapped);
  if (legacyVersion !== null) {
    if (legacyVersion === 2
        && isAuthenticatedLegacyV2Envelope(wrapped, namespace, context)) {
      throw anchorError('anchor_state_migration_required');
    }
    throw anchorError('anchor_state_invalid');
  }
  if (!plainRecord(wrapped)
      || !exactKeys(wrapped, ['keyId', 'mac', 'payload', 'schemaVersion'])
      || wrapped.schemaVersion !== STATE_VERSION || wrapped.keyId !== context.keyId
      || !SHA256_RE.test(String(wrapped.mac || ''))) throw anchorError('anchor_state_invalid');
  validateState(wrapped.payload);
  const payload = clone(wrapped.payload);
  if (payload.namespace !== namespace) throw anchorError('anchor_state_invalid');
  const expected = Buffer.from(stateMac(payload, context.keyId, context.secret), 'hex');
  const supplied = Buffer.from(wrapped.mac, 'hex');
  if (supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) {
    throw anchorError('anchor_state_invalid');
  }
  assertExpectedBinding(payload.binding, context.binding);
  return payload;
}

function legacyEnvelopeVersion(value) {
  if (!plainRecord(value)
      || !exactKeys(value, ['keyId', 'mac', 'payload', 'schemaVersion'])) return null;
  const versions = [...MIGRATION_ELIGIBLE_STATE_VERSIONS, ...UNSUPPORTED_STATE_VERSIONS];
  return versions.includes(value.schemaVersion) ? value.schemaVersion : null;
}

function isAuthenticatedLegacyV2Envelope(wrapped, namespace, context) {
  try {
    if (wrapped.schemaVersion !== 2 || wrapped.keyId !== context.keyId
        || !SHA256_RE.test(String(wrapped.mac || ''))) return false;
    validateLegacyV2State(wrapped.payload);
    if (wrapped.payload.namespace !== namespace
        || canonicalJson(wrapped.payload.binding) !== canonicalJson(context.binding)) return false;
    const expected = Buffer.from(
      legacyV2StateMac(wrapped.payload, context.keyId, context.secret), 'hex',
    );
    const supplied = Buffer.from(wrapped.mac, 'hex');
    return supplied.length === expected.length && crypto.timingSafeEqual(supplied, expected);
  } catch {
    return false;
  }
}

function validateLegacyV2State(value) {
  const keys = [
    'binding', 'generation', 'headDigest', 'lastResolution', 'namespace',
    'pending', 'revision', 'schemaVersion',
  ];
  if (!plainRecord(value) || !exactKeys(value, keys) || value.schemaVersion !== 2
      || !NAMESPACE_RE.test(String(value.namespace || '')) || !validCommittedState(value)) {
    throw anchorError('anchor_state_invalid');
  }
  validateBinding(value.binding);
  if (value.pending !== null && !validStoredTransition(value.pending)) {
    throw anchorError('anchor_state_invalid');
  }
  if (value.pending && !sameCommitted(
    value, value.pending.expectedRevision, value.pending.expectedDigest,
  )) throw anchorError('anchor_state_invalid');
  validateLegacyV2ResolutionLifecycle(value);
}

function validateLegacyV2ResolutionLifecycle(value) {
  if (value.lastResolution === null) {
    const expectedGeneration = value.pending === null ? 0 : 1;
    if (value.generation !== expectedGeneration || value.revision !== 0
        || value.headDigest !== ZERO_DIGEST) throw anchorError('anchor_state_invalid');
    return;
  }
  const last = value.lastResolution;
  if (!plainRecord(last)
      || !exactKeys(last, ['outcome', 'resolvedGeneration', 'transition'])
      || !['aborted', 'finalized'].includes(last.outcome)
      || !nonNegativeSafeInteger(last.resolvedGeneration) || last.resolvedGeneration < 2
      || last.resolvedGeneration % 2 !== 0 || !validStoredTransition(last.transition)) {
    throw anchorError('anchor_state_invalid');
  }
  const expectedGeneration = last.resolvedGeneration + (value.pending === null ? 0 : 1);
  const committed = last.outcome === 'finalized'
    ? [last.transition.targetRevision, last.transition.targetDigest]
    : [last.transition.expectedRevision, last.transition.expectedDigest];
  if (value.generation !== expectedGeneration || !sameCommitted(value, ...committed)) {
    throw anchorError('anchor_state_invalid');
  }
}

function legacyV2StateMac(payload, keyId, secret) {
  const domain = `redactwall.monotonic-anchor.v2\0${keyId}\0${canonicalJson(payload.binding)}\0`;
  return crypto.createHmac('sha256', secret)
    .update(`${domain}${canonicalJson(payload)}`, 'utf8').digest('hex');
}

function stateMac(payload, keyId, secret) {
  const domain = `redactwall.monotonic-anchor.v3\0${keyId}\0${canonicalJson(payload.binding)}\0`;
  return crypto.createHmac('sha256', secret)
    .update(`${domain}${canonicalJson(payload)}`, 'utf8').digest('hex');
}

function assertExpectedBinding(actual, expected) {
  if (canonicalJson(actual) !== canonicalJson(expected)) {
    throw anchorError('anchor_state_binding_invalid');
  }
}

function validateState(value) {
  const keys = [
    'abortedTransitionDigests', 'ancestry', 'binding', 'generation',
    'headDigest', 'lastResolution', 'lineageDigest', 'namespace', 'pending',
    'revision', 'schemaVersion',
  ];
  if (!plainRecord(value) || !exactKeys(value, keys) || value.schemaVersion !== STATE_VERSION
      || !NAMESPACE_RE.test(String(value.namespace || '')) || !validCommittedState(value)) {
    throw anchorError('anchor_state_invalid');
  }
  validateBinding(value.binding);
  if (value.pending !== null && !validStoredTransition(value.pending)) {
    throw anchorError('anchor_state_invalid');
  }
  if (value.pending && !sameCommitted(value,
    value.pending.expectedRevision, value.pending.expectedDigest)) {
    throw anchorError('anchor_state_invalid');
  }
  validateLineage(value);
  validateResolutionLifecycle(value);
  validateAbortedTransitions(value);
}

function validCommittedState(value) {
  return nonNegativeSafeInteger(value.generation)
    && nonNegativeSafeInteger(value.revision)
    && SHA256_RE.test(String(value.headDigest || ''))
    && ((value.revision === 0) === (value.headDigest === ZERO_DIGEST));
}

function validateBinding(value) {
  const keys = ['assurance', 'keyId', 'purpose', 'storageContext', 'storageIdentity'];
  if (!plainRecord(value) || !exactKeys(value, keys)
      || value.assurance !== TEST_WITNESS_ASSURANCE
      || !KEY_ID_RE.test(String(value.keyId || ''))
      || !PURPOSE_RE.test(String(value.purpose || ''))
      || !STORAGE_CONTEXT_RE.test(String(value.storageContext || ''))
      || !SHA256_RE.test(String(value.storageIdentity || ''))) {
    throw anchorError('anchor_state_invalid');
  }
}

function validateLineage(value) {
  if (!SHA256_RE.test(String(value.lineageDigest || ''))
      || !exactArray(value.ancestry, MAX_ANCESTRY_PROOF)
      || value.ancestry.length !== Math.min(value.revision, MAX_ANCESTRY_PROOF)) {
    throw anchorError('anchor_state_invalid');
  }
  if (value.revision === 0) {
    if (value.lineageDigest !== initialLineageDigest(value.binding, value.namespace)) {
      throw anchorError('anchor_state_invalid');
    }
    return;
  }
  const firstRevision = value.revision - value.ancestry.length + 1;
  let priorLineage = null;
  for (let index = 0; index < value.ancestry.length; index += 1) {
    const entry = value.ancestry[index];
    const expectedRevision = firstRevision + index;
    if (!validLineageEntry(entry) || entry.revision !== expectedRevision) {
      throw anchorError('anchor_state_invalid');
    }
    if (index === 0 && expectedRevision === 1) {
      priorLineage = initialLineageDigest(value.binding, value.namespace);
    }
    if (priorLineage !== null && entry.parentLineageDigest !== priorLineage) {
      throw anchorError('anchor_state_invalid');
    }
    const core = {
      headDigest: entry.headDigest,
      parentLineageDigest: entry.parentLineageDigest,
      revision: entry.revision,
      transitionDigest: entry.transitionDigest,
    };
    if (entry.lineageDigest !== committedLineageDigest(
      value.binding, value.namespace, core,
    )) throw anchorError('anchor_state_invalid');
    priorLineage = entry.lineageDigest;
  }
  const latest = value.ancestry[value.ancestry.length - 1];
  if (latest.headDigest !== value.headDigest
      || latest.lineageDigest !== value.lineageDigest) {
    throw anchorError('anchor_state_invalid');
  }
}

function validLineageEntry(value) {
  const keys = [
    'headDigest', 'lineageDigest', 'parentLineageDigest', 'revision',
    'transitionDigest',
  ];
  return plainRecord(value) && exactKeys(value, keys)
    && Number.isSafeInteger(value.revision) && value.revision > 0
    && SHA256_RE.test(String(value.headDigest || ''))
    && SHA256_RE.test(String(value.lineageDigest || ''))
    && SHA256_RE.test(String(value.parentLineageDigest || ''))
    && SHA256_RE.test(String(value.transitionDigest || ''));
}

function validateResolutionLifecycle(value) {
  if (value.lastResolution === null) {
    const expectedGeneration = value.pending === null ? 0 : 1;
    if (value.generation !== expectedGeneration || value.revision !== 0
        || value.headDigest !== ZERO_DIGEST) throw anchorError('anchor_state_invalid');
    return;
  }
  const last = value.lastResolution;
  if (!plainRecord(last)
      || !exactKeys(last, ['outcome', 'resolvedGeneration', 'transition'])
      || !['aborted', 'finalized'].includes(last.outcome)
      || !nonNegativeSafeInteger(last.resolvedGeneration) || last.resolvedGeneration < 2
      || last.resolvedGeneration % 2 !== 0 || !validStoredTransition(last.transition)) {
    throw anchorError('anchor_state_invalid');
  }
  const expectedGeneration = last.resolvedGeneration + (value.pending === null ? 0 : 1);
  const committed = last.outcome === 'finalized'
    ? [last.transition.targetRevision, last.transition.targetDigest]
    : [last.transition.expectedRevision, last.transition.expectedDigest];
  if (value.generation !== expectedGeneration || !sameCommitted(value, ...committed)) {
    throw anchorError('anchor_state_invalid');
  }
  if (last.outcome === 'finalized') {
    const latest = value.ancestry[value.ancestry.length - 1];
    if (!latest || latest.transitionDigest !== transitionDigest(last.transition)) {
      throw anchorError('anchor_state_invalid');
    }
  }
}

function validateAbortedTransitions(value) {
  if (!exactArray(value.abortedTransitionDigests, MAX_ABORTED_TRANSITIONS)) {
    throw anchorError('anchor_state_invalid');
  }
  const seen = new Set();
  for (const digest of value.abortedTransitionDigests) {
    if (!SHA256_RE.test(String(digest || '')) || seen.has(digest)) {
      throw anchorError('anchor_state_invalid');
    }
    seen.add(digest);
  }
  const last = value.lastResolution;
  if (!last || last.outcome === 'finalized') {
    if (value.abortedTransitionDigests.length !== 0) {
      throw anchorError('anchor_state_invalid');
    }
  } else if (value.abortedTransitionDigests.at(-1)
      !== transitionDigest(last.transition)) {
    throw anchorError('anchor_state_invalid');
  }
  if (value.pending
      && seen.has(transitionDigest(value.pending))) throw anchorError('anchor_state_invalid');
}

function validStoredTransition(value) {
  const keys = [
    'expectedDigest', 'expectedRevision', 'targetDigest', 'targetRevision', 'witnessDigest',
  ];
  return plainRecord(value) && exactKeys(value, keys) && validTransition(value);
}

function sameTransition(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function sameCommitted(state, revision, digest) {
  return state.revision === revision && state.headDigest === digest;
}

function exactKeys(value, keys) {
  const actual = Reflect.ownKeys(value);
  if (actual.some((key) => typeof key !== 'string')
      || actual.sort().join(',') !== [...keys].sort().join(',')) return false;
  return actual.every((key) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor?.enumerable === true
      && Object.prototype.hasOwnProperty.call(descriptor, 'value');
  });
}

function exactArray(value, maxLength) {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype
      || !Number.isSafeInteger(value.length) || value.length > maxLength) return false;
  const actual = Reflect.ownKeys(value);
  const expected = Array.from({ length: value.length }, (_, index) => String(index));
  expected.push('length');
  if (actual.some((key) => typeof key !== 'string')
      || actual.sort().join(',') !== expected.sort().join(',')) return false;
  return expected.every((key) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, 'value')) return false;
    return key === 'length' ? descriptor.enumerable === false : descriptor.enumerable === true;
  });
}

function cloneStoredMap(value) {
  if (!(value instanceof Map)) throw anchorError('anchor_reference_storage_invalid');
  const output = new Map();
  for (const [key, item] of value) {
    if (typeof key !== 'string') throw anchorError('anchor_reference_storage_invalid');
    output.set(key, cloneStoredValue(item));
  }
  return output;
}

function cloneStoredValue(value, seen = new Map()) {
  if (!value || typeof value !== 'object') return value;
  if (seen.has(value)) return seen.get(value);
  const output = Array.isArray(value) ? [] : Object.create(Object.getPrototypeOf(value));
  seen.set(value, output);
  for (const key of Reflect.ownKeys(value)) {
    if (Array.isArray(value) && key === 'length') continue;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (Object.prototype.hasOwnProperty.call(descriptor, 'value')) {
      descriptor.value = cloneStoredValue(descriptor.value, seen);
    }
    Object.defineProperty(output, key, descriptor);
  }
  if (Array.isArray(value)) {
    const length = Object.getOwnPropertyDescriptor(value, 'length');
    Object.defineProperty(output, 'length', length);
  }
  return output;
}

function safeCanonicalDataJson(value) {
  try { return canonicalDataJson(value, new Set()); }
  catch { return null; }
}

function canonicalDataJson(value, ancestors) {
  if (value === null || ['string', 'boolean'].includes(typeof value)) {
    return JSON.stringify(value);
  }
  if (typeof value === 'number' && Number.isFinite(value) && !Object.is(value, -0)) {
    return JSON.stringify(value);
  }
  if (!value || typeof value !== 'object' || ancestors.has(value)) {
    throw anchorError('anchor_reference_storage_invalid');
  }
  ancestors.add(value);
  try {
    if (Array.isArray(value)) return canonicalDataArray(value, ancestors);
    if (!plainRecord(value)) throw anchorError('anchor_reference_storage_invalid');
    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => typeof key !== 'string')) {
      throw anchorError('anchor_reference_storage_invalid');
    }
    keys.sort();
    return `{${keys.map((key) => {
      const descriptor = checkedCanonicalDescriptor(value, key, true);
      return `${JSON.stringify(key)}:${canonicalDataJson(descriptor.value, ancestors)}`;
    }).join(',')}}`;
  } finally {
    ancestors.delete(value);
  }
}

function canonicalDataArray(value, ancestors) {
  if (Object.getPrototypeOf(value) !== Array.prototype) {
    throw anchorError('anchor_reference_storage_invalid');
  }
  const expected = Array.from({ length: value.length }, (_, index) => String(index));
  const actual = Reflect.ownKeys(value);
  const allowed = [...expected, 'length'];
  if (actual.some((key) => typeof key !== 'string')
      || actual.sort().join(',') !== allowed.sort().join(',')) {
    throw anchorError('anchor_reference_storage_invalid');
  }
  return `[${expected.map((key) => canonicalDataJson(
    checkedCanonicalDescriptor(value, key, true).value, ancestors,
  )).join(',')}]`;
}

function checkedCanonicalDescriptor(value, key, enumerable) {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (!descriptor || descriptor.enumerable !== enumerable
      || !Object.prototype.hasOwnProperty.call(descriptor, 'value')) {
    throw anchorError('anchor_reference_storage_invalid');
  }
  return descriptor;
}

function nonNegativeSafeInteger(value) {
  return Number.isSafeInteger(value) && value >= 0 && !Object.is(value, -0);
}

function plainRecord(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (!value || typeof value !== 'object') return JSON.stringify(value);
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}

function clone(value) {
  try { return JSON.parse(JSON.stringify(value)); }
  catch { throw anchorError('anchor_state_invalid'); }
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function anchorError(code) {
  const error = new Error('monotonic anchor operation rejected');
  error.code = code;
  return error;
}

module.exports = {
  ANCHOR_STATE_MIGRATION_STATUS,
  INDEPENDENT_WITNESS_ASSURANCE,
  MAX_PENDING,
  TEST_WITNESS_ASSURANCE,
  ZERO_DIGEST,
  assertProductionMonotonicAnchorAuthority,
  createReferenceMonotonicAnchorAuthority,
  createReferenceMonotonicAnchorStorage,
  createProductionMonotonicAnchorAuthority,
};
